/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <winsock2.h>
#include <windows.h>
#include <synchapi.h>
#include <processthreadsapi.h>
#include <assert.h>
#include <stdio.h>

/*
 * It's impossible to include ntstatus.h without getting a ton of warnings,
 * and these are not defined in winnt.h, so define these here.  Add safety
 * guards just in case.
 */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND                 ((NTSTATUS)0xC0000225L)
#endif

#include <bcrypt.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/sergensio.h>
#include <gensio/gensio_list.h>
#include <gensio/gensio_osops_addrinfo.h>
#include <gensio/gensio_osops_stdsock.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_circbuf.h>
#include <gensio/gensio_win.h>
#include <gensio/argvutils.h>
#include <pthread_handler.h>
#include "errtrig.h"

#if defined(_MSC_VER) && defined(ENABLE_INTERNAL_TRACE)
#include <intrin.h>
#endif

static void win_finish_free(struct gensio_os_funcs *o);

static DWORD
gensio_time_to_ms(struct gensio_time *time)
{
    if (!time)
	return INFINITE;
    if (time->secs > 1000000)
	return 1000000000; /* Cap time at a million seconds. */
    return (time->secs * 1000) + ((time->nsecs + 999999) / 1000000);
}

static ULONGLONG
gensio_time_to_ms64(struct gensio_time *time)
{
    return ((ULONGLONG)time->secs * 1000) + ((time->nsecs + 999999) / 1000000);
}

static void
win_ms64_time_to_gensio(gensio_time *gtime, ULONGLONG ms64)
{
    gtime->secs = ms64 / 1000;
    gtime->nsecs = (ms64 % 1000) * 1000000;
}

static void
win_calc_timediff(gensio_time *timeout, ULONGLONG entry, ULONGLONG exit,
		  DWORD mtimeout)
{
    ULONGLONG elapsed;

    elapsed = exit - entry;
    if (elapsed > mtimeout) {
	timeout->secs = 0;
	timeout->nsecs = 0;
    } else {
	win_ms64_time_to_gensio(timeout, mtimeout - elapsed);
    }
}

struct iostat {
    BOOL wait;
    BOOL ready;
    void (*handler)(struct gensio_iod *iod, void *cb_data);
};

struct gensio_iod_win {
    struct gensio_iod iod;

    enum gensio_iod_type type;
    void (*clean)(struct gensio_iod_win *);
    void (*wake)(struct gensio_iod_win *);
    void (*check)(struct gensio_iod_win *);
    void (*shutdown)(struct gensio_iod_win *); /* Optional. */
    intptr_t fd;
    struct gensio_link link;
    struct gensio_link all_link;

    /*
     * Is the iod in raw mode?  This is only set for stdin stdio iods
     * so they can properly handle ^Z in raw mode.
     */
    BOOL is_raw;

    BOOL done;

    BOOL is_stdio;

    struct iostat read;
    struct iostat write;
    struct iostat except;
    BOOL closed;

    DWORD (*threadfunc)(LPVOID data);
    DWORD werr; /* For reporting errors from the sub-thread, windows error. */
    int err; /* Current error condition, gensio error */

    HANDLE threadh;
    DWORD threadid;
    CRITICAL_SECTION lock;

    unsigned int in_handler_count;
    BOOL handlers_set;
    BOOL in_handlers_clear;
    void (*cleared_handler)(struct gensio_iod *iod, void *cb_data);
    void *cb_data;

    void (*set_read_handler)(struct gensio_iod_win *wiod, bool enable);
    void (*set_write_handler)(struct gensio_iod_win *wiod, bool enable);
    void (*set_except_handler)(struct gensio_iod_win *wiod, bool enable);
    void (*clear_fd_handlers)(struct gensio_iod_win *wiod);
};

#define iod_to_win(i) gensio_container_of(i, struct gensio_iod_win, iod);

enum win_timer_state {
    WIN_TIMER_STOPPED = 0,
    WIN_TIMER_IN_HEAP,
    WIN_TIMER_IN_QUEUE,
    WIN_TIMER_PENDING /* Timeout is set, waiting for the handler to return. */
};

typedef struct heap_val_s {
    struct gensio_iod_win wiod;

    void (*handler)(struct gensio_timer *t, void *cb_data);
    void *cb_data;

    void (*done)(struct gensio_timer *t, void *cb_data);
    void *done_cb_data;

    ULONGLONG end_time;

    enum win_timer_state state;

    /* Have I been freed? */
    BOOL freed;

    /* Am I currently in a handler? */
    unsigned int in_handler_count;
} heap_val_t;

#define wiod_to_timer(w) gensio_container_of(w, struct gensio_timer, val.wiod)

static int i_win_close(struct gensio_iod **iodp, bool force);

#define heap_s theap_s
#define heap_node_s gensio_timer
#define HEAP_EXPORT_NAME(s) theap_ ## s
#define HEAP_NAMES_LOCAL static
#define HEAP_OUTPUT_PRINTF "(%ld.%7.7ld)"
#define HEAP_OUTPUT_DATA pos->timeout.tv_sec, pos->timeout.tv_usec

static int
heap_cmp_key(heap_val_t *t1, heap_val_t *t2)
{
    if (t1->end_time < t2->end_time)
	return -1;
    if (t1->end_time > t2->end_time)
	return 1;
    return 0;
}

#include "heap.h"

struct gensio_data {
    /* Used to wake me up when something is in waiting_iods. */
    HANDLE waiter;

    BOOL freed;

    CRITICAL_SECTION glock;
    unsigned int refcount;
    struct gensio_list waiting_iods;
    struct gensio_list all_iods;

    CRITICAL_SECTION once_lock;

    CRITICAL_SECTION timer_lock;
    struct theap_s timer_heap;
    HANDLE timerth;
    DWORD timerthid;
    WSAEVENT timer_wakeev;

    struct gensio_os_proc_data *proc_data;

    struct gensio_memtrack *mtrack;

    int (*orig_recv)(struct gensio_iod *iod, void *buf, gensiods buflen,
		     gensiods *rcount, int gflags);
    int (*orig_send)(struct gensio_iod *iod,
		     const struct gensio_sg *sg, gensiods sglen,
		     gensiods *rcount, int gflags);
    int (*orig_sendto)(struct gensio_iod *iod,
		       const struct gensio_sg *sg, gensiods sglen,
		       gensiods *rcount, int gflags,
		       const struct gensio_addr *raddr);
    int (*orig_recvfrom)(struct gensio_iod *iod, void *buf, gensiods buflen,
			 gensiods *rcount, int flags,
			 struct gensio_addr *addr);
    int (*orig_accept)(struct gensio_iod *iod,
		       struct gensio_addr **raddr, struct gensio_iod **newiod);
    int (*orig_connect)(struct gensio_iod *iod,
			const struct gensio_addr *addr);
};

#define glock_lock(d) EnterCriticalSection(&(d)->glock)
#define glock_unlock(d)  LeaveCriticalSection(&(d)->glock)

static void *
win_zalloc(struct gensio_os_funcs *o, gensiods size)
{
    struct gensio_data *d = o->user_data;

    return gensio_i_zalloc(d->mtrack, size);
}

static void
win_free(struct gensio_os_funcs *o, void *v)
{
    struct gensio_data *d = o->user_data;

    gensio_i_free(d->mtrack, v);
}

#if 0
static void
print_err(char *name, DWORD val)
{
    char errbuf[128];

    strcpy(errbuf, "Unknown error");
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		  val, 0, errbuf, sizeof(errbuf), NULL);
    fprintf(stderr, "%s: %ld - %s\n", name, val, errbuf); fflush(stderr);
}
#endif

static void
i_queue_iod(struct gensio_iod_win *wiod)
{
    struct gensio_data *d = wiod->iod.f->user_data;
    BOOL rvb;

    if (!gensio_list_link_inlist(&wiod->link)) {
	gensio_list_add_tail(&d->waiting_iods, &wiod->link);
	rvb = ReleaseSemaphore(d->waiter, 1, NULL);
	if (!rvb)
	    /* Too many posts is improbable, but ok. */
	    assert(GetLastError() == ERROR_TOO_MANY_POSTS);
    }
}

static void
queue_iod(struct gensio_iod_win *wiod)
{
    struct gensio_data *d = wiod->iod.f->user_data;

    glock_lock(d);
    i_queue_iod(wiod);
    glock_unlock(d);
}

static DWORD WINAPI
timer_thread(LPVOID data)
{
    struct gensio_os_funcs *o = data;
    struct gensio_data *d = o->user_data;
    struct gensio_timer *t;
    ULONGLONG now, delay;
    int rv;

    EnterCriticalSection(&d->timer_lock);
    while (!d->freed) {
	now = GetTickCount64();
	t = theap_get_top(&d->timer_heap);
	while (t && t->val.end_time <= now) {
	    theap_remove(&d->timer_heap, t);
	    t->val.state = WIN_TIMER_IN_QUEUE;
	    queue_iod(&t->val.wiod);
	    t = theap_get_top(&d->timer_heap);
	    now = GetTickCount64();
	}
	if (t)
	    delay = t->val.end_time - now;
	else
	    delay = 1000000;
	LeaveCriticalSection(&d->timer_lock);
	rv = WSAWaitForMultipleEvents(1, &d->timer_wakeev, FALSE,
				      (DWORD) delay, FALSE);
	assert(rv != WSA_WAIT_FAILED);
	EnterCriticalSection(&d->timer_lock);
	assert(WSAResetEvent(d->timer_wakeev));
    }
    LeaveCriticalSection(&d->timer_lock);
    return 0;
}

static int
win_alloc_iod(struct gensio_os_funcs *o, unsigned int size, int fd,
	      enum gensio_iod_type type,
	      int (*iod_init)(struct gensio_iod_win *, void *), void *cb_data,
	      struct gensio_iod_win **rwiod)
{
    struct gensio_data *d = o->user_data;
    struct gensio_iod_win *wiod;
    int rv = 0;

    wiod = o->zalloc(o, size);
    if (!wiod)
	return GE_NOMEM;
    InitializeCriticalSection(&wiod->lock);
    wiod->iod.f = o;
    wiod->type = type;
    wiod->fd = fd;

    if (iod_init) {
	rv = iod_init(wiod, cb_data);
	if (rv)
	    goto out_err;
    }

    if (wiod->threadfunc) {
	wiod->threadh = CreateThread(NULL, 0, wiod->threadfunc, wiod, 0,
				     &wiod->threadid);
	if (!wiod->threadh)
	    goto out_err;
    }

    glock_lock(d);
    gensio_list_add_tail(&d->all_iods, &wiod->all_link);
    glock_unlock(d);
    *rwiod = wiod;
    return 0;

 out_err:
    wiod->done = TRUE;
    if (wiod->shutdown) {
	wiod->shutdown(wiod);
    } else if (wiod->threadh) {
	wiod->wake(wiod);
	WaitForSingleObject(wiod->threadh, INFINITE);
    }
    if (wiod->clean)
	wiod->clean(wiod);
    DeleteCriticalSection(&wiod->lock);
    o->free(o, wiod);
    return rv;
}

struct gensio_lock {
    struct gensio_os_funcs *o;
    CRITICAL_SECTION lock;
};

static struct gensio_lock *win_alloc_lock(struct gensio_os_funcs *o)
{
    struct gensio_lock *lock;

    lock = o->zalloc(o, sizeof(*lock));
    if (!lock)
	return NULL;
    lock->o = o;
    if (!InitializeCriticalSectionAndSpinCount(&lock->lock, 0)) {
	o->free(o, lock);
	return NULL;
    }
    return lock;
}

static void win_free_lock(struct gensio_lock *lock)
{
    DeleteCriticalSection(&lock->lock);
    lock->o->free(lock->o, lock);
}

static void win_lock(struct gensio_lock *lock)
{
    EnterCriticalSection(&lock->lock);
}

static void win_unlock(struct gensio_lock *lock)
{
    LeaveCriticalSection(&lock->lock);
}

/* Call this at the return of every iod handler. */
static void
win_iod_handler_done(struct gensio_iod_win *wiod)
{
    void (*cleared_handler)(struct gensio_iod *iod, void *cb_data) = NULL;
    void *cb_data;

    EnterCriticalSection(&wiod->lock);
    assert(wiod->in_handler_count > 0);
    wiod->in_handler_count--;
    if (wiod->in_handlers_clear && wiod->in_handler_count == 0) {
	cleared_handler = wiod->cleared_handler;
	cb_data = wiod->cb_data;
	wiod->handlers_set = FALSE;
	wiod->read.handler = NULL;
	wiod->write.handler = NULL;
	wiod->except.handler = NULL;
	wiod->cleared_handler = NULL;
    }
    LeaveCriticalSection(&wiod->lock);
    if (cleared_handler)
	cleared_handler(&wiod->iod, cb_data);
}

static int
win_set_fd_handlers(struct gensio_iod *iod,
		    void *cb_data,
		    void (*read_handler)(struct gensio_iod *iod,
					 void *cb_data),
		    void (*write_handler)(struct gensio_iod *iod,
					  void *cb_data),
		    void (*except_handler)(struct gensio_iod *iod,
					   void *cb_data),
		    void (*cleared_handler)(struct gensio_iod *iod,
					    void *cb_data))
{
    struct gensio_iod_win *wiod = iod_to_win(iod);
    int rv = GE_INUSE;

    EnterCriticalSection(&wiod->lock);
    if (!wiod->handlers_set) {
	rv = 0;
	wiod->handlers_set = TRUE;
	wiod->read.handler = read_handler;
	wiod->write.handler = write_handler;
	wiod->except.handler = except_handler;
	wiod->cleared_handler = cleared_handler;
	wiod->cb_data = cb_data;
    }
    LeaveCriticalSection(&wiod->lock);
    return rv;
}

static void
win_clear_fd_handlers(struct gensio_iod *iod)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);

    EnterCriticalSection(&wiod->lock);
    if (wiod->handlers_set && !wiod->in_handlers_clear) {
	wiod->in_handlers_clear = TRUE;
	if (wiod->clear_fd_handlers) {
	    wiod->clear_fd_handlers(wiod);
	    goto out;
	}
	wiod->read.wait = FALSE;
	wiod->read.ready = FALSE;
	wiod->write.wait = FALSE;
	wiod->write.ready = FALSE;
	wiod->except.wait = FALSE;
	wiod->except.ready = FALSE;
	if (wiod->in_handler_count == 0)
	    queue_iod(wiod);
    }
out:
    LeaveCriticalSection(&wiod->lock);
}

static void
win_clear_fd_handlers_norpt(struct gensio_iod *iod)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);

    EnterCriticalSection(&wiod->lock);
    if (wiod->handlers_set && !wiod->in_handlers_clear) {
	wiod->handlers_set = false;
	wiod->read.handler = NULL;
	wiod->write.handler = NULL;
	wiod->except.handler = NULL;
	wiod->cleared_handler = NULL;
    }
    LeaveCriticalSection(&wiod->lock);
}

static void
win_set_read_handler(struct gensio_iod *iod, bool enable)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);

    EnterCriticalSection(&wiod->lock);
    if (wiod->read.wait != enable && !wiod->in_handlers_clear) {
	wiod->read.wait = enable;
	if (wiod->set_read_handler) {
	    wiod->set_read_handler(wiod, enable);
	} else {
	    if (enable) {
		if (wiod->read.ready)
		    queue_iod(wiod);
		else
		    wiod->wake(wiod);
	    }
	}
    }
    LeaveCriticalSection(&wiod->lock);
}

static void
win_set_write_handler(struct gensio_iod *iod, bool enable)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);

    EnterCriticalSection(&wiod->lock);
    if (wiod->write.wait != enable && !wiod->in_handlers_clear) {
	wiod->write.wait = enable;
	if (wiod->set_write_handler) {
	    wiod->set_write_handler(wiod, enable);
	} else {
	    if (enable) {
		if (wiod->write.ready)
		    queue_iod(wiod);
		else
		    wiod->wake(wiod);
	    }
	}
    }
    LeaveCriticalSection(&wiod->lock);
}

static void
win_set_except_handler(struct gensio_iod *iod, bool enable)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);

    EnterCriticalSection(&wiod->lock);
    if (wiod->except.wait != enable && !wiod->in_handlers_clear) {
	wiod->except.wait = enable;
	if (wiod->set_except_handler) {
	    wiod->set_except_handler(wiod, enable);
	} else {
	    if (enable) {
		if (wiod->except.ready)
		    queue_iod(wiod);
		else
		    wiod->wake(wiod);
	    }
	}
    }
    LeaveCriticalSection(&wiod->lock);
}

static void
win_timer_check(struct gensio_iod_win *wiod)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_data *d = o->user_data;
    struct gensio_timer *t = wiod_to_timer(wiod);

    t->val.in_handler_count++;
    glock_unlock(d);
    EnterCriticalSection(&d->timer_lock);
    if (t->val.state == WIN_TIMER_IN_QUEUE) {
	t->val.state = WIN_TIMER_STOPPED;
	LeaveCriticalSection(&d->timer_lock);
	t->val.handler(t, t->val.cb_data);
	EnterCriticalSection(&d->timer_lock);
    }
    else {
	assert(t->val.state == WIN_TIMER_STOPPED);
    }
    if (t->val.done && !t->val.freed) {
	void (*done)(struct gensio_timer *t, void *cb_data) = t->val.done;
	void *cb_data = t->val.done_cb_data;

	t->val.done = NULL;
	LeaveCriticalSection(&d->timer_lock);
	done(t, cb_data);
	EnterCriticalSection(&d->timer_lock);
    }
    if (t->val.freed) {
	LeaveCriticalSection(&d->timer_lock);
	o->release_iod(&t->val.wiod.iod);
	glock_lock(d);
	return;
    }
    if (t->val.state == WIN_TIMER_PENDING) {
	theap_add(&d->timer_heap, t);
	assert(WSASetEvent(d->timer_wakeev));
	t->val.state = WIN_TIMER_IN_HEAP;
    }
    LeaveCriticalSection(&d->timer_lock);
    glock_lock(d);
    t->val.in_handler_count--;
}

static struct gensio_timer *
win_alloc_timer(struct gensio_os_funcs *o,
		void (*handler)(struct gensio_timer *t, void *cb_data),
		void *cb_data)
{
    struct gensio_timer *t = NULL;
    struct gensio_iod_win *wiod;
    int rv;

    rv = win_alloc_iod(o, sizeof(struct gensio_timer), -1, 0, NULL, NULL,
		       &wiod);
    if (!rv) {
	wiod->check = win_timer_check;
	t = wiod_to_timer(wiod);
	t->val.handler = handler;
	t->val.cb_data = cb_data;
    }
    return t;
}

static void
win_stop_timer_now(struct gensio_timer *timer)
{
    struct gensio_os_funcs *o = timer->val.wiod.iod.f;
    struct gensio_data *d = o->user_data;

    if (timer->val.state == WIN_TIMER_IN_QUEUE) {
	glock_lock(d);
	/*
	 * We aren't holding glock_lock until just above, so
	 * it;s possible it was pulled from the list but hasn't
	 * been run.
	 */
	if (gensio_list_link_inlist(&timer->val.wiod.link))
	    gensio_list_rm(&d->waiting_iods, &timer->val.wiod.link);
	glock_unlock(d);
    } else if (timer->val.state == WIN_TIMER_IN_HEAP) {
	theap_remove(&d->timer_heap, timer);
    }
    timer->val.state = WIN_TIMER_STOPPED;
}

static void
win_free_timer(struct gensio_timer *timer)
{
    struct gensio_os_funcs *o = timer->val.wiod.iod.f;
    struct gensio_data *d = o->user_data;

    EnterCriticalSection(&d->timer_lock);
    if (!timer->val.freed) {
	timer->val.freed = TRUE;
	win_stop_timer_now(timer);
	if (timer->val.in_handler_count == 0)
	    o->release_iod(&timer->val.wiod.iod);
    }
    LeaveCriticalSection(&d->timer_lock);
}

static int
win_add_timer(struct gensio_timer *timer, ULONGLONG end_time)
{
    struct gensio_os_funcs *o = timer->val.wiod.iod.f;
    struct gensio_data *d = o->user_data;
    int rv = 0;

    EnterCriticalSection(&d->timer_lock);
    if (timer->val.freed) {
	rv = GE_INVAL;
	goto out_unlock;
    }
    if (timer->val.state != WIN_TIMER_STOPPED || timer->val.done) {
	rv = GE_INUSE;
	goto out_unlock;
    }
    timer->val.end_time = end_time;
    if (timer->val.in_handler_count > 0) {
	/* We'll add it when the handler returns. */
	timer->val.state = WIN_TIMER_PENDING;
    } else {
	theap_add(&d->timer_heap, timer);
	assert(WSASetEvent(d->timer_wakeev));
	timer->val.state = WIN_TIMER_IN_HEAP;
    }
 out_unlock:
    LeaveCriticalSection(&d->timer_lock);
    return rv;
}

static int
win_start_timer(struct gensio_timer *timer, gensio_time *timeout)
{
    return win_add_timer(timer,
			 GetTickCount64() + gensio_time_to_ms64(timeout));
}

static int win_start_timer_abs(struct gensio_timer *timer,
			       gensio_time *timeout)
{
    return win_add_timer(timer, gensio_time_to_ms64(timeout));
}

static int win_stop_timer(struct gensio_timer *timer)
{
    struct gensio_os_funcs *o = timer->val.wiod.iod.f;
    struct gensio_data *d = o->user_data;
    int rv = 0;

    EnterCriticalSection(&d->timer_lock);
    if (timer->val.freed) {
	rv = GE_INVAL;
	goto out_unlock;
    }
    if (timer->val.state != WIN_TIMER_STOPPED)
	win_stop_timer_now(timer);
    else
	rv = GE_TIMEDOUT;
 out_unlock:
    LeaveCriticalSection(&d->timer_lock);
    return rv;
}

static int win_stop_timer_with_done(struct gensio_timer *timer,
			     void (*done_handler)(struct gensio_timer *t,
						  void *cb_data),
			     void *cb_data)
{
    struct gensio_os_funcs *o = timer->val.wiod.iod.f;
    struct gensio_data *d = o->user_data;
    int rv = 0;

    EnterCriticalSection(&d->timer_lock);
    if (timer->val.freed) {
	rv = GE_INVAL;
	goto out_unlock;
    }
    switch (timer->val.state) {
    case WIN_TIMER_STOPPED:
	if (timer->val.in_handler_count == 0) {
	    rv = GE_TIMEDOUT;
	    goto out_unlock;
	}
	if (timer->val.done) {
	    rv = GE_INUSE;
	    goto out_unlock;
	}
	break;

    case WIN_TIMER_IN_HEAP:
    case WIN_TIMER_IN_QUEUE:
	win_stop_timer_now(timer);
	timer->val.state = WIN_TIMER_STOPPED;
	queue_iod(&timer->val.wiod);
	break;

    case WIN_TIMER_PENDING:
	if (timer->val.done) {
	    rv = GE_INUSE;
	    goto out_unlock;
	}
	timer->val.state = WIN_TIMER_STOPPED;
	break;
    }
    timer->val.done = done_handler;
    timer->val.done_cb_data = cb_data;

 out_unlock:
    LeaveCriticalSection(&d->timer_lock);
    return rv;
}

struct gensio_runner {
    struct gensio_iod_win wiod;
    BOOL running;
    BOOL freed;
    BOOL in_handler_count;
    void (*handler)(struct gensio_runner *r, void *cb_data);
    void *cb_data;
};

#define wiod_to_runner(w) gensio_container_of(w, struct gensio_runner, wiod)

static void
win_runner_check(struct gensio_iod_win *wiod)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_data *d = o->user_data;
    struct gensio_runner *r = wiod_to_runner(wiod);

    if (r->freed)
	goto out_free;
    r->running = FALSE;
    r->in_handler_count++;
    glock_unlock(d);
    r->handler(r, r->cb_data);
    glock_lock(d);
    r->in_handler_count--;
    if (r->freed) {
    out_free:
	glock_unlock(d);
	o->release_iod(&r->wiod.iod);
	glock_lock(d);
    }
}

static struct gensio_runner *
win_alloc_runner(struct gensio_os_funcs *o,
		 void (*handler)(struct gensio_runner *r, void *cb_data),
		 void *cb_data)
{
    struct gensio_runner *r = NULL;
    struct gensio_iod_win *wiod;
    int rv;

    rv = win_alloc_iod(o, sizeof(struct gensio_runner), -1, 0, NULL, NULL,
		       &wiod);
    if (!rv) {
	wiod->check = win_runner_check;
	r = wiod_to_runner(wiod);
	r->handler = handler;
	r->cb_data = cb_data;
    }
    return r;
}

static void
win_free_runner(struct gensio_runner *runner)
{
    struct gensio_os_funcs *o = runner->wiod.iod.f;
    struct gensio_data *d = o->user_data;

    glock_lock(d);
    if (!runner->freed) {
	runner->freed = TRUE;
	if (runner->in_handler_count == 0) {
	    if (runner->running) {
		gensio_list_rm(&d->waiting_iods, &runner->wiod.link);
		runner->running = FALSE;
	    }
	    glock_unlock(d);
	    o->release_iod(&runner->wiod.iod);
	    return;
	}
	/* If in the handler, nothing to do, it will catch it on return. */
    }
    glock_unlock(d);
}

static int
win_run(struct gensio_runner *runner)
{
    struct gensio_os_funcs *o = runner->wiod.iod.f;
    struct gensio_data *d = o->user_data;
    int rv = 0;

    glock_lock(d);
    if (runner->freed) {
	rv = GE_INVAL;
    } else if (runner->running) {
	rv = GE_INUSE;
    } else {
	runner->running = TRUE;
	i_queue_iod(&runner->wiod);
    }
    glock_unlock(d);

    return rv;
}

struct gensio_waiter {
    struct gensio_os_funcs *o;
    HANDLE wait_sem;
    CRITICAL_SECTION lock;
    unsigned int num_waiters;
    unsigned int count;
    BOOL in_free;
};

static struct gensio_waiter *
win_alloc_waiter(struct gensio_os_funcs *o)
{
    struct gensio_waiter *w;

    w = o->zalloc(o, sizeof(*w));
    if (!w)
	return NULL;
    w->o = o;
    w->wait_sem = CreateSemaphoreA(NULL, 0, 1000000, NULL);
    if (!w->wait_sem) {
	o->free(o, w);
	return NULL;
    }
    InitializeCriticalSection(&w->lock);

    return w;
}

static void
win_finish_free_waiter(struct gensio_waiter *waiter)
{
    CloseHandle(waiter->wait_sem);
    DeleteCriticalSection(&waiter->lock);
    waiter->o->free(waiter->o, waiter);
}

static void
win_free_waiter(struct gensio_waiter *waiter)
{
    int rv;

    EnterCriticalSection(&waiter->lock);
    if (waiter->in_free)
	goto out_unlock;
    waiter->in_free = TRUE;
    if (waiter->num_waiters > 0) {
	rv = ReleaseSemaphore(waiter, waiter->num_waiters, NULL);
	assert(rv != 0);
	goto out_unlock;
    }
    LeaveCriticalSection(&waiter->lock);
    win_finish_free_waiter(waiter);
    return;

 out_unlock:
    LeaveCriticalSection(&waiter->lock);
}

static void
win_check_iods(struct gensio_os_funcs *o)
{
    struct gensio_data *d = o->user_data;

    glock_lock(d);
    while (!gensio_list_empty(&d->waiting_iods)) {
	struct gensio_link *l = gensio_list_first(&d->waiting_iods);
	struct gensio_iod_win *wiod;

	wiod = gensio_container_of(l, struct gensio_iod_win, link);
	gensio_list_rm(&d->waiting_iods, l);

	wiod->check(wiod);
    }
    glock_unlock(d);
}

static int
win_do_wait(struct gensio_waiter *waiter, unsigned int count,
	    gensio_time *timeout, BOOL alerts)
{
    struct gensio_data *d = waiter->o->user_data;
    int rv = 0, nrh = 0;
    ULONGLONG entry_time, end_time, now;
    DWORD rvw, mtimeout;
    HANDLE h[3];

    entry_time = GetTickCount64();
    mtimeout = gensio_time_to_ms(timeout);
    end_time = entry_time + mtimeout;
    now = entry_time;

    h[nrh++] = d->waiter;
    h[nrh++] = waiter->wait_sem;
    if (d->proc_data)
	h[nrh++] = gensio_os_proc_win_get_main_handle(d->proc_data);

    EnterCriticalSection(&waiter->lock);
    if (waiter->in_free) {
	LeaveCriticalSection(&waiter->lock);
	return GE_INVAL;
    }

    waiter->num_waiters++;
    while (count) {
	while (waiter->count == 0) {
	    if (waiter->in_free)
		goto waitdone;
	    if (now > end_time) {
		rv = GE_TIMEDOUT;
		goto waitdone;
	    }
	    LeaveCriticalSection(&waiter->lock);
	    rvw = WaitForMultipleObjectsEx(nrh, h, FALSE, end_time - now,
					   alerts);
	    assert(rvw != WAIT_FAILED);
	    if (rvw != WAIT_TIMEOUT)
		win_check_iods(waiter->o);
	    if (d->proc_data)
		gensio_os_proc_check_handlers(d->proc_data);
	    now = GetTickCount64();
	    EnterCriticalSection(&waiter->lock);
	}
	waiter->count--;
	count--;
    }
 waitdone:
    waiter->num_waiters--;

    if (waiter->in_free && waiter->num_waiters == 0) {
	LeaveCriticalSection(&waiter->lock);
	win_finish_free_waiter(waiter);
    } else {
	LeaveCriticalSection(&waiter->lock);
    }

    if (timeout)
	win_calc_timediff(timeout, entry_time, now, mtimeout);
    return rv;
}

static int
win_wait(struct gensio_waiter *waiter, unsigned int count,
	 gensio_time *timeout)
{
    return win_do_wait(waiter, count, timeout, FALSE);
}

static int
win_wait_intr(struct gensio_waiter *waiter, unsigned int count,
	      gensio_time *timeout)
{
    return win_do_wait(waiter, count, timeout, TRUE);
}

static void win_wake(struct gensio_waiter *waiter)
{
    int rv;

    EnterCriticalSection(&waiter->lock);
    waiter->count++;
    LeaveCriticalSection(&waiter->lock);
    rv = ReleaseSemaphore(waiter->wait_sem, 1, NULL);
    assert(rv != 0);
}

static int win_service(struct gensio_os_funcs *o, gensio_time *timeout)
{
    struct gensio_data *d = o->user_data;
    ULONGLONG entry_time;
    DWORD mtimeout, rvw;
    int rv = 0;

    entry_time = GetTickCount64();
    mtimeout = gensio_time_to_ms(timeout);
    rvw = WaitForSingleObject(d->waiter, mtimeout);
    assert(rvw != WAIT_FAILED);
    if (rvw == WAIT_TIMEOUT)
	rv = GE_TIMEDOUT;
    else
	win_check_iods(o);

    if (timeout)
	win_calc_timediff(timeout, entry_time, GetTickCount64(), mtimeout);
    return rv;
}

static SRWLOCK def_win_os_funcs_lock = SRWLOCK_INIT;
static struct gensio_os_funcs *def_win_os_funcs;

static struct gensio_os_funcs *
win_get_funcs(struct gensio_os_funcs *o)
{
    struct gensio_data *d = o->user_data;

    glock_lock(d);
    assert(d->refcount > 0);
    d->refcount++;
    glock_unlock(d);
    return o;
}

static void
win_free_funcs(struct gensio_os_funcs *o)
{
    struct gensio_data *d = o->user_data;

    AcquireSRWLockExclusive(&def_win_os_funcs_lock);
    glock_lock(d);
    assert(d->refcount > 0);
    if (d->refcount > 1) {
	d->refcount--;
	glock_unlock(d);
	ReleaseSRWLockExclusive(&def_win_os_funcs_lock);
	return;
    }
    glock_unlock(d);
    if (o == def_win_os_funcs)
	def_win_os_funcs = NULL;
    ReleaseSRWLockExclusive(&def_win_os_funcs_lock);

    if (!d->freed) {
	d->freed = TRUE;
	if (gensio_list_empty(&d->all_iods)) {
	    win_finish_free(o);
	    return;
	}
    }
}

static void win_call_once(struct gensio_os_funcs *o, struct gensio_once *once,
			  void (*func)(void *cb_data), void *cb_data)
{
    struct gensio_data *d = o->user_data;
    if (once->called)
	return;
    EnterCriticalSection(&d->once_lock);
    if (!once->called) {
	once->called = true;
	LeaveCriticalSection(&d->once_lock);
	func(cb_data);
    } else {
	LeaveCriticalSection(&d->once_lock);
    }
}

static void win_get_monotonic_time(struct gensio_os_funcs *o,
				   gensio_time *time)
{
    win_ms64_time_to_gensio(time, GetTickCount64());
}

static int win_handle_fork(struct gensio_os_funcs *o)
{
    /* FIXME */
    return GE_NOTSUP;
}

static int win_wait_intr_sigmask(struct gensio_waiter *waiter,
				 unsigned int count, gensio_time *timeout,
				 struct gensio_os_proc_data *proc_data)
{
    return win_wait_intr(waiter, count, timeout);
}

static void
win_iod_check_handler(struct gensio_iod_win *wiod, struct iostat *stat)
{
    EnterCriticalSection(&wiod->lock);
    while (stat->wait && stat->handler && (stat->ready || wiod->closed)) {
	void (*handler)(struct gensio_iod *iod, void *cb_data) = stat->handler;
	void *cb_data = wiod->cb_data;

	LeaveCriticalSection(&wiod->lock);
	handler(&wiod->iod, cb_data);
	EnterCriticalSection(&wiod->lock);
    }
    LeaveCriticalSection(&wiod->lock);
}

static void
win_iod_check(struct gensio_iod_win *wiod)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_data *d = o->user_data;

    glock_unlock(d);
    EnterCriticalSection(&wiod->lock);
    wiod->in_handler_count++;
    LeaveCriticalSection(&wiod->lock);
    win_iod_check_handler(wiod, &wiod->read);
    win_iod_check_handler(wiod, &wiod->write);
    win_iod_check_handler(wiod, &wiod->except);
    win_iod_handler_done(wiod);
    glock_lock(d);
}

struct gensio_iod_win_sock {
    struct gensio_iod_win wiod;
    WSAEVENT wakeev;
    WSAEVENT sockev;
    BOOL connected;
    void *sockinfo;
    enum { CL_NOT_CALLED, CL_CALLED, CL_DONE } close_state;
};

#define wiod_to_winsock(w) gensio_container_of(w, struct gensio_iod_win_sock,\
					       wiod)

static DWORD WINAPI
winsock_func(LPVOID data)
{
    struct gensio_iod_win_sock *swiod = data;
    struct gensio_iod_win *wiod = &swiod->wiod;
    WSAEVENT waiters[2];
    unsigned int i;
    int rv;

    EnterCriticalSection(&wiod->lock);
    waiters[0] = swiod->wakeev;
    waiters[1] = swiod->sockev;
    for(;;) {
	WSANETWORKEVENTS revents;
	long events = 0;
	BOOL queueit = FALSE;

	if (!wiod->closed) {
	    events = FD_CLOSE;
	    if (wiod->read.wait && !wiod->read.ready)
		events |= FD_READ | FD_ACCEPT;
	    if (wiod->write.wait && !wiod->write.ready)
		events |= FD_WRITE | FD_CONNECT;
	    if (wiod->except.wait && !wiod->except.ready)
		events |= FD_OOB;
	}
	LeaveCriticalSection(&wiod->lock);
	i = 1;
	if (events) {
	    /* FIXME - check if events changed? */
	    rv = WSAEventSelect(wiod->fd, swiod->sockev, events);
	    if (rv == SOCKET_ERROR) {
		EnterCriticalSection(&wiod->lock);
		if (!wiod->werr)
		    wiod->werr = WSAGetLastError();
		wiod->closed = TRUE;
		queueit = TRUE;
		goto do_queue;
	    }
	    i++;
	}
	rv = WSAWaitForMultipleEvents(i, waiters, FALSE, INFINITE, FALSE);
	EnterCriticalSection(&wiod->lock);
	if (wiod->done)
	    break;
	if (rv == WSA_WAIT_FAILED) {
	    wiod->closed = TRUE;
	    queueit = TRUE;
	} else if (rv == WSA_WAIT_EVENT_0) {
	    WSAResetEvent(swiod->wakeev);
	} else if (rv == WSA_WAIT_EVENT_0 + 1) {
	    rv = WSAEnumNetworkEvents(wiod->fd, swiod->sockev, &revents);
	    if (rv == SOCKET_ERROR) {
		if (!wiod->werr)
		    wiod->werr = WSAGetLastError();
		wiod->closed = TRUE;
		queueit = TRUE;
	    } else {
		if (revents.lNetworkEvents & (FD_READ | FD_ACCEPT)) {
		    wiod->read.ready = TRUE;
		    if (wiod->read.wait)
			queueit = TRUE;
		}
		if (revents.lNetworkEvents & (FD_WRITE | FD_CONNECT)) {
		    wiod->write.ready = TRUE;
		    if (wiod->write.wait)
			queueit = TRUE;
		}
		if (revents.lNetworkEvents & FD_OOB) {
		    wiod->except.ready = TRUE;
		    if (wiod->except.wait)
			queueit = TRUE;
		}
		if (revents.lNetworkEvents & FD_CLOSE) {
		    wiod->closed = TRUE;
		    queueit = TRUE;
		}
	    }
	}
    do_queue:
	if (queueit)
	    queue_iod(wiod);
    }
    LeaveCriticalSection(&wiod->lock);
    return 0;
}

static void
win_iod_socket_wake(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_sock *swiod = wiod_to_winsock(wiod);

    assert(WSASetEvent(swiod->wakeev));
}

static void
win_iod_socket_clean(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_sock *swiod = wiod_to_winsock(wiod);

    if (swiod->sockev != WSA_INVALID_EVENT)
	WSACloseEvent(swiod->sockev);
    if (swiod->wakeev != WSA_INVALID_EVENT)
	WSACloseEvent(swiod->wakeev);
    if (wiod->fd != -1)
	closesocket(wiod->fd);
}

static int
win_iod_socket_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_sock *swiod = wiod_to_winsock(wiod);

    swiod->wakeev = WSA_INVALID_EVENT;
    swiod->sockev = WSA_INVALID_EVENT;

    swiod->wakeev = WSACreateEvent();
    if (swiod->wakeev == WSA_INVALID_EVENT)
	goto out_err;

    swiod->sockev = WSACreateEvent();
    if (swiod->sockev == WSA_INVALID_EVENT)
	goto out_err;

    wiod->threadfunc = winsock_func;
    wiod->clean = win_iod_socket_clean;
    wiod->wake = win_iod_socket_wake;
    wiod->check = win_iod_check;

    return 0;

 out_err:
    win_iod_socket_clean(wiod);
    return GE_NOMEM;
}

/* Used to pass data into the intitialization routines. */
struct win_init_info {
    HANDLE ioh;
    HANDLE processh;
    const char *name;
};

struct gensio_iod_win_file {
    struct gensio_iod_win wiod;
    HANDLE ioh;
    BOOL readable;
    BOOL writeable;
};

#define wiod_to_winfile(w) gensio_container_of(w, struct gensio_iod_win_file,\
					       wiod)

static void
win_dummy_wake(struct gensio_iod_win *wiod)
{
}

static int
win_iod_file_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_file *fwiod = wiod_to_winfile(wiod);

    if (cb_data) {
	fwiod->readable = *((BOOL *) cb_data);
	fwiod->writeable = !fwiod->readable;
    } else {
	fwiod->readable = TRUE;
	fwiod->writeable = TRUE;
    }
    fwiod->ioh = (HANDLE) wiod->fd;
    wiod->read.ready = fwiod->readable;
    wiod->write.ready = fwiod->writeable;
    wiod->check = win_iod_check;
    wiod->wake = win_dummy_wake;

    return 0;
}

static int
win_file_write(struct gensio_iod_win *wiod,
	       const struct gensio_sg *sg, gensiods sglen,
	       gensiods *rcount)
{
    struct gensio_iod_win_file *fwiod = wiod_to_winfile(wiod);
    gensiods i, count = 0;
    DWORD len;

    if (!fwiod->writeable)
	return GE_NOTSUP;

    for (i = 0; i < sglen; i++) {
	if (!WriteFile(fwiod->ioh, sg[i].buf, sg[i].buflen, &len, FALSE)) {
	    if (count > 0)
		goto out;
	    return gensio_os_err_to_err(wiod->iod.f, GetLastError());
	}
	count += len;
    }

 out:
    *rcount = count;
    return 0;
}

static int
win_file_read(struct gensio_iod_win *wiod,
	      void *ibuf, gensiods buflen, gensiods *rcount)
{
    struct gensio_iod_win_file *fwiod = wiod_to_winfile(wiod);
    DWORD len;

    if (!ReadFile(fwiod->ioh, ibuf, buflen, &len, FALSE))
	return gensio_os_err_to_err(wiod->iod.f, GetLastError());
    if (len == 0)
	return GE_REMCLOSE;
    *rcount = len;
    return 0;
}

/*
 * Windows stdio/pipe (unidirectional) handling
 *
 * Just about everything about Windows stdio sucks.  I mean, there's
 * the whole "newline" situation.  And ^Z for EOF?
 *
 * But for this library, the main problem with is is that there is no
 * feasible way to set the I/O handles non-blocking.  So we have to
 * work around it. The same is true for anonymous pipes.  A major
 * oversight in the design of Windows.
 *
 * The basic structure is to create a separate threads to do the I/O
 * with it's own buffer.  The input thread normally sits waiting for
 * read data and putting that data into the buffer.  If the buffer is
 * full it sits waiting on an event.  The read code will send the
 * event when it gets some data from the buffer.
 *
 * The write code is similar.  It normally sits waiting on an event.
 * When the write code puts some data into the buffer it sends an
 * event to the thread, which wakes up and writes the data until the
 * buffer is empty.
 *
 * The big problem is closing.  There is no reliable way to wake the
 * thread if it is blocked on an I/O operation.  You can use
 * CancelSynchronousIo(), but there is a race between releasing the
 * lock and the read/write being done where the cancel won't work.
 * The solution is ugly, the code sends CancelSynchronousIo() to the
 * thread until the thread terminates, which kind of violates the
 * non-blocking, but there's no way around it.
 *
 * Flushing output data is a bit of a problem.  As there is no
 * reliable way to wake a thread that is blocked on I/O, it sets a
 * flag and wakes the stdout thread (except that is racy, of course,
 * but we hope for the best).  The write operation will not allow data
 * to be written until the flush is completed by the thread.
 */
struct gensio_iod_win_oneway {
    struct gensio_iod_win wiod;
    HANDLE wakeh;
    HANDLE ioh;

    struct gensio_circbuf *buf;

    BOOL is_console;
    BOOL readable;

    BOOL do_flush; /* Tell out to flush it's data. */
};

#define wiod_to_win_oneway(w) gensio_container_of(w,			    \
					       struct gensio_iod_win_oneway, \
					       wiod)

static void check_winsize(struct gensio_iod_win_oneway *owiod);

static DWORD WINAPI
win_oneway_in_thread(LPVOID data)
{
    struct gensio_iod_win_oneway *owiod = data;
    struct gensio_iod_win *wiod = &owiod->wiod;
    HANDLE waiters[2] = { owiod->ioh, owiod->wakeh };
    DWORD rvw;

    /*
     * This is a hack to avoid an issue with Windows raw setting.  If
     * we let a read happen before setting the console to raw, the
     * console won't go into raw mode until after enter is pressed.
     * So don't start reading input until the user has enabled read to
     * allow them time to set the input as raw.
     */
    goto start_loop;

    EnterCriticalSection(&wiod->lock);
    for(;;) {
	BOOL rvb;

	if (gensio_circbuf_room_left(owiod->buf) && !wiod->werr) {
	    gensiods readsize;
	    void *readpos;
	    DWORD nread;

	    gensio_circbuf_next_write_area(owiod->buf, &readpos, &readsize);
	    if (owiod->is_console) {
		LeaveCriticalSection(&wiod->lock);
		while (true) {
		    rvw = WaitForMultipleObjects(2, waiters, FALSE, INFINITE);
		    EnterCriticalSection(&wiod->lock);
		    if (wiod->done)
			goto continue_loop;
		    if (rvw == WAIT_FAILED)
			goto out_err;
		    if (rvw == WAIT_OBJECT_0 + 1) {
			/* Maybe we were woken to handle the first winsize. */
			check_winsize(owiod);
		    }
		    if (rvw == WAIT_OBJECT_0) {
			INPUT_RECORD r;

			LeaveCriticalSection(&wiod->lock);
			rvb = PeekConsoleInput(owiod->ioh, &r, 1, &nread);
			EnterCriticalSection(&wiod->lock);
			if (!rvb)
			    goto out_err;
			if (r.EventType == WINDOW_BUFFER_SIZE_EVENT) {
			    ReadConsoleInput(owiod->ioh, &r, 1, &nread);
			    check_winsize(owiod);
			} else {
			    goto leave_peek_loop;
			}
		    }
		    LeaveCriticalSection(&wiod->lock);
		}
		EnterCriticalSection(&wiod->lock);
	    }
	leave_peek_loop:
	    if (wiod->done)
		goto continue_loop;
	    LeaveCriticalSection(&wiod->lock);
	    rvb = ReadFile(owiod->ioh, readpos, readsize, &nread, NULL);
	    EnterCriticalSection(&wiod->lock);
	    if (wiod->done)
		goto continue_loop;
	    if (!rvb) {
		if (GetLastError() == ERROR_OPERATION_ABORTED)
		     /*
		      * We got a CancelSynchronousIo().  We are
		      * probably being shut down, but don't handle it
		      * as an error.
		      */
		    goto continue_loop;
		goto out_err;
	    }
	    /*
	     * We handle this here because sometimes the event is
	     * already eaten in ReadFile and we don't see it
	     * above where we check.
	     */
	    if (owiod->is_console)
		check_winsize(owiod);
	    if (nread == 0) {
		/* EOF (^Z<cr>) from windows. */
		if (wiod->is_raw) {
		    *((char *) readpos) = 0x1a; /* Insert the ^Z */
		    nread = 1;
		    goto insert_data;
		}
		rvw = ERROR_BROKEN_PIPE;
		goto out_err_noconv;
	    } else {
	    insert_data:
		gensio_circbuf_data_added(owiod->buf, nread);
		if (!wiod->read.ready) {
		    wiod->read.ready = TRUE;
		    queue_iod(wiod);
		}
	    }
	} else {
	    LeaveCriticalSection(&wiod->lock);
	start_loop:
	    rvw = WaitForSingleObject(owiod->wakeh, INFINITE);
	    EnterCriticalSection(&wiod->lock);
	    if (rvw == WAIT_FAILED)
		goto out_err;
	    if (!wiod->done)
		/* Maybe we were woken to handle the first winsize. */
		check_winsize(owiod);
	}
    continue_loop:
	if (wiod->done)
	    break;
    }
    LeaveCriticalSection(&wiod->lock);

    return 0;

 out_err:
    rvw = GetLastError();
 out_err_noconv:
    if (!wiod->werr) {
	wiod->read.ready = TRUE;
	wiod->werr = rvw;
	queue_iod(wiod);
    }
    LeaveCriticalSection(&wiod->lock);
    return 0;
}

static DWORD WINAPI
win_oneway_out_thread(LPVOID data)
{
    struct gensio_iod_win_oneway *owiod = data;
    struct gensio_iod_win *wiod = &owiod->wiod;
    DWORD rvw;

    EnterCriticalSection(&wiod->lock);
    for(;;) {
	BOOL rvb;

	if (gensio_circbuf_datalen(owiod->buf) > 0) {
	    gensiods writelen;
	    void *writepos;
	    DWORD nwrite;

	    gensio_circbuf_next_read_area(owiod->buf, &writepos, &writelen);
	    LeaveCriticalSection(&wiod->lock);
	    rvb = WriteFile(owiod->ioh, writepos, writelen, &nwrite, NULL);
	    EnterCriticalSection(&wiod->lock);
	    if (!rvb) {
		if (GetLastError() == ERROR_OPERATION_ABORTED)
		     /*
		      * We got a CancelSynchronousIo().  We are
		      * probably being shut down, but don't handle it
		      * as an error.
		      */
		    goto continue_loop;
		goto out_err;
	    }

	    if (!owiod->do_flush) {
		gensio_circbuf_data_removed(owiod->buf, nwrite);

		if (!wiod->write.ready && !wiod->in_handlers_clear) {
		    wiod->write.ready = TRUE;
		    queue_iod(wiod);
		}
	    }
	} else {
	    LeaveCriticalSection(&wiod->lock);
	    rvw = WaitForSingleObject(owiod->wakeh, INFINITE);
	    EnterCriticalSection(&wiod->lock);
	    if (rvw == WAIT_FAILED)
		goto out_err;
	}
    continue_loop:
	if (wiod->done)
	    break;
	if (owiod->do_flush) {
	    gensio_circbuf_reset(owiod->buf);
	    owiod->do_flush = FALSE;
	}
    }
    LeaveCriticalSection(&wiod->lock);

    return 0;

 out_err:
    rvw = GetLastError();
    if (!wiod->werr) {
	wiod->write.ready = TRUE;
	wiod->werr = rvw;
	queue_iod(wiod);
    }
    LeaveCriticalSection(&wiod->lock);
    return 0;
}

static int
win_oneway_bufcount(struct gensio_iod_win *wiod, int whichbuf, gensiods *count)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr)
	*count = 0;
    else if ((wiod->fd == 0 && whichbuf == GENSIO_IN_BUF) ||
	     (wiod->fd == 1 && whichbuf == GENSIO_OUT_BUF))
	*count = gensio_circbuf_datalen(owiod->buf);
    else
	*count = 0;
    LeaveCriticalSection(&wiod->lock);
    return 0;
}

static int
win_oneway_close(struct gensio_iod_win *wiod, bool force)
{
    int rv = 0;
    gensiods count;

    EnterCriticalSection(&wiod->lock);
    if (!force) {
	rv = win_oneway_bufcount(wiod, GENSIO_OUT_BUF, &count);
	if (!rv && count > 0) {
	    rv = GE_INPROGRESS;
	    goto out;
	}
    }
    wiod->closed = TRUE;
    if (!wiod->err)
	wiod->err = GE_LOCALCLOSED;
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static void
win_iod_oneway_shutdown(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);

    /* This sucks, see notes at beginning of oneway section. */
    assert(SetEvent(owiod->wakeh));
    CancelSynchronousIo(wiod->threadh);
    while (WaitForSingleObject(wiod->threadh, 1) == WAIT_TIMEOUT) {
	assert(SetEvent(owiod->wakeh));
	CancelSynchronousIo(wiod->threadh);
    }
    wiod->threadh = NULL;
    if (owiod->ioh) {
	CloseHandle(owiod->ioh);
	owiod->ioh = NULL;
    }
}

static void
win_oneway_flush(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);

    if (owiod->readable) /* output only */
	return;
    EnterCriticalSection(&wiod->lock);
    if (!wiod->err && !wiod->werr) {
	owiod->do_flush = TRUE;
	assert(SetEvent(owiod->wakeh));
	CancelSynchronousIo(wiod->threadh);
    }
    LeaveCriticalSection(&wiod->lock);
}

static int
win_oneway_write(struct gensio_iod_win *wiod,
		const struct gensio_sg *sg, gensiods sglen,
		gensiods *rcount)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);
    gensiods count = 0;
    int rv = 0;

    EnterCriticalSection(&wiod->lock);
    if (owiod->readable) {
	rv = GE_NOTSUP;
	goto out_err;
    }
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out_err;
    }
    if (owiod->do_flush)
	goto out;
    gensio_circbuf_sg_write(owiod->buf, sg, sglen, &count);
    wiod->write.ready = (gensio_circbuf_room_left(owiod->buf) > 0
			 || wiod->err || wiod->werr);
    if (count)
	assert(SetEvent(owiod->wakeh));
 out:
    if (rcount)
	*rcount = count;
 out_err:
    LeaveCriticalSection(&wiod->lock);
    return rv;
}

static int
win_oneway_read(struct gensio_iod_win *wiod,
	       void *ibuf, gensiods buflen, gensiods *rcount)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);
    gensiods count = 0;
    BOOL was_full;
    int rv = 0;

    EnterCriticalSection(&wiod->lock);
    if (!owiod->readable) {
	rv = GE_NOTSUP;
	goto out_err;
    }
    if (gensio_circbuf_datalen(owiod->buf) == 0 && (wiod->err || wiod->werr)) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out_err;
    }

    was_full = gensio_circbuf_room_left(owiod->buf) == 0;
    gensio_circbuf_read(owiod->buf, ibuf, buflen, &count);
    wiod->read.ready = (gensio_circbuf_datalen(owiod->buf) > 0
			|| wiod->err || wiod->werr);
    if (was_full && count)
	assert(SetEvent(owiod->wakeh));
    if (rcount)
	*rcount = count;
 out_err:
    LeaveCriticalSection(&wiod->lock);
    return rv;
}

static void
win_iod_oneway_wake(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);

    assert(SetEvent(owiod->wakeh));
}

static void
win_iod_oneway_clean(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);

    if (owiod->ioh) {
	CloseHandle(owiod->ioh);
	owiod->ioh = NULL;
    }
    if (owiod->wakeh) {
	CloseHandle(owiod->wakeh);
	owiod->wakeh = NULL;
    }
    if (owiod->buf) {
	gensio_circbuf_free(owiod->buf);
	owiod->buf = NULL;
    }
}

static int
win_iod_oneway_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);
    struct gensio_os_funcs* o = wiod->iod.f;

    owiod->buf = gensio_circbuf_alloc(o, 2048);
    if (!owiod->buf)
	return GE_NOMEM;

    owiod->wakeh = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!owiod->wakeh) {
	gensio_circbuf_free(owiod->buf);
	owiod->buf = NULL;
	return GE_NOMEM;
    }

    if (owiod->readable) {
	wiod->threadfunc = win_oneway_in_thread;
    } else {
	wiod->threadfunc = win_oneway_out_thread;
	wiod->write.ready = TRUE;
    }

    wiod->clean = win_iod_oneway_clean;
    wiod->wake = win_iod_oneway_wake;
    wiod->check = win_iod_check;
    wiod->shutdown = win_iod_oneway_shutdown;
    return 0;
}

struct gensio_iod_win_console {
    struct gensio_iod_win_oneway owiod;

    struct stdio_mode *mode;
};

#define owiod_to_winconsole(ow) gensio_container_of(ow,			    \
					       struct gensio_iod_win_console, \
					       owiod)

static int
win_console_makeraw(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);
    struct gensio_iod_win_console *cowiod = owiod_to_winconsole(owiod);
    int rv;

    if (owiod->readable) {
	rv = gensio_win_stdin_makeraw(wiod->iod.f, owiod->ioh, &cowiod->mode);
	if (!rv)
	    wiod->is_raw = TRUE;
    } else {
	rv = gensio_win_stdout_makeraw(wiod->iod.f, owiod->ioh, &cowiod->mode);
	if (!rv)
	    wiod->is_raw = TRUE;
    }
    return rv;
}

static int
win_console_close(struct gensio_iod_win *wiod, bool force)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);
    struct gensio_iod_win_console *cowiod = owiod_to_winconsole(owiod);

    gensio_win_stdio_cleanup(wiod->iod.f, owiod->ioh, &cowiod->mode);
    return win_oneway_close(wiod, force);
}

static int
win_iod_console2_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);
    BOOL readable = *((BOOL *) cb_data);

    owiod->readable = readable;
    owiod->ioh = (HANDLE) wiod->fd;
    owiod->is_console = true;
    return win_iod_oneway_init(wiod, NULL);
}

static int
win_iod_console_init(struct gensio_iod_win *wiod, void *cb_data)
{
    HANDLE h;
    BOOL readable;
    int rv;

    if (wiod->fd > 1 || wiod->fd < 0)
	return GE_INVAL;

    if (wiod->fd == 0) { /* stdin */
	h = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, 0,
			  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	readable = TRUE;
    } else {
	h = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, 0,
			  NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	readable = FALSE;
    }
    if (h == INVALID_HANDLE_VALUE)
	return gensio_os_err_to_err(wiod->iod.f, GetLastError());

    wiod->fd = (intptr_t) h;
    rv = win_iod_console2_init(wiod, &readable);

    if (rv)
	CloseHandle(h);
    return rv;
}

struct gensio_iod_win_pipe
{
    struct gensio_iod_win_oneway owiod;
};

#define owiod_to_winpipe(ow) gensio_container_of(ow,			\
					     struct gensio_iod_win_pipe,\
					     owiod)
static int
win_iod_read_pipe_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);

    owiod->readable = TRUE;

    return win_iod_oneway_init(wiod, cb_data);
}

static int
win_iod_write_pipe_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);

    owiod->readable = FALSE;

    return win_iod_oneway_init(wiod, cb_data);
}

static int
win_iod_pipe_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_oneway *owiod = wiod_to_win_oneway(wiod);
    DWORD pflags;
    BOOL readable;

    owiod->ioh = (HANDLE) wiod->fd;
    if (cb_data) {
	readable = *((BOOL *) cb_data);
    } else {
	if (!GetNamedPipeInfo(owiod->ioh, &pflags, NULL, NULL, NULL))
	    return gensio_os_err_to_err(wiod->iod.f, GetLastError());
	readable = pflags & PIPE_SERVER_END;
    }
    if (readable)
	return win_iod_read_pipe_init(wiod, cb_data);
    else
	return win_iod_write_pipe_init(wiod, cb_data);
}

/*
 * bidirectional I/O handle
 */
struct gensio_iod_win_twoway {
    struct gensio_iod_win wiod;

    HANDLE wakeh;
    HANDLE ioh;

    /*
     * An optional extra handle that will be added to the object wait.
     * If it is set, call extrah_func.
     */
    HANDLE extrah;
    DWORD (*extrah_func)(struct gensio_iod_win_twoway *);

    BOOL readable;
    BOOL writeable;

    struct gensio_circbuf *inbuf;
    struct gensio_circbuf *outbuf;

    BOOL do_flush; /* Tell thread to flush output data. */
};

#define wiod_to_win_twoway(w) gensio_container_of(w,			\
					       struct gensio_iod_win_twoway, \
					       wiod)

static DWORD WINAPI
win_twoway_thread(LPVOID data)
{
    struct gensio_iod_win_twoway *twiod = data;
    struct gensio_iod_win *wiod = &twiod->wiod;
    DWORD rvw, nwait;
    BOOL reading = FALSE, writing = FALSE;
    OVERLAPPED reado, writeo;
    HANDLE waiters[4];

    memset(&reado, 0, sizeof(reado));
    memset(&writeo, 0, sizeof(writeo));

    EnterCriticalSection(&wiod->lock);
    reado.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!reado.hEvent)
	goto out_err;
    writeo.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!writeo.hEvent)
	goto out_err;

    waiters[0] = twiod->wakeh;
    waiters[1] = reado.hEvent;
    waiters[2] = writeo.hEvent;
    nwait = 3;
    if (twiod->extrah)
	waiters[nwait++] = twiod->extrah;

    for(;;) {
	BOOL rvb;

	if (!reading && gensio_circbuf_room_left(twiod->inbuf) && !wiod->werr
			&& twiod->readable) {
	    gensiods readsize;
	    void *readpos;

	    gensio_circbuf_next_write_area(twiod->inbuf, &readpos, &readsize);
	    reading = TRUE;
	    LeaveCriticalSection(&wiod->lock);
	    rvb = ReadFile(twiod->ioh, readpos, readsize, NULL, &reado);
	    EnterCriticalSection(&wiod->lock);
	    if (!rvb) {
		rvw = GetLastError();
		if (rvw != ERROR_IO_PENDING)
		    goto out_err_noget;
	    }
	} else if (!writing && gensio_circbuf_datalen(twiod->outbuf) > 0 &&
		   !wiod->werr && twiod->writeable) {
	    gensiods writelen;
	    void *writepos;

	    gensio_circbuf_next_read_area(twiod->outbuf, &writepos, &writelen);
	    writing = TRUE;
	    LeaveCriticalSection(&wiod->lock);
	    rvb = WriteFile(twiod->ioh, writepos, writelen, NULL, &writeo);
	    EnterCriticalSection(&wiod->lock);
	    if (!rvb) {
		rvw = GetLastError();
		if (rvw != ERROR_IO_PENDING)
		    goto out_err_noget;
	    }
	} else {
	    LeaveCriticalSection(&wiod->lock);
	    rvw = WaitForMultipleObjects(nwait, waiters, FALSE, INFINITE);
	    EnterCriticalSection(&wiod->lock);
	    if (rvw == WAIT_FAILED)
		goto out_err;

	    if (rvw == WAIT_OBJECT_0 + 1) {
		DWORD nread = 0;

		/* Read event. */
		if (!GetOverlappedResult(twiod->ioh, &reado, &nread, FALSE))
		    goto out_err;

		if (nread > 0) {
		    gensio_circbuf_data_added(twiod->inbuf, nread);
		    if (!wiod->read.ready) {
			wiod->read.ready = TRUE;
			queue_iod(wiod);
		    }
		}
		reading = FALSE;
	    } else if (rvw == WAIT_OBJECT_0 + 2 ||
		       rvw == ERROR_OPERATION_ABORTED) {
		DWORD nwrite = 0;

		/* Write event. */
		if (!GetOverlappedResult(twiod->ioh, &writeo, &nwrite, FALSE))
		    goto out_err;

		if (twiod->do_flush || nwrite > 0) {
		    if (twiod->do_flush) {
			gensio_circbuf_reset(twiod->outbuf);
			twiod->do_flush = FALSE;
		    } else {
			gensio_circbuf_data_removed(twiod->outbuf, nwrite);
		    }

		    if (!wiod->write.ready && !wiod->in_handlers_clear) {
			wiod->write.ready = TRUE;
			queue_iod(wiod);
		    }
		}
		writing = FALSE;
	    } else if (rvw == WAIT_OBJECT_0 + 3) {
		rvw = twiod->extrah_func(twiod);
		if (rvw)
		    goto out_err_noget;
	    }
	}
	if (wiod->done)
	    break;
	if (twiod->do_flush) {
	    if (writing) {
		CancelIoEx(twiod->ioh, &writeo);
	    } else {
		gensio_circbuf_reset(twiod->outbuf);
		twiod->do_flush = FALSE;
	    }
	}
    }
 exitth:
    if (reading)
	CancelIoEx(twiod->ioh, &reado);
    if (writing)
	CancelIoEx(twiod->ioh, &writeo);
    if (reado.hEvent)
	CloseHandle(reado.hEvent);
    if (writeo.hEvent)
	CloseHandle(writeo.hEvent);

    if (!twiod->readable)
	wiod->read.ready = TRUE;
    if (!twiod->writeable)
	wiod->write.ready = TRUE;
    queue_iod(wiod);
    LeaveCriticalSection(&wiod->lock);

    return 0;

 out_err:
    rvw = GetLastError();
 out_err_noget:
    if (!wiod->werr) {
	wiod->read.ready = TRUE;
	wiod->write.ready = TRUE;
	wiod->werr = rvw;
	queue_iod(wiod);
    }
    goto exitth;
}

/* Must be called with wiod lock held. */
static int
win_twoway_close(struct gensio_iod_win *wiod) {
    wiod->closed = TRUE;
    if (!wiod->err)
	wiod->err = GE_LOCALCLOSED;

    return 0;
}

static int
win_twoway_bufcount(struct gensio_iod_win *wiod, int whichbuf, gensiods *count)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr)
	*count = 0;
    else if (twiod->readable && whichbuf == GENSIO_IN_BUF)
	*count = gensio_circbuf_datalen(twiod->inbuf);
    else if (twiod->writeable && whichbuf == GENSIO_OUT_BUF)
	*count = gensio_circbuf_datalen(twiod->outbuf);
    else
	*count = 0;
    LeaveCriticalSection(&wiod->lock);
    return 0;
}

static void
win_twoway_flush(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);

    if (wiod->fd != 1) /* stdout only */
	return;
    EnterCriticalSection(&wiod->lock);
    if (!wiod->err && !wiod->werr) {
	twiod->do_flush = TRUE;
	assert(SetEvent(twiod->wakeh));
    }
    LeaveCriticalSection(&wiod->lock);
}

static int
win_twoway_write(struct gensio_iod_win *wiod,
		 const struct gensio_sg *sg, gensiods sglen,
		 gensiods *rcount)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);
    gensiods count = 0;
    int rv = 0;

    EnterCriticalSection(&wiod->lock);
    if (!twiod->writeable) {
	wiod->err = GE_NOTSUP;
	goto out;
    }
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out_err;
    }
    if (twiod->do_flush)
	goto out;
    gensio_circbuf_sg_write(twiod->outbuf, sg, sglen, &count);
    wiod->write.ready = (gensio_circbuf_room_left(twiod->outbuf) > 0
			 || wiod->err || wiod->werr);
    if (!wiod->write.ready)
	wiod->wake(wiod);
    LeaveCriticalSection(&wiod->lock);
    if (count)
	assert(SetEvent(twiod->wakeh));
 out:
    if (rcount)
	*rcount = count;
 out_err:
    return rv;
}

static int
win_twoway_read(struct gensio_iod_win *wiod,
		void *ibuf, gensiods buflen, gensiods *rcount)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);
    gensiods count = 0;
    BOOL was_full;
    int rv = 0;

    EnterCriticalSection(&wiod->lock);
    if (!twiod->readable) {
	wiod->err = GE_NOTSUP;
	goto out;
    }
    if (gensio_circbuf_datalen(twiod->inbuf) && (wiod->err || wiod->werr)) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }

    was_full = gensio_circbuf_room_left(twiod->inbuf) == 0;
    gensio_circbuf_read(twiod->inbuf, ibuf, buflen, &count);
    wiod->read.ready = (gensio_circbuf_datalen(twiod->inbuf) > 0
			|| wiod->err || wiod->werr);
    if (!wiod->read.ready)
	wiod->wake(wiod);
    if (was_full && count)
	assert(SetEvent(twiod->wakeh));
 out:
    LeaveCriticalSection(&wiod->lock);
    if (rcount)
	*rcount = count;
    return rv;
}

static void
win_iod_twoway_wake(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);

    assert(SetEvent(twiod->wakeh));
}

static void
win_iod_twoway_clean(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);

    if (twiod->wakeh)
	CloseHandle(twiod->wakeh);
    if (twiod->inbuf) {
	gensio_circbuf_free(twiod->inbuf);
	twiod->inbuf = NULL;
    }

    if (twiod->outbuf) {
	gensio_circbuf_free(twiod->outbuf);
	twiod->outbuf = NULL;
    }
}

static int
win_iod_twoway_init(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);
    struct gensio_os_funcs *o = wiod->iod.f;

    twiod->inbuf = gensio_circbuf_alloc(o, 2048);
    if (!twiod->inbuf)
	return GE_NOMEM;

    twiod->outbuf = gensio_circbuf_alloc(o, 2048);
    if (!twiod->outbuf) {
	gensio_circbuf_free(twiod->inbuf);
	twiod->inbuf = NULL;
	return GE_NOMEM;
    }
    wiod->write.ready = TRUE;

    twiod->wakeh = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!twiod->wakeh) {
	gensio_circbuf_free(twiod->outbuf);
	twiod->outbuf = NULL;
	gensio_circbuf_free(twiod->inbuf);
	twiod->inbuf = NULL;
	return GE_NOMEM;
    }

    return 0;
}

struct gensio_iod_win_dev
{
    struct gensio_iod_win_twoway twiod;

    char *name;

    BOOL is_serial_port;

    struct gensio_win_commport *cominfo;
};

#define twiod_to_windev(tw) gensio_container_of(tw,			\
					    struct gensio_iod_win_dev, \
					    twiod)
static int
win_dev_control(struct gensio_iod_win *wiod, int op, bool get, intptr_t val)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);
    struct gensio_iod_win_dev *dtwiod = twiod_to_windev(twiod);
    struct gensio_os_funcs *o = wiod->iod.f;
    int rv = 0;

    if (!dtwiod->is_serial_port)
	return GE_NOTSUP;

    EnterCriticalSection(&wiod->lock);
    rv = gensio_win_commport_control(o, op, get, val, &dtwiod->cominfo,
				     twiod->ioh);
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static DWORD
win_dev_break_handler(struct gensio_iod_win_twoway *twiod)
{
    struct gensio_iod_win_dev *dtwiod = twiod_to_windev(twiod);

    return gensio_win_commport_break_done(twiod->wiod.iod.f, twiod->ioh,
					  &dtwiod->cominfo);
}

static void
win_iod_dev_clean(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);
    struct gensio_iod_win_dev *dtwiod = twiod_to_windev(twiod);

    win_iod_twoway_clean(wiod);
    if (dtwiod->name)
	wiod->iod.f->free(wiod->iod.f, dtwiod->name);
}

static int
win_dev_close(struct gensio_iod_win *wiod, bool force)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);
    struct gensio_iod_win_dev *dtwiod = twiod_to_windev(twiod);
    int rv;
    gensiods count;

    EnterCriticalSection(&wiod->lock);
    if (!force) {
	rv = win_twoway_bufcount(wiod, GENSIO_OUT_BUF, &count);
	if (!rv && count > 0) {
	    rv = GE_INPROGRESS;
	    goto out;
	}
    }
    rv = win_twoway_close(wiod);
    if (twiod->ioh) {
	twiod->extrah = NULL;
	gensio_win_cleanup_commport(wiod->iod.f, twiod->ioh,
				    &dtwiod->cominfo);
	CloseHandle(twiod->ioh);
    }
 out:
    LeaveCriticalSection(&wiod->lock);
    return rv;
}

static int
win_iod_dev_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_twoway *twiod = wiod_to_win_twoway(wiod);
    struct gensio_iod_win_dev *dtwiod = twiod_to_windev(twiod);
    struct gensio_os_funcs *o = wiod->iod.f;
    int rv;
    COMMPROP props;
    struct win_init_info *info = cb_data;

    rv = win_iod_twoway_init(wiod);
    if (rv)
	return rv;

    rv = GE_NOMEM;
    dtwiod->name = gensio_alloc_sprintf(o, "\\\\.\\%s", info->name);
    if (!dtwiod->name)
	goto out_err;

    twiod->ioh = CreateFileA(dtwiod->name, GENERIC_READ | GENERIC_WRITE,
		   	     0, NULL,
			     OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (twiod->ioh == INVALID_HANDLE_VALUE)
	goto out_err_conv;

    if (GetFileType(twiod->ioh) != FILE_TYPE_CHAR) {
	rv = GE_NOTSUP;
	goto out_err;
    }
    memset(&props, 0, sizeof(props));
    if (!GetCommProperties(twiod->ioh, &props))
	goto out_err_conv;

    switch (props.dwProvSubType) {
    case PST_MODEM:
    case PST_RS232:
    case PST_RS422:
    case PST_RS423:
    case PST_RS449:
	dtwiod->is_serial_port = TRUE;
	twiod->readable = TRUE;
	twiod->writeable = TRUE;
	break;
    case PST_PARALLELPORT:
	dtwiod->is_serial_port = FALSE;
	twiod->writeable = TRUE;
	twiod->readable = FALSE;
	break;
    default:
	rv = GE_NOTSUP;
	goto out_err;
    }

    if (dtwiod->is_serial_port) {
	rv = gensio_win_setup_commport(o, twiod->ioh, &dtwiod->cominfo,
				       &twiod->extrah);
	if (rv)
	    goto out_err;
	twiod->extrah_func = win_dev_break_handler;
    }

    wiod->threadfunc = win_twoway_thread;

    wiod->clean = win_iod_dev_clean;
    wiod->wake = win_iod_twoway_wake;
    wiod->check = win_iod_check;

    return 0;

 out_err_conv:
    rv = gensio_os_err_to_err(o, GetLastError());
 out_err:
    win_iod_dev_clean(wiod);
    return rv;
}

/*
 * A pty iod doesn't work like the other ones.  It doesn't use any of
 * the iod services.  Instead, it has two pipe iods for the input and
 * output of the child process and this basically routes data and
 * event between those pipes and the user.
 */
struct gensio_iod_win_pty
{
    struct gensio_iod_win wiod;

    struct gensio_iod_win *write; /* Data (input) sent to the child */
    struct gensio_iod_win *read; /* Data (output) from the child */
    HANDLE child;
    HPCON ptyh;
    HANDLE control; /* Used to control a gensio_pty_helper. */
    HANDLE child_in;
    HANDLE child_out;
    HANDLE watch_thread;
    DWORD watch_thread_id;
    HANDLE watch_start;

    unsigned int clearcount;

    const char **argv;
    const char **env;
    char *start_dir;
};

#define wiod_to_win_pty(w) gensio_container_of(w,			  \
					       struct gensio_iod_win_pty, \
					       wiod)

static int
win_pty_write(struct gensio_iod_win *wiod,
	      const struct gensio_sg *sg, gensiods sglen,
	      gensiods *rcount)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_iod_win_pty *piod = wiod_to_win_pty(wiod);
    int rv = 0;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out_err;
    }
    rv = o->write(&piod->write->iod, sg, sglen, rcount);
    if (rv)
	wiod->err = rv;
 out_err:
    LeaveCriticalSection(&wiod->lock);
    return rv;
}

static int
win_pty_read(struct gensio_iod_win *wiod,
	     void *ibuf, gensiods buflen, gensiods *rcount)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_iod_win_pty *piod = wiod_to_win_pty(wiod);
    int rv = 0;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err) {
	rv = wiod->err;
	goto out;
    }
    rv = o->read(&piod->read->iod, ibuf, buflen, rcount);
    if (rv)
	wiod->err = rv;
 out:
    LeaveCriticalSection(&wiod->lock);
    return rv;
}

static void
win_pty_set_read_handler(struct gensio_iod_win *wiod, bool enable)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_iod_win_pty *piod = wiod_to_win_pty(wiod);

    EnterCriticalSection(&wiod->lock);
    o->set_read_handler(&piod->read->iod, enable);
    LeaveCriticalSection(&wiod->lock);
}

static void
win_pty_set_write_handler(struct gensio_iod_win *wiod, bool enable)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_iod_win_pty *piod = wiod_to_win_pty(wiod);

    EnterCriticalSection(&wiod->lock);
    o->set_write_handler(&piod->write->iod, enable);
    LeaveCriticalSection(&wiod->lock);
}

static void
win_pty_set_except_handler(struct gensio_iod_win *wiod, bool enable)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_iod_win_pty *piod = wiod_to_win_pty(wiod);

    EnterCriticalSection(&wiod->lock);
    o->set_except_handler(&piod->read->iod, enable);
    o->set_except_handler(&piod->write->iod, enable);
    LeaveCriticalSection(&wiod->lock);
}

static int
win_pty_shutdown(struct gensio_iod_win_pty *piod, bool force)
{
    struct gensio_iod_win *wiod = &piod->wiod;
    struct gensio_iod *iod;
    int rv = 0;

    if (wiod->closed)
	return 0;

    wiod->closed = TRUE;
    if (piod->write) {
	iod = &piod->write->iod;
	rv = i_win_close(&iod, force);
	if (rv)
	    return rv;;
	piod->write = NULL;
    }
    if (piod->read) {
	iod = &piod->read->iod;
	rv = i_win_close(&iod, force);
	if (rv)
	    return rv;
	piod->read = NULL;
    }
    return 0;
}

static int
win_pty_close(struct gensio_iod_win *wiod, bool force)
{
    struct gensio_iod_win_pty *piod = wiod_to_win_pty(wiod);
    int rv;

    EnterCriticalSection(&wiod->lock);
    rv = win_pty_shutdown(piod, force);
    if (rv)
	goto out;
    if (piod->child)
	TerminateProcess(piod->child, 0);
    if (piod->watch_thread) {
	LeaveCriticalSection(&wiod->lock);
	WaitForSingleObject(piod->watch_thread, INFINITE);
	EnterCriticalSection(&wiod->lock);
	CloseHandle(piod->watch_thread);
	piod->watch_thread = NULL;
    }
    if (piod->child) {
	CloseHandle(piod->child);
	piod->child = NULL;
    }
 out:
    LeaveCriticalSection(&wiod->lock);
    return rv;
}

/*
 * Wait for the child process to die and close the pty and files when
 * that happens.  This is necessary because the read will not wake up
 * when the child dies unless the pty is closed.
 */
static DWORD WINAPI
win_pty_watch_thread(LPVOID data)
{
    struct gensio_iod_win_pty *piod = data;
    struct gensio_iod_win *wiod = &piod->wiod;

    WaitForSingleObject(piod->watch_start, INFINITE);

    EnterCriticalSection(&wiod->lock);
    /* If child is not set, the thread start failed, just quit. */
    if (piod->child) {
	LeaveCriticalSection(&wiod->lock);
	WaitForSingleObject(piod->child, INFINITE);
	EnterCriticalSection(&wiod->lock);
	if (piod->ptyh) {
	    ClosePseudoConsole(piod->ptyh);
	    piod->ptyh = NULL;
	}
	if (piod->control) {
	    CloseHandle(piod->control);
	    piod->control = NULL;
	}
    }
    LeaveCriticalSection(&wiod->lock);
    return 0;
}

struct pty_helper_cmd {
    unsigned int cmd;
    unsigned int size;
    union {
	struct {
	    int x;
	    int y;
	} resize;
    };
};
#define PTY_RESIZE 1

static int
win_pty_control(struct gensio_iod_win *wiod, int op, bool get, intptr_t val)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_iod_win_pty *piod = wiod_to_win_pty(wiod);
    int err = 0;

    const char **nargv;

    if (get) {
	if (op == GENSIO_IOD_CONTROL_PID) {
	    if (!piod->child)
		return GE_NOTREADY;
	    *((intptr_t *) val) = (intptr_t) piod->child;
	    return 0;
	}
	return GE_NOTSUP;
    }

    switch (op) {
    case GENSIO_IOD_CONTROL_ARGV:
	err = gensio_argv_copy(o, (const char **) val, NULL, &nargv);
	if (err)
	    return err;
	if (piod->argv)
	    gensio_argv_free(o, piod->argv);
	piod->argv = nargv;
	return 0;

    case GENSIO_IOD_CONTROL_ENV:
	err = gensio_argv_copy(o, (const char **) val, NULL, &nargv);
	if (err)
	    return err;
	if (piod->env)
	    gensio_argv_free(o, piod->env);
	piod->env = nargv;
	return 0;

    case GENSIO_IOD_CONTROL_START:
	EnterCriticalSection(&wiod->lock);
	if (piod->child) {
	    err = GE_INUSE;
	} else {
	    piod->watch_thread = CreateThread(NULL, 0, win_pty_watch_thread,
					      piod, 0, &piod->watch_thread_id);
	    if (!piod->watch_thread) {
		err = gensio_os_err_to_err(o, GetLastError());
	    } else {
		err = gensio_win_pty_start(o, piod->ptyh,
					   &piod->child_in, &piod->child_out,
					   piod->argv,
					   piod->env, piod->start_dir,
					   &piod->child, &piod->control);
		assert(SetEvent(piod->watch_start));
		if (err) {
		    HANDLE wthread = piod->watch_thread;

		    piod->watch_thread = NULL;
		    LeaveCriticalSection(&wiod->lock);
		    WaitForSingleObject(wthread, INFINITE);
		    CloseHandle(wthread);
		    return err;
		}
	    }
	}
	LeaveCriticalSection(&wiod->lock);
	return err;

    case GENSIO_IOD_CONTROL_STOP:
	EnterCriticalSection(&wiod->lock);
	err = win_pty_shutdown(piod, false);
	LeaveCriticalSection(&wiod->lock);
	return err;

    case GENSIO_IOD_CONTROL_WIN_SIZE: {
	struct gensio_winsize *gwin = (struct gensio_winsize *) val;
	if (piod->control) {
	    struct pty_helper_cmd cmd;
	    DWORD len = 0;

	    cmd.cmd = PTY_RESIZE;
	    cmd.size = sizeof(cmd);
	    cmd.resize.x = gwin->ws_col;
	    cmd.resize.y = gwin->ws_row;

	    WriteFile(piod->control, &cmd, sizeof(cmd), &len, FALSE);
	} else {
	    COORD size;
	    HRESULT hr;

	    size.Y = gwin->ws_row;
	    size.X = gwin->ws_col;
	    hr = ResizePseudoConsole(piod->ptyh, size);
	    if (hr != S_OK) {
		if (HRESULT_FACILITY(hr) == FACILITY_WIN32)
		    err = gensio_os_err_to_err(o, HRESULT_CODE(hr));
		else
		    err = gensio_os_err_to_err(o, hr); /* Force an OS_ERR. */
	    }
	}
	return err;
    }

    case GENSIO_IOD_CONTROL_START_DIR: {
	char *dir = (char *) val;

	if (dir) {
	    dir = gensio_strdup(o, dir);
	    if (!dir)
		return GE_NOMEM;
	}

	if (piod->start_dir)
	    o->free(o, piod->start_dir);
	piod->start_dir = dir;
	return 0;
    }

    default:
	return GE_NOTSUP;
    }
}

static void win_pty_read_handler(struct gensio_iod *iod, void *cb_data)
{
    struct gensio_iod_win_pty *piod = cb_data;

    piod->wiod.read.handler(&piod->wiod.iod, piod->wiod.cb_data);
}

static void win_pty_write_handler(struct gensio_iod *iod, void *cb_data)
{
    struct gensio_iod_win_pty *piod = cb_data;

    piod->wiod.write.handler(&piod->wiod.iod, piod->wiod.cb_data);
}

static void win_pty_except_handler(struct gensio_iod *iod, void *cb_data)
{
    struct gensio_iod_win_pty *piod = cb_data;

    piod->wiod.except.handler(&piod->wiod.iod, piod->wiod.cb_data);
}

static void win_pty_cleared_handler(struct gensio_iod *iod, void *cb_data)
{
    struct gensio_iod_win_pty *piod = cb_data;
    struct gensio_iod_win *wiod = &piod->wiod;
    void (*cleared)(struct gensio_iod *iod, void *cb_data) = NULL;

    EnterCriticalSection(&wiod->lock);
    assert(piod->clearcount > 0);
    piod->clearcount--;
    if (piod->clearcount == 0) {
	cleared = wiod->cleared_handler;
	wiod->in_handlers_clear = false;
    }
    LeaveCriticalSection(&wiod->lock);
    if (cleared)
	cleared(&wiod->iod, wiod->cb_data);
}

static void
win_pty_clear_fd_handlers(struct gensio_iod_win *wiod)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_iod_win_pty *piod = wiod_to_win_pty(wiod);

    EnterCriticalSection(&wiod->lock);
    if (piod->read) {
	o->clear_fd_handlers(&piod->read->iod);
	piod->clearcount++;
    }
    if (piod->write) {
	o->clear_fd_handlers(&piod->write->iod);
	piod->clearcount++;
    }
    LeaveCriticalSection(&wiod->lock);
}

static void
win_iod_pty_clean(struct gensio_iod_win *wiod)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_iod_win_pty *piod = wiod_to_win_pty(wiod);

    if (piod->child_in)
	CloseHandle(piod->child_in);
    if (piod->child_out)
	CloseHandle(piod->child_out);
    if (piod->read)
	o->release_iod(&piod->read->iod);
    if (piod->write)
	o->release_iod(&piod->write->iod);
    if (piod->child)
	CloseHandle(piod->child);
    if (piod->ptyh)
	ClosePseudoConsole(piod->ptyh);
    if (piod->control)
	CloseHandle(piod->control);
    if (piod->watch_start)
	CloseHandle(piod->watch_start);
    if (piod->argv)
	gensio_argv_free(o, piod->argv);
    if (piod->env)
	gensio_argv_free(o, piod->env);
    if (piod->start_dir)
	o->free(o, piod->start_dir);
}

static int
win_iod_pty_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_os_funcs *o = wiod->iod.f;
    struct gensio_iod_win_pty *piod = wiod_to_win_pty(wiod);
    HANDLE readh = NULL, writeh = NULL;
    BOOL readable;
    int err;

    wiod->clean = win_iod_pty_clean;
    wiod->set_read_handler = win_pty_set_read_handler;
    wiod->set_write_handler = win_pty_set_write_handler;
    wiod->set_except_handler = win_pty_set_except_handler;
    wiod->clear_fd_handlers = win_pty_clear_fd_handlers;

    piod->watch_start = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!piod->watch_start) {
	err = gensio_os_err_to_err(o, GetLastError());
	goto out_err;
    }

    err = gensio_win_pty_alloc(o, &readh, &writeh,
			       &piod->child_in, &piod->child_out, &piod->ptyh);
    if (err)
	goto out_err;

    readable = TRUE;
    err = win_alloc_iod(o, sizeof(struct gensio_iod_win_pipe),
			(intptr_t) readh,
			GENSIO_IOD_PIPE, win_iod_pipe_init,
			&readable, &piod->read);
    if (err)
	goto out_err;
    readh = NULL;
    err = win_set_fd_handlers(&piod->read->iod, piod,
			      win_pty_read_handler, NULL,
			      win_pty_except_handler, win_pty_cleared_handler);
    if (err)
	goto out_err;

    readable = FALSE;
    err = win_alloc_iod(o, sizeof(struct gensio_iod_win_pipe),
			(intptr_t) writeh,
			GENSIO_IOD_PIPE, win_iod_pipe_init,
			&readable, &piod->write);
    if (err)
	goto out_err;
    writeh = NULL;
    err = win_set_fd_handlers(&piod->write->iod, piod,
			      NULL, win_pty_write_handler,
			      win_pty_except_handler, win_pty_cleared_handler);
    if (err)
	goto out_err;

    return 0;

 out_err:
    if (readh)
	CloseHandle(readh);
    if (writeh)
	CloseHandle(writeh);
    if (piod->watch_start) {
	CloseHandle(piod->watch_start);
	piod->watch_start = NULL;
    }
    return err;
}

static unsigned int win_iod_sizes[NR_GENSIO_IOD_TYPES] = {
    [GENSIO_IOD_SOCKET] = sizeof(struct gensio_iod_win_sock),
    [GENSIO_IOD_CONSOLE] = sizeof(struct gensio_iod_win_console),
    [GENSIO_IOD_FILE] = sizeof(struct gensio_iod_win_file),
    [GENSIO_IOD_PTY] = sizeof(struct gensio_iod_win_pty),
    /*
     * FIXME - no GENSIO_IOD_PIPE support.  The add_iod function
     * doesn't have a way to pass if the handle is read or write, and
     * there's no way to tell from the handle.  If we ever need this,
     * a ... will need to be added to add_iod and the read/write type
     * passed there.
     */
};
typedef int (*win_iod_initfunc)(struct gensio_iod_win *, void *);
static win_iod_initfunc win_iod_init[NR_GENSIO_IOD_TYPES] = {
    [GENSIO_IOD_SOCKET] = win_iod_socket_init,
    [GENSIO_IOD_CONSOLE] = win_iod_console_init,
    [GENSIO_IOD_FILE] = win_iod_file_init,
    [GENSIO_IOD_PTY] = win_iod_pty_init,
};

static int
win_stdio_init(struct gensio_os_funcs *o, intptr_t fd,
	       struct gensio_iod **riod)
{
    int rv;
    struct gensio_iod_win *wiod;
    HANDLE h;
    BOOL readable;

    if (fd > 1 || fd < 0)
	return GE_INVAL;

    if (fd == 0) { /* stdin */
	h = GetStdHandle(STD_INPUT_HANDLE);
	readable = TRUE;
    } else {
	h = GetStdHandle(STD_OUTPUT_HANDLE);
	readable = FALSE;
    }
    if (h == INVALID_HANDLE_VALUE)
	return gensio_os_err_to_err(o, GetLastError());
    /* Per testing, GetStdHandle does not return a duplicate. */
    if (!DuplicateHandle(GetCurrentProcess(),
			 h,
			 GetCurrentProcess(),
			 &h,
			 0, FALSE, DUPLICATE_SAME_ACCESS))
	return gensio_os_err_to_err(o, GetLastError());

    switch (GetFileType(h)) {
    case FILE_TYPE_CHAR:
	rv = win_alloc_iod(o, sizeof(struct gensio_iod_win_console),
			   (intptr_t) h, GENSIO_IOD_CONSOLE,
			   win_iod_console2_init, &readable, &wiod);
	break;

    case FILE_TYPE_DISK:
	rv = win_alloc_iod(o, sizeof(struct gensio_iod_win_file), (intptr_t) h,
			   GENSIO_IOD_FILE, win_iod_file_init,
			   &readable, &wiod);
	break;

    case FILE_TYPE_PIPE:
	rv = win_alloc_iod(o, sizeof(struct gensio_iod_win_pipe), (intptr_t) h,
			   GENSIO_IOD_PIPE, win_iod_pipe_init,
			   &readable, &wiod);
	break;

    default:
	rv = GE_INVAL;
    }

    if (rv)
	CloseHandle(h);
    else
	*riod = &wiod->iod;

    return rv;
}

static int
win_add_iod(struct gensio_os_funcs *o, enum gensio_iod_type type,
	    intptr_t fd, struct gensio_iod **riod)
{
    int rv;
    struct gensio_iod_win *wiod;

    if (type == GENSIO_IOD_STDIO)
	return win_stdio_init(o, fd, riod);

    if (type >= NR_GENSIO_IOD_TYPES || type < 0 || win_iod_sizes[type] == 0)
	return GE_NOTSUP;

    rv = win_alloc_iod(o, win_iod_sizes[type], fd, type,
		       win_iod_init[type], NULL, &wiod);
    if (!rv)
	*riod = &wiod->iod;
    return rv;
}

static void win_release_iod(struct gensio_iod *iod)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_data *d = o->user_data;
    struct gensio_iod_win *wiod = iod_to_win(iod);
    BOOL do_free = FALSE;

    EnterCriticalSection(&wiod->lock);
    wiod->done = TRUE;
    if (wiod->shutdown) {
	LeaveCriticalSection(&wiod->lock);
	wiod->shutdown(wiod);
    } else if (wiod->threadh) {
	wiod->wake(wiod);
	LeaveCriticalSection(&wiod->lock);
	WaitForSingleObject(wiod->threadh, INFINITE);
    } else {
	LeaveCriticalSection(&wiod->lock);
    }

    glock_lock(d);
    if (gensio_list_link_inlist(&wiod->link))
	gensio_list_rm(&d->waiting_iods, &wiod->link);
    gensio_list_rm(&d->all_iods, &wiod->all_link);
    do_free = d->freed && gensio_list_empty(&d->all_iods);
    glock_unlock(d);

    if (wiod->clean)
	wiod->clean(wiod);
    DeleteCriticalSection(&wiod->lock);
    o->free(o, wiod);

    if (do_free)
	win_finish_free(o);
}

static int
win_iod_get_type(struct gensio_iod *iod)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);

    return wiod->type;
}

static int
win_iod_get_fd(struct gensio_iod *iod)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);

    return wiod->fd;
}

static int
win_iod_control(struct gensio_iod *iod, int op, bool get, intptr_t val)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);

    if (wiod->type == GENSIO_IOD_SOCKET) {
	struct gensio_iod_win_sock *siod = wiod_to_winsock(wiod);

	if (op == GENSIO_IOD_CONTROL_IS_CLOSED) {
	    if (!get)
		return GE_NOTSUP;
	    *((bool *) val) = wiod->closed;
	    return 0;
	}

	if (op != GENSIO_IOD_CONTROL_SOCKINFO)
	    return GE_NOTSUP;

	if (get)
	    *((void **) val) = siod->sockinfo;
	else
	    siod->sockinfo = (void *) val;

	return 0;
    }

    if (wiod->type == GENSIO_IOD_DEV)
	return win_dev_control(wiod, op, get, val);

    if (wiod->type == GENSIO_IOD_PTY)
	return win_pty_control(wiod, op, get, val);

    return GE_NOTSUP;
}

static int
win_recv(struct gensio_iod *iod, void *buf, gensiods buflen,
	 gensiods *rcount, int gflags)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_iod_win *wiod = iod_to_win(iod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    wiod->read.ready = FALSE;
    wiod->except.ready = FALSE;
    rv = d->orig_recv(iod, buf, buflen, rcount, gflags);
    wiod->wake(wiod);
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_send(struct gensio_iod *iod,
	 const struct gensio_sg *sg, gensiods sglen,
	 gensiods *rcount, int gflags)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_iod_win *wiod = iod_to_win(iod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    wiod->write.ready = FALSE;
    rv = d->orig_send(iod, sg, sglen, rcount, gflags);
    wiod->wake(wiod);
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_sendto(struct gensio_iod *iod,
	   const struct gensio_sg *sg, gensiods sglen,
	   gensiods *rcount, int gflags,
	   const struct gensio_addr *raddr)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_iod_win *wiod = iod_to_win(iod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    wiod->write.ready = FALSE;
    rv = d->orig_sendto(iod, sg, sglen, rcount, gflags, raddr);
    wiod->wake(wiod);
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_recvfrom(struct gensio_iod *iod, void *buf, gensiods buflen,
	     gensiods *rcount, int flags, struct gensio_addr *addr)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_iod_win *wiod = iod_to_win(iod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    wiod->read.ready = FALSE;
    wiod->except.ready = FALSE;
    rv = d->orig_recvfrom(iod, buf, buflen, rcount, flags, addr);
    wiod->wake(wiod);
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_accept(struct gensio_iod *iod,
	   struct gensio_addr **raddr, struct gensio_iod **newiod)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_iod_win *wiod = iod_to_win(iod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    rv = d->orig_accept(iod, raddr, newiod);
    wiod->read.ready = FALSE;
    wiod->wake(wiod);
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_connect(struct gensio_iod *iod, const struct gensio_addr *addr)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_iod_win *wiod = iod_to_win(iod);
    struct gensio_iod_win_sock *siod = wiod_to_winsock(wiod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->iod.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    rv = d->orig_connect(iod, addr);
    if (rv == 0)
	siod->connected = TRUE;
    wiod->wake(wiod);
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
i_win_close(struct gensio_iod **iodp, bool force)
{
    struct gensio_iod *iod = *iodp;
    struct gensio_iod_win *wiod = iod_to_win(iod);
    struct gensio_os_funcs *o = iod->f;
    int err = 0;

    /* Don't do errtrig on close, it can fail and not cause any issues. */

    if (wiod->type == GENSIO_IOD_SOCKET) {
	struct gensio_iod_win_sock *siod = wiod_to_winsock(wiod);
	EnterCriticalSection(&wiod->lock);
	if (siod->close_state == CL_DONE) {
	    err = 0;
	} else {
	    err = o->close_socket(iod, siod->close_state == CL_CALLED, force);
	    if (err == GE_INPROGRESS) {
		siod->close_state = CL_CALLED;
	    } else {
		wiod->fd = -1;
		siod->close_state = CL_DONE;
	    }
	}
	LeaveCriticalSection(&wiod->lock);
    } else if (wiod->type == GENSIO_IOD_CONSOLE) {
	err = win_console_close(wiod, force);
    } else if (wiod->type == GENSIO_IOD_FILE) {
	struct gensio_iod_win_file *fiod = wiod_to_winfile(wiod);
	CloseHandle(fiod->ioh);
	wiod->read.ready = FALSE;
	wiod->write.ready = FALSE;
    } else if (wiod->type == GENSIO_IOD_PIPE) {
	err = win_oneway_close(wiod, force);
    } else if (wiod->type == GENSIO_IOD_DEV) {
	err = win_dev_close(wiod, force);
    } else if (wiod->type == GENSIO_IOD_PTY) {
	err = win_pty_close(wiod, force);
    } else {
	err = GE_NOTSUP;
    }
    if (!err) {
	win_release_iod(iod);
	*iodp = NULL;
    }
    return err;
}

static int
win_close(struct gensio_iod **iodp)
{
    return i_win_close(iodp, true);
}

static int
win_graceful_close(struct gensio_iod **iodp)
{
    return i_win_close(iodp, false);
}

static int
win_set_non_blocking(struct gensio_iod *iod)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);
    struct gensio_os_funcs *o = iod->f;
    unsigned long flags = 1;
    int rv = 0;

    if (do_errtrig())
	return GE_NOMEM;

    if (wiod->type == GENSIO_IOD_SOCKET) {
	rv = ioctlsocket(wiod->fd, FIONBIO, &flags);
    } else if (wiod->type == GENSIO_IOD_CONSOLE) {
	/* Nothing to do, already non-blocking. */
    } else if (wiod->type == GENSIO_IOD_DEV) {
	/* Nothing to do, already non-blocking. */
    } else if (wiod->type == GENSIO_IOD_PIPE) {
	/* Nothing to do, already non-blocking. */
    } else if (wiod->type == GENSIO_IOD_FILE) {
	/* Nothing to do, already non-blocking. */
    } else if (wiod->type == GENSIO_IOD_PIPE) {
	/* Nothing to do, already non-blocking. */
    } else if (wiod->type == GENSIO_IOD_PTY) {
	/* Nothing to do, already non-blocking. */
    } else {
	return GE_NOTSUP;
    }
    if (rv)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

static int
win_write(struct gensio_iod *iod,
	  const struct gensio_sg *sg, gensiods sglen,
	  gensiods *rcount)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);
    struct gensio_os_funcs *o = iod->f;

    if (wiod->type == GENSIO_IOD_SOCKET) {
	return o->send(iod, sg, sglen, rcount, 0);
    } else if (wiod->type == GENSIO_IOD_FILE) {
	return win_file_write(wiod, sg, sglen, rcount);
    } else if (wiod->type == GENSIO_IOD_CONSOLE ||
	       wiod->type == GENSIO_IOD_PIPE) {
	return win_oneway_write(wiod, sg, sglen, rcount);
    } else if (wiod->type == GENSIO_IOD_DEV) {
	return win_twoway_write(wiod, sg, sglen, rcount);
    } else if (wiod->type == GENSIO_IOD_PTY) {
	return win_pty_write(wiod, sg, sglen, rcount);
    }

    return GE_NOTSUP;
}

static int
win_read(struct gensio_iod *iod,
	 void *ibuf, gensiods buflen, gensiods *rcount)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);
    struct gensio_os_funcs *o = iod->f;

    if (wiod->type == GENSIO_IOD_SOCKET) {
	return o->recv(iod, ibuf, buflen, rcount, 0);
    } else if (wiod->type == GENSIO_IOD_FILE) {
	return win_file_read(wiod, ibuf, buflen, rcount);
    } else if (wiod->type == GENSIO_IOD_CONSOLE ||
	       wiod->type == GENSIO_IOD_PIPE) {
	return win_oneway_read(wiod, ibuf, buflen, rcount);
    } else if (wiod->type == GENSIO_IOD_DEV) {
	return win_twoway_read(wiod, ibuf, buflen, rcount);
    } else if (wiod->type == GENSIO_IOD_PTY) {
	return win_pty_read(wiod, ibuf, buflen, rcount);
    }

    return GE_NOTSUP;
}

static bool
win_is_regfile(struct gensio_os_funcs *o, intptr_t fd)
{
    switch (fd) {
    case 0:
	return GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_DISK;
    case 1:
	return GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_DISK;
    case 2:
	return GetFileType(GetStdHandle(STD_ERROR_HANDLE)) == FILE_TYPE_DISK;
    }

    return GetFileType((HANDLE) fd) == FILE_TYPE_DISK;
}

static int
win_bufcount(struct gensio_iod *iod, int whichbuf, gensiods *count)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);

    if (wiod->type == GENSIO_IOD_CONSOLE ||
	wiod->type == GENSIO_IOD_PIPE)
	return win_oneway_bufcount(wiod, whichbuf, count);
    if (wiod->type == GENSIO_IOD_DEV)
	return win_twoway_bufcount(wiod, whichbuf, count);

    return GE_NOTSUP;
}

static void
win_flush(struct gensio_iod *iod, int whichbuf)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);

    if (wiod->type == GENSIO_IOD_CONSOLE ||
	wiod->type == GENSIO_IOD_PIPE)
	win_oneway_flush(wiod);
    else if (wiod->type == GENSIO_IOD_DEV)
	win_twoway_flush(wiod);
}

static int
win_makeraw(struct gensio_iod *iod)
{
    struct gensio_iod_win *wiod = iod_to_win(iod);
    int rv = GE_NOTSUP;

    if (do_errtrig())
	return GE_NOMEM;

    if (wiod->type == GENSIO_IOD_CONSOLE)
	rv = win_console_makeraw(wiod);
    if (wiod->type == GENSIO_IOD_DEV)
	rv = 0; /* Nothing to do. */
    if (wiod->type == GENSIO_IOD_PIPE)
	rv = 0; /* Nothing to do. */
    if (wiod->type == GENSIO_IOD_FILE)
	rv = 0; /* Nothing to do. */

    return rv;
}

static int
win_open_dev(struct gensio_os_funcs *o, const char *iname, int options,
	     struct gensio_iod **riod)
{
    struct gensio_iod_win *wiod;
    struct win_init_info info;
    int rv;

    info.name = iname;
    rv = win_alloc_iod(o, sizeof(struct gensio_iod_win_dev), -1,
		       GENSIO_IOD_DEV, win_iod_dev_init, &info, &wiod);
    if (!rv)
	*riod = &wiod->iod;
    return rv;
}

/*
 * FIXME - This currently doesn't handle running the subprogram as a
 * different user like it should (and the selector code does).
 */
static int
win_exec_subprog(struct gensio_os_funcs *o,
		 const char *argv[], const char **env,
		 const char *start_dir,
		 unsigned int flags,
		 intptr_t *rpid,
		 struct gensio_iod **rstdin,
		 struct gensio_iod **rstdout,
		 struct gensio_iod **rstderr)
{
    int rv = 0;
    HANDLE phandle = NULL;
    HANDLE stdin_m = NULL;
    HANDLE stdout_m = NULL;
    HANDLE stderr_m = NULL;
    struct gensio_iod_win *stdin_iod = NULL;
    struct gensio_iod_win *stdout_iod = NULL;
    struct gensio_iod_win *stderr_iod = NULL;
    BOOL readable = FALSE;

    rv = gensio_win_do_exec(o, argv, env, start_dir, flags, &phandle,
			    &stdin_m, &stdout_m,
			    rstderr ? &stderr_m : NULL);
    if (rv)
	return rv;


    rv = win_alloc_iod(o, sizeof(struct gensio_iod_win_pipe),
		       (intptr_t) stdin_m, GENSIO_IOD_PIPE,
		       win_iod_pipe_init, &readable, &stdin_iod);
    if (rv)
	goto out_err;
    readable = TRUE;
    rv = win_alloc_iod(o, sizeof(struct gensio_iod_win_pipe),
		       (intptr_t) stdout_m, GENSIO_IOD_PIPE,
		       win_iod_pipe_init, &readable, &stdout_iod);
    if (rv)
	goto out_err;

    if (stderr_m) {
	rv = win_alloc_iod(o, sizeof(struct gensio_iod_win_pipe),
			   (intptr_t) stderr_m, GENSIO_IOD_PIPE,
			   win_iod_pipe_init, &readable, &stderr_iod);
	if (rv)
	    goto out_err;
    }

    *rpid = (intptr_t) phandle;
    *rstdin = &stdin_iod->iod;
    *rstdout = &stdout_iod->iod;
    if (rstderr)
	*rstderr = &stderr_iod->iod;
    return 0;

 out_err:
    if (stdin_iod) {
	struct gensio_iod *iod = &stdin_iod->iod;
	o->close(&iod);
    } else if (stdin_m)
	CloseHandle(stdin_m);
    if (stdout_iod) {
	struct gensio_iod *iod = &stdout_iod->iod;
	o->close(&iod);
    } else if (stdout_m)
	CloseHandle(stdout_m);
    if (stderr_iod) {
	struct gensio_iod *iod = &stderr_iod->iod;
	o->close(&iod);
    } else if (stderr_m)
	CloseHandle(stderr_m);
    return rv;
}

static int
win_wait_subprog(struct gensio_os_funcs *o, intptr_t pid, int *retcode)
{
    HANDLE processh = (HANDLE) pid;
    DWORD exit_code;

    if (GetExitCodeProcess(processh, &exit_code)) {
	if (exit_code == STILL_ACTIVE)
	    return GE_INPROGRESS;
	*retcode = exit_code;
	CloseHandle(processh);
	return 0;
    }
    return gensio_os_err_to_err(o, GetLastError());
}

static int
win_kill_subprog(struct gensio_os_funcs *o, intptr_t pid, bool force)
{
    HANDLE processh = (HANDLE) pid;

    if (!force) /* Window's doesn't have a non-forceful kill. */
	return 0;
    if (!TerminateProcess(processh, 1))
	return gensio_os_err_to_err(o, GetLastError());
    return 0;
}

static int
win_get_random(struct gensio_os_funcs *o,
	       void *data, unsigned int len)
{
    NTSTATUS rv;
    BCRYPT_ALG_HANDLE alg;
    int err = 0;

    rv = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RNG_ALGORITHM,
				     MS_PRIMITIVE_PROVIDER, 0);
    if (rv != STATUS_SUCCESS)
	return gensio_os_err_to_err(o, rv);
    rv = BCryptGenRandom(alg, data, len, 0);
    if (rv != STATUS_SUCCESS)
	err = gensio_os_err_to_err(o, rv);
    BCryptCloseAlgorithmProvider(alg, 0);
    return err;
}

static void
win_finish_free(struct gensio_os_funcs *o)
{
    struct gensio_data *d = o->user_data;

    gensio_memtrack_cleanup(d->mtrack);
    if (d->timerth) {
	assert(WSASetEvent(d->timer_wakeev));
	WaitForSingleObject(d->timerth, INFINITE);
    }
    if (d->waiter)
	CloseHandle(d->waiter);
    if (d->timer_wakeev)
	WSACloseEvent(d->timer_wakeev);
    gensio_stdsock_cleanup(o);
    DeleteCriticalSection(&d->glock);
    DeleteCriticalSection(&d->timer_lock);
    DeleteCriticalSection(&d->once_lock);
    free(d);
    free(o);
    WSACleanup();
}

static int
gensio_win_control(struct gensio_os_funcs *o, int func, void *data,
		   gensiods *datalen)
{
    struct gensio_data *d = o->user_data;

    switch (func) {
    case GENSIO_CONTROL_SET_PROC_DATA:
	d->proc_data = data;
	return 0;

    default:
	return GE_NOTSUP;
    }
}

int
gensio_win_funcs_alloc(struct gensio_os_funcs **ro)
{
    struct gensio_data *d;
    struct gensio_os_funcs *o;
    int err = GE_NOMEM;

    o = malloc(sizeof(*o));
    if (!o)
	return GE_NOMEM;
    memset(o, 0, sizeof(*o));

    d = malloc(sizeof(*d));
    if (!d) {
	free(o);
	return GE_NOMEM;
    }
    memset(d, 0, sizeof(*d));
    d->refcount = 1;
    InitializeCriticalSection(&d->glock);
    InitializeCriticalSection(&d->timer_lock);
    InitializeCriticalSection(&d->once_lock);
    gensio_list_init(&d->waiting_iods);
    gensio_list_init(&d->all_iods);
    theap_init(&d->timer_heap);

    d->mtrack = gensio_memtrack_alloc();

    o->user_data = d;

    d->waiter = CreateSemaphoreA(NULL, 0, 1000000, NULL);
    if (!d->waiter)
	goto out_err;

    d->timer_wakeev = WSACreateEvent();
    if (d->timer_wakeev == WSA_INVALID_EVENT)
	goto out_err;

    d->timerth = CreateThread(NULL, 0, timer_thread, o, 0, &d->timerthid);
    if (!d->timerth)
	goto out_err;

    o->zalloc = win_zalloc;
    o->free = win_free;
    o->alloc_lock = win_alloc_lock;
    o->free_lock = win_free_lock;
    o->lock = win_lock;
    o->unlock = win_unlock;
    o->set_fd_handlers = win_set_fd_handlers;
    o->clear_fd_handlers = win_clear_fd_handlers;
    o->clear_fd_handlers_norpt = win_clear_fd_handlers_norpt;
    o->set_read_handler = win_set_read_handler;
    o->set_write_handler = win_set_write_handler;
    o->set_except_handler = win_set_except_handler;
    o->alloc_timer = win_alloc_timer;
    o->free_timer = win_free_timer;
    o->start_timer = win_start_timer;
    o->start_timer_abs = win_start_timer_abs;
    o->stop_timer = win_stop_timer;
    o->stop_timer_with_done = win_stop_timer_with_done;
    o->alloc_runner = win_alloc_runner;
    o->free_runner = win_free_runner;
    o->run = win_run;
    o->alloc_waiter = win_alloc_waiter;
    o->free_waiter = win_free_waiter;
    o->wait = win_wait;
    o->wait_intr = win_wait_intr;
    o->wake = win_wake;
    o->service = win_service;
    o->free_funcs = win_free_funcs;
    o->get_funcs = win_get_funcs;
    o->call_once = win_call_once;
    o->get_monotonic_time = win_get_monotonic_time;
    o->handle_fork = win_handle_fork;
    o->wait_intr_sigmask = win_wait_intr_sigmask;
    o->add_iod = win_add_iod;
    o->release_iod = win_release_iod;
    o->iod_get_type = win_iod_get_type;
    o->iod_get_fd = win_iod_get_fd;
    o->iod_control = win_iod_control;

    o->set_non_blocking = win_set_non_blocking;
    o->close = win_close;
    o->graceful_close = win_graceful_close;
    o->write = win_write;
    o->read = win_read;
    o->is_regfile = win_is_regfile;
    o->bufcount = win_bufcount;
    o->flush = win_flush;
    o->makeraw = win_makeraw;
    o->open_dev = win_open_dev;
    o->exec_subprog = win_exec_subprog;
    o->kill_subprog = win_kill_subprog;
    o->wait_subprog = win_wait_subprog;
    o->get_random = win_get_random;
    o->control = gensio_win_control;

    gensio_addr_addrinfo_set_os_funcs(o);
    err = gensio_stdsock_set_os_funcs(o);
    if (err)
	goto out_err;

    /* We have to catch these to reset status. */
    d->orig_recv = o->recv;
    d->orig_send = o->send;
    d->orig_sendto = o->sendto;
    d->orig_recvfrom = o->recvfrom;
    d->orig_accept = o->accept;
    d->orig_connect = o->connect;
    o->recv = win_recv;
    o->send = win_send;
    o->sendto = win_sendto;
    o->recvfrom = win_recvfrom;
    o->accept = win_accept;
    o->connect = win_connect;

    *ro = o;
    return 0;

 out_err:
    win_finish_free(o);
    return err;
}

struct gensio_os_proc_data {
    struct gensio_os_funcs *o;
    lock_type lock;

    BOOL term_handler_set;
    BOOL got_term_sig;
    void (*term_handler)(void *handler_data);
    void *term_handler_data;

    BOOL winsize_handler_set;
    HANDLE outcon;
    int x_chrs;
    int y_chrs;
    int x_bits;
    int y_bits;
    BOOL got_winsize_sig;
    void (*winsize_handler)(int x_chrs, int y_chrs,
			    int x_bits, int y_bits,
			    void *handler_data);
    void *winsize_handler_data;

    HANDLE global_waiter;

    struct gensio_os_cleanup_handler *cleanup_handlers;
};
static struct gensio_os_proc_data proc_data;

int
gensio_os_proc_setup(struct gensio_os_funcs *o,
		     struct gensio_os_proc_data **data)
{
    int rv;
    HRESULT res;

    res = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    switch (res) {
    case S_OK: case S_FALSE:
	break;
    case RPC_E_CHANGED_MODE:	return GE_INCONSISTENT;
    case E_INVALIDARG:		return GE_INVAL;
    case E_OUTOFMEMORY:		return GE_NOMEM;
    case E_UNEXPECTED: default: return GE_OSERR;
    }

    proc_data.global_waiter = CreateSemaphoreA(NULL, 0, 1000000, NULL);
    if (!proc_data.global_waiter) {
	CoUninitialize();
	return GE_NOMEM;
    }

    rv = o->control(o, GENSIO_CONTROL_SET_PROC_DATA, &proc_data, NULL);
    if (rv) {
	CloseHandle(proc_data.global_waiter);
	CoUninitialize();
	proc_data.global_waiter = NULL;
	return rv;
    }
    LOCK_INIT(&proc_data.lock);
    proc_data.o = o;
    *data = &proc_data;
    return 0;
}

static void
proc_release_sem(struct gensio_os_proc_data *data)
{
    BOOL rvb;

    rvb = ReleaseSemaphore(proc_data.global_waiter, 1, NULL);
    if (!rvb)
	/* Too many posts is improbable, but ok. */
	assert(GetLastError() == ERROR_TOO_MANY_POSTS);
}

static BOOL
ConCtrlHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
	proc_data.got_term_sig = true;
	proc_release_sem(&proc_data);
	return TRUE;

    default:
	return FALSE;
    }
}

void check_winsize(struct gensio_iod_win_oneway *owiod)
{
    struct gensio_iod_win *wiod = &owiod->wiod;
    struct gensio_iod *iod = &wiod->iod;
    struct gensio_os_funcs *o = iod->f;
    struct gensio_data *d = o->user_data;
    struct gensio_os_proc_data *data = d->proc_data;
    CONSOLE_SCREEN_BUFFER_INFOEX sbi;
    int x_chrs, y_chrs;

    LOCK(&data->lock);
    if (!data->winsize_handler_set)
	goto out_unlock;
    if (!data->outcon) {
	data->outcon = CreateFileA("CONOUT$", GENERIC_WRITE | GENERIC_READ, 0,
				   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
				   NULL);
	if (data->outcon == INVALID_HANDLE_VALUE) {
	    data->outcon = NULL;
	    goto out_unlock;
	}
    }
    memset(&sbi, 0, sizeof(sbi));
    sbi.cbSize = sizeof(sbi);
    if (!GetConsoleScreenBufferInfoEx(data->outcon, &sbi))
	goto out_unlock;
    x_chrs = sbi.dwSize.X;
    y_chrs = sbi.srWindow.Bottom - sbi.srWindow.Top + 1;
    if (x_chrs != data->x_chrs || y_chrs != data->y_chrs) {
	data->x_chrs = x_chrs;
	data->y_chrs = y_chrs;
	data->got_winsize_sig = TRUE;
	proc_release_sem(data);
    }
 out_unlock:
    UNLOCK(&data->lock);
}

void
gensio_register_os_cleanup_handler(struct gensio_os_funcs *o,
				   struct gensio_os_cleanup_handler *h)
{
    struct gensio_data *d = o->user_data;
    struct gensio_os_proc_data *data = d->proc_data;

    LOCK(&data->lock);
    h->next = data->cleanup_handlers;
    data->cleanup_handlers = h;
    UNLOCK(&data->lock);
}

void
gensio_os_proc_cleanup(struct gensio_os_proc_data *data)
{
    /* We should be single-threaded here. */
    while (data->cleanup_handlers) {
	struct gensio_os_cleanup_handler *h = data->cleanup_handlers;

	data->cleanup_handlers = h->next;
	h->cleanup(h);
    }

    if (data->term_handler_set) {
	SetConsoleCtrlHandler(ConCtrlHandler, false);
	data->term_handler_set = false;
    }
    if (data->outcon) {
	CloseHandle(data->outcon);
	data->outcon = NULL;
    }
    if (data->global_waiter) {
	CloseHandle(data->global_waiter);
	data->global_waiter = NULL;
    }
    LOCK_DESTROY(&proc_data.lock);
    CoUninitialize();
}

HANDLE
gensio_os_proc_win_get_main_handle(struct gensio_os_proc_data *data)
{
    return data->global_waiter;
}

void
gensio_os_proc_check_handlers(struct gensio_os_proc_data *data)
{
    LOCK(&data->lock);
    if (data->got_term_sig) {
	data->got_term_sig = FALSE;
	if (data->term_handler)
	    data->term_handler(data->term_handler_data);
    }
    if (data->got_winsize_sig) {
	data->got_winsize_sig = FALSE;
	if (data->winsize_handler)
	    data->winsize_handler(data->x_chrs, data->y_chrs,
				  data->x_bits, data->y_bits,
				  data->winsize_handler_data);
    }
    UNLOCK(&data->lock);
}

int
gensio_os_proc_register_term_handler(struct gensio_os_proc_data *data,
				     void (*handler)(void *handler_data),
				     void *handler_data)
{
    int err = 0;

    LOCK(&data->lock);
    if (SetConsoleCtrlHandler(ConCtrlHandler, TRUE) == 0) {
	err = gensio_os_err_to_err(data->o, GetLastError());
    } else {
	data->term_handler = handler;
	data->term_handler_data = handler_data;
	data->term_handler_set = true;
    }
    UNLOCK(&data->lock);
    return err;
}

int
gensio_os_proc_register_reload_handler(struct gensio_os_proc_data *data,
				       void (*handler)(void *handler_data),
				       void *handler_data)
{
    return GE_NOTSUP;
}

int
gensio_os_proc_register_winsize_handler(struct gensio_os_proc_data *data,
					struct gensio_iod *console_iod,
					void (*handler)(int x_chrs, int y_chrs,
							int x_bits, int y_bits,
							void *handler_data),
					void *handler_data)
{
    struct gensio_iod_win *wiod = iod_to_win(console_iod);
    int err = 0;

    if (wiod->type != GENSIO_IOD_CONSOLE)
	return GE_INVAL;
    LOCK(&data->lock);
    data->winsize_handler = handler;
    data->winsize_handler_data = handler_data;
    data->winsize_handler_set = true;
    UNLOCK(&data->lock);
    /* Wake the input handler to do the winch handling. */
    SetEvent(wiod_to_win_oneway(wiod)->wakeh);
    proc_release_sem(data);
    return err;
}

struct gensio_thread {
    struct gensio_os_funcs *o;
    HANDLE handle;
    DWORD tid;
    void (*start_func)(void *data);
    void *data;
};

static DWORD WINAPI
gensio_os_thread_func(LPVOID info)
{
    struct gensio_thread *tid = info;

    tid->start_func(tid->data);
    return 0;
}

int
gensio_os_new_thread(struct gensio_os_funcs *o,
		     void (*start_func)(void *data), void *data,
		     struct gensio_thread **thread_id)
{
    struct gensio_thread *tid;
    int rv;

    tid = o->zalloc(o, sizeof(*tid));
    if (!tid)
	return GE_NOMEM;
    tid->o = o;
    tid->start_func = start_func;
    tid->data = data;
    tid->handle = CreateThread(NULL, 0, gensio_os_thread_func, tid, 0,
			       &tid->tid);
    if (!tid->handle) {
	rv = gensio_os_err_to_err(o, GetLastError());
	o->free(o, tid);
	return rv;
    }
    *thread_id = tid;
    return 0;
}

int gensio_os_wait_thread(struct gensio_thread *tid)
{
    WaitForSingleObject(tid->handle, INFINITE);
    tid->o->free(tid->o, tid);
    return 0;
}

int
gensio_i_os_err_to_err(struct gensio_os_funcs *o,
		       int oserr, const char *caller, const char *file,
		       unsigned int lineno)
{
    int err;

    if (oserr == 0)
	return 0;

    switch(oserr) {
    case WSAEINVAL:		err = GE_INVAL; break;
    case WSAEINPROGRESS:	err = GE_INPROGRESS; break;
    case WSAETIMEDOUT:		err = GE_TIMEDOUT; break;
    case WSAECONNRESET:		err = GE_REMCLOSE; break;
    case WSAECONNABORTED:	err = GE_REMCLOSE; break;
    case WSAEHOSTUNREACH:	err = GE_HOSTDOWN; break;
    case WSAECONNREFUSED:	err = GE_CONNREFUSE; break;
    case WSAEADDRINUSE:		err = GE_ADDRINUSE; break;
    case WSAEINTR:		err = GE_INTERRUPTED; break;
    case WSAESHUTDOWN:		err = GE_SHUTDOWN; break;
    case WSAEMSGSIZE:		err = GE_TOOBIG; break;
    case WSAEACCES:		err = GE_PERM; break;
    case WSAEWOULDBLOCK:	err = GE_INPROGRESS; break;

    case STATUS_NOT_FOUND:	err = GE_NOTFOUND; break;
    case STATUS_INVALID_PARAMETER: err = GE_INVAL; break;
    case STATUS_NO_MEMORY:	err = GE_NOMEM; break;

    case ERROR_NOT_ENOUGH_MEMORY: err = GE_NOMEM; break;
    case ERROR_BROKEN_PIPE:	err = GE_REMCLOSE; break;
    case ERROR_NO_DATA:		err = GE_REMCLOSE; break;
    case ERROR_FILE_NOT_FOUND:	err = GE_NOTFOUND; break;
    case ERROR_NOT_FOUND:	err = GE_NOTFOUND; break;
    case ERROR_ACCESS_DENIED:	err = GE_PERM; break;
    default:			err = GE_OSERR;
    }

    if (err == GE_OSERR) {
	char errbuf[128];

	errbuf[0] = '\0';
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      oserr, 0, errbuf, sizeof(errbuf), NULL);
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled OS error in %s:%d: %s (%d)", caller, lineno,
		   errbuf, oserr);
    }

    return err;
}

int
gensio_default_os_hnd(int wake_sig, struct gensio_os_funcs **o)
{
    int err = 0;

    AcquireSRWLockExclusive(&def_win_os_funcs_lock);
    if (!def_win_os_funcs)
	err = gensio_win_funcs_alloc(&def_win_os_funcs);
    else
	win_get_funcs(def_win_os_funcs);
    ReleaseSRWLockExclusive(&def_win_os_funcs_lock);

    if (!err)
	*o = def_win_os_funcs;
    return 0;
}

void
gensio_osfunc_exit(int rv)
{
    exit(rv);
}
