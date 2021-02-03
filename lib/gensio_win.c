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
#include <gensio/sergensio.h>
#include <gensio/gensio_list.h>
#include <gensio/gensio_err.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_osops_addrinfo.h>
#include <gensio/gensio_osops_stdsock.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_circbuf.h>
#include <gensio/gensio_win.h>
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
    struct gensio_iod r;

    enum gensio_iod_type type;
    void (*clean)(struct gensio_iod_win *);
    void (*wake)(struct gensio_iod_win *);
    void (*check)(struct gensio_iod_win *);
    void (*shutdown)(struct gensio_iod_win *); /* Optional. */
    int fd;
    int protocol;
    struct gensio_link link;
    struct gensio_link all_link;

    BOOL done;

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
};

#define i_to_win(iod) gensio_container_of(iod, struct gensio_iod_win, r);

enum win_timer_state {
    WIN_TIMER_STOPPED = 0,
    WIN_TIMER_IN_HEAP,
    WIN_TIMER_IN_QUEUE,
    WIN_TIMER_PENDING /* Timeout is set, waiting for the handler to return. */
};

typedef struct heap_val_s {
    struct gensio_iod_win i;

    void (*handler)(struct gensio_timer *t, void *cb_data);
    void *cb_data;

    void (*done)(struct gensio_timer *t, void *cb_data);
    void *done_cb_data;

    ULONGLONG end_time;

    enum win_timer_state state;

    /* Have I been freed? */
    BOOL freed;

    /* Am I currently in a handler? */
    BOOL in_handler;
} heap_val_t;

#define i_to_timer(iod) gensio_container_of(iod, struct gensio_timer, val.i)

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

    WSADATA wsa_data;

    BOOL freed;

    CRITICAL_SECTION lock;
    struct gensio_list waiting_iods;
    struct gensio_list all_iods;

    CRITICAL_SECTION once_lock;

    CRITICAL_SECTION timer_lock;
    struct theap_s timer_heap;
    HANDLE timerth;
    DWORD timerthid;
    WSAEVENT timer_wakeev;

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

static void *
win_zalloc(struct gensio_os_funcs *o, unsigned int size)
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
i_queue_iod(struct gensio_iod_win *iod)
{
    struct gensio_data *d = iod->r.f->user_data;
    BOOL rvb;

    if (!gensio_list_link_inlist(&iod->link)) {
	gensio_list_add_tail(&d->waiting_iods, &iod->link);
	rvb = ReleaseSemaphore(d->waiter, 1, NULL);
	if (!rvb)
	    /* Too many posts is improbable, but ok. */
	    assert(GetLastError() == ERROR_TOO_MANY_POSTS);
    }
}

static void
queue_iod(struct gensio_iod_win *iod)
{
    struct gensio_data *d = iod->r.f->user_data;

    EnterCriticalSection(&d->lock);
    i_queue_iod(iod);
    LeaveCriticalSection(&d->lock);
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
	    queue_iod(&t->val.i);
	    t = theap_get_top(&d->timer_heap);
	    now = GetTickCount64();
	}
	LeaveCriticalSection(&d->timer_lock);
	if (t)
	    delay = t->val.end_time - now;
	else
	    delay = 1000000;
	rv = WSAWaitForMultipleEvents(1, &d->timer_wakeev, FALSE,
				      (DWORD) delay, FALSE);
	assert(rv != WSA_WAIT_FAILED);
	WSAResetEvent(&d->timer_wakeev);
	EnterCriticalSection(&d->timer_lock);
    }
    LeaveCriticalSection(&d->timer_lock);
    return 0;
}

static int
win_alloc_iod(struct gensio_os_funcs *o, unsigned int size, int fd,
	      enum gensio_iod_type type,
	      int (*iod_init)(struct gensio_iod_win *, void *), void *cb_data,
	      struct gensio_iod_win **riod)
{
    struct gensio_data *d = o->user_data;
    struct gensio_iod_win *iod;
    int rv = 0;

    iod = o->zalloc(o, size);
    if (!iod)
	return GE_NOMEM;
    InitializeCriticalSection(&iod->lock);
    iod->r.f = o;
    iod->type = type;
    iod->fd = fd;

    if (iod_init) {
	rv = iod_init(iod, cb_data);
	if (rv)
	    goto out_err;
    }

    if (iod->threadfunc) {
	iod->threadh = CreateThread(NULL, 0, iod->threadfunc, iod, 0,
				    &iod->threadid);
	if (!iod->threadh)
	    goto out_err;
    }

    EnterCriticalSection(&d->lock);
    gensio_list_add_tail(&d->all_iods, &iod->all_link);
    LeaveCriticalSection(&d->lock);
    *riod = iod;
    return 0;

 out_err:
    iod->done = TRUE;
    if (iod->shutdown) {
	iod->shutdown(iod);
    } else if (iod->threadh) {
	iod->wake(iod);
	WaitForSingleObject(iod->threadh, INFINITE);
    }
    if (iod->clean)
	iod->clean(iod);
    DeleteCriticalSection(&iod->lock);
    o->free(o, iod);
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
win_iod_handler_done(struct gensio_iod_win *iod)
{
    void (*cleared_handler)(struct gensio_iod *iod, void *cb_data) = NULL;
    void *cb_data;

    EnterCriticalSection(&iod->lock);
    assert(iod->in_handler_count > 0);
    iod->in_handler_count--;
    if (iod->in_handlers_clear && iod->in_handler_count == 0) {
	cleared_handler = iod->cleared_handler;
	cb_data = iod->cb_data;
	iod->handlers_set = FALSE;
	iod->read.handler = NULL;
	iod->write.handler = NULL;
	iod->except.handler = NULL;
	iod->cleared_handler = NULL;
    }
    LeaveCriticalSection(&iod->lock);
    if (cleared_handler)
	cleared_handler(&iod->r, cb_data);
}

static int
win_set_fd_handlers(struct gensio_iod *iiod,
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
    struct gensio_iod_win *iod = i_to_win(iiod);
    int rv = GE_INUSE;

    EnterCriticalSection(&iod->lock);
    if (!iod->handlers_set) {
	rv = 0;
	iod->handlers_set = TRUE;
	iod->read.handler = read_handler;
	iod->write.handler = write_handler;
	iod->except.handler = except_handler;
	iod->cleared_handler = cleared_handler;
	iod->cb_data = cb_data;
    }
    LeaveCriticalSection(&iod->lock);
    return rv;
}

static void
win_clear_fd_handlers(struct gensio_iod *iiod)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    EnterCriticalSection(&iod->lock);
    if (iod->handlers_set && !iod->in_handlers_clear) {
	iod->in_handlers_clear = TRUE;
	if (iod->in_handler_count == 0)
	    queue_iod(iod);
    }
    LeaveCriticalSection(&iod->lock);
}

static void
win_clear_fd_handlers_norpt(struct gensio_iod *iiod)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    EnterCriticalSection(&iod->lock);
    if (iod->handlers_set && !iod->in_handlers_clear) {
	iod->handlers_set = false;
	iod->read.handler = NULL;
	iod->write.handler = NULL;
	iod->except.handler = NULL;
	iod->cleared_handler = NULL;
    }
    LeaveCriticalSection(&iod->lock);
}

static void
win_set_read_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    EnterCriticalSection(&iod->lock);
    if (iod->read.wait != enable && !iod->in_handlers_clear) {
	iod->read.wait = enable;
	if (enable) {
	    if (iod->read.ready)
		queue_iod(iod);
	    else
		iod->wake(iod);
	}
    }
    LeaveCriticalSection(&iod->lock);
}

static void
win_set_write_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    EnterCriticalSection(&iod->lock);
    if (iod->write.wait != enable && !iod->in_handlers_clear) {
	iod->write.wait = enable;
	if (enable) {
	    if (iod->write.ready)
		queue_iod(iod);
	    else
		iod->wake(iod);
	}
    }
    LeaveCriticalSection(&iod->lock);
}

static void
win_set_except_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    EnterCriticalSection(&iod->lock);
    if (iod->except.wait != enable && !iod->in_handlers_clear) {
	iod->except.wait = enable;
	if (enable) {
	    if (iod->except.ready)
		queue_iod(iod);
	    else
		iod->wake(iod);
	}
    }
    LeaveCriticalSection(&iod->lock);
}

static void
win_timer_check(struct gensio_iod_win *iod)
{
    struct gensio_os_funcs *o = iod->r.f;
    struct gensio_data *d = o->user_data;
    struct gensio_timer *t = i_to_timer(iod);

    EnterCriticalSection(&d->timer_lock);
    t->val.state = WIN_TIMER_STOPPED;
    t->val.in_handler = TRUE;
    LeaveCriticalSection(&d->timer_lock);
    t->val.handler(t, t->val.cb_data);
    EnterCriticalSection(&d->timer_lock);
    if (t->val.done) {
	void (*done)(struct gensio_timer *t, void *cb_data) = t->val.done;
	void *cb_data = t->val.done_cb_data;

	t->val.done = NULL;
	LeaveCriticalSection(&d->timer_lock);
	done(t, cb_data);
	EnterCriticalSection(&d->timer_lock);
    }
    t->val.in_handler = FALSE;
    if (t->val.freed) {
	LeaveCriticalSection(&d->timer_lock);
	o->release_iod(&t->val.i.r);
	return;
    }
    if (t->val.state == WIN_TIMER_PENDING) {
	theap_add(&d->timer_heap, t);
	assert(WSASetEvent(d->timer_wakeev));
	t->val.state = WIN_TIMER_IN_HEAP;
    }
    LeaveCriticalSection(&d->timer_lock);
}

static struct gensio_timer *
win_alloc_timer(struct gensio_os_funcs *o,
		void (*handler)(struct gensio_timer *t, void *cb_data),
		void *cb_data)
{
    struct gensio_timer *t = NULL;
    struct gensio_iod_win *iod;
    int rv;

    rv = win_alloc_iod(o, sizeof(struct gensio_timer), -1, 0, NULL, NULL, &iod);
    if (!rv) {
	iod->check = win_timer_check;
	t = i_to_timer(iod);
	t->val.handler = handler;
	t->val.cb_data = cb_data;
    }
    return t;
}

static void
win_stop_timer_now(struct gensio_timer *timer)
{
    struct gensio_os_funcs *o = timer->val.i.r.f;
    struct gensio_data *d = o->user_data;

    if (timer->val.state == WIN_TIMER_IN_QUEUE) {
	EnterCriticalSection(&d->lock);
	gensio_list_rm(&d->waiting_iods, &timer->val.i.link);
	LeaveCriticalSection(&d->lock);
    } else if (timer->val.state == WIN_TIMER_IN_HEAP) {
	theap_remove(&d->timer_heap, timer);
    }
    timer->val.state = WIN_TIMER_STOPPED;
}

static void
win_free_timer(struct gensio_timer *timer)
{
    struct gensio_os_funcs *o = timer->val.i.r.f;
    struct gensio_data *d = o->user_data;

    EnterCriticalSection(&d->timer_lock);
    if (!timer->val.freed) {
	timer->val.freed = TRUE;
	win_stop_timer_now(timer);
	if (!timer->val.in_handler)
	    o->release_iod(&timer->val.i.r);
    }
    LeaveCriticalSection(&d->timer_lock);
}

static int
win_add_timer(struct gensio_timer *timer, ULONGLONG end_time)
{
    struct gensio_os_funcs *o = timer->val.i.r.f;
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
    if (timer->val.in_handler) {
	timer->val.state = WIN_TIMER_PENDING;
    } else {
	/* Otherwise we'll add it when the handler returns. */
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
    struct gensio_os_funcs *o = timer->val.i.r.f;
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
    struct gensio_os_funcs *o = timer->val.i.r.f;
    struct gensio_data *d = o->user_data;
    int rv = 0;

    EnterCriticalSection(&d->timer_lock);
    if (timer->val.freed) {
	rv = GE_INVAL;
	goto out_unlock;
    }
    switch (timer->val.state) {
    case WIN_TIMER_STOPPED:
	if (!timer->val.in_handler) {
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
	queue_iod(&timer->val.i);
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
    struct gensio_iod_win i;
    BOOL running;
    BOOL freed;
    BOOL in_handler;
    void (*handler)(struct gensio_runner *r, void *cb_data);
    void *cb_data;
};

#define i_to_runner(iod) gensio_container_of(iod, struct gensio_runner, i)

static void
win_runner_check(struct gensio_iod_win *iod)
{
    struct gensio_os_funcs *o = iod->r.f;
    struct gensio_data *d = o->user_data;
    struct gensio_runner *r = i_to_runner(iod);
    BOOL freed;

    EnterCriticalSection(&d->lock);
    if (r->freed) {
	LeaveCriticalSection(&d->lock);
	o->release_iod(&r->i.r);
	return;
    }
    r->running = FALSE;
    r->in_handler = TRUE;
    LeaveCriticalSection(&d->lock);
    r->handler(r, r->cb_data);
    EnterCriticalSection(&d->lock);
    r->in_handler = FALSE;
    freed = r->freed;
    LeaveCriticalSection(&d->lock);
    if (freed)
	o->release_iod(&r->i.r);
}

static struct gensio_runner *
win_alloc_runner(struct gensio_os_funcs *o,
		 void (*handler)(struct gensio_runner *r, void *cb_data),
		 void *cb_data)
{
    struct gensio_runner *r = NULL;
    struct gensio_iod_win *iod;
    int rv;

    rv = win_alloc_iod(o, sizeof(struct gensio_runner), -1, 0, NULL, NULL,
		       &iod);
    if (!rv) {
	iod->check = win_runner_check;
	r = i_to_runner(iod);
	r->handler = handler;
	r->cb_data = cb_data;
    }
    return r;
}

static void
win_free_runner(struct gensio_runner *runner)
{
    struct gensio_os_funcs *o = runner->i.r.f;
    struct gensio_data *d = o->user_data;

    EnterCriticalSection(&d->lock);
    if (!runner->freed) {
	runner->freed = TRUE;
	if (!runner->in_handler) {
	    if (runner->running) {
		gensio_list_rm(&d->waiting_iods, &runner->i.link);
		runner->running = FALSE;
	    }
	    o->release_iod(&runner->i.r);
	}
	/* If in the handler, nothing to do, it will catch it on return. */
    }
    LeaveCriticalSection(&d->lock);
}

static int
win_run(struct gensio_runner *runner)
{
    struct gensio_os_funcs *o = runner->i.r.f;
    struct gensio_data *d = o->user_data;
    int rv = 0;

    EnterCriticalSection(&d->lock);
    if (runner->freed) {
	rv = GE_INVAL;
    } else if (runner->running) {
	rv = GE_INUSE;
    } else {
	runner->running = TRUE;
	i_queue_iod(&runner->i);
    }
    LeaveCriticalSection(&d->lock);

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
    win_finish_free_waiter(waiter);
 out_unlock:
    LeaveCriticalSection(&waiter->lock);
}

static void
win_check_iods(struct gensio_os_funcs *o)
{
    struct gensio_data *d = o->user_data;

    EnterCriticalSection(&d->lock);
    while (!gensio_list_empty(&d->waiting_iods)) {
	struct gensio_link *l = gensio_list_first(&d->waiting_iods);
	struct gensio_iod_win *iod;

	iod = gensio_container_of(l, struct gensio_iod_win, link);
	gensio_list_rm(&d->waiting_iods, l);

	LeaveCriticalSection(&d->lock);
	iod->check(iod);
	EnterCriticalSection(&d->lock);
    }
    LeaveCriticalSection(&d->lock);
}

static int
win_do_wait(struct gensio_waiter *waiter, unsigned int count,
	    gensio_time *timeout, BOOL alerts)
{
    struct gensio_data *d = waiter->o->user_data;
    int rv = 0;
    ULONGLONG entry_time, end_time, now;
    DWORD rvw, mtimeout;
    HANDLE h[2];

    entry_time = GetTickCount64();
    mtimeout = gensio_time_to_ms(timeout);
    end_time = entry_time + mtimeout;
    now = entry_time;

    h[0] = d->waiter;
    h[1] = waiter->wait_sem;

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
	    rvw = WaitForMultipleObjectsEx(2, h, FALSE, end_time - now, alerts);
	    assert(rvw != WAIT_FAILED);
	    if (rvw != WAIT_TIMEOUT)
		win_check_iods(waiter->o);
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

static void win_free_funcs(struct gensio_os_funcs *o)
{
    struct gensio_data *d = o->user_data;

    EnterCriticalSection(&d->lock);
    if (!d->freed) {
	d->freed = TRUE;
	if (gensio_list_empty(&d->all_iods))
	    win_finish_free(o);
    }
    LeaveCriticalSection(&d->lock);
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
				 void *sigmask)
{
    return win_wait_intr(waiter, count, timeout);
}

static void
win_iod_check_handler(struct gensio_iod_win *iod, struct iostat *stat)
{
    EnterCriticalSection(&iod->lock);
    if (stat->wait && stat->handler && (stat->ready || iod->closed)) {
	void (*handler)(struct gensio_iod *iod, void *cb_data) = stat->handler;
	void *cb_data = iod->cb_data;

	LeaveCriticalSection(&iod->lock);
	handler(&iod->r, cb_data);
    } else {
	LeaveCriticalSection(&iod->lock);
    }
}

static void
win_iod_check(struct gensio_iod_win *iod)
{
    EnterCriticalSection(&iod->lock);
    iod->in_handler_count++;
    LeaveCriticalSection(&iod->lock);
    win_iod_check_handler(iod, &iod->read);
    win_iod_check_handler(iod, &iod->write);
    win_iod_check_handler(iod, &iod->except);
    win_iod_handler_done(iod);
}

struct gensio_iod_win_sock {
    struct gensio_iod_win i;
    WSAEVENT wakeev;
    WSAEVENT sockev;
    BOOL connected;
};

#define i_to_winsock(iod) gensio_container_of(iod, struct gensio_iod_win_sock,\
					      i);

static DWORD WINAPI
winsock_func(LPVOID data)
{
    struct gensio_iod_win_sock *iod = data;
    struct gensio_iod_win *wiod = &iod->i;
    WSAEVENT waiters[2];
    unsigned int i;
    int rv;

    EnterCriticalSection(&wiod->lock);
    waiters[0] = iod->wakeev;
    waiters[1] = iod->sockev;
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
	    rv = WSAEventSelect(wiod->fd, iod->sockev, events);
	    if (rv == SOCKET_ERROR) {
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
	    WSAResetEvent(iod->wakeev);
	} else if (rv == WSA_WAIT_EVENT_0 + 1) {
	    rv = WSAEnumNetworkEvents(wiod->fd, iod->sockev, &revents);
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
    struct gensio_iod_win_sock *iod = i_to_winsock(wiod);

    assert(WSASetEvent(iod->wakeev));
}

static void
win_iod_socket_clean(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_sock *iod = i_to_winsock(wiod);

    if (iod->sockev != WSA_INVALID_EVENT)
	WSACloseEvent(iod->sockev);
    if (iod->wakeev != WSA_INVALID_EVENT)
	WSACloseEvent(iod->wakeev);
    closesocket(wiod->fd);
}

static int
win_iod_socket_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_sock *iod = i_to_winsock(wiod);

    iod->wakeev = WSA_INVALID_EVENT;
    iod->sockev = WSA_INVALID_EVENT;

    iod->wakeev = WSACreateEvent();
    if (iod->wakeev == WSA_INVALID_EVENT)
	goto out_err;

    iod->sockev = WSACreateEvent();
    if (iod->sockev == WSA_INVALID_EVENT)
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
    struct gensio_iod_win i;
    HANDLE wakeh;
    HANDLE ioh;

    struct gensio_circbuf *buf;

    BOOL readable;

    BOOL do_flush; /* Tell out to flush it's data. */
};

#define i_to_win_oneway(iod) gensio_container_of(iod,			    \
						struct gensio_iod_win_oneway, \
						i);

static DWORD WINAPI
win_oneway_in_thread(LPVOID data)
{
    struct gensio_iod_win_oneway *iod = data;
    struct gensio_iod_win *wiod = &iod->i;
    DWORD rvw;

    EnterCriticalSection(&wiod->lock);
    for(;;) {
	BOOL rvb;

	if (gensio_circbuf_room_left(iod->buf) && !wiod->werr) {
	    gensiods readsize;
	    void *readpos;
	    DWORD nread;

	    gensio_circbuf_next_write_area(iod->buf, &readpos, &readsize);
	    LeaveCriticalSection(&wiod->lock);
	    rvb = ReadFile(iod->ioh, readpos, readsize, &nread, NULL);
	    EnterCriticalSection(&wiod->lock);
	    if (!rvb)
		goto out_err;

	    if (nread == 0) {
		/* EOF (^Z<cr>) from windows. */
		rvw = ERROR_BROKEN_PIPE;
		goto out_err_noconv;
	    } else {
		gensio_circbuf_data_added(iod->buf, nread);
		if (!wiod->read.ready) {
		    wiod->read.ready = TRUE;
		    queue_iod(wiod);
		}
	    }
	} else {
	    LeaveCriticalSection(&wiod->lock);
	    rvw = WaitForSingleObject(iod->wakeh, INFINITE);
	    EnterCriticalSection(&wiod->lock);
	    if (rvw == WAIT_FAILED)
		goto out_err;
	}
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
    struct gensio_iod_win_oneway *iod = data;
    struct gensio_iod_win *wiod = &iod->i;
    DWORD rvw;

    EnterCriticalSection(&wiod->lock);
    for(;;) {
	BOOL rvb;

	if (gensio_circbuf_datalen(iod->buf) > 0) {
	    gensiods writelen;
	    void *writepos;
	    DWORD nwrite;

	    gensio_circbuf_next_read_area(iod->buf, &writepos, &writelen);
	    LeaveCriticalSection(&wiod->lock);
	    rvb = WriteFile(iod->ioh, writepos, writelen, &nwrite, NULL);
	    EnterCriticalSection(&wiod->lock);
	    if (!rvb)
		goto out_err;

	    if (!iod->do_flush) {
		gensio_circbuf_data_removed(iod->buf, nwrite);

		if (!wiod->write.ready) {
		    wiod->write.ready = TRUE;
		    queue_iod(wiod);
		}
	    }
	} else {
	    LeaveCriticalSection(&wiod->lock);
	    rvw = WaitForSingleObject(iod->wakeh, INFINITE);
	    EnterCriticalSection(&wiod->lock);
	    if (rvw == WAIT_FAILED)
		goto out_err;
	}
	if (wiod->done)
	    break;
	if (iod->do_flush) {
	    gensio_circbuf_reset(iod->buf);
	    iod->do_flush = FALSE;
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
win_oneway_close(struct gensio_iod_win *wiod)
{
    EnterCriticalSection(&wiod->lock);
    wiod->closed = TRUE;
    if (!wiod->err)
	wiod->err = GE_LOCALCLOSED;
    LeaveCriticalSection(&wiod->lock);

    return 0;
}

static void
win_iod_oneway_shutdown(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *iod = i_to_win_oneway(wiod);

    /* This sucks, see notes at beginning of oneway section. */
    assert(SetEvent(iod->wakeh));
    CancelSynchronousIo(wiod->threadh);
    while (WaitForSingleObject(wiod->threadh, 1) == WAIT_TIMEOUT) {
	assert(SetEvent(iod->wakeh));
	CancelSynchronousIo(wiod->threadh);
    }
    wiod->threadh = NULL;
    if (iod->ioh) {
	CloseHandle(iod->ioh);
	iod->ioh = NULL;
    }
}

static int
win_oneway_bufcount(struct gensio_iod_win *wiod, int whichbuf, gensiods *count)
{
    struct gensio_iod_win_oneway *iod = i_to_win_oneway(wiod);

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr)
	*count = 0;
    else if ((wiod->fd == 0 && whichbuf == GENSIO_IN_BUF) ||
	     (wiod->fd == 1 && whichbuf == GENSIO_OUT_BUF))
	*count = gensio_circbuf_datalen(iod->buf);
    else
	*count = 0;
    LeaveCriticalSection(&wiod->lock);
    return 0;
}

static void
win_oneway_flush(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *iod = i_to_win_oneway(wiod);

    if (iod->readable) /* output only */
	return;
    EnterCriticalSection(&wiod->lock);
    if (!wiod->err && !wiod->werr) {
	iod->do_flush = TRUE;
	assert(SetEvent(iod->wakeh));
	CancelSynchronousIo(wiod->threadh);
    }
    LeaveCriticalSection(&wiod->lock);
}

static int
win_oneway_write(struct gensio_iod_win *wiod,
		const struct gensio_sg *sg, gensiods sglen,
		gensiods *rcount)
{
    struct gensio_iod_win_oneway *iod = i_to_win_oneway(wiod);
    gensiods count = 0;
    int rv = 0;

    EnterCriticalSection(&wiod->lock);
    if (iod->readable) {
	rv = GE_NOTSUP;
	goto out_err;
    }
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->r.f, wiod->werr);
	rv = wiod->err;
	goto out_err;
    }
    if (iod->do_flush)
	goto out;
    gensio_circbuf_sg_write(iod->buf, sg, sglen, &count);
    wiod->write.ready = gensio_circbuf_room_left(iod->buf) > 0;
    if (count)
	assert(SetEvent(iod->wakeh));
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
    struct gensio_iod_win_oneway *iod = i_to_win_oneway(wiod);
    gensiods count = 0;
    BOOL was_full;
    int rv = 0;

    EnterCriticalSection(&wiod->lock);
    if (!iod->readable) {
	rv = GE_NOTSUP;
	goto out_err;
    }
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->r.f, wiod->werr);
	rv = wiod->err;
	goto out_err;
    }

    was_full = gensio_circbuf_room_left(iod->buf) == 0;
    gensio_circbuf_read(iod->buf, ibuf, buflen, &count);
    wiod->read.ready = gensio_circbuf_datalen(iod->buf) > 0;
    if (was_full && count)
	assert(SetEvent(iod->wakeh));
    if (rcount)
	*rcount = count;
 out_err:
    LeaveCriticalSection(&wiod->lock);
    return rv;
}

static void
win_iod_oneway_wake(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *iod = i_to_win_oneway(wiod);

    assert(SetEvent(iod->wakeh));
}

static void
win_iod_oneway_clean(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *iod = i_to_win_oneway(wiod);

    if (iod->ioh) {
	CloseHandle(iod->ioh);
	iod->ioh = NULL;
    }
    if (iod->wakeh) {
	CloseHandle(iod->wakeh);
	iod->wakeh = NULL;
    }
    if (iod->buf) {
	gensio_circbuf_free(iod->buf);
	iod->buf = NULL;
    }
}

static int
win_iod_oneway_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_oneway *iod = i_to_win_oneway(wiod);
    struct gensio_os_funcs *o = wiod->r.f;

    iod->buf = gensio_circbuf_alloc(o, 2048);
    if (!iod->buf)
	return GE_NOMEM;

    iod->wakeh = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!iod->wakeh) {
	gensio_circbuf_free(iod->buf);
	iod->buf = NULL;
	return GE_NOMEM;
    }

    if (iod->readable)
	wiod->threadfunc = win_oneway_in_thread;
    else
	wiod->threadfunc = win_oneway_out_thread;

    wiod->clean = win_iod_oneway_clean;
    wiod->wake = win_iod_oneway_wake;
    wiod->check = win_iod_check;
    wiod->shutdown = win_iod_oneway_shutdown;
    return 0;
}

struct gensio_iod_win_stdio {
    struct gensio_iod_win_oneway w;

    struct stdio_mode *mode;
};

#define i_to_winstdio(iod) gensio_container_of(iod,			    \
					       struct gensio_iod_win_stdio, \
					       w);

static int
win_stdio_makeraw(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *oiod = i_to_win_oneway(wiod);
    struct gensio_iod_win_stdio *iod = i_to_winstdio(oiod);

    if (wiod->fd != 0)
	/*
	 * Nothing to do for stdout. Disabling ENABLE_PROCESSED_OUTPUT
	 * is not a good thing to do.
	 */
	return 0;

    return gensio_win_stdio_makeraw(wiod->r.f, oiod->ioh, &iod->mode);
}

static int
win_stdio_close(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_oneway *oiod = i_to_win_oneway(wiod);
    struct gensio_iod_win_stdio *iod = i_to_winstdio(oiod);

    gensio_win_stdio_cleanup(wiod->r.f, oiod->ioh, &iod->mode);
    return win_oneway_close(wiod);
}

static int
win_iod_stdio_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_oneway *oiod = i_to_win_oneway(wiod);
    HANDLE h;

    if (wiod->fd > 1 || wiod->fd < 0)
	return GE_INVAL;

    if (wiod->fd == 0) { /* stdin */
	h = GetStdHandle(STD_INPUT_HANDLE);
	oiod->readable = TRUE;
    } else {
	h = GetStdHandle(STD_OUTPUT_HANDLE);
	oiod->readable = FALSE;
    }
    if (h == INVALID_HANDLE_VALUE)
	return gensio_os_err_to_err(wiod->r.f, GetLastError());
    /* Per testing, GetStdHandle does not return a duplicate. */
    if (!DuplicateHandle(GetCurrentProcess(),
			 h,
			 GetCurrentProcess(),
			 &oiod->ioh,
			 0, FALSE, DUPLICATE_SAME_ACCESS))
	return gensio_os_err_to_err(wiod->r.f, GetLastError());

    return win_iod_oneway_init(wiod, cb_data);
}

struct gensio_iod_win_pipe
{
    struct gensio_iod_win_oneway b;
};

#define i_to_winpipe(iod) gensio_container_of(iod,			\
					      struct gensio_iod_win_pipe,\
					      b);
static int
win_iod_read_pipe_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_oneway *oiod = i_to_win_oneway(wiod);

    oiod->readable = TRUE;

    return win_iod_oneway_init(wiod, cb_data);
}

static int
win_iod_write_pipe_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_oneway *oiod = i_to_win_oneway(wiod);

    oiod->readable = FALSE;

    return win_iod_oneway_init(wiod, cb_data);
}

static int
win_iod_pipe_init(struct gensio_iod_win *wiod, void *cb_data)
{
    DWORD pflags;

    wiod->iod = (HANDLE) wiod->fd;
    if (!GetNamedPipeInfo(wiod->ioh, &pflags, NULL, NULL, NULL))
	return gensio_os_err_to_err(o, GetLastError());
    if (pflags & PIPE_SERVER_END)
	return win_iod_read_pipe_init(woid, cb_data);
    else
	return win_iod_write_pipe_init(woid, cb_data);
}

/*
 * bidirectional I/O handle
 */
struct gensio_iod_win_twoway {
    struct gensio_iod_win i;

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

#define i_to_win_twoway(iod) gensio_container_of(iod,			\
						 struct gensio_iod_win_twoway, \
						 i);

static DWORD WINAPI
win_twoway_thread(LPVOID data)
{
    struct gensio_iod_win_twoway *iod = data;
    struct gensio_iod_win *wiod = &iod->i;
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

    waiters[0] = iod->wakeh;
    waiters[1] = reado.hEvent;
    waiters[2] = writeo.hEvent;
    nwait = 3;
    if (iod->extrah)
	waiters[nwait++] = iod->extrah;

    for(;;) {
	BOOL rvb;

	if (!reading && gensio_circbuf_room_left(iod->inbuf) && !wiod->werr
			&& iod->readable) {
	    gensiods readsize;
	    void *readpos;

	    gensio_circbuf_next_write_area(iod->inbuf, &readpos, &readsize);
	    reading = TRUE;
	    LeaveCriticalSection(&wiod->lock);
	    rvb = ReadFile(iod->ioh, readpos, readsize, NULL, &reado);
	    EnterCriticalSection(&wiod->lock);
	    if (!rvb) {
		rvw = GetLastError();
		if (rvw != ERROR_IO_PENDING)
		    goto out_err_noget;
	    }
	} else if (!writing && gensio_circbuf_datalen(iod->outbuf) > 0 &&
		   !wiod->werr && iod->writeable) {
	    gensiods writelen;
	    void *writepos;

	    gensio_circbuf_next_read_area(iod->outbuf, &writepos, &writelen);
	    writing = TRUE;
	    LeaveCriticalSection(&wiod->lock);
	    rvb = WriteFile(iod->ioh, writepos, writelen, NULL, &writeo);
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
		if (!GetOverlappedResult(iod->ioh, &reado, &nread, FALSE))
		    goto out_err;

		if (nread > 0) {
		    gensio_circbuf_data_added(iod->inbuf, nread);
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
		if (!GetOverlappedResult(iod->ioh, &writeo, &nwrite, FALSE))
		    goto out_err;

		if (iod->do_flush || nwrite > 0) {
		    if (iod->do_flush) {
			gensio_circbuf_reset(iod->outbuf);
			iod->do_flush = FALSE;
		    } else {
			gensio_circbuf_data_removed(iod->outbuf, nwrite);
		    }

		    if (!wiod->write.ready) {
			wiod->write.ready = TRUE;
			queue_iod(wiod);
		    }
		}
		writing = FALSE;
	    } else if (rvw == WAIT_OBJECT_0 + 3) {
		rvw = iod->extrah_func(iod);
		if (iod->extrah)
		    goto out_err;
	    }
	}
	if (wiod->done)
	    break;
	if (iod->do_flush) {
	    if (writing) {
		CancelIoEx(iod->ioh, &writeo);
	    } else {
		gensio_circbuf_reset(iod->outbuf);
		iod->do_flush = FALSE;
	    }
	}
    }
 exitth:
    if (reading)
	CancelIoEx(iod->ioh, &reado);
    if (writing)
	CancelIoEx(iod->ioh, &writeo);
    if (reado.hEvent)
	CloseHandle(reado.hEvent);
    if (writeo.hEvent)
	CloseHandle(writeo.hEvent);

    if (!iod->readable)
	wiod->read.ready = TRUE;
    if (!iod->writeable)
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

static int
win_twoway_close(struct gensio_iod_win *wiod) {
    EnterCriticalSection(&wiod->lock);
    wiod->closed = TRUE;
    if (!wiod->err)
	wiod->err = GE_LOCALCLOSED;
    LeaveCriticalSection(&wiod->lock);

    return 0;
}

static int
win_twoway_bufcount(struct gensio_iod_win *wiod, int whichbuf, gensiods *count)
{
    struct gensio_iod_win_twoway *iod = i_to_win_twoway(wiod);

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr)
	*count = 0;
    else if (iod->readable && whichbuf == GENSIO_IN_BUF)
	*count = gensio_circbuf_datalen(iod->inbuf);
    else if (iod->writeable && whichbuf == GENSIO_OUT_BUF)
	*count = gensio_circbuf_datalen(iod->outbuf);
    else
	*count = 0;
    LeaveCriticalSection(&wiod->lock);
    return 0;
}

static void
win_twoway_flush(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *iod = i_to_win_twoway(wiod);

    if (wiod->fd != 1) /* stdout only */
	return;
    EnterCriticalSection(&wiod->lock);
    if (!wiod->err && !wiod->werr) {
	iod->do_flush = TRUE;
	assert(SetEvent(iod->wakeh));
    }
    LeaveCriticalSection(&wiod->lock);
}

static int
win_twoway_write(struct gensio_iod_win *wiod,
		 const struct gensio_sg *sg, gensiods sglen,
		 gensiods *rcount)
{
    struct gensio_iod_win_twoway *iod = i_to_win_twoway(wiod);
    gensiods count = 0;
    int rv = 0;

    EnterCriticalSection(&wiod->lock);
    if (!iod->writeable) {
	wiod->err = GE_NOTSUP;
	goto out;
    }
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->r.f, wiod->werr);
	rv = wiod->err;
	goto out_err;
    }
    if (iod->do_flush)
	goto out;
    gensio_circbuf_sg_write(iod->outbuf, sg, sglen, &count);
    wiod->write.ready = gensio_circbuf_room_left(iod->outbuf) > 0;
    LeaveCriticalSection(&wiod->lock);
    if (count)
	assert(SetEvent(iod->wakeh));
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
    struct gensio_iod_win_twoway *iod = i_to_win_twoway(wiod);
    gensiods count = 0;
    BOOL was_full;
    int rv = 0;

    EnterCriticalSection(&wiod->lock);
    if (!iod->readable) {
	wiod->err = GE_NOTSUP;
	goto out;
    }
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->r.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }

    was_full = gensio_circbuf_room_left(iod->inbuf) == 0;
    gensio_circbuf_read(iod->inbuf, ibuf, buflen, &count);
    wiod->read.ready = gensio_circbuf_datalen(iod->inbuf) > 0;
    if (was_full && count)
	assert(SetEvent(iod->wakeh));
 out:
    LeaveCriticalSection(&wiod->lock);
    if (rcount)
	*rcount = count;
    return rv;
}

static void
win_iod_twoway_wake(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *iod = i_to_win_twoway(wiod);

    assert(SetEvent(iod->wakeh));
}

static void
win_iod_twoway_clean(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *iod = i_to_win_twoway(wiod);

    if (iod->wakeh)
	CloseHandle(iod->wakeh);
    if (iod->inbuf) {
	gensio_circbuf_free(iod->inbuf);
	iod->inbuf = NULL;
    }

    if (iod->outbuf) {
	gensio_circbuf_free(iod->outbuf);
	iod->outbuf = NULL;
    }
}

static int
win_iod_twoway_init(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *iod = i_to_win_twoway(wiod);
    struct gensio_os_funcs *o = wiod->r.f;

    iod->inbuf = gensio_circbuf_alloc(o, 2048);
    if (!iod->inbuf)
	return GE_NOMEM;

    iod->outbuf = gensio_circbuf_alloc(o, 2048);
    if (!iod->outbuf) {
	gensio_circbuf_free(iod->inbuf);
	iod->inbuf = NULL;
	return GE_NOMEM;
    }

    iod->wakeh = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!iod->wakeh) {
	gensio_circbuf_free(iod->outbuf);
	iod->outbuf = NULL;
	gensio_circbuf_free(iod->inbuf);
	iod->inbuf = NULL;
	return GE_NOMEM;
    }

    return 0;
}

struct gensio_iod_win_dev
{
    struct gensio_iod_win_twoway b;

    char *name;

    BOOL is_serial_port;

    struct gensio_win_commport *cominfo;
};

#define i_to_windev(iod) gensio_container_of(iod,			\
					     struct gensio_iod_win_dev, \
					     b);
static int
win_dev_control(struct gensio_iod_win *wiod, int op, bool get, intptr_t val)
{
    struct gensio_iod_win_twoway *biod = i_to_win_twoway(wiod);
    struct gensio_iod_win_dev *iod = i_to_windev(biod);
    struct gensio_os_funcs *o = wiod->r.f;
    int rv = 0;

    if (!iod->is_serial_port)
	return GE_NOTSUP;

    EnterCriticalSection(&wiod->lock);
    rv = gensio_win_commport_control(o, op, get, val, &iod->cominfo,
				     biod->ioh);
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static DWORD
win_dev_break_handler(struct gensio_iod_win_twoway *biod)
{
    struct gensio_iod_win_dev *iod = i_to_windev(biod);

    return gensio_win_commport_break_done(biod->i.r.f, biod->ioh,
					  &iod->cominfo);
}

static void
win_iod_dev_clean(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *biod = i_to_win_twoway(wiod);
    struct gensio_iod_win_dev *iod = i_to_windev(biod);

    win_iod_twoway_clean(wiod);
    if (iod->name)
	wiod->r.f->free(wiod->r.f, iod->name);
}

static int
win_dev_close(struct gensio_iod_win *wiod)
{
    struct gensio_iod_win_twoway *biod = i_to_win_twoway(wiod);
    struct gensio_iod_win_dev *iod = i_to_windev(biod);
    int rv;

    rv = win_twoway_close(wiod);
    EnterCriticalSection(&wiod->lock);
    if (biod->ioh) {
	biod->extrah = NULL;
	gensio_win_cleanup_commport(wiod->r.f, biod->ioh, &iod->cominfo);
	CloseHandle(biod->ioh);
    }
    LeaveCriticalSection(&wiod->lock);
    return rv;
}

static int
win_iod_dev_init(struct gensio_iod_win *wiod, void *cb_data)
{
    struct gensio_iod_win_twoway *biod = i_to_win_twoway(wiod);
    struct gensio_iod_win_dev *iod = i_to_windev(biod);
    struct gensio_os_funcs *o = wiod->r.f;
    int rv;
    COMMPROP props;
    struct win_init_info *info = cb_data;

    rv = win_iod_twoway_init(wiod);
    if (rv)
	return rv;

    rv = GE_NOMEM;
    iod->name = gensio_alloc_sprintf(o, "\\\\.\\%s", info->name);
    if (!iod->name)
	goto out_err;

    biod->ioh = CreateFileA(iod->name, GENERIC_READ | GENERIC_WRITE, 0, NULL,
			    OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (!biod->ioh)
	goto out_err_conv;

    if (GetFileType(biod->ioh) != FILE_TYPE_CHAR) {
	rv = GE_NOTSUP;
	goto out_err;
    }
    if (!GetCommProperties(biod->ioh, &props))
	goto out_err_conv;

    switch (props.dwProvSubType) {
    case PST_MODEM:
    case PST_RS232:
    case PST_RS422:
    case PST_RS423:
    case PST_RS449:
	iod->is_serial_port = TRUE;
	biod->readable = TRUE;
	biod->writeable = TRUE;
	break;
    case PST_PARALLELPORT:
	iod->is_serial_port = FALSE;
	biod->writeable = TRUE;
	biod->readable = FALSE;
	break;
    default:
	rv = GE_NOTSUP;
	goto out_err;
    }

    if (iod->is_serial_port) {
	rv = gensio_win_setup_commport(o, biod->ioh, &iod->cominfo,
				       &biod->extrah);
	if (rv)
	    goto out_err;
	biod->extrah_func = win_dev_break_handler;
    }

    wiod->threadfunc = win_twoway_thread;

    wiod->clean = win_iod_dev_clean;
    wiod->wake = win_iod_twoway_wake;
    wiod->check = win_iod_check;

    return 0;

 out_err_conv:
    rv = gensio_os_err_to_err(o, GetLastError());
 out_err:
    win_iod_twoway_clean(wiod);
    return rv;
}

static unsigned int win_iod_sizes[NR_GENSIO_IOD_TYPES] = {
    [GENSIO_IOD_SOCKET] = sizeof(struct gensio_iod_win_sock),
    [GENSIO_IOD_STDIO] = sizeof(struct gensio_iod_win_stdio),
    [GENSIO_IOD_PIPE] = sizeof(struct gensio_iod_win_pipe),
};
typedef int (*win_iod_initfunc)(struct gensio_iod_win *, void *);
static win_iod_initfunc win_iod_init[NR_GENSIO_IOD_TYPES] = {
    [GENSIO_IOD_SOCKET] = win_iod_socket_init,
    [GENSIO_IOD_STDIO] = win_iod_stdio_init,
    [GENSIO_IOD_PIPE] = win_iod_pipe_init,
};

static int
win_add_iod(struct gensio_os_funcs *o, enum gensio_iod_type type,
	    intptr_t fd, struct gensio_iod **riod)
{
    int rv;
    struct gensio_iod_win *iod;

    if (type >= NR_GENSIO_IOD_TYPES || type < 0 || win_iod_sizes[type] == 0)
	return GE_NOTSUP;

    rv = win_alloc_iod(o, win_iod_sizes[type], fd, type,
		       win_iod_init[type], NULL, &iod);
    if (!rv)
	*riod = &iod->r;
    return rv;
}

static void win_release_iod(struct gensio_iod *iiod)
{
    struct gensio_os_funcs *o = iiod->f;
    struct gensio_data *d = o->user_data;
    struct gensio_iod_win *iod = i_to_win(iiod);
    BOOL do_free = FALSE;

    EnterCriticalSection(&d->lock);
    iod->done = TRUE;
    LeaveCriticalSection(&d->lock);
    if (iod->shutdown) {
	iod->shutdown(iod);
    } else if (iod->threadh) {
	iod->wake(iod);
	WaitForSingleObject(iod->threadh, INFINITE);
    }

    EnterCriticalSection(&d->lock);
    if (gensio_list_link_inlist(&iod->link))
	gensio_list_rm(&d->waiting_iods, &iod->link);
    gensio_list_rm(&d->all_iods, &iod->all_link);
    do_free = d->freed && gensio_list_empty(&d->all_iods);
    LeaveCriticalSection(&d->lock);

    if (iod->clean)
	iod->clean(iod);
    DeleteCriticalSection(&iod->lock);
    o->free(o, iod);

    if (do_free)
	win_finish_free(o);
}

static int
win_iod_get_type(struct gensio_iod *iiod)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    return iod->type;
}

static int
win_iod_get_fd(struct gensio_iod *iiod)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    return iod->fd;
}

static int
win_iod_get_protocol(struct gensio_iod *iiod)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    return iod->protocol;
}

static void
win_iod_set_protocol(struct gensio_iod *iiod, int protocol)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    iod->protocol = protocol;
}

static int
win_iod_control(struct gensio_iod *iiod, int op, bool get, intptr_t val)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    if (iod->type == GENSIO_IOD_DEV)
	return win_dev_control(iod, op, get, val);
    return GE_NOTSUP;
}

static int
win_recv(struct gensio_iod *iiod, void *buf, gensiods buflen,
	 gensiods *rcount, int gflags)
{
    struct gensio_os_funcs *o = iiod->f;
    struct gensio_iod_win *wiod = i_to_win(iiod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->r.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    wiod->read.ready = FALSE;
    wiod->except.ready = FALSE;
    rv = d->orig_recv(iiod, buf, buflen, rcount, gflags);
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_send(struct gensio_iod *iiod,
	 const struct gensio_sg *sg, gensiods sglen,
	 gensiods *rcount, int gflags)
{
    struct gensio_os_funcs *o = iiod->f;
    struct gensio_iod_win *wiod = i_to_win(iiod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->r.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    wiod->write.ready = FALSE;
    rv = d->orig_send(iiod, sg, sglen, rcount, gflags);
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_sendto(struct gensio_iod *iiod,
	   const struct gensio_sg *sg, gensiods sglen,
	   gensiods *rcount, int gflags,
	   const struct gensio_addr *raddr)
{
    struct gensio_os_funcs *o = iiod->f;
    struct gensio_iod_win *wiod = i_to_win(iiod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->r.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    wiod->write.ready = FALSE;
    rv = d->orig_sendto(iiod, sg, sglen, rcount, gflags, raddr);
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_recvfrom(struct gensio_iod *iiod, void *buf, gensiods buflen,
	     gensiods *rcount, int flags, struct gensio_addr *addr)
{
    struct gensio_os_funcs *o = iiod->f;
    struct gensio_iod_win *wiod = i_to_win(iiod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->r.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    wiod->read.ready = FALSE;
    wiod->except.ready = FALSE;
    rv = d->orig_recvfrom(iiod, buf, buflen, rcount, flags, addr);
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_accept(struct gensio_iod *iiod,
	   struct gensio_addr **raddr, struct gensio_iod **newiod)
{
    struct gensio_os_funcs *o = iiod->f;
    struct gensio_iod_win *wiod = i_to_win(iiod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->r.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    rv = d->orig_accept(iiod, raddr, newiod);
    if (rv && WSAGetLastError() != WSAEWOULDBLOCK)
	wiod->read.ready = FALSE;
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_connect(struct gensio_iod *iiod, const struct gensio_addr *addr)
{
    struct gensio_os_funcs *o = iiod->f;
    struct gensio_iod_win *wiod = i_to_win(iiod);
    struct gensio_iod_win_sock *siod = i_to_winsock(wiod);
    struct gensio_data *d = o->user_data;
    int rv;

    if (wiod->type != GENSIO_IOD_SOCKET)
	return GE_INVAL;

    EnterCriticalSection(&wiod->lock);
    if (wiod->err || wiod->werr) {
	if (!wiod->err)
	    wiod->err = gensio_os_err_to_err(wiod->r.f, wiod->werr);
	rv = wiod->err;
	goto out;
    }
    rv = d->orig_connect(iiod, addr);
    if (rv == 0)
	siod->connected = TRUE;
 out:
    LeaveCriticalSection(&wiod->lock);

    return rv;
}

static int
win_close(struct gensio_iod **iodp)
{
    struct gensio_iod *iiod = *iodp;
    struct gensio_iod_win *iod = i_to_win(iiod);
    struct gensio_os_funcs *o = iiod->f;
    int err;

    /* Don't do errtrig on close, it can fail and not cause any issues. */

    assert(iod);
    if (iod->type == GENSIO_IOD_SOCKET) {
	err = o->close_socket(iiod);
    } else if (iod->type == GENSIO_IOD_STDIO) {
	err = win_stdio_close(iod);
    } else if (iod->type == GENSIO_IOD_PIPE) {
	err = win_oneway_close(iod);
    } else if (iod->type == GENSIO_IOD_DEV) {
	err = win_dev_close(iod);
    } else {
	err = GE_NOTSUP;
    }
    if (!err) {
	win_release_iod(iiod);
	*iodp = NULL;
    }
    return err;
}

static int
win_set_non_blocking(struct gensio_iod *iiod)
{
    struct gensio_iod_win *iod = i_to_win(iiod);
    struct gensio_os_funcs *o = iiod->f;
    unsigned long flags = 1;
    int rv = 0;

    if (do_errtrig())
	return GE_NOMEM;

    if (iod->type == GENSIO_IOD_SOCKET) {
	rv = ioctlsocket(iod->fd, FIONBIO, &flags);
    } else if (iod->type == GENSIO_IOD_STDIO) {
	/* Nothing to do, already non-blocking. */
    } else if (iod->type == GENSIO_IOD_DEV) {
	/* Nothing to do, already non-blocking. */
    } else if (iod->type == GENSIO_IOD_PIPE) {
	/* Nothing to do, already non-blocking. */
    } else {
	return GE_NOTSUP;
    }
    if (rv)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

static int
win_write(struct gensio_iod *iiod,
	  const struct gensio_sg *sg, gensiods sglen,
	  gensiods *rcount)
{
    struct gensio_iod_win *iod = i_to_win(iiod);
    struct gensio_os_funcs *o = iiod->f;

    if (iod->type == GENSIO_IOD_SOCKET) {
	return o->send(iiod, sg, sglen, rcount, 0);
    } else if (iod->type == GENSIO_IOD_STDIO || 
	       iod->type == GENSIO_IOD_PIPE) {
	return win_oneway_write(iod, sg, sglen, rcount);
    } else if (iod->type == GENSIO_IOD_DEV) {
	return win_twoway_write(iod, sg, sglen, rcount);
    }

    return GE_NOTSUP;
}

static int
win_read(struct gensio_iod *iiod,
	 void *ibuf, gensiods buflen, gensiods *rcount)
{
    struct gensio_iod_win *iod = i_to_win(iiod);
    struct gensio_os_funcs *o = iiod->f;

    if (iod->type == GENSIO_IOD_SOCKET) {
	return o->recv(iiod, ibuf, buflen, rcount, 0);
    } else if (iod->type == GENSIO_IOD_STDIO ||
	       iod->type == GENSIO_IOD_PIPE) {
	return win_oneway_read(iod, ibuf, buflen, rcount);
    } else if (iod->type == GENSIO_IOD_DEV) {
	return win_twoway_read(iod, ibuf, buflen, rcount);
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
win_bufcount(struct gensio_iod *iiod, int whichbuf, gensiods *count)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    if (iod->type == GENSIO_IOD_STDIO ||
	iod->type == GENSIO_IOD_PIPE)
	return win_oneway_bufcount(iod, whichbuf, count);
    if (iod->type == GENSIO_IOD_DEV)
	return win_twoway_bufcount(iod, whichbuf, count);

    return GE_NOTSUP;
}

static void
win_flush(struct gensio_iod *iiod, int whichbuf)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    if (iod->type == GENSIO_IOD_STDIO ||
	iod->type == GENSIO_IOD_PIPE)
	win_oneway_flush(iod);
    else if (iod->type == GENSIO_IOD_DEV)
	win_twoway_flush(iod);
}

static int
win_makeraw(struct gensio_iod *iiod)
{
    struct gensio_iod_win *iod = i_to_win(iiod);

    if (do_errtrig())
	return GE_NOMEM;

    if (iod->type == GENSIO_IOD_STDIO)
	return win_stdio_makeraw(iod);
    if (iod->type == GENSIO_IOD_DEV)
	return 0; /* Nothing to do. */
    if (iod->type == GENSIO_IOD_PIPE)
	return 0; /* Nothing to do. */

    return GE_NOTSUP;
}

static int
win_open_dev(struct gensio_os_funcs *o, const char *iname, int options,
	     struct gensio_iod **riod)
{
    struct gensio_iod_win *iod;
    struct win_init_info info;
    int rv;

    info.name = iname;
    rv = win_alloc_iod(o, sizeof(struct gensio_iod_win_dev), -1,
		       GENSIO_IOD_DEV, win_iod_dev_init, &info, &iod);
    if (!rv)
	*riod = &iod->r;
    return rv;
}

/*
 * FIXME - This currently doesn't handle running the subprogram as a
 * different user like it should (and the selector code does).
 */
static int
win_exec_subprog(struct gensio_os_funcs *o,
		 const char *argv[], const char **env,
		 bool stderr_to_stdout,
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

    rv = gensio_win_do_exec(o, argv, env, stderr_to_stdout, &phandle,
			    &stdin_m, &stdout_m,
			    rstderr ? &stderr_m : NULL);
    if (rv)
	return rv;


    rv = o->add_iod(o, GENSIO_IOD_PIPE, (intptr_t) stdin_m, &stdin_iod);
    if (rv)
	goto out_err;
    rv = o->add_iod(o, GENSIO_IOD_PIPE, (intptr_t) stdout_m, &stdout_iod);
    if (rv)
	goto out_err;

    if (stderr_m) {
	rv = o->add_iod(o, GENSIO_IOD_PIPE, (intptr_t) stderr_m, &stderr_iod);
	if (rv)
	    goto out_err;
    }

    *rpid = (intptr_t) phandle;
    *rstdin = &stdin_iod->r;
    *rstdout = &stdout_iod->r;
    if (rstderr)
	*rstderr = &stderr_iod->r;
    return 0;

 out_err:
    if (stdin_iod) {
	struct gensio_iod *iod = &stdin_iod->r;
	o->close(&iod);
    } else if (stdin_m)
	CloseHandle(stdin_m);
    if (stdout_iod) {
	struct gensio_iod *iod = &stdout_iod->r;
	o->close(&iod);
    } else if (stdout_m)
	CloseHandle(stdout_m);
    if (stderr_iod) {
	struct gensio_iod *iod = &stderr_iod->r;
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
    DeleteCriticalSection(&d->lock);
    DeleteCriticalSection(&d->timer_lock);
    DeleteCriticalSection(&d->once_lock);
    free(d);
    free(o);
    WSACleanup();
}

int
gensio_win_funcs_alloc(struct gensio_os_funcs **ro)
{
    struct gensio_data *d;
    struct gensio_os_funcs *o;

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
    InitializeCriticalSection(&d->lock);
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
    o->call_once = win_call_once;
    o->get_monotonic_time = win_get_monotonic_time;
    o->handle_fork = win_handle_fork;
    o->wait_intr_sigmask = win_wait_intr_sigmask;
    o->add_iod = win_add_iod;
    o->release_iod = win_release_iod;
    o->iod_get_type = win_iod_get_type;
    o->iod_get_fd = win_iod_get_fd;
    o->iod_get_protocol = win_iod_get_protocol;
    o->iod_set_protocol = win_iod_set_protocol;
    o->iod_control = win_iod_control;

    o->set_non_blocking = win_set_non_blocking;
    o->close = win_close;
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

    gensio_addr_addrinfo_set_os_funcs(o);
    gensio_stdsock_set_os_funcs(o);

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

    if (WSAStartup(MAKEWORD(2, 2), &d->wsa_data))
	goto out_err;

    *ro = o;
    return o;

 out_err:
    win_finish_free(o);
    return GE_NOMEM;
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
    case ERROR_FILE_NOT_FOUND:	err = GE_NOTFOUND; break;
    case ERROR_NOT_FOUND:	err = GE_NOTFOUND; break;
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

static INIT_ONCE win_oshnd_once = INIT_ONCE_STATIC_INIT;
static struct gensio_os_funcs *def_win_os_funcs;

static BOOL CALLBACK win_oshnd_init(PINIT_ONCE InitOnce,
				    PVOID Parameter,
				    PVOID *lpContext)
{
    int rv = gensio_win_funcs_alloc(&def_win_os_funcs);
    
    if (!rv)
	*lpContext = def_win_os_funcs;
    return !!def_win_os_funcs;
}

int
gensio_default_os_hnd(int wake_sig, struct gensio_os_funcs **o)
{
    BOOL worked;
    void *r;

    worked = InitOnceExecuteOnce(&win_oshnd_once, win_oshnd_init,
				 NULL, &r);
    if (!worked)
	return GE_NOMEM;
    *o = r;
    return 0;
}

void
gensio_osfunc_exit(int rv)
{
    exit(rv);
}
