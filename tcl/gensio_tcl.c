/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This library provides a gensio_os_funcs object for use by gensio.
 * It can be used if you have a project based on tcl that you want to
 * integrate gensio into.
 *
 * Unfortunately, it has some limitations because of weaknesses in the
 * tcl interface.  Basically, no threads.
 *
 * In tcl, if you start a timer, that timer will only fire in that
 * thread's call to Tcl_DoOneEvent.  Same with file handlers.
 * Basically, timers, idle calls, and file handlers belong to a thread.
 *
 * You could, theoretically, have multiple threads as long as you
 * allocate an os handler per thread and did everything with an os
 * handler only in the thread that created it.  But that's not very
 * useful.
 *
 * If you really want real threading to work, you put tcl on top of
 * gensio os funcs using Tcl_NotifierProcs.  I leave that as an
 * exercise to the reader.
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_tcl.h>
#include <gensio/gensio_err.h>
#include <gensio/gensio.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_osops_addrinfo.h>
#include <gensio/gensio_osops_stdsock.h>
#include <gensio/argvutils.h>

#define TCL_THREADS 1
#include <tcl.h>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <string.h>
#include <sys/ioctl.h>

struct gensio_data
{
    struct gensio_memtrack *mtrack;
    unsigned int refcount;
    struct gensio_os_proc_data *pdata;
};

static void *
gensio_tcl_zalloc(struct gensio_os_funcs *f, gensiods size)
{
    struct gensio_data *d = f->user_data;

    return gensio_i_zalloc(d->mtrack, size);
}

static void
gensio_tcl_free(struct gensio_os_funcs *f, void *data)
{
    struct gensio_data *d = f->user_data;

    gensio_i_free(d->mtrack, data);
}

struct gensio_lock {
    struct gensio_os_funcs *f;
    Tcl_Mutex mutex;
};

static struct gensio_lock *
gensio_tcl_alloc_lock(struct gensio_os_funcs *f)
{
    struct gensio_lock *lock;

    lock = gensio_tcl_zalloc(f, sizeof(*lock));
    if (!lock)
	return NULL;
    lock->f = f;

    return lock;
}

static void
gensio_tcl_free_lock(struct gensio_lock *lock)
{
    Tcl_MutexFinalize(&lock->mutex);
    gensio_tcl_free(lock->f, lock);
}

static void
gensio_tcl_lock(struct gensio_lock *lock)
{
    Tcl_MutexLock(&lock->mutex);
}

static void
gensio_tcl_unlock(struct gensio_lock *lock)
{
    Tcl_MutexUnlock(&lock->mutex);
}

struct gensio_iod_tcl {
    struct gensio_iod r;

    Tcl_Mutex lock;

    int mask;

    bool in_clear;
    enum { CL_NOT_CALLED, CL_CALLED, CL_DONE } close_state;

    int orig_fd;
    int fd;
    enum gensio_iod_type type;
    void *sockinfo;
    bool handlers_set;
    bool is_stdio;
    void *cb_data;
    void (*read_handler)(struct gensio_iod *iod, void *cb_data);
    void (*write_handler)(struct gensio_iod *iod, void *cb_data);
    void (*except_handler)(struct gensio_iod *iod, void *cb_data);
    void (*cleared_handler)(struct gensio_iod *iod, void *cb_data);

    struct stdio_mode *mode;

    struct gensio_unix_termios *termios;

    /* For GENSIO_IOD_FILE */
    struct gensio_runner *runner;
    bool read_enabled;
    bool write_enabled;
    bool in_handler;

    /* For GENSIO_IOD_PTY */
    const char **argv;
    const char **env;
    char *start_dir;
    int pid;
};

#define i_to_tcl(i) gensio_container_of(i, struct gensio_iod_tcl, r);

static void
tcl_file_handler(ClientData data, int mask)
{
    struct gensio_iod_tcl *iod = data;

    if (mask & TCL_READABLE)
	iod->read_handler(&iod->r, iod->cb_data);
    if (mask & TCL_WRITABLE)
	iod->write_handler(&iod->r, iod->cb_data);
    if (mask & TCL_EXCEPTION)
	iod->except_handler(&iod->r, iod->cb_data);
}

static void
tcl_cleared_done(ClientData data)
{
    struct gensio_iod_tcl *iod = data;

    Tcl_MutexLock(&iod->lock);
    iod->handlers_set = false;
    iod->read_handler = NULL;
    iod->write_handler = NULL;
    iod->except_handler = NULL;
    iod->in_clear = false;
    Tcl_MutexUnlock(&iod->lock);
    if (iod->cleared_handler)
	iod->cleared_handler(&iod->r, iod->cb_data);
}

static int
gensio_tcl_set_fd_handlers(struct gensio_iod *iiod,
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
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);

    Tcl_MutexLock(&iod->lock);
    if (iod->handlers_set) {
	Tcl_MutexUnlock(&iod->lock);
	return GE_INUSE;
    }

    iod->handlers_set = true;

    iod->cb_data = cb_data;
    iod->read_handler = read_handler;
    iod->write_handler = write_handler;
    iod->except_handler = except_handler;
    iod->cleared_handler = cleared_handler;

    Tcl_MutexUnlock(&iod->lock);

    return 0;
}

static void
gensio_tcl_clear_fd_handlers(struct gensio_iod *iiod)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);

    Tcl_MutexLock(&iod->lock);
    if (!iod->handlers_set || iod->in_clear)
	goto out_unlock;
    if (iod->mask)
	Tcl_DeleteFileHandler(iod->fd);
    iod->in_clear = true;
    Tcl_DoWhenIdle(tcl_cleared_done, iod);
 out_unlock:
    Tcl_MutexUnlock(&iod->lock);
}

static void
gensio_tcl_clear_fd_handlers_norpt(struct gensio_iod *iiod)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);

    Tcl_MutexLock(&iod->lock);
    assert(iod->mask == 0);
    iod->handlers_set = false;
    Tcl_MutexUnlock(&iod->lock);
}

static void
file_runner(struct gensio_runner *r, void *cb_data)
{
    struct gensio_iod_tcl *iod = cb_data;

    Tcl_MutexLock(&iod->lock);
    while (iod->read_enabled || iod->write_enabled) {
	if (iod->read_enabled) {
	    Tcl_MutexUnlock(&iod->lock);
	    iod->read_handler(&iod->r, iod->cb_data);
	    Tcl_MutexLock(&iod->lock);
	}
	if (iod->write_enabled) {
	    Tcl_MutexUnlock(&iod->lock);
	    iod->write_handler(&iod->r, iod->cb_data);
	    Tcl_MutexLock(&iod->lock);
	}
    }
    iod->in_handler = false;
    if (iod->in_clear) {
	iod->in_clear = false;
	iod->handlers_set = false;
	Tcl_MutexUnlock(&iod->lock);
	iod->cleared_handler(&iod->r, iod->cb_data);
	Tcl_MutexLock(&iod->lock);
    }
    Tcl_MutexUnlock(&iod->lock);
}

static void
gensio_tcl_set_read_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);
    int new_mask;

    Tcl_MutexLock(&iod->lock);
    if (iod->type == GENSIO_IOD_FILE) {
	if (iod->read_enabled == enable || iod->in_clear)
	    goto out_unlock;
	iod->read_enabled = enable;
	if (enable && !iod->in_handler) {
	    iod->r.f->run(iod->runner);
	    iod->in_handler = true;
	}
	goto out_unlock;
    }

    new_mask = iod->mask;
    if (enable)
	new_mask |= TCL_READABLE;
    else
	new_mask &= ~TCL_READABLE;

    if (new_mask == iod->mask)
	goto out_unlock;

    iod->mask = new_mask;
    if (new_mask == 0)
	Tcl_DeleteFileHandler(iod->fd);
    else
	Tcl_CreateFileHandler(iod->fd, new_mask, tcl_file_handler, iod);
 out_unlock:
    Tcl_MutexUnlock(&iod->lock);
}

static void
gensio_tcl_set_write_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);
    int new_mask;

    Tcl_MutexLock(&iod->lock);
    if (iod->type == GENSIO_IOD_FILE) {
	if (iod->write_enabled == enable || iod->in_clear)
	    goto out_unlock;
	iod->write_enabled = enable;
	if (enable && !iod->in_handler) {
	    iod->r.f->run(iod->runner);
	    iod->in_handler = true;
	}
	goto out_unlock;
    }

    new_mask = iod->mask;
    if (enable)
	new_mask |= TCL_WRITABLE;
    else
	new_mask &= ~TCL_WRITABLE;

    if (new_mask == iod->mask)
	goto out_unlock;

    iod->mask = new_mask;
    Tcl_CreateFileHandler(iod->fd, new_mask, tcl_file_handler, iod);
 out_unlock:
    Tcl_MutexUnlock(&iod->lock);
}

static void
gensio_tcl_set_except_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);
    int new_mask;

    if (iod->type == GENSIO_IOD_FILE)
	return;

    Tcl_MutexLock(&iod->lock);
    new_mask = iod->mask;
    if (enable)
	new_mask |= TCL_EXCEPTION;
    else
	new_mask &= ~TCL_EXCEPTION;

    if (new_mask == iod->mask)
	goto out_unlock;

    iod->mask = new_mask;
    Tcl_CreateFileHandler(iod->fd, new_mask, tcl_file_handler, iod);
 out_unlock:
    Tcl_MutexUnlock(&iod->lock);
}

struct gensio_timer
{
    struct gensio_os_funcs *o;

    void (*handler)(struct gensio_timer *t, void *cb_data);
    void *cb_data;

    Tcl_Mutex lock;

    Tcl_TimerToken timer_id;

    enum {
	  TCL_TIMER_FREE,
	  TCL_TIMER_IN_STOP,
	  TCL_TIMER_STOPPED,
	  TCL_TIMER_RUNNING
    } state;

    void (*done_handler)(struct gensio_timer *t, void *cb_data);
    void *done_cb_data;
};

static void
gensio_tcl_timeout_handler(ClientData data)
{
    struct gensio_timer *t = data;
    void (*handler)(struct gensio_timer *t, void *cb_data) = NULL;
    void *cb_data;

    Tcl_MutexLock(&t->lock);
    if (t->timer_id) {
	handler = t->handler;
	cb_data = t->cb_data;
	t->state = TCL_TIMER_STOPPED;
	t->timer_id = 0;
    }
    Tcl_MutexUnlock(&t->lock);

    if (handler)
	handler(t, cb_data);
}

static struct gensio_timer *
gensio_tcl_alloc_timer(struct gensio_os_funcs *o,
			void (*handler)(struct gensio_timer *t,
					void *cb_data),
			void *cb_data)
{
    struct gensio_timer *t;

    t = o->zalloc(o, sizeof(*t));
    if (!t)
	return NULL;

    t->o = o;
    t->handler = handler;
    t->cb_data = cb_data;
    t->state = TCL_TIMER_STOPPED;

    return t;
}

static void
gensio_tcl_free_timer(struct gensio_timer *t)
{
    Tcl_MutexLock(&t->lock);
    assert(t->state != TCL_TIMER_FREE);
    if (t->state == TCL_TIMER_RUNNING) {
	Tcl_DeleteTimerHandler(t->timer_id);
	t->timer_id = NULL;
    }
    t->state = TCL_TIMER_FREE;
    Tcl_MutexUnlock(&t->lock);
    t->o->free(t->o, t);
}

/*
 * Various time conversion routines.  Note that we always truncate up
 * to the next time unit.  These are used for timers, and if you don't
 * you can end up with an early timeout.
 */
static unsigned int
gensio_time_to_ms(gensio_time *t)
{
    return t->secs * 1000 + (t->nsecs + 999999) / 1000000;
}

static int64_t
gensio_time_to_us(gensio_time *t)
{
    return t->secs * 1000000ULL + (t->nsecs + 999) / 1000;
}

static unsigned int
us_time_to_ms(int64_t t)
{
    return (t + 999) / 1000;
}

static void
us_time_to_gensio(int64_t t, gensio_time *gt)
{
    gt->secs = t / 1000000;
    gt->nsecs = t % 1000000 * 1000;
}

static int
gensio_tcl_start_timer(struct gensio_timer *t, gensio_time *timeout)
{
    int msec = gensio_time_to_ms(timeout);
    int rv = 0;

    Tcl_MutexLock(&t->lock);
    assert(t->state != TCL_TIMER_FREE);
    if (t->state != TCL_TIMER_STOPPED) {
	rv = GE_INUSE;
    } else {
	t->done_handler = NULL;
	t->timer_id = Tcl_CreateTimerHandler(msec, gensio_tcl_timeout_handler,
					     t);
	if (!t->timer_id) {
	    rv = GE_NOMEM;
	} else {
	    t->state = TCL_TIMER_RUNNING;
	}
    }
    Tcl_MutexUnlock(&t->lock);

    return rv;
}

static int
gensio_tcl_start_timer_abs(struct gensio_timer *t, gensio_time *timeout)
{
    struct timespec ts;
    int64_t tnsecs, nnsecs;
    int msec;
    int rv = 0;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    tnsecs = timeout->secs * 1000000000ULL + timeout->nsecs;
    nnsecs = ts.tv_sec * 1000000000ULL | ts.tv_nsec;
    if (tnsecs < nnsecs)
	tnsecs = 0;
    else
	tnsecs -= nnsecs;
    msec = (tnsecs + 999999ULL) / 1000000;

    Tcl_MutexLock(&t->lock);
    assert(t->state != TCL_TIMER_FREE);
    if (t->state != TCL_TIMER_STOPPED) {
	rv = GE_INUSE;
    } else {
	t->done_handler = NULL;
	t->timer_id = Tcl_CreateTimerHandler(msec, gensio_tcl_timeout_handler,
					     t);
	if (!t->timer_id) {
	    rv = GE_NOMEM;
	} else {
	    t->state = TCL_TIMER_RUNNING;
	}
    }
    Tcl_MutexUnlock(&t->lock);
    return rv;
}

static int
gensio_tcl_stop_timer(struct gensio_timer *t)
{
    int rv = 0;

    Tcl_MutexLock(&t->lock);
    assert(t->state != TCL_TIMER_FREE);
    if (t->state != TCL_TIMER_RUNNING) {
	rv = GE_TIMEDOUT;
    } else {
	t->state = TCL_TIMER_STOPPED;
	Tcl_DeleteTimerHandler(t->timer_id);
	t->timer_id = NULL;
    }
    Tcl_MutexUnlock(&t->lock);
    return rv;
}

static void
gensio_tcl_timeout_done(ClientData data)
{
    struct gensio_timer *t = data;
    void (*done_handler)(struct gensio_timer *t, void *cb_data) = NULL;
    void *done_cb_data;

    Tcl_MutexLock(&t->lock);
    if (t->state == TCL_TIMER_FREE) {
	Tcl_MutexFinalize(&t->lock);
	t->o->free(t->o, t);
    } else {
	t->state = TCL_TIMER_STOPPED;
	done_handler = t->done_handler;
	done_cb_data = t->done_cb_data;
	t->done_handler = NULL;
    }
    Tcl_MutexUnlock(&t->lock);

    if (done_handler)
	done_handler(t, done_cb_data);
}

static int
gensio_tcl_stop_timer_with_done(struct gensio_timer *t,
				 void (*done_handler)(struct gensio_timer *t,
						      void *cb_data),
				 void *cb_data)
{
    int rv = 0;

    Tcl_MutexLock(&t->lock);
    if (t->state == TCL_TIMER_IN_STOP) {
	rv = GE_INUSE;
    } else if (t->state != TCL_TIMER_RUNNING) {
	rv = GE_TIMEDOUT;
    } else {
	t->state = TCL_TIMER_IN_STOP;
	t->done_handler = done_handler;
	t->done_cb_data = cb_data;
	Tcl_DeleteTimerHandler(t->timer_id);
	t->timer_id = NULL;
	Tcl_DoWhenIdle(gensio_tcl_timeout_done, t);
    }
    Tcl_MutexUnlock(&t->lock);

    return rv;
}

struct gensio_runner
{
    struct gensio_os_funcs *o;

    void (*handler)(struct gensio_runner *r, void *cb_data);
    void *cb_data;
    bool freed;
    bool in_use;

    Tcl_Mutex lock;
};

static void
gensio_tcl_idle_handler(ClientData data)
{
    struct gensio_runner *r = (void *) data;
    void (*handler)(struct gensio_runner *r, void *cb_data) = NULL;
    void *cb_data;

    Tcl_MutexLock(&r->lock);
    if (r->freed) {
	Tcl_MutexUnlock(&r->lock);
	Tcl_MutexFinalize(&r->lock);
	r->o->free(r->o, r);
    } else {
	handler = r->handler;
	cb_data = r->cb_data;
	r->in_use = false;
	Tcl_MutexUnlock(&r->lock);
    }

    if (handler)
	handler(r, cb_data);
}

static struct gensio_runner *
gensio_tcl_alloc_runner(struct gensio_os_funcs *o,
			 void (*handler)(struct gensio_runner *r,
					 void *cb_data),
			 void *cb_data)
{
    struct gensio_runner *r;

    r = o->zalloc(o, sizeof(*r));
    if (!r)
	return NULL;

    r->o = o;
    r->handler = handler;
    r->cb_data = cb_data;

    return r;
}

static void
gensio_tcl_free_runner(struct gensio_runner *r)
{
    Tcl_MutexLock(&r->lock);
    if (r->in_use) {
	r->freed = true;
	Tcl_MutexUnlock(&r->lock);
    } else {
	Tcl_MutexUnlock(&r->lock);
	Tcl_MutexFinalize(&r->lock);
	r->o->free(r->o, r);
    }
}

static int
gensio_tcl_run(struct gensio_runner *r)
{
    int rv = 0;

    Tcl_MutexLock(&r->lock);
    if (r->in_use) {
	rv = GE_INUSE;
    } else {
	Tcl_DoWhenIdle(gensio_tcl_idle_handler, r);
	r->in_use = true;
    }
    Tcl_MutexUnlock(&r->lock);
    return rv;
}

struct gensio_waiter
{
    struct gensio_os_funcs *o;

    unsigned int count;
};

static struct gensio_waiter *
gensio_tcl_alloc_waiter(struct gensio_os_funcs *o)
{
    struct gensio_waiter *w;

    w = o->zalloc(o, sizeof(*w));
    if (!w)
	return NULL;

    w->o = o;

    return w;
}

static void
gensio_tcl_free_waiter(struct gensio_waiter *w)
{
    w->o->free(w->o, w);
}

struct dummy_timeout_data {
    bool did_something;
    Tcl_TimerToken timer;
};

static void
dummy_timeout_handler(ClientData data)
{
    struct dummy_timeout_data *td = data;

    td->did_something = false;
}

static void
dummy_idle_handler(ClientData data)
{
    struct dummy_timeout_data *td = data;

    td->did_something = false;
}

struct timeout_info {
    gensio_time *timeout;

    /* Times below are in microseconds. */
    int64_t start;
    int64_t now;
    int64_t end;
};

static int64_t
fetch_us_time(void)
{
    Tcl_Time now;

    Tcl_GetTime(&now);
    return (now.sec * 1000000ULL) + now.usec;
}

static void
setup_timeout(struct timeout_info *t)
{
    if (t->timeout) {
	t->start = t->now = fetch_us_time();
	t->end = t->now + gensio_time_to_us(t->timeout);
    } else {
	t->start = 0;
	t->now = 0;
	t->end = 0;
    }
}

static bool
timed_out(struct timeout_info *t)
{
    return t->timeout && t->now >= t->end;
}

static bool
timeout_wait(struct timeout_info *t)
{
    struct dummy_timeout_data td = { .did_something = true, .timer = NULL };

    if (t->timeout) {
	unsigned int timeout = us_time_to_ms(t->end - t->now);

	if (timeout) {
	    td.timer = Tcl_CreateTimerHandler(timeout,
					      dummy_timeout_handler,
					      &td);
	    Tcl_DoOneEvent(0);
	    Tcl_DeleteTimerHandler(td.timer);
	} else {
	    Tcl_DoWhenIdle(dummy_idle_handler, &td);
	    Tcl_DoOneEvent(0);
	    if (!td.did_something)
		Tcl_CancelIdleCall(dummy_idle_handler, &td);
	}
	if (td.timer)
	    Tcl_DeleteTimerHandler(td.timer);
    } else {
	Tcl_DoOneEvent(0);
    }

    return td.did_something;
}

static void
timeout_end(struct timeout_info *t)
{
    if (t->timeout) {
	int64_t diff = t->end - t->now;

	if (diff > 0) {
	    us_time_to_gensio(diff, t->timeout);
	} else {
	    t->timeout->secs = 0;
	    t->timeout->nsecs = 0;
	}
    }
}

static int
gensio_tcl_wait_intr_sigmask(struct gensio_waiter *w, unsigned int count,
			     gensio_time *timeout,
			     struct gensio_os_proc_data *proc_data)
{
    struct timeout_info ti = { .timeout = timeout };
    int rv = 0;
    sigset_t origmask;

    if (proc_data) {
	pthread_sigmask(SIG_SETMASK,
			gensio_os_proc_unix_get_wait_sigset(proc_data),
			&origmask);
    }
    setup_timeout(&ti);

    while (count > w->count && !timed_out(&ti)) {
	timeout_wait(&ti);
	ti.now = fetch_us_time();
    }
    if (count > w->count)
	rv = GE_TIMEDOUT;
    else
	w->count -= count;

    timeout_end(&ti);

    if (proc_data) {
	pthread_sigmask(SIG_SETMASK, &origmask, NULL);
	gensio_os_proc_check_handlers(proc_data);
    }

    return rv;
}

static int
gensio_tcl_wait(struct gensio_waiter *w, unsigned int count,
		gensio_time *timeout)
{
    struct gensio_data *d = w->o->user_data;
    int rv = GE_INTERRUPTED;

    while (rv == GE_INTERRUPTED)
	rv = gensio_tcl_wait_intr_sigmask(w, count, timeout, d->pdata);

    return rv;
}

static int
gensio_tcl_wait_intr(struct gensio_waiter *w, unsigned int count,
		     gensio_time *timeout)
{
    struct gensio_data *d = w->o->user_data;

    return gensio_tcl_wait_intr_sigmask(w, count, timeout, d->pdata);
}

static void
gensio_tcl_wake(struct gensio_waiter *w)
{
    w->count += 1;
}

static int
gensio_tcl_add_iod(struct gensio_os_funcs *o, enum gensio_iod_type type,
		   intptr_t ofd, struct gensio_iod **riod)
{
    struct gensio_iod_tcl *iod = NULL;
    bool closefd = false;
    int err = GE_NOMEM, fd = ofd;

    if (type == GENSIO_IOD_CONSOLE) {
       if (fd == 0)
           fd = open("/dev/tty", O_RDONLY);
       else if (fd == 1)
           fd = open("/dev/tty", O_WRONLY);
       else
           return GE_INVAL;
       if (fd == -1)
           return gensio_os_err_to_err(o, errno);
       closefd = true;
    } else if (type == GENSIO_IOD_PTY) {
	err = gensio_unix_pty_alloc(o, &fd);
	if (err)
	    return err;
	closefd = true;
    }

    iod = o->zalloc(o, sizeof(*iod));
    if (!iod) {
	err = GE_NOMEM;
	goto out_err;
    }

    iod->r.f = o;
    iod->fd = fd;
    iod->orig_fd = ofd;
    if (type == GENSIO_IOD_STDIO) {
	struct stat statb;

	iod->is_stdio = true;

	err = fstat(fd, &statb);
	if (err == -1) {
	    err = gensio_os_err_to_err(o, errno);
	    goto out_err;
	}
	switch (statb.st_mode & S_IFMT) {
	case S_IFREG: type = GENSIO_IOD_FILE; break;
	case S_IFCHR: type = GENSIO_IOD_DEV; break;
	case S_IFIFO: type = GENSIO_IOD_PIPE; break;
	case S_IFSOCK: type = GENSIO_IOD_SOCKET; break;
	default:
	    err = GE_INVAL;
	    goto out_err;
	}
    } else if (type == GENSIO_IOD_PTY) {
	iod->pid = -1;
    }
    iod->type = type;

    if (type == GENSIO_IOD_FILE) {
	iod->runner = o->alloc_runner(o, file_runner, iod);
	if (!iod->runner)
	    goto out_err;
    }

    *riod = &iod->r;

    return 0;
 out_err:
    if (iod)
	o->free(o, iod);
    else if (closefd)
	close(fd);
    return err;
}

static void
gensio_tcl_release_iod(struct gensio_iod *iiod)
{
    struct gensio_os_funcs *o = iiod->f;
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);

    assert(!iod->handlers_set);
    Tcl_MutexFinalize(&iod->lock);
    if (iod->type == GENSIO_IOD_FILE)
	o->free_runner(iod->runner);
    if (iod->type == GENSIO_IOD_PTY) {
	if (iod->argv)
	    gensio_argv_free(o, iod->argv);
	if (iod->env)
	    gensio_argv_free(o, iod->env);
    }
    o->free(o, iod);
}

static int
gensio_tcl_iod_get_type(struct gensio_iod *iiod)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);

    return iod->type;
}

static int
gensio_tcl_iod_get_fd(struct gensio_iod *iiod)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);

    return iod->fd;
}

static int
gensio_tcl_pty_control(struct gensio_iod_tcl *iod, int op, bool get,
		       intptr_t val)
{
    struct gensio_os_funcs *o = iod->r.f;
    int err = 0;
    const char **nargv;

    if (get) {
	if (op == GENSIO_IOD_CONTROL_PID) {
	    if (iod->pid == -1)
		return GE_NOTREADY;
	    *((intptr_t *) val) = iod->pid;
	    return 0;
	}
	return GE_NOTSUP;
    }

    switch (op) {
    case GENSIO_IOD_CONTROL_ARGV:
	err = gensio_argv_copy(o, (const char **) val, NULL, &nargv);
	if (err)
	    return err;
	if (iod->argv)
	    gensio_argv_free(o, iod->argv);
	iod->argv = nargv;
	return 0;

    case GENSIO_IOD_CONTROL_ENV:
	err = gensio_argv_copy(o, (const char **) val, NULL, &nargv);
	if (err)
	    return err;
	if (iod->env)
	    gensio_argv_free(o, iod->env);
	iod->env = nargv;
	return 0;

    case GENSIO_IOD_CONTROL_START:
	return gensio_unix_pty_start(o, iod->fd, iod->argv,
				     iod->env, iod->start_dir, &iod->pid);

    case GENSIO_IOD_CONTROL_STOP:
	if (iod->fd != -1) {
	    close(iod->fd);
	    iod->fd = -1;
	}
	return 0;

    case GENSIO_IOD_CONTROL_WIN_SIZE: {
	struct winsize win;
	struct gensio_winsize *gwin = (struct gensio_winsize *) val;

	win.ws_row = gwin->ws_row;
	win.ws_col = gwin->ws_col;
	win.ws_xpixel = gwin->ws_xpixel;
	win.ws_ypixel = gwin->ws_ypixel;
	if (ioctl(iod->fd, TIOCSWINSZ, &win) == -1)
	    err = gensio_os_err_to_err(o, errno);
	return err;
    }

    case GENSIO_IOD_CONTROL_START_DIR: {
	char *dir = (char *) val;

	if (dir) {
	    dir = gensio_strdup(o, dir);
	    if (!dir)
		return GE_NOMEM;
	}

	if (iod->start_dir)
	    o->free(o, iod->start_dir);
	iod->start_dir = dir;
	return 0;
    }

    default:
	return GE_NOTSUP;
    }
}

static int
gensio_tcl_iod_control(struct gensio_iod *iiod, int op, bool get, intptr_t val)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);

    if (iod->type == GENSIO_IOD_SOCKET) {
	if (op != GENSIO_IOD_CONTROL_SOCKINFO)
	    return GE_NOTSUP;

	if (get)
	    *((void **) val) = iod->sockinfo;
	else
	    iod->sockinfo = (void *) val;

	return 0;
    }

    if (iod->type == GENSIO_IOD_PTY)
	return gensio_tcl_pty_control(iod, op, get, val);

    if (iod->type != GENSIO_IOD_DEV)
	return GE_NOTSUP;

    return gensio_unix_termios_control(iiod->f, op, get, val, &iod->termios,
				       iod->fd);
}

static int
gensio_tcl_set_non_blocking(struct gensio_iod *iiod)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);
    int rv = 0;

    if (iod->type == GENSIO_IOD_FILE)
	return 0;

    rv = gensio_unix_do_nonblock(iiod->f, iod->fd, &iod->mode);

    return rv;
}

static int
gensio_tcl_close(struct gensio_iod **iodp)
{
    struct gensio_iod *iiod = *iodp;
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);
    struct gensio_os_funcs *o = iiod->f;
    int err = 0;

    assert(iodp);
    assert(!iod->handlers_set);

    if (iod->type != GENSIO_IOD_FILE) {
	gensio_unix_cleanup_termios(o, &iod->termios, iod->fd);
	gensio_unix_do_cleanup_nonblock(o, iod->fd, &iod->mode);
    }

    if (iod->type == GENSIO_IOD_SOCKET) {
	if (iod->close_state == CL_DONE) {
	    err = 0;
	} else {
	    err = o->close_socket(iiod, iod->close_state == CL_CALLED, false);
	    if (err == GE_INPROGRESS)
		iod->close_state = CL_CALLED;
	    else
		iod->close_state = CL_DONE;
	}
    } else if (!iod->is_stdio) {
	if (iod->fd != -1) {
	    err = close(iod->fd);
	    if (err == -1)
		err = gensio_os_err_to_err(o, errno);
#ifdef ENABLE_INTERNAL_TRACE
	/* Close should never fail, but don't crash in production builds. */
	    assert(err == 0);
#endif
	}
    }
    o->release_iod(iiod);
    *iodp = NULL;

    return err;
}

#define ERRHANDLE()			\
do {								\
    int err = 0;						\
    if (rv < 0) {						\
	if (errno == EINTR)					\
	    goto retry;						\
	if (errno == EWOULDBLOCK || errno == EAGAIN)		\
	    rv = 0; /* Handle like a zero-byte write. */	\
	else {							\
	    err = errno;					\
	    assert(err);					\
	}							\
    } else if (rv == 0) {					\
	err = EPIPE;						\
    }								\
    if (!err && rcount)						\
	*rcount = rv;						\
    rv = gensio_os_err_to_err(o, err);				\
} while(0)

static int
gensio_tcl_write(struct gensio_iod *iiod, const struct gensio_sg *sg,
		  gensiods sglen, gensiods *rcount)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);
    struct gensio_os_funcs *o = iiod->f;
    ssize_t rv;

    if (sglen == 0) {
	if (rcount)
	    *rcount = 0;
	return 0;
    }
 retry:
    rv = writev(iod->fd, (struct iovec *) sg, sglen);
    ERRHANDLE();
    return rv;
}

static int
gensio_tcl_read(struct gensio_iod *iiod, void *buf, gensiods buflen,
		 gensiods *rcount)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);
    struct gensio_os_funcs *o = iiod->f;
    ssize_t rv;

    if (buflen == 0) {
	if (rcount)
	    *rcount = 0;
	return 0;
    }
 retry:
    rv = read(iod->fd, buf, buflen);
    ERRHANDLE();
    return rv;
}

static bool
gensio_tcl_is_regfile(struct gensio_os_funcs *o, intptr_t fd)
{
    int err;
    struct stat statb;

    err = fstat(fd, &statb);
    if (err == -1)
	return false;

    return (statb.st_mode & S_IFMT) == S_IFREG;
}

static int
gensio_tcl_bufcount(struct gensio_iod *iiod, int whichbuf, gensiods *count)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);

    return gensio_unix_get_bufcount(iiod->f, iod->fd, whichbuf, count);
}

static void
gensio_tcl_flush(struct gensio_iod *iiod, int whichbuf)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);

    gensio_unix_do_flush(iiod->f, iod->fd, whichbuf);
}

static int
gensio_tcl_makeraw(struct gensio_iod *iiod)
{
    struct gensio_iod_tcl *iod = i_to_tcl(iiod);

    if (iod->orig_fd == 1 || iod->orig_fd == 2 || iod->type == GENSIO_IOD_FILE)
	/* Only set this for stdin or other files. */
	return 0;

    return gensio_unix_setup_termios(iiod->f, iod->fd, &iod->termios);
}

static int
gensio_tcl_open_dev(struct gensio_os_funcs *o, const char *iname, int options,
		    struct gensio_iod **riod)
{
    int flags, fd, err;

    flags = O_NONBLOCK | O_NOCTTY;
    if (options & (GENSIO_OPEN_OPTION_READABLE | GENSIO_OPEN_OPTION_WRITEABLE))
	flags |= O_RDWR;
    else if (options & GENSIO_OPEN_OPTION_READABLE)
	flags |= O_RDONLY;
    else if (options & GENSIO_OPEN_OPTION_WRITEABLE)
	flags |= O_WRONLY;

    fd = open(iname, flags);
    if (fd == -1)
	return gensio_os_err_to_err(o, errno);
    err = o->add_iod(o, GENSIO_IOD_DEV, fd, riod);
    if (err)
	close(fd);
    return err;
}

static void
generic_close(intptr_t fd)
{
    close(fd);
}

static int
gensio_tcl_exec_subprog(struct gensio_os_funcs *o,
			const char *argv[], const char **env,
			const char *start_dir,
			unsigned int flags,
			intptr_t *rpid,
			struct gensio_iod **rstdin,
			struct gensio_iod **rstdout,
			struct gensio_iod **rstderr)
{
    int err;
    struct gensio_iod *stdiniod = NULL, *stdoutiod = NULL, *stderriod = NULL;
    intptr_t infd = -1, outfd = -1, errfd = -1;
    intptr_t pid = -1;

    int uinfd = -1, uoutfd = -1, uerrfd = -1;
    int upid = -1;

    err = gensio_unix_do_exec(o, argv, env, start_dir, flags, &upid, &uinfd,
			      &uoutfd, rstderr ? &uerrfd : NULL);
    if (err)
	return err;
    infd = uinfd;
    outfd = uoutfd;
    errfd = uerrfd;
    pid = upid;

    err = o->add_iod(o, GENSIO_IOD_PIPE, infd, &stdiniod);
    if (err)
	goto out_err;
    infd = -1;
    err = o->add_iod(o, GENSIO_IOD_PIPE, outfd, &stdoutiod);
    if (err)
	goto out_err;
    outfd = -1;
    err = o->set_non_blocking(stdiniod);
    if (err)
	goto out_err;
    err = o->set_non_blocking(stdoutiod);
    if (err)
	goto out_err;

    if (rstderr) {
	err = o->add_iod(o, GENSIO_IOD_PIPE, errfd, &stderriod);
	if (err)
	    goto out_err;
	errfd = -1;
	err = o->set_non_blocking(stderriod);
	if (err)
	    goto out_err;
    }

    *rpid = pid;
    *rstdin = stdiniod;
    *rstdout = stdoutiod;
    if (rstderr)
	*rstderr = stderriod;
    return 0;

 out_err:
    if (stderriod)
	o->close(&stderriod);
    else if (errfd != -1)
	generic_close(errfd);
    if (stdiniod)
	o->close(&stdiniod);
    else if (infd != -1)
	generic_close(infd);
    if (stdoutiod)
	o->close(&stdoutiod);
    else if (outfd != -1)
	generic_close(outfd);
    return err;
}

static int
gensio_tcl_kill_subprog(struct gensio_os_funcs *o, intptr_t pid, bool force)
{
    int rv;

    rv = kill(pid, force ? SIGKILL : SIGTERM);
    if (rv < 0)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

static int
gensio_tcl_wait_subprog(struct gensio_os_funcs *o, intptr_t pid, int *retcode)
{
    pid_t rv;

    rv = waitpid(pid, retcode, WNOHANG);
    if (rv < 0)
	return gensio_os_err_to_err(o, errno);

    if (rv == 0)
	return GE_INPROGRESS;

    return 0;
}

static int
gensio_tcl_service(struct gensio_os_funcs *o, gensio_time *timeout)
{
    struct timeout_info ti = { .timeout = timeout };
    int rv = GE_TIMEDOUT;

    setup_timeout(&ti);

    if (timeout_wait(&ti))
	rv = 0;
    ti.now = fetch_us_time();

    timeout_end(&ti);

    return rv;
}

static struct gensio_os_funcs *
gensio_tcl_get_funcs(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;

    d->refcount++;
    return f;
}

static void
gensio_tcl_free_funcs(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;

    assert(d->refcount > 0);
    if (d->refcount > 1) {
	d->refcount--;
	return;
    }
    gensio_memtrack_cleanup(d->mtrack);
    free(d);
    free(f);
}

static Tcl_Mutex once_lock;

static void
gensio_tcl_call_once(struct gensio_os_funcs *f, struct gensio_once *once,
		      void (*func)(void *cb_data), void *cb_data)
{
    if (once->called)
	return;
    Tcl_MutexLock(&once_lock);
    if (!once->called) {
	once->called = true;
	func(cb_data);
    }
    Tcl_MutexUnlock(&once_lock);
}

static void
gensio_tcl_get_monotonic_time(struct gensio_os_funcs *f, gensio_time *time)
{
    Tcl_Time ttime;

    Tcl_GetTime(&ttime);
    time->secs = ttime.sec;
    time->nsecs = ttime.usec * 1000;
}

static int
gensio_tcl_handle_fork(struct gensio_os_funcs *f)
{
    return 0;
}

static int
gensio_tcl_get_random(struct gensio_os_funcs *o, void *data, unsigned int len)
{
    int fd;
    int rv;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1)
	return gensio_os_err_to_err(o, errno);

    while (len > 0) {
	rv = read(fd, data, len);
	if (rv < 0) {
	    rv = errno;
	    goto out;
	}
	len -= rv;
	data += rv;
    }

    rv = 0;

 out:
    close(fd);
    return gensio_os_err_to_err(o, rv);
}

static int
gensio_tcl_control(struct gensio_os_funcs *o, int func, void *data,
		   gensiods *datalen)
{
    struct gensio_data *d = o->user_data;

    switch (func) {
    case GENSIO_CONTROL_SET_PROC_DATA:
	d->pdata = data;
	return 0;

    default:
	return GE_NOTSUP;
    }
}

int
gensio_tcl_funcs_alloc(struct gensio_os_funcs **ro)
{
    struct gensio_data *d;
    struct gensio_os_funcs *o;
    Tcl_Interp *interp;
    int err;

    /*
     * TCL won't work until after you create an intepreter.  So do
     * that here to avoid crashes in the TCL library.
     */
    interp = Tcl_CreateInterp();
    Tcl_DeleteInterp(interp);

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

    o->user_data = d;
    d->mtrack = gensio_memtrack_alloc();

    o->zalloc = gensio_tcl_zalloc;
    o->free = gensio_tcl_free;
    o->alloc_lock = gensio_tcl_alloc_lock;
    o->free_lock = gensio_tcl_free_lock;
    o->lock = gensio_tcl_lock;
    o->unlock = gensio_tcl_unlock;
    o->set_fd_handlers = gensio_tcl_set_fd_handlers;
    o->clear_fd_handlers = gensio_tcl_clear_fd_handlers;
    o->clear_fd_handlers_norpt = gensio_tcl_clear_fd_handlers_norpt;
    o->set_read_handler = gensio_tcl_set_read_handler;
    o->set_write_handler = gensio_tcl_set_write_handler;
    o->set_except_handler = gensio_tcl_set_except_handler;
    o->alloc_timer = gensio_tcl_alloc_timer;
    o->free_timer = gensio_tcl_free_timer;
    o->start_timer = gensio_tcl_start_timer;
    o->start_timer_abs = gensio_tcl_start_timer_abs;
    o->stop_timer = gensio_tcl_stop_timer;
    o->stop_timer_with_done = gensio_tcl_stop_timer_with_done;
    o->alloc_runner = gensio_tcl_alloc_runner;
    o->free_runner = gensio_tcl_free_runner;
    o->run = gensio_tcl_run;
    o->alloc_waiter = gensio_tcl_alloc_waiter;
    o->free_waiter = gensio_tcl_free_waiter;
    o->wait = gensio_tcl_wait;
    o->wait_intr = gensio_tcl_wait_intr;
    o->wait_intr_sigmask = gensio_tcl_wait_intr_sigmask;
    o->wake = gensio_tcl_wake;
    o->service = gensio_tcl_service;
    o->get_funcs = gensio_tcl_get_funcs;
    o->free_funcs = gensio_tcl_free_funcs;
    o->call_once = gensio_tcl_call_once;
    o->get_monotonic_time = gensio_tcl_get_monotonic_time;
    o->handle_fork = gensio_tcl_handle_fork;
    o->add_iod = gensio_tcl_add_iod;
    o->release_iod = gensio_tcl_release_iod;
    o->iod_get_type = gensio_tcl_iod_get_type;
    o->iod_get_fd = gensio_tcl_iod_get_fd;

    o->set_non_blocking = gensio_tcl_set_non_blocking;
    o->close = gensio_tcl_close;
    o->graceful_close = gensio_tcl_close;
    o->write = gensio_tcl_write;
    o->read = gensio_tcl_read;
    o->is_regfile = gensio_tcl_is_regfile;
    o->bufcount = gensio_tcl_bufcount;
    o->flush = gensio_tcl_flush;
    o->makeraw = gensio_tcl_makeraw;
    o->open_dev = gensio_tcl_open_dev;
    o->exec_subprog = gensio_tcl_exec_subprog;
    o->kill_subprog = gensio_tcl_kill_subprog;
    o->wait_subprog = gensio_tcl_wait_subprog;
    o->get_random = gensio_tcl_get_random;
    o->iod_control = gensio_tcl_iod_control;
    o->control = gensio_tcl_control;

    gensio_addr_addrinfo_set_os_funcs(o);
    err = gensio_stdsock_set_os_funcs(o);
    if (err) {
	free(o);
	free(d);
	return err;
    }

    *ro = o;
    return 0;
}
