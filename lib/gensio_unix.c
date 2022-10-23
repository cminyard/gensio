/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <errno.h>

#include "pthread_handler.h"

#include <gensio/gensio_unix.h>
#include <gensio/selector.h>
#include <gensio/gensio_selector.h>
#include <gensio/gensio.h>
#include <gensio/gensio_osops_addrinfo.h>
#include <gensio/gensio_osops_stdsock.h>
#include <gensio/gensio_osops.h>
#include <gensio/sergensio.h>

#include "utils.h"
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "errtrig.h"

struct gensio_data {
    struct selector_s *sel;
    lock_type reflock;
    unsigned int refcount;
    bool freesel;
    int wake_sig;
    struct gensio_os_proc_data *pdata;
    struct gensio_memtrack *mtrack;
};

static void *
gensio_unix_zalloc(struct gensio_os_funcs *o, gensiods size)
{
    struct gensio_data *d = o->user_data;

    return gensio_i_zalloc(d->mtrack, size);
}

static void
gensio_unix_free(struct gensio_os_funcs *o, void *v)
{
    struct gensio_data *d = o->user_data;

    gensio_i_free(d->mtrack, v);
}

static void
add_to_timeval(struct timeval *tv1, gensio_time *t2)
{
    tv1->tv_sec += t2->secs;
    tv1->tv_usec += (t2->nsecs + 500) / 1000;
    while (tv1->tv_usec > 1000000) {
	tv1->tv_usec -= 1000000;
	tv1->tv_sec += 1;
    }
    while (tv1->tv_usec < 0) {
	tv1->tv_usec += 1000000;
	tv1->tv_sec -= 1;
    }
}

static struct timeval *
gensio_time_to_timeval(struct timeval *tv, gensio_time *t)
{
    if (!t)
	return NULL;
    tv->tv_sec = t->secs;
    tv->tv_usec = (t->nsecs + 500) / 1000;
    return tv;
}

static void
timeval_to_gensio_time(gensio_time *t, struct timeval *tv)
{
    if (tv) {
	t->secs = tv->tv_sec;
	t->nsecs = tv->tv_usec * 1000;
    }
}

#ifdef USE_PTHREADS

#include <pthread.h>

struct waiter_data {
    pthread_t tid;
    int wake_sig;
    unsigned int count;
    struct waiter_data *prev;
    struct waiter_data *next;
};

typedef struct waiter_s {
    struct gensio_os_funcs *o;
    struct selector_s *sel;
    int wake_sig;
    unsigned int count;
    pthread_mutex_t lock;
    struct waiter_data wts;
} waiter_t;

static waiter_t *
alloc_waiter(struct gensio_os_funcs *o, struct selector_s *sel, int wake_sig)
{
    waiter_t *waiter;

    waiter = o->zalloc(o, sizeof(waiter_t));
    if (waiter) {
	waiter->o = o;
	waiter->wake_sig = wake_sig;
	waiter->sel = sel;
	pthread_mutex_init(&waiter->lock, NULL);
	waiter->wts.next = &waiter->wts;
	waiter->wts.prev = &waiter->wts;
    }
    return waiter;
}

static void
free_waiter(waiter_t *waiter)
{
    assert(waiter);
    assert(waiter->wts.next == waiter->wts.prev);
    pthread_mutex_destroy(&waiter->lock);
    waiter->o->free(waiter->o, waiter);
}

static void
wake_thread_send_sig_waiter(long thread_id, void *cb_data)
{
    struct waiter_data *w = cb_data;

    pthread_kill(w->tid, w->wake_sig);
}

static void
i_wake_waiter(waiter_t *waiter, unsigned int count)
{
    struct waiter_data *w;

    w = waiter->wts.next;
    while (w != &waiter->wts && count > 0) {
	if (w->count > 0) {
	    if (w->count >= count) {
		w->count -= count;
		count = 0;
	    } else {
		count -= w->count;
		w->count = 0;
	    }
	    if (w->count == 0) {
#ifdef BROKEN_PSELECT
		sel_wake_one(waiter->sel, (long) w->tid,
			     wake_thread_send_sig_waiter, w);
#else
		pthread_kill(w->tid, w->wake_sig);
#endif
	    }
	}
	w = w->next;
    }
    waiter->count += count;
}

static int
i_wait_for_waiter_timeout(waiter_t *waiter, unsigned int count,
			  gensio_time *timeout, bool intr,
			  sigset_t *sigmask)
{
    struct waiter_data w;
    struct timeval tv, *rtv;
    int err = 0;

    w.tid = pthread_self();
    w.wake_sig = waiter->wake_sig;
    w.next = NULL;
    w.prev = NULL;
    w.count = count;

    pthread_mutex_lock(&waiter->lock);
    waiter->wts.next->prev = &w;
    w.next = waiter->wts.next;
    waiter->wts.next = &w;
    w.prev = &waiter->wts;

    rtv = gensio_time_to_timeval(&tv, timeout);

    if (waiter->count > 0) {
	if (waiter->count >= w.count) {
	    waiter->count -= w.count;
	    w.count = 0;
	} else {
	    w.count -= waiter->count;
	    waiter->count = 0;
	}
    }
    while (w.count > 0) {
	pthread_mutex_unlock(&waiter->lock);
	if (intr)
	    err = sel_select_intr_sigmask(waiter->sel,
					  wake_thread_send_sig_waiter,
					  (long) w.tid, &w, rtv, sigmask);
	else
	    err = sel_select(waiter->sel, wake_thread_send_sig_waiter,
			     (long) w.tid, &w, rtv);
	if (err < 0)
	    err = errno;
	else if (err == 0)
	    err = ETIMEDOUT;
	else
	    err = 0;
	/* lock may affect errno, delay it until here. */
	pthread_mutex_lock(&waiter->lock);
	if (err)
	    break;
    }
    timeval_to_gensio_time(timeout, rtv);
    w.next->prev = w.prev;
    w.prev->next = w.next;
    if (w.count == 0) {
	err = 0; /* If our count was decremented to zero, ignore errors. */
    } else if (err) {
	/*
	 * If there was an error, re-add whatever was decremented to the
	 * waiter.
	 */
	i_wake_waiter(waiter, count - w.count);
    }
    pthread_mutex_unlock(&waiter->lock);

    return err;
}

static void
wake_waiter(waiter_t *waiter)
{
    pthread_mutex_lock(&waiter->lock);
    i_wake_waiter(waiter, 1);
    pthread_mutex_unlock(&waiter->lock);
}

#else /* USE_PTHREADS */

typedef struct waiter_s {
    struct gensio_os_funcs *o;
    unsigned int count;
    struct selector_s *sel;
} waiter_t;

static waiter_t *
alloc_waiter(struct gensio_os_funcs *o, struct selector_s *sel, int wake_sig)
{
    waiter_t *waiter;

    waiter = o->zalloc(o, sizeof(waiter_t));
    if (waiter) {
	waiter->o = o;
	waiter->sel = sel;
    }
    return waiter;
}

static void
free_waiter(waiter_t *waiter)
{
    assert(waiter);
    waiter->o->free(waiter->o, waiter);
}

static int
i_wait_for_waiter_timeout(waiter_t *waiter, unsigned int count,
			  gensio_time *timeout, bool intr, sigset_t *sigmask)
{
    struct timeval tv, *rtv;
    int err = 0;

    rtv = gensio_time_to_timeval(&tv, timeout);
    while (waiter->count < count) {
	if (intr)
	    err = sel_select_intr_sigmask(waiter->sel, 0, 0, NULL, rtv,
					  sigmask);
	else
	    err = sel_select(waiter->sel, 0, 0, NULL, rtv);
	if (err < 0) {
	    err = errno;
	    break;
	} else if (err == 0) {
	    err = ETIMEDOUT;
	    break;
	}
	err = 0;
    }
    timeval_to_gensio_time(timeout, rtv);
    if (!err)
	waiter->count -= count;
    return err;
}

static void
wake_waiter(waiter_t *waiter)
{
    waiter->count++;
}

#endif /* USE_PTHREADS */

static int
wait_for_waiter_timeout_intr_sigmask(waiter_t *waiter, unsigned int count,
				     gensio_time *timeout, sigset_t *sigmask)
{
    return i_wait_for_waiter_timeout(waiter, count, timeout, true, sigmask);
}

struct gensio_lock {
    struct gensio_os_funcs *f;
    lock_type lock;
};

static struct gensio_lock *
gensio_unix_alloc_lock(struct gensio_os_funcs *f)
{
    struct gensio_lock *lock = f->zalloc(f, sizeof(*lock));

    if (lock) {
	lock->f = f;
	LOCK_INIT(&lock->lock);
    }

    return lock;
}

static void
gensio_unix_free_lock(struct gensio_lock *lock)
{
    LOCK_DESTROY(&lock->lock);
    lock->f->free(lock->f, lock);
}

static void
gensio_unix_lock(struct gensio_lock *lock)
{
    LOCK(&lock->lock);
}

static void
gensio_unix_unlock(struct gensio_lock *lock)
{
    UNLOCK(&lock->lock);
}

struct gensio_iod_file {
    struct gensio_lock *lock;
    struct gensio_runner *runner;
    bool read_enabled;
    bool write_enabled;
    bool do_clear;
    bool in_handler;
};

struct gensio_iod_socket {
    void *sockinfo;
};

struct gensio_iod_pty {
    const char **argv;
    const char **env;
    pid_t pid;
    char *start_dir;
};

struct gensio_iod_unix {
    struct gensio_iod r;
    int orig_fd;
    int fd;
    enum gensio_iod_type type;
    bool handlers_set;
    bool is_stdio;
    void *cb_data;
    void (*read_handler)(struct gensio_iod *iod, void *cb_data);
    void (*write_handler)(struct gensio_iod *iod, void *cb_data);
    void (*except_handler)(struct gensio_iod *iod, void *cb_data);
    void (*cleared_handler)(struct gensio_iod *iod, void *cb_data);

    struct stdio_mode *mode;

    /* Used by dev and pty. */
    struct gensio_unix_termios *termios;

    union {
	struct gensio_iod_file file;
	struct gensio_iod_socket socket;
	struct gensio_iod_pty pty;
    } u;
};

#define i_to_sel(i) gensio_container_of(i, struct gensio_iod_unix, r);

static void iod_read_handler(int fd, void *cb_data)
{
    struct gensio_iod_unix *iod = cb_data;

    iod->read_handler(&iod->r, iod->cb_data);
}

static void iod_write_handler(int fd, void *cb_data)
{
    struct gensio_iod_unix *iod = cb_data;

    iod->write_handler(&iod->r, iod->cb_data);
}

static void iod_except_handler(int fd, void *cb_data)
{
    struct gensio_iod_unix *iod = cb_data;

    iod->except_handler(&iod->r, iod->cb_data);
}

static void iod_cleared_handler(int fd, void *cb_data)
{
    struct gensio_iod_unix *iod = cb_data;

    iod->handlers_set = false;
    iod->cleared_handler(&iod->r, iod->cb_data);
}

static int
gensio_unix_set_fd_handlers(struct gensio_iod *iiod,
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
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *f = iiod->f;
    struct gensio_data *d = f->user_data;
    int rv = 0;

    if (iod->handlers_set)
	return GE_INUSE;

    iod->cb_data = cb_data;
    iod->read_handler = read_handler;
    iod->write_handler = write_handler;
    iod->except_handler = except_handler;
    iod->cleared_handler = cleared_handler;
    if (iod->type != GENSIO_IOD_FILE)
	rv = sel_set_fd_handlers(d->sel, iod->fd, iod,
				 read_handler ? iod_read_handler : NULL,
				 write_handler ? iod_write_handler : NULL,
				 except_handler ? iod_except_handler : NULL,
				 cleared_handler ? iod_cleared_handler : NULL);
    if (!rv)
	iod->handlers_set = true;
    return gensio_os_err_to_err(f, rv);
}


static void
gensio_unix_clear_fd_handlers(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *f = iiod->f;
    struct gensio_data *d = f->user_data;

    if (!iod->handlers_set)
	return;
    if (iod->type == GENSIO_IOD_FILE) {
	f->lock(iod->u.file.lock);
	if (!iod->u.file.do_clear) {
	    iod->u.file.do_clear = true;
	    f->run(iod->u.file.runner);
	}
	f->unlock(iod->u.file.lock);
    } else {
	sel_clear_fd_handlers(d->sel, iod->fd);
    }
}

static void
gensio_unix_clear_fd_handlers_norpt(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *f = iiod->f;
    struct gensio_data *d = f->user_data;

    if (iod->handlers_set) {
	iod->handlers_set = false;
	if (iod->type != GENSIO_IOD_FILE)
	    sel_clear_fd_handlers_norpt(d->sel, iod->fd);
    }
}

static void
file_runner(struct gensio_runner *r, void *cb_data)
{
    struct gensio_iod_unix *iod = cb_data;
    struct gensio_os_funcs *f = iod->r.f;

    f->lock(iod->u.file.lock);
    while (iod->u.file.read_enabled || iod->u.file.write_enabled) {
	if (iod->u.file.read_enabled) {
	    f->unlock(iod->u.file.lock);
	    iod->read_handler(&iod->r, iod->cb_data);
	    f->lock(iod->u.file.lock);
	}
	if (iod->u.file.write_enabled) {
	    f->unlock(iod->u.file.lock);
	    iod->write_handler(&iod->r, iod->cb_data);
	    f->lock(iod->u.file.lock);
	}
    }
    iod->u.file.in_handler = false;
    if (iod->u.file.do_clear) {
	iod->u.file.do_clear = false;
	iod->handlers_set = false;
	f->unlock(iod->u.file.lock);
	iod->cleared_handler(&iod->r, iod->cb_data);
	f->lock(iod->u.file.lock);
    }
    f->unlock(iod->u.file.lock);
}

static void
gensio_unix_set_read_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *f = iiod->f;
    struct gensio_data *d = f->user_data;
    int op;

    if (iod->type == GENSIO_IOD_FILE) {
	if (iod->u.file.read_enabled == enable || iod->u.file.do_clear)
	    return;
	f->lock(iod->u.file.lock);
	iod->u.file.read_enabled = enable;
	if (enable && !iod->u.file.in_handler) {
	    f->run(iod->u.file.runner);
	    iod->u.file.in_handler = true;
	}
	f->unlock(iod->u.file.lock);
	return;
    }

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_read_handler(d->sel, iod->fd, op);
}

static void
gensio_unix_set_write_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *f = iiod->f;
    struct gensio_data *d = f->user_data;
    int op;

    if (iod->type == GENSIO_IOD_FILE) {
	if (iod->u.file.write_enabled == enable || iod->u.file.do_clear)
	    return;
	f->lock(iod->u.file.lock);
	iod->u.file.write_enabled = enable;
	if (enable && !iod->u.file.in_handler) {
	    f->run(iod->u.file.runner);
	    iod->u.file.in_handler = true;
	}
	f->unlock(iod->u.file.lock);
	return;
    }

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_write_handler(d->sel, iod->fd, op);
}

static void
gensio_unix_set_except_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *f = iiod->f;
    struct gensio_data *d = f->user_data;
    int op;

    if (iod->type == GENSIO_IOD_FILE)
	return;

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_except_handler(d->sel, iod->fd, op);
}

struct gensio_timer {
    struct gensio_os_funcs *f;
    void (*handler)(struct gensio_timer *t, void *cb_data);
    void *cb_data;
    sel_timer_t *sel_timer;
    lock_type lock;

    void (*done_handler)(struct gensio_timer *t, void *cb_data);
    void *done_cb_data;
};

static void
gensio_timeout_handler(struct selector_s *sel,
		       struct sel_timer_s *sel_timer, void *cb_data)
{
    struct gensio_timer *timer = cb_data;

    timer->handler(timer, timer->cb_data);
}

static struct gensio_timer *
gensio_unix_alloc_timer(struct gensio_os_funcs *f,
			void (*handler)(struct gensio_timer *t, void *cb_data),
			void *cb_data)
{
    struct gensio_data *d = f->user_data;
    struct gensio_timer *timer;
    int rv;

    timer = f->zalloc(f, sizeof(*timer));
    if (!timer)
	return NULL;

    timer->f = f;
    timer->handler = handler;
    timer->cb_data = cb_data;
    LOCK_INIT(&timer->lock);

    rv = sel_alloc_timer(d->sel, gensio_timeout_handler, timer,
			 &timer->sel_timer);
    if (rv) {
	f->free(f, timer);
	return NULL;
    }

    return timer;
}

static void
gensio_unix_free_timer(struct gensio_timer *timer)
{
    sel_free_timer(timer->sel_timer);
    timer->f->free(timer->f, timer);
}

static int
gensio_unix_start_timer(struct gensio_timer *timer, gensio_time *timeout)
{
    struct timeval tv;
    int rv;

    sel_get_monotonic_time(&tv);
    add_to_timeval(&tv, timeout);
    rv = sel_start_timer(timer->sel_timer, &tv);
    return gensio_os_err_to_err(timer->f, rv);
}

static int
gensio_unix_start_timer_abs(struct gensio_timer *timer, gensio_time *timeout)
{
    int rv;
    struct timeval tv, *rtv;

    rtv = gensio_time_to_timeval(&tv, timeout);
    rv = sel_start_timer(timer->sel_timer, rtv);
    return gensio_os_err_to_err(timer->f, rv);
}

static int
gensio_unix_stop_timer(struct gensio_timer *timer)
{
    int rv;

    rv = sel_stop_timer(timer->sel_timer);
    return gensio_os_err_to_err(timer->f, rv);
}

static void
gensio_stop_timer_done(struct selector_s *sel,
		       struct sel_timer_s *sel_timer, void *cb_data)
{
    struct gensio_timer *timer = cb_data;
    void (*done_handler)(struct gensio_timer *t, void *cb_data);
    void *done_cb_data;

    LOCK(&timer->lock);
    done_handler = timer->done_handler;
    done_cb_data = timer->done_cb_data;
    timer->done_handler = NULL;
    UNLOCK(&timer->lock);
    done_handler(timer, done_cb_data);
}

static int
gensio_unix_stop_timer_with_done(struct gensio_timer *timer,
				 void (*done_handler)(struct gensio_timer *t,
						      void *cb_data),
				 void *cb_data)
{
    int rv;

    LOCK(&timer->lock);
    if (timer->done_handler) {
	UNLOCK(&timer->lock);
	return GE_INUSE;
    }
    rv = sel_stop_timer_with_done(timer->sel_timer, gensio_stop_timer_done,
				  timer);
    if (!rv) {
	timer->done_handler = done_handler;
	timer->done_cb_data = cb_data;
    }
    UNLOCK(&timer->lock);
    return gensio_os_err_to_err(timer->f, rv);
}

struct gensio_runner {
    struct gensio_os_funcs *f;
    struct sel_runner_s *sel_runner;
    void (*handler)(struct gensio_runner *r, void *cb_data);
    void *cb_data;
};

static struct gensio_runner *
gensio_unix_alloc_runner(struct gensio_os_funcs *f,
			 void (*handler)(struct gensio_runner *r,
					 void *cb_data),
			 void *cb_data)
{
    struct gensio_data *d = f->user_data;
    struct gensio_runner *runner;
    int rv;

    runner = f->zalloc(f, sizeof(*runner));
    if (!runner)
	return NULL;

    runner->f = f;
    runner->handler = handler;
    runner->cb_data = cb_data;

    rv = sel_alloc_runner(d->sel, &runner->sel_runner);
    if (rv) {
	f->free(f, runner);
	return NULL;
    }

    return runner;
}

static void
gensio_unix_free_runner(struct gensio_runner *runner)
{
    sel_free_runner(runner->sel_runner);
    runner->f->free(runner->f, runner);
}

static void
gensio_runner_handler(sel_runner_t *sel_runner, void *cb_data)
{
    struct gensio_runner *runner = cb_data;

    runner->handler(runner, runner->cb_data);
}

static int
gensio_unix_run(struct gensio_runner *runner)
{
    return sel_run(runner->sel_runner, gensio_runner_handler, runner);
}

struct gensio_waiter {
    struct gensio_os_funcs *f;
    struct waiter_s *sel_waiter;
};

static struct gensio_waiter *
gensio_unix_alloc_waiter(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;
    struct gensio_waiter *waiter = f->zalloc(f, sizeof(*waiter));

    if (!waiter)
	return NULL;

    waiter->f = f;

    waiter->sel_waiter = alloc_waiter(f, d->sel, d->wake_sig);
    if (!waiter->sel_waiter) {
	f->free(f, waiter);
	return NULL;
    }

    return waiter;
}

static void
gensio_unix_free_waiter(struct gensio_waiter *waiter)
{
    free_waiter(waiter->sel_waiter);
    waiter->f->free(waiter->f, waiter);
}

static int
gensio_unix_wait_intr_sigmask(struct gensio_waiter *waiter, unsigned int count,
			      gensio_time *timeout,
			      struct gensio_os_proc_data *proc_data)
{
    int err;
    sigset_t *wait_sigs = NULL;

    if (proc_data)
	wait_sigs = gensio_os_proc_unix_get_wait_sigset(proc_data);
    err = wait_for_waiter_timeout_intr_sigmask(waiter->sel_waiter, count,
					       timeout, wait_sigs);
    if (proc_data)
	gensio_os_proc_check_handlers(proc_data);
    return gensio_os_err_to_err(waiter->f, err);
}

static int
gensio_unix_wait(struct gensio_waiter *waiter, unsigned int count,
		 gensio_time *timeout)
{
    struct gensio_data *d = waiter->f->user_data;
    int err = GE_INTERRUPTED;

    while (err == GE_INTERRUPTED)
	err = gensio_unix_wait_intr_sigmask(waiter, count, timeout, d->pdata);
    return err;
}

static int
gensio_unix_wait_intr(struct gensio_waiter *waiter, unsigned int count,
		      gensio_time *timeout)
{
    struct gensio_data *d = waiter->f->user_data;

    return gensio_unix_wait_intr_sigmask(waiter, count, timeout, d->pdata);
}

static void
gensio_unix_wake(struct gensio_waiter *waiter)
{
    wake_waiter(waiter->sel_waiter);
}

#ifdef USE_PTHREADS
#include <pthread.h>
#include <signal.h>

struct wait_data {
    pthread_t id;
    int wake_sig;
};

static void
wake_thread_send_sig(long thread_id, void *cb_data)
{
    struct wait_data *w = cb_data;

    pthread_kill(w->id, w->wake_sig);
}

static int
gensio_unix_service(struct gensio_os_funcs *f, gensio_time *timeout)
{
    struct gensio_data *d = f->user_data;
    struct wait_data w;
    struct timeval tv, *rtv;
    int err;

    w.id = pthread_self();
    w.wake_sig = d->wake_sig;
    rtv = gensio_time_to_timeval(&tv, timeout);
    err = sel_select_intr(d->sel, wake_thread_send_sig, (long) w.id, &w, rtv);
    if (err < 0)
	err = gensio_os_err_to_err(f, errno);
    else if (err == 0)
	err = GE_TIMEDOUT;
    else
	err = 0;
    timeval_to_gensio_time(timeout, rtv);

    return err;
}
#else
static int
gensio_unix_service(struct gensio_os_funcs *f, gensio_time *timeout)
{
    struct gensio_data *d = f->user_data;
    struct timeval tv, *rtv;
    int err;

    rtv = gensio_time_to_timeval(&tv, timeout);
    err = sel_select_intr(d->sel, NULL, 0, NULL, rtv);
    if (err < 0)
	err = gensio_os_err_to_err(f, errno);
    else if (err == 0)
	err = GE_TIMEDOUT;
    else
	err = 0;
    timeval_to_gensio_time(timeout, rtv);

    return err;
}
#endif

static int
gensio_unix_get_wake_sig(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;

    return d->wake_sig;
}

static lock_type defos_lock = LOCK_INITIALIZER;
static struct gensio_os_funcs *defoshnd;
static int defoshnd_wake_sig = -1;

static struct gensio_os_funcs *
gensio_unix_get_funcs(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;

    LOCK(&d->reflock);
    assert(d->refcount > 0);
    d->refcount++;
    UNLOCK(&d->reflock);
    return f;
}

static void
gensio_unix_free_funcs(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;

    LOCK(&defos_lock);
    LOCK(&d->reflock);
    assert(d->refcount > 0);
    if (d->refcount > 1) {
	d->refcount--;
	UNLOCK(&d->reflock);
	UNLOCK(&defos_lock);
	return;
    }
    UNLOCK(&d->reflock);

    if (f == defoshnd)
	defoshnd = NULL;
    UNLOCK(&defos_lock);

    gensio_stdsock_cleanup(f);
    gensio_memtrack_cleanup(d->mtrack);
    if (d->freesel)
	sel_free_selector(d->sel);
    free(f->user_data);
    free(f);
}

static lock_type once_lock = LOCK_INITIALIZER;

static void
gensio_unix_call_once(struct gensio_os_funcs *f, struct gensio_once *once,
		      void (*func)(void *cb_data), void *cb_data)
{
    if (once->called)
	return;
    LOCK(&once_lock);
    if (!once->called) {
	once->called = true;
	func(cb_data);
    }
    UNLOCK(&once_lock);
}

static void
gensio_unix_get_monotonic_time(struct gensio_os_funcs *f, gensio_time *time)
{
    struct timeval tv;

    sel_get_monotonic_time(&tv);
    timeval_to_gensio_time(time, &tv);
}

static int
gensio_handle_fork(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;

    return sel_setup_forked_process(d->sel);
}

static int
gensio_unix_add_iod(struct gensio_os_funcs *o, enum gensio_iod_type type,
		    intptr_t ofd, struct gensio_iod **riod)
{
    struct gensio_iod_unix *iod = NULL;
    bool closefd = false;
    int err = GE_NOMEM, fd = ofd;

    if (type >= NR_GENSIO_IOD_TYPES)
	return GE_INVAL;

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
	iod->u.pty.pid = -1;
    }
    iod->type = type;

    if (type == GENSIO_IOD_FILE) {
	iod->u.file.lock = o->alloc_lock(o);
	if (!iod->u.file.lock)
	    goto out_err;
	iod->u.file.runner = o->alloc_runner(o, file_runner, iod);
	if (!iod->u.file.runner) {
	    o->free_lock(iod->u.file.lock);
	    goto out_err;
	}
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
gensio_unix_release_iod(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *o = iod->r.f;

    assert(!iod->handlers_set);
    if (iod->type == GENSIO_IOD_FILE) {
	o->free_runner(iod->u.file.runner);
	o->free_lock(iod->u.file.lock);
    }
    if (iod->type == GENSIO_IOD_PTY) {
	if (iod->u.pty.argv)
	    gensio_argv_free(o, iod->u.pty.argv);
	if (iod->u.pty.env)
	    gensio_argv_free(o, iod->u.pty.env);
	if (iod->u.pty.start_dir)
	    o->free(o, iod->u.pty.start_dir);
    }
    o->free(o, iod);
}

static int
gensio_unix_iod_get_type(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    return iod->type;
}

static int
gensio_unix_iod_get_fd(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    return iod->fd;
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
gensio_unix_write(struct gensio_iod *iiod,
		  const struct gensio_sg *sg, gensiods sglen,
		  gensiods *rcount)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *o = iiod->f;
    ssize_t rv;

    if (do_errtrig())
	return GE_NOMEM;

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
gensio_unix_read(struct gensio_iod *iiod,
		 void *buf, gensiods buflen, gensiods *rcount)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *o = iiod->f;
    ssize_t rv;

    if (do_errtrig())
	return GE_NOMEM;

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

static int
gensio_unix_close(struct gensio_iod **iodp)
{
    struct gensio_iod *iiod = *iodp;
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *o = iiod->f;
    int err = 0;

    /* Don't do errtrig on close, it can fail and not cause any issues. */

    assert(iodp);
    assert(!iod->handlers_set);
    if (iod->type != GENSIO_IOD_FILE)
	gensio_unix_do_cleanup_nonblock(o, iod->fd, &iod->mode);

    if (iod->termios)
	gensio_unix_cleanup_termios(o, &iod->termios, iod->fd);

    if (iod->type == GENSIO_IOD_SOCKET) {
	err = o->close_socket(iiod, false, true);
    } else if (!iod->is_stdio && iod->fd != -1) {
	err = close(iod->fd);
	iod->fd = -1;
#ifdef ENABLE_INTERNAL_TRACE
	/* Close should never fail, but don't crash in production builds. */
	assert(err == 0);
#endif
    }
    o->release_iod(iiod);
    *iodp = NULL;

    if (err == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

static int
gensio_unix_set_non_blocking(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    if (do_errtrig())
	return GE_NOMEM;

    if (iod->type == GENSIO_IOD_FILE)
	return 0;

    return gensio_unix_do_nonblock(iiod->f, iod->fd, &iod->mode);
}

int
gensio_unix_bufcount(struct gensio_iod *iiod, int whichbuf, gensiods *rcount)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    return gensio_unix_get_bufcount(iiod->f, iod->fd, whichbuf, rcount);
}

static bool
gensio_unix_is_regfile(struct gensio_os_funcs *o, intptr_t fd)
{
    int err;
    struct stat statb;

    err = fstat(fd, &statb);
    if (err == -1)
	return false;

    return (statb.st_mode & S_IFMT) == S_IFREG;
}

static void
gensio_unix_flush(struct gensio_iod *iiod, int whichbuf)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    gensio_unix_do_flush(iiod->f, iod->fd, whichbuf);
}

static int
gensio_unix_makeraw(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    if (iod->type == GENSIO_IOD_DEV || iod->type == GENSIO_IOD_PTY ||
		(iod->type == GENSIO_IOD_CONSOLE && iod->orig_fd == 0))
	/* Only set this for stdin or other files. */
	return gensio_unix_setup_termios(iiod->f, iod->fd, &iod->termios);

    return 0;
}

static int
gensio_unix_open_dev(struct gensio_os_funcs *o, const char *name,
		     int options, struct gensio_iod **riod)
{
    int flags, fd, err;

    flags = O_NONBLOCK | O_NOCTTY;
    if (options & (GENSIO_OPEN_OPTION_READABLE | GENSIO_OPEN_OPTION_WRITEABLE))
	flags |= O_RDWR;
    else if (options & GENSIO_OPEN_OPTION_READABLE)
	flags |= O_RDONLY;
    else if (options & GENSIO_OPEN_OPTION_WRITEABLE)
	flags |= O_WRONLY;

    fd = open(name, flags);
    if (fd == -1)
	return gensio_os_err_to_err(o, errno);
    err = o->add_iod(o, GENSIO_IOD_DEV, fd, riod);
    if (err)
	close(fd);
    return err;
}

static int
gensio_unix_exec_subprog(struct gensio_os_funcs *o,
			 const char *argv[], const char **env,
			 const char *start_dir,
			 unsigned int flags,
			 intptr_t *rpid,
			 struct gensio_iod **rstdin,
			 struct gensio_iod **rstdout,
			 struct gensio_iod **rstderr)
{
    int err;
    int infd = -1, outfd = -1, errfd = -1;
    struct gensio_iod *stdiniod = NULL, *stdoutiod = NULL, *stderriod = NULL;
    int pid = -1;

    err = gensio_unix_do_exec(o, argv, env, start_dir, flags, &pid, &infd,
			      &outfd, rstderr ? &errfd : NULL);
    if (err)
	return err;

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
	close(errfd);
    if (stdiniod)
	o->close(&stdiniod);
    else if (infd != -1)
	close(infd);
    if (stdoutiod)
	o->close(&stdoutiod);
    else if (outfd != -1)
	close(outfd);
    return err;
}

static int
gensio_unix_pty_control(struct gensio_iod_unix *iod, int op, bool get,
			intptr_t val)
{
    struct gensio_os_funcs *o = iod->r.f;
    int err = 0;
    const char **nargv;

    if (get) {
	if (op == GENSIO_IOD_CONTROL_PID) {
	    if (iod->u.pty.pid == -1)
		return GE_NOTREADY;
	    *((intptr_t *) val) = iod->u.pty.pid;
	    return 0;
	}
	return GE_NOTSUP;
    }

    switch (op) {
    case GENSIO_IOD_CONTROL_ARGV:
	err = gensio_argv_copy(o, (const char **) val, NULL, &nargv);
	if (err)
	    return err;
	if (iod->u.pty.argv)
	    gensio_argv_free(o, iod->u.pty.argv);
	iod->u.pty.argv = nargv;
	return 0;

    case GENSIO_IOD_CONTROL_ENV:
	err = gensio_argv_copy(o, (const char **) val, NULL, &nargv);
	if (err)
	    return err;
	if (iod->u.pty.env)
	    gensio_argv_free(o, iod->u.pty.env);
	iod->u.pty.env = nargv;
	return 0;

    case GENSIO_IOD_CONTROL_START:
	return gensio_unix_pty_start(o, iod->fd, iod->u.pty.argv,
				     iod->u.pty.env, iod->u.pty.start_dir,
				     &iod->u.pty.pid);

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

	if (iod->u.pty.start_dir)
	    o->free(o, iod->u.pty.start_dir);
	iod->u.pty.start_dir = dir;
	return 0;
    }

    default:
	return GE_NOTSUP;
    }
}

static int
gensio_unix_iod_control(struct gensio_iod *iiod, int op, bool get, intptr_t val)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    if (iod->type == GENSIO_IOD_SOCKET) {
	if (op != GENSIO_IOD_CONTROL_SOCKINFO)
	    return GE_NOTSUP;

	if (get)
	    *((void **) val) = iod->u.socket.sockinfo;
	else
	    iod->u.socket.sockinfo = (void *) val;

	return 0;
    }

    if (iod->type == GENSIO_IOD_PTY)
	return gensio_unix_pty_control(iod, op, get, val);

    if (iod->type != GENSIO_IOD_DEV)
	return GE_NOTSUP;

    return gensio_unix_termios_control(iiod->f, op, get, val,
				       &iod->termios, iod->fd);
}

static int
gensio_unix_kill_subprog(struct gensio_os_funcs *o, intptr_t pid,
			 bool force)
{
    int rv;

    rv = kill(pid, force ? SIGKILL : SIGTERM);
    if (rv < 0)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

static int
gensio_unix_wait_subprog(struct gensio_os_funcs *o, intptr_t pid,
			 int *retcode)
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
gensio_unix_get_random(struct gensio_os_funcs *o,
		       void *data, unsigned int len)
{
    int fd;
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

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
gensio_unix_control(struct gensio_os_funcs *o, int func, void *data,
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

static struct gensio_os_funcs *
gensio_unix_alloc_sel(struct selector_s *sel, int wake_sig)
{
    struct gensio_data *d;
    struct gensio_os_funcs *o;

    o = malloc(sizeof(*o));
    if (!o)
	return NULL;
    memset(o, 0, sizeof(*o));

    d = malloc(sizeof(*d));
    if (!d) {
	free(o);
	return NULL;
    }
    memset(d, 0, sizeof(*d));
    LOCK_INIT(&d->reflock);
    d->refcount = 1;

    o->user_data = d;
    d->sel = sel;
    d->wake_sig = wake_sig;
    d->mtrack = gensio_memtrack_alloc();

    o->zalloc = gensio_unix_zalloc;
    o->free = gensio_unix_free;
    o->alloc_lock = gensio_unix_alloc_lock;
    o->free_lock = gensio_unix_free_lock;
    o->lock = gensio_unix_lock;
    o->unlock = gensio_unix_unlock;
    o->set_fd_handlers = gensio_unix_set_fd_handlers;
    o->clear_fd_handlers = gensio_unix_clear_fd_handlers;
    o->clear_fd_handlers_norpt = gensio_unix_clear_fd_handlers_norpt;
    o->set_read_handler = gensio_unix_set_read_handler;
    o->set_write_handler = gensio_unix_set_write_handler;
    o->set_except_handler = gensio_unix_set_except_handler;
    o->alloc_timer = gensio_unix_alloc_timer;
    o->free_timer = gensio_unix_free_timer;
    o->start_timer = gensio_unix_start_timer;
    o->start_timer_abs = gensio_unix_start_timer_abs;
    o->stop_timer = gensio_unix_stop_timer;
    o->stop_timer_with_done = gensio_unix_stop_timer_with_done;
    o->alloc_runner = gensio_unix_alloc_runner;
    o->free_runner = gensio_unix_free_runner;
    o->run = gensio_unix_run;
    o->alloc_waiter = gensio_unix_alloc_waiter;
    o->free_waiter = gensio_unix_free_waiter;
    o->wait = gensio_unix_wait;
    o->wait_intr = gensio_unix_wait_intr;
    o->wait_intr_sigmask = gensio_unix_wait_intr_sigmask;
    o->wake = gensio_unix_wake;
    o->service = gensio_unix_service;
    o->get_wake_sig = gensio_unix_get_wake_sig;
    o->get_funcs = gensio_unix_get_funcs;
    o->free_funcs = gensio_unix_free_funcs;
    o->call_once = gensio_unix_call_once;
    o->get_monotonic_time = gensio_unix_get_monotonic_time;
    o->handle_fork = gensio_handle_fork;
    o->add_iod = gensio_unix_add_iod;
    o->release_iod = gensio_unix_release_iod;
    o->iod_get_type = gensio_unix_iod_get_type;
    o->iod_get_fd = gensio_unix_iod_get_fd;

    o->set_non_blocking = gensio_unix_set_non_blocking;
    o->close = gensio_unix_close;
    o->graceful_close = gensio_unix_close;
    o->write = gensio_unix_write;
    o->read = gensio_unix_read;
    o->is_regfile = gensio_unix_is_regfile;
    o->bufcount = gensio_unix_bufcount;
    o->flush = gensio_unix_flush;
    o->makeraw = gensio_unix_makeraw;
    o->open_dev = gensio_unix_open_dev;
    o->exec_subprog = gensio_unix_exec_subprog;
    o->kill_subprog = gensio_unix_kill_subprog;
    o->wait_subprog = gensio_unix_wait_subprog;
    o->get_random = gensio_unix_get_random;
    o->iod_control = gensio_unix_iod_control;
    o->control = gensio_unix_control;

    gensio_addr_addrinfo_set_os_funcs(o);
    if (gensio_stdsock_set_os_funcs(o)) {
	free(d);
	free(o);
	return NULL;
    }

    return o;
}

struct gensio_os_proc_data {
    struct gensio_os_funcs *o;
    int wake_sig;
    sigset_t old_sigs; /* Original signal mask. */
    sigset_t wait_sigs; /* Signal mask to use when waiting. */
    sigset_t check_sigs; /* Signals we are checking for. */

    struct sigaction old_wakesig;

    struct sigaction old_sigchld;
    bool got_sigchld;

    lock_type handler_lock;

    bool term_sig_set;
    bool got_term_sig;
    struct sigaction old_sigint;
    struct sigaction old_sigquit;
    struct sigaction old_sigterm;
    void (*term_handler)(void *handler_data);
    void *term_handler_data;

    bool reload_sig_set;
    bool got_reload_sig;
    struct sigaction old_sighup;
    void (*reload_handler)(void *handler_data);
    void *reload_handler_data;

#if HAVE_DECL_SIGWINCH
    bool winch_sig_set;
    bool got_winch_sig;
    struct sigaction old_sigwinch;
    void (*winch_handler)(int x_chrs, int y_chrs,
			  int x_bits, int y_bits,
			  void *handler_data);
    void *winch_handler_data;
    int winch_fd;
#endif

    struct gensio_os_cleanup_handler *cleanup_handlers;
};

/* We only have one of these per process, so it's global. */
static struct gensio_os_proc_data proc_data;

static void
handle_sigchld(int sig)
{
    proc_data.got_sigchld = true;
}

static void
handle_wakesig(int sig)
{
}

static void
term_sig_handler(int sig)
{
    proc_data.got_term_sig = true;
}

static void
reload_sig_handler(int sig)
{
    proc_data.got_reload_sig = true;
}

#if HAVE_DECL_SIGWINCH
static void
winch_sig_handler(int sig)
{
    proc_data.got_winch_sig = true;
}
#endif

int
gensio_os_proc_setup(struct gensio_os_funcs *o,
		     struct gensio_os_proc_data **rdata)
{
    struct gensio_os_proc_data *data;
    sigset_t sigs;
    struct sigaction sigdo;
    int rv;

    data = &proc_data;
    data->o = o;
    if (o->get_wake_sig)
	data->wake_sig = o->get_wake_sig(o);

    sigemptyset(&sigs);
    sigemptyset(&data->check_sigs);
    if (data->wake_sig)
	sigaddset(&sigs, data->wake_sig);
    sigaddset(&sigs, SIGCHLD); /* Ignore SIGCHLD in normal operation. */
    sigaddset(&sigs, SIGPIPE); /* Ignore broken pipes. */
    rv = sigprocmask(SIG_BLOCK, &sigs, &data->old_sigs);
    if (rv) {
	rv = gensio_os_err_to_err(o, errno);
	return rv;
    }
    data->wait_sigs = data->old_sigs;
    if (data->wake_sig)
	sigdelset(&data->wait_sigs, data->wake_sig);
    sigdelset(&data->wait_sigs, SIGCHLD); /* Allow SIGCHLD while waiting. */
    sigaddset(&data->check_sigs, SIGCHLD);
    sigaddset(&data->wait_sigs, SIGPIPE); /* No SIGPIPE ever. */

    memset(&sigdo, 0, sizeof(sigdo));
    sigdo.sa_handler = handle_sigchld;
    sigdo.sa_flags = SA_NOCLDSTOP;
    rv = sigaction(SIGCHLD, &sigdo, &data->old_sigchld);
    if (rv) {
	rv = gensio_os_err_to_err(o, errno);
	sigprocmask(SIG_SETMASK, &data->old_sigs, NULL);
	return rv;
    }

    if (data->wake_sig) {
	sigdo.sa_handler = handle_wakesig;
	sigdo.sa_flags = 0;
	rv = sigaction(data->wake_sig, &sigdo, &data->old_wakesig);
	if (rv) {
	    rv = gensio_os_err_to_err(o, errno);
	    sigaction(SIGCHLD, &data->old_sigchld, NULL);
	    sigprocmask(SIG_SETMASK, &data->old_sigs, NULL);
	    return rv;
	}
    }

    rv = data->o->control(o, GENSIO_CONTROL_SET_PROC_DATA, data, NULL);
    if (rv) {
	sigaction(SIGCHLD, &data->old_sigchld, NULL);
	sigprocmask(SIG_SETMASK, &data->old_sigs, NULL);
	if (data->wake_sig)
	    sigaction(data->wake_sig, &data->old_wakesig, NULL);
	return rv;
    }

    LOCK_INIT(&data->handler_lock);

    *rdata = data;
    return 0;
}

void
gensio_register_os_cleanup_handler(struct gensio_os_funcs *o,
				   struct gensio_os_cleanup_handler *h)
{
    struct gensio_data *d = o->user_data;
    struct gensio_os_proc_data *data = d->pdata;

    LOCK(&data->handler_lock);
    h->next = data->cleanup_handlers;
    data->cleanup_handlers = h;
    UNLOCK(&data->handler_lock);
}

static int
check_for_sigpending(sigset_t *check_for)
{
#ifdef HAVE_SIGTIMEDWAIT
    static struct timespec zerotime = { 0, 0 };
    return sigtimedwait(check_for, NULL, &zerotime);
#else
#ifdef NSIG
    /* Nothing to do */
#elif defined(_NSIG)
#define NSIG _NSIG
#elif defined(SIGRTMAX)
#define NSIG SIGRTMAX
#else
#define NSIG 64
#endif
    int rsig = 0, sig;
    sigset_t pending;

    sigpending(&pending);
    for (sig = 0; sig < NSIG; sig++) {
	if (sigismember(&pending, sig) && sigismember(check_for, sig)) {
	    rsig = sig;
	    sigwait(&check_for, &sig);
	    break;
	}
    }
    return rsig;
#endif
}

void
gensio_os_proc_cleanup(struct gensio_os_proc_data *data)
{
    int sig;

    /* We should be single-threaded here. */
    while (data->cleanup_handlers) {
	struct gensio_os_cleanup_handler *h = data->cleanup_handlers;

	data->cleanup_handlers = h->next;
	h->cleanup(h);
    }

    LOCK_DESTROY(&data->handler_lock);

    if (data->wake_sig)
	sigaction(data->wake_sig, &data->old_wakesig, NULL);
    if (data->term_sig_set) {
	data->term_sig_set = false;
	sigaction(SIGINT, &data->old_sigint, NULL);
	sigaction(SIGQUIT, &data->old_sigquit, NULL);
	sigaction(SIGTERM, &data->old_sigterm, NULL);
    }
    if (data->reload_sig_set) {
	data->reload_sig_set = false;
	sigaction(SIGHUP, &data->old_sighup, NULL);
    }
#if HAVE_DECL_SIGWINCH
    if (data->winch_sig_set) {
	data->winch_sig_set = false;
	sigaction(SIGWINCH, &data->old_sigwinch, NULL);
    }
#endif
    sigaction(SIGCHLD, &data->old_sigchld, NULL);

    /* Clear out any pending signals before we restore the mask. */
    while ((sig = check_for_sigpending(&data->check_sigs)) > 0)
	;

    sigprocmask(SIG_SETMASK, &data->old_sigs, NULL);
}

void
gensio_os_proc_check_handlers(struct gensio_os_proc_data *data)
{
    int sig;

    LOCK(&data->handler_lock);
    /*
     * Poll implementations (at least epoll) will not necessarily
     * check for signals if they return immediately.  So to avoid
     * missing a signal on a really busy system, check for signals
     * here.
     */
    while ((sig = check_for_sigpending(&data->check_sigs)) > 0) {
	switch(sig) {
	case SIGCHLD:
	    data->got_sigchld = true;
	    break;
	case SIGQUIT:
	case SIGTERM:
	case SIGINT:
	    data->got_term_sig = true;
	    break;
	case SIGHUP:
	    data->got_reload_sig = true;
	    break;
#if HAVE_DECL_SIGWINCH
	case SIGWINCH:
	    data->got_winch_sig = true;
	    break;
#endif
	default:
	    assert(0);
	}
    }
    if (data->got_term_sig) {
	data->got_term_sig = false;
	data->term_handler(data->term_handler_data);
    }
    if (data->got_reload_sig) {
	data->got_reload_sig = false;
	data->reload_handler(data->reload_handler_data);
    }
#if HAVE_DECL_SIGWINCH
    if (data->got_winch_sig) {
	struct winsize win;
	int err;

	data->got_winch_sig = false;
	err = ioctl(data->winch_fd, TIOCGWINSZ, &win);
	if (err == 0)
	    data->winch_handler(win.ws_col, win.ws_row,
				win.ws_xpixel, win.ws_ypixel,
				data->winch_handler_data);
    }
#endif
    UNLOCK(&data->handler_lock);
}

int
gensio_os_proc_register_term_handler(struct gensio_os_proc_data *data,
				     void (*handler)(void *handler_data),
				     void *handler_data)
{
    int err;
    struct sigaction act;
    sigset_t sigs, old_sigs;

    if (data->term_sig_set) {
	data->term_sig_set = false;
	sigaction(SIGINT, &data->old_sigint, NULL);
	sigaction(SIGQUIT, &data->old_sigquit, NULL);
	sigaction(SIGTERM, &data->old_sigterm, NULL);
    }
    if (!handler)
	return 0;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGQUIT);
    sigaddset(&sigs, SIGTERM);
    err = sigprocmask(SIG_BLOCK, &sigs, &old_sigs);
    if (err)
	return gensio_os_err_to_err(data->o, errno);

    data->term_handler = handler;
    data->term_handler_data = handler_data;

    memset(&act, 0, sizeof(act));
    act.sa_handler = term_sig_handler;
    act.sa_flags |= SA_RESETHAND;
    err = sigaction(SIGINT, &act, &data->old_sigint);
    if (err) {
	err = errno;
	goto out_err;
    }
    err = sigaction(SIGQUIT, &act, &data->old_sigquit);
    if (err) {
	err = errno;
	sigaction(SIGINT, &data->old_sigint, NULL);
	goto out_err;
    }
    err = sigaction(SIGTERM, &act, &data->old_sigterm);
    if (err) {
	err = errno;
	sigaction(SIGINT, &data->old_sigint, NULL);
	sigaction(SIGQUIT, &data->old_sigquit, NULL);
	goto out_err;
    }

    sigdelset(&data->wait_sigs, SIGINT);
    sigdelset(&data->wait_sigs, SIGQUIT);
    sigdelset(&data->wait_sigs, SIGTERM);
    sigaddset(&data->check_sigs, SIGINT);
    sigaddset(&data->check_sigs, SIGQUIT);
    sigaddset(&data->check_sigs, SIGTERM);
    data->term_sig_set = true;
    return 0;

 out_err:
    sigprocmask(SIG_SETMASK, &old_sigs, NULL);
    return gensio_os_err_to_err(data->o, err);
}

int gensio_os_proc_register_reload_handler(struct gensio_os_proc_data *data,
					   void (*handler)(void *handler_data),
					   void *handler_data)
{
    int err;
    struct sigaction act;
    sigset_t sigs, old_sigs;

    if (data->reload_sig_set) {
	data->reload_sig_set = false;
	sigaction(SIGHUP, &data->old_sighup, NULL);
    }
    if (!handler)
	return 0;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGHUP);
    err = sigprocmask(SIG_BLOCK, &sigs, &old_sigs);
    if (err)
	return gensio_os_err_to_err(data->o, errno);

    data->reload_handler = handler;
    data->reload_handler_data = handler_data;

    memset(&act, 0, sizeof(act));
    act.sa_handler = reload_sig_handler;
    err = sigaction(SIGHUP, &act, &data->old_sighup);
    if (err) {
	err = errno;
	goto out_err;
    }
    sigdelset(&data->wait_sigs, SIGHUP);
    sigaddset(&data->check_sigs, SIGHUP);
    data->reload_sig_set = true;
    return 0;

 out_err:
    sigprocmask(SIG_SETMASK, &old_sigs, NULL);
    return gensio_os_err_to_err(data->o, err);
}

int
gensio_os_proc_register_winsize_handler(struct gensio_os_proc_data *data,
					struct gensio_iod *console_iod,
					void (*handler)(int x_chrs, int y_chrs,
							int x_bits, int y_bits,
							void *handler_data),
					void *handler_data)
{
#if HAVE_DECL_SIGWINCH
    struct gensio_iod_unix *iod = i_to_sel(console_iod);
    int err;
    struct sigaction act;
    sigset_t sigs, old_sigs;
    struct winsize win;

    if (data->winch_sig_set) {
	data->winch_sig_set = false;
	sigaction(SIGWINCH, &data->old_sigwinch, NULL);
    }
    if (!handler)
	return 0;

    err = ioctl(iod->fd, TIOCGWINSZ, &win);
    if (err == -1)
	return GE_NOTSUP;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGWINCH);
    err = sigprocmask(SIG_BLOCK, &sigs, &old_sigs);
    if (err)
	return gensio_os_err_to_err(data->o, errno);

    data->winch_handler = handler;
    data->winch_handler_data = handler_data;
    data->winch_fd = iod->fd;

    memset(&act, 0, sizeof(act));
    act.sa_handler = winch_sig_handler;
    err = sigaction(SIGWINCH, &act, &data->old_sigwinch);
    if (err) {
	err = errno;
	goto out_err;
    }
    sigdelset(&data->wait_sigs, SIGWINCH);
    data->winch_sig_set = true;
    kill(getpid(), SIGWINCH);
    return 0;

 out_err:
    sigprocmask(SIG_SETMASK, &old_sigs, NULL);
    return gensio_os_err_to_err(data->o, err);
#else
    return GE_NOTSUP;
#endif
}

sigset_t *
gensio_os_proc_unix_get_wait_sigset(struct gensio_os_proc_data *data)
{
    return &data->wait_sigs;
}

struct gensio_thread {
    struct gensio_os_funcs *o;
#ifdef USE_PTHREADS
    pthread_t id;
#endif
    void (*start_func)(void *data);
    void *data;
};

static void *
gensio_os_thread_func(void *info)
{
    struct gensio_thread *tid = info;

    tid->start_func(tid->data);
    return NULL;
}

int
gensio_os_new_thread(struct gensio_os_funcs *o,
		     void (*start_func)(void *data), void *data,
		     struct gensio_thread **thread_id)
{
#ifdef USE_PTHREADS
    struct gensio_thread *tid;
    int rv;

    tid = o->zalloc(o, sizeof(*tid));
    if (!tid)
	return GE_NOMEM;
    tid->o = o;
    tid->start_func = start_func;
    tid->data = data;
    rv = pthread_create(&tid->id, NULL, gensio_os_thread_func, tid);
    if (rv) {
	o->free(o, tid);
	return gensio_os_err_to_err(o, rv);
    }
    *thread_id = tid;
    return 0;
#else
    return GE_NOTSUP;
#endif
}

int gensio_os_wait_thread(struct gensio_thread *tid)
{
#ifdef USE_PTHREADS
    int rv;

    rv = pthread_join(tid->id, NULL);
    if (rv)
	return gensio_os_err_to_err(tid->o, rv);
    tid->o->free(tid->o, tid);
    return 0;
#else
    return GE_NOTSUP;
#endif
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
    case ENOMEM:	err = GE_NOMEM; break;
    case EINVAL:	err = GE_INVAL; break;
    case ENOENT:	err = GE_NOTFOUND; break;
    case EEXIST:	err = GE_EXISTS; break;
    case EBUSY:		err = GE_INUSE; break;
    case EAGAIN:	err = GE_INPROGRESS; break;
#if EAGAIN != EINPROGRESS
    case EINPROGRESS:	err = GE_INPROGRESS; break;
#endif
    case ETIMEDOUT:	err = GE_TIMEDOUT; break;
    case EPIPE:		err = GE_REMCLOSE; break;
    case ECONNRESET:	err = GE_REMCLOSE; break;
    case EHOSTUNREACH:	err = GE_HOSTDOWN; break;
    case ECONNREFUSED:	err = GE_CONNREFUSE; break;
    case EIO:		err = GE_IOERR; break;
    case EADDRINUSE:	err = GE_ADDRINUSE; break;
    case EINTR:		err = GE_INTERRUPTED; break;
    case ESHUTDOWN:     err = GE_SHUTDOWN; break;
    case EMSGSIZE:      err = GE_TOOBIG; break;
    case EPERM:         err = GE_PERM; break;
    case EACCES:        err = GE_PERM; break;
    default:		err = GE_OSERR;
    }

    if (err == GE_OSERR) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled OS error in %s:%d: %s (%d)", caller, lineno,
		   strerror(oserr), oserr);
    }

    return err;
}

#ifdef USE_PTHREADS
struct sel_lock_s
{
    lock_type lock;
};

static sel_lock_t *
defsel_lock_alloc(void *cb_data)
{
    sel_lock_t *l;

    l = malloc(sizeof(*l));
    if (!l)
	return NULL;
    LOCK_INIT(&l->lock);
    return l;
}

static void
defsel_lock_free(sel_lock_t *l)
{
    LOCK_DESTROY(&l->lock);
    free(l);
}

static void
defsel_lock(sel_lock_t *l)
{
    LOCK(&l->lock);
}

static void
defsel_unlock(sel_lock_t *l)
{
    UNLOCK(&l->lock);
}

#endif

int
gensio_unix_funcs_alloc(struct selector_s *sel, int wake_sig,
			struct gensio_os_funcs **ro)
{
    struct gensio_os_funcs *o;
    bool freesel = false;
    int rv;

    if (!sel) {
#ifdef USE_PTHREADS
	rv = sel_alloc_selector_thread(&sel, wake_sig,
				       defsel_lock_alloc,
				       defsel_lock_free, defsel_lock,
				       defsel_unlock, NULL);
#else
	rv = sel_alloc_selector_nothread(&sel);
#endif
	if (rv)
	    return GE_NOMEM;
	freesel = true;
    }

    o = gensio_unix_alloc_sel(sel, wake_sig);
    if (o) {
	struct gensio_data *d = o->user_data;

	d->freesel = freesel;
    } else if (freesel) {
	sel_free_selector(sel);
    }

    *ro = o;
    return 0;
}

struct gensio_os_funcs *
gensio_selector_alloc(struct selector_s *sel, int wake_sig)
{
    struct gensio_os_funcs *o = NULL;

    gensio_unix_funcs_alloc(sel, wake_sig, &o);
    return o;
}

static void
defoshnd_init(void)
{
    gensio_unix_funcs_alloc(NULL, defoshnd_wake_sig, &defoshnd);
}

int
gensio_default_os_hnd(int wake_sig, struct gensio_os_funcs **o)
{
    int err = 0;

    if (wake_sig == -198234)
	wake_sig = SIGUSR1;

    LOCK(&defos_lock);
    if (!defoshnd) {
	defoshnd_wake_sig = wake_sig;
	defoshnd_init();
	if (!defoshnd) {
	    defoshnd_wake_sig = -1;
	    err = GE_NOMEM;
	}
    } else if (wake_sig != defoshnd_wake_sig) {
	err = GE_INVAL;
    } else {
	gensio_unix_get_funcs(defoshnd);
    }
    UNLOCK(&defos_lock);

    if (!err)
	*o = defoshnd;
    return err;
}

void
gensio_osfunc_exit(int rv)
{
    errtrig_exit(rv);
}
