/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include "config.h"
#include <malloc.h>
#include <string.h>
#include <errno.h>

#ifdef USE_PTHREADS
#include <pthread.h>
#else
#define pthread_mutex_t int
#define pthread_mutex_lock(l) do { } while (0)
#define pthread_mutex_unlock(l) do { } while (0)
#define pthread_mutex_init(l, n) do { } while (0)
#define pthread_mutex_destroy(l, n) do { } while (0)
#define PTHREAD_MUTEX_INITIALIZER 0
#endif

#include <gensio/gensio_selector.h>

#include <gensio/waiter.h>
#include "utils.h"
#include <stdlib.h>

struct gensio_data {
    struct selector_s *sel;
    int wake_sig;
};

#if 1
#define OUT_OF_MEMORY_TEST
#endif

#ifdef OUT_OF_MEMORY_TEST
#include <assert.h>
/*
 * Some memory allocation failure testing.  If the GENSIO_OOM_TEST
 * environment variable is set to number N, the Nth memory allocation
 * will fail (return NULL).  The program should call gensio_sel_exit
 * (below); it will cause specific values to be returned on an exit
 * failure.
 */
pthread_mutex_t oom_mutex = PTHREAD_MUTEX_INITIALIZER;
bool oom_initialized;
bool oom_ready;
bool triggered;
unsigned int oom_count;
unsigned int oom_curr;
#endif

static void *
gensio_sel_zalloc(struct gensio_os_funcs *f, unsigned int size)
{
    void *d;
    unsigned int curr;

#ifdef OUT_OF_MEMORY_TEST
    if (!oom_initialized) {
	char *s = getenv("GENSIO_OOM_TEST");

	oom_initialized = true;
	if (s) {
	    oom_count = strtoul(s, NULL, 0);
	    oom_ready = true;
	}
    }
    if (oom_ready) {
	curr = oom_curr++;
	if (curr == oom_count) {
	    triggered = true;
	    return NULL;
	}
    }
#endif

    d = malloc(size);
    if (d)
	memset(d, 0, size);
    return d;
}

static void
gensio_sel_free(struct gensio_os_funcs *f, void *data)
{
    free(data);
}

struct gensio_lock {
    struct gensio_os_funcs *f;
    pthread_mutex_t lock;
};

static struct gensio_lock *
gensio_sel_alloc_lock(struct gensio_os_funcs *f)
{
    struct gensio_lock *lock = f->zalloc(f, sizeof(*lock));

    if (lock) {
	lock->f = f;
	pthread_mutex_init(&lock->lock, NULL);
    }

    return lock;
}

static void
gensio_sel_free_lock(struct gensio_lock *lock)
{
    pthread_mutex_destroy(&lock->lock);
    lock->f->free(lock->f, lock);
}

static void
gensio_sel_lock(struct gensio_lock *lock)
{
    pthread_mutex_lock(&lock->lock);
}

static void
gensio_sel_unlock(struct gensio_lock *lock)
{
    pthread_mutex_unlock(&lock->lock);
}

static int
gensio_sel_set_fd_handlers(struct gensio_os_funcs *f,
			   int fd,
			   void *cb_data,
			   void (*read_handler)(int fd, void *cb_data),
			   void (*write_handler)(int fd, void *cb_data),
			   void (*except_handler)(int fd, void *cb_data),
			   void (*cleared_handler)(int fd, void *cb_data))
{
    struct gensio_data *d = f->user_data;
    int rv;

    rv = sel_set_fd_handlers(d->sel, fd, cb_data, read_handler, write_handler,
			     except_handler, cleared_handler);
    return gensio_os_err_to_err(f, rv);
}


static void
gensio_sel_clear_fd_handlers(struct gensio_os_funcs *f, int fd)
{
    struct gensio_data *d = f->user_data;

    sel_clear_fd_handlers(d->sel, fd);
}

static void
gensio_sel_clear_fd_handlers_norpt(struct gensio_os_funcs *f, int fd)
{
    struct gensio_data *d = f->user_data;

    sel_clear_fd_handlers_norpt(d->sel, fd);
}

static void
gensio_sel_set_read_handler(struct gensio_os_funcs *f, int fd, bool enable)
{
    struct gensio_data *d = f->user_data;
    int op;

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_read_handler(d->sel, fd, op);
}

static void
gensio_sel_set_write_handler(struct gensio_os_funcs *f, int fd, bool enable)
{
    struct gensio_data *d = f->user_data;
    int op;

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_write_handler(d->sel, fd, op);
}

static void
gensio_sel_set_except_handler(struct gensio_os_funcs *f, int fd, bool enable)
{
    struct gensio_data *d = f->user_data;
    int op;

    if (enable)
	op = SEL_FD_HANDLER_ENABLED;
    else
	op = SEL_FD_HANDLER_DISABLED;

    sel_set_fd_except_handler(d->sel, fd, op);
}

struct gensio_timer {
    struct gensio_os_funcs *f;
    void (*handler)(struct gensio_timer *t, void *cb_data);
    void *cb_data;
    sel_timer_t *sel_timer;
    pthread_mutex_t lock;

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
gensio_sel_alloc_timer(struct gensio_os_funcs *f,
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
    pthread_mutex_init(&timer->lock, NULL);

    rv = sel_alloc_timer(d->sel, gensio_timeout_handler, timer,
			 &timer->sel_timer);
    if (rv) {
	f->free(f, timer);
	return NULL;
    }

    return timer;
}

static void
gensio_sel_free_timer(struct gensio_timer *timer)
{
    sel_free_timer(timer->sel_timer);
    timer->f->free(timer->f, timer);
}

static int
gensio_sel_start_timer(struct gensio_timer *timer, struct timeval *timeout)
{
    struct timeval tv;
    int rv;

    sel_get_monotonic_time(&tv);
    add_to_timeval(&tv, timeout);
    rv = sel_start_timer(timer->sel_timer, &tv);
    return gensio_os_err_to_err(timer->f, rv);
}

static int
gensio_sel_start_timer_abs(struct gensio_timer *timer, struct timeval *timeout)
{
    int rv;

    rv = sel_start_timer(timer->sel_timer, timeout);
    return gensio_os_err_to_err(timer->f, rv);
}

static int
gensio_sel_stop_timer(struct gensio_timer *timer)
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

    pthread_mutex_lock(&timer->lock);
    done_handler = timer->done_handler;
    done_cb_data = timer->done_cb_data;
    pthread_mutex_unlock(&timer->lock);
    done_handler(timer, done_cb_data);
}

static int
gensio_sel_stop_timer_with_done(struct gensio_timer *timer,
				void (*done_handler)(struct gensio_timer *t,
						     void *cb_data),
				void *cb_data)
{
    int rv;

    pthread_mutex_lock(&timer->lock);
    rv = sel_stop_timer_with_done(timer->sel_timer, gensio_stop_timer_done,
				  timer);
    if (!rv) {
	timer->done_handler = done_handler;
	timer->done_cb_data = cb_data;
    }
    pthread_mutex_unlock(&timer->lock);
    return gensio_os_err_to_err(timer->f, rv);
}

struct gensio_runner {
    struct gensio_os_funcs *f;
    struct sel_runner_s *sel_runner;
    void (*handler)(struct gensio_runner *r, void *cb_data);
    void *cb_data;
};

static struct gensio_runner *
gensio_sel_alloc_runner(struct gensio_os_funcs *f,
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
gensio_sel_free_runner(struct gensio_runner *runner)
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
gensio_sel_run(struct gensio_runner *runner)
{
    return sel_run(runner->sel_runner, gensio_runner_handler, runner);
}

struct gensio_waiter {
    struct gensio_os_funcs *f;
    struct waiter_s *sel_waiter;
};

static struct gensio_waiter *
gensio_sel_alloc_waiter(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;
    struct gensio_waiter *waiter = f->zalloc(f, sizeof(*waiter));

    if (!waiter)
	return NULL;

    waiter->f = f;

    waiter->sel_waiter = alloc_waiter(d->sel, d->wake_sig);
    if (!waiter->sel_waiter) {
	f->free(f, waiter);
	return NULL;
    }

    return waiter;
}

static void
gensio_sel_free_waiter(struct gensio_waiter *waiter)
{
    free_waiter(waiter->sel_waiter);
    waiter->f->free(waiter->f, waiter);
}

static int
gensio_sel_wait(struct gensio_waiter *waiter, unsigned int count,
		struct timeval *timeout)
{
    int err;

    err = wait_for_waiter_timeout(waiter->sel_waiter, count, timeout);
    return gensio_os_err_to_err(waiter->f, err);
}


static int
gensio_sel_wait_intr(struct gensio_waiter *waiter, unsigned int count,
		     struct timeval *timeout)
{
    int err;

    err = wait_for_waiter_timeout_intr(waiter->sel_waiter, count, timeout);
    return gensio_os_err_to_err(waiter->f, err);
}

static void
gensio_sel_wake(struct gensio_waiter *waiter)
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
gensio_sel_service(struct gensio_os_funcs *f, struct timeval *timeout)
{
    struct gensio_data *d = f->user_data;
    struct wait_data w;
    int err;

    w.id = pthread_self();
    w.wake_sig = d->wake_sig;
    err = sel_select_intr(d->sel, wake_thread_send_sig, w.id, &w, timeout);
    if (err < 0)
	err = gensio_os_err_to_err(f, errno);
    else if (err == 0)
	err = GE_TIMEDOUT;
    else
	err = 0;

    return err;
}
#else
static int
gensio_sel_service(struct gensio_os_funcs *f, struct timeval *timeout)
{
    struct gensio_data *d = f->user_data;
    int err;

    err = sel_select_intr(d->sel, NULL, 0, NULL, timeout);
    if (err < 0)
	err = gensio_os_err_to_err(f, errno);
    else if (err == 0)
	err = GE_TIMEDOUT;
    else
	err = 0;

    return err;
}
#endif

static void
gensio_sel_free_funcs(struct gensio_os_funcs *f)
{
    free(f->user_data);
    free(f);
}

static pthread_mutex_t once_lock = PTHREAD_MUTEX_INITIALIZER;

static void
gensio_sel_call_once(struct gensio_os_funcs *f, struct gensio_once *once,
		     void (*func)(void *cb_data), void *cb_data)
{
    if (once->called)
	return;
    pthread_mutex_lock(&once_lock);
    if (!once->called) {
	once->called = true;
	pthread_mutex_unlock(&once_lock);
	func(cb_data);
    } else {
	pthread_mutex_unlock(&once_lock);
    }
}

static void
gensio_sel_get_monotonic_time(struct gensio_os_funcs *f, struct timeval *time)
{
    sel_get_monotonic_time(time);
}

static int
gensio_handle_fork(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;

    return sel_setup_forked_process(d->sel);
}

struct gensio_os_funcs *
gensio_selector_alloc(struct selector_s *sel, int wake_sig)
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

    o->user_data = d;
    d->sel = sel;
    d->wake_sig = wake_sig;

    o->zalloc = gensio_sel_zalloc;
    o->free = gensio_sel_free;
    o->alloc_lock = gensio_sel_alloc_lock;
    o->free_lock = gensio_sel_free_lock;
    o->lock = gensio_sel_lock;
    o->unlock = gensio_sel_unlock;
    o->set_fd_handlers = gensio_sel_set_fd_handlers;
    o->clear_fd_handlers = gensio_sel_clear_fd_handlers;
    o->clear_fd_handlers_norpt = gensio_sel_clear_fd_handlers_norpt;
    o->set_read_handler = gensio_sel_set_read_handler;
    o->set_write_handler = gensio_sel_set_write_handler;
    o->set_except_handler = gensio_sel_set_except_handler;
    o->alloc_timer = gensio_sel_alloc_timer;
    o->free_timer = gensio_sel_free_timer;
    o->start_timer = gensio_sel_start_timer;
    o->start_timer_abs = gensio_sel_start_timer_abs;
    o->stop_timer = gensio_sel_stop_timer;
    o->stop_timer_with_done = gensio_sel_stop_timer_with_done;
    o->alloc_runner = gensio_sel_alloc_runner;
    o->free_runner = gensio_sel_free_runner;
    o->run = gensio_sel_run;
    o->alloc_waiter = gensio_sel_alloc_waiter;
    o->free_waiter = gensio_sel_free_waiter;
    o->wait = gensio_sel_wait;
    o->wait_intr = gensio_sel_wait_intr;
    o->wake = gensio_sel_wake;
    o->service = gensio_sel_service;
    o->free_funcs = gensio_sel_free_funcs;
    o->call_once = gensio_sel_call_once;
    o->get_monotonic_time = gensio_sel_get_monotonic_time;
    o->handle_fork = gensio_handle_fork;

    return o;
}

static struct gensio_os_funcs *defoshnd;
static int defoshnd_wake_sig = -1;

#ifdef USE_PTHREADS
struct sel_lock_s
{
    pthread_mutex_t lock;
};

sel_lock_t *defsel_lock_alloc(void *cb_data)
{
    sel_lock_t *l;

    l = malloc(sizeof(*l));
    if (!l)
	return NULL;
    pthread_mutex_init(&l->lock, NULL);
    return l;
}

void defsel_lock_free(sel_lock_t *l)
{
    pthread_mutex_destroy(&l->lock);
    free(l);
}

void defsel_lock(sel_lock_t *l)
{
    pthread_mutex_lock(&l->lock);
}

void defsel_unlock(sel_lock_t *l)
{
    pthread_mutex_unlock(&l->lock);
}

static pthread_once_t defos_once = PTHREAD_ONCE_INIT;
#endif

void defoshnd_init(void)
{
    struct selector_s *sel;
    int rv;

#ifdef USE_PTHREADS
    rv = sel_alloc_selector_thread(&sel, defoshnd_wake_sig, defsel_lock_alloc,
				   defsel_lock_free, defsel_lock,
				   defsel_unlock, NULL);
#else
    rv = sel_alloc_selector_nothread(&sel);
#endif
    if (rv)
	return;

    defoshnd = gensio_selector_alloc(sel, defoshnd_wake_sig);
    if (!defoshnd)
	sel_free_selector(sel);
}

int
gensio_default_os_hnd(int wake_sig, struct gensio_os_funcs **o)
{
    if (defoshnd_wake_sig != -1 && wake_sig != defoshnd_wake_sig)
	return GE_INVAL;

    if (!defoshnd) {
	defoshnd_wake_sig = wake_sig;
#ifdef USE_PTHREADS
	pthread_once(&defos_once, defoshnd_init);
#else
	defoshnd_init();
#endif

	if (!defoshnd)
	    return GE_NOMEM;
    }

    *o = defoshnd;
    return 0;
}

void
gensio_sel_exit(int rv)
{
#ifndef OUT_OF_MEMORY_TEST
    exit(rv);
#else
    if (!oom_ready)
	exit(rv);
    assert (rv == 1 || rv == 0); /* Only these values are allowed. */

    /*
     * Return an error.  The values mean:
     *
     * 0 - No error occurred and the memory allocation failure didn't happen
     * 1 - An error occurred and the memory allocation failure happenned
     * 2 - No error occurred and the memory allocation failure happenned
     * 3 - An error occurred and the memory allocation failure didn't happen
     */
    if (rv == 0 && triggered)
	exit(2);
    if (rv == 0 && !triggered)
	exit(0);
    if (rv == 1 && triggered)
	exit(1);
    if (rv == 1 && !triggered)
	exit(3);
    assert(false); /* Shouldn't get here. */
#endif
}
