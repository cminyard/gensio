/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <malloc.h>
#include <string.h>
#include <errno.h>

#include "pthread_handler.h"

#include <gensio/gensio_selector.h>
#include <gensio/selector.h>
#include <gensio/gensio.h>

#include "utils.h"
#include <stdlib.h>
#include <assert.h>

struct gensio_data {
    struct selector_s *sel;
    bool freesel;
    int wake_sig;
};

#ifdef ENABLE_INTERNAL_TRACE
#define OUT_OF_MEMORY_TEST
#define TRACK_ALLOCED_MEMORY
#endif

#ifdef OUT_OF_MEMORY_TEST
/* Declared in selector.c */
extern lock_type oom_mutex;
extern bool oom_initialized;
extern bool oom_ready;
extern bool triggered;
extern unsigned int oom_count;
extern unsigned int oom_curr;
#endif
#ifdef TRACK_ALLOCED_MEMORY
lock_type memtrk_mutex = LOCK_INITIALIZER;
struct memory_link {
    struct memory_link *next;
    struct memory_link *prev;
};
struct memory_header {
    struct memory_link link;
    void *callers[4];
    void *freers[4];
    bool inuse;
};
struct memory_link memhead = { &memhead, &memhead };
struct memory_link memfree = { &memfree, &memfree };
unsigned long freecount;
bool memtracking_initialized;
bool memtracking_ready;
bool memtracking_abort_on_lost;
#endif

static void *
gensio_sel_zalloc(struct gensio_os_funcs *f, unsigned int size)
{
    void *d;
#ifdef OUT_OF_MEMORY_TEST
    unsigned int curr;

    {
	bool triggerit = false;

	LOCK(&oom_mutex);
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
		triggerit = true;
	    }
	}
	UNLOCK(&oom_mutex);
	if (triggerit)
	    return NULL;
    }
#endif
#ifdef TRACK_ALLOCED_MEMORY
    if (!memtracking_initialized) {
	LOCK(&memtrk_mutex);
	if (!memtracking_initialized) {
	    char *s = getenv("GENSIO_MEMTRACK");

	    memtracking_initialized = true;
	    if (s) {
		memtracking_ready = true;
		if (strstr(s, "abort"))
		    memtracking_abort_on_lost = true;
	    }
	}
	UNLOCK(&memtrk_mutex);
    }
    if (memtracking_ready) {
	d = malloc(size + sizeof(struct memory_header));
	if (d) {
	    struct memory_header *h = d;

	    d = ((char *) d) + sizeof(struct memory_header);
	    memset(h->callers, 0, sizeof(void *) * 4);
	    h->callers[0] = __builtin_return_address(0);
#if 0
	    h->callers[1] = __builtin_return_address(1);
	    h->callers[2] = __builtin_return_address(2);
	    h->callers[3] = __builtin_return_address(3);
#endif
	    memset(h->freers, 0, sizeof(void *) * 4);
	    h->inuse = true;
	    LOCK(&memtrk_mutex);
	    h->link.next = &memhead;
	    h->link.prev = memhead.prev;
	    memhead.prev->next = &h->link;
	    memhead.prev = &h->link;
	    freecount++;
	    UNLOCK(&memtrk_mutex);
	}
    } else
#endif
    d = malloc(size);

    if (d)
	memset(d, 0, size);
    return d;
}

static void
gensio_sel_free(struct gensio_os_funcs *f, void *data)
{
    assert(data);
#ifdef TRACK_ALLOCED_MEMORY
    if (memtracking_ready) {
	struct memory_header *h = ((struct memory_header *)
				   (((char *) data) - sizeof(*h)));

	if (!h->inuse) {
	    fprintf(stderr, "Free of already freed data at %p.\n", data);
	    fprintf(stderr, "  allocated at %p %p %p %p.\n",
		    h->callers[0], h->callers[1],
		    h->callers[2], h->callers[3]);
	    fprintf(stderr, "  freed at %p %p %p %p.\n",
		    h->freers[0], h->freers[1],
		    h->freers[2], h->freers[3]);
	    *((volatile char *) 0) = 1;
	    assert(h->inuse);
	    return;
	}
	data = h;
	h->freers[0] = __builtin_return_address(0);
#if 0
	h->freers[1] = __builtin_return_address(1);
	h->freers[2] = __builtin_return_address(2);
	h->freers[3] = __builtin_return_address(3);
#endif
	LOCK(&memtrk_mutex);
	h->link.next->prev = h->link.prev;
	h->link.prev->next = h->link.next;
	h->inuse = false;
	freecount--;
	/* Add it to the free list, don't free it. */
	h->link.next = &memfree;
	h->link.prev = memfree.prev;
	memfree.prev->next = &h->link;
	memfree.prev = &h->link;
	UNLOCK(&memtrk_mutex);
    } else
#endif
    free(data);
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
#include <signal.h>
#include <stdbool.h>

struct waiter_data {
    pthread_t tid;
    int wake_sig;
    struct waiter_data *prev;
    struct waiter_data *next;
};

typedef struct waiter_s {
    struct selector_s *sel;
    int wake_sig;
    unsigned int count;
    pthread_mutex_t lock;
    struct waiter_data wts;
} waiter_t;

static waiter_t *
alloc_waiter(struct selector_s *sel, int wake_sig)
{
    waiter_t *waiter;

    waiter = malloc(sizeof(waiter_t));
    if (waiter) {
	memset(waiter, 0, sizeof(*waiter));
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
    free(waiter);
}

static void
wake_thread_send_sig_waiter(long thread_id, void *cb_data)
{
    struct waiter_data *w = cb_data;

    pthread_kill(w->tid, w->wake_sig);
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

    pthread_mutex_lock(&waiter->lock);
    waiter->wts.next->prev = &w;
    w.next = waiter->wts.next;
    waiter->wts.next = &w;
    w.prev = &waiter->wts;

    rtv = gensio_time_to_timeval(&tv, timeout);
    while (waiter->count < count) {
	pthread_mutex_unlock(&waiter->lock);
	if (intr)
	    err = sel_select_intr_sigmask(waiter->sel,
					  wake_thread_send_sig_waiter,
					  w.tid, &w, rtv, sigmask);
	else
	    err = sel_select(waiter->sel, wake_thread_send_sig_waiter, w.tid, &w,
			     rtv);
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
    if (!err)
	waiter->count -= count;
    w.next->prev = w.prev;
    w.prev->next = w.next;
    pthread_mutex_unlock(&waiter->lock);

    return err;
}

static void
wake_waiter(waiter_t *waiter)
{
    struct waiter_data *w;

    pthread_mutex_lock(&waiter->lock);
    waiter->count++;
    w = waiter->wts.next;
    while (w != &waiter->wts) {
	pthread_kill(w->tid, w->wake_sig);
	w = w->next;
    }
    pthread_mutex_unlock(&waiter->lock);
}

#else /* USE_PTHREADS */

typedef struct waiter_s {
    unsigned int count;
    struct selector_s *sel;
} waiter_t;

static waiter_t *
alloc_waiter(struct selector_s *sel, int wake_sig)
{
    waiter_t *waiter;

    waiter = malloc(sizeof(waiter_t));
    if (waiter)
	memset(waiter, 0, sizeof(*waiter));
    waiter->sel = sel;
    return waiter;
}

static void
free_waiter(waiter_t *waiter)
{
    assert(waiter);
    free(waiter);
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
wait_for_waiter_timeout(waiter_t *waiter, unsigned int count,
			gensio_time *timeout)
{
    return i_wait_for_waiter_timeout(waiter, count, timeout, false, NULL);
}

static int
wait_for_waiter_timeout_intr(waiter_t *waiter, unsigned int count,
			     gensio_time *timeout)
{
    return i_wait_for_waiter_timeout(waiter, count, timeout, true, NULL);
}

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
gensio_sel_alloc_lock(struct gensio_os_funcs *f)
{
    struct gensio_lock *lock = f->zalloc(f, sizeof(*lock));

    if (lock) {
	lock->f = f;
	LOCK_INIT(&lock->lock);
    }

    return lock;
}

static void
gensio_sel_free_lock(struct gensio_lock *lock)
{
    LOCK_DESTROY(&lock->lock);
    lock->f->free(lock->f, lock);
}

static void
gensio_sel_lock(struct gensio_lock *lock)
{
    LOCK(&lock->lock);
}

static void
gensio_sel_unlock(struct gensio_lock *lock)
{
    UNLOCK(&lock->lock);
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
gensio_sel_free_timer(struct gensio_timer *timer)
{
    sel_free_timer(timer->sel_timer);
    timer->f->free(timer->f, timer);
}

static int
gensio_sel_start_timer(struct gensio_timer *timer, gensio_time *timeout)
{
    struct timeval tv;
    int rv;

    sel_get_monotonic_time(&tv);
    add_to_timeval(&tv, timeout);
    rv = sel_start_timer(timer->sel_timer, &tv);
    return gensio_os_err_to_err(timer->f, rv);
}

static int
gensio_sel_start_timer_abs(struct gensio_timer *timer, gensio_time *timeout)
{
    int rv;
    struct timeval tv, *rtv;

    rtv = gensio_time_to_timeval(&tv, timeout);
    rv = sel_start_timer(timer->sel_timer, rtv);
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

    LOCK(&timer->lock);
    done_handler = timer->done_handler;
    done_cb_data = timer->done_cb_data;
    timer->done_handler = NULL;
    UNLOCK(&timer->lock);
    done_handler(timer, done_cb_data);
}

static int
gensio_sel_stop_timer_with_done(struct gensio_timer *timer,
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
		gensio_time *timeout)
{
    int err;

    err = wait_for_waiter_timeout(waiter->sel_waiter, count, timeout);
    return gensio_os_err_to_err(waiter->f, err);
}


static int
gensio_sel_wait_intr(struct gensio_waiter *waiter, unsigned int count,
		     gensio_time *timeout)
{
    int err;

    err = wait_for_waiter_timeout_intr(waiter->sel_waiter, count, timeout);
    return gensio_os_err_to_err(waiter->f, err);
}

static int
gensio_sel_wait_intr_sigmask(struct gensio_waiter *waiter, unsigned int count,
			     gensio_time *timeout, void *sigmask)
{
    int err;

    err = wait_for_waiter_timeout_intr_sigmask(waiter->sel_waiter, count,
					       timeout, sigmask);
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
gensio_sel_service(struct gensio_os_funcs *f, gensio_time *timeout)
{
    struct gensio_data *d = f->user_data;
    struct wait_data w;
    struct timeval tv, *rtv;
    int err;

    w.id = pthread_self();
    w.wake_sig = d->wake_sig;
    rtv = gensio_time_to_timeval(&tv, timeout);
    err = sel_select_intr(d->sel, wake_thread_send_sig, w.id, &w, rtv);
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
gensio_sel_service(struct gensio_os_funcs *f, gensio_time *timeout)
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

static void
gensio_sel_free_funcs(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;

    if (d->freesel)
	sel_free_selector(d->sel);
    free(f->user_data);
    free(f);
}

static lock_type once_lock = LOCK_INITIALIZER;

static void
gensio_sel_call_once(struct gensio_os_funcs *f, struct gensio_once *once,
		     void (*func)(void *cb_data), void *cb_data)
{
    if (once->called)
	return;
    LOCK(&once_lock);
    if (!once->called) {
	once->called = true;
	UNLOCK(&once_lock);
	func(cb_data);
    } else {
	UNLOCK(&once_lock);
    }
}

static void
gensio_sel_get_monotonic_time(struct gensio_os_funcs *f, gensio_time *time)
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

static struct gensio_os_funcs *
gensio_selector_alloc_sel(struct selector_s *sel, int wake_sig)
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
    o->wait_intr_sigmask = gensio_sel_wait_intr_sigmask;

    return o;
}

static struct gensio_os_funcs *defoshnd;
static int defoshnd_wake_sig = -1;

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

static pthread_once_t defos_once = PTHREAD_ONCE_INIT;
#endif

struct gensio_os_funcs *
gensio_selector_alloc(struct selector_s *sel, int wake_sig)
{
    struct gensio_os_funcs *o;
    bool freesel = false;
    int rv;

    if (!sel) {
#ifdef USE_PTHREADS
	rv = sel_alloc_selector_thread(&sel, defoshnd_wake_sig,
				       defsel_lock_alloc,
				       defsel_lock_free, defsel_lock,
				       defsel_unlock, NULL);
#else
	rv = sel_alloc_selector_nothread(&sel);
#endif
	if (rv)
	    return NULL;
	freesel = true;
    }

    o = gensio_selector_alloc_sel(sel, wake_sig);
    if (o) {
	struct gensio_data *d = o->user_data;

	d->freesel = freesel;
    } else if (freesel) {
	sel_free_selector(sel);
    }

    return o;
}

static void
defoshnd_init(void)
{
    defoshnd = gensio_selector_alloc(NULL, defoshnd_wake_sig);
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
#ifdef TRACK_ALLOCED_MEMORY
    {
	struct memory_link *l = memhead.next;

	while (l != &memhead) {
	    /* link is first element */
	    struct memory_header *h = (struct memory_header *) l;

	    fprintf(stderr, "Lost memory at %p allocated at %p %p %p %p\n",
		    ((char *) h) + sizeof(*h), h->callers[0], h->callers[1],
		    h->callers[2], h->callers[3]);
	    l = l->next;
	}
	if (freecount) {
	    fprintf(stderr, "Memory tracking done with %lu items\n", freecount);
	    assert(!memtracking_abort_on_lost);
	}
    }
#endif
#ifdef OUT_OF_MEMORY_TEST
    if (oom_ready) {
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
	    rv = 2;
	if (rv == 0 && !triggered)
	    rv = 0;
	if (rv == 1 && triggered)
	    rv = 1;
	if (rv == 1 && !triggered)
	    rv = 3;
    }
#endif
    exit(rv);
}
