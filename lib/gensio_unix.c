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
#include "errtrig.h"

struct gensio_data {
    struct selector_s *sel;
    bool freesel;
    int wake_sig;
};

#ifdef ENABLE_INTERNAL_TRACE
#define TRACK_ALLOCED_MEMORY
#endif

#ifdef TRACK_ALLOCED_MEMORY
lock_type memtrk_mutex = LOCK_INITIALIZER;
struct memory_link {
    struct memory_link *next;
    struct memory_link *prev;
};
struct memory_header {
    struct memory_link link;
    unsigned long long magic;
    void *callers[4];
    void *freers[4];
    unsigned int size;
    bool inuse;
};
#define MEMORY_MAGIC 0x547a075c3733e437ULL
struct memory_link memhead = { &memhead, &memhead };
struct memory_link memfree = { &memfree, &memfree };
unsigned long freecount;
bool memtracking_initialized;
bool memtracking_ready;
bool memtracking_abort_on_lost;
#endif

static void *
gensio_unix_zalloc(struct gensio_os_funcs *f, unsigned int size)
{
    void *d;

    if (do_errtrig())
	return NULL;
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
	d = malloc(size + sizeof(struct memory_header) + 1024);
	if (d) {
	    struct memory_header *h = d;

	    d = ((char *) d) + sizeof(struct memory_header);
	    h->magic = MEMORY_MAGIC;
	    memset(h->callers, 0, sizeof(void *) * 4);
	    h->callers[0] = __builtin_return_address(0);
#if 0
	    h->callers[1] = __builtin_return_address(1);
	    h->callers[2] = __builtin_return_address(2);
	    h->callers[3] = __builtin_return_address(3);
#endif
	    memset(h->freers, 0, sizeof(void *) * 4);
	    h->inuse = true;
	    h->size = size;
	    memset(((unsigned char *) d) + size, 0xaf, 1024);
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
gensio_unix_free(struct gensio_os_funcs *f, void *data)
{
    assert(data);
#ifdef TRACK_ALLOCED_MEMORY
    if (memtracking_ready) {
	struct memory_header *h = ((struct memory_header *)
				   (((char *) data) - sizeof(*h)));
	unsigned int i;
	unsigned char *c;

	h->freers[0] = __builtin_return_address(0);
#if 0
	h->freers[1] = __builtin_return_address(1);
	h->freers[2] = __builtin_return_address(2);
	h->freers[3] = __builtin_return_address(3);
#endif
	if (h->magic != MEMORY_MAGIC) {
	    fprintf(stderr, "Free of unallocated data at %p.\n", data);
	    fprintf(stderr, "  allocated at %p %p %p %p.\n",
		    h->callers[0], h->callers[1],
		    h->callers[2], h->callers[3]);
	    fprintf(stderr, "  freed at %p %p %p %p.\n",
		    h->freers[0], h->freers[1],
		    h->freers[2], h->freers[3]);
	    fflush(stderr);
	    *((volatile char *) 0) = 1;
	    assert(h->inuse);
	    return;
	}
	if (!h->inuse) {
	    fprintf(stderr, "Free of already freed data at %p.\n", data);
	    fprintf(stderr, "  allocated at %p %p %p %p.\n",
		    h->callers[0], h->callers[1],
		    h->callers[2], h->callers[3]);
	    fprintf(stderr, "  freed at %p %p %p %p.\n",
		    h->freers[0], h->freers[1],
		    h->freers[2], h->freers[3]);
	    fflush(stderr);
	    *((volatile char *) 0) = 1;
	    assert(h->inuse);
	    return;
	}
	for (i = 0, c = ((unsigned char *) data) + h->size;
	     i < 1024; i++, c++) {
	    if (*c != 0xaf) {
		fprintf(stderr, "Memory overrun at %p.\n", data);
		fprintf(stderr, "  allocated at %p %p %p %p.\n",
			h->callers[0], h->callers[1],
			h->callers[2], h->callers[3]);
		fprintf(stderr, "  freed at %p %p %p %p.\n",
			h->freers[0], h->freers[1],
			h->freers[2], h->freers[3]);
		fflush(stderr);
		*((volatile char *) 0) = 1;
		assert(h->inuse);
		return;
	    }
	}
	memset(data, 0xde, h->size);
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
gensio_exit_check_memory(void)
{
#ifdef TRACK_ALLOCED_MEMORY
    struct memory_link *l;
    unsigned char *d, *c;
    unsigned int i;

    l = memfree.next;
    while (l != &memfree) {
	/* link is first element */
	struct memory_header *h = (struct memory_header *) l;

	d = ((unsigned char *) h) + sizeof(*h);

	if (h->magic != MEMORY_MAGIC) {
	    fprintf(stderr, "Unallocated data in free list at %p.\n", d);
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

	for (i = 0, c = d; i < h->size; i++, c++) {
	    if (*c != 0xde) {
		fprintf(stderr, "Use after free at %p.\n", d);
		fprintf(stderr, "  allocated at %p %p %p %p.\n",
			h->callers[0], h->callers[1],
			h->callers[2], h->callers[3]);
		fprintf(stderr, "  freed at %p %p %p %p.\n",
			h->freers[0], h->freers[1],
			h->freers[2], h->freers[3]);
		fflush(stderr);
		*((volatile char *) 0) = 1;
		assert(h->inuse);
		return;
	    }
	}

	for (i = 0, c = d + h->size; i < 1024; i++, c++) {
	    if (*c != 0xaf) {
		fprintf(stderr, "Memory overrun after free at %p.\n", d);
		fprintf(stderr, "  allocated at %p %p %p %p.\n",
			h->callers[0], h->callers[1],
			h->callers[2], h->callers[3]);
		fprintf(stderr, "  freed at %p %p %p %p.\n",
			h->freers[0], h->freers[1],
			h->freers[2], h->freers[3]);
		fflush(stderr);
		*((volatile char *) 0) = 1;
		assert(h->inuse);
		return;
	    }
	}

	l = l->next;
    }

    l = memhead.next;
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
	fflush(stderr);
	assert(!memtracking_abort_on_lost);
    }
#endif
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
	    if (w->count == 0)
		pthread_kill(w->tid, w->wake_sig);
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
    if (w.count == 0) {
	err = 0; /* If our count was decremented to zero, ignore errors. */
    } else if (err) {
	/*
	 * If there was an error, re-add whatever was decremented to the
	 * waiter.
	 */
	i_wake_waiter(waiter, count - w.count);
    }
    w.next->prev = w.prev;
    w.prev->next = w.next;
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

struct gensio_iod_unix {
    struct gensio_iod r;
    int fd;
    enum gensio_iod_type type;
    int protocol; /* GENSIO_NET_PROTOCOL_xxx */
    bool handlers_set;
    void *cb_data;
    void (*read_handler)(struct gensio_iod *iod, void *cb_data);
    void (*write_handler)(struct gensio_iod *iod, void *cb_data);
    void (*except_handler)(struct gensio_iod *iod, void *cb_data);
    void (*cleared_handler)(struct gensio_iod *iod, void *cb_data);

    struct stdio_mode *mode;

    struct gensio_unix_termios *termios;
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
    int rv;

    if (iod->handlers_set)
	return GE_INUSE;

    iod->cb_data = cb_data;
    iod->read_handler = read_handler;
    iod->write_handler = write_handler;
    iod->except_handler = except_handler;
    iod->cleared_handler = cleared_handler;

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

    if (iod->handlers_set)
	sel_clear_fd_handlers(d->sel, iod->fd);
}

static void
gensio_unix_clear_fd_handlers_norpt(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *f = iiod->f;
    struct gensio_data *d = f->user_data;

    if (iod->handlers_set) {
	iod->handlers_set = false;
	sel_clear_fd_handlers_norpt(d->sel, iod->fd);
    }
}

static void
gensio_unix_set_read_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    struct gensio_os_funcs *f = iiod->f;
    struct gensio_data *d = f->user_data;
    int op;

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

    waiter->sel_waiter = alloc_waiter(d->sel, d->wake_sig);
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
gensio_unix_wait(struct gensio_waiter *waiter, unsigned int count,
		 gensio_time *timeout)
{
    int err;

    err = wait_for_waiter_timeout(waiter->sel_waiter, count, timeout);
    return gensio_os_err_to_err(waiter->f, err);
}


static int
gensio_unix_wait_intr(struct gensio_waiter *waiter, unsigned int count,
		      gensio_time *timeout)
{
    int err;

    err = wait_for_waiter_timeout_intr(waiter->sel_waiter, count, timeout);
    return gensio_os_err_to_err(waiter->f, err);
}

static int
gensio_unix_wait_intr_sigmask(struct gensio_waiter *waiter, unsigned int count,
			      gensio_time *timeout, void *sigmask)
{
    int err;

    err = wait_for_waiter_timeout_intr_sigmask(waiter->sel_waiter, count,
					       timeout, sigmask);
    return gensio_os_err_to_err(waiter->f, err);
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

static void
gensio_unix_free_funcs(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;

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
	UNLOCK(&once_lock);
	func(cb_data);
    } else {
	UNLOCK(&once_lock);
    }
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
		    intptr_t fd, struct gensio_iod **riod)
{
    struct gensio_iod_unix *iod;

    iod = o->zalloc(o, sizeof(*iod));
    if (!iod)
	return GE_NOMEM;
    iod->r.f = o;
    iod->type = type;
    iod->fd = fd;

    *riod = &iod->r;
    return 0;
}

static void
gensio_unix_release_iod(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    assert(!iod->handlers_set);
    iod->r.f->free(iiod->f, iod);
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

static int
gensio_unix_iod_get_protocol(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    return iod->protocol;
}

static void
gensio_unix_iod_set_protocol(struct gensio_iod *iiod, int protocol)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    iod->protocol = protocol;
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
    gensio_unix_cleanup_termios(o, &iod->termios, iod->fd);
    gensio_unix_do_cleanup_nonblock(o, iod->fd, &iod->mode);

    if (iod->type != GENSIO_IOD_STDIO) {
	err = close(iod->fd);
#ifdef ENABLE_INTERNAL_TRACE
	/* Close should never fail, but don't crash in production builds. */
	if (err) {
	    err = errno;
	    assert(0);
	}
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

    return gensio_unix_do_nonblock(iiod->f, iod->fd, &iod->mode);
}

int
gensio_unix_bufcount(struct gensio_iod *iiod, int whichbuf, gensiods *rcount)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    return gensio_unix_get_bufcount(iiod->f, iod->fd, whichbuf, rcount);
}

static bool
gensio_unix_is_regfile(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);
    int err;
    struct stat statb;

    err = fstat(iod->fd, &statb);
    if (err == -1)
	return false;

    return (statb.st_mode & S_IFMT) == S_IFREG;
}

static bool
gensio_unix_is_console(struct gensio_iod *iiod)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    return isatty(iod->fd);
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

    if (iod->fd == 1 || iod->fd == 2)
	/* Only set this for stdin or other files. */
	return 0;

    return gensio_unix_setup_termios(iiod->f, iod->fd, &iod->termios);
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

extern char **environ;

static int
gensio_unix_exec_subprog(struct gensio_os_funcs *o,
			 const char *argv[], const char **env,
			 bool stderr_to_stdout,
			 intptr_t *rpid,
			 struct gensio_iod **rstdin,
			 struct gensio_iod **rstdout,
			 struct gensio_iod **rstderr)
{
    int err;
    int stdinpipe[2] = {-1, -1};
    int stdoutpipe[2] = {-1, -1};
    int stderrpipe[2] = {-1, -1};
    struct gensio_iod *stdiniod = NULL, *stdoutiod = NULL, *stderriod = NULL;
    int pid = -1;

    if (stderr_to_stdout && rstderr)
	return GE_INVAL;

    err = pipe(stdinpipe);
    if (err) {
	err = errno;
	goto out_err;
    }

    err = pipe(stdoutpipe);
    if (err) {
	err = errno;
	goto out_err;
    }

    err = o->add_iod(o, GENSIO_IOD_PIPE, stdinpipe[1], &stdiniod);
    if (err)
	goto out_err_noconv;
    err = o->add_iod(o, GENSIO_IOD_PIPE, stdoutpipe[0], &stdoutiod);
    if (err)
	goto out_err_noconv;
    err = o->set_non_blocking(stdiniod);
    if (err)
	goto out_err_noconv;
    err = o->set_non_blocking(stdoutiod);
    if (err)
	goto out_err_noconv;

    if (rstderr) {
	err = pipe(stderrpipe);
	if (err) {
	    err = errno;
	    goto out_err;
	}
	err = o->add_iod(o, GENSIO_IOD_PIPE, stderrpipe[0], &stderriod);
	if (err)
	    goto out_err_noconv;
	err = o->set_non_blocking(stderriod);
	if (err)
	    goto out_err_noconv;
    }

    pid = fork();
    if (pid < 0) {
	err = errno;
	goto out_err;
    }
    if (pid == 0) {
	int i, openfiles = sysconf(_SC_OPEN_MAX);

	dup2(stdinpipe[0], 0);
	dup2(stdoutpipe[1], 1);
	if (stderr_to_stdout)
	    dup2(stdoutpipe[1], 2);
	else if (rstderr)
	    dup2(stderrpipe[1], 2);

	/* Close everything but stdio. */
	for (i = 3; i < openfiles; i++)
	    close(i);

	err = gensio_os_setupnewprog();
	if (err) {
	    fprintf(stderr, "Unable to set groups or user: %s\r\n",
		    strerror(err));
	    exit(1);
	}

	if (env)
	    environ = (char **) env;

	execvp(argv[0], (char * const *) argv);
	fprintf(stderr, "Err: %s %s\r\n", argv[0], strerror(errno));
	exit(1); /* Only reached on error. */
    }

    close(stdinpipe[0]);
    close(stdoutpipe[1]);
    if (stderriod)
	close(stderrpipe[1]);

    *rpid = pid;
    *rstdin = stdiniod;
    *rstdout = stdoutiod;
    if (rstderr)
	*rstderr = stderriod;
    return 0;

 out_err:
    err = gensio_os_err_to_err(o, err);
 out_err_noconv:
    if (stderriod) {
	o->close(&stderriod);
	stderrpipe[0] = -1;
    }
    if (stdiniod) {
	o->close(&stdiniod);
	stdinpipe[1] = -1;
    }
    if (stdoutiod) {
	o->close(&stdoutiod);
	stdoutpipe[0] = -1;
    }
    if (stdinpipe[0] != -1)
	close(stdinpipe[0]);
    if (stdinpipe[1] != -1)
	close(stdinpipe[1]);
    if (stdoutpipe[0] != -1)
	close(stdoutpipe[0]);
    if (stdoutpipe[1] != -1)
	close(stdoutpipe[1]);
    if (stderrpipe[0] != -1)
	close(stderrpipe[0]);
    if (stderrpipe[1] != -1)
	close(stderrpipe[1]);

    return err;
}

static int
gensio_unix_iod_control(struct gensio_iod *iiod, int op, bool get, intptr_t val)
{
    struct gensio_iod_unix *iod = i_to_sel(iiod);

    if (iod->type != GENSIO_IOD_DEV)
	return GE_NOTSUP;

    return gensio_unix_termios_control(iiod->f, op, get, val, &iod->termios,
				       iod->fd);
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

    o->user_data = d;
    d->sel = sel;
    d->wake_sig = wake_sig;

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
    o->free_funcs = gensio_unix_free_funcs;
    o->call_once = gensio_unix_call_once;
    o->get_monotonic_time = gensio_unix_get_monotonic_time;
    o->handle_fork = gensio_handle_fork;
    o->add_iod = gensio_unix_add_iod;
    o->release_iod = gensio_unix_release_iod;
    o->iod_get_type = gensio_unix_iod_get_type;
    o->iod_get_fd = gensio_unix_iod_get_fd;
    o->iod_get_protocol = gensio_unix_iod_get_protocol;
    o->iod_set_protocol = gensio_unix_iod_set_protocol;

    o->set_non_blocking = gensio_unix_set_non_blocking;
    o->close = gensio_unix_close;
    o->write = gensio_unix_write;
    o->read = gensio_unix_read;
    o->is_regfile = gensio_unix_is_regfile;
    o->is_console = gensio_unix_is_console;
    o->bufcount = gensio_unix_bufcount;
    o->flush = gensio_unix_flush;
    o->makeraw = gensio_unix_makeraw;
    o->open_dev = gensio_unix_open_dev;
    o->exec_subprog = gensio_unix_exec_subprog;
    o->kill_subprog = gensio_unix_kill_subprog;
    o->wait_subprog = gensio_unix_wait_subprog;
    o->get_random = gensio_unix_get_random;
    o->iod_control = gensio_unix_iod_control;

    gensio_addr_addrinfo_set_os_funcs(o);
    gensio_stdsock_set_os_funcs(o);

    return o;
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
gensio_unix_funcs_alloc(struct selector_s *sel, int wake_sig)
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

    o = gensio_unix_alloc_sel(sel, wake_sig);
    if (o) {
	struct gensio_data *d = o->user_data;

	d->freesel = freesel;
    } else if (freesel) {
	sel_free_selector(sel);
    }

    return o;
}

struct gensio_os_funcs *
gensio_selector_alloc(struct selector_s *sel, int wake_sig)
{
    return gensio_unix_funcs_alloc(sel, wake_sig);
}

static void
defoshnd_init(void)
{
    defoshnd = gensio_unix_funcs_alloc(NULL, defoshnd_wake_sig);
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
gensio_osfunc_exit(int rv)
{
    gensio_exit_check_memory();
    errtrig_exit(rv);
}
