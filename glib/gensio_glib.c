/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_list.h>
#include <gensio/gensio_glib.h>
#include <gensio/gensio_err.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_osops_addrinfo.h>
#include <gensio/gensio_osops_stdsock.h>

#include <glib.h>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

struct gensio_data
{
    gint      priority;

    GMutex lock;
    GCond cond; /* Global waiting threads. */
    struct gensio_list waiting_threads;
    struct gensio_wait_thread *main_context_owner;
};

static void *
gensio_glib_zalloc(struct gensio_os_funcs *f, unsigned int size)
{
    return g_malloc0(size);
}

static void
gensio_glib_free(struct gensio_os_funcs *f, void *data)
{
    g_free(data);
}

struct gensio_lock {
    struct gensio_os_funcs *f;
    GMutex mutex;
};

static struct gensio_lock *
gensio_glib_alloc_lock(struct gensio_os_funcs *f)
{
    struct gensio_lock *lock;

    lock = gensio_glib_zalloc(f, sizeof(*lock));
    if (!lock)
	return NULL;
    lock->f = f;
    g_mutex_init(&lock->mutex);

    return lock;
}

static void
gensio_glib_free_lock(struct gensio_lock *lock)
{
    g_mutex_clear(&lock->mutex);
    gensio_glib_free(lock->f, lock);
}

static void
gensio_glib_lock(struct gensio_lock *lock)
{
    g_mutex_lock(&lock->mutex);
}

static void
gensio_glib_unlock(struct gensio_lock *lock)
{
    g_mutex_unlock(&lock->mutex);
}

struct gensio_iod_glib {
    struct gensio_iod r;

    GMutex lock;

    GIOChannel *chan;

    guint read_id;
    guint write_id;
    guint except_id;

    guint idle_id;
    bool in_clear;
    unsigned int clear_count;

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

#define i_to_glib(i) gensio_container_of(i, struct gensio_iod_glib, r);

static gboolean
glib_read_handler(GIOChannel *source,
		  GIOCondition condition,
		  gpointer data)
{
    struct gensio_iod_glib *iod = data;

    iod->read_handler(&iod->r, iod->cb_data);
    return G_SOURCE_CONTINUE;
}

static gboolean
glib_write_handler(GIOChannel *source,
		   GIOCondition condition,
		   gpointer data)
{
    struct gensio_iod_glib *iod = data;

    iod->write_handler(&iod->r, iod->cb_data);
    return G_SOURCE_CONTINUE;
}

static gboolean
glib_except_handler(GIOChannel *source,
		    GIOCondition condition,
		    gpointer data)
{
    struct gensio_iod_glib *iod = data;

    iod->except_handler(&iod->r, iod->cb_data);
    return G_SOURCE_CONTINUE;
}

static gboolean
glib_cleared_done(gpointer data)
{
    struct gensio_iod_glib *iod = data;

    g_mutex_lock(&iod->lock);
    iod->handlers_set = false;
    iod->idle_id = 0;
    iod->read_handler = NULL;
    iod->write_handler = NULL;
    iod->except_handler = NULL;
    iod->in_clear = false;
    g_mutex_unlock(&iod->lock);
    if (iod->cleared_handler)
	iod->cleared_handler(&iod->r, iod->cb_data);
    return G_SOURCE_REMOVE;
}

static gint
glib_real_cleared_handler(gpointer data)
{
    struct gensio_iod_glib *iod = data;

    g_mutex_lock(&iod->lock);
    assert(iod->clear_count > 0);
    iod->clear_count--;
    if (iod->clear_count == 0) {
	g_mutex_unlock(&iod->lock);
	glib_cleared_done(iod);
    } else {
	g_mutex_unlock(&iod->lock);
    }
    return G_SOURCE_REMOVE;
}

static void
glib_cleared_handler(gpointer data)
{
    /* This can run from user context, call it from base context. */
    g_idle_add(glib_real_cleared_handler, data);
}

static int
gensio_glib_set_fd_handlers(struct gensio_iod *iiod,
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
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    g_mutex_lock(&iod->lock);
    if (iod->handlers_set) {
	g_mutex_unlock(&iod->lock);
	return GE_INUSE;
    }

    iod->handlers_set = true;
    iod->clear_count = 1;

    iod->cb_data = cb_data;
    iod->read_handler = read_handler;
    iod->write_handler = write_handler;
    iod->except_handler = except_handler;
    iod->cleared_handler = cleared_handler;
    g_mutex_unlock(&iod->lock);

    return 0;
}

static void
gensio_glib_clear_fd_handlers(struct gensio_iod *iiod)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    g_mutex_lock(&iod->lock);
    if (!iod->handlers_set || iod->in_clear)
	goto out_unlock;
    if (iod->read_id) {
	g_source_remove(iod->read_id);
	iod->read_id = 0;
    }
    if (iod->write_id) {
	g_source_remove(iod->write_id);
	iod->write_id = 0;
    }
    if (iod->except_id) {
	g_source_remove(iod->except_id);
	iod->except_id = 0;
    }
    iod->in_clear = true;
    if (iod->clear_count == 1) {
	iod->clear_count = 0;
	iod->idle_id = g_idle_add(glib_cleared_done, iod);
    } else {
	iod->clear_count--;
	/* Done operation will be handled in the cleared handlers. */
    }
 out_unlock:
    g_mutex_unlock(&iod->lock);
}

static void
gensio_glib_clear_fd_handlers_norpt(struct gensio_iod *iiod)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    g_mutex_lock(&iod->lock);
    assert(!iod->read_id && !iod->write_id && !iod->except_id &&
	   !iod->idle_id && iod->clear_count <= 1);
    iod->clear_count = 0;
    iod->handlers_set = false;
    g_mutex_unlock(&iod->lock);
}

static void
gensio_glib_set_read_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    g_mutex_lock(&iod->lock);
    if (iod->read_id && !enable) {
	g_source_remove(iod->read_id);
	iod->read_id = 0;
    } else if (!iod->read_id && enable) {
	iod->read_id = g_io_add_watch_full(iod->chan, 0, G_IO_IN,
					   glib_read_handler, iod,
					   glib_cleared_handler);
	assert(iod->read_id);
	iod->clear_count++;
    }
    g_mutex_unlock(&iod->lock);
}

static void
gensio_glib_set_write_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    g_mutex_lock(&iod->lock);
    if (iod->write_id && !enable) {
	g_source_remove(iod->write_id);
	iod->write_id = 0;
    } else if (!iod->write_id && enable) {
	iod->write_id = g_io_add_watch_full(iod->chan, 0, G_IO_OUT,
					    glib_write_handler, iod,
					    glib_cleared_handler);
	assert(iod->write_id);
	iod->clear_count++;
    }
    g_mutex_unlock(&iod->lock);
}

static void
gensio_glib_set_except_handler(struct gensio_iod *iiod, bool enable)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    g_mutex_lock(&iod->lock);
    if (iod->except_id && !enable) {
	g_source_remove(iod->except_id);
	iod->except_id = 0;
    } else if (!iod->except_id && enable) {
	iod->except_id = g_io_add_watch_full(iod->chan, 0, G_IO_PRI | G_IO_ERR,
					     glib_except_handler, iod,
					     glib_cleared_handler);
	assert(iod->except_id);
	iod->clear_count++;
    }
    g_mutex_unlock(&iod->lock);
}

struct gensio_timer
{
    struct gensio_os_funcs *o;

    void (*handler)(struct gensio_timer *t, void *cb_data);
    void *cb_data;

    GMutex lock;
    guint timer_id;

    void (*done_handler)(struct gensio_timer *t, void *cb_data);
    void *done_cb_data;
};

static gboolean
gensio_glib_timeout_handler(gpointer data)
{
    struct gensio_timer *t = (void *) data;
    void (*handler)(struct gensio_timer *t, void *cb_data) = NULL;
    void *cb_data;

    g_mutex_lock(&t->lock);
    if (t->timer_id) {
	handler = t->handler;
	cb_data = t->cb_data;
	t->timer_id = 0;
    }
    g_mutex_unlock(&t->lock);

    if (handler)
	handler(t, cb_data);

    return G_SOURCE_REMOVE;
}

static void
gensio_glib_timeout_destroyed(gpointer data)
{
    struct gensio_timer *t = (void *) data;
    void (*handler)(struct gensio_timer *t, void *cb_data) = NULL;
    void *cb_data;

    g_mutex_lock(&t->lock);
    handler = t->done_handler;
    cb_data = t->done_cb_data;
    t->done_handler = NULL;
    g_mutex_unlock(&t->lock);

    if (handler)
	handler(t, cb_data);
}

static struct gensio_timer *
gensio_glib_alloc_timer(struct gensio_os_funcs *o,
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
    g_mutex_init(&t->lock);

    return t;
}

static void
gensio_glib_free_timer(struct gensio_timer *t)
{
    g_mutex_clear(&t->lock);
    t->o->free(t->o, t);
}

/*
 * Various time conversion routines.  Note that we always truncate up
 * to the next time unit.  These are used for timers, and if you don't
 * you can end up with an early timeout.
 */
static guint
gensio_time_to_ms(gensio_time *t)
{
    return t->secs * 1000 + (t->nsecs + 999999) / 1000000;
}

static guint
gensio_time_to_us(gensio_time *t)
{
    return t->secs * 1000000 + (t->nsecs + 999) / 1000;
}

static guint
us_time_to_ms(gint64 t)
{
    return (t + 999) / 1000;
}

static void
us_time_to_gensio(gint64 t, gensio_time *gt)
{
    gt->secs = t / 1000000;
    gt->nsecs = t % 1000000 * 1000;
}

static int
gensio_glib_start_timer(struct gensio_timer *t, gensio_time *timeout)
{
    guint msec = gensio_time_to_ms(timeout);
    int rv = 0;

    g_mutex_lock(&t->lock);
    if (t->timer_id) {
	rv = GE_INUSE;
    } else {
	t->timer_id = g_timeout_add_full(0, msec, gensio_glib_timeout_handler,
					 t, gensio_glib_timeout_destroyed);
	if (!t->timer_id)
	    rv = GE_NOMEM;
    }
    g_mutex_unlock(&t->lock);
    return rv;
}

static int
gensio_glib_start_timer_abs(struct gensio_timer *t, gensio_time *timeout)
{
    gint64 now, msec;
    int rv = 0;

    g_mutex_lock(&t->lock);
    if (t->timer_id) {
	rv = GE_INUSE;
    } else {
	msec = gensio_time_to_ms(timeout);
	now = g_get_monotonic_time();
	msec -= now;
	if (msec < 0)
	    msec = 0;

	t->timer_id = g_timeout_add_full(0, msec, gensio_glib_timeout_handler,
					 t, gensio_glib_timeout_destroyed);
	if (!t->timer_id)
	    rv = GE_NOMEM;
    }
    g_mutex_unlock(&t->lock);
    return rv;
}

static int
gensio_glib_stop_timer(struct gensio_timer *t)
{
    int rv = 0;

    g_mutex_lock(&t->lock);
    if (!t->timer_id) {
	rv = GE_TIMEDOUT;
    } else {
	g_source_remove(t->timer_id);
	t->timer_id = 0;
    }
    g_mutex_unlock(&t->lock);
    return rv;
}

static int
gensio_glib_stop_timer_with_done(struct gensio_timer *t,
				 void (*done_handler)(struct gensio_timer *t,
						      void *cb_data),
				 void *cb_data)
{
    int rv = 0;

    g_mutex_lock(&t->lock);
    if (!t->timer_id) {
	rv = GE_TIMEDOUT;
    } else if (t->done_handler) {
	rv = GE_INUSE;
    } else {
	t->done_handler = done_handler;
	t->done_cb_data = cb_data;
	g_source_remove(t->timer_id);
	t->timer_id = 0;
    }
    g_mutex_unlock(&t->lock);
    return rv;
}

struct gensio_runner
{
    struct gensio_os_funcs *o;

    void (*handler)(struct gensio_runner *r, void *cb_data);
    void *cb_data;

    GMutex lock;
    guint idle_id;
};

static gboolean
gensio_glib_idle_handler(gpointer data)
{
    struct gensio_runner *r = (void *) data;
    void (*handler)(struct gensio_runner *r, void *cb_data) = NULL;
    void *cb_data;

    g_mutex_lock(&r->lock);
    handler = r->handler;
    cb_data = r->cb_data;
    r->idle_id = 0;
    g_mutex_unlock(&r->lock);

    if (handler)
	handler(r, cb_data);

    return G_SOURCE_REMOVE;
}

static struct gensio_runner *
gensio_glib_alloc_runner(struct gensio_os_funcs *o,
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
    g_mutex_init(&r->lock);

    return r;
}

static void
gensio_glib_free_runner(struct gensio_runner *r)
{
    g_mutex_clear(&r->lock);
    r->o->free(r->o, r);
}

static int
gensio_glib_run(struct gensio_runner *r)
{
    int rv = 0;

    g_mutex_lock(&r->lock);
    if (r->idle_id) {
	rv = GE_INUSE;
    } else {
	r->idle_id = g_idle_add(gensio_glib_idle_handler, r);
	if (!r->idle_id)
	    rv = GE_NOMEM;
    }
    g_mutex_unlock(&r->lock);
    return rv;
}

struct gensio_waiter
{
    struct gensio_os_funcs *o;

    GCond cond;

    unsigned int count;

    struct gensio_list waiting_threads;
};

struct gensio_wait_thread
{
    GCond *cond;

    unsigned int count;

    /* Link for a specific waiter. */
    struct gensio_link wait_link;

    /* Link for all threads waiting in the os handler. */
    struct gensio_link global_link;
};

static struct gensio_waiter *
gensio_glib_alloc_waiter(struct gensio_os_funcs *o)
{
    struct gensio_waiter *w;

    w = o->zalloc(o, sizeof(*w));
    if (!w)
	return NULL;

    w->o = o;
    g_cond_init(&w->cond);
    gensio_list_init(&w->waiting_threads);

    return w;
}

static void
gensio_glib_free_waiter(struct gensio_waiter *w)
{
    assert(gensio_list_empty(&w->waiting_threads));
    g_cond_clear(&w->cond);
    w->o->free(w->o, w);
}

static gboolean
dummy_timeout_handler(gpointer data)
{
    /* Will be removed in the main loop, avoid races with remove. */
    return G_SOURCE_CONTINUE;
}

#define gensio_glib_wake_next_thread(list, link) do {			\
    if (!gensio_list_empty(list)) {					\
	struct gensio_link *l = gensio_list_first(list);		\
	struct gensio_wait_thread *ot;					\
	ot = gensio_container_of(l, struct gensio_wait_thread, link);	\
	g_cond_signal(ot->cond);					\
    }									\
} while(0)

static void
i_gensio_glib_wake(struct gensio_waiter *w, unsigned int count)
{
    struct gensio_link *l;

    gensio_list_for_each(&w->waiting_threads, l) {
	struct gensio_wait_thread *ot;

	ot = gensio_container_of(l, struct gensio_wait_thread, wait_link);
	if (ot->count) {
	    if (ot->count >= count) {
		ot->count -= count;
		count = 0;
	    } else {
		count -= ot->count;
		ot->count = 0;
	    }
	    if (ot->count == 0) {
		if (ot->cond) {
		    g_cond_signal(ot->cond);
		} else {
		    g_main_context_wakeup(NULL);
		}
	    }
	}
	if (count == 0)
	    break;
    }
}

struct timeout_info {
    gensio_time *timeout;
    gint64 start;
    gint64 now;
    gint64 end;
};

static void
setup_timeout(struct timeout_info *t)
{
    if (t->timeout) {
	t->start = t->now = g_get_monotonic_time();
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

static void
timeout_wait(struct timeout_info *t)
{
    if (t->timeout) {
	guint timerid;

	timerid = g_timeout_add(us_time_to_ms(t->end - t->now),
				dummy_timeout_handler, NULL);
	g_main_context_iteration(NULL, TRUE);
	g_source_remove(timerid);
    } else {
	g_main_context_iteration(NULL, TRUE);
    }
}

static void
timeout_end(struct timeout_info *t)
{
    if (t->timeout) {
	gint64 diff = t->end - t->now;

	if (diff > 0) {
	    us_time_to_gensio(diff, t->timeout);
	} else {
	    t->timeout->secs = 0;
	    t->timeout->nsecs = 0;
	}
    }
}

static int
gensio_glib_wait(struct gensio_waiter *w, unsigned int count,
		 gensio_time *timeout)
{
    struct gensio_data *d = w->o->user_data;
    struct gensio_wait_thread t;
    struct timeout_info ti = { .timeout = timeout };
    int rv = 0;

    gensio_list_link_init(&t.wait_link);
    gensio_list_link_init(&t.global_link);
    t.count = count;
    setup_timeout(&ti);

    g_mutex_lock(&d->lock);
    if (w->count > 0) {
	if (w->count >= t.count) {
	    w->count -= t.count;
	    t.count = 0;
	} else {
	    t.count -= w->count;
	    w->count = 0;
	}
    }
    gensio_list_add_tail(&w->waiting_threads, &t.wait_link);
    gensio_list_add_tail(&d->waiting_threads, &t.global_link);
    while (t.count > 0 && !timed_out(&ti)) {
	if (!d->main_context_owner)
	    d->main_context_owner = &t;
	if (d->main_context_owner == &t) {
	    /* This is the thread that will run the main context. */
	    t.cond = NULL;
	    g_mutex_unlock(&d->lock);
	    timeout_wait(&ti);
	    g_mutex_lock(&d->lock);
	} else {
	    /* Not running the main context, just wait on a cond. */
	    t.cond = &w->cond;
	    if (timeout)
		g_cond_wait_until(t.cond, &d->lock, ti.end);
	    else
		g_cond_wait(t.cond, &d->lock);
	}
	ti.now = g_get_monotonic_time();
    }
    gensio_list_rm(&w->waiting_threads, &t.wait_link);
    gensio_list_rm(&d->waiting_threads, &t.global_link);
    if (d->main_context_owner == &t) {
	d->main_context_owner = NULL;
	/* Need to get another main context owner. */
	gensio_glib_wake_next_thread(&d->waiting_threads, global_link);
    }
    if (t.count > 0) {
	rv = GE_TIMEDOUT;
	/* Re-add whatever was decremented to the waiter. */
	i_gensio_glib_wake(w, count - t.count);
    }
    g_mutex_unlock(&d->lock);

    timeout_end(&ti);

    return rv;
}

static int
gensio_glib_wait_intr(struct gensio_waiter *w, unsigned int count,
		      gensio_time *timeout)
{
    return gensio_glib_wait(w, count, timeout);
}

static int
gensio_glib_wait_intr_sigmask(struct gensio_waiter *w, unsigned int count,
			      gensio_time *timeout, void *sigmask)
{
    return gensio_glib_wait(w, count, timeout);
}

static void
gensio_glib_wake(struct gensio_waiter *w)
{
    struct gensio_data *d = w->o->user_data;

    g_mutex_lock(&d->lock);
    i_gensio_glib_wake(w, 1);
    g_mutex_unlock(&d->lock);
}

static int
gensio_glib_add_iod(struct gensio_os_funcs *o, enum gensio_iod_type type,
		    intptr_t fd, struct gensio_iod **riod)
{
    struct gensio_iod_glib *iod;

    iod = o->zalloc(o, sizeof(*iod));
    if (!iod)
	return GE_NOMEM;

    iod->r.f = o;
    iod->fd = fd;
    iod->type = type;

    iod->chan = g_io_channel_unix_new(iod->fd);
    if (!iod->chan) {
	o->free(o, iod);
	return GE_NOMEM;
    }
    g_io_channel_set_encoding(iod->chan, NULL, NULL);

    g_mutex_init(&iod->lock);
    *riod = &iod->r;

    return 0;
}

static void
gensio_glib_release_iod(struct gensio_iod *iiod)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    assert(!iod->handlers_set);
    g_mutex_clear(&iod->lock);
    iiod->f->free(iiod->f, iod);
}

static int
gensio_glib_iod_get_type(struct gensio_iod *iiod)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    return iod->type;
}

static int
gensio_glib_iod_get_fd(struct gensio_iod *iiod)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    return iod->fd;
}

static int
gensio_glib_iod_get_protocol(struct gensio_iod *iiod)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    return iod->protocol;
}

static void
gensio_glib_iod_set_protocol(struct gensio_iod *iiod, int protocol)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    iod->protocol = protocol;
}

static int
gensio_glib_iod_control(struct gensio_iod *iiod, int op, bool get, intptr_t val)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    if (iod->type != GENSIO_IOD_DEV)
	return GE_NOTSUP;

    return gensio_unix_termios_control(iiod->f, op, get, val, &iod->termios,
				       iod->fd);
}

static int
gensio_glib_set_non_blocking(struct gensio_iod *iiod)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    return gensio_unix_do_nonblock(iiod->f, iod->fd, &iod->mode);
}

static int
gensio_glib_close(struct gensio_iod **iodp)
{
    struct gensio_iod *iiod = *iodp;
    struct gensio_iod_glib *iod = i_to_glib(iiod);
    struct gensio_os_funcs *o = iiod->f;
    int err = 0;

    assert(iodp);
    assert(!iod->handlers_set);
    gensio_unix_cleanup_termios(o, &iod->termios, iod->fd);
    gensio_unix_do_cleanup_nonblock(o, iod->fd, &iod->mode);

    if (iod->type == GENSIO_IOD_SOCKET) {
	err = o->close_socket(iiod);
    } else if (iod->type != GENSIO_IOD_STDIO) {
	err = close(iod->fd);
#ifdef ENABLE_INTERNAL_TRACE
	/* Close should never fail, but don't crash in production builds. */
	if (err) {
	    err = errno;
	    assert(0);
	}
#endif
	if (err == -1)
	    err = gensio_os_err_to_err(o, errno);
    }
    o->release_iod(iiod);
    *iodp = NULL;

    return err;
}

static int
glib_err_to_err(struct gensio_os_funcs *o, GError *ierr)
{
    int err;

    if (!ierr || ierr->code == 0)
	return 0;

    switch (ierr->code) {
    case G_IO_CHANNEL_ERROR_FBIG:	err = GE_TOOBIG; break;
    case G_IO_CHANNEL_ERROR_INVAL:	err = GE_INVAL; break;
    case G_IO_CHANNEL_ERROR_IO:		err = GE_IOERR; break;
    case G_IO_CHANNEL_ERROR_NOSPC:	err = GE_NOMEM; break;
    case G_IO_CHANNEL_ERROR_NXIO:	err = GE_NOTFOUND; break;
    case G_IO_CHANNEL_ERROR_PIPE:	err = GE_REMCLOSE; break;

    case G_IO_CHANNEL_ERROR_ISDIR:
    case G_IO_CHANNEL_ERROR_OVERFLOW:
    case G_IO_CHANNEL_ERROR_FAILED:
    default:
	err = GE_OSERR;
    }

    if (err == GE_OSERR) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled glib error: %s (%d)", ierr->message, ierr->code);
    }

    return err;
}

static int
gensio_glib_write(struct gensio_iod *iiod, const struct gensio_sg *sg,
		  gensiods sglen, gensiods *rcount)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);
    gensiods i;
    gensiods count = 0;
    GIOStatus st;
    GError *err = NULL;
    gsize size;
    int rv = 0;

    for (i = 0; i < sglen; i++) {
	st = g_io_channel_write_chars(iod->chan, sg[i].buf, sg[i].buflen,
				      &size, &err);
	switch (st) {
	case G_IO_STATUS_NORMAL:
	    count += size;
	    break;

	case G_IO_STATUS_EOF:
	    rv = GE_REMCLOSE;
	    goto out;

	case G_IO_STATUS_ERROR:
	    rv = glib_err_to_err(iiod->f, err);
	    goto out;

	case G_IO_STATUS_AGAIN:
	    rv = 0;
	    goto out;

	default:
	    assert(0);
	}
    }
 out:
    if (count > 0) {
	g_io_channel_flush(iod->chan, NULL);
	rv = 0;
    }
    if (!rv)
	*rcount = count;

    return rv;
}

static int
gensio_glib_read(struct gensio_iod *iiod, void *buf, gensiods buflen,
		 gensiods *rcount)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);
    gensiods count = 0;
    GIOStatus st;
    GError *err = NULL;
    gsize size;
    int rv = 0;

    st = g_io_channel_read_chars(iod->chan, buf, buflen, &size, &err);
    switch (st) {
    case G_IO_STATUS_NORMAL:
	count = size;
	break;

    case G_IO_STATUS_EOF:
	rv = GE_REMCLOSE;
	goto out;

    case G_IO_STATUS_ERROR:
	rv = glib_err_to_err(iiod->f, err);
	goto out;

    case G_IO_STATUS_AGAIN:
	rv = 0;
	goto out;

    default:
	assert(0);
    }
 out:
    if (!rv)
	*rcount = count;

    return rv;
}

static bool
gensio_glib_is_regfile(struct gensio_os_funcs *o, intptr_t fd)
{
    int err;
    struct stat statb;

    err = fstat(fd, &statb);
    if (err == -1)
	return false;

    return (statb.st_mode & S_IFMT) == S_IFREG;
}

static int
gensio_glib_bufcount(struct gensio_iod *iiod, int whichbuf, gensiods *count)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    return gensio_unix_get_bufcount(iiod->f, iod->fd, whichbuf, count);
}

static void
gensio_glib_flush(struct gensio_iod *iiod, int whichbuf)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);
    GError *err;

    g_io_channel_flush(iod->chan, &err);
}

static int
gensio_glib_makeraw(struct gensio_iod *iiod)
{
    struct gensio_iod_glib *iod = i_to_glib(iiod);

    if (iod->fd == 1 || iod->fd == 2)
	/* Only set this for stdin or other files. */
	return 0;

    return gensio_unix_setup_termios(iiod->f, iod->fd, &iod->termios);
}

static int
gensio_glib_open_dev(struct gensio_os_funcs *o, const char *name, int options,
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

    fd = open(name, flags);
    if (fd == -1)
	return gensio_os_err_to_err(o, errno);
    err = o->add_iod(o, GENSIO_IOD_DEV, fd, riod);
    if (err)
	close(fd);
    return err;
}

static int
gensio_glib_exec_subprog(struct gensio_os_funcs *o,
			const char *argv[], const char **env,
			bool stderr_to_stdout,
			intptr_t *rpid,
			struct gensio_iod **rstdin,
			struct gensio_iod **rstdout,
			struct gensio_iod **rstderr)
{
    int err;
    int infd = -1, outfd = -1, errfd = -1;
    struct gensio_iod *stdiniod = NULL, *stdoutiod = NULL, *stderriod = NULL;
    int pid = -1;

    err = gensio_unix_do_exec(o, argv, env, stderr_to_stdout, &pid, &infd,
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
gensio_glib_kill_subprog(struct gensio_os_funcs *o, intptr_t pid, bool force)
{
    int rv;

    rv = kill(pid, force ? SIGKILL : SIGTERM);
    if (rv < 0)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

static int
gensio_glib_wait_subprog(struct gensio_os_funcs *o, intptr_t pid, int *retcode)
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
gensio_glib_service(struct gensio_os_funcs *o, gensio_time *timeout)
{
    struct gensio_data *d = o->user_data;
    struct gensio_wait_thread t;
    struct timeout_info ti = { .timeout = timeout };
    int rv = 0;

    gensio_list_link_init(&t.global_link);
    t.count = 0;
    setup_timeout(&ti);

    g_mutex_lock(&d->lock);
    gensio_list_add_tail(&d->waiting_threads, &t.global_link);
    while (!timed_out(&ti)) {
	if (!d->main_context_owner)
	    d->main_context_owner = &t;
	if (d->main_context_owner == &t) {
	    /* This is the thread that will run the main context. */
	    t.cond = NULL;
	    g_mutex_unlock(&d->lock);
	    timeout_wait(&ti);
	    g_mutex_lock(&d->lock);
	} else {
	    /* Not running the main context, just wait on a cond. */
	    t.cond = &d->cond;
	    if (timeout)
		g_cond_wait_until(t.cond, &d->lock, ti.end);
	    else
		g_cond_wait(t.cond, &d->lock);
	}
	ti.now = g_get_monotonic_time();
    }
    gensio_list_rm(&d->waiting_threads, &t.global_link);
    if (d->main_context_owner == &t) {
	d->main_context_owner = NULL;
	/* Need to get another main context owner. */
	gensio_glib_wake_next_thread(&d->waiting_threads, global_link);
    }
    g_mutex_unlock(&d->lock);

    timeout_end(&ti);
    if (timeout->secs == 0 && timeout->nsecs == 0)
	rv = GE_TIMEDOUT;

    return rv;
}

static void
gensio_glib_free_funcs(struct gensio_os_funcs *f)
{
    struct gensio_data *d = f->user_data;

    g_cond_clear(&d->cond);
    g_mutex_clear(&d->lock);
    free(d);
    free(f);
}

GMutex once_lock;

static void
gensio_glib_call_once(struct gensio_os_funcs *f, struct gensio_once *once,
		      void (*func)(void *cb_data), void *cb_data)
{
    if (once->called)
	return;
    g_mutex_lock(&once_lock);
    if (!once->called) {
	once->called = true;
	func(cb_data);
    }
    g_mutex_unlock(&once_lock);
}

static void
gensio_glib_get_monotonic_time(struct gensio_os_funcs *f, gensio_time *time)
{
    us_time_to_gensio(g_get_monotonic_time(), time);
}

static int
gensio_glib_handle_fork(struct gensio_os_funcs *f)
{
    return 0;
}

static int
gensio_glib_get_random(struct gensio_os_funcs *o, void *data, unsigned int len)
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

int
gensio_glib_funcs_alloc(struct gensio_os_funcs **ro)
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

    o->user_data = d;
    gensio_list_init(&d->waiting_threads);
    g_mutex_init(&d->lock);
    g_cond_init(&d->cond);

    o->zalloc = gensio_glib_zalloc;
    o->free = gensio_glib_free;
    o->alloc_lock = gensio_glib_alloc_lock;
    o->free_lock = gensio_glib_free_lock;
    o->lock = gensio_glib_lock;
    o->unlock = gensio_glib_unlock;
    o->set_fd_handlers = gensio_glib_set_fd_handlers;
    o->clear_fd_handlers = gensio_glib_clear_fd_handlers;
    o->clear_fd_handlers_norpt = gensio_glib_clear_fd_handlers_norpt;
    o->set_read_handler = gensio_glib_set_read_handler;
    o->set_write_handler = gensio_glib_set_write_handler;
    o->set_except_handler = gensio_glib_set_except_handler;
    o->alloc_timer = gensio_glib_alloc_timer;
    o->free_timer = gensio_glib_free_timer;
    o->start_timer = gensio_glib_start_timer;
    o->start_timer_abs = gensio_glib_start_timer_abs;
    o->stop_timer = gensio_glib_stop_timer;
    o->stop_timer_with_done = gensio_glib_stop_timer_with_done;
    o->alloc_runner = gensio_glib_alloc_runner;
    o->free_runner = gensio_glib_free_runner;
    o->run = gensio_glib_run;
    o->alloc_waiter = gensio_glib_alloc_waiter;
    o->free_waiter = gensio_glib_free_waiter;
    o->wait = gensio_glib_wait;
    o->wait_intr = gensio_glib_wait_intr;
    o->wait_intr_sigmask = gensio_glib_wait_intr_sigmask;
    o->wake = gensio_glib_wake;
    o->service = gensio_glib_service;
    o->free_funcs = gensio_glib_free_funcs;
    o->call_once = gensio_glib_call_once;
    o->get_monotonic_time = gensio_glib_get_monotonic_time;
    o->handle_fork = gensio_glib_handle_fork;
    o->add_iod = gensio_glib_add_iod;
    o->release_iod = gensio_glib_release_iod;
    o->iod_get_type = gensio_glib_iod_get_type;
    o->iod_get_fd = gensio_glib_iod_get_fd;
    o->iod_get_protocol = gensio_glib_iod_get_protocol;
    o->iod_set_protocol = gensio_glib_iod_set_protocol;

    o->set_non_blocking = gensio_glib_set_non_blocking;
    o->close = gensio_glib_close;
    o->write = gensio_glib_write;
    o->read = gensio_glib_read;
    o->is_regfile = gensio_glib_is_regfile;
    o->bufcount = gensio_glib_bufcount;
    o->flush = gensio_glib_flush;
    o->makeraw = gensio_glib_makeraw;
    o->open_dev = gensio_glib_open_dev;
    o->exec_subprog = gensio_glib_exec_subprog;
    o->kill_subprog = gensio_glib_kill_subprog;
    o->wait_subprog = gensio_glib_wait_subprog;
    o->get_random = gensio_glib_get_random;
    o->iod_control = gensio_glib_iod_control;

    gensio_addr_addrinfo_set_os_funcs(o);
    gensio_stdsock_set_os_funcs(o);

    *ro = o;
    return 0;
}
