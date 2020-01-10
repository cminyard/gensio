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
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include <gensio/gensio_class.h>
#include <gensio/gensio_base.h>

#ifdef DEBUG_DATA
#define ENABLE_PRBUF 1
#include <utils/utils.h>
#endif

enum basen_state { BASEN_CLOSED,
		   BASEN_IN_LL_OPEN,
		   BASEN_IN_FILTER_OPEN,
		   BASEN_OPEN,
		   BASEN_CLOSE_WAIT_DRAIN,
		   BASEN_IN_FILTER_CLOSE,
		   BASEN_IN_LL_CLOSE };

#ifdef DEBUG_STATE
static char *basen_statestr[] = {
    "CLOSED",
    "IN_LL_OPEN",
    "IN_FILTER_OPEN",
    "OPEN",
    "CLOSE_WAIT_DRAIN",
    "IN_FILTER_CLOSE",
    "IN_LL_CLOSE"
};
#endif

struct basen_data {
    struct gensio *io;
    struct gensio *child;

    struct gensio_os_funcs *o;
    struct gensio_filter *filter;
    struct gensio_ll *ll;

    struct gensio_lock *lock;
    struct gensio_timer *timer;
    bool timer_start_pending;
    struct timeval pending_timer;

    unsigned int refcount;

    unsigned int freeref;

    enum basen_state state;

    gensio_done_err open_done;
    void *open_data;

    gensio_done close_done;
    void *close_data;

    bool read_enabled;
    bool in_read;

    bool xmit_enabled;
    bool tmp_xmit_enabled; /* Make sure the xmit code get called once. */
    bool in_xmit_ready;
    bool redo_xmit_ready;

    int saved_xmit_err;

    /*
     * We got an error from the lower layer, it's probably not working
     * any more.
     */
    bool ll_err_occurred;
    int ll_err;

    /*
     * Used to run user callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

    bool deferred_read;
    bool deferred_open;
    bool deferred_close;

    struct stel_req *reqs;
};

struct gensio_ll {
    struct gensio_os_funcs *o;
    struct basen_data  *ndata;
    gensio_ll_func func;
    void *user_data;
};

struct gensio_filter {
    struct gensio_os_funcs *o;
    struct basen_data  *ndata;
    gensio_filter_func func;
    void *user_data;
};

static void
basen_lock(struct basen_data *ndata)
{
    ndata->o->lock(ndata->lock);
}

static void
basen_unlock(struct basen_data *ndata)
{
    ndata->o->unlock(ndata->lock);
}

static void
basen_finish_free(struct basen_data *ndata)
{
    if (ndata->lock)
	ndata->o->free_lock(ndata->lock);
    if (ndata->timer)
	ndata->o->free_timer(ndata->timer);
    if (ndata->deferred_op_runner)
	ndata->o->free_runner(ndata->deferred_op_runner);
    if (ndata->filter)
	gensio_filter_free(ndata->filter);
    if (ndata->ll)
	gensio_ll_free(ndata->ll);
    if (ndata->io)
	gensio_data_free(ndata->io);
    ndata->o->free(ndata->o, ndata);
}

static void
basen_timer_stopped(struct gensio_timer *t, void *cb_data)
{
    struct basen_data *ndata = cb_data;

    basen_finish_free(ndata);
}

static void
basen_ref(struct basen_data *ndata)
{
    ndata->refcount++;
}

static void
basen_lock_and_ref(struct basen_data *ndata)
{
    basen_lock(ndata);
    basen_ref(ndata);
}

/*
 * This can *only* be called if the refcount is guaranteed not to reach
 * zero.
 */
static void
basen_deref(struct basen_data *ndata)
{
    assert(ndata->refcount > 1);
    ndata->refcount--;
}

static void
basen_deref_and_unlock(struct basen_data *ndata)
{
    unsigned int count;

    assert(ndata->refcount > 0);
    count = --ndata->refcount;
    basen_unlock(ndata);
    if (count == 0) {
	if (ndata->timer) {
	    int err = ndata->o->stop_timer_with_done(ndata->timer,
						     basen_timer_stopped,
						     ndata);

	    if (err != GE_TIMEDOUT)
		return;
	}
	basen_finish_free(ndata);
    }
}

#ifdef DEBUG_STATE
static void
i_basen_set_state(struct basen_data *ndata, enum basen_state state, int line)
{
    printf("Setting state for %s(%s) to %s at line %d\r\n",
	   gensio_get_type(ndata->io, 0),
	   gensio_is_client(ndata->io) ? "client" : "server",
	   basen_statestr[state], line);
    ndata->state = state;
}

#define basen_set_state(ndata, state) \
    i_basen_set_state(ndata, state, __LINE__)
#else
static void
basen_set_state(struct basen_data *ndata, enum basen_state state)
{
    ndata->state = state;
}
#endif

static bool
filter_ul_read_pending(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_ul_read_pending(ndata->filter);
    return false;
}

static bool
filter_ll_write_pending(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_ll_write_pending(ndata->filter);
    return false;
}

static bool
filter_ll_read_needed(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_ll_read_needed(ndata->filter);
    return false;
}

/* Provides a way to verify keys and such. */
static int
filter_check_open_done(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_check_open_done(ndata->filter, ndata->io);
    return 0;
}

static int
filter_try_connect(struct basen_data *ndata, struct timeval *timeout)
{
    if (ndata->filter)
	return gensio_filter_try_connect(ndata->filter, timeout);
    return 0;
}

static int
filter_try_disconnect(struct basen_data *ndata, struct timeval *timeout)
{
    if (ndata->filter)
	return gensio_filter_try_disconnect(ndata->filter, timeout);
    return 0;
}

static int
filter_ul_write(struct basen_data *ndata, gensio_ul_filter_data_handler handler,
		gensiods *rcount,
		const struct gensio_sg *sg, gensiods sglen,
		const char *const *auxdata)
{
    if (ndata->filter)
	return gensio_filter_ul_write(ndata->filter, handler,
				      ndata, rcount, sg, sglen, auxdata);
    return handler(ndata, rcount, sg, sglen, auxdata);
}	     

static int
filter_ll_write(struct basen_data *ndata, gensio_ll_filter_data_handler handler,
		gensiods *rcount,
		unsigned char *buf, gensiods buflen,
		const char *const *auxdata)
{
    if (ndata->filter)
	return gensio_filter_ll_write(ndata->filter, handler,
				      ndata, rcount, buf, buflen, auxdata);
    return handler(ndata, rcount, buf, buflen, auxdata);
}	     

static int
filter_setup(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_setup(ndata->filter, ndata->io);
    return 0;
}

static void
filter_cleanup(struct basen_data *ndata)
{
    if (ndata->filter)
	gensio_filter_cleanup(ndata->filter);
}


static int
ll_write(struct basen_data *ndata, gensiods *rcount,
	 const struct gensio_sg *sg, gensiods sglen, const char *const *auxdata)
{
#ifdef DEBUG_DATA
    printf("LL write:");
    prbuf(buf, buflen);
#endif
    return gensio_ll_write(ndata->ll, rcount, sg, sglen, auxdata);
}

/*
 * Returns 0 if the open was immediate, GE_INPROGRESS if it was deferred,
 * and an errno otherwise.
 */
static int
ll_open(struct basen_data *ndata, gensio_ll_open_done done, void *open_data)
{
    return gensio_ll_open(ndata->ll, done, open_data);
}

static void basen_sched_deferred_op(struct basen_data *ndata);

static void
ll_close(struct basen_data *ndata, gensio_ll_close_done done, void *close_data)
{
    int err;

    basen_set_state(ndata, BASEN_IN_LL_CLOSE);
    err = gensio_ll_close(ndata->ll, done, close_data);
    if (err != GE_INPROGRESS) {
	ndata->deferred_close = true;
	basen_sched_deferred_op(ndata);
    }
}

static void
ll_set_read_callback_enable(struct basen_data *ndata, bool enable)
{
    gensio_ll_set_read_callback(ndata->ll, enable);
}

static void
ll_set_write_callback_enable(struct basen_data *ndata, bool enable)
{
    gensio_ll_set_write_callback(ndata->ll, enable);
}

static void
basen_set_ll_enables(struct basen_data *ndata)
{
    if (filter_ll_write_pending(ndata) || ndata->xmit_enabled ||
		ndata->tmp_xmit_enabled)
	ll_set_write_callback_enable(ndata, true);
    else
	ll_set_write_callback_enable(ndata, false);
    if (((((ndata->read_enabled && !filter_ul_read_pending(ndata)) ||
		filter_ll_read_needed(ndata)) && ndata->state == BASEN_OPEN) ||
	    ndata->state == BASEN_IN_FILTER_OPEN ||
	    ndata->state == BASEN_IN_FILTER_CLOSE) &&
	   !ndata->in_read && !ndata->ll_err_occurred)
	ll_set_read_callback_enable(ndata, true);
    else
	ll_set_read_callback_enable(ndata, false);
}

static int
basen_write_data_handler(void *cb_data, gensiods *rcount,
			 const struct gensio_sg *sg, gensiods sglen,
			 const char *const *auxdata)
{
    struct basen_data *ndata = cb_data;

    return ll_write(ndata, rcount, sg, sglen, auxdata);
}

static int
basen_write(struct basen_data *ndata, gensiods *rcount,
	    const struct gensio_sg *sg, gensiods sglen,
	    const char *const *auxdata)
{
    int err = 0;

    basen_lock(ndata);
    if (ndata->state != BASEN_OPEN) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    if (ndata->saved_xmit_err) {
	err = ndata->saved_xmit_err;
	ndata->saved_xmit_err = 0;
	goto out_unlock;
    }

    err = filter_ul_write(ndata, basen_write_data_handler, rcount, sg, sglen,
			  auxdata);

 out_unlock:
    basen_set_ll_enables(ndata);
    basen_unlock(ndata);

    return err;
}

static int
basen_read_data_handler(void *cb_data,
			gensiods *rcount,
			unsigned char *buf,
			gensiods buflen,
			const char *const *auxdata)
{
    struct basen_data *ndata = cb_data;
    gensiods count = 0, rval;

    basen_lock(ndata);
    while (ndata->state == BASEN_OPEN && ndata->read_enabled &&
	   count < buflen) {
	rval = buflen - count;
	basen_unlock(ndata);
	gensio_cb(ndata->io, GENSIO_EVENT_READ, 0, buf + count, &rval, auxdata);
	if (rval > buflen - count)
	    rval = buflen - count;
	count += rval;
	if (count >= buflen)
	    goto out; /* Don't claim the lock if I don't have to. */
	basen_lock(ndata);
    }
    basen_unlock(ndata);

 out:
    *rcount = count;
    return 0;
}

static void basen_ll_close_on_err(void *cb_data, void *close_data);
static void basen_ll_close_done(void *cb_data, void *close_data);
static void basen_i_close(struct basen_data *ndata,
			  gensio_done close_done, void *close_data);

static void basen_ll_close_on_err(void *cb_data, void *close_data);
static void basen_ll_close_done(void *cb_data, void *close_data);
static void basen_i_close(struct basen_data *ndata,
			  gensio_done close_done, void *close_data);

static void
handle_readerr(struct basen_data *ndata, int err)
{
    struct gensio *io = ndata->io;
    bool old_enable;

    old_enable = ndata->read_enabled;
    /* Do this here so the user can modify it. */
    ndata->read_enabled = false;

    if (ndata->ll_err)
	goto call_parent_err;

    ndata->ll_err_occurred = true;
    ndata->ll_err = err;
    if (ndata->state == BASEN_IN_FILTER_OPEN ||
			ndata->state == BASEN_IN_LL_OPEN) {
	ll_close(ndata, basen_ll_close_on_err, (void *) (long) err);
    } else if (ndata->state == BASEN_CLOSE_WAIT_DRAIN ||
			ndata->state == BASEN_IN_FILTER_CLOSE) {
	ll_close(ndata, basen_ll_close_done, NULL);
    } else if (gensio_get_cb(io)) {
	goto call_parent_err;
    } else {
	basen_i_close(ndata, NULL, NULL);
    }
    return;
 call_parent_err:
    while ((old_enable || ndata->read_enabled) && !ndata->in_read) {
	ndata->in_read = true;
	basen_unlock(ndata);
	gensio_cb(io, GENSIO_EVENT_READ, err, NULL, NULL, NULL);
	basen_lock(ndata);
	ndata->in_read = false;
	old_enable = false;
    }
    if (ndata->state != BASEN_CLOSED)
	basen_set_ll_enables(ndata);
}

static void basen_finish_close(struct basen_data *ndata);

static void basen_try_connect(struct basen_data *ndata);

static void
basen_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct basen_data *ndata = cbdata;
    int err;

    basen_lock(ndata);
 retry:
    if (ndata->deferred_open) {
	ndata->deferred_open = false;
	basen_try_connect(ndata);
    }

    if (ndata->deferred_close) {
	ndata->deferred_close = false;
	basen_finish_close(ndata);
    }

    if (ndata->deferred_read) {
	if (ndata->state != BASEN_OPEN)
	    goto out_unlock;

	ndata->deferred_read = false;

	if (ndata->ll_err) {
	    err = ndata->ll_err;
	} else {
	    do {
		basen_unlock(ndata);
		err = filter_ll_write(ndata, basen_read_data_handler,
				      NULL, NULL, 0, NULL);
		basen_lock(ndata);
	    } while (!err && ndata->read_enabled &&
		     filter_ul_read_pending(ndata));
	}
	ndata->in_read = false;
	if (err)
	    handle_readerr(ndata, err);
    }

    if (ndata->deferred_read || ndata->deferred_open || ndata->deferred_close)
	goto retry;

 out_unlock:
    ndata->deferred_op_pending = false;
    if (ndata->state != BASEN_CLOSED)
	basen_set_ll_enables(ndata);
    basen_deref_and_unlock(ndata);
}

static void
basen_sched_deferred_op(struct basen_data *ndata)
{
    if (!ndata->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	ndata->deferred_op_pending = true;
	basen_ref(ndata);
	ndata->o->run(ndata->deferred_op_runner);
    }
}

static void
basen_finish_close(struct basen_data *ndata)
{
    filter_cleanup(ndata);
    basen_set_state(ndata, BASEN_CLOSED);
    basen_deref(ndata);
    if (ndata->close_done) {
	basen_unlock(ndata);
	ndata->close_done(ndata->io, ndata->close_data);
	basen_lock(ndata);
    }
}

static void
basen_finish_open(struct basen_data *ndata, int err)
{
    if (err) {
	basen_set_state(ndata, BASEN_CLOSED);
	basen_deref(ndata);
	filter_cleanup(ndata);
    } else {
	basen_set_state(ndata, BASEN_OPEN);
	if (ndata->timer_start_pending)
	    ndata->o->start_timer(ndata->timer, &ndata->pending_timer);
    }

    if (ndata->open_done) {
	basen_unlock(ndata);
	ndata->open_done(ndata->io, err, ndata->open_data);
	basen_lock(ndata);
    }
}

static void
basen_ll_close_done(void *cb_data, void *close_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock_and_ref(ndata);
    basen_finish_close(ndata);
    basen_deref_and_unlock(ndata);
}

static void
basen_ll_close_on_err(void *cb_data, void *close_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock_and_ref(ndata);
    basen_finish_open(ndata, (long) close_data);
    basen_deref_and_unlock(ndata);
}

static void
basen_try_connect(struct basen_data *ndata)
{
    int err;
    struct timeval timeout = {0, 0};

    if (ndata->state != BASEN_IN_FILTER_OPEN)
	/*
	 * We can race between the timer, input, and output, make sure
	 * not to call this extraneously.
	 */
	return;

    ll_set_write_callback_enable(ndata, false);
    ll_set_read_callback_enable(ndata, false);

    err = filter_try_connect(ndata, &timeout);
    if (!err || err == GE_INPROGRESS || err == GE_RETRY)
	basen_set_ll_enables(ndata);
    if (err == GE_INPROGRESS)
	return;
    if (err == GE_RETRY) {
	ndata->o->start_timer(ndata->timer, &timeout);
	return;
    }

    if (!err)
	err = filter_check_open_done(ndata);

    if (err)
	ll_close(ndata, basen_ll_close_on_err, (void *) (long) err);
    else
	basen_finish_open(ndata, 0);
}

static void
basen_ll_open_done(void *cb_data, int err, void *open_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock_and_ref(ndata);
    if (err) {
	basen_finish_open(ndata, err);
    } else {
	/*
	 * Once the lower layer is open, propagate the traits.
	 */
	if (ndata->child) {
	    if (gensio_is_reliable(ndata->child))
		gensio_set_is_reliable(ndata->io, true);
	    if (gensio_is_authenticated(ndata->child))
		gensio_set_is_authenticated(ndata->io, true);
	    if (gensio_is_encrypted(ndata->child))
		gensio_set_is_encrypted(ndata->io, true);
	}

	basen_set_state(ndata, BASEN_IN_FILTER_OPEN);
	basen_try_connect(ndata);
	basen_set_ll_enables(ndata);
    }
    basen_deref_and_unlock(ndata);
}

static int
basen_open(struct basen_data *ndata, gensio_done_err open_done, void *open_data)
{
    int err = GE_INUSE;

    basen_lock_and_ref(ndata);
    if (ndata->state == BASEN_CLOSED) {
	err = filter_setup(ndata);
	if (err)
	    goto out_err;

	ndata->in_read = false;
	ndata->deferred_read = false;
	ndata->deferred_open = false;
	ndata->deferred_close = false;
	ndata->read_enabled = false;
	ndata->xmit_enabled = false;
	ndata->timer_start_pending = false;

	ndata->open_done = open_done;
	ndata->open_data = open_data;
	err = ll_open(ndata, basen_ll_open_done, ndata);
	if (err == 0) {
	    basen_ref(ndata);
	    basen_set_state(ndata, BASEN_IN_FILTER_OPEN);
	    ndata->deferred_open = true;
	    basen_sched_deferred_op(ndata);
	} else if (err == GE_INPROGRESS) {
	    basen_set_state(ndata, BASEN_IN_LL_OPEN);
	    basen_ref(ndata);
	    err = 0;
	} else {
	    filter_cleanup(ndata);
	    goto out_err;
	}	    
    }
 out_err:
    basen_deref_and_unlock(ndata);

    return err;
}

static int
basen_open_nochild(struct basen_data *ndata,
		   gensio_done_err open_done, void *open_data)
{
    int err = GE_INUSE;

    basen_lock(ndata);
    if (ndata->state == BASEN_CLOSED) {
	err = filter_setup(ndata);
	if (err)
	    goto out_err;

	ndata->in_read = false;
	ndata->deferred_read = false;
	ndata->deferred_open = false;
	ndata->deferred_close = false;
	ndata->read_enabled = false;
	ndata->xmit_enabled = false;
	ndata->timer_start_pending = false;

	ndata->open_done = open_done;
	ndata->open_data = open_data;

	basen_ref(ndata);
	basen_set_state(ndata, BASEN_IN_FILTER_OPEN);
	ndata->deferred_open = true;
	basen_sched_deferred_op(ndata);
	/* Call the first try open from the xmit handler. */
	ndata->tmp_xmit_enabled = true;
	basen_set_ll_enables(ndata);
    }
 out_err:
    basen_unlock(ndata);

    return err;
}

static void
basen_try_close(struct basen_data *ndata)
{
    int err;
    struct timeval timeout = {0, 0};

    ll_set_write_callback_enable(ndata, false);
    ll_set_read_callback_enable(ndata, false);

    err = filter_try_disconnect(ndata, &timeout);
    if (err == GE_INPROGRESS || err == GE_RETRY)
	basen_set_ll_enables(ndata);
    if (err == GE_INPROGRESS)
	return;
    if (err == GE_RETRY) {
	ndata->o->start_timer(ndata->timer, &timeout);
	return;
    }

    /* FIXME - error handling? */
    ll_close(ndata, basen_ll_close_done, NULL);
}

static void
basen_i_close(struct basen_data *ndata,
	      gensio_done close_done, void *close_data)
{
    ndata->close_done = close_done;
    ndata->close_data = close_data;
    if (ndata->ll_err_occurred || ndata->state == BASEN_IN_LL_OPEN) {
	ll_close(ndata, basen_ll_close_done, NULL);
    } else if (filter_ll_write_pending(ndata)) {
	basen_set_state(ndata, BASEN_CLOSE_WAIT_DRAIN);
    } else {
	basen_set_state(ndata, BASEN_IN_FILTER_CLOSE);
	basen_try_close(ndata);
    }
    basen_set_ll_enables(ndata);
}

static int
basen_close(struct basen_data *ndata, gensio_done close_done, void *close_data)
{
    int err = 0;

    basen_lock(ndata);
    if (ndata->state != BASEN_OPEN) {
	if (ndata->state == BASEN_IN_FILTER_OPEN ||
			ndata->state == BASEN_IN_LL_OPEN) {
	    basen_i_close(ndata, close_done, close_data);
	} else {
	    err = GE_NOTREADY;
	}
    } else {
	basen_i_close(ndata, close_done, close_data);
    }
    basen_unlock(ndata);

    return err;
}

static void
basen_free(struct basen_data *ndata)
{
    basen_lock(ndata);
    assert(ndata->freeref > 0);
    if (--ndata->freeref > 0) {
	basen_unlock(ndata);
	return;
    }

    if (ndata->state == BASEN_IN_FILTER_CLOSE ||
		ndata->state == BASEN_IN_LL_CLOSE) {
	ndata->close_done = NULL;
    } else if (ndata->state == BASEN_IN_FILTER_OPEN ||
			ndata->state == BASEN_IN_LL_OPEN) {
	basen_i_close(ndata, NULL, NULL);
	/* We have to lose the reference that in_open state is holding. */
	basen_deref(ndata);
    } else if (ndata->state != BASEN_CLOSED) {
	basen_i_close(ndata, NULL, NULL);
    }
    /* Lose the initial ref so it will be freed when done. */
    basen_deref_and_unlock(ndata);
}

static void
basen_do_ref(struct basen_data *ndata)
{
    basen_lock(ndata);
    ndata->freeref++;
    basen_unlock(ndata);
}

static void
basen_timeout(struct gensio_timer *timer, void *cb_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    switch (ndata->state) {
    case BASEN_IN_FILTER_OPEN:
	basen_try_connect(ndata);
	break;

    case BASEN_IN_FILTER_CLOSE:
	basen_try_close(ndata);
	break;

    case BASEN_OPEN:
	basen_unlock(ndata);
	gensio_filter_timeout(ndata->filter);
	basen_lock(ndata);
	break;

    default:
	break;
    }
    basen_set_ll_enables(ndata);
    basen_unlock(ndata);
}

static void
basen_set_read_callback_enable(struct basen_data *ndata, bool enabled)
{
    bool read_pending;

    basen_lock(ndata);
    if (ndata->state == BASEN_CLOSED || ndata->state == BASEN_IN_FILTER_CLOSE ||
		ndata->state == BASEN_IN_LL_CLOSE)
	goto out_unlock;
    ndata->read_enabled = enabled;
    read_pending = filter_ul_read_pending(ndata);
    if (ndata->in_read || ndata->state == BASEN_IN_FILTER_OPEN ||
			ndata->state == BASEN_IN_LL_OPEN ||
			(read_pending && !enabled)) {
	/* Nothing to do, let the read/open handling wake things up. */
    } else if (read_pending || ndata->ll_err) {
	/* in_read keeps this from getting called while pending. */
	ndata->in_read = true;
	ndata->deferred_read = true;
	basen_sched_deferred_op(ndata);
    } else {
	/*
	 * FIXME - here (and other places) we don't disable the low-level
	 * handler, that is done in the callbacks.  That's not optimal,
	 * need to figure out a way to set this more accurately.
	 */
	basen_set_ll_enables(ndata);
    }
 out_unlock:
    basen_unlock(ndata);
}

static void
basen_set_write_callback_enable(struct basen_data *ndata, bool enabled)
{
    basen_lock(ndata);
    if (ndata->state == BASEN_CLOSED || ndata->state == BASEN_IN_FILTER_CLOSE ||
			ndata->state == BASEN_IN_LL_CLOSE)
	goto out_unlock;
    if (ndata->xmit_enabled != enabled) {
	ndata->xmit_enabled = enabled;
	basen_set_ll_enables(ndata);
    }
 out_unlock:
    basen_unlock(ndata);
}

static int
gensio_base_func(struct gensio *io, int func, gensiods *count,
		 const void *cbuf, gensiods buflen, void *buf,
		 const char *const *auxdata)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);
    int rv, rv2;

    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	return basen_write(ndata, count, cbuf, buflen, auxdata);

    case GENSIO_FUNC_RADDR_TO_STR:
	return gensio_ll_raddr_to_str(ndata->ll, count, buf, buflen);

    case GENSIO_FUNC_GET_RADDR:
	return gensio_ll_get_raddr(ndata->ll, buf, count);

    case GENSIO_FUNC_OPEN:
	return basen_open(ndata, cbuf, buf);

    case GENSIO_FUNC_OPEN_NOCHILD:
	return basen_open_nochild(ndata, cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return basen_close(ndata, cbuf, buf);

    case GENSIO_FUNC_FREE:
	basen_free(ndata);
	return 0;

    case GENSIO_FUNC_REF:
	basen_do_ref(ndata);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	basen_set_read_callback_enable(ndata, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	basen_set_write_callback_enable(ndata, buflen);
	return 0;

    case GENSIO_FUNC_REMOTE_ID:
	return gensio_ll_remote_id(ndata->ll, buf);

    case GENSIO_FUNC_CONTROL:
	rv = GE_NOTSUP;
	if (ndata->filter) {
	    rv = gensio_filter_control(ndata->filter, *((bool *) cbuf), buflen,
				       buf, count);
	    if (rv && rv != GE_NOTSUP)
		return rv;
	}
	rv2 = gensio_ll_control(ndata->ll, *((bool *) cbuf), buflen, buf,
				count);
	if (rv2 == GE_NOTSUP)
	    return rv;
	return rv2;

    case GENSIO_FUNC_DISABLE:
	if (ndata->state != BASEN_CLOSED) {
	    basen_set_state(ndata, BASEN_CLOSED);
	    basen_deref(ndata);
	    if (ndata->filter)
		gensio_filter_cleanup(ndata->filter);
	    gensio_ll_disable(ndata->ll);
	    if (ndata->child)
		gensio_disable(ndata->child);
	}
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static gensiods
basen_ll_read(void *cb_data, int readerr,
	      unsigned char *ibuf, gensiods buflen,
	      const char *const *auxdata)
{
    struct basen_data *ndata = cb_data;
    unsigned char *buf = ibuf;

#ifdef DEBUG_DATA
    printf("LL read:");
    prbuf(buf, buflen);
#endif
    basen_lock_and_ref(ndata);
    ll_set_read_callback_enable(ndata, false);
    if (readerr) {
	handle_readerr(ndata, readerr);
	goto out_finish;
    }

    if (ndata->in_read)
	/* Currently in a deferred read, just let that handle it. */
	goto out_unlock;

    if (buflen > 0) {
	ndata->in_read = true;
	do {
	    gensiods wrlen = 0;

	    basen_unlock(ndata);
	    readerr = filter_ll_write(ndata, basen_read_data_handler, &wrlen,
				      buf, buflen, auxdata);
	    basen_lock(ndata);

	    if (!readerr) {
		if (wrlen > buflen)
		    wrlen = buflen;
		buf += wrlen;
		buflen -= wrlen;
	    }
	} while (!readerr && ndata->read_enabled &&
		 (buflen > 0 || filter_ul_read_pending(ndata)));
	ndata->in_read = false;
	if (readerr) {
	    handle_readerr(ndata, readerr);
	    goto out_finish;
	}

	if (ndata->state == BASEN_IN_FILTER_OPEN)
	    basen_try_connect(ndata);
	if (ndata->state == BASEN_IN_FILTER_CLOSE)
	    basen_try_close(ndata);
    }

 out_finish:
    basen_set_ll_enables(ndata);
 out_unlock:
    basen_deref_and_unlock(ndata);

    return buf - ibuf;
}

static void
basen_ll_write_ready(void *cb_data)
{
    struct basen_data *ndata = cb_data;
    int err;

    basen_lock_and_ref(ndata);
    if (ndata->in_xmit_ready) {
	/*
	 * Another thread is already in the loop, we don't allow two
	 * callbacks at a time.  Just tell the other loop to do it
	 * again.
	 */
	ll_set_write_callback_enable(ndata, false);
	ndata->redo_xmit_ready = true;
	goto out;
    }
    ndata->in_xmit_ready = true;
 retry:
    ll_set_write_callback_enable(ndata, false);
    if (filter_ll_write_pending(ndata)) {
	err = filter_ul_write(ndata, basen_write_data_handler, NULL, NULL, 0,
			      NULL);
	if (err)
	    ndata->saved_xmit_err = err;
    }

    if (ndata->state == BASEN_CLOSE_WAIT_DRAIN &&
		!filter_ll_write_pending(ndata))
	basen_set_state(ndata, BASEN_IN_FILTER_CLOSE);
    if (ndata->state == BASEN_IN_FILTER_OPEN)
	basen_try_connect(ndata);
    if (ndata->state == BASEN_IN_FILTER_CLOSE)
	basen_try_close(ndata);
    if (ndata->state != BASEN_IN_FILTER_OPEN && !filter_ll_write_pending(ndata)
		&& ndata->xmit_enabled) {
	basen_unlock(ndata);
	gensio_cb(ndata->io, GENSIO_EVENT_WRITE_READY, 0, NULL, 0, NULL);
	basen_lock(ndata);
    }

    ndata->tmp_xmit_enabled = false;

    if (ndata->redo_xmit_ready) {
	/* Got another xmit ready while we were unlocked. */
	ndata->redo_xmit_ready = false;
	if (ndata->xmit_enabled || filter_ll_write_pending(ndata))
	    goto retry;
    }

    basen_set_ll_enables(ndata);
    ndata->in_xmit_ready = false;
 out:
    basen_deref_and_unlock(ndata);
}

static gensiods
gensio_ll_base_cb(void *cb_data, int op, int val,
		  void *buf, gensiods buflen,
		  const char *const *auxdata)
{
    switch (op) {
    case GENSIO_LL_CB_READ:
	return basen_ll_read(cb_data, val, buf, buflen, auxdata);

    case GENSIO_LL_CB_WRITE_READY:
	basen_ll_write_ready(cb_data);
	return 0;

    default:
	return 0;
    }
};

static void
basen_output_ready(void *cb_data)
{
    struct basen_data *ndata = cb_data;

    ll_set_write_callback_enable(ndata, true);
}

static void
basen_start_timer(void *cb_data, struct timeval *timeout)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    if (ndata->state == BASEN_OPEN) {
	ndata->o->start_timer(ndata->timer, timeout);
    } else {
	ndata->timer_start_pending = true;
	ndata->pending_timer = *timeout;
    }
    basen_unlock(ndata);
}

static int
gensio_base_filter_cb(void *cb_data, int op, void *data)
{
    switch (op) {
    case GENSIO_FILTER_CB_OUTPUT_READY:
	basen_output_ready(cb_data);
	return 0;

    case GENSIO_FILTER_CB_START_TIMER:
	basen_start_timer(cb_data, data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static struct gensio *
gensio_i_alloc(struct gensio_os_funcs *o,
	       struct gensio_ll *ll,
	       struct gensio_filter *filter,
	       struct gensio *child,
	       const char *typename,
	       bool is_client,
	       gensio_done_err open_done, void *open_data,
	       gensio_event cb, void *user_data)
{
    struct basen_data *ndata = o->zalloc(o, sizeof(*ndata));

    if (!ndata)
	return NULL;

    ndata->o = o;
    ndata->refcount = 1;
    ndata->freeref = 1;

    ndata->lock = o->alloc_lock(o);
    if (!ndata->lock)
	goto out_nomem;

    ndata->timer = o->alloc_timer(o, basen_timeout, ndata);
    if (!ndata->timer)
	goto out_nomem;

    ndata->deferred_op_runner = o->alloc_runner(o, basen_deferred_op, ndata);
    if (!ndata->deferred_op_runner)
	goto out_nomem;

    ll->ndata = ndata;
    if (filter) {
	filter->ndata = ndata;
	gensio_filter_set_callback(filter, gensio_base_filter_cb, ndata);
    }
    ndata->io = gensio_data_alloc(o, cb, user_data, gensio_base_func,
				  child, typename, ndata);
    if (!ndata->io)
	goto out_nomem;
    ndata->child = child;
    gensio_set_is_client(ndata->io, is_client);
    gensio_ll_set_callback(ll, gensio_ll_base_cb, ndata);

    /*
     * Save this until we succeed, otherwise basen_finish_free will
     * free them, but we don't want them freed if we fail.
     */
    ndata->ll = ll;
    ndata->filter = filter;

    if (is_client) {
	basen_set_state(ndata, BASEN_CLOSED);
    } else {
	if (filter_setup(ndata)) {
	    ndata->filter = NULL;
	    ndata->ll = NULL;
	    goto out_nomem;
	}

	ndata->open_done = open_done;
	ndata->open_data = open_data;
	basen_set_state(ndata, BASEN_IN_FILTER_OPEN);
	basen_ref(ndata);
	/* Call the first try open from the xmit handler. */
	ndata->tmp_xmit_enabled = true;
	basen_set_ll_enables(ndata);
    }

    return ndata->io;

out_nomem:
    basen_finish_free(ndata);
    return NULL;
}

struct gensio *
base_gensio_alloc(struct gensio_os_funcs *o,
		  struct gensio_ll *ll,
		  struct gensio_filter *filter,
		  struct gensio *child,
		  const char *typename,
		  gensio_event cb, void *user_data)
{
    return gensio_i_alloc(o, ll, filter, child, typename, true,
			  NULL, NULL, cb, user_data);
}

struct gensio *
base_gensio_server_alloc(struct gensio_os_funcs *o,
			 struct gensio_ll *ll,
			 struct gensio_filter *filter,
			 struct gensio *child,
			 const char *typename,
			 gensio_done_err open_done, void *open_data)
{
    return gensio_i_alloc(o, ll, filter, child, typename, false,
			  open_done, open_data, NULL, NULL);
}

void
gensio_filter_set_callback(struct gensio_filter *filter,
			   gensio_filter_cb cb, void *cb_data)
{
    filter->func(filter, GENSIO_FILTER_FUNC_SET_CALLBACK,
		 cb, cb_data,
		 NULL, NULL, NULL, 0, NULL);
}

bool
gensio_filter_ul_read_pending(struct gensio_filter *filter)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_UL_READ_PENDING,
			NULL, NULL, NULL, NULL, NULL, 0, NULL);
}

bool
gensio_filter_ll_write_pending(struct gensio_filter *filter)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_LL_WRITE_PENDING,
			NULL, NULL, NULL, NULL, NULL, 0, NULL);
}

bool
gensio_filter_ll_read_needed(struct gensio_filter *filter)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_LL_READ_NEEDED,
			NULL, NULL, NULL, NULL, NULL, 0, NULL);
}

int
gensio_filter_check_open_done(struct gensio_filter *filter,
			      struct gensio *io)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_CHECK_OPEN_DONE,
			NULL, io, NULL, NULL, NULL, 0, NULL);
}

int
gensio_filter_try_connect(struct gensio_filter *filter,
			  struct timeval *timeout)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_TRY_CONNECT,
			NULL, timeout, NULL, NULL, NULL, 0, NULL);
}

int
gensio_filter_try_disconnect(struct gensio_filter *filter,
			     struct timeval *timeout)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_TRY_DISCONNECT,
			NULL, timeout, NULL, NULL, NULL, 0, NULL);
}

int
gensio_filter_ul_write(struct gensio_filter *filter,
		       gensio_ul_filter_data_handler handler, void *cb_data,
		       gensiods *rcount,
		       const struct gensio_sg *sg, gensiods sglen,
		       const char *const *auxdata)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_UL_WRITE_SG,
			handler, cb_data, rcount, NULL, sg, sglen, auxdata);
}

int
gensio_filter_ll_write(struct gensio_filter *filter,
		       gensio_ll_filter_data_handler handler, void *cb_data,
		       gensiods *rcount,
		       unsigned char *buf, gensiods buflen,
		       const char *const *auxdata)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_LL_WRITE,
			handler, cb_data, rcount, buf, NULL, buflen, auxdata);
}

void
gensio_filter_timeout(struct gensio_filter *filter)
{
    filter->func(filter, GENSIO_FILTER_FUNC_TIMEOUT,
		 NULL, NULL, NULL, NULL, NULL, 0, NULL);
}

int
gensio_filter_setup(struct gensio_filter *filter, struct gensio *io)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_SETUP,
			NULL, io, NULL, NULL, NULL, 0, NULL);
}

void
gensio_filter_cleanup(struct gensio_filter *filter)
{
    filter->func(filter, GENSIO_FILTER_FUNC_CLEANUP,
		 NULL, NULL, NULL, NULL, NULL, 0, NULL);
}

void
gensio_filter_free(struct gensio_filter *filter)
{
    filter->func(filter, GENSIO_FILTER_FUNC_FREE,
		 NULL, NULL, NULL, NULL, NULL, 0, NULL);
}

int
gensio_filter_control(struct gensio_filter *filter, bool get,
		      unsigned int option, char *data, gensiods *datalen)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_CONTROL,
			NULL, data, datalen, NULL, &get, option, NULL);
}

struct gensio *
gensio_filter_get_gensio(struct gensio_filter *filter)
{
    return filter->ndata->io;
}

int
gensio_filter_do_event(struct gensio_filter *filter, int event, int err,
		       unsigned char *buf, gensiods *buflen,
		       const char *const *auxdata)
{
    struct basen_data *ndata = filter->ndata;

    return gensio_cb(ndata->io, event, err, buf, buflen, auxdata);
}

struct gensio_filter *
gensio_filter_alloc_data(struct gensio_os_funcs *o,
			 gensio_filter_func func, void *user_data)
{
    struct gensio_filter *filter = o->zalloc(o, sizeof(*filter));

    if (!filter)
	return NULL;

    filter->o = o;
    filter->func = func;
    filter->user_data = user_data;
    return filter;
}

void
gensio_filter_free_data(struct gensio_filter *filter)
{
    filter->o->free(filter->o, filter);
}

void *
gensio_filter_get_user_data(struct gensio_filter *filter)
{
    return filter->user_data;
}

void
gensio_ll_set_callback(struct gensio_ll *ll,
		       gensio_ll_cb cb, void *cb_data)
{
    ll->func(ll, GENSIO_LL_FUNC_SET_CALLBACK, NULL, cb_data, cb, 0, NULL);
}

int
gensio_ll_write(struct gensio_ll *ll, gensiods *rcount,
		const struct gensio_sg *sg, gensiods sglen,
		const char *const *auxdata)
{
    return ll->func(ll, GENSIO_LL_FUNC_WRITE_SG, rcount, NULL, sg, sglen,
		    auxdata);
}

int
gensio_ll_raddr_to_str(struct gensio_ll *ll, gensiods *pos,
		       char *buf, gensiods buflen)
{
    return ll->func(ll, GENSIO_LL_FUNC_RADDR_TO_STR, pos, buf, NULL, buflen,
		    NULL);
}

int
gensio_ll_get_raddr(struct gensio_ll *ll, void *addr, gensiods *addrlen)
{
    return ll->func(ll, GENSIO_LL_FUNC_GET_RADDR, addrlen, addr, NULL, 0,
		    NULL);
}

int
gensio_ll_remote_id(struct gensio_ll *ll, int *id)
{
    return ll->func(ll, GENSIO_LL_FUNC_REMOTE_ID, NULL, id, NULL, 0,
		    NULL);
}

int
gensio_ll_open(struct gensio_ll *ll,
	       gensio_ll_open_done done, void *open_data)
{
    return ll->func(ll, GENSIO_LL_FUNC_OPEN, NULL, open_data, done, 0,
		    NULL);
}

int
gensio_ll_close(struct gensio_ll *ll,
		gensio_ll_close_done done, void *close_data)
{
    return ll->func(ll, GENSIO_LL_FUNC_CLOSE, NULL, close_data, done, 0,
		    NULL);
}

void
gensio_ll_set_read_callback(struct gensio_ll *ll, bool enabled)
{
    ll->func(ll, GENSIO_LL_FUNC_SET_READ_CALLBACK, NULL, NULL, NULL, enabled,
	     NULL);
}

void
gensio_ll_set_write_callback(struct gensio_ll *ll, bool enabled)
{
    ll->func(ll, GENSIO_LL_FUNC_SET_WRITE_CALLBACK, NULL, NULL, NULL, enabled,
	     NULL);
}

void
gensio_ll_free(struct gensio_ll *ll)
{
    ll->func(ll, GENSIO_LL_FUNC_FREE, NULL, NULL, NULL, 0, NULL);
}

void
gensio_ll_disable(struct gensio_ll *ll)
{
    ll->func(ll, GENSIO_LL_FUNC_DISABLE, NULL, NULL, NULL, 0, NULL);
}

int
gensio_ll_control(struct gensio_ll *ll, bool get, int option, char *data,
		  gensiods *datalen)
{
    return ll->func(ll, GENSIO_LL_FUNC_CONTROL, datalen, data, &get, option,
		    NULL);
}

int
gensio_ll_do_event(struct gensio_ll *ll, int event, int err,
		   unsigned char *buf, gensiods *buflen,
		   const char *const *auxdata)
{
    struct basen_data *ndata = ll->ndata;

    return gensio_cb(ndata->io, event, err, buf, buflen, auxdata);
}

struct gensio_ll *
gensio_ll_alloc_data(struct gensio_os_funcs *o,
		     gensio_ll_func func, void *user_data)
{
    struct gensio_ll *ll = o->zalloc(o, sizeof(*ll));

    if (!ll)
	return NULL;

    ll->o = o;
    ll->func = func;
    ll->user_data = user_data;
    return ll;
}

void
gensio_ll_free_data(struct gensio_ll *ll)
{
    ll->o->free(ll->o, ll);
}

void *
gensio_ll_get_user_data(struct gensio_ll *ll)
{
    return ll->user_data;
}
