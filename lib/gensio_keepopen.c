/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This code is for a gensio that will never report child errors and
 * attempts to keep the child open.
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>

/*
 * KEEPN_CLOSED:
 *     open:
 *         open_done = userfunc
 *         rv = start child open
 *         if (rv)
 *             // Use this to report the open immediately
 *             ->KEEPN_OPEN_INIT_FAIL
 *             start zero timer
 *         else
 *             ->KEEPN_IN_OPEN
 *
 * KEEPN_IN_OPEN:
 *     close:
 *         rv = start child close
 *         if (rv)
 *             ->KEEPN_CLOSE_STOP_TIMER
 *             start zero-length timer
 *         else
 *             ->KEEPN_IN_CLOSE
 *     opened:
 *         report open
 *         open_done = NULL
 *         if (err)
 *             start timer
 *             ->KEEPN_CHILD_CLOSED
 *         else
 *             ->KEEPN_OPEN
 *             report open
 *
 * KEEPN_OPEN_INIT_FAIL: //Failed on first open only
 *     close:
 *         ->KEEPN_CLOSE_STOP_TIMER  // timeout will open/close it
 *     timeout:
 *         start timer
 *         ->KEEPN_CHILD_CLOSED
 *
 * KEEPN_OPEN:
 *     pass data through
 *     close:
 *         rv = start child close
 *         if (rv)
 *             ->KEEPN_CLOSED
 *         else
 *             ->KEEPN_IN_CLOSE
 *     I/O error:
 *         rv = start child close
 *         if (rv)
 *             start timer
 *             ->KEEPN_CHILD_CLOSED
 *         else
 *             ->KEEPN_CHILD_ERR_CLOSE
 *
 * KEEPN_IN_CLOSE:
 *     closed:
 *         if open_done
 *             report open
 *             open_done = NULL
 *         ->KEEPN_CLOSED
 *         report close
 *
 * KEEPN_CHILD_ERR_CLOSE:
 *     close:
 *         ->KEEPN_IN_CLOSE
 *     closed:
 *         incr refcount
 *         start timer
 *         ->KEEPN_CHILD_CLOSED
 *
 * KEEPN_CHILD_CLOSED:
 *     close:
 *         ->KEEPN_CLOSE_STOP_TIMER
 *         rv = stop_timer
 *         if (rv == GE_TIMEDOUT)
 *             --
 *         else if (rv == 0)
 *             start zero-length timer
 *         else
 *             error
 *     timeout:
 *         rv = start chid open
 *         if (rv)
 *             start timer
 *         else
 *             ->KEEPN_CHILD_CLOSED_IN_OPEN
 *
 * KEEPN_CLOSE_STOP_TIMER:
 *     timeout:
 *         if open_done
 *             report open
 *             open_done = NULL
 *         ->KEEPN_CLOSED
 *         report close
 *
 * KEEPN_CHILD_CLOSED_IN_OPEN:
 *     close:
 *         rv = start child close
 *         if (rv)
 *             ->KEEPN_CLOSE_STOP_TIMER
 *             start zero-length timer
 *         else
 *             ->KEEPN_IN_CLOSE
 *     opened:
 *         if (err)
 *             start timer
 *             ->KEEPN_CHILD_CLOSED
 *         else
 *             ->KEEPN_OPEN
 *
 */

enum keepn_state {
    KEEPN_CLOSED,
    KEEPN_IN_OPEN,
    KEEPN_OPEN_INIT_FAIL,
    KEEPN_OPEN,
    KEEPN_IN_CLOSE,
    KEEPN_CHILD_ERR_CLOSE,
    KEEPN_CHILD_CLOSED,
    KEEPN_CLOSE_STOP_TIMER,
    KEEPN_CHILD_CLOSED_IN_OPEN,
};

struct keepn_data {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    struct gensio *child;

    unsigned int refcount;
    enum keepn_state state;

    int last_child_err;

    bool discard_badwrites;

    /* Keep these around to set them when the open completes. */
    bool rx_enable;
    bool tx_enable;

    struct gensio *io;

    struct gensio_timer *retry_timer;
    struct gensio_time retry_time;

    bool read_enabled;
    bool xmit_enabled;

    gensio_done_err open_done;
    void *open_data;

    gensio_done close_done;
    void *close_data;
};

static void
keepn_finish_free(struct keepn_data *ndata)
{
    struct gensio_os_funcs *o = ndata->o;

    if (ndata->io)
	gensio_data_free(ndata->io);
    if (ndata->child)
	gensio_free(ndata->child);
    if (ndata->retry_timer)
	o->free_timer(ndata->retry_timer);
    if (ndata->lock)
	o->free_lock(ndata->lock);
    o->free(o, ndata);
}

static void
keepn_lock(struct keepn_data *ndata)
{
    ndata->o->lock(ndata->lock);
}

static void
keepn_unlock(struct keepn_data *ndata)
{
    ndata->o->unlock(ndata->lock);
}

static void
keepn_ref(struct keepn_data *ndata)
{
    assert(ndata->refcount > 0);
    ndata->refcount++;
}

/* Cannot be called for the last deref. */
static void
keepn_deref(struct keepn_data *ndata)
{
    assert(ndata->refcount > 1);
    ndata->refcount--;
}

static void
keepn_unlock_and_deref(struct keepn_data *ndata)
{
    assert(ndata->refcount > 0);
    if (ndata->refcount == 1) {
	keepn_unlock(ndata);
	keepn_finish_free(ndata);
    } else {
	ndata->refcount--;
	keepn_unlock(ndata);
    }
}

static void
keepn_start_zero_timer(struct keepn_data *ndata)
{
    gensio_time timeout = { 0, 0 };

    keepn_ref(ndata);
    if (ndata->o->start_timer(ndata->retry_timer, &timeout) != 0)
	assert(0);
}

static void
keepn_start_timer(struct keepn_data *ndata)
{
    keepn_ref(ndata);
    if (ndata->o->start_timer(ndata->retry_timer, &ndata->retry_time) != 0)
	assert(0);
}

static void
keepn_cancel_timer(struct keepn_data *ndata)
{
    int err = ndata->o->stop_timer(ndata->retry_timer);
    if (err == GE_TIMEDOUT) {
	/*
	 * In the timer handler before the lock, just let the
	 * timer handle handle it.
	 */
    } else if (!err) {
	keepn_start_zero_timer(ndata);
	keepn_deref(ndata);
    } else {
	assert(0);
    }
}

static void
keepn_check_open_done(struct keepn_data *ndata)
{
    if (ndata->open_done) {
	gensio_done_err open_done = ndata->open_done;
	void *open_data = ndata->open_data;

	/*
	 * I don't think that anything can change the state at
	 * this point, so no need for a marker that we are in open
	 * done.
	 */
	ndata->open_done = NULL;
	keepn_unlock(ndata);
	open_done(ndata->io, 0, open_data);
	keepn_lock(ndata);
    }
}

static void
keepn_check_close_done(struct keepn_data *ndata)
{
    gensio_done close_done = ndata->close_done;
    void *close_data = ndata->close_data;

    ndata->close_done = NULL;
    keepn_unlock(ndata);
    if (close_done)
	close_done(ndata->io, close_data);
    keepn_lock(ndata);
}

static void
keepn_open_done(struct gensio *io, int err, void *open_data)
{
    struct keepn_data *ndata = open_data;

    keepn_lock(ndata);
    switch (ndata->state) {
    case KEEPN_IN_OPEN:
	if (err) {
	    ndata->last_child_err = err;
	    gensio_log(ndata->o, GENSIO_LOG_INFO,
		       "Error opening child gensio: %s",
		       gensio_err_to_str(err));
	    ndata->state = KEEPN_CHILD_CLOSED;
	    keepn_start_timer(ndata);
	} else {
	    /*
	     * last_child_err is set if there was a previous error, we
	     * use that to know if this was the first connection and
	     * don't report on a first connection.
	     */
	    if (ndata->last_child_err)
		gensio_log(ndata->o, GENSIO_LOG_INFO,
			   "child gensio open restored");
	    gensio_set_write_callback_enable(ndata->child, ndata->tx_enable);
	    gensio_set_read_callback_enable(ndata->child, ndata->rx_enable);
	    ndata->state = KEEPN_OPEN;
	}
	if (ndata->open_done) {
	    gensio_done_err open_done = ndata->open_done;
	    void *open_data = ndata->open_data;

	    /*
	     * I don't think that anything can change the state at
	     * this point, so no need for a marker that we are in open
	     * done.
	     */
	    ndata->open_done = NULL;
	    keepn_unlock(ndata);
	    open_done(ndata->io, 0, open_data);
	    keepn_lock(ndata);
	}
	break;

    default:
	assert(0);
    }
    keepn_unlock(ndata);
}

static void
keepn_close_done(struct gensio *io, void *open_data)
{
    struct keepn_data *ndata = open_data;

    keepn_lock(ndata);
    switch (ndata->state) {
    case KEEPN_IN_CLOSE:
	keepn_check_open_done(ndata);
	ndata->state = KEEPN_CLOSED;
	keepn_check_close_done(ndata);
	break;

    case KEEPN_CHILD_ERR_CLOSE:
	ndata->state = KEEPN_CHILD_CLOSED;
	keepn_start_timer(ndata);
	break;

    default:
	assert(0);
    }
    keepn_unlock_and_deref(ndata);
}

static int
keepn_handle_io_err(struct keepn_data *ndata, int err)
{

    keepn_lock(ndata);
    if (ndata->state != KEEPN_OPEN)
	goto out_unlock;

    ndata->last_child_err = err;
    gensio_log(ndata->o, GENSIO_LOG_INFO, "I/O error from child gensio: %s",
	       gensio_err_to_str(err));

    err = gensio_close(ndata->child, keepn_close_done, ndata);
    if (err) {
	keepn_start_timer(ndata);
	ndata->state = KEEPN_CHILD_CLOSED;
    } else {
	ndata->state = KEEPN_CHILD_ERR_CLOSE;
	keepn_ref(ndata);
    }
    
 out_unlock:
    keepn_unlock(ndata);
    return 0;
}

static int
keepn_event(struct gensio *io, void *user_data,
	    int event, int err,
	    unsigned char *buf, gensiods *buflen,
	    const char *const *auxdata)
{
    struct keepn_data *ndata = user_data;

    if (err && event == GENSIO_EVENT_READ) {
	keepn_handle_io_err(ndata, err);
	return 0;
    }

    /* All other events just pass through. */
    return gensio_cb(ndata->io, event, err, buf, buflen, auxdata);
}

static void
keepn_retry_timeout(struct gensio_timer *t, void *cb_data)
{
    struct keepn_data *ndata = cb_data;
    int err;

    keepn_lock(ndata);
    switch (ndata->state) {
    case KEEPN_OPEN_INIT_FAIL:
	gensio_log(ndata->o, GENSIO_LOG_INFO, "Error from gensio open: %s",
		   gensio_err_to_str(ndata->last_child_err));
	keepn_check_open_done(ndata);
	ndata->state = KEEPN_CHILD_CLOSED;
	keepn_start_timer(ndata);
	break;

    case KEEPN_CHILD_CLOSED:
	err = gensio_open(ndata->child, keepn_open_done, ndata);
	if (err)
	    keepn_start_timer(ndata);
	else
	    ndata->state = KEEPN_IN_OPEN;
	break;

    case KEEPN_CLOSE_STOP_TIMER:
	keepn_check_open_done(ndata);
	ndata->state = KEEPN_CLOSED;
	keepn_check_close_done(ndata);
	break;

    default:
	assert(0);
    }
    keepn_unlock_and_deref(ndata);
}

static int
keepn_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    struct keepn_data *ndata = gensio_get_gensio_data(io);
    int err;

    keepn_lock(ndata);
    if (ndata->state != KEEPN_CLOSED) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    err = gensio_open(ndata->child, keepn_open_done, ndata);
    if (err) {
	ndata->last_child_err = err;
	ndata->state = KEEPN_OPEN_INIT_FAIL;
	keepn_start_zero_timer(ndata);
    } else {
	ndata->last_child_err = 0;
	ndata->state = KEEPN_IN_OPEN;
    }
    ndata->open_done = open_done;
    ndata->open_data = open_data;
 out_unlock:
    keepn_unlock(ndata);

    return 0;
}

static int
keepn_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    struct keepn_data *ndata = gensio_get_gensio_data(io);
    int err = 0;

    keepn_lock(ndata);
    switch (ndata->state) {
    case KEEPN_OPEN:
    case KEEPN_IN_OPEN:
	err = gensio_close(ndata->child, keepn_close_done, ndata);
	if (err) {
	    ndata->state = KEEPN_CLOSE_STOP_TIMER;
	    keepn_start_zero_timer(ndata);
	} else {
	    ndata->state = KEEPN_IN_CLOSE;
	    keepn_ref(ndata);
	}
	break;

    case KEEPN_OPEN_INIT_FAIL:
	ndata->state = KEEPN_CLOSE_STOP_TIMER;
	break;

    case KEEPN_CHILD_ERR_CLOSE:
	ndata->state = KEEPN_IN_CLOSE;
	break;

    case KEEPN_CHILD_CLOSED:
	ndata->state = KEEPN_CLOSE_STOP_TIMER;
	keepn_cancel_timer(ndata);
	break;

    case KEEPN_CHILD_CLOSED_IN_OPEN:
	err = gensio_close(ndata->child, keepn_close_done, ndata);
	if (err) {
	    ndata->state = KEEPN_CLOSE_STOP_TIMER;
	    keepn_start_zero_timer(ndata);
	} else {
	    ndata->state = KEEPN_IN_CLOSE;
	    keepn_ref(ndata);
	}
	break;

    default:
	err = GE_NOTREADY;
	goto out_unlock;
    }
    ndata->close_done = close_done;
    ndata->close_data = close_data;
 out_unlock:
    keepn_unlock(ndata);

    return err;
}

static void
keepn_free(struct gensio *io)
{
    struct keepn_data *ndata = gensio_get_gensio_data(io);

    keepn_lock(ndata);
    switch(ndata->state) {
    case KEEPN_CLOSED:
    case KEEPN_IN_CLOSE:
    case KEEPN_CHILD_ERR_CLOSE:
	ndata->state = KEEPN_CLOSED;
	break;

    case KEEPN_OPEN_INIT_FAIL:
	ndata->state = KEEPN_CLOSE_STOP_TIMER;
	/* fallthrough */
    case KEEPN_CLOSE_STOP_TIMER:
	ndata->open_done = NULL; /* Don't call the open callback on a free. */
	break;

    case KEEPN_IN_OPEN:
    case KEEPN_OPEN:
    case KEEPN_CHILD_CLOSED_IN_OPEN:
	/* Close operation will grab a ref. */
	keepn_close(ndata->io, NULL, NULL);
	ndata->state = KEEPN_CLOSED;
	break;

    case KEEPN_CHILD_CLOSED:
	ndata->state = KEEPN_CLOSE_STOP_TIMER;
	keepn_cancel_timer(ndata);
	break;
    }
    keepn_unlock_and_deref(ndata);
}

static int
keepn_disable(struct gensio *io)
{
    struct keepn_data *ndata = gensio_get_gensio_data(io);

    keepn_lock(ndata);
    ndata->state = KEEPN_CLOSED;
    keepn_unlock(ndata);

    return 0;
}

static int
keepn_gensio_func(struct gensio *io, int func, gensiods *count,
		  const void *cbuf, gensiods buflen, void *buf,
		  const char *const *auxdata)
{
    struct keepn_data *ndata = gensio_get_gensio_data(io);
    int err;

    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	err = gensio_call_func(ndata->child,
			       func, count, cbuf, buflen, buf, auxdata);
	if (err) {
	    keepn_handle_io_err(ndata, err);
	    if (ndata->discard_badwrites) {
		gensiods i, amt = 0;
		const struct gensio_sg *sg = cbuf;

		for (i = 0; i < buflen; i++)
		    amt += sg[i].buflen;
		*count = amt;
	    } else {
		*count = 0; /* Tell the user to wait. */
	    }
	}
	return 0;

    case GENSIO_FUNC_OPEN:
	return keepn_open(io, (void *) cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return keepn_close(io, (void *) cbuf, buf);

    case GENSIO_FUNC_FREE:
	keepn_free(io);
	return 0;

    case GENSIO_FUNC_DISABLE:
	return keepn_disable(io);

    case GENSIO_FUNC_SET_READ_CALLBACK:
	keepn_lock(ndata);
	ndata->rx_enable = buflen;
	keepn_unlock(ndata);
	goto passon;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	keepn_lock(ndata);
	ndata->tx_enable = buflen;
	keepn_unlock(ndata);
	goto passon;

    default:
    passon:
	/* Everything but the above just passes through. */
	return gensio_call_func(ndata->child,
				func, count, cbuf, buflen, buf, auxdata);
    }
}

static int
keepopen_gensio_alloc(struct gensio *child, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio)
{
    struct keepn_data *ndata = NULL;
    int i;
    struct gensio_time retry_time = { 1, 0 };
    bool discard_badwrites = false;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keytime(args[i], "retry-time", 'm', &retry_time) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "discard-badwrites",
				 &discard_badwrites) > 0)
	    continue;
	return GE_INVAL;
    }

    ndata = o->zalloc(o, sizeof(*ndata));
    if (!ndata)
	return GE_NOMEM;
    ndata->o = o;
    ndata->refcount = 1;

    ndata->retry_timer = o->alloc_timer(o, keepn_retry_timeout, ndata);
    if (!ndata->retry_timer)
	goto out_nomem;

    ndata->lock = o->alloc_lock(o);
    if (!ndata->lock)
	goto out_nomem;

    ndata->child = child;
    ndata->retry_time = retry_time;
    ndata->discard_badwrites = discard_badwrites;
    gensio_set_callback(child, keepn_event, ndata);

    ndata->io = gensio_data_alloc(ndata->o, cb, user_data,
				  keepn_gensio_func, child, "keepopen", ndata);
    if (!ndata->io)
	goto out_nomem;
    gensio_set_is_client(ndata->io, true);

    *new_gensio = ndata->io;

    return 0;

 out_nomem:
    keepn_finish_free(ndata);
    return GE_NOMEM;
}

static int
str_to_keepopen_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    err = str_to_gensio(str, o, NULL, NULL, &io2);
    if (err)
	return err;

    err = keepopen_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

int
gensio_init_keepopen(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "keepopen",
				str_to_keepopen_gensio, keepopen_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
