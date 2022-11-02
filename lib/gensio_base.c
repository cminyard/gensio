/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_base.h>
#include <gensio/gensio_os_funcs.h>

#ifdef DEBUG_DATA
#define ENABLE_PRBUF 1
#include "utils.h"
#endif

/*
 * Events:
 *   ll_write_ready
 *   ll_read
 *   ll_open_done
 *   ll_close_done
 *   write
 *   open
 *   close
 *   free
 */
enum basen_state {
    /*
     * gensio is closed, either at initial startup after close is
     * complete.
     *
     * open && ll open deferred -> BASEN_IN_LL_OPEN
     * open && ll open success && filter open deferred -> BASEN_IN_FILTER_OPEN
     * open && ll open success && filter open success -> BASEN_OPEN
     */
    BASEN_CLOSED,

    /*
     * We have requested that our ll open, but have not received the
     * confirmation yet.
     *
     * ll open done (err) -> BASEN_CLOSED
     * ll open done && filter open deferred -> BASEN_IN_FILTER_OPEN
     * ll open done && filter open success -> BASEN_OPEN
     * close -> BASEN_IN_LL_CLOSE
     * io err should not be possible
     */
    BASEN_IN_LL_OPEN,

    /*
     * We have requested that the filter open (if we have a filter)
     * but it has not yet been confirmed.
     *
     * filter open done -> BASEN_OPEN
     * close -> BASEN_IN_LL_CLOSE
     * io err -> BASEN_IN_LL_IO_ERR_CLOSE
     */
    BASEN_IN_FILTER_OPEN,

    /*
     * gensio is operational
     *
     * close && write data pending -> BASEN_CLOSE_WAIT_DRAIN
     * close && no write data pending && filter close deferred ->
     *                 BASEN_IN_FILTER_CLOSE
     * close && no write data pending && filter close complete ->
		       BASEN_IN_LL_CLOSE
     * io err -> BASEN_IN_LL_IO_ERR_CLOSE
     */
    BASEN_OPEN,

    /*
     * A close has been requested, but we have write data to deliver.
     *
     * All data written && filter close deferred -> BASEN_IN_FILTER_CLOSE
     * All data written && filter close complete -> BASEN_IN_LL_CLOSE
     * io err -> BASEN_IN_LL_CLOSE
     */
    BASEN_CLOSE_WAIT_DRAIN,

    /*
     * A close has been requested and all data is delivered.  The
     * filter close has been requested but it has not yet reported
     * closed.
     *
     * filter close done -> BASEN_IN_LL_CLOSE
     * io err -> BASEN_IN_LL_CLOSE
     */
    BASEN_IN_FILTER_CLOSE,

    /*
     * A close has been requested and the filter is closed.  The ll
     * close has been requested but it has not yet reported closed.
     *
     * ll close done && all writes finished -> BASEN_CLOSE
     * finish all writes -> BASEN_CLOSE
     * io err -> ignore
     */
    BASEN_IN_LL_CLOSE,

    /*
     * An I/O error happened on BASEN_OPEN, waiting for the LL to close.
     *
     * close -> BASEN_IN_LL_CLOSE
     * ll close done && all writes finished -> BASEN_IO_ERR_CLOSE
     * finish all writes -> BASEN_IO_ERR_CLOSE
     * io err -> ignore
     */
    BASEN_IN_LL_IO_ERR_CLOSE,

    /*
     * An I/O error happened on BASEN_OPEN or before, waiting close call.
     *
     * close -> BASEN_CLOSE
     * io err should not be possible
     */
    BASEN_IO_ERR_CLOSE
};

#ifdef ENABLE_INTERNAL_TRACE
#define DEBUG_STATE
#endif

#ifdef DEBUG_STATE
struct basen_state_trace {
    enum basen_state old_state;
    enum basen_state new_state;
    int line;
};
#define STATE_TRACE_LEN 256
struct basen_data;
static void i_basen_add_trace(struct basen_data *ndata,
			      enum basen_state new_state, int line);
#else
#define i_basen_add_trace(ndata, new_state, line)
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
    gensio_time pending_timer;

    unsigned int refcount;

    enum basen_state state;

    gensio_done_err open_done;
    void *open_data;

    gensio_done close_done;
    void *close_data;
    bool close_requested;
    bool ll_want_close;
    unsigned int in_write_count;

    bool read_enabled;
    bool in_read;

    bool xmit_enabled;
    bool in_xmit_ready;
    bool redo_xmit_ready;
    bool ll_can_write;

    /*
     * We got an error from the lower layer, it's probably not working
     * any more.
     */
    int ll_err;

    /*
     * Transfer data to the deferred open.
     */
    int open_err;

    /*
     * Used to run user callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

    bool deferred_read;
    bool deferred_write;
    bool deferred_open;
    bool deferred_close;

#ifdef DEBUG_STATE
    struct basen_state_trace state_trace[STATE_TRACE_LEN];
    unsigned int state_trace_pos;
#endif
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

static void i_handle_ioerr(struct basen_data *ndata, int err, int line);
static void basen_filter_try_close(struct basen_data *ndata, bool was_timeout);
static void basen_check_open_close_ops(struct basen_data *ndata);
#define handle_ioerr(n, e) i_handle_ioerr(n, e, __LINE__)

static void
i_basen_lock(struct basen_data *ndata)
{
    ndata->o->lock(ndata->lock);
}
#define basen_lock(ndata) do { \
	i_basen_lock((ndata));						\
	i_basen_add_trace(ndata, 1800 + ndata->refcount, __LINE__);	\
    } while(false)

static void
i_basen_unlock(struct basen_data *ndata)
{
    ndata->o->unlock(ndata->lock);
}
#define basen_unlock(ndata) do { \
	i_basen_add_trace(ndata, 1900 + ndata->refcount, __LINE__);	\
	i_basen_unlock((ndata));					\
    } while(false)

static void
basen_finish_free(struct basen_data *ndata)
{
    if (ndata->io)
	gensio_data_free(ndata->io);
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
    ndata->o->free(ndata->o, ndata);
}

static void
i_basen_ref(struct basen_data *ndata, int line)
{
    assert(ndata->refcount > 0);
    ndata->refcount++;
    i_basen_add_trace(ndata, 1000 + ndata->refcount, line);
}
#define basen_ref(ndata) i_basen_ref((ndata), __LINE__)

static void
i_basen_lock_and_ref(struct basen_data *ndata, int line)
{
    i_basen_lock(ndata);
    i_basen_ref(ndata, line);
}
#define basen_lock_and_ref(ndata) i_basen_lock_and_ref((ndata), __LINE__)

/*
 * This can *only* be called if the refcount is guaranteed not to reach
 * zero.
 */
static void
i_basen_deref(struct basen_data *ndata, int line)
{
    assert(ndata->refcount > 1);
    i_basen_add_trace(ndata, 1000 + ndata->refcount, line);
    ndata->refcount--;
}
#define basen_deref(ndata) i_basen_deref((ndata), __LINE__)

static void
i_basen_deref_and_unlock(struct basen_data *ndata, int line)
{
    unsigned int count;

    assert(ndata->refcount > 0);
    i_basen_add_trace(ndata, 1000 + ndata->refcount, line);
    count = --ndata->refcount;
    i_basen_unlock(ndata);
    if (count == 0)
	basen_finish_free(ndata);
}
#define basen_deref_and_unlock(ndata) i_basen_deref_and_unlock((ndata), __LINE__)

static void
basen_start_timer(struct basen_data *ndata, gensio_time *timeout)
{
    if (ndata->o->start_timer(ndata->timer, timeout) == 0)
	basen_ref(ndata);
}

static void
basen_stop_timer(struct basen_data *ndata)
{
    if (ndata->o->stop_timer(ndata->timer) == 0)
	basen_deref(ndata);
}

#ifdef DEBUG_STATE
static void
i_basen_add_trace(struct basen_data *ndata,
		  enum basen_state new_state, int line)
{
    ndata->state_trace[ndata->state_trace_pos].old_state = ndata->state;
    ndata->state_trace[ndata->state_trace_pos].new_state = new_state;
    ndata->state_trace[ndata->state_trace_pos].line = line;
    if (ndata->state_trace_pos == STATE_TRACE_LEN - 1)
	ndata->state_trace_pos = 0;
    else
	ndata->state_trace_pos++;
}

static void
i_basen_set_state(struct basen_data *ndata, enum basen_state state, int line)
{
    i_basen_add_trace(ndata, state, line);
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
filter_ll_write_queued(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_ll_write_queued(ndata->filter);
    return false;
}

static void
filter_io_err(struct basen_data *ndata, int err)
{
    if (ndata->filter)
	gensio_filter_io_err(ndata->filter, err);
}

static bool
filter_ul_can_write(struct basen_data *ndata)
{
    if (ndata->filter)
	return gensio_filter_ul_can_write(ndata->filter);
    return ndata->ll_can_write;
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
filter_try_connect(struct basen_data *ndata, gensio_time *timeout,
		   bool was_timeout)
{
    if (ndata->filter)
	return gensio_filter_try_connect(ndata->filter, timeout, was_timeout);
    return 0;
}

static int
filter_try_disconnect(struct basen_data *ndata, gensio_time *timeout,
		      bool was_timeout)
{
    if (ndata->filter)
	return gensio_filter_try_disconnect(ndata->filter, timeout,
					    was_timeout);
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
    if (buflen)
	return handler(ndata, rcount, buf, buflen, auxdata);
    return 0;
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
    int rv;

#ifdef DEBUG_DATA
    printf("LL write:");
    do {
	unsigned int i;
	for (i = 0; i < sglen; i++)
	    prbuf(sg[i].buf, sg[i].buflen);
    } while (false);
#endif
    rv = gensio_ll_write(ndata->ll, rcount, sg, sglen, auxdata);
#ifdef DEBUG_DATA
    printf("LL write returned %d accepted %ld\n", rv, rcount ? *rcount : 0);
#endif
    return rv;
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
basen_ll_close_done(void *cb_data, void *close_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    i_basen_add_trace(ndata, 1100, __LINE__);
    switch(ndata->state) {
    case BASEN_IN_LL_CLOSE:
    case BASEN_IO_ERR_CLOSE:
	/* Don't move to BASEN_CLOSED until later to avoid races. */
	i_basen_add_trace(ndata, 102, __LINE__);
	ndata->deferred_close = true;
	basen_sched_deferred_op(ndata);
	break;

    case BASEN_IN_LL_IO_ERR_CLOSE:
	basen_set_state(ndata, BASEN_IO_ERR_CLOSE);
	/*
	 * This is kind of a hack.  This can come from an error two
	 * places, either filter open or open.  If it's in filter
	 * open, we need to deliver the open failure to the user,
	 * otherwise we will already be set to deliver a read/write
	 * failture.  So if open_done is set, we are in filter open,
	 * and know to deliver the open failure.
	 */
	if (ndata->open_done) {
	    ndata->deferred_open = true;
	    basen_sched_deferred_op(ndata);
	}
	break;

    default:
	assert(0);
    }
    basen_unlock(ndata);
}

static int
i_ll_close(struct basen_data *ndata, int line)
{
    int rv;

    rv = gensio_ll_close(ndata->ll, basen_ll_close_done, ndata);
    return rv;
}
#define ll_close(n) i_ll_close(n, __LINE__);

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
    bool enabled;

    if (ndata->state == BASEN_CLOSED || ndata->ll_err) {
	ll_set_write_callback_enable(ndata, false);
	ll_set_read_callback_enable(ndata, false);
	return;
    }

    ll_set_write_callback_enable(ndata, !ndata->ll_can_write);

    enabled = false;
    if (ndata->in_read)
	goto out_set;

    switch(ndata->state) {
    case BASEN_IN_FILTER_OPEN:
    case BASEN_IN_FILTER_CLOSE:
	enabled = filter_ll_read_needed(ndata);
	break;

    case BASEN_OPEN:
	if (filter_ul_read_pending(ndata) && ndata->read_enabled) {
	    ndata->deferred_read = true;
	    basen_sched_deferred_op(ndata);
	    enabled = false;
	} else {
	    enabled = ndata->read_enabled;
	}
	/* Fallthrough */
    case BASEN_CLOSE_WAIT_DRAIN:
	enabled = enabled || filter_ll_read_needed(ndata);
	break;

    case BASEN_IN_LL_CLOSE:
	enabled = false;
	break;

    default:
	enabled = true;
	break;
    }
 out_set:
    ll_set_read_callback_enable(ndata, enabled);
}

static int
basen_write_data_handler(void *cb_data, gensiods *rcount,
			 const struct gensio_sg *sg, gensiods sglen,
			 const char *const *auxdata)
{
    struct basen_data *ndata = cb_data;
    int rv;
    gensiods i, total = 0, count = 0;

    for (i = 0; i < sglen; i++)
	total += sg[i].buflen;
    rv = ll_write(ndata, &count, sg, sglen, auxdata);
    if (!rv && count < total)
	ndata->ll_can_write = false;
    if (rcount)
	*rcount = count;
    return rv;
}

static int
basen_filter_ul_push(struct basen_data *ndata, bool check_open_close)
{
    if (!ndata->ll_err && ndata->ll_can_write &&
		filter_ll_write_pending(ndata)) {
	int err;

	err = filter_ul_write(ndata, basen_write_data_handler, NULL, NULL, 0,
			      NULL);
	if (err) {
	    handle_ioerr(ndata, err);
	    return err;
	}
	if (check_open_close)
	    basen_check_open_close_ops(ndata);
    }

    return 0;
}

static bool
write_data_pending(struct basen_data *ndata)
{
    return filter_ll_write_queued(ndata) || ndata->in_write_count > 0;
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
    if (ndata->ll_err) {
	err = ndata->ll_err;
	goto out_unlock;
    }
    ndata->in_write_count++;

    err = filter_ul_write(ndata, basen_write_data_handler, rcount, sg, sglen,
			  auxdata);

    ndata->in_write_count--;
    if (err)
	handle_ioerr(ndata, err);

    /*
     * We make sure that nothing is in a write call before starting a
     * close.  So if anything wants to call ll_close() and
     * in_write_count is non-zero, it must set ll_want_close to defer
     * to here.
     */
    if (ndata->in_write_count == 0 && ndata->ll_want_close) {
	int rv;

	switch (ndata->state) {
	case BASEN_CLOSE_WAIT_DRAIN:
	    basen_set_state(ndata, BASEN_IN_LL_CLOSE);
	    rv = ll_close(ndata);
	    if (rv) {
		ndata->deferred_close = true;
		basen_sched_deferred_op(ndata);
	    }
	    break;

	case BASEN_IN_LL_IO_ERR_CLOSE:
	    basen_set_state(ndata, BASEN_IO_ERR_CLOSE);
	    break;

	case BASEN_IN_LL_CLOSE:
	    ndata->deferred_close = true;
	    basen_sched_deferred_op(ndata);
	    break;

	default:
	    assert(0);
	}
    }
 out_unlock:
    basen_set_ll_enables(ndata);
    basen_unlock(ndata);

    return err;
}

static bool
basen_can_deliver_ul_data(struct basen_data *ndata)
{
    return ndata->state == BASEN_OPEN ||
	ndata->state == BASEN_IN_LL_IO_ERR_CLOSE ||
	ndata->state == BASEN_IO_ERR_CLOSE;
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
    int err = 0;

    basen_lock(ndata);
    if (!basen_can_deliver_ul_data(ndata)) {
	if (ndata->state != BASEN_IN_LL_OPEN &&
		ndata->state != BASEN_IN_FILTER_OPEN) {
	    /*
	     * Just eat the data if we aren't open.  But not on
	     * pre-open because we can get data there on a race.
	     */
	    count = buflen;
	}
	goto out_unlock;
    }
    while (basen_can_deliver_ul_data(ndata) && ndata->read_enabled &&
	   (count < buflen || ndata->ll_err)) {
	if (ndata->ll_err && !filter_ul_read_pending(ndata)) {
	    basen_unlock(ndata);
	    err = gensio_cb(ndata->io, GENSIO_EVENT_READ, ndata->ll_err,
			    NULL, NULL, NULL);
	    basen_lock(ndata);
	} else {
	    basen_unlock(ndata);
	    rval = buflen - count;
	    err = gensio_cb(ndata->io, GENSIO_EVENT_READ, 0,
			    buf + count, &rval, auxdata);
#ifdef ENABLE_INTERNAL_TRACE
	    /* Only for testing. */
	    assert(rval <= buflen - count);
#else
	    if (rval > buflen - count)
		rval = buflen - count;
#endif
	    count += rval;
	    if (count >= buflen)
		goto out; /* Don't claim the lock if I don't have to. */
	    basen_lock(ndata);
	}
    }
 out_unlock:
    basen_unlock(ndata);

 out:
    if (rcount)
	*rcount = count;
    return err;
}

static void
i_handle_ioerr(struct basen_data *ndata, int err, int line)
{
    int rv;

    i_basen_add_trace(ndata, 905, line);
    assert(err);

    if (ndata->ll_err)
	return; /* Already handled. */

    ll_set_write_callback_enable(ndata, false);
    ll_set_read_callback_enable(ndata, false);

    ndata->ll_err = err;
    ndata->open_err = err;

    /* Strange looking, but don't enable ll write if we get an error. */
    ndata->ll_can_write = true;

    switch(ndata->state) {
    case BASEN_CLOSED:
    case BASEN_IN_LL_OPEN:
    case BASEN_IO_ERR_CLOSE:
	assert(0);
	break;

    case BASEN_IN_FILTER_OPEN:
	filter_io_err(ndata, err);
	basen_set_state(ndata, BASEN_IN_LL_IO_ERR_CLOSE);
	/*
	 * No need to check for in_write_count here, it can't be
	 * pending because we can't have started a write yet.
	 */
	rv = ll_close(ndata);
	if (rv)
	    basen_set_state(ndata, BASEN_IO_ERR_CLOSE);
	break;

    case BASEN_OPEN:
	filter_io_err(ndata, err);
	ndata->deferred_read = true;
	ndata->deferred_write = true;
	basen_sched_deferred_op(ndata);
	basen_set_state(ndata, BASEN_IN_LL_IO_ERR_CLOSE);
	if (ndata->in_write_count == 0) {
	    rv = ll_close(ndata);
	    if (rv)
		basen_set_state(ndata, BASEN_IO_ERR_CLOSE);
	} else {
	    ndata->ll_want_close = true;
	}
	break;

    case BASEN_CLOSE_WAIT_DRAIN:
	filter_io_err(ndata, err);
	basen_set_state(ndata, BASEN_IN_LL_CLOSE);
	if (ndata->in_write_count == 0) {
	    rv = ll_close(ndata);
	    if (rv) {
		ndata->deferred_close = true;
		basen_sched_deferred_op(ndata);
	    }
	} else {
	    ndata->ll_want_close = true;
	}
	break;

    case BASEN_IN_FILTER_CLOSE:
	filter_io_err(ndata, err);
	basen_set_state(ndata, BASEN_IN_LL_CLOSE);
	if (ndata->in_write_count == 0) {
	    rv = ll_close(ndata);
	    if (rv) {
		ndata->deferred_close = true;
		basen_sched_deferred_op(ndata);
	    }
	} else {
	    ndata->ll_want_close = true;
	}
	break;

    case BASEN_IN_LL_CLOSE:
    case BASEN_IN_LL_IO_ERR_CLOSE:
	break;
    }
}

static void
basen_timer_stopped(struct gensio_timer *t, void *cb_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    basen_deref_and_unlock(ndata);
}

/*
 * Note that you must be holding an extra ref when calling this,
 * the close_done call may free the gensio.
 */
static void
basen_finish_close(struct basen_data *ndata)
{
    /*
     * We don't have to worry about write here, write is only done in
     * write callbacks from the ll close, and when the ll close is
     * reported we are guaranteed to not be in a write callback.  We
     * also don't need to worry about a read operation except for a
     * deferred one for the same reason.
     */
    assert(!ndata->in_xmit_ready);
    if (ndata->deferred_op_pending) {
	i_basen_add_trace(ndata, 101, __LINE__);
	ndata->deferred_close = true;
	return;
    }
    assert(!ndata->in_read);
    filter_cleanup(ndata);
    basen_set_state(ndata, BASEN_CLOSED);
    if (ndata->close_done) {
	basen_unlock(ndata);
	ndata->close_done(ndata->io, ndata->close_data);
	basen_lock(ndata);
    }
    if (ndata->timer) {
	/*
	 * This will either stop the timer and call
	 * basen_timer_stopped which will do the deref for the timer,
	 * or it will fail if there was no timer running (no ref) or
	 * if the timer was in the callback (the callback will deref).
	 */
	ndata->o->stop_timer_with_done(ndata->timer,
				       basen_timer_stopped,
				       ndata);
    }
    basen_deref(ndata); /* Lose the ref for the open. */
}

static void
basen_finish_open(struct basen_data *ndata, int err)
{
    gensio_done_err open_done;
    void *open_data;

    i_basen_add_trace(ndata, 100, __LINE__);
    if (!err) {
	assert(ndata->state == BASEN_IN_FILTER_OPEN || ndata->state == BASEN_OPEN);
	basen_set_state(ndata, BASEN_OPEN);
	if (ndata->timer_start_pending)
	    basen_start_timer(ndata, &ndata->pending_timer);
    }

    open_done = ndata->open_done;
    ndata->open_done = NULL;
    open_data = ndata->open_data;
    basen_unlock(ndata);
    open_done(ndata->io, err, open_data);
    basen_lock(ndata);
}

/*
 * Returns true if the open callback has been called but a close has
 * not been requested.  We also call in ll_close, to flush out any
 * data we have.
 */
static bool
basen_in_read_callbackable_state(struct basen_data *ndata)
{
    return (ndata->state == BASEN_OPEN ||
	    ndata->state == BASEN_CLOSE_WAIT_DRAIN ||
	    ndata->state == BASEN_IN_LL_IO_ERR_CLOSE ||
	    ndata->state == BASEN_IN_LL_CLOSE ||
	    ndata->state == BASEN_IN_FILTER_CLOSE ||
	    ndata->state == BASEN_IO_ERR_CLOSE);
}

/* Returns true if the open callback has been called but close has not. */
static bool
basen_in_write_callbackable_state(struct basen_data *ndata)
{
    return (ndata->state == BASEN_OPEN ||
	    ndata->state == BASEN_IN_LL_IO_ERR_CLOSE ||
	    ndata->state == BASEN_IO_ERR_CLOSE);
}

static void
basen_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct basen_data *ndata = cbdata;
    int err;

    basen_lock(ndata);
    ndata->deferred_op_pending = false;

    if (ndata->deferred_open) {
	ndata->deferred_open = false;
	i_basen_add_trace(ndata, 100, __LINE__);
	basen_finish_open(ndata, ndata->open_err);
    }

    while (ndata->deferred_read) {
	if (ndata->in_read || !ndata->read_enabled)
	    goto skip_read;
	ndata->deferred_read = false;
	ndata->in_read = true;
	do {
	    if (ndata->ll_err && !filter_ul_read_pending(ndata)) {
		/* Automatically disable read on an error. */
		ndata->read_enabled = false;
		basen_unlock(ndata);
		err = gensio_cb(ndata->io, GENSIO_EVENT_READ, ndata->ll_err,
				NULL, NULL, NULL);
		basen_lock(ndata);
	    } else {
		basen_unlock(ndata);
		err = filter_ll_write(ndata, basen_read_data_handler,
				      NULL, NULL, 0, NULL);
		basen_lock(ndata);
	    }
	    if (err) {
		handle_ioerr(ndata, err);
		break;
	    }
	} while (ndata->read_enabled &&
		 (ndata->ll_err || filter_ul_read_pending(ndata)));
	ndata->in_read = false;
    }

 skip_read:
    /* The write side is primarily for delivery when an error occurs. */
    while (ndata->deferred_write) {
	ndata->deferred_write = false;
	if (ndata->in_xmit_ready)
	    goto skip_write;
	ndata->in_xmit_ready = true;
	while (basen_in_write_callbackable_state(ndata) &&
	       (filter_ul_can_write(ndata) || ndata->ll_err)
	       && ndata->xmit_enabled) {
	    basen_unlock(ndata);
	    err = gensio_cb(ndata->io, GENSIO_EVENT_WRITE_READY, 0, NULL,
			    0, NULL);
	    basen_lock(ndata);
	    if (err) {
		handle_ioerr(ndata, err);
		break;
	    }
	}
	ndata->in_xmit_ready = false;
    }

 skip_write:
    if (ndata->deferred_close) {
	if (!(ndata->in_xmit_ready || ndata->in_read)) {
	    ndata->deferred_close = false;
	    i_basen_add_trace(ndata, 101, __LINE__);
	    basen_finish_close(ndata);
	}
    }

    if (ndata->state != BASEN_CLOSED) {
	basen_filter_ul_push(ndata, true);
	basen_set_ll_enables(ndata);
    }
    basen_deref_and_unlock(ndata); /* Ref from basen_sched_deferred_op */
}

static void
basen_sched_deferred_op(struct basen_data *ndata)
{
    if (!ndata->deferred_op_pending) {
	ndata->deferred_op_pending = true;
	basen_ref(ndata);
	ndata->o->run(ndata->deferred_op_runner);
    }
}

static int
basen_filter_try_connect(struct basen_data *ndata, bool was_timeout)
{
    int err;
    gensio_time timeout = {0, 0};

    err = filter_try_connect(ndata, &timeout, was_timeout);
    if (!err || err == GE_INPROGRESS || err == GE_RETRY) {
	int err2 = basen_filter_ul_push(ndata, false);
	if (err2) {
	    basen_set_ll_enables(ndata);
	    return err2;
	} else if (err == GE_INPROGRESS) {
	    err = filter_try_connect(ndata, &timeout, false);
	    basen_set_ll_enables(ndata);
	}
    }
    if (err == GE_INPROGRESS)
	return GE_INPROGRESS;
    if (err == GE_RETRY) {
	basen_start_timer(ndata, &timeout);
	return GE_INPROGRESS;
    }

    if (!err)
	err = filter_check_open_done(ndata);

    return err;
}

static void
basen_filter_try_connect_finish(struct basen_data *ndata, bool was_timeout)
{
    int err;

    err = basen_filter_try_connect(ndata, was_timeout);
    if (!err) {
	i_basen_add_trace(ndata, 100, __LINE__);
	basen_set_state(ndata, BASEN_OPEN);
	ndata->deferred_open = true;
	basen_sched_deferred_op(ndata);
    } else if (err != GE_INPROGRESS)
	handle_ioerr(ndata, err);
}

static void
basen_ll_open_done(void *cb_data, int err, void *open_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock_and_ref(ndata);
    if (ndata->ll_err || ndata->open_err) {
	/* Nothing to do here, we failed the open, a close should be pending. */
    } else if (err) {
	basen_set_state(ndata, BASEN_CLOSED);
	i_basen_add_trace(ndata, 100, __LINE__);
	basen_finish_open(ndata, err);
	basen_deref(ndata);
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
	basen_filter_try_connect_finish(ndata, false);
	basen_set_ll_enables(ndata);
    }
    basen_deref_and_unlock(ndata);
}

static int
basen_open(struct basen_data *ndata, gensio_done_err open_done, void *open_data)
{
    int err = GE_INUSE;

    if (!open_done)
	return GE_INVAL;

    basen_lock(ndata);
    if (ndata->state == BASEN_CLOSED) {
	err = filter_setup(ndata);
	if (err)
	    goto out_err;

	ndata->ll_err = 0;
	ndata->open_err = 0;
	ndata->in_read = false;
	ndata->deferred_read = false;
	ndata->deferred_write = false;
	ndata->deferred_open = false;
	ndata->deferred_close = false;
	ndata->read_enabled = false;
	ndata->xmit_enabled = false;
	ndata->ll_can_write = false;
	ndata->timer_start_pending = false;
	ndata->close_requested = false;
	ndata->ll_want_close = false;

	ndata->open_done = open_done;
	ndata->open_data = open_data;
	basen_set_state(ndata, BASEN_IN_LL_OPEN);
	err = ll_open(ndata, basen_ll_open_done, ndata);
	if (err == 0) {
	    basen_set_state(ndata, BASEN_IN_FILTER_OPEN);
	    err = basen_filter_try_connect(ndata, false);
	    if (!err) {
		/* We are fully open, schedule it. */
		basen_set_state(ndata, BASEN_OPEN);
		ndata->deferred_open = true;
		basen_sched_deferred_op(ndata);
	    } else if (err == GE_INPROGRESS) {
		err = 0;
	    }
	} else if (err == GE_INPROGRESS) {
	    err = 0;
	}
	if (err)
	    basen_set_state(ndata, BASEN_CLOSED);
	else
	    basen_ref(ndata); /* Ref for open. */
    }
 out_err:
    basen_unlock(ndata);

    return err;
}

static int
basen_open_nochild(struct basen_data *ndata,
		   gensio_done_err open_done, void *open_data)
{
    int err = GE_INUSE;

    if (!open_done)
	return GE_INVAL;

    basen_lock(ndata);
    if (ndata->state == BASEN_CLOSED) {
	err = filter_setup(ndata);
	if (err)
	    goto out_err;

	ndata->ll_err = 0;
	ndata->open_err = 0;
	ndata->in_read = false;
	ndata->deferred_read = false;
	ndata->deferred_write = false;
	ndata->deferred_open = false;
	ndata->deferred_close = false;
	ndata->read_enabled = false;
	ndata->xmit_enabled = false;
	ndata->timer_start_pending = false;

	ndata->open_done = open_done;
	ndata->open_data = open_data;

	basen_set_state(ndata, BASEN_IN_FILTER_OPEN);
	err = basen_filter_try_connect(ndata, false);
	if (!err) {
	    /* We are fully open, schedule it. */
	    basen_set_state(ndata, BASEN_OPEN);
	    ndata->deferred_open = true;
	    basen_sched_deferred_op(ndata);
	} else if (err == GE_INPROGRESS) {
	    err = 0;
	}
	if (err)
	    basen_set_state(ndata, BASEN_CLOSED);
	else
	    basen_ref(ndata); /* Ref for open */

	basen_set_ll_enables(ndata);
    }
 out_err:
    basen_unlock(ndata);

    return err;
}

static void
basen_filter_try_close(struct basen_data *ndata, bool was_timeout)
{
    int err;
    gensio_time timeout = {0, 0};

    err = filter_try_disconnect(ndata, &timeout, was_timeout);
    if (err == GE_INPROGRESS || err == GE_RETRY) {
	basen_filter_ul_push(ndata, false);
	if (err == GE_INPROGRESS)
	    err = filter_try_disconnect(ndata, &timeout, was_timeout);
	basen_set_ll_enables(ndata);
    }
    if (err == GE_INPROGRESS)
	return;
    if (err == GE_RETRY) {
	basen_start_timer(ndata, &timeout);
	return;
    }

    /* Ignore errors here, just go on. */
    basen_set_state(ndata, BASEN_IN_LL_CLOSE);
    if (ndata->in_write_count == 0) {
	err = ll_close(ndata);
	if (err) {
	    ndata->deferred_close = true;
	    basen_sched_deferred_op(ndata);
	}
    } else {
	ndata->ll_want_close = true;
    }
}

static void
basen_i_close(struct basen_data *ndata,
	      gensio_done close_done, void *close_data)
{
    int rv;

    ndata->read_enabled = false;
    ndata->xmit_enabled = false;
    ndata->close_done = close_done;
    ndata->close_data = close_data;
    /*
     * Set local close no matter what, so it get's delivered if open is
     * not yet complete.
     */
    ndata->open_err = GE_LOCALCLOSED;
    if (ndata->state == BASEN_IN_LL_OPEN ||
		ndata->state == BASEN_IN_FILTER_OPEN) {
	basen_set_state(ndata, BASEN_IN_LL_CLOSE);
	/*
	 * No need to check for in_write_count here, it can't be
	 * pending because we can't have started a write yet.
	 */
	rv = ll_close(ndata);
	if (rv) {
	    ndata->deferred_close = true;
	    basen_sched_deferred_op(ndata);
	}
    } else if (write_data_pending(ndata)) {
	basen_set_state(ndata, BASEN_CLOSE_WAIT_DRAIN);
    } else {
	basen_set_state(ndata, BASEN_IN_FILTER_CLOSE);
	basen_filter_try_close(ndata, false);
    }
    basen_set_ll_enables(ndata);
}

static int
basen_close(struct basen_data *ndata, gensio_done close_done, void *close_data)
{
    int err = 0;

    basen_lock(ndata);
    if (ndata->close_requested) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    ndata->close_requested = true;
    i_basen_add_trace(ndata, 103, __LINE__);
    if (ndata->state == BASEN_OPEN || ndata->state == BASEN_IN_FILTER_OPEN ||
		ndata->state == BASEN_IN_LL_OPEN) {
	basen_i_close(ndata, close_done, close_data);
    } else if (ndata->state == BASEN_IN_LL_IO_ERR_CLOSE) {
	ndata->close_done = close_done;
	ndata->close_data = close_data;
	basen_set_state(ndata, BASEN_IN_LL_CLOSE);
    } else if (ndata->state == BASEN_IO_ERR_CLOSE) {
	ndata->close_done = close_done;
	ndata->close_data = close_data;
	i_basen_add_trace(ndata, 102, __LINE__);
	ndata->deferred_close = true;
	basen_sched_deferred_op(ndata);
    } else {
	err = GE_NOTREADY;
    }
 out_unlock:
    basen_unlock(ndata);

    return err;
}

static void
basen_free(struct basen_data *ndata)
{
    basen_lock(ndata);
    i_basen_add_trace(ndata, 103, __LINE__);
    switch (ndata->state) {
    case BASEN_CLOSED:
	/* We can free immediately. */
	break;

    case BASEN_IN_LL_OPEN:
    case BASEN_IN_FILTER_OPEN:
    case BASEN_OPEN:
	/* Need to close before we can free */
	basen_i_close(ndata, NULL, NULL);
	break;

    case BASEN_IN_LL_IO_ERR_CLOSE:
	ndata->close_done = NULL;
	basen_set_state(ndata, BASEN_IN_LL_CLOSE);
	break;

    case BASEN_IO_ERR_CLOSE:
	ndata->close_done = NULL;
	ndata->deferred_close = true;
	basen_sched_deferred_op(ndata);
	break;

    default:
	/* In the close process, lose a ref so it will free when done. */
	/* Don't call the done */
	ndata->close_done = NULL;
	break;
    }
    /* Lose the initial ref so it will be freed when done. */
    basen_deref_and_unlock(ndata);
}

static void
basen_timeout(struct gensio_timer *timer, void *cb_data)
{
    struct basen_data *ndata = cb_data;
    int err;

    basen_lock(ndata);
    switch (ndata->state) {
    case BASEN_IN_FILTER_OPEN:
	basen_filter_try_connect_finish(ndata, true);
	break;

    case BASEN_IN_FILTER_CLOSE:
	basen_filter_try_close(ndata, true);
	break;

    case BASEN_OPEN:
    case BASEN_CLOSE_WAIT_DRAIN:
	basen_unlock(ndata);
	err = gensio_filter_timeout(ndata->filter);
	basen_lock(ndata);
	if (err)
	    handle_ioerr(ndata, err);
	break;

    default:
	break;
    }
    basen_filter_ul_push(ndata, true);
    basen_set_ll_enables(ndata);
    basen_deref_and_unlock(ndata);
}

static void
basen_set_read_callback_enable(struct basen_data *ndata, bool enabled)
{
    bool read_pending;

    basen_lock(ndata);
    i_basen_add_trace(ndata, 1100 + ndata->read_enabled * 10 + enabled,
		      __LINE__);
    if (ndata->read_enabled == enabled)
	goto out_unlock;
    if (!basen_in_read_callbackable_state(ndata))
	goto out_unlock;
    ndata->read_enabled = enabled;
    read_pending = filter_ul_read_pending(ndata);
    if (ndata->deferred_op_pending && enabled) {
	/* Nothing to do, let the read/open handling wake things up. */
	ndata->deferred_read = true;
    } else if (enabled && (read_pending || ndata->ll_err) &&
	       ndata->state == BASEN_OPEN) {
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
    i_basen_add_trace(ndata, 1100 + ndata->xmit_enabled * 10 + enabled,
		      __LINE__);
    if (ndata->xmit_enabled == enabled)
	goto out_unlock;
    if (!basen_in_write_callbackable_state(ndata))
	goto out_unlock;
    ndata->xmit_enabled = enabled;
    if (enabled && (filter_ul_can_write(ndata) || ndata->ll_err)) {
	/* We can write, schedule the callback as a deferred op. */
	ndata->deferred_write = true;
	basen_sched_deferred_op(ndata);
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

    case GENSIO_FUNC_OPEN:
	return basen_open(ndata, (void *) cbuf, buf);

    case GENSIO_FUNC_OPEN_NOCHILD:
	return basen_open_nochild(ndata, (void *) cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return basen_close(ndata, (void *) cbuf, buf);

    case GENSIO_FUNC_FREE:
	basen_free(ndata);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	basen_set_read_callback_enable(ndata, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	basen_set_write_callback_enable(ndata, buflen);
	return 0;

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

static void
basen_check_open_close_ops(struct basen_data *ndata)
{
    if (ndata->deferred_close) {
	if (!(ndata->in_xmit_ready || ndata->in_read)) {
	    ndata->deferred_close = false;
	    i_basen_add_trace(ndata, 101, __LINE__);
	    basen_finish_close(ndata);
	}
	return;
    }
    if (ndata->state == BASEN_IN_FILTER_OPEN)
	basen_filter_try_connect_finish(ndata, false);
    if (ndata->state == BASEN_IN_FILTER_CLOSE)
	basen_filter_try_close(ndata, false);
    if (ndata->state == BASEN_CLOSE_WAIT_DRAIN) {
	if (!write_data_pending(ndata)) {
	    basen_set_state(ndata, BASEN_IN_FILTER_CLOSE);
	    basen_filter_try_close(ndata, false);
	}
    }
}

static gensiods
basen_ll_read(void *cb_data, int readerr,
	      unsigned char *ibuf, gensiods buflen,
	      const char *const *auxdata)
{
    struct basen_data *ndata = cb_data;
    unsigned char *buf = ibuf;
    int err;

#ifdef DEBUG_DATA
    printf("LL read:");
    prbuf(buf, buflen);
#endif
    basen_lock_and_ref(ndata);
    if (readerr) {
	handle_ioerr(ndata, readerr);
	goto out_finish;
    }
    if (ndata->ll_err) {
	/* If we are handling an error, throw the data away. */
	buf += buflen;
	goto out_finish;
    }

    while (buflen > 0 &&
	   (ndata->read_enabled || filter_ll_read_needed(ndata))) {

	if (ndata->in_read) {
	    /* Currently in a deferred read, just let that handle it. */
	    ll_set_read_callback_enable(ndata, false);
	    goto out_unlock;
	}

	ndata->in_read = true;
	do {
	    gensiods wrlen = 0;

	    basen_unlock(ndata);
	    readerr = filter_ll_write(ndata, basen_read_data_handler,
				      &wrlen, buf, buflen, auxdata);
	    basen_lock(ndata);

	    if (ndata->ll_err || readerr) {
		ndata->in_read = false;
		buf += buflen;
		if (readerr && !ndata->ll_err)
		    handle_ioerr(ndata, readerr);
		else if (ndata->deferred_read)
		    /*
		     * Deferred op can happen while we are
		     * unlocked. ll_err will be set, so this is the
		     * right place to do it.
		     */
		    basen_sched_deferred_op(ndata);
		goto out_finish;
	    } else {
#ifdef ENABLE_INTERNAL_TRACE
		/* Only for testing. */
		assert(wrlen <= buflen);
#else
		if (wrlen > buflen)
		    wrlen = buflen;
#endif
		buf += wrlen;
		buflen -= wrlen;
	    }
	} while (ndata->read_enabled && buflen > 0);
	ndata->in_read = false;

	basen_filter_ul_push(ndata, true);

	basen_check_open_close_ops(ndata);

	while (basen_in_write_callbackable_state(ndata) &&
	       (filter_ul_can_write(ndata) || ndata->ll_err)
	       && ndata->xmit_enabled) {
	    basen_unlock(ndata);
	    err = gensio_cb(ndata->io, GENSIO_EVENT_WRITE_READY, 0, NULL,
			    0, NULL);
	    basen_lock(ndata);
	    if (err) {
		handle_ioerr(ndata, err);
		break;
	    }
	}
    }

 out_finish:
    basen_set_ll_enables(ndata);
 out_unlock:
    basen_deref_and_unlock(ndata);

#ifdef DEBUG_DATA
    printf("LL read returns %ld\n", buf - ibuf);
#endif
    return buf - ibuf;
}

static void
basen_ll_write_ready(void *cb_data)
{
    struct basen_data *ndata = cb_data;
    int err;

    basen_lock_and_ref(ndata);
    if (ndata->ll_err) {
	/* Just ignore it if we have an error. */
	ll_set_write_callback_enable(ndata, false);
	goto out;
    }
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
    ndata->ll_can_write = true;
    ndata->in_xmit_ready = true;
 retry:
    if (filter_ll_write_pending(ndata)) {
	err = filter_ul_write(ndata, basen_write_data_handler, NULL, NULL, 0,
			      NULL);
	if (err) {
	    handle_ioerr(ndata, err);
	    goto out_setnotready;
	}
    }

    basen_filter_ul_push(ndata, true);

    basen_check_open_close_ops(ndata);

    while (basen_in_write_callbackable_state(ndata) &&
	   (filter_ul_can_write(ndata) || ndata->ll_err)
	   && ndata->xmit_enabled) {
	basen_unlock(ndata);
	err = gensio_cb(ndata->io, GENSIO_EVENT_WRITE_READY, 0, NULL, 0, NULL);
	basen_lock(ndata);
	if (err) {
	    handle_ioerr(ndata, err);
	    goto out_setnotready;
	}
    }

    if (ndata->redo_xmit_ready) {
	/* Got another xmit ready while we were unlocked. */
	ndata->redo_xmit_ready = false;
	if (ndata->xmit_enabled || filter_ll_write_pending(ndata))
	    goto retry;
    }

 out_setnotready:
    basen_set_ll_enables(ndata);
    ndata->in_xmit_ready = false;
    if (ndata->deferred_write)
	/* Could have gotten a deferred write while we were unlocked. */
	basen_sched_deferred_op(ndata);
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

    /* Force the lower-level callback to be enabled. */
    ndata->ll_can_write = false;
    ll_set_write_callback_enable(ndata, true);
}

static void
basen_start_timer_op(void *cb_data, gensio_time *timeout)
{
    struct basen_data *ndata = cb_data;

    if (ndata->state == BASEN_OPEN || ndata->state == BASEN_CLOSE_WAIT_DRAIN) {
	basen_start_timer(ndata, timeout);
    } else {
	ndata->timer_start_pending = true;
	ndata->pending_timer = *timeout;
    }
}

static void
basen_stop_timer_op(void *cb_data)
{
    struct basen_data *ndata = cb_data;

    if (ndata->state == BASEN_OPEN || ndata->state == BASEN_CLOSE_WAIT_DRAIN) {
	basen_stop_timer(ndata);
    }
}

static int
basen_call_child_control_op(struct basen_data *ndata,
			    struct gensio_filter_cb_control_data *ctrl)
{
    return gensio_control(ndata->child, ctrl->depth, ctrl->get, ctrl->option,
			  ctrl->data, ctrl->datalen);
}

static void
basen_filter_open_done(void *cb_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    if (ndata->state == BASEN_IN_FILTER_OPEN) {
	basen_filter_try_connect_finish(ndata, false);
	basen_set_ll_enables(ndata);
    }
    basen_unlock(ndata);
}

static void
basen_filter_input_ready(void *cb_data)
{
    struct basen_data *ndata = cb_data;

    basen_lock(ndata);
    basen_set_ll_enables(ndata);
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
	basen_start_timer_op(cb_data, data);
	return 0;

    case GENSIO_FILTER_CB_STOP_TIMER:
	basen_stop_timer_op(cb_data);
	return 0;

    case GENSIO_FILTER_CB_CONTROL:
	basen_call_child_control_op(cb_data, data);
	return 0;

    case GENSIO_FILTER_CB_OPEN_DONE:
	basen_filter_open_done(cb_data);
	return 0;

    case GENSIO_FILTER_CB_INPUT_READY:
	basen_filter_input_ready(cb_data);
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
    ndata->io = gensio_data_alloc(o, cb, user_data, gensio_base_func,
				  child, typename, ndata);
    if (!ndata->io)
	goto out_nomem;
    ndata->child = child;
    gensio_set_is_client(ndata->io, is_client);
    gensio_ll_set_callback(ll, gensio_ll_base_cb, ndata);
    if (filter) {
	filter->ndata = ndata;
	gensio_filter_set_callback(filter, gensio_base_filter_cb, ndata);
    }

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

	/* This is not ideal, it should really return GE_NOMEM. */
	if (!open_done)
	    goto out_nomem;

	ndata->open_done = open_done;
	ndata->open_data = open_data;
    }

    if (ndata->child) {
	if (gensio_is_reliable(ndata->child))
	    gensio_set_is_reliable(ndata->io, true);
	if (gensio_is_authenticated(ndata->child))
	    gensio_set_is_authenticated(ndata->io, true);
	if (gensio_is_encrypted(ndata->child))
	    gensio_set_is_encrypted(ndata->io, true);
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

int
base_gensio_server_start(struct gensio *io)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);
    int err;

    basen_lock(ndata);
    basen_set_state(ndata, BASEN_IN_FILTER_OPEN);
    err = basen_filter_try_connect(ndata, false);
    if (!err) {
	err = basen_filter_ul_push(ndata, true);
	if (!err) {
	    /* We are fully open, schedule it. */
	    basen_set_state(ndata, BASEN_OPEN);
	    ndata->deferred_open = true;
	    basen_sched_deferred_op(ndata);
	}
    } else if (err == GE_INPROGRESS) {
	err = basen_filter_ul_push(ndata, true);
    } else {
	basen_set_state(ndata, BASEN_CLOSED);
	err = GE_NOMEM;
	goto out_unlock;
    }
    basen_ref(ndata); /* For the open. */
    basen_set_ll_enables(ndata);

 out_unlock:
    basen_unlock(ndata);

    return err;
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
gensio_filter_ul_can_write(struct gensio_filter *filter)
{
    bool val = true;
    int err;

    /* If not implemented, this will just be ignored. */
    err = filter->func(filter, GENSIO_FILTER_FUNC_UL_CAN_WRITE,
		       NULL, &val, NULL, NULL, NULL, 0, NULL);
    if (err)
	return filter->ndata->ll_can_write;
    return val;
}

bool
gensio_filter_ll_write_queued(struct gensio_filter *filter)
{
    bool val = true;
    int rv;

    /* If not implemented, this will just be ignored. */
    rv = filter->func(filter, GENSIO_FILTER_FUNC_LL_WRITE_QUEUED,
		      NULL, &val, NULL, NULL, NULL, 0, NULL);
    if (rv)
	return gensio_filter_ll_write_pending(filter);
    return val;
}

void
gensio_filter_io_err(struct gensio_filter *filter, int err)
{
    filter->func(filter, GENSIO_FILTER_FUNC_IO_ERR,
		 NULL, &err, NULL, NULL, NULL, 0, NULL);
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
			  gensio_time *timeout,
			  bool was_timeout)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_TRY_CONNECT,
			NULL, timeout, NULL, NULL, NULL, was_timeout, NULL);
}

int
gensio_filter_try_disconnect(struct gensio_filter *filter,
			     gensio_time *timeout,
			     bool was_timeout)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_TRY_DISCONNECT,
			NULL, timeout, NULL, NULL, NULL, was_timeout, NULL);
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

int
gensio_filter_timeout(struct gensio_filter *filter)
{
    return filter->func(filter, GENSIO_FILTER_FUNC_TIMEOUT,
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

struct gensio_ll *
base_gensio_get_ll(struct gensio *io)
{
    struct basen_data *ndata = gensio_get_gensio_data(io);

    return ndata->ll;
}
