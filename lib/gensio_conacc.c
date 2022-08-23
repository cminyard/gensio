/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code creates a gensio accepter that make a gensio connection. */

#include "config.h"
#include <assert.h>
#include <gensio/gensio.h>
#include <gensio/gensio_time.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_base.h>

enum conaccn_state {
    CONACCN_CLOSED,
    CONACCN_IN_OPEN,
    CONACCN_OPEN,
    CONACCN_IN_CLOSE
};

struct conaccna_data;

struct conaccn_data {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    struct conaccna_data *nadata;
    enum conaccn_state child_state;

    struct gensio *io;
    gensio_event cb;
    void *user_data;

    struct gensio *child;

    bool in_close;
    gensio_done close_done;
    void *close_data;

    unsigned int refcount;
};

enum conaccna_state {
    /*
     * Events of concern:
     *  From the user:
     *   startup
     *   shutdown
     *   cb_enable
     *   cb_disable
     *  Internal:
     *   timeout
     *   open failed
     *   open succeeded
     *   ndata closed
     *   deferred op
     *   stop timer done
     *
     * Variables of concern:
     *   retry_timeout
     *   enabled
     */

    /*
     * Starting state, or state when shutdown completes.
     *
     * startup:
     *   !enabled: -> CONACCNA_DISABLED
     *   enabled:
     *     ndata open: -> CONACCNA_READY
     *     ndata not open:
     *       open no error: -> CONACCNA_OPENING
     *       open error:
     *         retry_timeout == 0: -> return error
     *         retry_timeout != 0: -> CONACCNA_WAITING_RETRY
     *
     * cb_enable: enabled = true
     *
     * cb_disable: enabled = false
     */
    CONACCNA_SHUTDOWN,

    /*
     * started, but disabled
     *
     * cb_enable:
     *   ndata open: -> CONACCNA_READY
     *   ndata not open:
     *     open no error: -> CONACCNA_OPENING, enabled_cb = cb
     *     open error:
     *        retry_timeout == 0: -> return error
     *        retry_timeout != 0: -> CONACCNA_WAITING_RETRY
     *
     * cb_disable: do nothing
     *
     * shutdown: -> CONACCNA_IN_SHUTDOWN, start deferred op
     */
    CONACCNA_DISABLED, /* Started, but disabled. */

    /*
     * ndata is being opened.
     *
     * shutdown: -> CONACCNA_OPEN_SHUTDOWN
     *
     * cb_enable: do nothing
     *
     * cb_disable: -> CONACCNA_OPEN_DISABLE
     *
     * open failed:
     *   retry_timeout == 0: -> CONACCNA_DEAD
     *   retry_timeout != 0: -> CONACCNA_WAITING_RETRY, start timer
     *
     * open succeeded: -> CONACCNA_READY
     */
    CONACCNA_OPENING,

    /*
     * ndata is open.
     *
     * shutdown: -> CONACC_IN_SHUTDOWN, start deferred op
     *
     * cb_enable: do nothing
     *
     * cb_disable: -> CONACC_IN_DISABLE, start deferred op
     *
     * ndata closed:
     *   retry_timeout != 0: -> CONACCNA_WAITING_RETRY, start timer
     *   retry_timeout == 0:
     *     open no error: -> CONACCNA_OPENING, enabled_cb = cb
     *     open error: start timer
     */
    CONACCNA_READY,

    /*
     * Timer is running waiting to retry the open.
     *
     * timeout:
     *   open no error: -> CONACCNA_OPENING
     *   open error: -> CONACCNA_WAITING_RETRY, start timer
     *
     * shutdown:
     *   -> CONACCNA_IN_SHUTDOWN
     *   stop timer failed: start deferred op
     *   stop timer succeeded: do nothing
     *
     * cb_enable: do nothing
     *
     * cb_disable:
     *   -> CONACC_IN_DISABLE,
     *   stop timer failed: start deferred op
     *   stop timer succeeded: do nothing
     */
    CONACCNA_WAITING_RETRY,

    /*
     * Got a shutdown while opening.
     *
     * open failed: -> CONACCNA_SHUTDOWN
     *
     * open succeeded: -> CONACCNA_SHUTDOWN
     *
     * cb_enable: enabled = true
     *
     * cb_disable: enabled = false
     */
    CONACCNA_OPEN_SHUTDOWN,

    /*
     * Waiting for timer cancel or deferred op to shut down.
     *
     * cb_enable: enabled = true
     *
     * cb_disable: enabled = false
     *
     * stop timer done: -> CONACCNA_SHUTDOWN
     *
     * deferred op: -> CONACCNA_SHUTDOWN
     */
    CONACCNA_IN_SHUTDOWN,

    /*
     * Got a disable while opening.
     *
     * shutdown: -> CONACCNA_OPEN_SHUTDOWN
     *
     * open failed: -> CONACCNA_DISABLED
     *
     * open succeeded: -> CONACCNA_DISABLED
     *
     * cb_enable: -> CONACCNA_OPENING, enabled = true
     *
     * cb_disable: do nothing
     */
    CONACCNA_OPEN_DISABLE,

    /*
     * Currently being disabled.
     *
     * shutdown: -> CONACCNA_IN_SHUTDOWN
     *
     * cb_enable: -> CONACCNA_IN_DISABLE_RESTART, enabled = true
     *
     * cb_disable: do nothing
     *
     * (timeout, stop timer done, deferred op): -> CONACCNA_DISABLED
     */
    CONACCNA_IN_DISABLE,

    /*
     * In disable, re-enable when disable done.
     *
     * shutdown: -> CONACCNA_IN_SHUTDOWN, start deferred op
     *
     * cb_enable: do nothing
     *
     * cb_disable: -> CONACC_IN_DISABLE, enabled = false
     *
     * (timeout, stop timer done, deferred op):
     *   ndata open: -> CONACCNA_READY
     *   ndata not open:
     *     open no error: -> CONACCNA_OPENING
     *     open error:
     *        retry_timeout == 0: -> CONACCNA_DEAD
     *        retry_timeout != 0: -> CONACCNA_WAITING_RETRY
     */
    CONACCNA_IN_DISABLE_RESTART,

    /*
     * Got an error on open.
     *
     * shutdown: -> CONACCNA_IN_SHUTDOWN, start deferred op
     *
     * cb_enable: enabled = true
     *
     * cb_disable: enabled = false
     */
    CONACCNA_DEAD /* Got an error from the start and no retry. */
};

struct conaccna_data {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    struct gensio_accepter *acc;

    struct conaccn_data *ndata;

    struct gensio_timer *retry_timer;
    struct gensio_time retry_time;

    bool deferred_op_pending;
    struct gensio_runner *deferred_runner;

    gensio_acc_done enabled_done;

    gensio_acc_done shutdown_done;

    bool enabled; /* accepter enable/disable state */

    enum conaccna_state state;

    /* Set when an error happens to report it back to the accepter log. */
    int con_err;

    /* Used to start the child gensio. */
    char *gensio_str;

    unsigned int refcount;
};

static void conacc_start(struct conaccna_data *nadata);
static void start_retry(struct conaccna_data *nadata);

static void
conaccn_lock(struct conaccn_data *ndata)
{
    ndata->o->lock(ndata->lock);
}

static void
conaccn_unlock(struct conaccn_data *ndata)
{
    ndata->o->unlock(ndata->lock);
}

static void
conaccn_ref(struct conaccn_data *ndata)
{
    assert(ndata->refcount > 0);
    ndata->refcount++;
}

static void
conaccn_finish_free(struct conaccn_data *ndata)
{
    struct gensio_os_funcs *o = ndata->o;

    if (ndata->io)
	gensio_data_free(ndata->io);
    if (ndata->child)
	gensio_free(ndata->child);
    if (ndata->lock)
	o->free_lock(ndata->lock);
    o->free(o, ndata);
}

static void
conaccn_deref_and_unlock(struct conaccn_data *ndata)
{
    assert(ndata->refcount > 0);
    ndata->refcount--;
    if (ndata->refcount == 0) {
	conaccn_unlock(ndata);
	conaccn_finish_free(ndata);
    } else {
	conaccn_unlock(ndata);
    }
}

static void
conaccna_lock(struct conaccna_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
conaccna_unlock(struct conaccna_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void
conaccna_ref(struct conaccna_data *nadata)
{
    assert(nadata->refcount > 0);
    nadata->refcount++;
}

static void
conaccna_finish_free(struct conaccna_data *nadata)
{
    struct gensio_os_funcs *o = nadata->o;

    if (nadata->gensio_str)
	o->free(o, nadata->gensio_str);
    if (nadata->deferred_runner)
	o->free_runner(nadata->deferred_runner);
    if (nadata->retry_timer)
	o->free_timer(nadata->retry_timer);
    if (nadata->lock)
	o->free_lock(nadata->lock);
    o->free(o, nadata);
}

static void
conaccna_deref(struct conaccna_data *nadata)
{
    /* Can only be called if this is not the final deref.  Must hold lock. */
    assert(nadata->refcount > 1);
    nadata->refcount--;
}

static void
conaccna_deref_and_unlock(struct conaccna_data *nadata)
{
    assert(nadata->refcount > 0);
    nadata->refcount--;
    if (nadata->refcount == 0) {
	conaccna_unlock(nadata);
	conaccna_finish_free(nadata);
    } else {
	conaccna_unlock(nadata);
    }
}

/* Releases the lock and re-acquires it. */
static void
conaccna_call_enabled(struct conaccna_data *nadata)
{
    gensio_acc_done done;

    if (nadata->enabled_done) {
	done = nadata->enabled_done;
	nadata->enabled_done = NULL;
	conaccna_unlock(nadata);
	done(nadata->acc, NULL);
	conaccna_lock(nadata);
    }
}

static void
conaccna_finish_shutdown(struct conaccna_data *nadata)
{
    gensio_acc_done done;

    conaccna_call_enabled(nadata);
    nadata->state = CONACCNA_SHUTDOWN;
    if (nadata->shutdown_done) {
	done = nadata->shutdown_done;
	nadata->shutdown_done = NULL;
	conaccna_unlock(nadata);
	done(nadata->acc, NULL);
	conaccna_lock(nadata);
    }
}

static void
conaccna_do_deferred(struct gensio_runner *runner, void *cb_data)
{
    struct conaccna_data *nadata = cb_data;

    conaccna_lock(nadata);
    nadata->deferred_op_pending = false;

    conaccna_call_enabled(nadata);

    switch (nadata->state) {
    case CONACCNA_SHUTDOWN:
    case CONACCNA_OPENING:
    case CONACCNA_READY:
    case CONACCNA_WAITING_RETRY:
    case CONACCNA_OPEN_SHUTDOWN:
    case CONACCNA_OPEN_DISABLE:
    case CONACCNA_DISABLED:
	break;

    case CONACCNA_IN_SHUTDOWN:
	conaccna_finish_shutdown(nadata);
	break;

    case CONACCNA_IN_DISABLE:
	nadata->state = CONACCNA_DISABLED;
	break;

    case CONACCNA_IN_DISABLE_RESTART:
	conacc_start(nadata);
	break;

    case CONACCNA_DEAD:
	if (nadata->con_err) {
	    int err = nadata->con_err;

	    nadata->con_err = 0;
	    conaccna_unlock(nadata);
	    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
			   "Error opening gensio: %s", gensio_err_to_str(err));
	    conaccna_lock(nadata);
	}
	break;
    }
    conaccna_deref_and_unlock(nadata);
}

static void
conaccna_deferred_op(struct conaccna_data *nadata)
{
    if (!nadata->deferred_op_pending) {
	nadata->deferred_op_pending = true;
	conaccna_ref(nadata);
	nadata->o->run(nadata->deferred_runner);
    }
}

static void
conaccn_finish_close(struct conaccn_data *ndata)
{
    struct conaccna_data *nadata = ndata->nadata;

    ndata->child_state = CONACCN_CLOSED;
    if (nadata) {
	conaccna_lock(nadata);
	nadata->ndata = NULL;
	switch (nadata->state) {
	case CONACCNA_SHUTDOWN:
	case CONACCNA_DISABLED:
	case CONACCNA_OPENING:
	case CONACCNA_WAITING_RETRY:
	case CONACCNA_OPEN_SHUTDOWN:
	case CONACCNA_IN_SHUTDOWN:
	case CONACCNA_OPEN_DISABLE:
	case CONACCNA_IN_DISABLE:
	case CONACCNA_IN_DISABLE_RESTART:
	case CONACCNA_DEAD:
	    break;

	case CONACCNA_READY:
	    if (!gensio_time_is_zero(nadata->retry_time))
		start_retry(nadata);
	    else
		conacc_start(nadata);
	}
	conaccna_deref_and_unlock(nadata);
    }
}

static void
conaccn_close_done(struct gensio *child_io, void *close_cb_data)
{
    struct conaccn_data *ndata = close_cb_data;
    gensio_done close_done;
    void *close_data;

    conaccn_lock(ndata);
    close_done = ndata->close_done;
    close_data = ndata->close_data;
    ndata->close_done = NULL;
    conaccn_unlock(ndata);
    if (close_done)
	close_done(ndata->io, close_data);
    conaccn_lock(ndata);
    conaccn_finish_close(ndata);
    conaccn_deref_and_unlock(ndata);
}

static int
i_conaccn_close(struct conaccn_data *ndata,
		gensio_done close_done, void *close_data)
{
    int err = 0;

    if (ndata->in_close || !ndata->child)
	return GE_NOTREADY;
    ndata->child_state = CONACCN_IN_CLOSE;
    err = gensio_close(ndata->child, conaccn_close_done, ndata);
    if (err) {
	conaccn_finish_close(ndata);
    } else {
	/* Note that we are using the ref owned by open. */
	conaccn_ref(ndata);
	ndata->close_done = close_done;
	ndata->close_data = close_data;
    }

    return err;
}

static int
conaccn_close(struct conaccn_data *ndata,
	      gensio_done close_done, void *close_data)
{
    int err;

    conaccn_lock(ndata);
    err = i_conaccn_close(ndata, close_done, close_data);
    conaccn_unlock(ndata);

    return err;
}

static void
conaccn_free(struct conaccn_data *ndata)
{
    conaccn_lock(ndata);
    switch (ndata->child_state) {
    case CONACCN_IN_OPEN:
    case CONACCN_OPEN:
	i_conaccn_close(ndata, NULL, NULL);
	/*
	 * If close returns an error, it won't grab a refcount and the
	 * below deref will free it.  Otherwise the deref in the close
	 * callback will free it.
	 */
	break;

    case CONACCN_CLOSED:
    case CONACCN_IN_CLOSE:
	/* Nothing to do except the deref below. */
	break;
    }
    conaccn_deref_and_unlock(ndata);
}

static void
conaccn_disable(struct conaccn_data *ndata)
{
    struct conaccna_data *nadata;

    conaccn_lock(ndata);
    ndata->child_state = CONACCN_CLOSED;
    gensio_disable(ndata->child);
    nadata = ndata->nadata;
    ndata->nadata = NULL;
    if (nadata) {
	conaccna_lock(nadata);
	nadata->ndata = NULL;
	if (!gensio_time_is_zero(nadata->retry_time))
	    start_retry(nadata);
	else
	    conacc_start(nadata);
	conacc_start(nadata);
	conaccna_unlock(nadata);
    }
    conaccn_unlock(ndata);
}

static int
conaccn_func(struct gensio *io, int func, gensiods *count,
	     const void *cbuf, gensiods buflen, void *buf,
	     const char *const *auxdata)
{
    struct conaccn_data *ndata = gensio_get_gensio_data(io);

    switch (func) {
    case GENSIO_FUNC_OPEN:
	return GE_NOTSUP;

    case GENSIO_FUNC_CLOSE:
	return conaccn_close(ndata, (void *) cbuf, buf);

    case GENSIO_FUNC_FREE:
	conaccn_free(ndata);
	return 0;

    case GENSIO_FUNC_DISABLE:
	conaccn_disable(ndata);
	return 0;

    default:
	/* Everything but the above just passes through. */
	return gensio_call_func(ndata->child,
				func, count, cbuf, buflen, buf, auxdata);
    }
}

static int
conaccn_event(struct gensio *io, void *user_data,
	      int event, int err,
	      unsigned char *buf, gensiods *buflen,
	      const char *const *auxdata)
{
    struct conaccn_data *ndata = user_data;

    if (!ndata->io)
	return GE_NOTSUP;

    /* All events just pass through. */
    return gensio_cb(ndata->io, event, err, buf, buflen, auxdata);
}

/* Called with the lock held. */
static void
start_retry(struct conaccna_data *nadata)
{
    struct gensio_os_funcs *o = nadata->o;

    nadata->state = CONACCNA_WAITING_RETRY;
    if (o->start_timer(nadata->retry_timer, &nadata->retry_time) != 0)
	assert(0);
    conaccna_ref(nadata);
}

static void
conaccn_open_done(struct gensio *io, int err, void *open_data)
{
    struct conaccn_data *ndata = open_data;
    struct conaccna_data *nadata = ndata->nadata;

    if (err)
	goto out_err;

    ndata->io = gensio_data_alloc(nadata->o, NULL, NULL,
				  conaccn_func, ndata->child,
				  "conacc", ndata);
    if (!ndata->io) {
	err = GE_NOMEM;
	goto out_err;
    }

    err = base_gensio_accepter_new_child_start(nadata->acc);
    if (err)
	goto out_err;
    gensio_set_attr_from_child(ndata->io, ndata->child);
    ndata->child_state = CONACCN_OPEN;
    base_gensio_accepter_new_child_end(nadata->acc, ndata->io, err);

 out_err:
    conaccna_lock(nadata);
    switch (nadata->state) {
    case CONACCNA_SHUTDOWN:
    case CONACCNA_DISABLED:
    case CONACCNA_READY:
    case CONACCNA_WAITING_RETRY:
    case CONACCNA_IN_SHUTDOWN:
    case CONACCNA_DEAD:
    case CONACCNA_IN_DISABLE:
    case CONACCNA_IN_DISABLE_RESTART:
	assert(0);
	break;

    case CONACCNA_OPENING:
	if (err) {
	    if (!gensio_time_is_zero(nadata->retry_time)) {
		start_retry(nadata);
	    } else {
		nadata->con_err = err;
		nadata->state = CONACCNA_DEAD;
		conaccna_deferred_op(nadata);
	    }
	    goto out_cleanup;
	}
	nadata->state = CONACCNA_READY;
	break;

    case CONACCNA_OPEN_SHUTDOWN:
	conaccna_finish_shutdown(nadata);
	goto out_cleanup;

    case CONACCNA_OPEN_DISABLE:
	nadata->state = CONACCNA_DISABLED;
	goto out_cleanup;
    }
    conaccna_unlock(nadata);

    /* Keep the nadata ref for the open child. */

    base_gensio_server_open_done(nadata->acc, ndata->io, 0);
    return;

 out_cleanup:
    if (!err) {
	err = GE_NOTREADY;
	base_gensio_server_open_done(nadata->acc, ndata->io, err);
    }
    conaccn_finish_free(ndata);
    conaccna_deref_and_unlock(nadata);
}

static void
conacc_start(struct conaccna_data *nadata)
{
    struct conaccn_data *ndata;
    int err = GE_NOMEM;

    if (nadata->ndata) {
	nadata->state = CONACCNA_READY;
	return;
    }

    nadata->state = CONACCNA_OPENING;

    ndata = nadata->o->zalloc(nadata->o, sizeof(*ndata));
    if (!ndata)
	goto out_err_nofree;
    ndata->o = nadata->o;
    ndata->nadata = nadata;
    ndata->refcount = 1;
    ndata->lock = nadata->o->alloc_lock(nadata->o);
    if (!ndata->lock)
	goto out_err;

    err = str_to_gensio(nadata->gensio_str, ndata->o, conaccn_event, ndata,
			&ndata->child);
    if (err)
	goto out_err;

    nadata->ndata = ndata;
    conaccna_ref(nadata);
    ndata->child_state = CONACCN_IN_OPEN;
    err = gensio_open(ndata->child, conaccn_open_done, ndata);
    if (err) {
	nadata->ndata = NULL;
	conaccna_deref(nadata);
	goto out_err;
    }
    return;

 out_err:
    conaccn_finish_free(ndata);
 out_err_nofree:
    if (!gensio_time_is_zero(nadata->retry_time)) {
	start_retry(nadata);
    } else {
	nadata->state = CONACCNA_DEAD;
	nadata->con_err = err;
	conaccna_deferred_op(nadata);
    }
}

static void
conaccna_retry_timeout(struct gensio_timer *t, void *cb_data)
{
    struct conaccna_data *nadata = cb_data;

    conaccna_lock(nadata);
    switch (nadata->state) {
    case CONACCNA_SHUTDOWN:
    case CONACCNA_DISABLED:
    case CONACCNA_OPENING:
    case CONACCNA_READY:
    case CONACCNA_OPEN_SHUTDOWN:
    case CONACCNA_OPEN_DISABLE:
    case CONACCNA_DEAD:
	assert(0);

    case CONACCNA_IN_SHUTDOWN:
	conaccna_finish_shutdown(nadata);
	break;

    case CONACCNA_IN_DISABLE_RESTART:
    case CONACCNA_WAITING_RETRY:
	conacc_start(nadata);
	break;

    case CONACCNA_IN_DISABLE:
	nadata->state = CONACCNA_DISABLED;
	break;
    }
    conaccna_deref_and_unlock(nadata);
}

static void
retry_timer_done(struct gensio_timer *t, void *cb_data)
{
    struct conaccna_data *nadata = cb_data;

    conaccna_lock(nadata);
    switch (nadata->state) {
    case CONACCNA_SHUTDOWN:
    case CONACCNA_DISABLED:
    case CONACCNA_OPENING:
    case CONACCNA_READY:
    case CONACCNA_WAITING_RETRY:
    case CONACCNA_OPEN_SHUTDOWN:
    case CONACCNA_OPEN_DISABLE:
    case CONACCNA_DEAD:
	assert(0);
	break;

    case CONACCNA_IN_SHUTDOWN:
	conaccna_finish_shutdown(nadata);
	break;

    case CONACCNA_IN_DISABLE:
	nadata->state = CONACCNA_DISABLED;
	conaccna_call_enabled(nadata);
	break;

    case CONACCNA_IN_DISABLE_RESTART:
	conacc_start(nadata);
	break;

    default:
	assert(0);
    }
    conaccna_deref_and_unlock(nadata);
}

static int
conaccna_startup(struct gensio_accepter *accepter,
		 struct conaccna_data *nadata)
{
    int rv = 0;

    conaccna_lock(nadata);
    if (nadata->state == CONACCNA_SHUTDOWN) {
	nadata->con_err = 0;
	if (!nadata->enabled)
	    nadata->state = CONACCNA_DISABLED;
	else {
	    conacc_start(nadata);
	    if (nadata->state == CONACCNA_DEAD) {
		nadata->state = CONACCNA_SHUTDOWN;
		rv = nadata->con_err;
		nadata->con_err = 0;
	    }
	}
    } else {
	rv = GE_NOTREADY;
    }
    conaccna_unlock(nadata);

    return rv;
}

static int
conaccna_shutdown(struct gensio_accepter *accepter,
		  struct conaccna_data *nadata,
		  gensio_acc_done shutdown_done)
{
    struct gensio_os_funcs *o = nadata->o;
    int rv = 0, err;

    conaccna_lock(nadata);
    switch (nadata->state) {
    case CONACCNA_SHUTDOWN:
    case CONACCNA_OPEN_SHUTDOWN:
    case CONACCNA_IN_SHUTDOWN:
	rv = GE_NOTREADY;
	break;

    case CONACCNA_OPENING:
	/* Let the shutdown happen when the open completes. */
	nadata->state = CONACCNA_OPEN_SHUTDOWN;
	break;

    case CONACCNA_READY:
	nadata->state = CONACCNA_IN_SHUTDOWN;
	conaccna_deferred_op(nadata);
	break;

    case CONACCNA_WAITING_RETRY:
	nadata->state = CONACCNA_IN_SHUTDOWN;
	err = o->stop_timer_with_done(nadata->retry_timer,
				      retry_timer_done, nadata);
	if (err == GE_TIMEDOUT) {
	    /* Done handler won't be called, run it in the deferred op. */
	    conaccna_deferred_op(nadata);
	} else if (!err) {
	    /* Done handler will be called. */
	} else {
	    /*
	     * We should not get GE_INUSE, that means there is already
	     * a stop in progress and the done handler will be called.
	     */
	    assert(0);
	}
	break;

    case CONACCNA_OPEN_DISABLE:
	nadata->state = CONACCNA_OPEN_SHUTDOWN;
	break;

    case CONACCNA_IN_DISABLE:
	nadata->state = CONACCNA_IN_SHUTDOWN;
	break;

    case CONACCNA_IN_DISABLE_RESTART:
	nadata->state = CONACCNA_IN_SHUTDOWN;
	conaccna_deferred_op(nadata);
	break;

    case CONACCNA_DISABLED:
    case CONACCNA_DEAD:
	nadata->state = CONACCNA_IN_SHUTDOWN;
	conaccna_deferred_op(nadata);
	break;
    }
    if (!rv)
	nadata->shutdown_done = shutdown_done;
    conaccna_unlock(nadata);

    return rv;
}

static int
conaccna_set_accept_callback_enable(struct gensio_accepter *accepter,
				    struct conaccna_data *nadata,
				    bool enabled,
				    gensio_acc_done done)
{
    int rv = 0, err;
    bool do_deferred = true;

    conaccna_lock(nadata);
    if (nadata->enabled_done) {
	rv = GE_INUSE;
	goto out_unlock;
    }
    switch (nadata->state) {
    case CONACCNA_SHUTDOWN:
    case CONACCNA_DEAD:
    case CONACCNA_OPEN_SHUTDOWN:
    case CONACCNA_IN_SHUTDOWN:
	break;

    case CONACCNA_DISABLED:
	if (enabled) {
	    conacc_start(nadata);
	    if (nadata->state == CONACCNA_DEAD) {
		nadata->state = CONACCNA_SHUTDOWN;
		rv = nadata->con_err;
		nadata->con_err = 0;
	    }
	}
	break;

    case CONACCNA_OPENING:
	if (!enabled)
	    nadata->state = CONACCNA_OPEN_DISABLE;
	break;

    case CONACCNA_READY:
	nadata->state = CONACCNA_IN_DISABLE;
	break;

    case CONACCNA_WAITING_RETRY:
	if (!enabled) {
	    nadata->state = CONACCNA_IN_DISABLE;
	    err = nadata->o->stop_timer_with_done(nadata->retry_timer,
						  retry_timer_done, nadata);
	    if (err == GE_TIMEDOUT) {
		/* Done handler won't be called, run it in the deferred op. */
	    } else if (!err) {
		/* Done handler will be called. */
		do_deferred = false;
	    } else {
		/*
		 * We should not get GE_INUSE, that means there is already
		 * a stop in progress and the done handler will be called.
		 */
		assert(0);
	    }
	}
	break;

    case CONACCNA_OPEN_DISABLE:
	if (enabled)
	    nadata->state = CONACCNA_OPENING;
	break;

    case CONACCNA_IN_DISABLE:
	if (enabled)
	    nadata->state = CONACCNA_IN_DISABLE_RESTART;
	break;

    case CONACCNA_IN_DISABLE_RESTART:
	if (!enabled)
	    nadata->state = CONACCNA_IN_DISABLE;
	break;
    }
    if (!rv) {
	nadata->enabled = enabled;
	nadata->enabled_done = done;
	if (do_deferred)
	    conaccna_deferred_op(nadata);
    }

 out_unlock:
    conaccna_unlock(nadata);

    return 0;
}

static void
conaccna_free(struct gensio_accepter *accepter,
	      struct conaccna_data *nadata)
{
    conaccna_lock(nadata);
    conaccna_deref_and_unlock(nadata);
}

static void
conaccna_disable(struct gensio_accepter *accepter,
		 struct conaccna_data *nadata)
{
    conaccna_lock(nadata);
    nadata->state = CONACCNA_DEAD;
    conaccna_unlock(nadata);
}

static int
conaccna_control(struct gensio_accepter *accepter, struct conaccna_data *nadata,
		 bool get, unsigned int option, char *data, gensiods *datalen)
{
    int err;
    int iooption;

    switch (option) {
    case GENSIO_ACC_CONTROL_LADDR:
	iooption = GENSIO_CONTROL_LADDR;
	break;

    case GENSIO_ACC_CONTROL_LPORT:
	iooption = GENSIO_CONTROL_LPORT;
	break;

    default:
	return GE_NOTSUP;
    }

    conaccna_lock(nadata);
    if (!nadata->ndata || !nadata->ndata->child) {
	err = GE_NOTREADY;
    } else {
	err = gensio_control(nadata->ndata->child, GENSIO_CONTROL_DEPTH_FIRST,
			     get, iooption, data, datalen);
    }
    conaccna_unlock(nadata);
    return err;
}

static int
conacc_base_acc_op(struct gensio_accepter *acc, int func,
		   void *acc_op_data, void *done, int val1,
		   void *data, void *data2, void *ret)
{
    switch (func) {
    case GENSIO_BASE_ACC_STARTUP:
	return conaccna_startup(acc, acc_op_data);

    case GENSIO_BASE_ACC_SHUTDOWN:
	return conaccna_shutdown(acc, acc_op_data, done);

    case GENSIO_BASE_ACC_SET_CB_ENABLE:
	return conaccna_set_accept_callback_enable(acc, acc_op_data,
						   val1, done);

    case GENSIO_BASE_ACC_FREE:
	conaccna_free(acc, acc_op_data);
	return 0;

    case GENSIO_BASE_ACC_DISABLE:
	conaccna_disable(acc, acc_op_data);
	return 0;

    case GENSIO_BASE_ACC_CONTROL:
	return conaccna_control(acc, acc_op_data,
				val1, *((unsigned int *) done), data, ret);

    default:
	return GE_NOTSUP;
    }
}

static int
conacc_gensio_accepter_alloc(const void *gdata,
			     const char * const args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb, void *user_data,
			     struct gensio_accepter **accepter)
{
    const char *gensio_str = gdata;
    struct conaccna_data *nadata;
    unsigned int i;
    struct gensio_time retry_time = { 0, 0 };
    int err;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keytime(args[i], "retry-time", 'm', &retry_time) > 0)
	    continue;
	return GE_INVAL;
    }

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;
    nadata->o = o;
    nadata->enabled = true;
    nadata->refcount = 1;
    nadata->retry_time = retry_time;

    nadata->gensio_str = gensio_strdup(o, gensio_str);
    if (!nadata->gensio_str)
	goto out_nomem;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    nadata->retry_timer = o->alloc_timer(o, conaccna_retry_timeout, nadata);
    if (!nadata->retry_timer)
	goto out_nomem;

    nadata->deferred_runner = o->alloc_runner(o, conaccna_do_deferred, nadata);
    if (!nadata->deferred_runner)
	goto out_nomem;

    err = base_gensio_accepter_alloc(NULL, conacc_base_acc_op, nadata,
				     o, "conacc", cb, user_data, accepter);
    if (err)
	goto out_err;
    nadata->acc = *accepter;

    /* FIXME - how to set gensio_acc attributes (reliable, etc.) */
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    conaccna_finish_free(nadata);
    return err;
}

static int
str_to_conacc_gensio_accepter(const char *str, const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **acc)
{
    return conacc_gensio_accepter_alloc(str, args, o, cb, user_data, acc);
}

int
gensio_init_conacc(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio_accepter(o, "conacc", str_to_conacc_gensio_accepter,
				  conacc_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
