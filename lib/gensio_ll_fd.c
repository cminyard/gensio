/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <assert.h>
#include <stdio.h>

#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_err.h>
#include <gensio/gensio_ll_fd.h>

enum fd_state {
    /*
     * fd is not operational
     *
     * open -> FD_IN_OPEN (set fds)
     */
    FD_CLOSED,

    /*
     * An open has been requested, but is not yet complete.
     *
     * fd opened -> FD_OPEN
     * close -> FD_IN_CLOSE
     * err
     *   if retry_open() = do retry
     *    -> FD_IN_OPEN_RETRY (clear fds)
     *   else
     *    -> FD_OPEN_ERR_WAIT (clear fds)
     */
    FD_IN_OPEN,

    /*
     * An open has been requested, but is not yet complete.  We got an
     * open failure and we cleared the old handlers but the clear is
     * not finish yet.  When the clear is done, we will retry.
     *
     * fd cleared
     *   if open success
     *     -> FD_IN_OPEN (set fds)
     *   else
     *     -> FD_CLOSED (report open err)
     * close -> FD_IN_CLOSE
     * err -> FD_OPEN_ERR_WAIT
     */
    FD_IN_OPEN_RETRY,

    /*
     * The fd is operational
     *
     * close -> FD_IN_CLOSE
     * err -> FD_ERR_WAIT
     */
    FD_OPEN,

    /*
     * The fd is waiting close
     *
     * fd cleared -> FD_CLOSED
     * err -> ignore
     */
    FD_IN_CLOSE,

    /*
     * An error occurred during open.
     *
     * fd cleared -> FD_CLOSED (report open err)
     * close -> FD_IN_CLOSE (report open err)
     */
    FD_OPEN_ERR_WAIT,

    /*
     * An error occurred.
     *
     * close -> FD_IN_CLOSED
     * err -> ignore
     */
    FD_ERR_WAIT
};

#ifdef ENABLE_INTERNAL_TRACE
#define DEBUG_STATE
#endif

#ifdef DEBUG_STATE
struct fd_state_trace {
    enum fd_state old_state;
    enum fd_state new_state;
    int line;
};
#define STATE_TRACE_LEN 256
#endif

struct fd_ll {
    struct gensio_ll *ll;
    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    unsigned int refcount;

    gensio_ll_cb cb;
    void *cb_data;

    struct gensio_iod *iod;

    enum fd_state state;

    bool read_enabled;
    bool write_enabled;
    bool write_only;

    const struct gensio_fd_ll_ops *ops;
    void *handler_data;

    gensio_ll_open_done open_done;
    void *open_data;
    int open_err;

    struct gensio_timer *close_timer;
    gensio_ll_close_done close_done;
    void *close_data;
    bool close_requested;
    bool freed;

    unsigned char *read_data;
    gensiods read_data_size;
    gensiods read_data_len;
    gensiods read_data_pos;
    const char *const *auxdata;

    bool in_read;
    bool in_write;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

    bool deferred_open;
    bool deferred_read;
    bool deferred_close;
    bool deferred_except;

#ifdef DEBUG_STATE
    struct fd_state_trace trace[STATE_TRACE_LEN];
    unsigned int trace_pos;
#endif
};

#define ll_to_fd(v) ((struct fd_ll *) gensio_ll_get_user_data(v))

static void fd_handle_write_ready(struct fd_ll *fdll, struct gensio_iod *iod);

static void fd_finish_free(struct fd_ll *fdll)
{
    if (fdll->ll)
	gensio_ll_free_data(fdll->ll);
    if (fdll->lock)
	fdll->o->free_lock(fdll->lock);
    if (fdll->close_timer)
	fdll->o->free_timer(fdll->close_timer);
    if (fdll->deferred_op_runner)
	fdll->o->free_runner(fdll->deferred_op_runner);
    if (fdll->read_data)
	fdll->o->free(fdll->o, fdll->read_data);
    if (fdll->ops)
	fdll->ops->free(fdll->handler_data);
    fdll->o->free(fdll->o, fdll);
}

#ifdef DEBUG_STATE
static void
i_fd_add_trace(struct fd_ll *fdll, enum fd_state new_state, int line)
{
    fdll->trace[fdll->trace_pos].old_state = fdll->state;
    fdll->trace[fdll->trace_pos].new_state = new_state;
    fdll->trace[fdll->trace_pos].line = line;
    if (fdll->trace_pos == STATE_TRACE_LEN - 1)
	fdll->trace_pos = 0;
    else
	fdll->trace_pos++;
}
#define fd_add_trace(fdll, new_state) \
    i_fd_add_trace(fdll, new_state, __LINE__)

static void
i_fd_lock(struct fd_ll *fdll, int line)
{
    fdll->o->lock(fdll->lock);
    i_fd_add_trace(fdll, 1000 + fdll->refcount, line);
}
#define fd_lock(fdll) i_fd_lock(fdll, __LINE__)

static void
i_fd_unlock(struct fd_ll *fdll, int line)
{
    i_fd_add_trace(fdll, 1000 + fdll->refcount, line);
    fdll->o->unlock(fdll->lock);
}
#define fd_unlock(fdll) i_fd_unlock(fdll, __LINE__)

static void
i_fd_ref(struct fd_ll *fdll, int line)
{
    assert(fdll->refcount > 0);
    fdll->refcount++;
    i_fd_add_trace(fdll, 1000 + fdll->refcount, line);
}
#define fd_ref(fdll) i_fd_ref(fdll, __LINE__)

static void
i_fd_deref(struct fd_ll *fdll, int line)
{
    assert(fdll->refcount > 1);
    fdll->refcount--;
    i_fd_add_trace(fdll, 1000 + fdll->refcount, line);
}
#define fd_deref(fdll) i_fd_deref(fdll, __LINE__)

static void
i_fd_lock_and_ref(struct fd_ll *fdll, int line)
{
    i_fd_lock(fdll, line);
    assert(fdll->refcount > 0);
    fdll->refcount++;
}
#define fd_lock_and_ref(fdll) i_fd_lock_and_ref(fdll, __LINE__)

static void
i_fd_set_state(struct fd_ll *fdll, enum fd_state state, int line)
{
    i_fd_add_trace(fdll, state, line);
    fdll->state = state;
}
#define fd_set_state(fdll, state) i_fd_set_state(fdll, state, __LINE__)

static void
i_fd_deref_and_unlock(struct fd_ll *fdll, int line)
{
    unsigned int count;

    assert(fdll->refcount > 0);
    count = --fdll->refcount;
    i_fd_unlock(fdll, line);
    if (count == 0)
	fd_finish_free(fdll);
}
#define fd_deref_and_unlock(fdll) i_fd_deref_and_unlock(fdll, __LINE__)

#else /* DEBUG_STATE */

#define fd_add_trace(fdll, new_state)

static void
fd_lock(struct fd_ll *fdll)
{
    fdll->o->lock(fdll->lock);
}

static void
fd_unlock(struct fd_ll *fdll)
{
    fdll->o->unlock(fdll->lock);
}

static void
fd_ref(struct fd_ll *fdll)
{
    assert(fdll->refcount > 0);
    fdll->refcount++;
}

static void
fd_deref(struct fd_ll *fdll)
{
    assert(fdll->refcount > 1);
    fdll->refcount--;
}

static void
fd_lock_and_ref(struct fd_ll *fdll)
{
    fd_lock(fdll);
    assert(fdll->refcount > 0);
    fdll->refcount++;
}

static void
fd_set_state(struct fd_ll *fdll, enum fd_state state)
{
    fdll->state = state;
}

static void
fd_deref_and_unlock(struct fd_ll *fdll)
{
    unsigned int count;

    assert(fdll->refcount > 0);
    count = --fdll->refcount;
    fd_unlock(fdll);
    if (count == 0)
	fd_finish_free(fdll);
}
#endif /* DEBUG_STATE */

static void
fd_set_callbacks(struct gensio_ll *ll, gensio_ll_cb cb, void *cb_data)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    fdll->cb = cb;
    fdll->cb_data = cb_data;
}

gensiods
gensio_fd_ll_callback(struct gensio_ll *ll, int op, int val, void *buf,
		      gensiods buflen, const void *data)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    return fdll->cb(fdll->cb_data, op, val, buf, buflen, data);
}

static int
fd_write(struct gensio_ll *ll, gensiods *rcount,
	 const struct gensio_sg *sg, gensiods sglen,
	 const char *const *auxdata)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    if (fdll->ops->write)
	return fdll->ops->write(fdll->handler_data, fdll->iod,
				rcount, sg, sglen, auxdata);

    return fdll->o->write(fdll->iod, sg, sglen, rcount);
}

static void
fd_deliver_read_data(struct fd_ll *fdll, int err)
{
    if (err || fdll->read_data_len) {
	gensiods count;

    retry:
	fd_unlock(fdll);
	count = gensio_fd_ll_callback(fdll->ll, GENSIO_LL_CB_READ, err,
				      fdll->read_data + fdll->read_data_pos,
				      fdll->read_data_len, fdll->auxdata);
	fd_lock(fdll);
	if (err || count >= fdll->read_data_len) {
	    fdll->read_data_pos = 0;
	    fdll->read_data_len = 0;
	    fdll->auxdata = NULL;
	} else {
	    fdll->read_data_pos += count;
	    fdll->read_data_len -= count;
	    if (fdll->read_enabled)
		goto retry;
	}
    }
}

static void
fd_finish_open(struct fd_ll *fdll, int err)
{
    gensio_ll_open_done open_done = fdll->open_done;

    if (err)
	fd_set_state(fdll, FD_CLOSED);
    else
	fd_set_state(fdll, FD_OPEN);


    fdll->open_done = NULL;
    fd_unlock(fdll);
    open_done(fdll->cb_data, err, fdll->open_data);
    fd_lock(fdll);

    if (fdll->state == FD_OPEN) {
	if (fdll->read_enabled)
	    fdll->o->set_read_handler(fdll->iod, true);
	if (fdll->write_enabled)
	    fdll->o->set_write_handler(fdll->iod, true);
	fdll->o->set_except_handler(fdll->iod,
				    fdll->read_enabled || fdll->write_enabled);
    }
}

static void fd_finish_close(struct fd_ll *fdll)
{
    fd_set_state(fdll, FD_CLOSED);
    if (fdll->close_done) {
	gensio_ll_close_done close_done = fdll->close_done;

	fdll->close_done = NULL;
	fd_unlock(fdll);
	close_done(fdll->cb_data, fdll->close_data);
	fd_lock(fdll);
    }
    fd_deref(fdll);
}

static void
fd_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct fd_ll *fdll = cbdata;

    fd_lock(fdll);
    if (fdll->deferred_open) {
	fdll->deferred_open = false;
	fd_finish_open(fdll, fdll->open_err);
    }

    if (fdll->deferred_except && fdll->write_enabled) {
	fdll->deferred_except = false;
	if (fdll->iod)
	    fd_handle_write_ready(fdll, fdll->iod);
    }

    while (fdll->deferred_read) {
	fdll->deferred_read = false;

	fdll->in_read = true;
	while (fdll->read_enabled && fdll->read_data_len)
	    fd_deliver_read_data(fdll, 0);
	fdll->in_read = false;
    }

    if (fdll->deferred_close) {
	fdll->deferred_close = false;
	fd_finish_close(fdll);
    }

    fdll->deferred_op_pending = false;
    if (fdll->state == FD_OPEN) {
	fdll->o->set_read_handler(fdll->iod, fdll->read_enabled);
	fdll->o->set_except_handler(fdll->iod,
				    fdll->read_enabled || fdll->write_enabled);
	fdll->o->set_write_handler(fdll->iod, fdll->write_enabled);
    }
    fd_deref_and_unlock(fdll);
}

static void
fd_sched_deferred_op(struct fd_ll *fdll)
{
    if (!fdll->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	fd_ref(fdll);
	fdll->deferred_op_pending = true;
	fdll->o->run(fdll->deferred_op_runner);
    }
}

static void
fd_start_close(struct fd_ll *fdll)
{
    if (fdll->ops->check_close)
	fdll->ops->check_close(fdll->handler_data, fdll->iod,
			       GENSIO_LL_CLOSE_STATE_START, NULL);
    if (!fdll->iod) {
	fdll->deferred_close = true;
	fd_sched_deferred_op(fdll);
    } else if (fdll->state != FD_OPEN_ERR_WAIT &&
	       fdll->state != FD_IN_OPEN_RETRY) {
	fdll->o->clear_fd_handlers(fdll->iod);
    }
    fd_set_state(fdll, FD_IN_CLOSE);
}

static void
fd_handle_incoming(struct fd_ll *fdll,
		   int (*doread)(struct gensio_iod *iod, void *buf, gensiods count,
				 gensiods *rcount, const char ***auxdata,
				 void *cb_data),
		   const char **auxdata, void *cb_data)
{
    int err = 0;
    gensiods count;

    fd_lock_and_ref(fdll);
    if (fdll->in_read || fdll->state == FD_ERR_WAIT ||
		fdll->state == FD_OPEN_ERR_WAIT)
	goto out_disable;
    fdll->in_read = true;

    if (!fdll->read_data_len) {
	fd_unlock(fdll);
	err = doread(fdll->iod, fdll->read_data, fdll->read_data_size, &count,
		     &auxdata, cb_data);
	fd_lock(fdll);
	if (!err) {
	    fdll->read_data_len = count;
	    fdll->auxdata = auxdata;
	}
    }

    fd_deliver_read_data(fdll, err);

    if (err) {
	switch(fdll->state) {
	case FD_IN_OPEN:
	case FD_IN_OPEN_RETRY:
	case FD_OPEN_ERR_WAIT:
	case FD_CLOSED:
	    assert(0); /* Should not be possible. */
	    break;

	case FD_OPEN:
	    fdll->o->set_write_handler(fdll->iod, false);
	    fdll->o->set_except_handler(fdll->iod, false);
	    fd_set_state(fdll, FD_ERR_WAIT);
	    break;

	case FD_ERR_WAIT:
	case FD_IN_CLOSE:
	    break;
	}
    }
    fdll->in_read = false;
    /*
     * We could turn off read when there is pending data, but
     * if the user is doing their job right, it shouldn't matter.
     */
    if (fdll->state == FD_OPEN && fdll->read_enabled) {
	fdll->o->set_read_handler(fdll->iod, true);
	fdll->o->set_except_handler(fdll->iod, true);
    } else {
    out_disable:
	fdll->o->set_read_handler(fdll->iod, false);
	fdll->o->set_except_handler(fdll->iod, fdll->write_enabled);
    }
    fd_deref_and_unlock(fdll);
}

void gensio_fd_ll_handle_incoming(struct gensio_ll *ll,
				  int (*doread)(struct gensio_iod *iod, void *buf,
						gensiods count,
						gensiods *rcount,
						const char ***auxdata,
						void *cb_data),
				  const char **auxdata,
				  void *cb_data)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    fd_handle_incoming(fdll, doread, auxdata, cb_data);
}

static int
gensio_ll_fd_read(struct gensio_iod *iod, void *buf, gensiods count, gensiods *rcount,
		  const char ***auxdata, void *cb_data)
{
    return iod->f->read(iod, buf, count, rcount);
}

static void
fd_read_ready(struct gensio_iod *iod, void *cbdata)
{
    struct fd_ll *fdll = cbdata;

    if (fdll->ops->read_ready) {
	fdll->ops->read_ready(fdll->handler_data, fdll->iod);
	return;
    }

    fd_handle_incoming(fdll, gensio_ll_fd_read, NULL, fdll);
}

static int fd_setup_handlers(struct fd_ll *fdll);

static void
fd_handle_write_ready(struct fd_ll *fdll, struct gensio_iod *iod)
{
    if (fdll->state == FD_IN_OPEN) {
	int err;

	fdll->o->set_write_handler(iod, false);
	fdll->o->set_except_handler(iod, fdll->read_enabled);
	err = fdll->ops->check_open(fdll->handler_data, fdll->iod);
	/*
	 * The GE_NOMEM check is strange here, but it really has more
	 * to do with testing.  check_open() is not going to return
	 * GE_NOMEM unless it's an error trigger failure, and we really
	 * want to fail in that case or we will get a "error triggered
	 * but no failure" in the test.
	 */
	if (err && err != GE_NOMEM && fdll->ops->retry_open) {
	    fd_set_state(fdll, FD_IN_OPEN_RETRY);
	    fdll->o->clear_fd_handlers(fdll->iod);
	} else {
	    if (err) {
		fdll->open_err = err;
		fd_set_state(fdll, FD_OPEN_ERR_WAIT);
		fdll->o->clear_fd_handlers(fdll->iod);
	    } else {
		fd_finish_open(fdll, 0);
	    }
	}
    } else if (fdll->state == FD_OPEN && fdll->write_enabled &&
	       !fdll->in_write) {
	fdll->in_write = true;
	fd_unlock(fdll);

	if (fdll->ops->write_ready)
	    fdll->ops->write_ready(fdll->handler_data, fdll->iod);
	else
	    gensio_fd_ll_callback(fdll->ll, GENSIO_LL_CB_WRITE_READY, 0,
				  NULL, 0, NULL);
	fd_lock(fdll);
	fdll->in_write = false;
	if ((fdll->state == FD_OPEN || fdll->state == FD_IN_CLOSE) &&
		fdll->write_enabled) {
	    fdll->o->set_write_handler(fdll->iod, true);
	    fdll->o->set_except_handler(fdll->iod, true);
	} else {
	    fdll->o->set_write_handler(iod, false);
	    fdll->o->set_except_handler(iod, fdll->read_enabled);
	}
    } else {
	fdll->o->set_write_handler(iod, false);
	fdll->o->set_except_handler(iod, fdll->read_enabled);
    }
}

static void
fd_write_ready(struct gensio_iod *iod, void *cbdata)
{
    struct fd_ll *fdll = cbdata;

    fd_lock_and_ref(fdll);
    fd_handle_write_ready(fdll, iod);
    fd_deref_and_unlock(fdll);
}

static void
fd_except_ready(struct gensio_iod *iod, void *cbdata)
{
    struct fd_ll *fdll = cbdata;
    int rv = 0;

    fd_lock(fdll);
    /*
     * In some cases, if a connect() call fails, we get an exception,
     * not a write ready.  So in the open case, call write ready.
     */
    if (fdll->state == FD_IN_OPEN || fdll->state == FD_IN_OPEN_RETRY) {
	fd_ref(fdll);
	fd_handle_write_ready(fdll, iod);
	fd_deref_and_unlock(fdll);
    } else if (fdll->ops->except_ready) {
	fd_unlock(fdll);
	rv = fdll->ops->except_ready(fdll->handler_data, fdll->iod);
	if (rv) {
	    fd_lock(fdll);
	    goto handle_except_internal;
	}
    } else {
    handle_except_internal:
	if (fdll->read_enabled) {
	    fd_unlock(fdll);
	    fd_read_ready(iod, fdll);
	} else {
	    if (fdll->write_enabled)
		fd_handle_write_ready(fdll, iod);
	    else
		fdll->deferred_except = true;
	    fd_unlock(fdll);
	}
    }
}

static void
fd_finish_cleared(struct fd_ll *fdll)
{
    if (fdll->iod)
	fdll->o->close(&fdll->iod);
    if (fdll->state == FD_OPEN_ERR_WAIT)
	fdll->deferred_open = true;
    fdll->deferred_close = true;
    fd_sched_deferred_op(fdll);
}

void
gensio_fd_ll_close_now(struct gensio_ll *ll)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    if (fdll->iod)
	fdll->o->close(&fdll->iod);
}

static void
fd_check_close(struct fd_ll *fdll)
{
    gensio_time timeout;
    int err = 0;

    if (fdll->ops->check_close) {
	err = fdll->ops->check_close(fdll->handler_data, fdll->iod,
				     GENSIO_LL_CLOSE_STATE_DONE, &timeout);
	if (err != GE_INPROGRESS)
	    fdll->iod = NULL;
    }

    if (err == GE_INPROGRESS) {
	fd_ref(fdll);
	fdll->o->start_timer(fdll->close_timer, &timeout);
    } else {
	fd_finish_cleared(fdll);
    }
}

static void
fd_close_timeout(struct gensio_timer *t, void *cb_data)
{
    struct fd_ll *fdll = cb_data;

    fd_lock(fdll);
    fd_check_close(fdll);
    fd_deref_and_unlock(fdll); /* Lose the timer ref. */
}

static void
fd_cleared(struct gensio_iod *iod, void *cb_data)
{
    struct fd_ll *fdll = cb_data;
    int err;

    fd_lock_and_ref(fdll);
    if (fdll->state == FD_IN_OPEN_RETRY) {
	fdll->o->close(&fdll->iod);
	err = fdll->ops->retry_open(fdll->handler_data, &fdll->iod);
	if (err == GE_INPROGRESS) {
	    err = fd_setup_handlers(fdll);
	    if (err)
		fdll->o->close(&fdll->iod);
	    else
		fd_set_state(fdll, FD_IN_OPEN);
	}
	if (err) {
	    fd_deref(fdll);
	    fd_finish_open(fdll, err);
	} else {
	    fdll->o->set_write_handler(fdll->iod, true);
	    fdll->o->set_except_handler(fdll->iod, true);
	}
    } else {
	fd_check_close(fdll);
    }
    fd_deref_and_unlock(fdll);
}

static int
fd_open(struct gensio_ll *ll, gensio_ll_open_done done, void *open_data)
{
    struct fd_ll *fdll = ll_to_fd(ll);
    int err;

    if (!fdll->ops->sub_open)
	return GE_NOTSUP;

    fd_lock(fdll);
    if (fdll->state != FD_CLOSED) {
	err = GE_NOTREADY;
	goto out;
    }

    fdll->close_requested = false;
    fdll->open_err = 0;
    fdll->read_data_len = 0;
    fdll->read_data_pos = 0;

    err = fdll->ops->sub_open(fdll->handler_data, &fdll->iod);
    if (err == GE_INPROGRESS || err == 0) {
	int err2 = fd_setup_handlers(fdll);
	if (err2) {
	    err = err2;
	    fdll->o->close(&fdll->iod);
	    goto out;
	}

	fdll->open_done = done;
	fdll->open_data = open_data;
	if (err == GE_INPROGRESS) {
	    fd_set_state(fdll, FD_IN_OPEN);
	    fdll->o->set_write_handler(fdll->iod, true);
	    fdll->o->set_except_handler(fdll->iod, true);
	} else {
	    fd_set_state(fdll, FD_OPEN);
	}
	fd_ref(fdll);
    }

 out:
    fd_unlock(fdll);
    return err;
}

static int
fd_setup_handlers(struct fd_ll *fdll)
{
    if (fdll->o->set_fd_handlers(fdll->iod, fdll, fd_read_ready,
				 fd_write_ready, fd_except_ready,
				 fd_cleared))
	return GE_NOMEM;
    return 0;
}

static int fd_close(struct gensio_ll *ll, gensio_ll_close_done done,
		    void *close_data)
{
    struct fd_ll *fdll = ll_to_fd(ll);
    int err = GE_NOTREADY;

    fd_lock(fdll);
    if (fdll->close_requested)
	goto out_unlock;
    switch(fdll->state) {
    case FD_IN_OPEN:
    case FD_IN_OPEN_RETRY:
	fdll->open_err = GE_LOCALCLOSED;
	/* Fallthrough */
    case FD_OPEN_ERR_WAIT:
	fdll->deferred_open = true;
	fd_sched_deferred_op(fdll);
	/* Fallthrough */
    case FD_OPEN:
    case FD_ERR_WAIT:
	fdll->close_done = done;
	fdll->close_data = close_data;
	fd_start_close(fdll);
	err = 0;
	break;

    case FD_CLOSED:
	break;

    default:
	assert(0);
    }
    fdll->close_requested = true;
 out_unlock:
    fd_unlock(fdll);

    return err;
}

static void
fd_set_read_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    fd_lock(fdll);
    if (fdll->write_only)
	goto out_unlock;
    fdll->read_enabled = enabled;

    if (fdll->in_read || fdll->state != FD_OPEN ||
			(fdll->read_data_len && !enabled)) {
	/* It will be handled in finish_read or open finish. */
    } else if (fdll->read_data_len) {
	/* Call the read from the selector to avoid lock nesting issues. */
	fdll->deferred_read = true;
	fd_sched_deferred_op(fdll);
    } else {
	fdll->o->set_read_handler(fdll->iod, enabled);
	fdll->o->set_except_handler(fdll->iod, enabled || fdll->write_enabled);
    }
 out_unlock:
    fd_unlock(fdll);
}

static void
fd_set_write_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    fd_lock(fdll);
    fdll->write_enabled = enabled;
    if (fdll->state == FD_OPEN || fdll->state == FD_IN_OPEN ||
		fdll->state == FD_IN_OPEN_RETRY) {
	fdll->o->set_write_handler(fdll->iod, enabled);
	fdll->o->set_except_handler(fdll->iod, enabled || fdll->read_enabled);
    } else if (fdll->deferred_except) {
	fd_sched_deferred_op(fdll);
    }
    fd_unlock(fdll);
}

static void fd_free(struct gensio_ll *ll)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    fd_lock(fdll);
    assert(!fdll->freed);
    fdll->freed = true;
    switch (fdll->state) {
    case FD_IN_CLOSE:
    case FD_CLOSED:
	break;

    case FD_OPEN:
    case FD_ERR_WAIT:
    case FD_OPEN_ERR_WAIT:
	fdll->close_done = NULL;
	fd_start_close(fdll);
	break;

    default:
	assert(0);
	break;
    }
    fd_deref_and_unlock(fdll);
}

static int fd_control(struct gensio_ll *ll, bool get, unsigned int option,
		      char *data, gensiods *datalen)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    if (!fdll->ops->control)
	return GE_NOTSUP;

    return fdll->ops->control(fdll->handler_data, fdll->iod, get, option, data,
			      datalen);
}

static void fd_disable(struct gensio_ll *ll)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    fd_set_state(fdll, FD_CLOSED);
    fd_deref(fdll);
    fdll->o->clear_fd_handlers_norpt(fdll->iod);
    fdll->o->close(&fdll->iod);
}

static int
gensio_ll_fd_func(struct gensio_ll *ll, int op, gensiods *count,
		  void *buf, const void *cbuf, gensiods buflen,
		  const char *const *auxdata)
{
    switch (op) {
    case GENSIO_LL_FUNC_SET_CALLBACK:
	fd_set_callbacks(ll, (void *) cbuf, buf);
	return 0;

    case GENSIO_LL_FUNC_WRITE_SG:
	return fd_write(ll, count, cbuf, buflen, auxdata);

    case GENSIO_LL_FUNC_OPEN:
	return fd_open(ll, (void *) cbuf, buf);

    case GENSIO_LL_FUNC_CLOSE:
	return fd_close(ll, (void *) cbuf, buf);

    case GENSIO_LL_FUNC_SET_READ_CALLBACK:
	fd_set_read_callback_enable(ll, buflen);
	return 0;

    case GENSIO_LL_FUNC_SET_WRITE_CALLBACK:
	fd_set_write_callback_enable(ll, buflen);
	return 0;

    case GENSIO_LL_FUNC_FREE:
	fd_free(ll);
	return 0;

    case GENSIO_LL_FUNC_CONTROL:
	return fd_control(ll, *((bool *) cbuf), buflen, buf, count);

    case GENSIO_LL_FUNC_DISABLE:
	fd_disable(ll);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

void *
gensio_fd_ll_get_handler_data(struct gensio_ll *ll)
{
    struct fd_ll *fdll = ll_to_fd(ll);

    return fdll->handler_data;
}

struct gensio_ll *
fd_gensio_ll_alloc(struct gensio_os_funcs *o,
		   struct gensio_iod *iod,
		   const struct gensio_fd_ll_ops *ops,
		   void *handler_data,
		   gensiods max_read_size,
		   bool write_only)
{
    struct fd_ll *fdll;

    fdll = o->zalloc(o, sizeof(*fdll));
    if (!fdll)
	return NULL;

    fdll->o = o;
    fdll->handler_data = handler_data;
    fdll->iod = iod;
    fdll->refcount = 1;
    fdll->write_only = write_only;
    if (!iod) {
	fd_set_state(fdll, FD_CLOSED);
    } else {
	fd_set_state(fdll, FD_OPEN);
	fd_ref(fdll);
    }

    fdll->close_timer = o->alloc_timer(o, fd_close_timeout, fdll);
    if (!fdll->close_timer)
	goto out_nomem;

    fdll->deferred_op_runner = o->alloc_runner(o, fd_deferred_op, fdll);
    if (!fdll->deferred_op_runner)
	goto out_nomem;

    fdll->lock = o->alloc_lock(o);
    if (!fdll->lock)
	goto out_nomem;

    fdll->read_data_size = max_read_size;
    if (max_read_size > 0) {
	fdll->read_data = o->zalloc(o, max_read_size);
	if (!fdll->read_data)
	    goto out_nomem;
    }

    fdll->ll = gensio_ll_alloc_data(o, gensio_ll_fd_func, fdll);
    if (!fdll->ll)
	goto out_nomem;

    if (iod) {
	int err = fd_setup_handlers(fdll);
	if (err)
	    goto out_nomem;
    }

    /*
     * Don't set ops until here to avoid it trying to call ops->free
     * on an error above.
     */
    fdll->ops = ops;

    return fdll->ll;

 out_nomem:
    fd_finish_free(fdll);
    return NULL;
}
