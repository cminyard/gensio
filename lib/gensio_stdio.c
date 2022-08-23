/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code handles stdio stream I/O. */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_class.h>

#include "utils.h"

static int gensio_stdio_func(struct gensio *io, int func, gensiods *count,
			     const void *cbuf, gensiods buflen, void *buf,
			     const char *const *auxdata);

struct stdiona_data;

struct stdion_channel {
    struct stdiona_data *nadata;

    int ll_err; /* Set if an error occurs reading or writing. */

    struct gensio_iod *in_iod;
    struct gensio_iod *out_iod;

    /* Are the above fds registered with set_fd_handlers()? */
    bool in_handler_set;
    bool out_handler_set;

    struct gensio *io;

    gensiods max_read_size;
    unsigned char *read_data;
    gensiods data_pending_len;
    gensiods data_pos;

    struct stdiona_data *stdiona;

    bool read_enabled;
    bool xmit_enabled;
    bool in_read;
    bool deferred_read;
    bool in_write_ready;
    bool write_pending;
    bool deferred_write;

    bool in_open;
    gensio_done_err open_done;
    void *open_data;

    /* For the client only. */
    bool in_close; /* A close is pending the running running. */
    bool deferred_close;
    bool closed;
    gensio_done close_done;
    void *close_data;

    bool in_free;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;
};

struct stdiona_data {
    struct gensio_lock *lock;

    struct gensio_os_funcs *o;

    bool raw;
    bool stderr_to_stdout;
    bool noredir_stderr;

    unsigned int refcount;

    int argc;
    const char **argv;
    const char **env;
    char *start_dir;

    struct gensio_runner *connect_runner;
    bool in_connect_runner;

    struct gensio_runner *enable_done_runner;
    gensio_acc_done enable_done;
    void *enable_done_data;

    struct gensio_timer *waitpid_timer;

    /* For the accepter only. */
    bool in_free;
    bool in_shutdown;
    bool enabled;
    bool in_startup;
    gensio_acc_done shutdown_done;
    void *shutdown_data;

    /* exit code from the sub-program, after close. */
    int exit_code;
    bool exit_code_set;
    unsigned int waitpid_retries;

    /*
     * If not -1, this is the PID of the other process and we are
     * in client mode.
     */
    intptr_t opid;

    struct stdion_channel io; /* stdin, stdout */
    struct stdion_channel err; /* stderr */

    /* If we are in a final close, this is the channel that did it. */
    struct stdion_channel *closing_chan;

    struct gensio_accepter *acc;
};

static void
stdiona_lock(struct stdiona_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
stdiona_unlock(struct stdiona_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void
stdiona_finish_free(struct stdiona_data *nadata)
{
    struct gensio_os_funcs *o = nadata->o;

    if (nadata->io.io)
	gensio_data_free(nadata->io.io);
    if (nadata->err.io)
	gensio_data_free(nadata->err.io);
    if (nadata->io.out_iod)
	o->release_iod(nadata->io.out_iod);
    if (nadata->io.in_iod)
	o->release_iod(nadata->io.in_iod);
    if (nadata->argv)
	gensio_argv_free(o, nadata->argv);
    if (nadata->env)
	gensio_argv_free(o, nadata->env);
    if (nadata->start_dir)
	o->free(o, nadata->start_dir);
    if (nadata->io.deferred_op_runner)
	o->free_runner(nadata->io.deferred_op_runner);
    if (nadata->err.deferred_op_runner)
	o->free_runner(nadata->err.deferred_op_runner);
    if (nadata->connect_runner)
	o->free_runner(nadata->connect_runner);
    if (nadata->enable_done_runner)
	o->free_runner(nadata->enable_done_runner);
    if (nadata->io.read_data)
	o->free(o, nadata->io.read_data);
    if (nadata->waitpid_timer)
	o->free_timer(nadata->waitpid_timer);
    if (nadata->err.read_data)
	o->free(o, nadata->err.read_data);
    if (nadata->lock)
	o->free_lock(nadata->lock);
    if (nadata->acc)
	gensio_acc_data_free(nadata->acc);
    o->free(o, nadata);
}

static void
stdiona_ref(struct stdiona_data *nadata)
{
    assert(nadata->refcount > 0);
    nadata->refcount++;
}

static void
stdiona_deref(struct stdiona_data *nadata)
{
    assert(nadata->refcount > 1);
    nadata->refcount--;
}

static void
stdiona_deref_and_unlock(struct stdiona_data *nadata)
{
    assert(nadata->refcount > 0);
    if (--nadata->refcount == 0) {
	stdiona_unlock(nadata);
	stdiona_finish_free(nadata);
    } else {
	stdiona_unlock(nadata);
    }
}

static int
stdion_write(struct gensio *io, gensiods *count,
	     const struct gensio_sg *sg, gensiods sglen)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    int rv;

    stdiona_lock(nadata);
    if (schan->ll_err) {
	rv = schan->ll_err;
    } else {
	rv = nadata->o->write(schan->in_iod, sg, sglen, count);
	if (rv)
	    schan->ll_err = rv;
    }
    stdiona_unlock(nadata);

    return rv;
}

/* Must be called with nadata->lock held */
static void
stdion_finish_read(struct stdion_channel *schan, int err)
{
    struct stdiona_data *nadata = schan->nadata;
    struct gensio_os_funcs *o = nadata->o;
    struct gensio *io = schan->io;
    gensiods count;

    if (err && !schan->ll_err && schan->out_iod) {
	schan->ll_err = err;
	o->set_read_handler(schan->out_iod, false);
	o->set_except_handler(schan->out_iod, false);
    }

    while ((schan->data_pending_len || schan->ll_err) &&
	       schan->read_enabled) {
	count = schan->data_pending_len;
	if (schan->ll_err && schan->data_pending_len == 0) {
	    schan->read_enabled = false;
	    stdiona_unlock(nadata);
	    err = gensio_cb(io, GENSIO_EVENT_READ, schan->ll_err, NULL,
			    NULL, NULL);
	    stdiona_lock(nadata);
	    if (err) {
		schan->ll_err = err;
		o->set_read_handler(schan->out_iod, false);
		o->set_except_handler(schan->out_iod, false);
		break;
	    }
	} else {
	    stdiona_unlock(nadata);
	    err = gensio_cb(io, GENSIO_EVENT_READ, 0,
			    schan->read_data + schan->data_pos, &count, NULL);
	    stdiona_lock(nadata);
	    if (!err) {
		if (count < schan->data_pending_len) {
		    /* The user didn't consume all the data. */
		    schan->data_pending_len -= count;
		    schan->data_pos += count;
		} else {
		    schan->data_pending_len = 0;
		}
	    }
	}
	if (err) {
	    schan->ll_err = err;
	    o->set_read_handler(schan->out_iod, false);
	    o->set_except_handler(schan->out_iod, false);
	    break;
	}
    }

    schan->in_read = false;

    if (schan->out_iod) {
	if (schan->closed) {
	    o->set_read_handler(schan->out_iod, false);
	    o->set_except_handler(schan->out_iod, false);
	} else if (schan->read_enabled) {
	    o->set_read_handler(schan->out_iod, true);
	    o->set_except_handler(schan->out_iod, true);
	}
    }
}

/* FIXME - This should probably be configurable. */
#define NUM_WAIT_RETRIES 1000
static void
check_waitpid(struct stdion_channel *schan)
{
    struct stdiona_data *nadata = schan->nadata;
    struct gensio_os_funcs *o = nadata->o;
    int rv;
    gensiods count = 0;
    gensio_time timeout = { 0, 10000000 };

    if (nadata->closing_chan)
	schan = nadata->closing_chan;

    /* Wait for the output buffer to clear for half our allotted time. */
    if (schan->out_iod) {
	o->bufcount(schan->out_iod, GENSIO_OUT_BUF, &count);
	if (count > 0 && nadata->waitpid_retries < NUM_WAIT_RETRIES / 2)
	    goto try_again;
    }

    if (schan->in_iod)
	o->close(&schan->in_iod);
    if (schan->out_iod)
	o->close(&schan->out_iod);

    if (nadata->opid != -1 && !nadata->io.out_handler_set &&
		!nadata->io.in_handler_set && !nadata->err.out_handler_set) {
	rv = o->wait_subprog(o, nadata->opid, &nadata->exit_code);
	if (rv == GE_INPROGRESS) {
	    goto try_again;
	} else {
	    if (rv)
		/* FIXME = no real way to report this. */
		;

	    nadata->exit_code_set = true;
	    nadata->opid = -1;
	}
    }

 close_anyway:
    if (schan->in_iod)
	o->close(&schan->in_iod);
    if (schan->out_iod) {
	if (count > 0)
	    o->flush(schan->out_iod, GENSIO_OUT_BUF);
	o->close(&schan->out_iod);
    }

    if (schan->close_done) {
	gensio_done close_done = schan->close_done;
	void *close_data = schan->close_data;

	schan->in_close = false;
	schan->close_done = NULL;

	stdiona_unlock(nadata);
	close_done(schan->io, close_data);
	stdiona_lock(nadata);
    }

    if (schan->in_free && schan->io) {
	gensio_data_free(schan->io);
	schan->io = NULL;
	stdiona_deref(nadata);
    }
    return;

 try_again:
    /* The sub-process has not died or buffer is not clear, wait a
       bit and try again. */

    if (nadata->waitpid_retries >= NUM_WAIT_RETRIES)
	goto close_anyway;
    nadata->waitpid_retries++;
    stdiona_ref(nadata);
    rv = o->start_timer(nadata->waitpid_timer, &timeout);
    assert(rv == 0);
    nadata->closing_chan = schan;
}

static void
check_waitpid_timeout(struct gensio_timer *t, void *cb_data)
{
    struct stdion_channel *schan = cb_data;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    check_waitpid(schan);
    stdiona_deref_and_unlock(nadata);
}

/*
 * Note that we do callbacks from this function, it must be called
 * from a handler or deferred op and not from a user call.
 */
static void
stdion_start_close(struct stdion_channel *schan)
{
    struct stdiona_data *nadata = schan->nadata;

    schan->read_enabled = false;
    schan->xmit_enabled = false;
    nadata->o->clear_fd_handlers(schan->out_iod);
    if (schan->in_iod)
	nadata->o->clear_fd_handlers(schan->in_iod);
}

static int
stdion_do_read(struct stdiona_data *nadata, struct stdion_channel *schan)
{
    int rv;
    gensiods count;

    rv = nadata->o->read(schan->out_iod, schan->read_data,
			 schan->max_read_size, &count);
    if (!rv) {
	schan->data_pending_len = count;
	schan->data_pos = 0;
    }

    return rv;
}

static void
stdion_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;
    struct gensio_os_funcs *o = nadata->o;
    struct gensio *io = schan->io;

    stdiona_lock(nadata);
 restart:
    if (schan->in_open) {
	if (schan->open_done) {
	    stdiona_unlock(nadata);
	    schan->open_done(io, 0, schan->open_data);
	    stdiona_lock(nadata);
	}
	schan->in_open = false;
	o->set_read_handler(schan->out_iod, schan->read_enabled);
	o->set_except_handler(schan->out_iod, schan->read_enabled);
	if (schan->in_iod) {
	    o->set_write_handler(schan->in_iod, schan->xmit_enabled);
	    o->set_except_handler(schan->in_iod, schan->xmit_enabled);
	}
    }

    if (schan->deferred_read) {
	schan->deferred_read = false;
	while (schan->read_enabled && schan->io &&
	       (schan->ll_err || schan->data_pending_len))
	    stdion_finish_read(schan, 0);
    }

    if (schan->deferred_close) {
	schan->deferred_close = false;
	stdion_start_close(schan);
    }

    if (schan->deferred_read || schan->in_open || schan->deferred_write)
	goto restart;

    schan->deferred_op_pending = false;

    stdiona_deref_and_unlock(nadata);
}

static void
stdion_start_deferred_op(struct stdion_channel *schan)
{
    if (!schan->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	schan->deferred_op_pending = true;
	schan->nadata->o->run(schan->deferred_op_runner);
	stdiona_ref(schan->nadata);
    }
}

static void
i_stdion_fd_cleared(struct gensio_iod *iod, struct stdiona_data *nadata,
		    struct stdion_channel *schan)
{
    struct gensio_os_funcs *o = nadata->o;

    if (iod == schan->in_iod) {
	schan->in_handler_set = false;
	o->close(&schan->in_iod);
    } else if (iod == schan->out_iod) {
	schan->out_handler_set = false;
	o->close(&schan->out_iod);
    } else {
	assert(false);
    }

    if (schan->in_close && !schan->in_handler_set && !schan->out_handler_set) {
	if (schan == &nadata->io && !nadata->err.out_handler_set &&
		nadata->err.out_iod) {
	    /* The stderr channel is not open, so close the fd. */
	    o->close(&nadata->err.out_iod);
	}
	check_waitpid(schan);
    }
}

static void
stdion_fd_cleared(struct gensio_iod *iod, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    i_stdion_fd_cleared(iod, nadata, schan);
    stdiona_deref_and_unlock(nadata);
}

static void
stdion_set_read_callback_enable(struct gensio *io, bool enabled)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (schan->read_enabled == enabled)
	goto out_unlock;
    schan->read_enabled = enabled;
    if ((!schan->in_close && schan->closed) || !schan->io)
	goto out_unlock;
    if (schan->in_read || schan->in_open ||
			(schan->data_pending_len && !enabled)) {
	/* Nothing to do, let the read handling wake things up. */
    } else if (schan->data_pending_len) {
	schan->deferred_read = true;
	schan->in_read = true;
	stdion_start_deferred_op(schan);
    } else if (schan->out_iod) { /* Could be in the middle of close. */
	nadata->o->set_read_handler(schan->out_iod, enabled);
	nadata->o->set_except_handler(schan->out_iod, enabled);
    }
 out_unlock:
    stdiona_unlock(nadata);
}

static void
stdion_set_write_callback_enable(struct gensio *io, bool enabled)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (schan->xmit_enabled == enabled)
	goto out_unlock;
    schan->xmit_enabled = enabled;
    if ((!schan->in_close && schan->closed) || !schan->in_iod)
	goto out_unlock;
    if (schan->in_open)
	goto out_unlock;
    if (schan->in_iod) { /* Could be in the middle of close. */
	nadata->o->set_write_handler(schan->in_iod, enabled);
	nadata->o->set_except_handler(schan->in_iod, enabled);
    }
 out_unlock:
    stdiona_unlock(nadata);
}

static void
stdion_read_ready(struct gensio_iod *iod, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    nadata->o->set_read_handler(schan->out_iod, false);
    nadata->o->set_except_handler(schan->out_iod, false);
    if (!schan->read_enabled || schan->in_read || schan->data_pending_len) {
	stdiona_unlock(nadata);
	return;
    }
    if (!schan->ll_err) {
	schan->in_read = true;
	stdion_finish_read(schan, stdion_do_read(nadata, schan));
    }
    stdiona_unlock(nadata);
}

static void
stdion_read_except_ready(struct gensio_iod *iod, void *cbdata)
{
    stdion_read_ready(iod, cbdata);
}

static void
stdion_write_ready(struct gensio_iod *iod, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;
    int err;

    stdiona_lock(nadata);
    if (schan->in_write_ready) {
	schan->write_pending = true;
	goto out;
    }
    schan->in_write_ready = true;
 retry:
    stdiona_unlock(nadata);
    err = gensio_cb(schan->io, GENSIO_EVENT_WRITE_READY, 0, NULL, NULL, NULL);
    stdiona_lock(nadata);
    if (err) {
	schan->ll_err = err;
	nadata->o->set_read_handler(schan->out_iod, false);
	nadata->o->set_except_handler(schan->out_iod, false);
    } else if (schan->write_pending) {
	schan->write_pending = false;
	if (schan->xmit_enabled)
	    goto retry;
    }
    schan->in_write_ready = false;
 out:
    stdiona_unlock(nadata);
}

static void
stdion_write_except_ready(struct gensio_iod *iod, void *cbdata)
{
    stdion_write_ready(iod, cbdata);
}

static int
setup_child_proc(struct stdiona_data *nadata)
{
    struct gensio_os_funcs *o = nadata->o;
    int rv;

    rv = o->exec_subprog(o, nadata->argv, nadata->env, nadata->start_dir,
			 nadata->stderr_to_stdout,
			 &nadata->opid, &nadata->io.in_iod,
			 &nadata->io.out_iod,
			 nadata->noredir_stderr ? NULL : &nadata->err.out_iod);
    return rv;
}

static int
setup_io_self(struct stdiona_data *nadata)
{
    struct gensio_os_funcs *o = nadata->o;
    int rv;

    if (nadata->raw) {
	rv = o->makeraw(nadata->io.in_iod);
	if (rv)
	    return rv;
	rv = o->makeraw(nadata->io.out_iod);
	if (rv)
	    return rv;
    }

    /*
     * If these are not regular files, save off the old flags and turn
     * on non-blocking.
     */
    rv = o->set_non_blocking(nadata->io.in_iod);
    if (rv)
	return rv;

    rv = o->set_non_blocking(nadata->io.out_iod);
    if (rv)
	return rv;

    return 0;
}

static void
cleanup_io_self(struct stdiona_data *nadata)
{
    if (nadata->io.out_handler_set)
	nadata->o->clear_fd_handlers_norpt(nadata->io.out_iod);
    nadata->io.out_handler_set = false;
    if (nadata->io.in_handler_set)
	nadata->o->clear_fd_handlers_norpt(nadata->io.in_iod);
    nadata->io.in_handler_set = false;
}

static int
stdion_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    struct gensio_os_funcs *o = nadata->o;
    int err;

    stdiona_lock(nadata);

    if (!schan->closed || schan->in_close) {
	err = GE_NOTREADY;
	goto out_unlock;
    }

    if (schan == &nadata->io) {
	if (nadata->argv && schan == &nadata->io)
	    err = setup_child_proc(nadata);
	else
	    err = setup_io_self(nadata);
	if (err)
	    goto out_err;
    }

    err = o->set_fd_handlers(schan->out_iod, schan,
			     stdion_read_ready, NULL,
			     stdion_read_except_ready,
			     stdion_fd_cleared);
    if (err)
	goto out_err;
    schan->out_handler_set = true;
    stdiona_ref(nadata);

    if (schan->in_iod) {
	/*
	 * On the write side we send an exception to the write ready
	 * operation.
	 */
	err = o->set_fd_handlers(schan->in_iod, schan,
				 NULL, stdion_write_ready,
				 stdion_write_except_ready,
				 stdion_fd_cleared);
	if (err)
	    goto out_err_deref;
	schan->in_handler_set = true;
	stdiona_ref(nadata);
    }

    schan->ll_err = 0;
    schan->closed = false;
    schan->in_open = true;
    schan->open_done = open_done;
    schan->open_data = open_data;
    stdion_start_deferred_op(schan);
    stdiona_unlock(nadata);

    return 0;

 out_err_deref:
    stdiona_deref(nadata);
 out_err:
    cleanup_io_self(nadata);
    if (nadata->io.in_iod)
	o->close(&nadata->io.in_iod);
    if (nadata->err.out_iod)
	o->close(&nadata->err.out_iod);
    if (nadata->io.out_iod)
	o->close(&nadata->io.out_iod);
 out_unlock:
    stdiona_unlock(nadata);

    return err;
}

static int
stdion_alloc_channel(struct gensio *io, const char * const args[],
		     gensio_event cb, void *user_data,
		     struct gensio **new_io)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    struct gensio_os_funcs *o = nadata->o;
    int rv = 0;
    unsigned int i;
    gensiods max_read_size = nadata->io.max_read_size;

    if (!nadata->err.out_iod || io != nadata->io.io)
	return GE_INVAL;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return GE_INVAL;
    }

    stdiona_lock(nadata);
    if (nadata->err.io) {
	rv = GE_INUSE;
	goto out_err;
    }

    nadata->err.max_read_size = max_read_size;
    nadata->err.read_data = o->zalloc(o, max_read_size);
    if (!nadata->err.read_data) {
	rv = GE_NOMEM;
	goto out_err;
    }
    nadata->err.data_pending_len = 0;
    nadata->err.data_pos = 0;
    nadata->err.read_enabled = false;
    nadata->err.xmit_enabled = false;

    nadata->err.io = gensio_data_alloc(o, cb, user_data,
				       gensio_stdio_func,
				       NULL, "stderr", &nadata->err);
    if (!nadata->err.io) {
	o->free(o, nadata->err.read_data);
	nadata->err.read_data = NULL;
	rv = GE_NOMEM;
	goto out_err;
    }
    stdiona_ref(nadata);

    *new_io = nadata->err.io;

 out_err:
    stdiona_unlock(nadata);

    return rv;
}

static void
i_stdion_close(struct stdion_channel *schan,
	       gensio_done close_done, void *close_data)
{
    schan->closed = true;
    schan->in_close = true;
    schan->close_done = close_done;
    schan->close_data = close_data;

    /*
     * Always run this in the deferred handler, it simplifies issues with
     * handling regular file shutdown.
     */
    schan->deferred_close = true;
    stdion_start_deferred_op(schan);
}

static int
stdion_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    int err = 0;

    stdiona_lock(nadata);
    if (schan->closed || schan->in_close)
	err = GE_NOTREADY;
    else
	i_stdion_close(schan, close_done, close_data);
    stdiona_unlock(nadata);

    return err;
}

static void
stdion_free(struct gensio *io)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    schan->in_free = true;
    if (schan->in_close) {
	schan->close_done = NULL;
	stdiona_unlock(nadata);
    } else if (schan->closed) {
	gensio_data_free(schan->io);
	schan->io = NULL;
	stdiona_deref_and_unlock(nadata);
    } else {
	i_stdion_close(schan, NULL, NULL);
	stdiona_unlock(nadata);
    }
}

static int
stdion_disable(struct gensio *io)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    struct gensio_os_funcs *o = nadata->o;

    if (!nadata->argv)
	return GE_NOTSUP;

    stdiona_lock(nadata);
    schan->closed = true;
    schan->in_close = false;
    schan->in_open = false;
    schan->close_done = NULL;
    if (nadata->io.out_handler_set)
	o->clear_fd_handlers_norpt(nadata->io.out_iod);
    if (nadata->io.out_iod)
	o->close(&nadata->io.out_iod);
    if (nadata->io.in_handler_set)
	o->clear_fd_handlers_norpt(nadata->io.in_iod);
    if (nadata->io.in_iod)
	o->close(&nadata->io.in_iod);
    if (nadata->err.out_handler_set)
	o->clear_fd_handlers_norpt(nadata->err.out_iod);
    if (nadata->err.out_iod)
	o->close(&nadata->err.out_iod);
    stdiona_deref_and_unlock(nadata);
    return 0;
}

static int
stdion_control(struct gensio *io, bool get, unsigned int option,
	       char *data, gensiods *datalen)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    struct gensio_os_funcs *o = nadata->o;
    const char **env, **argv;
    int err, status, val;
    gensiods pos;

    switch (option) {
    case GENSIO_CONTROL_ENVIRONMENT:
	if (get)
	    return GE_NOTSUP;
	if (data) {
	    err = gensio_argv_copy(o, (const char **) data, NULL, &env);
	    if (err)
		return err;
	} else {
	    env = NULL;
	}
	if (nadata->env)
	    gensio_argv_free(o, nadata->env);
	nadata->env = env;
	return 0;

    case GENSIO_CONTROL_ARGS:
	if (get)
	    return GE_NOTSUP;
	if (data) {
	    err = gensio_argv_copy(o, (const char **) data, NULL, &argv);
	    if (err)
		return err;
	} else {
	    argv = NULL;
	}
	if (nadata->argv)
	    gensio_argv_free(o, nadata->argv);
	nadata->argv = argv;
	return 0;

    case GENSIO_CONTROL_EXIT_CODE:
	if (!get)
	    return GE_NOTSUP;
	err = 0;
	stdiona_lock(nadata);
	if (!nadata->exit_code_set)
	    err = GE_NOTREADY;
	stdiona_unlock(nadata);
	if (!err)
	    *datalen = snprintf(data, *datalen, "%d", nadata->exit_code);
	return err;

    case GENSIO_CONTROL_WAIT_TASK:
	if (!get)
	    return GE_NOTSUP;
	stdiona_lock(nadata);
	if (nadata->opid == -1)
	    err = GE_NOTREADY;
	else
	    err = o->wait_subprog(o, nadata->opid, &status);
	if (!err) {
	    nadata->opid = -1;
	    nadata->exit_code = status;
	}
	stdiona_unlock(nadata);
	if (!err)
	    *datalen = snprintf(data, *datalen, "%d", status);
	return 0;

    case GENSIO_CONTROL_KILL_TASK:
	if (get)
	    return GE_NOTSUP;
	stdiona_lock(nadata);
	if (nadata->opid == -1) {
	    err = GE_NOTREADY;
	} else {
	    val = strtoul(data, NULL, 0);
	    err = o->kill_subprog(o, nadata->opid, val);
	}
	stdiona_unlock(nadata);
	return err;

    case GENSIO_CONTROL_CLOSE_OUTPUT:
	if (get)
	    return GE_NOTSUP;
	err = 0;
	stdiona_lock(nadata);
	if (!schan->in_iod)
	    err = GE_NOTREADY;
	else
	    o->clear_fd_handlers(schan->in_iod);
	stdiona_unlock(nadata);
	return err;

    case GENSIO_CONTROL_RADDR:
	if (!get)
	    return GE_NOTSUP;
	pos = 0;
	if (io == nadata->io.io)
	    gensio_pos_snprintf(data, *datalen, &pos, "stdio");
	else
	    gensio_pos_snprintf(data, *datalen, &pos, "stderr");
	if (nadata->argv) {
	    gensio_pos_snprintf(data, *datalen, &pos, ",");
	    gensio_argv_snprintf(data, *datalen, &pos, nadata->argv);
	} else {
	    gensio_pos_snprintf(data, *datalen, &pos, "(self)");
	}
	*datalen = pos;
	return 0;

    case GENSIO_CONTROL_REMOTE_ID:
	if (!get)
	    return GE_NOTSUP;
	*datalen = snprintf(data, *datalen, "%llu",
			    (unsigned long long) nadata->opid);
	return 0;

    case GENSIO_CONTROL_IOD:
	if (!get)
	    return GE_NOTSUP;
	if (*datalen != sizeof(void *))
	    return GE_INVAL;
	val = strtoul(data, NULL, 0);
	if (val == 0)
	    memcpy(data, &schan->out_iod, sizeof(void *));
	else if (val == 1)
	    memcpy(data, &schan->in_iod, sizeof(void *));
	else
	    return GE_INVAL;
	return 0;

    case GENSIO_CONTROL_START_DIRECTORY:
	if (get) {
	    *datalen = snprintf(data, *datalen, "%s", nadata->start_dir);
	} else {
	    char *dir;

	    dir = gensio_strdup(o, (char *) data);
	    if (!dir)
		return GE_NOMEM;
	    if (nadata->start_dir)
		o->free(o, nadata->start_dir);
	    nadata->start_dir = dir;
	}
	return 0;
    }

    return GE_NOTSUP;
}

static int
gensio_stdio_func(struct gensio *io, int func, gensiods *count,
		  const void *cbuf, gensiods buflen, void *buf,
		  const char *const *auxdata)
{
    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	return stdion_write(io, count, cbuf, buflen);

    case GENSIO_FUNC_OPEN:
	return stdion_open(io, (void *) cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return stdion_close(io, (void *) cbuf, buf);

    case GENSIO_FUNC_FREE:
	stdion_free(io);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	stdion_set_read_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	stdion_set_write_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_ALLOC_CHANNEL:
    {
	struct gensio_func_alloc_channel_data *d = buf;
	return stdion_alloc_channel(io, d->args, d->cb, d->user_data,
				    &d->new_io);
    }

    case GENSIO_FUNC_DISABLE:
	return stdion_disable(io);

    case GENSIO_FUNC_CONTROL:
	return stdion_control(io, *((bool *) cbuf), buflen, buf, count);

    default:
	return GE_NOTSUP;
    }
}

static int
stdio_nadata_setup(struct gensio_os_funcs *o, gensiods max_read_size,
		   bool raw, struct stdiona_data **new_nadata)
{
    struct stdiona_data *nadata;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;
    nadata->o = o;
    nadata->refcount = 1;
    nadata->io.closed = true;
    nadata->err.closed = true;
    nadata->io.nadata = nadata;
    nadata->err.nadata = nadata;
    nadata->opid = -1;

    nadata->waitpid_timer = o->alloc_timer(o, check_waitpid_timeout,
					   &nadata->io);
    if (!nadata->waitpid_timer)
	goto out_nomem;

    nadata->raw = raw;
    nadata->io.max_read_size = max_read_size;
    nadata->io.read_data = o->zalloc(o, max_read_size);
    if (!nadata->io.read_data)
	goto out_nomem;

    nadata->io.deferred_op_runner = o->alloc_runner(o, stdion_deferred_op,
						    &nadata->io);
    if (!nadata->io.deferred_op_runner)
	goto out_nomem;

    nadata->err.deferred_op_runner = o->alloc_runner(o, stdion_deferred_op,
						     &nadata->err);
    if (!nadata->err.deferred_op_runner)
	goto out_nomem;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    *new_nadata = nadata;

    return 0;

 out_nomem:
    stdiona_finish_free(nadata);

    return GE_NOMEM;
}

static int
setup_self(struct stdiona_data *nadata, bool console)
{
    struct gensio_os_funcs *o = nadata->o;
    int err;
    enum gensio_iod_type type;

    if (console)
	type = GENSIO_IOD_CONSOLE;
    else
	type = GENSIO_IOD_STDIO;
    err = o->add_iod(o, type, 1, &nadata->io.in_iod);
    if (err)
	return err;
    err = o->add_iod(o, type, 0, &nadata->io.out_iod);
    if (err)
	return err;

    return 0;
}

static int
stdio_gensio_alloc(const void *gdata, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    const char * const *argv = gdata;
    int err;
    struct stdiona_data *nadata = NULL;
    int i;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    bool self = false;
    bool console = false;
    bool stderr_to_stdout = false;
    bool noredir_stderr = false;
    bool raw = false;
    const char *start_dir = NULL;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "console", &console) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "self", &self) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "raw", &raw) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "start-dir", &start_dir) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "stderr-to-stdout",
				 &stderr_to_stdout) > 0) {
	    /* We don't want to setup stderr here. */
	    noredir_stderr = true;
	    continue;
	}
	if (gensio_check_keybool(args[i], "noredir-stderr",
				 &noredir_stderr) > 0)
	    continue;
	return GE_INVAL;
    }

    if (raw && !(self || console))
	return GE_INVAL;

    err = stdio_nadata_setup(o, max_read_size, raw, &nadata);
    if (err)
	return err;

    nadata->stderr_to_stdout = stderr_to_stdout;
    nadata->noredir_stderr = noredir_stderr;
    if (start_dir) {
	nadata->start_dir = gensio_strdup(o, start_dir);
	if (!nadata->start_dir) {
	    err = GE_NOMEM;
	    goto out_err;
	}
    }

    if (self || console) {
	err = setup_self(nadata, console);
	if (err)
	    goto out_err;
    } else {
	err = gensio_argv_copy(o, argv, NULL, &nadata->argv);
	if (err)
	    goto out_err;
    }

    nadata->io.io = gensio_data_alloc(o, cb, user_data,
				      gensio_stdio_func, NULL, "stdio",
				      &nadata->io);
    if (!nadata->io.io)
	goto out_nomem;
    gensio_set_is_client(nadata->io.io, true);
    gensio_set_is_reliable(nadata->io.io, true);

    *new_gensio = nadata->io.io;

    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    stdiona_finish_free(nadata);
    return err;
}

static int
str_to_stdio_gensio(const char *str, const char * const args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **new_gensio)
{
    int err;
    const char **argv;

    err = gensio_str_to_argv(o, str, NULL, &argv, NULL);
    if (!err) {
	err = stdio_gensio_alloc(argv, args, o, cb, user_data, new_gensio);
	gensio_argv_free(o, argv);
    }
    return err;
}

static void
stdiona_do_connect(struct gensio_runner *runner, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;

    stdiona_lock(nadata);
 retry:
    if (nadata->in_startup) {
	nadata->in_startup = false;
	stdiona_unlock(nadata);
	gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_NEW_CONNECTION,
		      nadata->io.io);
	stdiona_lock(nadata);
    }

    if (nadata->in_shutdown) {
	nadata->in_shutdown = false;
	stdiona_unlock(nadata);
	if (nadata->shutdown_done)
	    nadata->shutdown_done(nadata->acc, nadata->shutdown_data);
	stdiona_lock(nadata);
    }

    if (nadata->in_startup || nadata->in_shutdown)
	goto retry;

    nadata->in_connect_runner = false;
    stdiona_deref_and_unlock(nadata); /* unlocks */
}

/*
 * fd cleared for a gensio from an acceptor only.
 */
static void
stdiona_fd_cleared(struct gensio_iod *iod, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (iod == schan->in_iod)
	schan->in_handler_set = false;
    else
	schan->out_handler_set = false;

    if (!schan->in_handler_set && !schan->out_handler_set && schan->in_close) {
	schan->in_close = false;
	if (schan->close_done) {
	    gensio_done close_done = schan->close_done;
	    void *close_data = schan->close_data;

	    schan->close_done = NULL;

	    stdiona_unlock(nadata);
	    close_done(schan->io, close_data);
	    stdiona_lock(nadata);
	}
    }

    /* Lose the refcount we got when we added the fd handler. */
    stdiona_deref_and_unlock(nadata); /* unlocks */
}

static int
stdiona_startup(struct gensio_accepter *accepter)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);
    struct gensio_os_funcs *o = nadata->o;
    int rv = 0;

    stdiona_lock(nadata);
    if (nadata->in_free || nadata->in_shutdown) {
	rv = GE_NOTREADY;
	goto out_unlock;
    }

    if (nadata->enabled) {
	rv = GE_INUSE;
	goto out_unlock;
    }

    rv = setup_io_self(nadata);
    if (rv)
	goto out_unlock;

    rv = o->set_fd_handlers(nadata->io.in_iod,
			    &nadata->io, NULL, stdion_write_ready, NULL,
			    stdiona_fd_cleared);
    if (rv)
	goto out_err;
    nadata->io.in_handler_set = true;
    stdiona_ref(nadata);

    rv = o->set_fd_handlers(nadata->io.out_iod,
			    &nadata->io, stdion_read_ready, NULL, NULL,
			    stdiona_fd_cleared);
    if (rv)
	goto out_err;
    nadata->io.out_handler_set = true;
    stdiona_ref(nadata);

    nadata->io.closed = false;
    nadata->in_startup = true;
    nadata->enabled = true;
    if (!nadata->in_connect_runner) {
	stdiona_ref(nadata);
	nadata->in_connect_runner = true;
	o->run(nadata->connect_runner);
    }
    stdiona_ref(nadata); /* One for the gensio. */

 out_unlock:
    stdiona_unlock(nadata);
    return rv;

 out_err:
    cleanup_io_self(nadata);
    goto out_unlock;
}

static int
stdiona_shutdown(struct gensio_accepter *accepter,
		 gensio_acc_done shutdown_done, void *shutdown_data)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    stdiona_lock(nadata);
    if (nadata->in_free) {
	rv = GE_NOTREADY;
    } else if (nadata->in_shutdown || !nadata->enabled) {
	rv = GE_NOTREADY;
    } else {
	nadata->in_shutdown = true;
	nadata->enabled = false;
	nadata->shutdown_done = shutdown_done;
	nadata->shutdown_data = shutdown_data;
	if (!nadata->in_connect_runner) {
	    stdiona_ref(nadata);
	    nadata->in_connect_runner = true;
	    nadata->o->run(nadata->connect_runner);
	}
    }
    stdiona_unlock(nadata);

    return rv;
}

static void
enable_done_op(struct gensio_runner *runner, void *cb_data)
{
    struct stdiona_data *nadata = cb_data;

    stdiona_lock(nadata);
    if (nadata->enable_done) {
	gensio_acc_done done = nadata->enable_done;
	void *done_data = nadata->enable_done_data;

	nadata->enable_done = NULL;
	stdiona_unlock(nadata);
	done(nadata->acc, done_data);
	stdiona_lock(nadata);
    }
    stdiona_deref_and_unlock(nadata);
}

static int
stdiona_set_accept_callback_enable(struct gensio_accepter *accepter,
				   bool enabled,
				   gensio_acc_done done, void *done_data)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    /* FIXME - there's no real enable for this, maybe there should be? */
    if (nadata->enable_done) {
	rv = GE_INUSE;
    } else {
	nadata->enable_done = done;
	nadata->enable_done_data = done_data;
	stdiona_ref(nadata);
	nadata->o->run(nadata->enable_done_runner);
    }

    return rv;
}

static void
stdiona_free(struct gensio_accepter *accepter)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);

    stdiona_lock(nadata);
    nadata->in_free = true;
    stdiona_deref_and_unlock(nadata);
}

static int
gensio_acc_stdio_func(struct gensio_accepter *acc, int func, int val,
		      const char *addr, void *done, void *data,
		      const void *data2, void *ret)
{
    switch (func) {
    case GENSIO_ACC_FUNC_STARTUP:
	return stdiona_startup(acc);

    case GENSIO_ACC_FUNC_SHUTDOWN:
	return stdiona_shutdown(acc, done, data);

    case GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK:
	return stdiona_set_accept_callback_enable(acc, val, done, data);

    case GENSIO_ACC_FUNC_FREE:
	stdiona_free(acc);
	return 0;

    case GENSIO_ACC_FUNC_STR_TO_GENSIO:
    default:
	return GE_NOTSUP;
    }
}

static int
stdio_gensio_accepter_alloc(const void *gdata,
			    const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb, void *user_data,
			    struct gensio_accepter **accepter)
{
    int err;
    struct stdiona_data *nadata = NULL;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    bool raw = false;
    int i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "raw", &raw) > 0)
	    continue;
	return GE_INVAL;
    }

    err = stdio_nadata_setup(o, max_read_size, raw, &nadata);
    if (err)
	return err;

    nadata->connect_runner = o->alloc_runner(o, stdiona_do_connect, nadata);
    if (!nadata->connect_runner) {
	stdiona_finish_free(nadata);
	return GE_NOMEM;
    }

    nadata->enable_done_runner = o->alloc_runner(o, enable_done_op, nadata);
    if (!nadata->enable_done_runner) {
	stdiona_finish_free(nadata);
	return err;
    }

    err = setup_self(nadata, false);
    if (err) {
	stdiona_finish_free(nadata);
	return err;
    }

    err = o->add_iod(o, GENSIO_IOD_STDIO, 0, &nadata->io.out_iod);
    if (err) {
	stdiona_finish_free(nadata);
	return err;
    }

    nadata->acc = gensio_acc_data_alloc(o, cb, user_data,
					gensio_acc_stdio_func,
					NULL, "stdio", nadata);
    if (!nadata->acc) {
	stdiona_finish_free(nadata);
	return GE_NOMEM;
    }
    gensio_acc_set_is_reliable(nadata->acc, true);

    nadata->io.io = gensio_data_alloc(o, NULL, NULL, gensio_stdio_func,
				      NULL, "stdio", &nadata->io);
    if (!nadata->io.io) {
	stdiona_finish_free(nadata);
	return GE_NOMEM;
    }

    *accepter = nadata->acc;
    return 0;
}

static int
str_to_stdio_gensio_accepter(const char *str, const char * const args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb,
			     void *user_data,
			     struct gensio_accepter **acc)
{
    return stdio_gensio_accepter_alloc(NULL, args, o, cb, user_data, acc);
}

int
gensio_init_stdio(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "stdio", str_to_stdio_gensio, stdio_gensio_alloc);
    if (rv)
	return rv;
    rv = register_gensio_accepter(o, "stdio", str_to_stdio_gensio_accepter,
				  stdio_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
