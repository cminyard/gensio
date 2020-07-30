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
#include <gensio/gensio_class.h>
#include <gensio/gensio_base.h>
#include <gensio/gensio_builtins.h>

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
    unsigned int freeref;
};

struct conaccna_data {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    struct gensio_accepter *acc;

    struct conaccn_data *ndata;

    bool deferred_op_pending;
    struct gensio_runner *deferred_runner;

    bool enabled;
    gensio_acc_done enabled_done;

    gensio_acc_done shutdown_done;

    /* Set when an error happens to report it back to the accepter log. */
    int con_err;

    /* Used to start the child gensio. */
    char *gensio_str;

    unsigned int refcount;
};

static void conacc_start(struct conaccna_data *nadata);

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
    if (nadata->lock)
	o->free_lock(nadata->lock);
    o->free(o, nadata);
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

static void
conaccna_do_deferred(struct gensio_runner *runner, void *cb_data)
{
    struct conaccna_data *nadata = cb_data;

    conaccna_lock(nadata);
    nadata->deferred_op_pending = false;

    if (nadata->con_err) {
	int err = nadata->con_err;

	nadata->con_err = 0;
	conaccna_unlock(nadata);
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Error opening gensio: %s", gensio_err_to_str(err));
	conaccna_lock(nadata);
    }

    if (nadata->enabled_done) {
	gensio_acc_done enabled_done = nadata->enabled_done;;

	nadata->enabled_done = NULL;
	conaccna_unlock(nadata);
	enabled_done(nadata->acc, NULL);
	conaccna_lock(nadata);
    }

    if (nadata->shutdown_done) {
	gensio_acc_done shutdown_done = nadata->shutdown_done;

	nadata->shutdown_done = NULL;
	conaccna_unlock(nadata);
	shutdown_done(nadata->acc, NULL);
	conaccna_lock(nadata);
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
    ndata->nadata = NULL;

    if (nadata) {
	conaccna_lock(nadata);
	nadata->ndata = NULL;
	conacc_start(nadata);
	conaccna_deref_and_unlock(nadata);
    }
}

static void
conaccn_close_done(struct gensio *child_io, void *close_data)
{
    struct conaccn_data *ndata = close_data;

    if (ndata->close_done)
	ndata->close_done(ndata->io, ndata->close_data);
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
    assert(ndata->freeref > 0);
    if (--ndata->freeref > 0) {
	conaccn_unlock(ndata);
	return;
    }

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
conaccn_func_ref(struct conaccn_data *ndata)
{
    conaccn_lock(ndata);
    ndata->freeref++;
    conaccn_unlock(ndata);
}

static void
conaccn_disable(struct conaccn_data *ndata)
{
    struct conaccna_data *nadata = ndata->nadata;

    conaccn_lock(ndata);
    ndata->child_state = CONACCN_CLOSED;
    gensio_disable(ndata->child);
    if (nadata) {
	conaccna_lock(nadata);
	nadata->ndata = NULL;
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
	return conaccn_close(ndata, cbuf, buf);

    case GENSIO_FUNC_FREE:
	conaccn_free(ndata);
	return 0;

    case GENSIO_FUNC_REF:
	conaccn_func_ref(ndata);
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


static void
conaccn_open_done(struct gensio *io, int err, void *open_data)
{
    struct conaccn_data *ndata = open_data;
    struct conaccna_data *nadata = ndata->nadata;

    conaccn_lock(ndata);
    conaccna_lock(nadata);
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

    conaccna_unlock(nadata);

    /* Keep the ref for the open child. */
    conaccn_unlock(ndata);

    base_gensio_server_open_done(nadata->acc, ndata->io, err);

    return;

 out_err:
    conaccn_unlock(ndata);
    conaccn_finish_free(ndata);
    nadata->con_err = err;
    conaccna_deferred_op(nadata);
    conaccna_deref_and_unlock(nadata);
}

static void
conacc_start(struct conaccna_data *nadata)
{
    struct conaccn_data *ndata;
    int err = GE_NOMEM;

    if (!nadata || !nadata->enabled)
	return;

    ndata = nadata->o->zalloc(nadata->o, sizeof(*ndata));
    if (!ndata)
	goto out_err_nofree;
    ndata->o = nadata->o;
    ndata->nadata = nadata;
    ndata->freeref = 1;
    ndata->refcount = 1;
    ndata->lock = nadata->o->alloc_lock(nadata->o);
    if (!ndata->lock)
	goto out_err;

    conaccn_lock(ndata);
    err = str_to_gensio(nadata->gensio_str, ndata->o, conaccn_event, ndata,
			&ndata->child);
    if (err)
	goto out_err_unlock;
    err = gensio_open(ndata->child, conaccn_open_done, ndata);
    if (err)
	goto out_err_unlock;

    nadata->ndata = ndata;
    conaccna_ref(nadata);
    ndata->child_state = CONACCN_IN_OPEN;
    conaccn_unlock(ndata);

    return;

 out_err_unlock:
    conaccn_unlock(ndata);
 out_err:
    conaccn_finish_free(ndata);
 out_err_nofree:
    nadata->con_err = err;
    conaccna_deferred_op(nadata);
}

static int
conaccna_startup(struct gensio_accepter *accepter,
		 struct conaccna_data *nadata)
{
    conaccna_lock(nadata);
    nadata->enabled = true;
    conacc_start(nadata);
    conaccna_unlock(nadata);

    return 0;
}

static int
conaccna_shutdown(struct gensio_accepter *accepter,
		  struct conaccna_data *nadata,
		  gensio_acc_done shutdown_done)
{
    conaccna_lock(nadata);
    nadata->enabled = false;
    /* Run the shutdown response in a runner to avoid deadlocks. */
    nadata->shutdown_done = shutdown_done;
    conaccna_deferred_op(nadata);
    conaccna_unlock(nadata);

    return 0;
}

static int
conaccna_set_accept_callback_enable(struct gensio_accepter *accepter,
				    struct conaccna_data *nadata,
				    bool enabled,
				    gensio_acc_done done)
{
    conaccna_lock(nadata);
    if (enabled != nadata->enabled) {
	nadata->enabled = enabled;
	conacc_start(nadata);
    }
    if (done) {
	nadata->enabled_done = done;
	conaccna_deferred_op(nadata);
    }
    conaccna_unlock(nadata);

    return 0;
}

static void
conaccna_free(struct gensio_accepter *accepter,
	      struct conaccna_data *nadata)
{
    conaccna_lock(nadata);
    nadata->enabled = false;
    conaccna_deref_and_unlock(nadata);
}

static void
conaccna_disable(struct gensio_accepter *accepter,
		 struct conaccna_data *nadata)
{
    conaccna_lock(nadata);
    nadata->enabled = false;
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

int
conacc_gensio_accepter_alloc(const char *gensio_str,
			     const char * const args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb, void *user_data,
			     struct gensio_accepter **accepter)
{
    struct conaccna_data *nadata;
    int err;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;
    nadata->o = o;
    nadata->refcount = 1;

    nadata->gensio_str = gensio_strdup(o, gensio_str);
    if (!nadata->gensio_str)
	goto out_nomem;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
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

int
str_to_conacc_gensio_accepter(const char *str, const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **acc)
{
    return conacc_gensio_accepter_alloc(str, args, o, cb, user_data, acc);
}
