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

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/argvutils.h>

struct gensna_data {
    struct gensio_accepter *acc;

    struct gensio_os_funcs *o;

    struct gensio_accepter *child;

    gensio_acc_done shutdown_done;
    gensio_acc_done cb_en_done;

    gensio_gensio_acc_cb acc_cb;
    void *acc_data;
};

static int
gensna_startup(struct gensio_accepter *accepter, struct gensna_data *nadata)
{
    return gensio_acc_startup(nadata->child);
}

static void
gensna_child_shutdown(struct gensio_accepter *accepter,
		     void *shutdown_data)
{
    struct gensna_data *nadata = shutdown_data;

    nadata->shutdown_done(nadata->acc, NULL);
}

static int
gensna_shutdown(struct gensio_accepter *accepter,
		struct gensna_data *nadata,
		gensio_acc_done shutdown_done)
{
    nadata->shutdown_done = shutdown_done;
    return gensio_acc_shutdown(nadata->child, gensna_child_shutdown, nadata);
}

static void
gensna_cb_en_done(struct gensio_accepter *accepter, void *cb_data)
{
    struct gensna_data *nadata = cb_data;

    nadata->cb_en_done(nadata->acc, NULL);
}

static int
gensna_set_accept_callback_enable(struct gensio_accepter *accepter,
				  struct gensna_data *nadata,
				  bool enabled,
				  gensio_acc_done done)
{
    gensio_acc_done ldone = NULL;

    nadata->cb_en_done = done;
    if (done)
	ldone = gensna_cb_en_done;
    return gensio_acc_set_accept_callback_enable_cb(nadata->child, enabled,
						    ldone, nadata);
}

static void
gensna_free(struct gensio_accepter *accepter, struct gensna_data *nadata)
{
    if (nadata->child)
	gensio_acc_free(nadata->child);
    if (nadata->acc_cb)
	nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_FREE, NULL, NULL,
		       NULL, NULL);
    nadata->o->free(nadata->o, nadata);
}

void
gensio_gensio_acc_free_nochild(struct gensio_accepter *accepter)
{
    struct gensna_data *nadata = base_gensio_accepter_get_op_data(accepter);

    nadata->child = NULL;
    gensio_acc_free(accepter);
}

static int
gensna_str_to_gensio(struct gensio_accepter *accepter,
		     struct gensna_data *nadata, const char *addr,
		     gensio_event cb, void *user_data, struct gensio **new_io)
{
    int err;
    struct gensio *child = NULL, *io;
    const char *type = gensio_acc_get_type(accepter, 0);
    size_t typelen = strlen(type);
    int argc = 0;
    const char **args = NULL;

    if (strncmp(addr, type, typelen) != 0 ||
		(addr[typelen] != ',' && addr[typelen] != '(' && addr[typelen]))
	return GE_INVAL;

    addr += typelen;
    if (*addr == '(') {
	err = gensio_scan_args(nadata->o, &addr, &argc, &args);
	if (err)
	    return err;
    } else if (*addr) {
	addr++; /* Skip the ',' */
    }

    err = gensio_acc_str_to_gensio(nadata->child, addr, NULL, NULL, &child);
    if (err)
	goto out;

    err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_ALLOC_GENSIO,
			 child, &io, NULL, args);

    if (!err) {
	gensio_set_callback(io, cb, user_data);
	*new_io = io;
    }

 out:
    if (args)
	gensio_argv_free(nadata->o, args);
    if (err) {
	if (child)
	    gensio_free(child);
    }
    return err;
}

static int
gensna_control(struct gensio_accepter *accepter, struct gensna_data *nadata,
	       bool get, unsigned int option, char *data, gensiods *datalen)
{
    return nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_CONTROL,
			  &get, data, datalen, &option);
}

static void
gensna_disable(struct gensio_accepter *accepter, struct gensna_data *nadata)
{
    nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_DISABLE,
		   NULL, NULL, NULL, NULL);
}

static int
gensio_gensio_base_acc_op(struct gensio_accepter *acc, int op,
			  void *acc_op_data, void *done, int val1,
			  void *data, void *data2, void *ret)
{
    switch(op) {
    case GENSIO_BASE_ACC_STARTUP:
	return gensna_startup(acc, acc_op_data);

    case GENSIO_BASE_ACC_SHUTDOWN:
	return gensna_shutdown(acc, acc_op_data, done);

    case GENSIO_BASE_ACC_SET_CB_ENABLE:
	return gensna_set_accept_callback_enable(acc, acc_op_data, val1, done);

    case GENSIO_BASE_ACC_FREE:
	gensna_free(acc, acc_op_data);
	return 0;

    case GENSIO_BASE_ACC_CONTROL:
	return gensna_control(acc, acc_op_data,
			      val1, *((unsigned int *) done), data, ret);

    case GENSIO_BASE_ACC_STR_TO_GENSIO:
	return gensna_str_to_gensio(acc, acc_op_data, (const char *) data,
				    (gensio_event) done, data2, ret);

    case GENSIO_BASE_ACC_DISABLE:
	gensna_disable(acc, acc_op_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static void
gensna_finish_server_open(struct gensio *net, int err, void *cb_data)
{
    struct gensna_data *nadata = cb_data;

    base_gensio_server_open_done(nadata->acc, net, err);
}

static int
gensna_child_event(struct gensio_accepter *accepter, void *user_data,
		   int event, void *data)
{
    struct gensna_data *nadata = user_data;
    struct gensio_os_funcs *o = nadata->o;
    struct gensio_filter *filter = NULL;
    struct gensio_ll *ll = NULL;
    struct gensio *io = NULL, *child;
    void *finish_data;
    bool base_allocated = true;
    int err;

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return gensio_acc_cb(nadata->acc, event, data);

    child = data;
    err = base_gensio_accepter_new_child_start(nadata->acc);
    if (err)
	goto out_err;

    err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_NEW_CHILD,
			 &finish_data, &filter, child, NULL);
    if (err == GE_NOTSUP) {
	struct gensio_new_child_io ncio;

	ncio.child = child;
	ncio.open_done = gensna_finish_server_open;
	ncio.open_data = nadata;
	err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_NEW_CHILD_IO,
			     &finish_data, &ncio, NULL, NULL);
	if (!err)
	    io = ncio.new_io;
	if (io)
	    base_allocated = false;
    }

    if (err)
	goto out_err_unlock;

    if (filter) {
	ll = gensio_gensio_ll_alloc(o, child);
	if (!ll)
	    goto out_nomem;
    }

    if (filter)
	io = base_gensio_server_alloc(o, ll, filter, child,
				      gensio_acc_get_type(nadata->acc, 0),
				      gensna_finish_server_open, nadata);
    if (!io)
	goto out_nomem;

    if (gensio_is_reliable(child))
	gensio_set_is_reliable(io, true);
    if (gensio_is_authenticated(child))
	gensio_set_is_authenticated(io, true);
    if (gensio_is_encrypted(child))
	gensio_set_is_encrypted(io, true);
    err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_FINISH_PARENT,
			 finish_data, io, child, NULL);
    if (err && err != GE_NOTSUP)
	goto out_err_unlock;

    if (base_allocated) {
	err = base_gensio_server_start(io);
	if (err)
	    goto out_err_unlock;
    }

    base_gensio_accepter_new_child_end(nadata->acc, io, 0);

    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err_unlock:
    base_gensio_accepter_new_child_end(nadata->acc, NULL, err);
 out_err:
    if (io) {
	gensio_free(io);
    } else {
	if (ll)
	    gensio_ll_free(ll);
	else
	    gensio_free(child);
	if (filter)
	    gensio_filter_free(filter);
    }
    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		   "Error allocating gensna gensio: %s",
		   gensio_err_to_str(err));
    return err;
}

int
gensio_gensio_accepter_alloc(struct gensio_accepter *child,
			     struct gensio_os_funcs *o,
			     const char *typename,
			     gensio_accepter_event cb, void *user_data,
			     gensio_gensio_acc_cb acc_cb,
			     void *acc_data,
			     struct gensio_accepter **accepter)
{
    struct gensna_data *nadata;
    int rv;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    nadata->o = o;

    rv = base_gensio_accepter_alloc(child, gensio_gensio_base_acc_op, nadata,
				    o, typename, cb, user_data, accepter);
    if (rv) {
	o->free(o, nadata);
	goto out;
    }

    nadata->acc_cb = acc_cb;
    nadata->acc_data = acc_data;
    nadata->child = child;
    nadata->acc = *accepter;
    gensio_acc_set_callback(child, gensna_child_event, nadata);

 out:
    return rv;
}
