/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <errno.h>

#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/argvutils.h>

#include "gensio_filter_trace.h"

int
trace_gensio_alloc(struct gensio *child, const char *const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;

    err = gensio_trace_filter_alloc(o, args, &filter);
    if (err)
	return err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "trace", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_set_is_packet(io, true);
    gensio_free(child); /* Lose the ref we acquired. */

    *net = io;
    return 0;
}

int
str_to_trace_gensio(const char *str, const char * const args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    err = str_to_gensio(str, o, NULL, NULL, &io2);
    if (err)
	return err;

    err = trace_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct tracena_data {
    struct gensio_accepter *acc;
    const char **args;
    struct gensio_os_funcs *o;
};

static void
tracena_free(void *acc_data)
{
    struct tracena_data *nadata = acc_data;

    if (nadata->args)
	gensio_argv_free(nadata->o, nadata->args);
    nadata->o->free(nadata->o, nadata);
}

int
tracena_alloc_gensio(void *acc_data, const char * const *iargs,
		     struct gensio *child, struct gensio **rio)
{
    struct tracena_data *nadata = acc_data;

    return trace_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);
}

static int
tracena_new_child(void *acc_data, void **finish_data,
		  struct gensio_filter **filter)
{
    struct tracena_data *nadata = acc_data;

    return gensio_trace_filter_alloc(nadata->o, nadata->args, filter);
}

static int
tracena_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    gensio_set_is_packet(io, true);
    return 0;
}

static int
gensio_gensio_acc_trace_cb(void *acc_data, int op, void *data1, void *data2,
			   void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return tracena_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return tracena_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return tracena_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	tracena_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

int
trace_gensio_accepter_alloc(struct gensio_accepter *child,
			    const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb, void *user_data,
			    struct gensio_accepter **accepter)
{
    struct tracena_data *nadata;
    int err;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    err = gensio_argv_copy(o, args, NULL, &nadata->args);
    if (err) {
	o->free(o, nadata);
	return err;
    }

    nadata->o = o;

    err = gensio_gensio_accepter_alloc(child, o, "trace", cb, user_data,
				       gensio_gensio_acc_trace_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;
    gensio_acc_set_is_packet(nadata->acc, true);
    *accepter = nadata->acc;

    return 0;

 out_err:
    tracena_free(nadata);
    return err;
}

int
str_to_trace_gensio_accepter(const char *str, const char * const args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb,
			     void *user_data,
			     struct gensio_accepter **acc)
{
    int err;
    struct gensio_accepter *acc2 = NULL;

    err = str_to_gensio_accepter(str, o, NULL, NULL, &acc2);
    if (!err) {
	err = trace_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}
