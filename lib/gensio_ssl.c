/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <gensio/gensio_err.h>

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/gensio_class.h>

#include "gensio_filter_ssl.h"

static int
ssl_gensio_alloc(struct gensio *child, const char *const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    struct gensio_ssl_filter_data *data;

    if (!gensio_is_reliable(child))
	/* Cowardly refusing to run SSL over an unreliable connection. */
	return GE_NOTSUP;

    err = gensio_ssl_filter_config(o, args, true, &data);
    if (err)
	return err;

    err = gensio_ssl_filter_alloc(data, &filter);
    gensio_ssl_filter_config_free(data);
    if (err)
	return err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "ssl", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_set_is_packet(io, true);
    gensio_set_is_reliable(io, true);
    gensio_set_is_encrypted(io, true);
    gensio_free(child); /* Lose the ref we acquired. */

    *net = io;
    return 0;
}

static int
str_to_ssl_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    err = str_to_gensio(str, o, NULL, NULL, &io2);
    if (err)
	return err;

    err = ssl_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct sslna_data {
    struct gensio_accepter *acc;
    struct gensio_ssl_filter_data *data;
    struct gensio_os_funcs *o;
};

static void
sslna_free(void *acc_data)
{
    struct sslna_data *nadata = acc_data;

    gensio_ssl_filter_config_free(nadata->data);
    nadata->o->free(nadata->o, nadata);
}

static int
sslna_alloc_gensio(void *acc_data, const char * const *iargs,
		   struct gensio *child, struct gensio **rio)
{
    struct sslna_data *nadata = acc_data;

    return ssl_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);
}

static int
sslna_new_child(void *acc_data, void **finish_data,
		struct gensio_filter **filter)
{
    struct sslna_data *nadata = acc_data;

    return gensio_ssl_filter_alloc(nadata->data, filter);
}

static int
sslna_gensio_event(struct gensio *io, void *user_data, int event, int err,
		   unsigned char *buf, gensiods *buflen,
		   const char *const *auxdata)
{
    struct sslna_data *nadata = user_data;

    if (event != GENSIO_EVENT_PRECERT_VERIFY)
	return GE_NOTSUP;

    return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_PRECERT_VERIFY, io);
}

static int
sslna_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    gensio_set_callback(io, sslna_gensio_event, acc_data);

    gensio_set_is_packet(io, true);
    gensio_set_is_reliable(io, true);
    return 0;
}

static int
gensio_gensio_acc_ssl_cb(void *acc_data, int op, void *data1, void *data2,
			 void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return sslna_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return sslna_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return sslna_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	sslna_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
ssl_gensio_accepter_alloc(struct gensio_accepter *child,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_accepter_event cb, void *user_data,
			  struct gensio_accepter **accepter)
{
    struct sslna_data *nadata;
    int err;

    if (!gensio_acc_is_reliable(child))
	/* Cowardly refusing to run SSL over an unreliable connection. */
	return GE_NOTSUP;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    err = gensio_ssl_filter_config(o, args, false, &nadata->data);
    if (err) {
	o->free(o, nadata);
	return err;
    }

    nadata->o = o;

    err = gensio_gensio_accepter_alloc(child, o, "ssl", cb, user_data,
				       gensio_gensio_acc_ssl_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;
    gensio_acc_set_is_packet(nadata->acc, true);
    gensio_acc_set_is_reliable(nadata->acc, true);
    *accepter = nadata->acc;

    return 0;

 out_err:
    sslna_free(nadata);
    return err;
}

static int
str_to_ssl_gensio_accepter(const char *str, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb,
			   void *user_data,
			   struct gensio_accepter **acc)
{
    int err;
    struct gensio_accepter *acc2 = NULL;

    err = str_to_gensio_accepter(str, o, NULL, NULL, &acc2);
    if (!err) {
	err = ssl_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_ssl(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "ssl",
				str_to_ssl_gensio, ssl_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "ssl",
					 str_to_ssl_gensio_accepter,
					 ssl_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
