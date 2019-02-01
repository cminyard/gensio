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

#include <gensio/gensio_class.h>

#ifdef HAVE_OPENSSL

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>

#include "gensio_filter_ssl.h"

int
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
	return EOPNOTSUPP;

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
	return ENOMEM;
    }
    gensio_ref(child);

    io = base_gensio_alloc(o, ll, filter, child, "ssl", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	return ENOMEM;
    }

    gensio_set_is_packet(io, true);
    gensio_set_is_reliable(io, true);
    gensio_set_is_encrypted(io, true);
    gensio_free(child); /* Lose the ref we acquired. */

    *net = io;
    return 0;
}

int
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

int
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
sslna_gensio_event(struct gensio *io, int event, int err,
		   unsigned char *buf, gensiods *buflen,
		   const char *const *auxdata)
{
    struct sslna_data *nadata = gensio_get_user_data(io);

    if (event != GENSIO_EVENT_PRECERT_VERIFY)
	return ENOTSUP;

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
	return ENOTSUP;
    }
}

int
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
	return EOPNOTSUPP;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return ENOMEM;

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

int
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

#else /* HAVE_OPENSSL */
int
ssl_gensio_alloc(struct gensio *child, const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **net)
{
    return ENOTSUP;
}

int
str_to_ssl_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return ENOTSUP;
}

int
ssl_gensio_accepter_alloc(struct gensio_accepter *child,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_accepter_event cb, void *user_data,
			  struct gensio_accepter **accepter)
{
    return ENOTSUP;
}

int
str_to_ssl_gensio_accepter(const char *str, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb,
			   void *user_data,
			   struct gensio_accepter **acc)
{
    return ENOTSUP;
}

#endif /* HAVE_OPENSSL */
