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

#include "gensio_filter_certauth.h"

int
certauth_gensio_alloc(struct gensio *child, const char *const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    struct gensio_certauth_filter_data *data;

    if (!gensio_is_reliable(child) || !gensio_is_encrypted(child))
	/*
	 * Cowardly refusing to run over an unreliable or unencrypted
	 * connection.
	 */
	return GE_NOTSUP;

    err = gensio_certauth_filter_config(o, args, true, &data);
    if (err)
	return err;

    err = gensio_certauth_filter_alloc(data, &filter);
    gensio_certauth_filter_config_free(data);
    if (err)
	return err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	return GE_NOMEM;
    }
    gensio_ref(child);

    io = base_gensio_alloc(o, ll, filter, child, "certauth", cb, user_data);
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

int
str_to_certauth_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    err = str_to_gensio(str, o, NULL, NULL, &io2);
    if (err)
	return err;

    err = certauth_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct certauthna_data {
    struct gensio_accepter *acc;
    struct gensio_certauth_filter_data *data;
    struct gensio_os_funcs *o;
};

static void
certauthna_free(void *acc_data)
{
    struct certauthna_data *nadata = acc_data;

    gensio_certauth_filter_config_free(nadata->data);
    nadata->o->free(nadata->o, nadata);
}

int
certauthna_alloc_gensio(void *acc_data, const char * const *iargs,
			struct gensio *child, struct gensio **rio)
{
    struct certauthna_data *nadata = acc_data;

    return certauth_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);
}

static int
certauthna_new_child(void *acc_data, void **finish_data,
		     struct gensio_filter **filter)
{
    struct certauthna_data *nadata = acc_data;

    return gensio_certauth_filter_alloc(nadata->data, filter);
}

static int
certauthna_gensio_event(struct gensio *io, int event, int err,
			unsigned char *buf, gensiods *buflen,
			const char *const *auxdata)
{
    struct certauthna_data *nadata = gensio_get_user_data(io);
    struct gensio_acc_password_verify_data pwvfy;
    int rv;

    switch (event) {
    case GENSIO_EVENT_AUTH_BEGIN:
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_AUTH_BEGIN, io);

    case GENSIO_EVENT_PRECERT_VERIFY:
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_PRECERT_VERIFY, io);

    case GENSIO_EVENT_PASSWORD_VERIFY:
	pwvfy.io = io;
	pwvfy.password = (char *) buf;
	pwvfy.password_len = strlen((const char *) buf);
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_PASSWORD_VERIFY,
			     &pwvfy);

    case GENSIO_EVENT_REQUEST_PASSWORD:
	pwvfy.io = io;
	pwvfy.password = (char *) buf;
	pwvfy.password_len = *buflen;
	rv = gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_REQUEST_PASSWORD,
			   &pwvfy);
	if (!rv)
	    *buflen = pwvfy.password_len;
	return rv;

    default:
	return GE_NOTSUP;
    }
}

static int
certauthna_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    gensio_set_callback(io, certauthna_gensio_event, acc_data);
    return 0;
}

static int
gensio_gensio_acc_certauth_cb(void *acc_data, int op, void *data1, void *data2,
			      void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return certauthna_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return certauthna_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return certauthna_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	certauthna_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

int
certauth_gensio_accepter_alloc(struct gensio_accepter *child,
			       const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb, void *user_data,
			       struct gensio_accepter **accepter)
{
    struct certauthna_data *nadata;
    int err;

    if (!gensio_acc_is_reliable(child))
	/* Cowardly refusing to run over an unreliable connection. */
	return GE_NOTSUP;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    err = gensio_certauth_filter_config(o, args, false, &nadata->data);
    if (err) {
	o->free(o, nadata);
	return err;
    }

    nadata->o = o;

    err = gensio_gensio_accepter_alloc(child, o, "certauth", cb, user_data,
				       gensio_gensio_acc_certauth_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;
    gensio_acc_set_is_packet(nadata->acc, gensio_acc_is_packet(child));
    gensio_acc_set_is_reliable(nadata->acc, gensio_acc_is_reliable(child));
    *accepter = nadata->acc;

    return 0;

 out_err:
    certauthna_free(nadata);
    return err;
}

int
str_to_certauth_gensio_accepter(const char *str, const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **acc)
{
    int err;
    struct gensio_accepter *acc2 = NULL;

    err = str_to_gensio_accepter(str, o, NULL, NULL, &acc2);
    if (!err) {
	err = certauth_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

#else /* HAVE_OPENSSL */
int
certauth_gensio_alloc(struct gensio *child, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **net)
{
    return GE_NOTSUP;
}

int
str_to_certauth_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return GE_NOTSUP;
}

int
certauth_gensio_accepter_alloc(struct gensio_accepter *child,
			       const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb, void *user_data,
			       struct gensio_accepter **accepter)
{
    return GE_NOTSUP;
}

int
str_to_certauth_gensio_accepter(const char *str, const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **acc)
{
    return GE_NOTSUP;
}

#endif /* HAVE_OPENSSL */
