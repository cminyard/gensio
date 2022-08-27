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

#include "gensio_filter_certauth.h"

static int
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
    bool is_client;

    err = gensio_certauth_filter_config(o, args, true, &data);
    if (err)
	return err;

    if (!gensio_is_reliable(child) ||
	!(gensio_is_encrypted(child) ||
	  gensio_certauth_filter_config_allow_unencrypted(data)))
	/*
	 * Cowardly refusing to run over an unreliable or unencrypted
	 * connection.  The allow-unencrypted flag is internal for
	 * testing and undocumented.
	 */
	return GE_NOTSUP;

    is_client = gensio_certauth_filter_config_is_client(data);
    err = gensio_certauth_filter_alloc(data, &filter);
    gensio_certauth_filter_config_free(data);
    if (err)
	return err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "certauth", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_set_is_client(io, is_client);
    gensio_set_is_packet(io, true);
    gensio_set_is_reliable(io, true);
    gensio_set_is_encrypted(io, true);
    gensio_free(child); /* Lose the ref we acquired. */

    *net = io;
    return 0;
}

static int
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

static int
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
certauthna_gensio_event(struct gensio *io, void *user_data, int event, int err,
			unsigned char *buf, gensiods *buflen,
			const char *const *auxdata)
{
    struct certauthna_data *nadata = user_data;
    struct gensio_acc_password_verify_data pwvfy;
    struct gensio_acc_postcert_verify_data postvfy;
    int rv;

    switch (event) {
    case GENSIO_EVENT_AUTH_BEGIN:
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_AUTH_BEGIN, io);

    case GENSIO_EVENT_PRECERT_VERIFY:
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_PRECERT_VERIFY, io);

    case GENSIO_EVENT_POSTCERT_VERIFY:
	postvfy.io = io;
	postvfy.err = err;
	postvfy.errstr = auxdata ? auxdata[0] : NULL;
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_POSTCERT_VERIFY,
			     &postvfy);

    case GENSIO_EVENT_PASSWORD_VERIFY:
	pwvfy.io = io;
	pwvfy.password = (char *) buf;
	pwvfy.password_len = *buflen;
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

    case GENSIO_EVENT_2FA_VERIFY:
	pwvfy.io = io;
	pwvfy.password = (char *) buf;
	pwvfy.password_len = *buflen;
	return gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_2FA_VERIFY,
			     &pwvfy);

    case GENSIO_EVENT_REQUEST_2FA:
	pwvfy.io = io;
	pwvfy.password = (char *) buf;
	pwvfy.password_len = 0;
	rv = gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_REQUEST_2FA,
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
    struct certauthna_data *nadata = acc_data;

    gensio_set_is_client(io, gensio_certauth_filter_config_is_client(
					nadata->data));
    gensio_set_is_packet(io, true);
    gensio_set_is_reliable(io, true);
    gensio_set_is_encrypted(io, true);

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

static int
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

static int
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

int
gensio_init_certauth(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "certauth",
				str_to_certauth_gensio, certauth_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "certauth",
					 str_to_certauth_gensio_accepter,
					 certauth_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
