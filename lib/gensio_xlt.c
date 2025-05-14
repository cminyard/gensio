/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018-2025  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/argvutils.h>

struct xlt_config {
    unsigned char inxlt[256];

    unsigned char outxlt[256];
};

struct xlt_filter {
    struct gensio_filter *filter;

    struct gensio_lock *lock;

    struct gensio_os_funcs *o;

    struct xlt_config config;

    unsigned char inbuf[256];
    gensiods inlen;

    unsigned char outbuf[256];
    gensiods outlen;
};

#define filter_to_xlt(v) ((struct xlt_filter *) \
			  gensio_filter_get_user_data(v))

static void
xlt_lock(struct xlt_filter *tfilter)
{
    tfilter->o->lock(tfilter->lock);
}

static void
xlt_unlock(struct xlt_filter *tfilter)
{
    tfilter->o->unlock(tfilter->lock);
}

static bool
xlt_ul_read_pending(struct gensio_filter *filter)
{
    struct xlt_filter *tfilter = filter_to_xlt(filter);

    return tfilter->inlen > 0;
}

static bool
xlt_ll_write_pending(struct gensio_filter *filter)
{
    struct xlt_filter *tfilter = filter_to_xlt(filter);

    return tfilter->outlen > 0;
}

static bool
xlt_ll_read_needed(struct gensio_filter *filter)
{
    return false;
}

static int
xlt_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static int
xlt_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

static int
xlt_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

static int
xlt_ul_write(struct gensio_filter *filter,
	       gensio_ul_filter_data_handler handler, void *cb_data,
	       gensiods *rcount,
	       const struct gensio_sg *sg, gensiods sglen,
	       const char *const *auxdata)
{
    struct xlt_filter *tfilter = filter_to_xlt(filter);
    int err = 0;
    gensiods i, j, pos = tfilter->outlen;
    gensiods count = 0;

    xlt_lock(tfilter);
    for (i = 0; pos < sizeof(tfilter->outbuf) && i < sglen; i++) {
	const unsigned char *buf = sg[i].buf;

	for (j = 0; pos < sizeof(tfilter->outbuf) && j < sg[i].buflen; j++)
	    tfilter->outbuf[pos++] = tfilter->config.outxlt[buf[j]];
    }
    tfilter->outlen = pos;

    if (tfilter->outlen > 0) {
	struct gensio_sg osg;

	osg.buf = tfilter->outbuf;
	osg.buflen = tfilter->outlen;
	err = handler(cb_data, &count, &osg, 1, auxdata);
	if (!err) {
	    if (count >= tfilter->outlen) {
		tfilter->outlen = 0;
	    } else {
		tfilter->outlen -= count;
		memmove(tfilter->outbuf, tfilter->outbuf + count,
			tfilter->outlen);
	    }
	}
    }
    xlt_unlock(tfilter);

    if (!err && rcount)
	*rcount = pos;

    return err;
}

static int
xlt_ll_write(struct gensio_filter *filter,
	       gensio_ll_filter_data_handler handler, void *cb_data,
	       gensiods *rcount,
	       unsigned char *buf, gensiods buflen,
	       const char *const *auxdata)
{
    struct xlt_filter *tfilter = filter_to_xlt(filter);
    int err = 0;
    gensiods i, pos = tfilter->inlen;
    gensiods count = 0;

    xlt_lock(tfilter);
    for (i = 0; pos < sizeof(tfilter->inbuf) && i < buflen; i++)
	tfilter->inbuf[pos++] = tfilter->config.inxlt[buf[i]];
    tfilter->inlen = pos;

    if (tfilter->inlen > 0) {
	err = handler(cb_data, &count, tfilter->inbuf, tfilter->inlen, auxdata);
	if (!err) {
	    if (count >= tfilter->inlen) {
		tfilter->inlen = 0;
	    } else {
		tfilter->inlen -= count;
		memmove(tfilter->inbuf, tfilter->inbuf + count,
			tfilter->inlen);
	    }
	}
    }
    xlt_unlock(tfilter);

    if (!err && rcount)
	*rcount = pos;

    return err;
}

static int
xlt_setup(struct gensio_filter *filter)
{
    return 0;
}

static void
xlt_filter_cleanup(struct gensio_filter *filter)
{
}

static void
tfilter_free(struct xlt_filter *tfilter)
{
    if (tfilter->lock)
	tfilter->o->free_lock(tfilter->lock);
    if (tfilter->filter)
	gensio_filter_free_data(tfilter->filter);
    tfilter->o->free(tfilter->o, tfilter);
}

static void
xlt_free(struct gensio_filter *filter)
{
    struct xlt_filter *tfilter = filter_to_xlt(filter);

    tfilter_free(tfilter);
}

static int gensio_xlt_filter_func(struct gensio_filter *filter, int op,
				    void *func, void *data,
				    gensiods *count,
				    void *buf, const void *cbuf,
				    gensiods buflen,
				    const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return xlt_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return xlt_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return xlt_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return xlt_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return xlt_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return xlt_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return xlt_ul_write(filter, func, data, count, cbuf, buflen,
			    auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return xlt_ll_write(filter, func, data, count, buf, buflen,
			    auxdata);

    case GENSIO_FILTER_FUNC_SETUP:
	return xlt_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	xlt_filter_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	xlt_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return GE_NOTSUP;

    default:
	return GE_NOTSUP;
    }
}

static int
process_xlt(unsigned char table[256], const char *str)
{
    char *end;
    unsigned long v1, v2;

    v1 = strtoul(str, &end, 0);
    if (end == str || *end != ':' || v1 >= 256)
	return GE_INVAL;
    str = end + 1;
    v2 = strtoul(str, &end, 0);
    if (end == str || *end != '\0' || v1 >= 256)
	return GE_INVAL;
    table[v1] = v2;
    return 0;
}

static int
gensio_xlt_config(struct gensio_pparm_info *p,
		  struct gensio_os_funcs *o,
		  const char * const args[],
		  struct gensio_base_parms *parms,
		  struct xlt_config *config)
{
    int rv;
    const char *str;
    bool bval;
    unsigned int i;

    for (i = 0; i < 256; i++) {
	config->inxlt[i] = i;
	config->outxlt[i] = i;
    }

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_value(p, args[i], "in", &str) > 0) {
	    rv = process_xlt(config->inxlt, str);
	    if (rv)
		return rv;
	    continue;
	}
	if (gensio_pparm_value(p, args[i], "out", &str) > 0) {
	    rv = process_xlt(config->outxlt, str);
	    if (rv)
		return rv;
	    continue;
	}
	if (gensio_pparm_bool(p, args[i], "crlf", &bval) > 0) {
	    config->inxlt['\r'] = '\n';
	    config->outxlt['\n'] = '\r';
	    continue;
	}
	if (gensio_pparm_bool(p, args[i], "lfcr", &bval) > 0) {
	    config->outxlt['\r'] = '\n';
	    config->inxlt['\n'] = '\r';
	    continue;
	}
	if (gensio_pparm_bool(p, args[i], "crnl", &bval) > 0) {
	    config->inxlt['\r'] = '\n';
	    config->outxlt['\n'] = '\r';
	    continue;
	}
	if (gensio_pparm_bool(p, args[i], "nlcr", &bval) > 0) {
	    config->outxlt['\r'] = '\n';
	    config->inxlt['\n'] = '\r';
	    continue;
	}
	if (gensio_base_parm(parms, p, args[i]) > 0)
	    continue;
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }
    return 0;
}

static int
gensio_xlt_filter_alloc(struct gensio_os_funcs *o,
			struct xlt_config *config,
			struct gensio_filter **rfilter)
{
    int rv = GE_INVAL;
    struct xlt_filter *tfilter;

    tfilter = o->zalloc(o, sizeof(*tfilter));
    if (!tfilter)
	return GE_NOMEM;

    tfilter->o = o;
    tfilter->config = *config;

    tfilter->lock = o->alloc_lock(o);
    if (!tfilter->lock) {
	rv = GE_NOMEM;
	goto out_err;
    }

    tfilter->filter = gensio_filter_alloc_data(o, gensio_xlt_filter_func,
					       tfilter);
    if (!tfilter->filter) {
	rv = GE_NOMEM;
	goto out_err;
    }

    *rfilter = tfilter->filter;
    return 0;

 out_err:
    tfilter_free(tfilter);
    return rv;
}

static int
xlt_gensio_alloc2(struct gensio *child, const char *const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio_base_parms **parms,
		  struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    struct xlt_config config;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "xlt", user_data);

    memset(&config, 0, sizeof(config));

    err = gensio_xlt_config(&p, 0, args, *parms, &config);
    if (err)
	return err;

    err = gensio_xlt_filter_alloc(o, &config, &filter);
    if (err)
	return err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "xlt", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	return GE_NOMEM;
    }
    gensio_free(child); /* Lose the ref we acquired. */

    err = gensio_base_parms_set(io, parms);
    if (err) {
	gensio_free(io);
	return err;
    }

    gensio_set_attr_from_child(io, child);

    *net = io;
    return 0;
}

static int
xlt_gensio_alloc(struct gensio *child, const char *const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **net)
{
    struct gensio_base_parms *parms;
    int err;

    err = gensio_base_parms_alloc(o, true, "xlt", &parms);
    if (err)
	return err;

    err = xlt_gensio_alloc2(child, args, o, cb, user_data,
			    &parms, net);

    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
str_to_xlt_gensio(const char *str, const char * const args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    /* cb is passed in for parmerr handling, it will be overriden later. */
    err = str_to_gensio(str, o, cb, user_data, &io2);
    if (err)
	return err;

    err = xlt_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct xltna_data {
    struct gensio_accepter *acc;
    struct xlt_config config;
    struct gensio_os_funcs *o;
    gensio_accepter_event cb;
    void *user_data;
};

static void
xltna_free(void *acc_data)
{
    struct xltna_data *nadata = acc_data;

    nadata->o->free(nadata->o, nadata);
}

static int
xltna_alloc_gensio(void *acc_data, const char * const *iargs,
		     struct gensio *child, struct gensio **rio)
{
    struct xltna_data *nadata = acc_data;
    struct gensio_base_parms *parms = NULL;
    int err;

    parms = gensio_acc_base_parms_dup(nadata->acc);
    if (!parms)
	return GE_NOMEM;

    err = xlt_gensio_alloc2(child, iargs, nadata->o, NULL, NULL,
			    &parms, rio);

    if (parms)
	gensio_base_parms_free(&parms);

    return err;
}

static int
xltna_new_child(void *acc_data, void **finish_data,
		  struct gensio_filter **filter)
{
    struct xltna_data *nadata = acc_data;

    return gensio_xlt_filter_alloc(nadata->o, &nadata->config, filter);
}

static int
xltna_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    gensio_set_attr_from_child(io, gensio_get_child(io, 0));
    return 0;
}

static int
gensio_gensio_acc_xlt_cb(void *acc_data, int op, void *data1, void *data2,
			   void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return xltna_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return xltna_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return xltna_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	xltna_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
xlt_gensio_accepter_alloc(struct gensio_accepter *child,
			    const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb, void *user_data,
			    struct gensio_accepter **accepter)
{
    struct xltna_data *nadata;
    int err;
    struct gensio_base_parms *parms = NULL;
    GENSIO_DECLARE_PPACCEPTER(p, o, cb, "xlt", user_data);

    err = gensio_base_parms_alloc(o, true, "xlt", &parms);
    if (err)
	goto out_err;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	goto out_nomem;

    err = gensio_xlt_config(&p, o, args, parms, &nadata->config);
    if (err)
	goto out_err;

    nadata->o = o;
    nadata->cb = cb;
    nadata->user_data = user_data;

    err = gensio_gensio_accepter_alloc(child, o, "xlt", cb, user_data,
				       gensio_gensio_acc_xlt_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;

    err = gensio_acc_base_parms_set(nadata->acc, &parms);
    if (err)
	goto out_err;

    gensio_acc_set_is_reliable(nadata->acc, gensio_acc_is_reliable(child));
    gensio_acc_set_is_packet(nadata->acc, gensio_acc_is_packet(child));
    gensio_acc_set_is_message(nadata->acc, gensio_acc_is_message(child));
    *accepter = nadata->acc;

    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (nadata) {
	if (nadata->acc)
	    gensio_acc_free(nadata->acc);
	else
	    xltna_free(nadata);
    }
    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
str_to_xlt_gensio_accepter(const char *str, const char * const args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb,
			     void *user_data,
			     struct gensio_accepter **acc)
{
    int err;
    struct gensio_accepter *acc2 = NULL;

    /* cb is passed in for parmerr handling, it will be overriden later. */
    err = str_to_gensio_accepter(str, o, cb, user_data, &acc2);
    if (!err) {
	err = xlt_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_xlt(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "xlt",
				str_to_xlt_gensio, xlt_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "xlt",
					 str_to_xlt_gensio_accepter,
					 xlt_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
