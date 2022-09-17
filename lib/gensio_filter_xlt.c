/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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
#include <gensio/gensio_class.h>
#include <gensio/gensio_os_funcs.h>

#include "gensio_filter_xlt.h"

struct xlt_filter {
    struct gensio_filter *filter;

    struct gensio_lock *lock;

    unsigned char inxlt[256];
    unsigned char inbuf[256];
    gensiods inlen;

    unsigned char outxlt[256];
    unsigned char outbuf[256];
    gensiods outlen;

    struct gensio_os_funcs *o;
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
	    tfilter->outbuf[pos++] = tfilter->outxlt[buf[j]];
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
	tfilter->inbuf[pos++] = tfilter->inxlt[buf[i]];
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

int
gensio_xlt_filter_alloc(struct gensio_os_funcs *o,
			const char * const args[],
			struct gensio_filter **rfilter)
{
    int rv = GE_INVAL;
    unsigned int i;
    struct xlt_filter *tfilter;
    const char *str;
    bool bval;

    tfilter = o->zalloc(o, sizeof(*tfilter));
    if (!tfilter)
	return GE_NOMEM;

    tfilter->o = o;

    for (i = 0; i < 256; i++) {
	tfilter->inxlt[i] = i;
	tfilter->outxlt[i] = i;
    }

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

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyvalue(args[i], "in", &str) > 0) {
	    rv = process_xlt(tfilter->inxlt, str);
	    if (rv)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "out", &str) > 0) {
	    rv = process_xlt(tfilter->outxlt, str);
	    if (rv)
		goto out_err;
	    continue;
	}
	if (gensio_check_keybool(args[i], "crlf", &bval) > 0) {
	    tfilter->inxlt['\r'] = '\n';
	    tfilter->outxlt['\n'] = '\r';
	    continue;
	}
	if (gensio_check_keybool(args[i], "lfcr", &bval) > 0) {
	    tfilter->outxlt['\r'] = '\n';
	    tfilter->inxlt['\n'] = '\r';
	    continue;
	}
	if (gensio_check_keybool(args[i], "crnl", &bval) > 0) {
	    tfilter->inxlt['\r'] = '\n';
	    tfilter->outxlt['\n'] = '\r';
	    continue;
	}
	if (gensio_check_keybool(args[i], "nlcr", &bval) > 0) {
	    tfilter->outxlt['\r'] = '\n';
	    tfilter->inxlt['\n'] = '\r';
	    continue;
	}
	goto out_err;
    }

    *rfilter = tfilter->filter;
    return 0;

 out_err:
    tfilter_free(tfilter);
    return rv;
}
