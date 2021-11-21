/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_ll_gensio.h>

#include <assert.h>

struct gensio_ll_child {
    struct gensio_ll *ll;
    struct gensio_os_funcs *o;
    gensio_ll_cb cb;
    void *cb_data;

    struct gensio *child;

    gensio_ll_open_done open_done;
    void *open_data;

    gensio_ll_close_done close_done;
    void *close_data;
};

#define ll_to_child(v) ((struct gensio_ll_child *) gensio_ll_get_user_data(v))

static void
child_set_callbacks(struct gensio_ll *ll, gensio_ll_cb cb, void *cb_data)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    cdata->cb = cb;
    cdata->cb_data = cb_data;
}

static int
child_write(struct gensio_ll *ll, gensiods *rcount,
	    const struct gensio_sg *sg, gensiods sglen,
	    const char *const *auxdata)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    return gensio_write_sg(cdata->child, rcount, sg, sglen, auxdata);
}

static void
child_open_handler(struct gensio *io, int err, void *open_data)
{
    struct gensio_ll_child *cdata = open_data;

    cdata->open_done(cdata->cb_data, err, cdata->open_data);
}

static int
child_open(struct gensio_ll *ll, gensio_ll_open_done done, void *open_data)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);
    int rv;

    cdata->open_done = done;
    cdata->open_data = open_data;
    rv = gensio_open(cdata->child, child_open_handler, cdata);
    if (rv == 0)
	rv = GE_INPROGRESS; /* gensios always call the open handler. */
    return rv;
}

static void
child_close_handler(struct gensio *io, void *close_data)
{
    struct gensio_ll_child *cdata = close_data;

    cdata->close_done(cdata->cb_data, cdata->close_data);
}

static int
child_close(struct gensio_ll *ll, gensio_ll_close_done done, void *close_data)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    cdata->close_done = done;
    cdata->close_data = close_data;
    return gensio_close(cdata->child, child_close_handler, cdata);
}

static void child_set_read_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    gensio_set_read_callback_enable(cdata->child, enabled);
}

static void child_set_write_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    gensio_set_write_callback_enable(cdata->child, enabled);
}

static void child_free(struct gensio_ll *ll)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    gensio_free(cdata->child);
    gensio_ll_free_data(cdata->ll);
    cdata->o->free(cdata->o, cdata);
}

static int
gensio_ll_child_func(struct gensio_ll *ll, int op, gensiods *count,
		     void *buf, const void *cbuf, gensiods buflen,
		     const char *const *auxdata)
{
    switch (op) {
    case GENSIO_LL_FUNC_SET_CALLBACK:
	child_set_callbacks(ll, (void *) cbuf, buf);
	return 0;

    case GENSIO_LL_FUNC_WRITE_SG:
	return child_write(ll, count, cbuf, buflen, buf);

    case GENSIO_LL_FUNC_OPEN:
	return child_open(ll, (void *) cbuf, buf);

    case GENSIO_LL_FUNC_CLOSE:
	return child_close(ll, (void *) cbuf, buf);

    case GENSIO_LL_FUNC_SET_READ_CALLBACK:
	child_set_read_callback_enable(ll, buflen);
	return 0;

    case GENSIO_LL_FUNC_SET_WRITE_CALLBACK:
	child_set_write_callback_enable(ll, buflen);
	return 0;

    case GENSIO_LL_FUNC_FREE:
	child_free(ll);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
child_event(struct gensio *io, void *user_data, int event, int err,
	    unsigned char *buf, gensiods *buflen, const char *const *auxdata)
{
    struct gensio_ll_child *cdata = user_data;
    gensiods rv;

    switch (event) {
    case GENSIO_EVENT_READ:
	rv = cdata->cb(cdata->cb_data, GENSIO_LL_CB_READ, err, buf,
		       buflen ? *buflen : 0, NULL);
	if (buflen)
	    *buflen = rv;
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	cdata->cb(cdata->cb_data, GENSIO_LL_CB_WRITE_READY, 0, NULL, 0, NULL);
	return 0;

    default:
	return gensio_ll_do_event(cdata->ll, event, err, buf, buflen, auxdata);
    }
}

struct gensio_ll *
gensio_gensio_ll_alloc(struct gensio_os_funcs *o,
		       struct gensio *child)
{
    struct gensio_ll_child *cdata;

    cdata = o->zalloc(o, sizeof(*cdata));
    if (!cdata)
	return NULL;

    cdata->o = o;
    cdata->ll = gensio_ll_alloc_data(o, gensio_ll_child_func, cdata);
    if (!cdata->ll) {
	o->free(o, cdata);
	return NULL;
    }

    cdata->child = child;
    gensio_set_callback(child, child_event, cdata);

    return cdata->ll;
}
