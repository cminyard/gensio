/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 * Like ll_gensio, but has separate children for in and out.
 */

#include "config.h"
#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_ll_gensio.h>

#include <assert.h>

enum ll_2gensio_state {
    LL_2GENSIO_CLOSED,

    /* In an open operation. */
    LL_2GENSIO_IN_OPEN,

    /* Got an error during open, closing children. */
    LL_2GENSIO_OPEN_ERR,

    /* Got a close when in the open process. */
    LL_2GENSIO_OPEN_CLOSE,

    LL_2GENSIO_OPEN,
    LL_2GENSIO_IN_CLOSE,
};

struct ll_2gensio_child {
    struct gensio_ll *ll;
    struct gensio_os_funcs *o;
    gensio_ll_cb cb;
    void *cb_data;

    enum ll_2gensio_state state;

    struct gensio_lock *lock;

    struct gensio *in_child;
    struct gensio *out_child;

    int open_err;
    gensio_ll_open_done open_done;
    void *open_data;
    unsigned int open_count;
    bool in_opened;
    bool out_opened;

    gensio_ll_close_done close_done;
    void *close_data;
    unsigned int close_count;
};

#define ll_to_child(v) ((struct ll_2gensio_child *) gensio_ll_get_user_data(v))

static void
ll_2gensio_lock(struct ll_2gensio_child *cdata)
{
    cdata->o->lock(cdata->lock);
}

static void
ll_2gensio_unlock(struct ll_2gensio_child *cdata)
{
    cdata->o->unlock(cdata->lock);
}

static void
child_set_callbacks(struct gensio_ll *ll, gensio_ll_cb cb, void *cb_data)
{
    struct ll_2gensio_child *cdata = ll_to_child(ll);

    cdata->cb = cb;
    cdata->cb_data = cb_data;
}

static int
child_write(struct gensio_ll *ll, gensiods *rcount,
	    const struct gensio_sg *sg, gensiods sglen,
	    const char *const *auxdata)
{
    struct ll_2gensio_child *cdata = ll_to_child(ll);

    return gensio_write_sg(cdata->out_child, rcount, sg, sglen, auxdata);
}

static void
child_close_handler(struct gensio *io, void *close_data)
{
    struct ll_2gensio_child *cdata = close_data;

    ll_2gensio_lock(cdata);
    cdata->close_count--;
    if (cdata->close_count == 0) {
	ll_2gensio_unlock(cdata);
	cdata->close_done(cdata->cb_data, cdata->close_data);
	return;
    }
    ll_2gensio_unlock(cdata);
}

/*
 * This handles the close of the other child when an open fails.
 */
static void
child_open_close_handler(struct gensio *io, void *close_data)
{
    struct ll_2gensio_child *cdata = close_data;

    ll_2gensio_lock(cdata);
    cdata->close_count--;
    if (cdata->close_count == 0) {
	cdata->state = LL_2GENSIO_CLOSED;
	if (cdata->state == LL_2GENSIO_OPEN_CLOSE) {
	    ll_2gensio_unlock(cdata);
	    cdata->close_done(cdata->cb_data, cdata->close_data);
	} else {
	    ll_2gensio_unlock(cdata);
	    cdata->open_done(cdata->cb_data, cdata->open_err,
			     cdata->open_data);
	}
	return;
    }
    ll_2gensio_unlock(cdata);
}

static void
child_open_handler(struct gensio *io, int err, void *open_data)
{
    struct ll_2gensio_child *cdata = open_data;

    ll_2gensio_lock(cdata);
    if (err)
	cdata->open_err = err;
    else if (io == cdata->in_child)
	cdata->in_opened = true;
    else
	cdata->out_opened = true;

    cdata->open_count--;
    if (cdata->open_count == 0) {
	bool do_open_done = true;

	if (cdata->state == LL_2GENSIO_OPEN_CLOSE || cdata->open_err) {
	    if (cdata->in_opened) {
		do_open_done = false;
		cdata->close_count++;
		gensio_close(cdata->in_child, child_open_close_handler, cdata);
	    }
	    if (cdata->out_opened) {
		do_open_done = false;
		cdata->close_count++;
		gensio_close(cdata->out_child, child_open_close_handler, cdata);
	    }
	    if (do_open_done)
		cdata->state = LL_2GENSIO_CLOSED;
	    else if (cdata->state != LL_2GENSIO_OPEN_CLOSE)
		cdata->state = LL_2GENSIO_OPEN_ERR;
	} else {
	    cdata->state = LL_2GENSIO_OPEN;
	}
	if (do_open_done) {
	    if (cdata->state == LL_2GENSIO_OPEN_CLOSE) {
		ll_2gensio_unlock(cdata);
		cdata->close_done(cdata->cb_data, cdata->close_data);
	    } else {
		ll_2gensio_unlock(cdata);
		cdata->open_done(cdata->cb_data, cdata->open_err,
				 cdata->open_data);
	    }
	    return;
	}
    }
    ll_2gensio_unlock(cdata);
}

static int
child_open(struct gensio_ll *ll, gensio_ll_open_done done, void *open_data)
{
    struct ll_2gensio_child *cdata = ll_to_child(ll);
    int rv;

    ll_2gensio_lock(cdata);
    if (cdata->state != LL_2GENSIO_CLOSED) {
	rv = GE_INUSE;
	goto out_unlock;
    }
    cdata->open_done = done;
    cdata->open_data = open_data;
    cdata->open_count = 2;
    rv = gensio_open(cdata->in_child, child_open_handler, cdata);
    if (rv != 0)
	goto out_unlock;
    cdata->state = LL_2GENSIO_IN_OPEN;
    rv = gensio_open(cdata->out_child, child_open_handler, cdata);
    if (rv != 0) {
	cdata->state = LL_2GENSIO_OPEN_ERR;
	cdata->open_err = rv;
	cdata->open_count--;
    }
    rv = GE_INPROGRESS;

 out_unlock:
    ll_2gensio_unlock(cdata);

    return rv; /* gensios always call the open handler. */
}

static int
child_close(struct gensio_ll *ll, gensio_ll_close_done done, void *close_data)
{
    struct ll_2gensio_child *cdata = ll_to_child(ll);
    int rv = 0;

    ll_2gensio_lock(cdata);
    switch (cdata->state) {
    case LL_2GENSIO_CLOSED:
    case LL_2GENSIO_IN_CLOSE:
    case LL_2GENSIO_OPEN_CLOSE:
	rv = GE_INUSE;
	goto out_unlock;
    default:
	break;
    }

    cdata->close_done = done;
    cdata->close_data = close_data;
    switch (cdata->state) {
    case LL_2GENSIO_IN_OPEN:
    case LL_2GENSIO_OPEN_ERR:
	cdata->state = LL_2GENSIO_OPEN_CLOSE;
	break;

    case LL_2GENSIO_OPEN:
	cdata->close_count = 2;
	rv = gensio_close(cdata->in_child, child_close_handler, cdata);
	assert(rv == 0);
	rv = gensio_close(cdata->out_child, child_close_handler, cdata);
	assert(rv == 0);
	break;

    default:
	break;
    }
 out_unlock:
    ll_2gensio_unlock(cdata);
    return rv;
}

static void child_set_read_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct ll_2gensio_child *cdata = ll_to_child(ll);

    gensio_set_read_callback_enable(cdata->in_child, enabled);
}

static void child_set_write_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct ll_2gensio_child *cdata = ll_to_child(ll);

    gensio_set_write_callback_enable(cdata->out_child, enabled);
}

static void child_free(struct gensio_ll *ll)
{
    struct ll_2gensio_child *cdata = ll_to_child(ll);

    gensio_free(cdata->in_child);
    gensio_free(cdata->out_child);
    gensio_ll_free_data(cdata->ll);
    cdata->o->free_lock(cdata->lock);
    cdata->o->free(cdata->o, cdata);
}

static int
ll_2gensio_child_func(struct gensio_ll *ll, int op, gensiods *count,
		     void *buf, const void *cbuf, gensiods buflen,
		     const char *const *auxdata)
{
    struct ll_2gensio_child *cdata = ll_to_child(ll);

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

    case GENSIO_LL_FUNC_CONTROL:
	return gensio_control(cdata->out_child, GENSIO_CONTROL_DEPTH_FIRST,
			      *((bool *) cbuf), buflen, buf, count);

    case GENSIO_LL_FUNC_FREE:
	child_free(ll);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
in_child_event(struct gensio *io, void *user_data, int event, int err,
	       unsigned char *buf, gensiods *buflen, const char *const *auxdata)
{
    struct ll_2gensio_child *cdata = user_data;
    gensiods rv;

    switch (event) {
    case GENSIO_EVENT_READ:
	rv = cdata->cb(cdata->cb_data, GENSIO_LL_CB_READ, err, buf,
		       buflen ? *buflen : 0, auxdata);
	if (buflen)
	    *buflen = rv;
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	gensio_set_write_callback_enable(cdata->in_child, false);
	return 0;

    default:
	return gensio_ll_do_event(cdata->ll, event, err, buf, buflen, auxdata);
    }
}

static int
out_child_event(struct gensio *io, void *user_data, int event, int err,
		unsigned char *buf, gensiods *buflen,
		const char *const *auxdata)
{
    struct ll_2gensio_child *cdata = user_data;

    switch (event) {
    case GENSIO_EVENT_READ:
	gensio_set_read_callback_enable(cdata->out_child, false);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	cdata->cb(cdata->cb_data, GENSIO_LL_CB_WRITE_READY, 0, NULL, 0, NULL);
	return 0;

    default:
	return gensio_ll_do_event(cdata->ll, event, err, buf, buflen, auxdata);
    }
}

struct gensio_ll *
gensio_2gensio_ll_alloc(struct gensio_os_funcs *o,
			struct gensio *in_child, struct gensio *out_child)
{
    struct ll_2gensio_child *cdata;

    if (out_child == NULL)
	return gensio_gensio_ll_alloc(o, in_child);

    cdata = o->zalloc(o, sizeof(*cdata));
    if (!cdata)
	return NULL;

    cdata->o = o;
    cdata->lock = o->alloc_lock(o);
    if (!cdata->lock) {
	o->free(o, cdata);
	return NULL;
    }

    cdata->ll = gensio_ll_alloc_data(o, ll_2gensio_child_func, cdata);
    if (!cdata->ll) {
	o->free_lock(cdata->lock);
	o->free(o, cdata);
	return NULL;
    }

    cdata->in_child = in_child;
    cdata->out_child = out_child;
    gensio_set_callback(in_child, in_child_event, cdata);
    gensio_set_callback(out_child, out_child_event, cdata);

    return cdata->ll;
}
