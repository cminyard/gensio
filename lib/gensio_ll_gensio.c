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
#include <gensio/gensio_ll_gensio.h>

#include <assert.h>
#include <unistd.h>

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
	    const unsigned char *buf, gensiods buflen,
	    const char *const *auxdata)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    return gensio_write(cdata->child, rcount, buf, buflen, auxdata);
}

static int
child_raddr_to_str(struct gensio_ll *ll, gensiods *pos,
		   char *buf, gensiods buflen)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    return gensio_raddr_to_str(cdata->child, pos, buf, buflen);
}

static int
child_get_raddr(struct gensio_ll *ll, void *addr, gensiods *addrlen)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    return gensio_get_raddr(cdata->child, addr, addrlen);
}

static int
child_remote_id(struct gensio_ll *ll, int *id)
{
    struct gensio_ll_child *cdata = ll_to_child(ll);

    return gensio_remote_id(cdata->child, id);
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
    int rv;

    cdata->close_done = done;
    cdata->close_data = close_data;
    rv = gensio_close(cdata->child, child_close_handler, cdata);
    if (rv == 0)
	rv = GE_INPROGRESS; /* Close is always deferred. */
    return rv;
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
	child_set_callbacks(ll, cbuf, buf);
	return 0;

    case GENSIO_LL_FUNC_WRITE:
	return child_write(ll, count, cbuf, buflen, buf);

    case GENSIO_LL_FUNC_RADDR_TO_STR:
	return child_raddr_to_str(ll, count, buf, buflen);

    case GENSIO_LL_FUNC_GET_RADDR:
	return child_get_raddr(ll, buf, count);

    case GENSIO_LL_FUNC_REMOTE_ID:
	return child_remote_id(ll, buf);

    case GENSIO_LL_FUNC_OPEN:
	return child_open(ll, cbuf, buf);

    case GENSIO_LL_FUNC_CLOSE:
	return child_close(ll, cbuf, buf);

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
child_event(struct gensio *io, int event, int err,
	    unsigned char *buf, gensiods *buflen, const char *const *auxdata)
{
    struct gensio_ll_child *cdata = gensio_get_user_data(io);

    switch (event) {
    case GENSIO_EVENT_READ:
	*buflen = cdata->cb(cdata->cb_data, GENSIO_LL_CB_READ, err, buf,
			    *buflen, NULL);
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
    cdata->child = child;
    cdata->ll = gensio_ll_alloc_data(o, gensio_ll_child_func, cdata);
    if (!cdata->ll) {
	o->free(o, cdata);
	return NULL;
    }

    gensio_set_callback(child, child_event, cdata);

    return cdata->ll;
}
