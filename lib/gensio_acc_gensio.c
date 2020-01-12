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
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include <gensio/gensio_class.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/argvutils.h>

struct basena_data {
    struct gensio_accepter *acc;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_accepter *child;

    gensio_gensio_acc_cb acc_cb;
    void *acc_data;

    unsigned int refcount;
    unsigned int in_cb_count;

    bool enabled;
    bool in_shutdown;
    bool freed;
    bool call_shutdown_done;
    gensio_acc_done shutdown_done;
    void *shutdown_data;
};

static void
basena_lock(struct basena_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
basena_unlock(struct basena_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void
basena_finish_free(struct basena_data *nadata)
{
    if (nadata->child)
	gensio_acc_free(nadata->child);
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->acc_cb)
	nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_FREE, NULL, NULL,
		       NULL, NULL);
    if (nadata->acc)
	gensio_acc_data_free(nadata->acc);
    nadata->o->free(nadata->o, nadata);
}

static void
basena_ref(struct basena_data *nadata)
{
    assert(nadata->refcount > 0);
    nadata->refcount++;
}

static void
basena_deref_and_unlock(struct basena_data *nadata)
{
    unsigned int count;

    assert(nadata->refcount > 0);
    count = --nadata->refcount;
    basena_unlock(nadata);
    if (count == 0)
	basena_finish_free(nadata);
}

static void
basena_finish_shutdown_unlock(struct basena_data *nadata)
{
    void *shutdown_data;
    void (*shutdown_done)(struct gensio_accepter *accepter,
			  void *shutdown_data);

    nadata->in_shutdown = false;
    shutdown_done = nadata->shutdown_done;
    shutdown_data = nadata->shutdown_data;
    nadata->shutdown_done = NULL;
    basena_unlock(nadata);

    if (shutdown_done)
	shutdown_done(nadata->acc, shutdown_data);

    basena_lock(nadata);
    basena_deref_and_unlock(nadata);
}

static void
basena_in_cb(struct basena_data *nadata)
{
    basena_ref(nadata);
    nadata->in_cb_count++;
}

static void
basena_leave_cb_unlock(struct basena_data *nadata)
{
    nadata->in_cb_count--;
    if (nadata->in_cb_count == 0 && nadata->call_shutdown_done)
	basena_finish_shutdown_unlock(nadata);
    else
	basena_deref_and_unlock(nadata);
}

static int
basena_startup(struct gensio_accepter *accepter)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);
    int err;

    basena_lock(nadata);
    err = gensio_acc_startup(nadata->child);
    if (!err)
	nadata->enabled = true;
    basena_unlock(nadata);

    return err;
}

static void
basena_child_shutdown(struct gensio_accepter *accepter,
		     void *shutdown_data)
{
    struct basena_data *nadata = shutdown_data;

    basena_lock(nadata);
    if (nadata->in_cb_count) {
	nadata->call_shutdown_done = true;
	basena_unlock(nadata);
    } else {
	basena_finish_shutdown_unlock(nadata);
    }
}

static int
basena_shutdown(struct gensio_accepter *accepter,
		gensio_acc_done shutdown_done,
		void *shutdown_data)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = GE_NOTREADY;

    basena_lock(nadata);
    if (nadata->enabled) {
	nadata->shutdown_done = shutdown_done;
	nadata->shutdown_data = shutdown_data;

	rv = gensio_acc_shutdown(nadata->child, basena_child_shutdown, nadata);
	if (!rv) {
	    basena_ref(nadata);
	    nadata->enabled = false;
	    nadata->in_shutdown = true;
	}
    }
    basena_unlock(nadata);
    return rv;
}

static int
basena_set_accept_callback_enable(struct gensio_accepter *accepter,
				  bool enabled,
				  gensio_acc_done done, void *done_data)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

    return gensio_acc_set_accept_callback_enable_cb(nadata->child, enabled,
						    done, done_data);
}

static void
basena_free(struct gensio_accepter *accepter)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv;

    basena_lock(nadata);
    assert(!nadata->freed);
    nadata->freed = true;
    if (nadata->in_shutdown) {
	nadata->shutdown_done = NULL;
	basena_deref_and_unlock(nadata);
    } else {
	rv = gensio_acc_shutdown(nadata->child, basena_child_shutdown, nadata);
	if (rv) {
	    basena_deref_and_unlock(nadata);
	} else {
	    /* No ref here, we let the shutdown ref free it. */
	    nadata->enabled = false;
	    nadata->in_shutdown = true;
	    basena_unlock(nadata);
	}
    }
}

static int
basena_str_to_gensio(struct gensio_accepter *accepter, const char *addr,
		     gensio_event cb, void *user_data, struct gensio **new_io)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);
    int err;
    struct gensio *child = NULL, *io;
    const char *type = gensio_acc_get_type(accepter, 0);
    unsigned int typelen = strlen(type);
    int argc = 0;
    const char **args = NULL;

    if (strncmp(addr, type, typelen) != 0 ||
		(addr[typelen] != ',' && addr[typelen] != '(' && addr[typelen]))
	return GE_INVAL;

    addr += typelen;
    if (*addr == '(') {
	err = gensio_scan_args(nadata->o, &addr, &argc, &args);
	if (err)
	    return err;
    } else if (*addr) {
	addr++; /* Skip the ',' */
    }

    err = gensio_acc_str_to_gensio(nadata->child, addr, NULL, NULL, &child);
    if (err)
	goto out;

    err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_ALLOC_GENSIO,
			 child, &io, NULL, args);

    if (!err) {
	gensio_set_callback(io, cb, user_data);
	*new_io = io;
    }

 out:
    if (args)
	gensio_argv_free(nadata->o, args);
    if (err) {
	if (child)
	    gensio_free(child);
    }
    return err;
}

static int
basena_control(struct gensio_accepter *accepter, bool get, unsigned int option,
	       char *data, gensiods *datalen)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

    return nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_CONTROL,
			  &get, data, datalen, &option);
}

static int
basena_disable(struct gensio_accepter *accepter)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

    return nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_DISABLE,
			  NULL, NULL, NULL, NULL);
}

static int
gensio_acc_base_func(struct gensio_accepter *acc, int func, int val,
		     const char *addr, void *done, void *data, const
		     void *data2, void *ret)
{
    switch (func) {
    case GENSIO_ACC_FUNC_STARTUP:
	return basena_startup(acc);

    case GENSIO_ACC_FUNC_SHUTDOWN:
	return basena_shutdown(acc, done, data);

    case GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK:
	return basena_set_accept_callback_enable(acc, val, done, data);

    case GENSIO_ACC_FUNC_FREE:
	basena_free(acc);
	return 0;

    case GENSIO_ACC_FUNC_STR_TO_GENSIO:
	return basena_str_to_gensio(acc, addr, done, data, ret);

    case GENSIO_ACC_FUNC_CONTROL:
	return basena_control(acc, val, *((unsigned int *) done), data, ret);

    case GENSIO_ACC_FUNC_DISABLE:
	return basena_disable(acc);

    default:
	return GE_NOTSUP;
    }
}

static void
basena_finish_server_open(struct gensio *net, int err, void *cb_data)
{
    struct basena_data *nadata = cb_data;

    basena_lock(nadata);
    if (err) {
	gensio_free(net);
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Error accepting a gensio: %s",
		       gensio_err_to_str(err));
    } else if (!nadata->in_shutdown) {
	nadata->in_cb_count++;
	basena_unlock(nadata);
	gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_NEW_CONNECTION, net);
	basena_lock(nadata);
	nadata->in_cb_count--;
    }

    gensio_acc_remove_pending_gensio(nadata->acc, net);
    basena_leave_cb_unlock(nadata);
}

static int
basena_child_event(struct gensio_accepter *accepter, void *user_data,
		   int event, void *data)
{
    struct basena_data *nadata = user_data;
    struct gensio_os_funcs *o = nadata->o;
    struct gensio_filter *filter = NULL;
    struct gensio_ll *ll = NULL;
    struct gensio *io = NULL, *child;
    void *finish_data;
    int err;

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return gensio_acc_cb(nadata->acc, event, data);

    child = data;
    basena_lock(nadata);
    if (nadata->in_shutdown) {
	basena_unlock(nadata);
	gensio_free(child);
	return GE_NOTREADY;
    }

    err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_NEW_CHILD,
			 &finish_data, &filter, child, NULL);
    if (err == GE_NOTSUP) {
	struct gensio_new_child_io ncio;

	ncio.child = child;
	ncio.open_done = basena_finish_server_open;
	ncio.open_data = nadata;
	err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_NEW_CHILD_IO,
			     &finish_data, &ncio, NULL, NULL);
	if (!err)
	    io = ncio.new_io;
    }
	
    if (err)
	goto out_err_unlock;

    if (filter) {
	ll = gensio_gensio_ll_alloc(o, child);
	if (!ll)
	    goto out_nomem;
    }

    if (filter)
	io = base_gensio_server_alloc(o, ll, filter, child,
				      gensio_acc_get_type(nadata->acc, 0),
				      basena_finish_server_open, nadata);
    if (!io)
	goto out_nomem;

    if (gensio_is_reliable(child))
	gensio_set_is_reliable(io, true);
    if (gensio_is_authenticated(child))
	gensio_set_is_authenticated(io, true);
    if (gensio_is_encrypted(child))
	gensio_set_is_encrypted(io, true);
    err = nadata->acc_cb(nadata->acc_data, GENSIO_GENSIO_ACC_FINISH_PARENT,
			 finish_data, io, child, NULL);
    if (err && err != GE_NOTSUP)
	goto out_err_unlock;
    basena_in_cb(nadata);
    gensio_acc_add_pending_gensio(nadata->acc, io);
    basena_unlock(nadata);
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err_unlock:
    basena_unlock(nadata);
    if (io) {
	gensio_free(io);
    } else {
	if (ll)
	    gensio_ll_free(ll);
	if (filter)
	    gensio_filter_free(filter);
    }
    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		   "Error allocating basena gensio: %s",
		   gensio_err_to_str(err));
    return err;
}

int
gensio_gensio_accepter_alloc(struct gensio_accepter *child,
			     struct gensio_os_funcs *o,
			     const char *typename,
			     gensio_accepter_event cb, void *user_data,
			     gensio_gensio_acc_cb acc_cb,
			     void *acc_data,
			     struct gensio_accepter **accepter)
{
    struct basena_data *nadata;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    nadata->o = o;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    nadata->acc = gensio_acc_data_alloc(o, cb, user_data, gensio_acc_base_func,
					child, typename, nadata);
    if (!nadata->acc)
	goto out_nomem;

    nadata->child = child;
    nadata->acc_cb = acc_cb;
    nadata->acc_data = acc_data;
    nadata->refcount = 1;

    gensio_acc_set_callback(child, basena_child_event, nadata);

    *accepter = nadata->acc;

    return 0;

out_nomem:
    basena_finish_free(nadata);
    return GE_NOMEM;
}
