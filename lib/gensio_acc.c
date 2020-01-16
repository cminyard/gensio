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
#include <gensio/gensio_base.h>
#include <gensio/argvutils.h>

struct basena_data {
    struct gensio_accepter *acc;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    gensio_base_acc_op ops;
    void *acc_op_data;

    gensio_gensio_acc_cb acc_cb;
    void *acc_data;

    gensio_acc_done set_cb_enable_done;
    void *set_cb_enable_done_data;

    unsigned int refcount;
    unsigned int in_cb_count;

    bool enabled;
    bool in_shutdown;
    bool shutdown_finished;
    bool freed;
    bool call_shutdown_done;
    gensio_acc_done shutdown_done;
    void *shutdown_data;
};

static int
base_gensio_acc_startup(struct basena_data *nadata)
{
    return nadata->ops(nadata->acc, GENSIO_BASE_ACC_STARTUP,
		       nadata->acc_op_data, NULL, 0, NULL, NULL, NULL);
}

static int
base_gensio_acc_shutdown(struct basena_data *nadata, gensio_acc_done done)
{
    return nadata->ops(nadata->acc, GENSIO_BASE_ACC_SHUTDOWN,
		       nadata->acc_op_data, done, 0, NULL, NULL, NULL);
}

static int
base_gensio_acc_set_cb_enable(struct basena_data *nadata, bool enabled,
			      gensio_acc_done done)
{
    return nadata->ops(nadata->acc, GENSIO_BASE_ACC_SET_CB_ENABLE,
		       nadata->acc_op_data, done, enabled, NULL, NULL, NULL);
}

static int
base_gensio_acc_free(struct basena_data *nadata)
{
    return nadata->ops(nadata->acc, GENSIO_BASE_ACC_FREE,
		       nadata->acc_op_data, NULL, 0, NULL, NULL, NULL);
}

static int
base_gensio_acc_disable(struct basena_data *nadata)
{
    return nadata->ops(nadata->acc, GENSIO_BASE_ACC_DISABLE,
		       nadata->acc_op_data, NULL, 0, NULL, NULL, NULL);
}

static int
base_gensio_acc_control(struct basena_data *nadata, bool get,
			unsigned int option, char *data, gensiods *datalen)
{
    return nadata->ops(nadata->acc, GENSIO_BASE_ACC_CONTROL,
		       nadata->acc_op_data, (unsigned int *) &option,
		       get, data, NULL, datalen);
}

static int
base_gensio_acc_str_to_gensio(struct basena_data *nadata, const char *addr,
			      gensio_event cb, void *user_data,
			      struct gensio **new_io)
{
    return nadata->ops(nadata->acc, GENSIO_BASE_ACC_STR_TO_GENSIO,
		       nadata->acc_op_data, cb, 0, (void *) addr, user_data,
		       new_io);
}

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
    struct gensio_os_funcs *o = nadata->o;

    if (nadata->lock)
	o->free_lock(nadata->lock);
    if (nadata->ops)
	base_gensio_acc_free(nadata);
    if (nadata->acc)
	gensio_acc_data_free(nadata->acc);
    memset(nadata, 0, sizeof(*nadata));
    o->free(o, nadata);
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
    nadata->shutdown_finished = true;
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
    assert(!nadata->freed);
    if (nadata->enabled || nadata->in_shutdown) {
	err = GE_NOTREADY;
    } else {
	nadata->shutdown_finished = false;
	err = base_gensio_acc_startup(nadata);
	if (!err)
	    nadata->enabled = true;
    }
    basena_unlock(nadata);

    return err;
}

static void
basena_child_shutdown_done(struct gensio_accepter *accepter,
			   void *shutdown_data)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

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

	rv = base_gensio_acc_shutdown(nadata,
				      basena_child_shutdown_done);
	if (!rv) {
	    basena_ref(nadata);
	    nadata->enabled = false;
	    nadata->in_shutdown = true;
	}
    }
    basena_unlock(nadata);
    return rv;
}

static void
basena_cb_en_done(struct gensio_accepter *accepter, void *cb_data)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);
    gensio_acc_done done;
    void *done_data;
    struct gensio_accepter *acc = nadata->acc;

    basena_lock(nadata);
    done = nadata->set_cb_enable_done;
    done_data = nadata->set_cb_enable_done_data;
    nadata->set_cb_enable_done = NULL;
    basena_unlock(nadata);

    done(acc, done_data);

    basena_lock(nadata);
    basena_leave_cb_unlock(nadata);
}

static int
basena_set_accept_callback_enable(struct gensio_accepter *accepter,
				  bool enabled,
				  gensio_acc_done done, void *done_data)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);
    gensio_acc_done ldone = NULL;
    int rv = 0;

    basena_lock(nadata);
    if (done && nadata->set_cb_enable_done) {
	rv = GE_NOTREADY;
    } else if (done) {
	nadata->set_cb_enable_done = done;
	nadata->set_cb_enable_done_data = done_data;
	ldone = basena_cb_en_done;
    }
    if (!rv)
	rv = base_gensio_acc_set_cb_enable(nadata, enabled, ldone);
    if (!rv && done)
	basena_in_cb(nadata);
    basena_unlock(nadata);
    return rv;
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
    } else if (nadata->shutdown_finished) {
	basena_deref_and_unlock(nadata);
    } else {
	rv = base_gensio_acc_shutdown(nadata,
				      basena_child_shutdown_done);
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

    return base_gensio_acc_str_to_gensio(nadata, addr, cb, user_data, new_io);
}

static int
basena_control(struct gensio_accepter *accepter, bool get, unsigned int option,
	       char *data, gensiods *datalen)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

    return base_gensio_acc_control(nadata, get, option, data, datalen);
}

static int
basena_disable(struct gensio_accepter *accepter)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

    return base_gensio_acc_disable(nadata);
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

int
base_gensio_accepter_new_child_start(struct gensio_accepter *accepter)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

    basena_lock(nadata);
    if (!nadata->enabled) {
	basena_unlock(nadata);
	return GE_NOTREADY;
    }
    return 0;
}

void
base_gensio_accepter_new_child_end(struct gensio_accepter *accepter,
				   struct gensio *io, int err)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

    if (!err) {
	basena_in_cb(nadata);
	gensio_acc_add_pending_gensio(nadata->acc, io);
    }
    basena_unlock(nadata);
}

void
base_gensio_io_closed_on_init(struct gensio *io, void *cb_data)
{
    gensio_free(io);
}

void
base_gensio_server_open_done(struct gensio_accepter *accepter,
			     struct gensio *net, int err)
{
    struct basena_data *nadata = gensio_acc_get_gensio_data(accepter);

    basena_lock(nadata);
    gensio_acc_remove_pending_gensio(nadata->acc, net);
    if (err) {
	gensio_close(net, base_gensio_io_closed_on_init, NULL);
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

    basena_leave_cb_unlock(nadata);
}

int
base_gensio_accepter_alloc(struct gensio_accepter *child,
			   gensio_base_acc_op ops,
			   void *acc_op_data,
			   struct gensio_os_funcs *o,
			   const char *typename,
			   gensio_accepter_event cb, void *user_data,
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

    nadata->ops = ops;
    nadata->acc_op_data = acc_op_data;
    nadata->refcount = 1;

    *accepter = nadata->acc;

    return 0;

out_nomem:
    basena_finish_free(nadata);
    return GE_NOMEM;
}
