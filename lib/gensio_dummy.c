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

/* This code creates a dummy gensio accepter that doesn't do anything. */

#include "config.h"
#include <gensio/gensio.h>
#include <gensio/gensio_class.h>

struct dummyna_data;

enum dummyna_state {
    DUMMY_DISABLED,
    DUMMY_ENABLED,
    DUMMY_IN_SHUTDOWN
};

struct dummyna_data {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    struct gensio_runner *shutdown_runner;
    gensio_acc_done shutdown_done;
    void *shutdown_data;
    enum dummyna_state state;
    struct gensio_accepter *acc;
};

static void
dummyna_lock(struct dummyna_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
dummyna_unlock(struct dummyna_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static int
dummyna_startup(struct gensio_accepter *accepter)
{
    struct dummyna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    dummyna_lock(nadata);
    if (nadata->state != DUMMY_DISABLED)
	rv = GE_INUSE;
    nadata->state = DUMMY_ENABLED;
    dummyna_unlock(nadata);
    return rv;
}

static void
dummyna_do_shutdown(struct gensio_runner *runner, void *cb_data)
{
    struct dummyna_data *nadata = cb_data;
    gensio_acc_done shutdown_done;
    void *shutdown_data;

    dummyna_lock(nadata);
    nadata->state = DUMMY_DISABLED;
    shutdown_done = nadata->shutdown_done;
    shutdown_data = nadata->shutdown_data;
    dummyna_unlock(nadata);

    shutdown_done(nadata->acc, shutdown_data);
}

static int
dummyna_shutdown(struct gensio_accepter *accepter,
		 gensio_acc_done shutdown_done, void *shutdown_data)
{
    struct dummyna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    dummyna_lock(nadata);
    if (nadata->state != DUMMY_ENABLED) {
	rv = GE_INUSE;
    } else {
	nadata->state = DUMMY_IN_SHUTDOWN;
	/* Run the shutdown response in a runner to avoid deadlocks. */
	nadata->shutdown_done = shutdown_data;
	nadata->shutdown_data = shutdown_data;
	nadata->o->run(nadata->shutdown_runner);
	dummyna_unlock(nadata);
    }

    return rv;
}

static int
dummyna_set_accept_callback_enable(struct gensio_accepter *accepter,
				   bool enabled,
				   gensio_acc_done done, void *done_data)
{
    return 0;
}

static void
dummyna_finish_free(struct dummyna_data *nadata)
{
    struct gensio_os_funcs *o = nadata->o;

    o->free_runner(nadata->shutdown_runner);
    o->free_lock(nadata->lock);
    o->free(o, nadata);
}

static void
dummyna_free(struct gensio_accepter *accepter)
{
    struct dummyna_data *nadata = gensio_acc_get_gensio_data(accepter);

    dummyna_finish_free(nadata);
}

static int
gensio_acc_dummy_func(struct gensio_accepter *acc, int func, int val,
		      const char *addr, void *done, void *data,
		      const void *data2, void *ret)
{
    switch (func) {
    case GENSIO_ACC_FUNC_STARTUP:
	return dummyna_startup(acc);

    case GENSIO_ACC_FUNC_SHUTDOWN:
	return dummyna_shutdown(acc, done, data);

    case GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK:
	return dummyna_set_accept_callback_enable(acc, val, done, data);

    case GENSIO_ACC_FUNC_FREE:
	dummyna_free(acc);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

int
dummy_gensio_accepter_alloc(const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb, void *user_data,
			    struct gensio_accepter **accepter)
{
    struct dummyna_data *nadata;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock) {
	dummyna_finish_free(nadata);
	return GE_NOMEM;
    }

    nadata->shutdown_runner = o->alloc_runner(o, dummyna_do_shutdown, nadata);
    if (!nadata->shutdown_runner) {
	dummyna_finish_free(nadata);
	return GE_NOMEM;
    }

    nadata->acc = gensio_acc_data_alloc(o, cb, user_data, gensio_acc_dummy_func,
					NULL, "dummy", nadata);
    if (!nadata->acc) {
	dummyna_finish_free(nadata);
	return GE_NOMEM;
    }

    *accepter = nadata->acc;
    return 0;
}

int
str_to_dummy_gensio_accepter(const char *str, const char * const args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb,
			     void *user_data,
			     struct gensio_accepter **acc)
{
    return dummy_gensio_accepter_alloc(args, o, cb, user_data, acc);
}
