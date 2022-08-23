/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code creates a dummy gensio accepter that doesn't do anything. */

#include "config.h"
#include <assert.h>
#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
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
    struct gensio_accepter *acc;
    enum dummyna_state state;

    bool deferred_pending;
    struct gensio_runner *deferred_runner;

    gensio_acc_done shutdown_done;
    void *shutdown_data;

    gensio_acc_done enabled_done;
    void *enabled_data;

    unsigned int refcount;
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

static void
dummyna_finish_free(struct dummyna_data *nadata)
{
    struct gensio_os_funcs *o = nadata->o;

    gensio_acc_data_free(nadata->acc);
    if (nadata->deferred_runner)
	o->free_runner(nadata->deferred_runner);
    if (nadata->lock)
	o->free_lock(nadata->lock);
    o->free(o, nadata);
}

void
dummyna_ref(struct dummyna_data *nadata)
{
    assert(nadata->refcount > 0);
    nadata->refcount++;
}

void
dummyna_deref_and_unlock(struct dummyna_data *nadata)
{
    assert(nadata->refcount > 0);
    nadata->refcount--;
    if (nadata->refcount == 0) {
	dummyna_unlock(nadata);
	dummyna_finish_free(nadata);
    } else {
	dummyna_unlock(nadata);
    }
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
dummyna_do_deferred(struct gensio_runner *runner, void *cb_data)
{
    struct dummyna_data *nadata = cb_data;

    dummyna_lock(nadata);
    nadata->deferred_pending = false;

    if (nadata->enabled_done) {
	gensio_acc_done enabled_done = nadata->enabled_done;;
	void *enabled_data = nadata->enabled_data;;

	nadata->enabled_done = NULL;
	dummyna_unlock(nadata);
	enabled_done(nadata->acc, enabled_data);
	dummyna_lock(nadata);
    }

    if (nadata->state == DUMMY_IN_SHUTDOWN) {
	gensio_acc_done shutdown_done = nadata->shutdown_done;
	void *shutdown_data = nadata->shutdown_data;

	nadata->state = DUMMY_DISABLED;
	if (shutdown_done) {
	    dummyna_unlock(nadata);
	    shutdown_done(nadata->acc, shutdown_data);
	    dummyna_lock(nadata);
	}
    }
    dummyna_deref_and_unlock(nadata);
}

void
dummyna_deferred_op(struct dummyna_data *nadata)
{
    if (!nadata->deferred_pending) {
	dummyna_ref(nadata);
	nadata->o->run(nadata->deferred_runner);
	nadata->deferred_pending = true;
    }
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
	nadata->shutdown_done = shutdown_done;
	nadata->shutdown_data = shutdown_data;
	dummyna_deferred_op(nadata);
    }
    dummyna_unlock(nadata);

    return rv;
}

static int
dummyna_set_accept_callback_enable(struct gensio_accepter *accepter,
				   bool enabled,
				   gensio_acc_done done, void *done_data)
{
    struct dummyna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    dummyna_lock(nadata);
    if (nadata->enabled_done) {
	rv = GE_INUSE;
    } else if (done) {
	/* Run the response in a runner to avoid deadlocks. */
	nadata->enabled_done = done;
	nadata->enabled_data = done_data;
	dummyna_deferred_op(nadata);
    }
    dummyna_unlock(nadata);

    return rv;
}

static void
dummyna_free(struct gensio_accepter *accepter)
{
    struct dummyna_data *nadata = gensio_acc_get_gensio_data(accepter);

    dummyna_lock(nadata);
    dummyna_deref_and_unlock(nadata);
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

static int
dummy_gensio_accepter_alloc(const void *gdata,
			    const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb, void *user_data,
			    struct gensio_accepter **accepter)
{
    struct dummyna_data *nadata;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;
    nadata->o = o;
    nadata->refcount = 1;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock) {
	dummyna_finish_free(nadata);
	return GE_NOMEM;
    }

    nadata->deferred_runner = o->alloc_runner(o, dummyna_do_deferred, nadata);
    if (!nadata->deferred_runner) {
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

static int
str_to_dummy_gensio_accepter(const char *str, const char * const args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb,
			     void *user_data,
			     struct gensio_accepter **acc)
{
    return dummy_gensio_accepter_alloc(NULL, args, o, cb, user_data, acc);
}

int
gensio_init_dummy(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio_accepter(o, "dummy", str_to_dummy_gensio_accepter,
				  dummy_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
