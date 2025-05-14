/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020-2025  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/argvutils.h>

struct ratelimit_config {
    gensiods xmit_buf_len;
    gensio_time delay;
};

struct ratelimit_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct ratelimit_config config;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    unsigned char *xmit_buf;

    bool xmit_ready;
};

#define filter_to_ratelimit(v) ((struct ratelimit_filter *) \
				gensio_filter_get_user_data(v))

static void
ratelimit_lock(struct ratelimit_filter *rfilter)
{
    rfilter->o->lock(rfilter->lock);
}

static void
ratelimit_unlock(struct ratelimit_filter *rfilter)
{
    rfilter->o->unlock(rfilter->lock);
}

static void
ratelimit_filter_start_timer(struct ratelimit_filter *rfilter)
{
    rfilter->filter_cb(rfilter->filter_cb_data,
		       GENSIO_FILTER_CB_START_TIMER, &rfilter->config.delay);
}

static void
ratelimit_set_callbacks(struct ratelimit_filter *rfilter,
			gensio_filter_cb cb, void *cb_data)
{
    rfilter->filter_cb = cb;
    rfilter->filter_cb_data = cb_data;
}

static bool
ratelimit_ul_read_pending(struct ratelimit_filter *rfilter)
{
    return false; /* We don't hold any read data. */
}

static bool
ratelimit_ll_write_pending(struct ratelimit_filter *rfilter)
{
    return false; /* We don't hold any write data. */
}

static int
ratelimit_ul_can_write(struct ratelimit_filter *rfilter, bool *rv)
{
    *rv = rfilter->xmit_ready;
    return 0;
}

static bool
ratelimit_ll_read_needed(struct ratelimit_filter *rfilter)
{
    return false;
}

static int
ratelimit_check_open_done(struct ratelimit_filter *rfilter, struct gensio *io)
{
    return 0;
}

static int
ratelimit_try_connect(struct ratelimit_filter *rfilter, gensio_time *timeout,
		      bool was_timeout)
{
    rfilter->xmit_ready = true;
    return 0;
}

static int
ratelimit_try_disconnect(struct ratelimit_filter *rfilter, gensio_time *timeout,
			 bool was_timeout)
{
    return 0;
}

static int
ratelimit_ul_write(struct ratelimit_filter *rfilter,
		   gensio_ul_filter_data_handler handler, void *cb_data,
		   gensiods *rcount,
		   const struct gensio_sg *sg, gensiods sglen,
		   const char *const *auxdata)
{
    gensiods i, count = 0;
    struct gensio_sg xsg;
    int err = 0;

    ratelimit_lock(rfilter);
    if (!rfilter->xmit_ready)
	goto out;
    for (i = 0; i < sglen && count < rfilter->config.xmit_buf_len; i++) {
	gensiods len = sg[i].buflen;

	if (len > rfilter->config.xmit_buf_len - count)
	    len = rfilter->config.xmit_buf_len - count;

	memcpy(rfilter->xmit_buf + count, sg[i].buf, len);
	count += len;
    }
    xsg.buf = rfilter->xmit_buf;
    xsg.buflen = count;
    ratelimit_unlock(rfilter);
    err = handler(cb_data, &count, &xsg, 1, auxdata);
    ratelimit_lock(rfilter);
    if (!err && count > 0) {
	rfilter->xmit_ready = false;
	ratelimit_filter_start_timer(rfilter);
    }
 out:
    ratelimit_unlock(rfilter);
    if (!err && rcount)
	*rcount = count;
    return err;
}

static int
ratelimit_ll_write(struct ratelimit_filter *rfilter,
		gensio_ll_filter_data_handler handler, void *cb_data,
		gensiods *rcount,
		unsigned char *buf, gensiods buflen,
		const char *const *auxdata)
{
    return handler(cb_data, rcount, buf, buflen, auxdata);
}

static int
ratelimit_setup(struct ratelimit_filter *rfilter)
{
    return 0;
}

static void
ratelimit_filter_cleanup(struct ratelimit_filter *rfilter)
{
}

static void
ratelimit_free(struct ratelimit_filter *rfilter)
{
    struct gensio_os_funcs *o = rfilter->o;

    if (rfilter->lock)
	o->free_lock(rfilter->lock);
    if (rfilter->xmit_buf)
	o->free(o, rfilter->xmit_buf);
    if (rfilter->filter)
	gensio_filter_free_data(rfilter->filter);
    o->free(o, rfilter);
}

static int
ratelimit_filter_timeout(struct ratelimit_filter *rfilter)
{
    ratelimit_lock(rfilter);
    rfilter->xmit_ready = true;
    rfilter->filter_cb(rfilter->filter_cb_data,
		       GENSIO_FILTER_CB_OUTPUT_READY, NULL);
    ratelimit_unlock(rfilter);
    return 0;
}

static int gensio_ratelimit_filter_func(struct gensio_filter *filter, int op,
					void *func, void *data,
					gensiods *count,
					void *buf, const void *cbuf,
					gensiods buflen,
					const char *const *auxdata)
{
    struct ratelimit_filter *rfilter = filter_to_ratelimit(filter);

    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	ratelimit_set_callbacks(rfilter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return ratelimit_ul_read_pending(rfilter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return ratelimit_ll_write_pending(rfilter);

    case GENSIO_FILTER_FUNC_UL_CAN_WRITE:
	return ratelimit_ul_can_write(rfilter, data);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return ratelimit_ll_read_needed(rfilter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return ratelimit_check_open_done(rfilter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return ratelimit_try_connect(rfilter, data, buflen);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return ratelimit_try_disconnect(rfilter, data, buflen);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return ratelimit_ul_write(rfilter, func, data, count, cbuf, buflen,
			       auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return ratelimit_ll_write(rfilter, func, data, count, buf, buflen,
			       auxdata);

    case GENSIO_FILTER_FUNC_SETUP:
	return ratelimit_setup(rfilter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	ratelimit_filter_cleanup(rfilter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	ratelimit_free(rfilter);
	return 0;

    case GENSIO_FILTER_FUNC_TIMEOUT:
	return ratelimit_filter_timeout(rfilter);

    default:
	return GE_NOTSUP;
    }
}

static struct gensio_filter *
gensio_ratelimit_filter_raw_alloc(struct gensio_os_funcs *o,
				  struct ratelimit_config *config)
{
    struct ratelimit_filter *rfilter;

    rfilter = o->zalloc(o, sizeof(*rfilter));
    if (!rfilter)
	return NULL;

    rfilter->o = o;
    rfilter->config = *config;

    rfilter->xmit_buf = o->zalloc(o, config->xmit_buf_len);
    if (!rfilter->xmit_buf)
	goto out_nomem;

    rfilter->lock = o->alloc_lock(o);
    if (!rfilter->lock)
	goto out_nomem;

    rfilter->filter = gensio_filter_alloc_data(o, gensio_ratelimit_filter_func,
					       rfilter);
    if (!rfilter->filter)
	goto out_nomem;

    return rfilter->filter;

 out_nomem:
    ratelimit_free(rfilter);
    return NULL;
}

static int
gensio_ratelimit_config(struct gensio_pparm_info *p,
			struct gensio_os_funcs *o,
			const char * const args[],
			struct gensio_base_parms *parms,
			struct ratelimit_config *config)
{
    unsigned int i;

    config->xmit_buf_len = 1;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_ds(p, args[i], "xmit_len", &config->xmit_buf_len) > 0)
	    continue;
	if (gensio_pparm_time(p, args[i], "xmit_delay", 0,
			      &config->delay) > 0)
	    continue;
	if (gensio_base_parm(parms, p, args[i]) > 0)
	    continue;
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

    if (config->delay.secs == 0 && config->delay.nsecs == 0) {
	gensio_pparm_slog(p, "xmit_delay cannot be zero");
	return GE_INVAL;
    }

    return 0;
}

static int
gensio_ratelimit_filter_alloc(struct gensio_os_funcs *o,
			      struct ratelimit_config *config,
			      struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;

    filter = gensio_ratelimit_filter_raw_alloc(o, config);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}

static int
ratelimit_gensio_alloc2(struct gensio *child, const char *const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio_base_parms **parms,
			struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    struct ratelimit_config config;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "ratelimit", user_data);

    memset(&config, 0, sizeof(config));

    err = gensio_ratelimit_config(&p, 0, args, *parms, &config);
    if (err)
	return err;

    err = gensio_ratelimit_filter_alloc(o, &config, &filter);
    if (err)
	return err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "ratelimit", cb, user_data);
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

    *net = io;
    return 0;
}

static int
ratelimit_gensio_alloc(struct gensio *child, const char *const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **net)
{
    return ratelimit_gensio_alloc2(child, args, o, cb, user_data, NULL, net);
}

static int
str_to_ratelimit_gensio(const char *str, const char * const args[],
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

    err = ratelimit_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct ratelimitna_data {
    struct gensio_accepter *acc;
    struct ratelimit_config config;
    struct gensio_os_funcs *o;
    gensio_accepter_event cb;
    void *user_data;
};

static void
ratelimitna_free(void *acc_data)
{
    struct ratelimitna_data *nadata = acc_data;

    nadata->o->free(nadata->o, nadata);
}

static int
ratelimitna_alloc_gensio(void *acc_data, const char * const *iargs,
			 struct gensio *child, struct gensio **rio)
{
    struct ratelimitna_data *nadata = acc_data;
    struct gensio_base_parms *parms = NULL;
    int err;

    parms = gensio_acc_base_parms_dup(nadata->acc);
    if (!parms)
	return GE_NOMEM;

    err = ratelimit_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);

    if (parms)
	gensio_base_parms_free(&parms);

    return err;
}

static int
ratelimitna_new_child(void *acc_data, void **finish_data,
		      struct gensio_filter **filter)
{
    struct ratelimitna_data *nadata = acc_data;

    return gensio_ratelimit_filter_alloc(nadata->o, &nadata->config, filter);
}

static int
ratelimitna_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    return 0;
}

static int
gensio_gensio_acc_ratelimit_cb(void *acc_data, int op, void *data1, void *data2,
			       void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return ratelimitna_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return ratelimitna_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return ratelimitna_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	ratelimitna_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
ratelimit_gensio_accepter_alloc(struct gensio_accepter *child,
				const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb, void *user_data,
				struct gensio_accepter **accepter)
{
    struct ratelimitna_data *nadata;
    int err;
    struct gensio_base_parms *parms = NULL;
    GENSIO_DECLARE_PPACCEPTER(p, o, cb, "msgdelim", user_data);

    err = gensio_base_parms_alloc(o, true, "msgdelim", &parms);
    if (err)
	goto out_err;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	goto out_nomem;

    err = gensio_ratelimit_config(&p, o, args, parms, &nadata->config);
    if (err)
	goto out_err;

    nadata->o = o;
    nadata->cb = cb;
    nadata->user_data = user_data;

    err = gensio_gensio_accepter_alloc(child, o, "ratelimit", cb, user_data,
				       gensio_gensio_acc_ratelimit_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;
    *accepter = nadata->acc;

    err = gensio_acc_base_parms_set(nadata->acc, &parms);
    if (err)
	goto out_err;

    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (nadata) {
	if (nadata->acc)
	    gensio_acc_free(nadata->acc);
	else
	    ratelimitna_free(nadata);
    }
    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
str_to_ratelimit_gensio_accepter(const char *str, const char * const args[],
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
	err = ratelimit_gensio_accepter_alloc(acc2, args, o, cb, user_data,
					      acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_ratelimit(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "ratelimit",
				str_to_ratelimit_gensio,
				ratelimit_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "ratelimit",
					 str_to_ratelimit_gensio_accepter,
					 ratelimit_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
