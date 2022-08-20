/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>

#include "gensio_filter_ratelimit.h"

struct ratelimit_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    gensiods xmit_buf_len;
    unsigned char *xmit_buf;
    gensio_time delay;

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
		       GENSIO_FILTER_CB_START_TIMER, &rfilter->delay);
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

static bool
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
    for (i = 0; i < sglen && count < rfilter->xmit_buf_len; i++) {
	gensiods len = sg[i].buflen;

	if (len > rfilter->xmit_buf_len - count)
	    len = rfilter->xmit_buf_len - count;

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
				  gensiods xmit_size,
				  struct gensio_time xmit_delay)
{
    struct ratelimit_filter *rfilter;

    rfilter = o->zalloc(o, sizeof(*rfilter));
    if (!rfilter)
	return NULL;

    rfilter->o = o;
    rfilter->xmit_buf_len = xmit_size;
    rfilter->delay = xmit_delay;

    rfilter->xmit_buf = o->zalloc(o, xmit_size);
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

int
gensio_ratelimit_filter_alloc(struct gensio_os_funcs *o,
			      const char * const args[],
			      struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    unsigned int i;
    gensiods xmit_len = 1;
    struct gensio_time xmit_delay = { 0, 0 };

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "xmit_len", &xmit_len) > 0)
	    continue;
	if (gensio_check_keytime(args[i], "xmit_delay", 0, &xmit_delay) > 0)
	    continue;
	return GE_INVAL;
    }

    if (xmit_delay.secs == 0 && xmit_delay.nsecs == 0)
	return GE_INVAL;

    filter = gensio_ratelimit_filter_raw_alloc(o, xmit_len, xmit_delay);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}
