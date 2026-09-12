/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018-2025  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/argvutils.h>

struct iosplit_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;
};

#define filter_to_iosplit(v) ((struct iosplit_filter *) \
			    gensio_filter_get_user_data(v))

static bool
iosplit_ul_read_pending(struct gensio_filter *filter)
{
    return false;
}

static bool
iosplit_ll_write_pending(struct gensio_filter *filter)
{
    return false;
}

static bool
iosplit_ll_read_needed(struct gensio_filter *filter)
{
    return false;
}

static int
iosplit_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static int
iosplit_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

static int
iosplit_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

static int
iosplit_ul_write(struct gensio_filter *filter,
	       gensio_ul_filter_data_handler handler, void *cb_data,
	       gensiods *rcount,
	       const struct gensio_sg *sg, gensiods sglen,
	       const char *const *auxdata)
{
    return handler(cb_data, rcount, sg, sglen, auxdata);
}

static int
iosplit_ll_write(struct gensio_filter *filter,
	       gensio_ll_filter_data_handler handler, void *cb_data,
	       gensiods *rcount,
	       unsigned char *buf, gensiods buflen,
	       const char *const *auxdata)
{
    return handler(cb_data, rcount, buf, buflen, auxdata);
}

static int
iosplit_setup(struct gensio_filter *filter)
{
    return 0;
}

static void
iosplit_filter_cleanup(struct gensio_filter *filter)
{
}

static void
tfilter_free(struct iosplit_filter *tfilter)
{
    if (tfilter->filter)
	gensio_filter_free_data(tfilter->filter);
    tfilter->o->free(tfilter->o, tfilter);
}

static void
iosplit_free(struct gensio_filter *filter)
{
    struct iosplit_filter *tfilter = filter_to_iosplit(filter);

    tfilter_free(tfilter);
}

static int gensio_iosplit_filter_func(struct gensio_filter *filter, int op,
				      void *func, void *data,
				      gensiods *count,
				      void *buf, const void *cbuf,
				      gensiods buflen,
				      const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return iosplit_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return iosplit_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return iosplit_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return iosplit_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return iosplit_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return iosplit_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return iosplit_ul_write(filter, func, data, count, cbuf, buflen,
				 auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return iosplit_ll_write(filter, func, data, count, buf, buflen,
				 auxdata);

    case GENSIO_FILTER_FUNC_SETUP:
	return iosplit_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	iosplit_filter_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	iosplit_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return GE_NOTSUP;

    default:
	return GE_NOTSUP;
    }
}

static struct gensio_filter *
gensio_iosplit_filter_raw_alloc(struct gensio_os_funcs *o)
{
    struct iosplit_filter *tfilter;

    tfilter = o->zalloc(o, sizeof(*tfilter));
    if (!tfilter)
	return NULL;

    tfilter->o = o;

    tfilter->filter = gensio_filter_alloc_data(o, gensio_iosplit_filter_func,
					       tfilter);
    if (!tfilter->filter)
	goto out_nomem;

    return tfilter->filter;

 out_nomem:
    tfilter_free(tfilter);
    return NULL;
}

static int
gensio_iosplit_filter_alloc(struct gensio_pparm_info *p,
			    struct gensio_os_funcs *o,
			    const char * const args[],
			    struct gensio_filter **rfilter,
			    struct gensio **out_child,
			    bool *discard)
{
    struct gensio_filter *filter;
    const char *outgen = NULL;
    unsigned int i;
    int err;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_value(p, args[i], "outgen", &outgen) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "discard", discard) > 0)
	    continue;
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

    if (!outgen) {
	gensio_pparm_slog(p, "outgen parameter must be provided\n");
	return GE_INVAL;
    }

    err = str_to_gensio(outgen, o, NULL, NULL, out_child);
    if (err) {
	gensio_pparm_log(p, "cannot allocate outgen '%s': %s\n",
			 outgen, gensio_err_to_str(err));
	return err;
    }


    filter = gensio_iosplit_filter_raw_alloc(o);
    if (!filter) {
	gensio_free(*out_child);
	*out_child = NULL;
	return GE_NOMEM;
    }

    *rfilter = filter;
    return 0;
}

static int
iosplit_gensio_alloc(struct gensio *child, const char *const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io, *out_child;
    bool discard = false;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "iosplit", user_data);

    err = gensio_iosplit_filter_alloc(&p, o, args, &filter, &out_child,
				      &discard);
    if (err)
	return err;

    ll = gensio_2gensio_ll_alloc(o, child, out_child, discard);
    if (!ll) {
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    /*
     * So gensio_ll_free doesn't free the child if this fails.  It
     * will free out_child, but that's ok.
     */
    gensio_ref(child);
    io = base_gensio_alloc(o, ll, filter, child, "iosplit", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_set_attr_from_child(io, child);

    gensio_free(child); /* Lose the ref we acquired. */

    *net = io;
    return 0;
}

static int
str_to_iosplit_gensio(const char *str, const char * const args[],
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

    err = iosplit_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

int
gensio_init_iosplit(struct gensio_os_funcs *o)
{
    return register_filter_gensio(o, "iosplit",
				  str_to_iosplit_gensio, iosplit_gensio_alloc);
}
