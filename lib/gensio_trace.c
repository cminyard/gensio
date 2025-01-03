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

enum trace_dir {
    DIR_NONE,
    DIR_READ,
    DIR_WRITE,
    DIR_BOTH
};

struct trace_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    enum trace_dir dir;
    enum trace_dir b4dir;
    enum trace_dir block;
    bool raw;
    char *filename;
    bool tr_stdout;
    bool tr_stderr;
    const char *modeflag;

    FILE *tr;
};

#define filter_to_trace(v) ((struct trace_filter *) \
			    gensio_filter_get_user_data(v))

static void
trace_lock(struct trace_filter *tfilter)
{
    tfilter->o->lock(tfilter->lock);
}

static void
trace_unlock(struct trace_filter *tfilter)
{
    tfilter->o->unlock(tfilter->lock);
}

static bool
trace_ul_read_pending(struct gensio_filter *filter)
{
    return false;
}

static bool
trace_ll_write_pending(struct gensio_filter *filter)
{
    return false;
}

static bool
trace_ll_read_needed(struct gensio_filter *filter)
{
    return false;
}

static int
trace_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static int
trace_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct trace_filter *tfilter = filter_to_trace(filter);

    if (tfilter->tr_stdout) {
	tfilter->tr = stdout;
    } else if (tfilter->tr_stderr) {
	tfilter->tr = stderr;
    } else if (tfilter->filename) {
	tfilter->tr = fopen(tfilter->filename, tfilter->modeflag);
	if (!tfilter->tr)
	    return GE_PERM;
    }
    return 0;
}

static int
trace_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

static void
trace_data(const char *op, struct trace_filter *tfilter,
	   int err, gensiods written,
	   const struct gensio_sg *sg, gensiods sglen)
{
    struct gensio_fdump h;
    gensio_time time;
    struct gensio_os_funcs *o = tfilter->o;
    FILE *f = tfilter->tr;
    bool raw = tfilter->raw;

    if (!f)
	return;

    trace_lock(tfilter);
    o->get_monotonic_time(o, &time);
    if (err) {
	if (!raw) {
	    fprintf(f, "%lld:%6.6d %s error: %d %s\n",
		    (long long) time.secs, (time.nsecs + 500) / 1000, op,
		    err, gensio_err_to_str(err));
	    fflush(f);
	}
    } else if (written > 0) {
	gensiods i, len;

	gensio_fdump_init(&h, 1);
	if (!raw)
	    fprintf(f, "%lld:%6.6d %s (%lu):\n",
		    (long long) time.secs, (time.nsecs + 500) / 1000,
		    op, (unsigned long) written);
	for (i = 0; i < sglen && written > 0; i++, written -= len) {
	    if (sg[i].buflen > written)
		len = written;
	    else
		len = sg[i].buflen;
	    if (raw)
		fwrite(sg[i].buf, 1, len, f);
	    else
		gensio_fdump_buf(f, sg[i].buf, len, &h);
	}
	gensio_fdump_buf_finish(f, &h);
	fflush(f);
    }
    trace_unlock(tfilter);
}

static int
trace_ul_write(struct gensio_filter *filter,
	       gensio_ul_filter_data_handler handler, void *cb_data,
	       gensiods *rcount,
	       const struct gensio_sg *sg, gensiods sglen,
	       const char *const *auxdata)
{
    struct trace_filter *tfilter = filter_to_trace(filter);
    int err = 0;
    gensiods count = 0;

    if (tfilter->b4dir == DIR_WRITE || tfilter->b4dir == DIR_BOTH) {
	unsigned int i;

	for (i = 0; i < sglen; i++)
	    count += sg[i].buflen;
	trace_data("b4Write", tfilter, err, count, sg, sglen);
    }

    if (tfilter->block == DIR_WRITE || tfilter->block == DIR_BOTH) {
	if (rcount) {
	    unsigned int i;

	    for (i = 0; i < sglen; i++)
		count += sg[i].buflen;
	    *rcount = count;
	}
	return 0;
    }

    err = handler(cb_data, &count, sg, sglen, auxdata);
    if (tfilter->dir == DIR_WRITE || tfilter->dir == DIR_BOTH)
	trace_data("Write", tfilter, err, count, sg, sglen);
    if (!err && rcount)
	*rcount = count;

    return err;
}

static int
trace_ll_write(struct gensio_filter *filter,
	       gensio_ll_filter_data_handler handler, void *cb_data,
	       gensiods *rcount,
	       unsigned char *buf, gensiods buflen,
	       const char *const *auxdata)
{
    struct trace_filter *tfilter = filter_to_trace(filter);
    int err = 0;
    gensiods count = 0;

    if (tfilter->b4dir == DIR_READ || tfilter->b4dir == DIR_BOTH) {
	struct gensio_sg sg = {buf, buflen};

	trace_data("b4Read", tfilter, err, buflen, &sg, 1);
    }

    if (tfilter->block == DIR_READ || tfilter->block == DIR_BOTH) {
	if (rcount)
	    *rcount = buflen;
	return 0;
    }

    err = handler(cb_data, &count, buf, buflen, auxdata);
    if (tfilter->dir == DIR_READ || tfilter->dir == DIR_BOTH) {
	struct gensio_sg sg = {buf, buflen};

	trace_data("Read", tfilter, err, count, &sg, 1);
    }
    if (!err && rcount)
	*rcount = count;

    return err;
}

static int
trace_setup(struct gensio_filter *filter)
{
    return 0;
}

static void
trace_filter_cleanup(struct gensio_filter *filter)
{
    struct trace_filter *tfilter = filter_to_trace(filter);

    if (!tfilter->tr_stdout && !tfilter->tr_stderr && tfilter->tr)
	fclose(tfilter->tr);
    tfilter->tr = NULL;
}

static void
tfilter_free(struct trace_filter *tfilter)
{
    if (tfilter->lock)
	tfilter->o->free_lock(tfilter->lock);
    if (tfilter->filter)
	gensio_filter_free_data(tfilter->filter);
    if (tfilter->filename)
	tfilter->o->free(tfilter->o, tfilter->filename);
    tfilter->o->free(tfilter->o, tfilter);
}

static void
trace_free(struct gensio_filter *filter)
{
    struct trace_filter *tfilter = filter_to_trace(filter);

    tfilter_free(tfilter);
}

static int gensio_trace_filter_func(struct gensio_filter *filter, int op,
				    void *func, void *data,
				    gensiods *count,
				    void *buf, const void *cbuf,
				    gensiods buflen,
				    const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return trace_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return trace_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return trace_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return trace_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return trace_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return trace_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return trace_ul_write(filter, func, data, count, cbuf, buflen,
				 auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return trace_ll_write(filter, func, data, count, buf, buflen,
				 auxdata);

    case GENSIO_FILTER_FUNC_SETUP:
	return trace_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	trace_filter_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	trace_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return GE_NOTSUP;

    default:
	return GE_NOTSUP;
    }
}

static struct gensio_filter *
gensio_trace_filter_raw_alloc(struct gensio_os_funcs *o, enum trace_dir dir,
			      enum trace_dir b4dir, enum trace_dir block,
			      bool raw, const char *filename, bool tr_stdout,
			      bool tr_stderr, const char *modeflag)
{
    struct trace_filter *tfilter;

    if (!filename && !tr_stdout && !tr_stderr)
	dir = DIR_NONE;

    tfilter = o->zalloc(o, sizeof(*tfilter));
    if (!tfilter)
	return NULL;

    tfilter->o = o;
    tfilter->dir = dir;
    tfilter->b4dir = b4dir;
    tfilter->block = block;
    tfilter->raw = raw;
    if (filename) {
	tfilter->filename = gensio_strdup(o, filename);
	if (!tfilter->filename)
	    goto out_nomem;
    }
    tfilter->tr_stdout = tr_stdout;
    tfilter->tr_stderr = tr_stderr;
    tfilter->modeflag = modeflag;

    tfilter->lock = o->alloc_lock(o);
    if (!tfilter->lock)
	goto out_nomem;

    tfilter->filter = gensio_filter_alloc_data(o, gensio_trace_filter_func,
					       tfilter);
    if (!tfilter->filter)
	goto out_nomem;

    return tfilter->filter;

 out_nomem:
    tfilter_free(tfilter);
    return NULL;
}

static struct gensio_enum_val trace_dir_enum[] = {
    { "none", DIR_NONE },
    { "read", DIR_READ },
    { "write", DIR_WRITE },
    { "both", DIR_BOTH },
    { NULL }
};

static int
gensio_trace_filter_alloc(struct gensio_pparm_info *p,
			  struct gensio_os_funcs *o,
			  const char * const args[],
			  struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    int dir = DIR_NONE, b4dir = DIR_NONE;
    int block = DIR_NONE;
    bool raw = false, tr_stdout = false, tr_stderr = false, tbool;
    const char *filename = NULL;
    unsigned int i;
    const char *modeflag = "a";

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_enum(p, args[i], "dir", trace_dir_enum, &dir) > 0)
	    continue;
	if (gensio_pparm_enum(p, args[i], "b4dir", trace_dir_enum, &b4dir) > 0)
	    continue;
	if (gensio_pparm_enum(p, args[i], "block", trace_dir_enum, &block) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "raw", &raw) > 0)
	    continue;
	if (gensio_pparm_value(p, args[i], "file", &filename) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "stdout", &tr_stdout) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "stderr", &tr_stderr) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "delold", &tbool) > 0) {
	    if (tbool)
		modeflag = "w";
	    continue;
	}
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

    filter = gensio_trace_filter_raw_alloc(o, dir, b4dir, block, raw, filename,
					   tr_stdout, tr_stderr, modeflag);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}

static int
trace_gensio_alloc(struct gensio *child, const char *const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "trace", user_data);

    err = gensio_trace_filter_alloc(&p, o, args, &filter);
    if (err)
	return err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "trace", cb, user_data);
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
str_to_trace_gensio(const char *str, const char * const args[],
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

    err = trace_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct tracena_data {
    struct gensio_accepter *acc;
    const char **args;
    struct gensio_os_funcs *o;
    gensio_accepter_event cb;
    void *user_data;
};

static void
tracena_free(void *acc_data)
{
    struct tracena_data *nadata = acc_data;

    if (nadata->args)
	gensio_argv_free(nadata->o, nadata->args);
    nadata->o->free(nadata->o, nadata);
}

static int
tracena_alloc_gensio(void *acc_data, const char * const *iargs,
		     struct gensio *child, struct gensio **rio)
{
    struct tracena_data *nadata = acc_data;

    return trace_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);
}

static int
tracena_new_child(void *acc_data, void **finish_data,
		  struct gensio_filter **filter)
{
    struct tracena_data *nadata = acc_data;
    GENSIO_DECLARE_PPACCEPTER(p, nadata->o, nadata->cb, "trace",
			      nadata->user_data);

    return gensio_trace_filter_alloc(&p, nadata->o, nadata->args, filter);
}

static int
tracena_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    gensio_set_attr_from_child(io, gensio_get_child(io, 0));
    return 0;
}

static int
gensio_gensio_acc_trace_cb(void *acc_data, int op, void *data1, void *data2,
			   void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return tracena_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return tracena_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return tracena_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	tracena_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
trace_gensio_accepter_alloc(struct gensio_accepter *child,
			    const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb, void *user_data,
			    struct gensio_accepter **accepter)
{
    struct tracena_data *nadata;
    int err;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    err = gensio_argv_copy(o, args, NULL, &nadata->args);
    if (err) {
	o->free(o, nadata);
	return err;
    }

    nadata->o = o;
    nadata->cb = cb;
    nadata->user_data = user_data;

    err = gensio_gensio_accepter_alloc(child, o, "trace", cb, user_data,
				       gensio_gensio_acc_trace_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;
    gensio_acc_set_is_reliable(nadata->acc, gensio_acc_is_reliable(child));
    gensio_acc_set_is_packet(nadata->acc, gensio_acc_is_packet(child));
    gensio_acc_set_is_message(nadata->acc, gensio_acc_is_message(child));
    *accepter = nadata->acc;

    return 0;

 out_err:
    tracena_free(nadata);
    return err;
}

static int
str_to_trace_gensio_accepter(const char *str, const char * const args[],
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
	err = trace_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_trace(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "trace",
				str_to_trace_gensio, trace_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "trace",
					 str_to_trace_gensio_accepter,
					 trace_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
