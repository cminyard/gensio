/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_os_funcs.h>

#include "gensio_filter_trace.h"

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
trace_data(const char *op, struct gensio_os_funcs *o,
	   FILE *f, bool raw, int err, gensiods written,
	   const struct gensio_sg *sg, gensiods sglen)
{
    struct gensio_fdump h;
    gensio_time time;

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
    if (tfilter->dir == DIR_WRITE || tfilter->dir == DIR_BOTH) {
	trace_lock(tfilter);
	if (tfilter->tr)
	    trace_data("Write", tfilter->o, tfilter->tr, tfilter->raw, err,
		       count, sg, sglen);
	trace_unlock(tfilter);
    }
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

    if (tfilter->block == DIR_READ || tfilter->block == DIR_BOTH) {
	if (rcount)
	    *rcount = buflen;
	return 0;
    }

    err = handler(cb_data, &count, buf, buflen, auxdata);
    if (tfilter->dir == DIR_READ || tfilter->dir == DIR_BOTH) {
	struct gensio_sg sg = {buf, buflen};

	trace_lock(tfilter);
	if (tfilter->tr)
	    trace_data("Read", tfilter->o, tfilter->tr, tfilter->raw, err,
		       count, &sg, 1);
	trace_unlock(tfilter);
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
			      enum trace_dir block,
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

int
gensio_trace_filter_alloc(struct gensio_os_funcs *o,
			  const char * const args[],
			  struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    int dir = DIR_NONE;
    int block = DIR_NONE;
    bool raw = false, tr_stdout = false, tr_stderr = false, tbool;
    const char *filename = NULL;
    unsigned int i;
    const char *modeflag = "a";

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyenum(args[i], "dir", trace_dir_enum, &dir) > 0)
	    continue;
	if (gensio_check_keyenum(args[i], "block", trace_dir_enum, &block) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "raw", &raw) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "file", &filename) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "stdout", &tr_stdout) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "stderr", &tr_stderr) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "delold", &tbool) > 0) {
	    if (tbool)
		modeflag = "w";
	    continue;
	}
	return GE_INVAL;
    }

    filter = gensio_trace_filter_raw_alloc(o, dir, block, raw, filename,
					   tr_stdout, tr_stderr, modeflag);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}
