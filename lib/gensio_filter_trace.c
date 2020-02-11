/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <gensio/gensio_class.h>

#include "gensio_filter_trace.h"

enum trace_dir {
    TRACE_NONE,
    TRACE_READ,
    TRACE_WRITE,
    TRACE_BOTH
};

struct trace_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    enum trace_dir dir;
    bool raw;
    char *filename;
    bool stdout;
    bool stderr;

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
trace_try_connect(struct gensio_filter *filter, struct timeval *timeout)
{
    struct trace_filter *tfilter = filter_to_trace(filter);

    if (tfilter->stdout) {
	tfilter->tr = stdout;
    } else if (tfilter->stderr) {
	tfilter->tr = stderr;
    } else if (tfilter->filename) {
	tfilter->tr = fopen(tfilter->filename, "a+");
	if (!tfilter->tr)
	    return gensio_os_err_to_err(tfilter->o, errno);
    }
    return 0;
}

static int
trace_try_disconnect(struct gensio_filter *filter, struct timeval *timeout)
{
    struct trace_filter *tfilter = filter_to_trace(filter);

    if (!tfilter->stdout && !tfilter->stderr && tfilter->tr)
	fclose(tfilter->tr);
    tfilter->tr = NULL;
    return 0;
}

struct dump_history {
    unsigned int column;
    unsigned int pos;
    unsigned char data[16];
};

static void
dump_buf(FILE *f, const unsigned char *buf, gensiods len,
	 struct dump_history *h)
{
    gensiods i, j;

    for (i = 0; i < len; i++) {
	if (h->column == 0)
	    fprintf(f, " %4.4x:", h->pos);
	fprintf(f, " %2.2x", buf[i]);
	h->data[h->column++] = buf[i];
	h->pos++;
	if (h->column == 16) {
	    fputs("  ", f);
	    for (j = 0; j < 16; j++) {
		if (isprint(h->data[j]))
		    fputc(h->data[j], f);
		else
		    fputc('.', f);
	    }
	    fputc('\n', f);
	    h->column = 0;
	}
    }
}

static void
dump_buf_finish(FILE *f, struct dump_history *h)
{
    gensiods i;

    if (h->column == 0)
	return;
    for (i = h->column; i < 16; i++)
	fputs("   ", f);
    fputs("  ", f);
    for (i = 0; i < h->column; i++) {
	if (isprint(h->data[i]))
	    fputc(h->data[i], f);
	else
	    fputc('.', f);
    }
    fputc('\n', f);
}

static void
trace_data(const char *op, struct gensio_os_funcs *o,
	   FILE *f, bool raw, int err, gensiods written,
	   const struct gensio_sg *sg, gensiods sglen)
{
    struct dump_history h;
    struct timeval time;

    o->get_monotonic_time(o, &time);
    if (err) {
	if (!raw) {
	    fprintf(f, "%ld:%6.6ld %s error: %d %s\n",
		    time.tv_sec, time.tv_usec, op,
		    err, gensio_err_to_str(err));
	    fflush(f);
	}
    } else if (written > 0) {
	gensiods i, len;

	memset(&h, 0, sizeof(h));
	fprintf(f, "%ld:%6.6ld %s (%lu):\n",
		time.tv_sec, time.tv_usec,
		op, (unsigned long) written);
	for (i = 0; i < sglen && written > 0; i++, written -= len) {
	    if (sg[i].buflen > written)
		len = written;
	    else
		len = sg[i].buflen;
	    if (raw)
		fwrite(sg[i].buf, 1, len, f);
	    else
		dump_buf(f, sg[i].buf, len, &h);
	}
	dump_buf_finish(f, &h);
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

    err = handler(cb_data, &count, sg, sglen, auxdata);
    if (tfilter->dir == TRACE_WRITE || tfilter->dir == TRACE_BOTH) {
	trace_lock(tfilter);
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

    err = handler(cb_data, &count, buf, buflen, auxdata);
    if (tfilter->dir == TRACE_READ || tfilter->dir == TRACE_BOTH) {
	struct gensio_sg sg = {buf, buflen};

	trace_lock(tfilter);
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
				    const void *func, void *data,
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
			      bool raw, const char *filename, bool stdout,
			      bool stderr)
{
    struct trace_filter *tfilter;

    if (!filename && !stdout && !stderr)
	dir = TRACE_NONE;

    tfilter = o->zalloc(o, sizeof(*tfilter));
    if (!tfilter)
	return NULL;

    tfilter->o = o;
    tfilter->dir = dir;
    tfilter->raw = raw;
    if (filename) {
	tfilter->filename = gensio_strdup(o, filename);
	if (!tfilter->filename)
	    goto out_nomem;
    }
    tfilter->stdout = stdout;
    tfilter->stderr = stderr;

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
    { "none", TRACE_NONE },
    { "read", TRACE_READ },
    { "write", TRACE_WRITE },
    { "both", TRACE_BOTH },
    {}
};

int
gensio_trace_filter_alloc(struct gensio_os_funcs *o,
			  const char * const args[],
			  struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    int dir = TRACE_NONE;
    bool raw = false, stdout = false, stderr = false;
    const char *filename = NULL;
    unsigned int i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyenum(args[i], "dir", trace_dir_enum, &dir) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "raw", &raw) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "file", &filename) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "stdout", &stdout) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "stderr", &stderr) > 0)
	    continue;
	return GE_INVAL;
    }

    filter = gensio_trace_filter_raw_alloc(o, dir, raw, filename,
					   stdout, stderr);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}
