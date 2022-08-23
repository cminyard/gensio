/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code is for a gensio that reads/writes files. */

#include "config.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>

#if !USE_FILE_STDIO
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

enum filen_state {
    FILEN_CLOSED,
    FILEN_IN_OPEN,
    FILEN_OPEN,
    FILEN_IN_OPEN_CLOSE,
    FILEN_IN_CLOSE,
};

struct filen_data {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    unsigned int refcount;
    enum filen_state state;

    struct gensio *io;

    gensiods max_read_size;
    unsigned char *read_data;
    gensiods data_pending_len;
    int read_err;

    char *infile;
    char *outfile;
    bool create;
#if USE_FILE_STDIO
    int mode;
    FILE *inf;
    FILE *outf;
#else
    mode_t mode;
    int inf;
    int outf;
#endif

    bool read_enabled;
    bool xmit_enabled;

    bool read_close;

    gensio_done_err open_done;
    void *open_data;

    gensio_done close_done;
    void *close_data;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;
};

static void filen_start_deferred_op(struct filen_data *ndata);

#if USE_FILE_STDIO
#define f_ready(f) ((f) != NULL)
#define f_set_not_ready(f) f = NULL
typedef int mode_type;
static int
f_writev(struct gensio_os_funcs *o,
	 FILE *f, const struct gensio_sg *sg, gensiods sglen,
	 gensiods *written)
{
    gensiods i, total = 0;
    size_t rv;

    for (i = 0; i < sglen; i++) {
	rv = fwrite(sg[i].buf, 1, sg[i].buflen, f);
	if (rv == 0) {
	    if (total == 0)
		return GE_REMCLOSE;
	    break;
	}
	total += rv;
    }

    *written = total;
    return 0;
}

static int
f_read(struct gensio_os_funcs *o,
       FILE *f, void *buf, gensiods len, gensiods *nrread)
{
    size_t rv;

    rv = fread(buf, 1, len, f);
    if (rv == 0) {
	rv = GE_REMCLOSE;
    } else {
	*nrread = rv;
	rv = 0;
    }
    return rv;
}
#define F_O_RDONLY 1
#define F_O_WRONLY 2
#define F_O_CREAT 4
static int
f_open(struct gensio_os_funcs *o,
       const char *fn, int flags, int mode, FILE **rf)
{
    char *fmode;
    FILE *f;

    if (flags & F_O_RDONLY) {
	fmode = "r";
    } else if (flags & F_O_WRONLY) {
	if (F_O_CREAT)
	    fmode = "w";
	else
	    fmode = "r+";
    } else {
	return GE_INVAL;
    }
    f = fopen(fn, fmode);
    if (!f)
	return GE_NOTFOUND;
    *rf = f;
    return 0;
}
#define f_close(f) fclose(f)
#else
#define F_O_RDONLY O_RDONLY
#define F_O_WRONLY O_WRONLY
#define F_O_CREAT O_CREAT
typedef mode_t mode_type;
#define f_ready(f) ((f) != -1)
#define f_set_not_ready(f) f = -1
static int
f_writev(struct gensio_os_funcs *o,
	 int fd, const struct gensio_sg *sg, gensiods sglen,
	 gensiods *written)
{
    int rv;

    rv = writev(fd, (const struct iovec *) sg, sglen);
    if (rv < 0) {
	rv = gensio_os_err_to_err(o, errno);
    } else if (rv == 0) {
	rv = GE_REMCLOSE;
    } else {
	*written = rv;
	rv = 0;
    }
    return rv;
}
static int
f_read(struct gensio_os_funcs *o,
       int fd, void *buf, gensiods len, gensiods *nrread)
{
    int rv;

    rv = read(fd, buf, len);
    if (rv < 0) {
	rv = gensio_os_err_to_err(o, errno);
    } else if (rv == 0) {
	rv = GE_REMCLOSE;
    } else {
	*nrread = rv;
	rv = 0;
    }
    return rv;
}
static int
f_open(struct gensio_os_funcs *o,
       const char *fn, int flags, int mode, int *rfd)
{
    int fd;
    int err = 0;

    fd = open(fn, flags, mode);
    if (fd == -1)
	err = gensio_os_err_to_err(o, errno);
    else
	*rfd = fd;
    return err;
}

#define f_close(f) close(f)
#endif

static void
filen_finish_free(struct filen_data *ndata)
{
    struct gensio_os_funcs *o = ndata->o;

    if (ndata->io)
	gensio_data_free(ndata->io);
    if (ndata->infile)
	o->free(ndata->o, ndata->infile);
    if (ndata->outfile)
	o->free(ndata->o, ndata->outfile);
    if (ndata->read_data)
	o->free(o, ndata->read_data);
    if (ndata->deferred_op_runner)
	o->free_runner(ndata->deferred_op_runner);
    if (ndata->lock)
	o->free_lock(ndata->lock);
    o->free(o, ndata);
}

static void
filen_lock(struct filen_data *ndata)
{
    ndata->o->lock(ndata->lock);
}

static void
filen_unlock(struct filen_data *ndata)
{
    ndata->o->unlock(ndata->lock);
}

static void
filen_ref(struct filen_data *ndata)
{
    assert(ndata->refcount > 0);
    ndata->refcount++;
}

static void
filen_unlock_and_deref(struct filen_data *ndata)
{
    assert(ndata->refcount > 0);
    if (ndata->refcount == 1) {
	filen_unlock(ndata);
	filen_finish_free(ndata);
    } else {
	ndata->refcount--;
	filen_unlock(ndata);
    }
}

static int
filen_write(struct gensio *io, gensiods *count,
	    const struct gensio_sg *sg, gensiods sglen)
{
    struct filen_data *ndata = gensio_get_gensio_data(io);
    gensiods total_write = 0, i;
    gensiods wcount = 0;
    int err = 0;

    filen_lock(ndata);
    if (ndata->state != FILEN_OPEN) {
	err = GE_NOTREADY;
    } else if (!f_ready(ndata->outf)) {
	/* Just drop the data. */
	for (total_write = 0, i = 0; i < sglen; i++)
	    total_write += sg->buflen;
    } else {
	err = f_writev(ndata->o, ndata->outf, sg, sglen, &wcount);
	if (!err)
	    total_write = wcount;
    }
    filen_unlock(ndata);
    if (count)
	*count = total_write;
    return err;
}

static void
filen_deferred_op(struct gensio_runner *runner, void *cb_data)
{
    struct filen_data *ndata = cb_data;
    int err = 0;

    filen_lock(ndata);
    ndata->deferred_op_pending = false;

    if (ndata->state == FILEN_IN_OPEN || ndata->state == FILEN_IN_OPEN_CLOSE) {
	if (ndata->state == FILEN_IN_OPEN_CLOSE) {
	    ndata->state = FILEN_IN_CLOSE;
	    err = GE_LOCALCLOSED;
	} else {
	    ndata->state = FILEN_OPEN;
	}
	if (ndata->open_done) {
	    filen_unlock(ndata);
	    ndata->open_done(ndata->io, err, ndata->open_data);
	    filen_lock(ndata);
	}
    }

    while (ndata->state == FILEN_OPEN &&
	   (f_ready(ndata->inf) || ndata->read_err) && ndata->read_enabled) {
	gensiods count = 0;

	if (ndata->data_pending_len == 0 && !ndata->read_err) {
	    err = f_read(ndata->o, ndata->inf, ndata->read_data,
			 ndata->max_read_size, &count);

	    if (err) {
		ndata->read_enabled = false;
		ndata->read_err = err;
	    } else {
		ndata->data_pending_len = count;
	    }
	}
	count = ndata->data_pending_len;
	if (!ndata->read_close && ndata->read_err == GE_REMCLOSE) {
	    /* Just don't report anything at the end of data. */
	    ndata->read_enabled = false;
	} else {
	    filen_unlock(ndata);
	    err = gensio_cb(ndata->io, GENSIO_EVENT_READ, ndata->read_err,
			    ndata->read_data, &count, NULL);
	    filen_lock(ndata);
	    if (err) {
		ndata->read_enabled = false;
		ndata->read_err = err;
		break;
	    }
	}
	if (count > 0) {
	    if (count >= ndata->data_pending_len) {
		ndata->data_pending_len = 0;
	    } else {
		memcpy(ndata->read_data, ndata->read_data + count,
		       ndata->data_pending_len - count);
		ndata->data_pending_len -= count;
	    }
	}
    }

    while (ndata->state == FILEN_OPEN && ndata->xmit_enabled) {
	filen_unlock(ndata);
	err = gensio_cb(ndata->io, GENSIO_EVENT_WRITE_READY, 0,
			NULL, NULL, NULL);
	filen_lock(ndata);
	if (err) {
	    ndata->read_enabled = false;
	    ndata->read_err = err;
	    break;
	}
    }

    if (ndata->state == FILEN_IN_CLOSE) {
	ndata->state = FILEN_CLOSED;
	if (ndata->close_done) {
	    filen_unlock(ndata);
	    ndata->close_done(ndata->io, ndata->close_data);
	    filen_lock(ndata);
	}
    }

    filen_unlock_and_deref(ndata);
}

static void
filen_start_deferred_op(struct filen_data *ndata)
{
    if (!ndata->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	ndata->deferred_op_pending = true;
	ndata->o->run(ndata->deferred_op_runner);
	filen_ref(ndata);
    }
}

static void
filen_set_read_callback_enable(struct gensio *io, bool enabled)
{
    struct filen_data *ndata = gensio_get_gensio_data(io);

    filen_lock(ndata);
    if (ndata->read_enabled != enabled) {
	ndata->read_enabled = enabled;
	if (enabled && ndata->state == FILEN_OPEN && f_ready(ndata->inf))
	    filen_start_deferred_op(ndata);
    }
    filen_unlock(ndata);
}

static void
filen_set_write_callback_enable(struct gensio *io, bool enabled)
{
    struct filen_data *ndata = gensio_get_gensio_data(io);

    filen_lock(ndata);
    if (ndata->xmit_enabled != enabled) {
	ndata->xmit_enabled = enabled;
	if (enabled && ndata->state == FILEN_OPEN)
	    filen_start_deferred_op(ndata);
    }
    filen_unlock(ndata);
}

static int
filen_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    struct filen_data *ndata = gensio_get_gensio_data(io);
    int err = 0;

    filen_lock(ndata);
    if (ndata->state != FILEN_CLOSED) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    if (ndata->infile) {
	err = f_open(ndata->o, ndata->infile, F_O_RDONLY, 0, &ndata->inf);
	if (err)
	    goto out_unlock;
    }
    if (ndata->outfile) {
	int flags = F_O_WRONLY;

	if (ndata->create)
	    flags |= F_O_CREAT;
	err = f_open(ndata->o, ndata->outfile, flags, ndata->mode,
		     &ndata->outf);
	if (err)
	    goto out_unlock;
    }
    ndata->state = FILEN_IN_OPEN;
    ndata->open_done = open_done;
    ndata->open_data = open_data;
    filen_start_deferred_op(ndata);
 out_unlock:
    filen_unlock(ndata);

    return err;
}

static int
filen_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    struct filen_data *ndata = gensio_get_gensio_data(io);
    int err = 0;

    filen_lock(ndata);
    if (ndata->state != FILEN_OPEN && ndata->state != FILEN_IN_OPEN) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    if (f_ready(ndata->inf)) {
	f_close(ndata->inf);
	f_set_not_ready(ndata->inf);
    }
    if (f_ready(ndata->outf)) {
	f_close(ndata->outf);
	f_set_not_ready(ndata->outf);
    }
    if (ndata->state == FILEN_IN_OPEN)
	ndata->state = FILEN_IN_OPEN_CLOSE;
    else
	ndata->state = FILEN_IN_CLOSE;
    ndata->close_done = close_done;
    ndata->close_data = close_data;
    filen_start_deferred_op(ndata);
 out_unlock:
    filen_unlock(ndata);

    return err;
}

static void
filen_free(struct gensio *io)
{
    struct filen_data *ndata = gensio_get_gensio_data(io);

    filen_lock(ndata);
    assert(ndata->refcount > 0);
    if (ndata->refcount == 1)
	ndata->state = FILEN_CLOSED;
    filen_unlock_and_deref(ndata);
}

static int
filen_disable(struct gensio *io)
{
    struct filen_data *ndata = gensio_get_gensio_data(io);

    filen_lock(ndata);
    ndata->state = FILEN_CLOSED;
    filen_unlock(ndata);

    return 0;
}

static int
filen_control(struct gensio *io, bool get, int op,
	      char *data, gensiods *datalen)
{
    struct filen_data *ndata = gensio_get_gensio_data(io);

    if (op != GENSIO_CONTROL_RADDR)
	return GE_NOTSUP;
    if (!get)
	return GE_NOTSUP;
    if (strtoul(data, NULL, 0) > 0)
	return GE_NOTFOUND;

    *datalen = snprintf(data, *datalen,
			"file(%s%s%s%s%s)",
			ndata->infile ? "infile=" : "",
			ndata->infile ? ndata->infile : "",
			(ndata->infile && ndata->outfile) ? "," : "",
			ndata->outfile ? "outfile=" : "",
			ndata->outfile ? ndata->outfile : "");

    return 0;
}

static int
gensio_file_func(struct gensio *io, int func, gensiods *count,
		  const void *cbuf, gensiods buflen, void *buf,
		  const char *const *auxdata)
{
    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	return filen_write(io, count, cbuf, buflen);

    case GENSIO_FUNC_OPEN:
	return filen_open(io, (void *) cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return filen_close(io, (void *) cbuf, buf);

    case GENSIO_FUNC_FREE:
	filen_free(io);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	filen_set_read_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	filen_set_write_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_DISABLE:
	return filen_disable(io);

    case GENSIO_FUNC_CONTROL:
	return filen_control(io, *((bool *) cbuf), buflen, buf, count);

    default:
	return GE_NOTSUP;
    }
}

struct file_ndata_data {
    gensiods max_read_size;
    const char *infile;
    const char *outfile;
    bool create;
    bool read_close;
    mode_type mode;
};

static int
file_ndata_setup(struct gensio_os_funcs *o, struct file_ndata_data *data,
		 struct filen_data **new_ndata)
{
    struct filen_data *ndata;

    ndata = o->zalloc(o, sizeof(*ndata));
    if (!ndata)
	return GE_NOMEM;
    ndata->o = o;
    ndata->refcount = 1;
    ndata->create = data->create;
    ndata->mode = data->mode;
    ndata->read_close = data->read_close;

    if (data->infile) {
	ndata->infile = gensio_strdup(o, data->infile);
	if (!ndata->infile)
	    goto out_nomem;
    }

    if (data->outfile) {
	ndata->outfile = gensio_strdup(o, data->outfile);
	if (!ndata->outfile)
	    goto out_nomem;
    }

    f_set_not_ready(ndata->inf);
    f_set_not_ready(ndata->outf);

    ndata->max_read_size = data->max_read_size;
    ndata->read_data = o->zalloc(o, data->max_read_size);
    if (!ndata->read_data)
	goto out_nomem;

    ndata->deferred_op_runner = o->alloc_runner(o, filen_deferred_op, ndata);
    if (!ndata->deferred_op_runner)
	goto out_nomem;

    ndata->lock = o->alloc_lock(o);
    if (!ndata->lock)
	goto out_nomem;

    *new_ndata = ndata;

    return 0;

 out_nomem:
    filen_finish_free(ndata);

    return GE_NOMEM;
}

static int
process_file_args(const char * const args[], struct file_ndata_data *data)
{
#if !USE_FILE_STDIO
    unsigned int mode;
#endif
    unsigned int umode = 6, gmode = 6, omode = 6, i;

    memset(data, 0, sizeof(*data));
    data->read_close = true;
    data->max_read_size = GENSIO_DEFAULT_BUF_SIZE;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &data->max_read_size) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "infile", &data->infile) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "outfile", &data->outfile) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "create", &data->create) > 0)
	    continue;
#if !USE_FILE_STDIO
	if (gensio_check_keymode(args[i], "umode", &umode) > 0)
	    continue;
	if (gensio_check_keymode(args[i], "gmode", &gmode) > 0)
	    continue;
	if (gensio_check_keymode(args[i], "omode", &omode) > 0)
	    continue;
	if (gensio_check_keyperm(args[i], "perm", &mode) > 0) {
	    umode = mode >> 6 & 7;
	    gmode = mode >> 3 & 7;
	    omode = mode & 7;
	    continue;
	}
#endif
	if (gensio_check_keybool(args[i], "read_close", &data->read_close) > 0)
	    continue;
	return GE_INVAL;
    }
    data->mode = umode << 6 | gmode << 3 | omode;
    return 0;
}

static int
file_gensio_alloc(const void *gdata,
		  const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    int err;
    struct filen_data *ndata = NULL;
    struct file_ndata_data data;

    err = process_file_args(args, &data);
    if (err)
	return err;

    err = file_ndata_setup(o, &data, &ndata);
    if (err)
	return err;

    ndata->io = gensio_data_alloc(ndata->o, cb, user_data,
				  gensio_file_func, NULL, "file", ndata);
    if (!ndata->io)
	goto out_nomem;
    gensio_set_is_client(ndata->io, true);
    gensio_set_is_reliable(ndata->io, true);

    *new_gensio = ndata->io;

    return 0;

 out_nomem:
    filen_finish_free(ndata);
    return GE_NOMEM;
}

static int
str_to_file_gensio(const char *str, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    return file_gensio_alloc(NULL, args, o, cb, user_data, new_gensio);
}

int
gensio_init_file(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "file", str_to_file_gensio, file_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
