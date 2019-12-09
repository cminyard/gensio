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

/* This code is for a gensio that reads/writes files. */

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdio.h>
#include "config.h"
#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>

enum filen_state {
    FILEN_CLOSED,
    FILEN_IN_OPEN,
    FILEN_OPEN,
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
    mode_t mode;

    int infd;
    int outfd;

    bool read_enabled;
    bool xmit_enabled;

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

static void
filen_finish_free(struct filen_data *ndata)
{
    struct gensio_os_funcs *o = ndata->o;

    if (ndata->infile)
	o->free(ndata->o, ndata->infile);
    if (ndata->outfile)
	o->free(ndata->o, ndata->outfile);
    if (ndata->io)
	gensio_data_free(ndata->io);
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
    ssize_t rv;
    int err = 0;

    filen_lock(ndata);
    if (ndata->state != FILEN_OPEN) {
	err = GE_NOTREADY;
    } else if (ndata->outfd == -1) {
	for (total_write = 0, i = 0; i < sglen; i++)
	    total_write += sg->buflen;
    } else {
	rv = writev(ndata->outfd, (const struct iovec *) sg, sglen);
	if (rv < 0)
	    err = gensio_os_err_to_err(ndata->o, errno);
	else if (rv == 0)
	    err = GE_REMCLOSE;
	else
	    total_write = rv;
    }
    filen_unlock(ndata);
    if (count)
	*count = total_write;
    return err;
}

static int
filen_raddr_to_str(struct gensio *io, gensiods *epos,
		    char *buf, gensiods buflen)
{
    struct filen_data *ndata = gensio_get_gensio_data(io);
    gensiods pos = 0;

    if (epos)
	pos = *epos;

    pos += snprintf(buf + pos, buflen - pos,
		    "file(%s%s%s%s%s)",
		    ndata->infile ? "infile=" : "",
		    ndata->infile ? ndata->infile : "",
		    (ndata->infile && ndata->outfile) ? "," : "",
		    ndata->outfile ? "outfile=" : "",
		    ndata->outfile ? ndata->outfile : "");

    if (epos)
	*epos = pos;

    return 0;
}

static int
filen_remote_id(struct gensio *io, int *id)
{
    return GE_NOTSUP;
}

static void
filen_deferred_op(struct gensio_runner *runner, void *cb_data)
{
    struct filen_data *ndata = cb_data;

    filen_lock(ndata);
    ndata->deferred_op_pending = false;

    if (ndata->state == FILEN_IN_OPEN) {
	ndata->state = FILEN_OPEN;
	if (ndata->open_done) {
	    filen_unlock(ndata);
	    ndata->open_done(ndata->io, 0, ndata->open_data);
	    filen_lock(ndata);
	}
    }

    while (ndata->state == FILEN_OPEN &&
	   (ndata->infd != -1 || ndata->read_err) && ndata->read_enabled) {
	gensiods count;

	if (ndata->data_pending_len == 0 && !ndata->read_err) {
	    ssize_t rv = read(ndata->infd, ndata->read_data,
			      ndata->max_read_size);

	    if (rv == -1) {
		ndata->read_enabled = false;
		ndata->read_err = gensio_os_err_to_err(ndata->o, errno);
	    } else if (rv == 0) {
		ndata->read_enabled = false;
		ndata->read_err = GE_REMCLOSE;
	    } else {
		ndata->data_pending_len = rv;
	    }
	}
	count = ndata->data_pending_len;
	filen_unlock(ndata);
	gensio_cb(ndata->io, GENSIO_EVENT_READ, ndata->read_err,
		  ndata->read_data, &count, NULL);
	filen_lock(ndata);
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
	gensio_cb(ndata->io, GENSIO_EVENT_WRITE_READY, 0,
		  NULL, NULL, NULL);
	filen_lock(ndata);
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
	if (enabled && ndata->state == FILEN_OPEN && ndata->infd != -1)
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
	ndata->infd = open(ndata->infile, O_RDONLY);
	if (ndata->infd == -1) {
	    err = gensio_os_err_to_err(ndata->o, errno);
	    goto out_unlock;
	}
    }
    if (ndata->outfile) {
	int flags = O_WRONLY;

	if (ndata->create)
	    flags |= O_CREAT;
	ndata->outfd = open(ndata->outfile, flags, ndata->mode);
	if (ndata->outfd == -1) {
	    err = gensio_os_err_to_err(ndata->o, errno);
	    goto out_unlock;
	}
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
    if (ndata->state != FILEN_OPEN) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    if (ndata->infd != -1) {
	close(ndata->infd);
	ndata->infd = -1;
    }
    if (ndata->outfd != -1) {
	close(ndata->outfd);
	ndata->outfd = -1;
    }
    ndata->state = FILEN_IN_CLOSE;
    ndata->close_done = close_done;
    ndata->close_data = close_data;
    filen_start_deferred_op(ndata);
 out_unlock:
    filen_unlock(ndata);

    return err;
}

static void
filen_func_ref(struct gensio *io)
{
    struct filen_data *ndata = gensio_get_gensio_data(io);

    filen_lock(ndata);
    filen_ref(ndata);
    filen_unlock(ndata);
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
gensio_file_func(struct gensio *io, int func, gensiods *count,
		  const void *cbuf, gensiods buflen, void *buf,
		  const char *const *auxdata)
{
    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	return filen_write(io, count, cbuf, buflen);

    case GENSIO_FUNC_RADDR_TO_STR:
	return filen_raddr_to_str(io, count, buf, buflen);

    case GENSIO_FUNC_OPEN:
	return filen_open(io, cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return filen_close(io, cbuf, buf);

    case GENSIO_FUNC_FREE:
	filen_free(io);
	return 0;

    case GENSIO_FUNC_REF:
	filen_func_ref(io);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	filen_set_read_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	filen_set_write_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_REMOTE_ID:
	return filen_remote_id(io, buf);

    case GENSIO_FUNC_DISABLE:
	return filen_disable(io);

    default:
	return GE_NOTSUP;
    }
}

static int
file_ndata_setup(struct gensio_os_funcs *o, gensiods max_read_size,
		 const char *infile, const char *outfile, bool create,
		 mode_t mode, struct filen_data **new_ndata)
{
    struct filen_data *ndata;

    ndata = o->zalloc(o, sizeof(*ndata));
    if (!ndata)
	return GE_NOMEM;
    ndata->o = o;
    ndata->refcount = 1;
    ndata->create = create;
    ndata->mode = mode;

    if (infile) {
	ndata->infile = gensio_strdup(o, infile);
	if (!ndata->infile)
	    goto out_nomem;
    }

    if (outfile) {
	ndata->outfile = gensio_strdup(o, outfile);
	if (!ndata->outfile)
	    goto out_nomem;
    }

    ndata->infd = -1;
    ndata->outfd = -1;

    ndata->max_read_size = max_read_size;
    ndata->read_data = o->zalloc(o, max_read_size);
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

int
gensio_check_keymode(const char *str, const char *key, unsigned int *rmode)
{
    const char *sval;
    int rv = gensio_check_keyvalue(str, key, &sval);
    unsigned int mode;

    if (!rv)
	return 0;

    if (*sval >= '0' && *sval <= '7') {
	if (sval[1])
	    return -1;
	*rmode = *sval - '0';
	return 1;
    }

    mode = 0;
    while (*sval) {
	if (*sval == 'r')
	    mode |= 4;
	else if (*sval == 'w')
	    mode |= 2;
	else if (*sval == 'x')
	    mode |= 1;
	else
	    return -1;
	sval++;
    }
    *rmode = mode;
    return 1;
}

int
file_gensio_alloc(const char * const argv[], const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    int err;
    struct filen_data *ndata = NULL;
    int i;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    const char *infile = NULL, *outfile = NULL;
    unsigned int umode = 6, gmode = 6, omode = 6;
    bool create = false;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "infile", &infile) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "outfile", &outfile) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "create", &create) > 0)
	    continue;
	if (gensio_check_keymode(args[i], "umode", &umode) > 0)
	    continue;
	if (gensio_check_keymode(args[i], "gmode", &gmode) > 0)
	    continue;
	if (gensio_check_keymode(args[i], "omode", &omode) > 0)
	    continue;
	return GE_INVAL;
    }

    err = file_ndata_setup(o, max_read_size, infile, outfile, create,
			   umode << 6 | gmode << 3 | omode, &ndata);
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

int
str_to_file_gensio(const char *str, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    int err;
    const char **argv;

    err = gensio_str_to_argv(o, str, NULL, &argv, NULL);
    if (!err) {
	err = file_gensio_alloc(argv, args, o, cb, user_data, new_gensio);
	gensio_argv_free(o, argv);
    }
    return err;

}
