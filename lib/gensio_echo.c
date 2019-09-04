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

/* This code is for a gensio that echos all writes back to read. */

#include <assert.h>
#include <string.h>
#include "config.h"
#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>

enum echon_state {
    ECHON_CLOSED,
    ECHON_IN_OPEN,
    ECHON_OPEN,
    ECHON_IN_CLOSE,
};

struct echon_data {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    unsigned int refcount;
    enum echon_state state;

    struct gensio *io;

    bool noecho;

    gensiods max_read_size;
    unsigned char *read_data;
    gensiods data_pending_len;

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

static void echon_start_deferred_op(struct echon_data *ndata);

static void
echon_finish_free(struct echon_data *ndata)
{
    struct gensio_os_funcs *o = ndata->o;

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
echon_lock(struct echon_data *ndata)
{
    ndata->o->lock(ndata->lock);
}

static void
echon_unlock(struct echon_data *ndata)
{
    ndata->o->unlock(ndata->lock);
}

static void
echon_ref(struct echon_data *ndata)
{
    assert(ndata->refcount > 0);
    ndata->refcount++;
}

static void
echon_unlock_and_deref(struct echon_data *ndata)
{
    assert(ndata->refcount > 0);
    if (ndata->refcount == 1) {
	echon_unlock(ndata);
	echon_finish_free(ndata);
    } else {
	ndata->refcount--;
	echon_unlock(ndata);
    }
}

static int
echon_write(struct gensio *io, gensiods *count,
	    const struct gensio_sg *sg, gensiods sglen)
{
    struct echon_data *ndata = gensio_get_gensio_data(io);
    gensiods total_write = 0, to_write, i;

    echon_lock(ndata);
    if (ndata->state != ECHON_OPEN) {
	echon_unlock(ndata);
	return GE_NOTREADY;
    }
    if (ndata->noecho) {
	echon_unlock(ndata);
	return 0;
    }
    for (i = 0; i < sglen; i++) {
	to_write = ndata->max_read_size - ndata->data_pending_len;
	if (to_write > sg[i].buflen)
	    to_write = sg[i].buflen;
	memcpy(ndata->read_data + ndata->data_pending_len,
	       sg[i].buf, to_write);
	ndata->data_pending_len += to_write;
	total_write += to_write;
    }
    if (total_write)
	echon_start_deferred_op(ndata);
    echon_unlock(ndata);
    if (count)
	*count = total_write;
    return 0;
}

static int
echon_raddr_to_str(struct gensio *io, gensiods *epos,
		    char *buf, gensiods buflen)
{
    gensiods pos = 0;

    if (epos)
	pos = *epos;

    strncpy(buf + pos, "echo", buflen - pos - 1);

    if (epos)
	*epos = pos;

    return 0;
}

static int
echon_remote_id(struct gensio *io, int *id)
{
    return GE_NOTSUP;
}

static void
echon_deferred_op(struct gensio_runner *runner, void *cb_data)
{
    struct echon_data *ndata = cb_data;

    echon_lock(ndata);
    if (ndata->state == ECHON_IN_OPEN) {
	ndata->state = ECHON_OPEN;
	if (ndata->open_done) {
	    echon_unlock(ndata);
	    ndata->open_done(ndata->io, 0, ndata->open_data);
	    echon_lock(ndata);
	}
    }

 more_read:
    while (ndata->state == ECHON_OPEN &&
	   ndata->data_pending_len && ndata->read_enabled) {
	gensiods count;

	count = ndata->data_pending_len;
	echon_unlock(ndata);
	gensio_cb(ndata->io, GENSIO_EVENT_READ, 0,
		  ndata->read_data, &count, NULL);
	echon_lock(ndata);
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

    while (ndata->state == ECHON_OPEN &&
	   ndata->data_pending_len < ndata->max_read_size &&
	   ndata->xmit_enabled) {
	echon_unlock(ndata);
	gensio_cb(ndata->io, GENSIO_EVENT_WRITE_READY, 0,
		  NULL, NULL, NULL);
	echon_lock(ndata);
    }
    if (ndata->state == ECHON_OPEN &&
		ndata->data_pending_len && ndata->read_enabled)
	goto more_read;

    if (ndata->state == ECHON_IN_CLOSE) {
	ndata->state = ECHON_CLOSED;
	if (ndata->close_done) {
	    echon_unlock(ndata);
	    ndata->close_done(ndata->io, ndata->close_data);
	    echon_lock(ndata);
	}
    }

    ndata->deferred_op_pending = false;

    echon_unlock_and_deref(ndata);
}

static void
echon_start_deferred_op(struct echon_data *ndata)
{
    if (!ndata->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	ndata->deferred_op_pending = true;
	ndata->o->run(ndata->deferred_op_runner);
	echon_ref(ndata);
    }
}

static void
echon_set_read_callback_enable(struct gensio *io, bool enabled)
{
    struct echon_data *ndata = gensio_get_gensio_data(io);

    echon_lock(ndata);
    ndata->read_enabled = enabled;
    if (enabled && ndata->state == ECHON_OPEN && ndata->data_pending_len)
	echon_start_deferred_op(ndata);
    echon_unlock(ndata);
}

static void
echon_set_write_callback_enable(struct gensio *io, bool enabled)
{
    struct echon_data *ndata = gensio_get_gensio_data(io);

    echon_lock(ndata);
    ndata->xmit_enabled = enabled;
    if (enabled && ndata->state == ECHON_OPEN &&
		ndata->data_pending_len < ndata->max_read_size)
	echon_start_deferred_op(ndata);
    echon_unlock(ndata);
}

static int
echon_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    struct echon_data *ndata = gensio_get_gensio_data(io);
    int err = 0;

    echon_lock(ndata);
    if (ndata->state != ECHON_CLOSED) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    ndata->state = ECHON_IN_OPEN;
    ndata->open_done = open_done;
    ndata->open_data = open_data;
    echon_start_deferred_op(ndata);
 out_unlock:
    echon_unlock(ndata);

    return err;
}

static int
echon_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    struct echon_data *ndata = gensio_get_gensio_data(io);
    int err = 0;

    echon_lock(ndata);
    if (ndata->state != ECHON_OPEN) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    ndata->state = ECHON_IN_CLOSE;
    ndata->close_done = close_done;
    ndata->close_data = close_data;
    echon_start_deferred_op(ndata);
 out_unlock:
    echon_unlock(ndata);

    return err;
}

static void
echon_func_ref(struct gensio *io)
{
    struct echon_data *ndata = gensio_get_gensio_data(io);

    echon_lock(ndata);
    echon_ref(ndata);
    echon_unlock(ndata);
}

static void
echon_free(struct gensio *io)
{
    struct echon_data *ndata = gensio_get_gensio_data(io);

    echon_lock(ndata);
    assert(ndata->refcount > 0);
    if (ndata->refcount == 1)
	ndata->state = ECHON_CLOSED;
    echon_unlock_and_deref(ndata);
}

static int
echon_disable(struct gensio *io)
{
    struct echon_data *ndata = gensio_get_gensio_data(io);

    echon_lock(ndata);
    ndata->state = ECHON_CLOSED;
    echon_unlock(ndata);

    return 0;
}

static int
gensio_echo_func(struct gensio *io, int func, gensiods *count,
		  const void *cbuf, gensiods buflen, void *buf,
		  const char *const *auxdata)
{
    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	return echon_write(io, count, cbuf, buflen);

    case GENSIO_FUNC_RADDR_TO_STR:
	return echon_raddr_to_str(io, count, buf, buflen);

    case GENSIO_FUNC_OPEN:
	return echon_open(io, cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return echon_close(io, cbuf, buf);

    case GENSIO_FUNC_FREE:
	echon_free(io);
	return 0;

    case GENSIO_FUNC_REF:
	echon_func_ref(io);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	echon_set_read_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	echon_set_write_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_REMOTE_ID:
	return echon_remote_id(io, buf);

    case GENSIO_FUNC_DISABLE:
	return echon_disable(io);

    default:
	return GE_NOTSUP;
    }
}

static int
echo_ndata_setup(struct gensio_os_funcs *o, gensiods max_read_size,
		   struct echon_data **new_ndata)
{
    struct echon_data *ndata;

    ndata = o->zalloc(o, sizeof(*ndata));
    if (!ndata)
	return GE_NOMEM;
    ndata->o = o;
    ndata->refcount = 1;

    ndata->max_read_size = max_read_size;
    ndata->read_data = o->zalloc(o, max_read_size);
    if (!ndata->read_data)
	goto out_nomem;

    ndata->deferred_op_runner = o->alloc_runner(o, echon_deferred_op, ndata);
    if (!ndata->deferred_op_runner)
	goto out_nomem;

    ndata->lock = o->alloc_lock(o);
    if (!ndata->lock)
	goto out_nomem;

    *new_ndata = ndata;

    return 0;

 out_nomem:
    echon_finish_free(ndata);

    return GE_NOMEM;
}

int
echo_gensio_alloc(const char * const argv[], const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    int err;
    struct echon_data *ndata = NULL;
    int i;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    bool noecho = false;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "noecho", &noecho) > 0)
	    continue;
	return GE_INVAL;
    }

    err = echo_ndata_setup(o, max_read_size, &ndata);
    if (err)
	return err;

    ndata->noecho = noecho;

    ndata->io = gensio_data_alloc(ndata->o, cb, user_data,
				  gensio_echo_func, NULL, "echo", ndata);
    if (!ndata->io)
	goto out_nomem;
    gensio_set_is_client(ndata->io, true);
    gensio_set_is_reliable(ndata->io, true);

    *new_gensio = ndata->io;

    return 0;

 out_nomem:
    echon_finish_free(ndata);
    return GE_NOMEM;
}

int
str_to_echo_gensio(const char *str, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    int err;
    const char **argv;

    err = gensio_str_to_argv(o, str, NULL, &argv, NULL);
    if (!err) {
	err = echo_gensio_alloc(argv, args, o, cb, user_data, new_gensio);
	gensio_argv_free(o, argv);
    }
    return err;
}
