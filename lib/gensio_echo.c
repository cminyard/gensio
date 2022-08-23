/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code is for a gensio that echos all writes back to read. */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "config.h"
#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_circbuf.h>

enum echon_state {
    ECHON_CLOSED,
    ECHON_IN_OPEN,
    ECHON_OPEN,
    ECHON_IN_OPEN_CLOSE,
    ECHON_IN_CLOSE,
};

struct echon_data {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    unsigned int refcount;
    enum echon_state state;

    struct gensio *io;

    bool noecho;
    bool justdata;

    struct gensio_circbuf *buf;

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
    if (ndata->buf)
	gensio_circbuf_free(ndata->buf);
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
echon_write(struct gensio *io, gensiods *rcount,
	    const struct gensio_sg *sg, gensiods sglen)
{
    struct echon_data *ndata = gensio_get_gensio_data(io);
    gensiods i, count = 0;

    echon_lock(ndata);
    if (ndata->state != ECHON_OPEN) {
	echon_unlock(ndata);
	return GE_NOTREADY;
    }
    if (ndata->noecho) {
	for (i = 0; i < sglen; i++)
	    count += sg[i].buflen;
	if (rcount)
	    *rcount = count;
	echon_unlock(ndata);
	return 0;
    }
    gensio_circbuf_sg_write(ndata->buf, sg, sglen, &count);
    if (count)
	echon_start_deferred_op(ndata);
    echon_unlock(ndata);
    if (rcount)
	*rcount = count;
    return 0;
}

static void
echon_deferred_op(struct gensio_runner *runner, void *cb_data)
{
    struct echon_data *ndata = cb_data;
    int err = 0;

    echon_lock(ndata);
    if (ndata->state == ECHON_IN_OPEN || ndata->state == ECHON_IN_OPEN_CLOSE) {
	if (ndata->state == ECHON_IN_OPEN_CLOSE) {
	    ndata->state = ECHON_IN_CLOSE;
	    err = GE_LOCALCLOSED;
	} else {
	    ndata->state = ECHON_OPEN;
	}
	if (ndata->open_done) {
	    echon_unlock(ndata);
	    ndata->open_done(ndata->io, err, ndata->open_data);
	    echon_lock(ndata);
	}
    }

 more_read:
    while (ndata->state == ECHON_OPEN &&
	   (gensio_circbuf_datalen(ndata->buf) > 0 || ndata->justdata) &&
	   ndata->read_enabled) {
	void *data;
	gensiods count;

	if (gensio_circbuf_datalen(ndata->buf) == 0) {
	    ndata->read_enabled = false;
	    echon_unlock(ndata);
	    gensio_cb(ndata->io, GENSIO_EVENT_READ, GE_REMCLOSE,
		      NULL, NULL, NULL);
	    echon_lock(ndata);
	} else {
	    gensio_circbuf_next_read_area(ndata->buf, &data, &count);
	    echon_unlock(ndata);
	    err = gensio_cb(ndata->io, GENSIO_EVENT_READ, 0,
			    data, &count, NULL);
	    echon_lock(ndata);
	    if (err)
		break;
	    gensio_circbuf_data_removed(ndata->buf, count);
	}
    }

    while (ndata->state == ECHON_OPEN &&
	   gensio_circbuf_room_left(ndata->buf) > 0 &&
	   ndata->xmit_enabled) {
	echon_unlock(ndata);
	err = gensio_cb(ndata->io, GENSIO_EVENT_WRITE_READY, 0,
			NULL, NULL, NULL);
	echon_lock(ndata);
	if (err)
	    break;
    }
    if (!err && ndata->state == ECHON_OPEN &&
		gensio_circbuf_datalen(ndata->buf) > 0 && ndata->read_enabled)
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
    if (enabled && ndata->state == ECHON_OPEN &&
		(gensio_circbuf_datalen(ndata->buf) > 0 || ndata->justdata))
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
		gensio_circbuf_room_left(ndata->buf) > 0)
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
    if (ndata->state != ECHON_OPEN && ndata->state != ECHON_IN_OPEN) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    if (ndata->state == ECHON_IN_OPEN)
	ndata->state = ECHON_IN_OPEN_CLOSE;
    else
	ndata->state = ECHON_IN_CLOSE;
    ndata->close_done = close_done;
    ndata->close_data = close_data;
    echon_start_deferred_op(ndata);
 out_unlock:
    echon_unlock(ndata);

    return err;
}

static void
echon_free(struct gensio *io)
{
    struct echon_data *ndata = gensio_get_gensio_data(io);

    echon_lock(ndata);
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
echon_control(struct gensio *io, bool get, int option, char *data,
	      gensiods *datalen)
{
    if (option != GENSIO_CONTROL_RADDR)
	return GE_NOTSUP;
    if (!get)
	return GE_NOTSUP;
    if (strtoul(data, NULL, 0) > 0)
	return GE_NOTFOUND;
    *datalen = gensio_pos_snprintf(data, *datalen, NULL, "echo");
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

    case GENSIO_FUNC_OPEN:
	return echon_open(io, (void *) cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return echon_close(io, (void *) cbuf, buf);

    case GENSIO_FUNC_FREE:
	echon_free(io);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	echon_set_read_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	echon_set_write_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_DISABLE:
	return echon_disable(io);

    case GENSIO_FUNC_CONTROL:
	return echon_control(io, *((bool *) cbuf), buflen, buf, count);

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

    ndata->buf = gensio_circbuf_alloc(o, max_read_size);
    if (!ndata->buf)
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

static int
echo_gensio_alloc(const void *gdata,
		  const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    int err;
    struct echon_data *ndata = NULL;
    int i;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    bool noecho = false;
    const char *data = NULL;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "noecho", &noecho) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "data", &data) > 0)
	    continue;
	return GE_INVAL;
    }

    if (data)
	max_read_size = strlen(data);

    err = echo_ndata_setup(o, max_read_size, &ndata);
    if (err)
	return err;

    if (data) {
	struct gensio_sg sg;

	if (noecho)
	    ndata->justdata = true;
	sg.buf = data;
	sg.buflen = max_read_size;
	gensio_circbuf_sg_write(ndata->buf, &sg, 1, NULL);
    }

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

static int
str_to_echo_gensio(const char *str, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    return echo_gensio_alloc(NULL, args, o, cb, user_data, new_gensio);
}

int
gensio_init_echo(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "echo", str_to_echo_gensio, echo_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
