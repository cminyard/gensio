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
#include <stdlib.h>
#include <ctype.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_os_funcs.h>

#include "gensio_filter_script.h"

enum script_state {
    SCRIPT_CLOSED,
    SCRIPT_IN_SUB_OPEN,
    SCRIPT_IN_OPEN,
    SCRIPT_OPEN,
    SCRIPT_OPEN_FAIL
};

struct script_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;

    enum script_state state;

    int err;

    struct gensio_lock *lock;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    /*
     * Script to gensio buffer, handles data coming from the script
     * gensio and out the main gensio.
     */
    unsigned char scrtog_buf[1024];
    gensiods scrtog_pos;
    gensiods scrtog_len;

    /*
     * Gensio to script buffer, handles data coming from the main gensio
     * and out to the script.
     */
    unsigned char gtoscr_buf[1024];
    gensiods gtoscr_pos;
    gensiods gtoscr_len;

    char *str;
    struct gensio *io;
};

#define filter_to_script(v) ((struct script_filter *) \
			     gensio_filter_get_user_data(v))

static void
script_lock(struct script_filter *sfilter)
{
    sfilter->o->lock(sfilter->lock);
}

static void
script_unlock(struct script_filter *sfilter)
{
    sfilter->o->unlock(sfilter->lock);
}

static bool
script_ul_read_pending(struct gensio_filter *filter)
{
    return false;
}

static bool
script_ll_write_pending(struct gensio_filter *filter)
{
    struct script_filter *sfilter = filter_to_script(filter);
    bool rv = false;

    script_lock(sfilter);
    if (sfilter->state == SCRIPT_IN_OPEN)
	rv = sfilter->scrtog_len > 0;
    script_unlock(sfilter);
    return rv;
}

static bool
script_ll_read_needed(struct gensio_filter *filter)
{
    struct script_filter *sfilter = filter_to_script(filter);
    bool rv = false;

    script_lock(sfilter);
    if (sfilter->state == SCRIPT_IN_OPEN)
	rv = sfilter->gtoscr_len == 0;
    script_unlock(sfilter);
    return rv;
}

static int
script_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    struct script_filter *sfilter = filter_to_script(filter);

    return sfilter->err;
}

static void
script_finish_close(struct gensio *io, void *close_data)
{
    struct script_filter *sfilter = close_data;
    char data[50];
    gensiods datalen = sizeof(data);

    if (!sfilter->err) {
	/* Check that the script returned no error. */
	int err = gensio_control(sfilter->io, 0, true, GENSIO_CONTROL_EXIT_CODE,
				 data, &datalen);
	if (!err) {
	    int errcode = strtoul(data, 0, 0);

	    if (errcode != 0) {
		err = GE_LOCALCLOSED;
		sfilter->state = SCRIPT_OPEN_FAIL;
	    }
	} else if (err == GE_NOTFOUND) {
	    /* Not stdio or pty, no subprogram. */
	    err = 0;
	}

	sfilter->err = err;
    }

    if (sfilter->err)
	sfilter->state = SCRIPT_OPEN_FAIL;
    else
	sfilter->state = SCRIPT_OPEN;

    gensio_free(sfilter->io);
    sfilter->io = NULL;

    sfilter->filter_cb(sfilter->filter_cb_data, GENSIO_FILTER_CB_OPEN_DONE,
		       NULL);
}

static void
script_handle_err_unlock(struct script_filter *sfilter, int err)
{
    if (sfilter->state == SCRIPT_IN_OPEN) {
	if (err == GE_REMCLOSE) {
	    /* Normal close */
	    err = 0;
	}
    }
 handle_err:
    sfilter->err = err;
    if (err) {
	gensio_set_read_callback_enable(sfilter->io, false);
	gensio_set_write_callback_enable(sfilter->io, false);
	sfilter->state = SCRIPT_OPEN_FAIL;
	script_unlock(sfilter);
	script_finish_close(sfilter->io, sfilter);
    } else {
	err = gensio_close(sfilter->io, script_finish_close, sfilter);
	if (err)
	    goto handle_err;
    }
    script_unlock(sfilter);
}

static void
script_open_done(struct gensio *io, int err, void *open_data)
{
    struct script_filter *sfilter = open_data;

    script_lock(sfilter);
    if (err) {
	script_handle_err_unlock(sfilter, err);
    } else {
	sfilter->state = SCRIPT_IN_OPEN;
	gensio_set_read_callback_enable(sfilter->io, true);
	script_unlock(sfilter);
	sfilter->filter_cb(sfilter->filter_cb_data,
			   GENSIO_FILTER_CB_INPUT_READY, NULL);
    }
}

static int
script_sub_event(struct gensio *io, void *user_data,
		 int event, int err,
		 unsigned char *buf, gensiods *buflen,
		 const char *const *auxdata)
{
    struct script_filter *sfilter = user_data;
    gensiods count;
    bool call_handler = false;

    if (sfilter->state != SCRIPT_IN_OPEN || io != sfilter->io)
	/* Not in the right state, or an old io. */
	return GE_NOTSUP;

    switch(event) {
    case GENSIO_EVENT_READ:
	script_lock(sfilter);
	if (err)
	    goto handle_err;
	if (*buflen == 0) {
	    /* Shouldn't happen, but just in case. */
	} else if (sfilter->scrtog_len > 0) {
	    gensio_set_read_callback_enable(sfilter->io, false);
	    *buflen = 0;
	} else {
	    count = *buflen;
	    if (count > sizeof(sfilter->scrtog_buf))
		count = sizeof(sfilter->scrtog_buf);
	    memcpy(sfilter->scrtog_buf, buf, count);
	    sfilter->scrtog_pos = 0;
	    sfilter->scrtog_len = count;
	    call_handler = true;
	    gensio_set_read_callback_enable(sfilter->io, false);
	}
	script_unlock(sfilter);
	if (call_handler)
	    sfilter->filter_cb(sfilter->filter_cb_data,
			       GENSIO_FILTER_CB_OUTPUT_READY, NULL);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	script_lock(sfilter);
	if (sfilter->gtoscr_len == 0) {
	    gensio_set_write_callback_enable(sfilter->io, false);
	} else {
	    err = gensio_write(sfilter->io, &count,
			       sfilter->gtoscr_buf + sfilter->gtoscr_pos,
			       sfilter->gtoscr_len, NULL);
	    if (err)
		goto handle_err;
	    if (count >= sfilter->gtoscr_len) {
		sfilter->gtoscr_len = 0;
		sfilter->gtoscr_pos = 0;
		call_handler = true;
		gensio_set_write_callback_enable(sfilter->io, false);
	    } else {
		sfilter->gtoscr_len -= count;
		sfilter->gtoscr_pos += count;
	    }
	}
	script_unlock(sfilter);
	if (call_handler)
	    sfilter->filter_cb(sfilter->filter_cb_data,
			       GENSIO_FILTER_CB_INPUT_READY, NULL);
	return 0;

    default:
	return GE_NOTSUP;
    }

 handle_err:
    script_handle_err_unlock(sfilter, err);
    return err;
}

static int
script_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct script_filter *sfilter = filter_to_script(filter);
    int err = GE_INPROGRESS;

    script_lock(sfilter);
    switch(sfilter->state) {
    case SCRIPT_IN_SUB_OPEN:
    case SCRIPT_IN_OPEN:
	break;

    case SCRIPT_CLOSED:
	err = str_to_gensio(sfilter->str, sfilter->o,
			    script_sub_event, sfilter, &sfilter->io);
	if (!err) {
	    err = gensio_open(sfilter->io, script_open_done, sfilter);
	    if (err) {
		gensio_free(sfilter->io);
		sfilter->io = NULL;
	    }
	}
	if (!err) {
	    sfilter->state = SCRIPT_IN_SUB_OPEN;
	    err = GE_INPROGRESS;
	}
	break;

    case SCRIPT_OPEN:
    case SCRIPT_OPEN_FAIL:
	err = 0;
	break;
    }
    script_unlock(sfilter);

    return err;
}

static int
script_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct script_filter *sfilter = filter_to_script(filter);
    int err;

    script_lock(sfilter);
    switch(sfilter->state) {
    case SCRIPT_IN_SUB_OPEN:
    case SCRIPT_IN_OPEN:
	gensio_free(sfilter->io);
	sfilter->io = NULL;
	/* fallthrough */

    case SCRIPT_OPEN:
	sfilter->state = SCRIPT_CLOSED;
	err = 0;
	break;
	
    default:
	err = GE_NOTREADY;
    }
    script_unlock(sfilter);
    return err;
}

static int
script_ul_write(struct gensio_filter *filter,
		gensio_ul_filter_data_handler handler, void *cb_data,
		gensiods *rcount,
		const struct gensio_sg *sg, gensiods sglen,
		const char *const *auxdata)
{
    struct script_filter *sfilter = filter_to_script(filter);
    gensiods count = 0;
    int err = 0;

    if (sfilter->state == SCRIPT_OPEN)
	return handler(cb_data, rcount, sg, sglen, auxdata);

    script_lock(sfilter);
    switch(sfilter->state) {
    case SCRIPT_IN_SUB_OPEN:
	*rcount = 0;
	break;

    case SCRIPT_IN_OPEN:
	if (sfilter->scrtog_len > 0) {
	    struct gensio_sg sg;

	    sg.buf = sfilter->scrtog_buf + sfilter->scrtog_pos;
	    sg.buflen = sfilter->scrtog_len;
	    script_unlock(sfilter);
	    err = handler(sfilter->filter_cb_data,
			  &count, &sg, 1, auxdata);	    
	    script_lock(sfilter);
	    if (err)
		goto out_err;
	    if (count >= sfilter->scrtog_len) {
		sfilter->scrtog_len = 0;
		sfilter->scrtog_pos = 0;
		gensio_set_read_callback_enable(sfilter->io, true);
	    } else {
		sfilter->scrtog_len -= count;
		sfilter->scrtog_pos += count;
	    }
	}
	break;

    default:
	return GE_NOTREADY;
    }
    script_unlock(sfilter);

    if (rcount)
	*rcount = count;

    return 0;

 out_err:
    script_handle_err_unlock(sfilter, err);
    return err;
}

static int
script_ll_write(struct gensio_filter *filter,
		gensio_ll_filter_data_handler handler, void *cb_data,
		gensiods *rcount,
		unsigned char *buf, gensiods buflen,
		const char *const *auxdata)
{
    struct script_filter *sfilter = filter_to_script(filter);
    int err = 0;
    gensiods count = 0;

    if (sfilter->state == SCRIPT_OPEN)
	return handler(cb_data, rcount, buf, buflen, auxdata);

    script_lock(sfilter);
    switch(sfilter->state) {
    case SCRIPT_IN_SUB_OPEN:
	break;

    case SCRIPT_IN_OPEN:
	if (sfilter->gtoscr_len == 0 && buflen > 0) {
	    if (buflen > sizeof(sfilter->gtoscr_buf))
		buflen = sizeof(sfilter->gtoscr_buf);

	    memcpy(sfilter->gtoscr_buf, buf, buflen);
	    sfilter->gtoscr_len = buflen;
	    sfilter->gtoscr_pos = 0;
	    count = buflen;
	    gensio_set_write_callback_enable(sfilter->io, true);
	}
	break;

    default:
	err = GE_NOTREADY;
    }
    script_unlock(sfilter);

    if (!err && rcount)
	*rcount = count;

    return err;
}

static int
script_setup(struct gensio_filter *filter)
{
    struct script_filter *sfilter = filter_to_script(filter);

    sfilter->err = 0;
    sfilter->scrtog_len = 0;
    sfilter->scrtog_pos = 0;
    sfilter->gtoscr_len = 0;
    sfilter->gtoscr_pos = 0;
    sfilter->state = SCRIPT_CLOSED;
    return 0;
}

static void
script_filter_cleanup(struct gensio_filter *filter)
{
    struct script_filter *sfilter = filter_to_script(filter);

    if (sfilter->io) {
	gensio_free(sfilter->io);
	sfilter->io = NULL;
    }
}

static void
sfilter_free(struct script_filter *sfilter)
{
    if (sfilter->lock)
	sfilter->o->free_lock(sfilter->lock);
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    if (sfilter->str)
	sfilter->o->free(sfilter->o, sfilter->str);
    sfilter->o->free(sfilter->o, sfilter);
}

static void
script_free(struct gensio_filter *filter)
{
    struct script_filter *sfilter = filter_to_script(filter);

    sfilter_free(sfilter);
}

static int
script_set_callback(struct gensio_filter *filter,
			gensio_filter_cb cb, void *cb_data)
{
    struct script_filter *sfilter = filter_to_script(filter);

    sfilter->filter_cb = cb;
    sfilter->filter_cb_data = cb_data;
    return 0;
}

static int gensio_script_filter_func(struct gensio_filter *filter, int op,
				     void *func, void *data,
				     gensiods *count,
				     void *buf, const void *cbuf,
				     gensiods buflen,
				     const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	return script_set_callback(filter, func, data);

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return script_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return script_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return script_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return script_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return script_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return script_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return script_ul_write(filter, func, data, count, cbuf, buflen,
			       auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return script_ll_write(filter, func, data, count, buf, buflen,
			       auxdata);

    case GENSIO_FILTER_FUNC_SETUP:
	return script_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	script_filter_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	script_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return GE_NOTSUP;

    default:
	return GE_NOTSUP;
    }
}

static struct gensio_filter *
gensio_script_filter_raw_alloc(struct gensio_os_funcs *o, char *str)
{
    struct script_filter *sfilter;

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return NULL;

    sfilter->o = o;
    sfilter->str = str;

    sfilter->lock = o->alloc_lock(o);
    if (!sfilter->lock)
	goto out_nomem;

    sfilter->filter = gensio_filter_alloc_data(o, gensio_script_filter_func,
					       sfilter);
    if (!sfilter->filter)
	goto out_nomem;

    return sfilter->filter;

 out_nomem:
    sfilter_free(sfilter);
    return NULL;
}

int
gensio_script_filter_alloc(struct gensio_os_funcs *o,
			   const char * const args[],
			   struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    const char *scr = NULL;
    const char *gensioscr = NULL;
    char *str;
    unsigned int i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyvalue(args[i], "script", &scr) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "gensio", &gensioscr) > 0)
	    continue;
	return GE_INVAL;
    }

    if (!scr && !gensioscr)
	return GE_INVAL;

    if (scr)
	str = gensio_alloc_sprintf(o, "stdio(noredir-stderr),%s", scr);
    else
	str = gensio_strdup(o, gensioscr);

    filter = gensio_script_filter_raw_alloc(o, str);
    if (!filter) {
	o->free(o, str);
	return GE_NOMEM;
    }

    *rfilter = filter;
    return 0;
}
