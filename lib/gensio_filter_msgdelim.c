/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <stdio.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>

#include "gensio_filter_msgdelim.h"
#include "crc16.h"

struct msgdelim_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    bool in_cmd; /* Last char was 254. */
    bool in_msg; /* Currently processing message data (after a start). */
    bool in_msg_complete; /* A full message is ready. */
    bool out_msg_complete;
    bool crc;

    /* Data waiting to be delivered to the user. */
    unsigned char *read_data;
    gensiods max_read_size;
    gensiods read_data_pos;
    gensiods read_data_len;

    /* Data waiting to be written. */
    unsigned char *write_data;
    gensiods buf_max_write; /* Maximum raw bytes (doubling 254s, etc.) */
    gensiods write_data_pos;
    gensiods write_data_len;

    gensiods max_write_size; /* Maximum user message size. */
    gensiods user_write_pos; /* Current user position. */
};

#define filter_to_msgdelim(v) ((struct msgdelim_filter *) \
			       gensio_filter_get_user_data(v))

static void
msgdelim_lock(struct msgdelim_filter *mfilter)
{
    mfilter->o->lock(mfilter->lock);
}

static void
msgdelim_unlock(struct msgdelim_filter *mfilter)
{
    mfilter->o->unlock(mfilter->lock);
}

static bool
msgdelim_ul_read_pending(struct gensio_filter *filter)
{
    struct msgdelim_filter *mfilter = filter_to_msgdelim(filter);

    return mfilter->in_msg_complete;
}

static bool
msgdelim_ll_write_pending(struct gensio_filter *filter)
{
    struct msgdelim_filter *mfilter = filter_to_msgdelim(filter);

    return mfilter->out_msg_complete;
}

static bool
msgdelim_ll_read_needed(struct gensio_filter *filter)
{
    return false;
}

static int
msgdelim_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    gensio_set_is_packet(io, true);
    return 0;
}

static int
msgdelim_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

#include <stdio.h>
static int
msgdelim_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct msgdelim_filter *mfilter = filter_to_msgdelim(filter);

    if (mfilter->write_data_len == 0 || !mfilter->out_msg_complete)
	return 0;
    else
	return GE_INPROGRESS;
}

static void
msgdelim_add_wrbyte(struct msgdelim_filter *mfilter, unsigned char byte)
{
    mfilter->write_data[mfilter->write_data_len++] = byte;
    if (byte == 254)
	mfilter->write_data[mfilter->write_data_len++] = 0;
}

static int
msgdelim_ul_write(struct gensio_filter *filter,
		  gensio_ul_filter_data_handler handler, void *cb_data,
		  gensiods *rcount,
		  const struct gensio_sg *sg, gensiods sglen,
		  const char *const *auxdata)
{
    struct msgdelim_filter *mfilter = filter_to_msgdelim(filter);
    int err = 0;

    msgdelim_lock(mfilter);
    if (mfilter->out_msg_complete) {
	if (rcount)
	    *rcount = 0;
    } else {
	gensiods i, j, writelen = 0;
	uint16_t crc = 0;

	for (i = 0; i < sglen; i++) {
	    gensiods inlen = sg[i].buflen;
	    const unsigned char *buf = sg[i].buf;

	    crc16(buf, inlen, &crc);
	    for (j = 0; j < inlen; j++) {
		if (mfilter->user_write_pos >= mfilter->max_write_size) {
		    err = GE_TOOBIG;
		    mfilter->user_write_pos = 0;
		    mfilter->write_data_len = 0;
		    mfilter->write_data_pos = 0;
		    goto out_err;
		}
		mfilter->user_write_pos++;
		msgdelim_add_wrbyte(mfilter, buf[j]);
	    }
	    writelen += inlen;
	}
	if (rcount)
	    *rcount = writelen;

	if (mfilter->user_write_pos > 0) {
	    mfilter->out_msg_complete = true;
	    if (mfilter->crc) {
		msgdelim_add_wrbyte(mfilter, crc >> 8);
		msgdelim_add_wrbyte(mfilter, crc & 0xff);
	    }
	    mfilter->write_data[mfilter->write_data_len++] = 254;
	    mfilter->write_data[mfilter->write_data_len++] = 1; /* separator */
	}
    }

    if (mfilter->out_msg_complete) {
	struct gensio_sg sg[1];
	gensiods len = mfilter->write_data_len - mfilter->write_data_pos;
	gensiods count;

	sg[0].buflen = len;
	sg[0].buf = mfilter->write_data + mfilter->write_data_pos;

	msgdelim_unlock(mfilter);
	err = handler(cb_data, &count, sg, 1, NULL);
	msgdelim_lock(mfilter);
	if (err) {
	    mfilter->out_msg_complete = false;
	} else {
	    if (count >= len) {
		mfilter->write_data_len = 0;
		mfilter->write_data_pos = 0;
		mfilter->out_msg_complete = false;
		mfilter->user_write_pos = 0;
	    } else {
		mfilter->write_data_pos += count;
	    }
	}
    }
 out_err:
    msgdelim_unlock(mfilter);

    return err;
}

static int
msgdelim_ll_write(struct gensio_filter *filter,
		gensio_ll_filter_data_handler handler, void *cb_data,
		gensiods *rcount,
		unsigned char *buf, gensiods buflen,
		const char *const *auxdata)
{
    struct msgdelim_filter *mfilter = filter_to_msgdelim(filter);
    gensiods in_buflen = buflen;
    int err = 0;
    static const char *eomaux[2] = { "eom", NULL };
    uint16_t crc;

    msgdelim_lock(mfilter);
    if (mfilter->in_msg_complete || buflen == 0) {
	if (rcount)
	    *rcount = 0;
    } else {
	while (buflen && !mfilter->in_msg_complete) {
	    unsigned char b = *buf++;

	    buflen--;

	    if (mfilter->in_cmd) {
		mfilter->in_cmd = false;
		switch (b) {
		case 0: /* 254 0 is one 254 */
		    b = 254;
		    goto handle_data;

		case 1: /* 254 1 is message separator */
		    if (mfilter->in_msg) {
			if (mfilter->crc) {
			    if (mfilter->read_data_len <= 2)
				break;
			    crc = 0;
			    crc16(mfilter->read_data, mfilter->read_data_len,
				  &crc);
			    if (crc != 0)
				break;
			    mfilter->read_data_len -= 2; /* Remove the CRC */
			}
			mfilter->in_msg_complete = true;
		    }
		    mfilter->in_msg = true;
		    break;

		default:
		    mfilter->in_msg = false;
		    break;
		}
	    } else if (b == 254) {
		mfilter->in_cmd = true;
	    } else {
	    handle_data:
		if (!mfilter->in_msg)
		    continue;
		if (mfilter->read_data_len >= mfilter->max_read_size) {
		    mfilter->in_msg = false;
		    continue;
		}
		mfilter->read_data[mfilter->read_data_len++] = b;
	    }
	}

	if (rcount)
	    *rcount = in_buflen - buflen;
    }

    if (mfilter->in_msg_complete) {
	gensiods count = 0;

	msgdelim_unlock(mfilter);
	err = handler(cb_data, &count,
		      mfilter->read_data + mfilter->read_data_pos,
		      mfilter->read_data_len, eomaux);
	msgdelim_lock(mfilter);
	if (!err) {
	    if (count >= mfilter->read_data_len) {
		mfilter->in_msg_complete = false;
		mfilter->read_data_len = 0;
		mfilter->read_data_pos = 0;
	    } else {
		mfilter->read_data_len -= count;
		mfilter->read_data_pos += count;
	    }
	}
    }
    msgdelim_unlock(mfilter);

    return err;
}

static int
msgdelim_setup(struct gensio_filter *filter)
{
    return 0;
}

static void
msgdelim_filter_cleanup(struct gensio_filter *filter)
{
    struct msgdelim_filter *mfilter = filter_to_msgdelim(filter);

    mfilter->read_data_len = 0;
    mfilter->read_data_pos = 0;
    mfilter->write_data_len = 0;
    mfilter->write_data_pos = 0;
    mfilter->user_write_pos = 0;
    mfilter->in_msg_complete = false;
    mfilter->in_msg = false;
    mfilter->out_msg_complete = false;
}

static void
mfilter_free(struct msgdelim_filter *mfilter)
{
    if (mfilter->lock)
	mfilter->o->free_lock(mfilter->lock);
    if (mfilter->read_data)
	mfilter->o->free(mfilter->o, mfilter->read_data);
    if (mfilter->write_data)
	mfilter->o->free(mfilter->o, mfilter->write_data);
    if (mfilter->filter)
	gensio_filter_free_data(mfilter->filter);
    mfilter->o->free(mfilter->o, mfilter);
}

static void
msgdelim_free(struct gensio_filter *filter)
{
    struct msgdelim_filter *mfilter = filter_to_msgdelim(filter);

    mfilter_free(mfilter);
}

static int
msgdelim_control(struct gensio_filter *filter, bool get, int op, char *data,
		 gensiods *datalen)
{
    struct msgdelim_filter *mfilter = filter_to_msgdelim(filter);

    switch (op) {
    case GENSIO_CONTROL_MAX_WRITE_PACKET:
	if (!get)
	    return GE_NOTSUP;
	*datalen = snprintf(data, *datalen, "%lu",
			    (unsigned long) mfilter->max_write_size);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int gensio_msgdelim_filter_func(struct gensio_filter *filter, int op,
				       void *func, void *data,
				       gensiods *count,
				       void *buf, const void *cbuf,
				       gensiods buflen,
				       const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return msgdelim_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return msgdelim_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return msgdelim_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return msgdelim_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return msgdelim_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return msgdelim_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return msgdelim_ul_write(filter, func, data, count, cbuf, buflen,
				 auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return msgdelim_ll_write(filter, func, data, count, buf, buflen,
				 auxdata);

    case GENSIO_FILTER_FUNC_SETUP:
	return msgdelim_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	msgdelim_filter_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	msgdelim_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return msgdelim_control(filter, *((bool *) cbuf), buflen, data, count);

    default:
	return GE_NOTSUP;
    }
}

static struct gensio_filter *
gensio_msgdelim_filter_raw_alloc(struct gensio_os_funcs *o,
				 gensiods max_read_size,
				 gensiods max_write_size,
				 bool crc)
{
    struct msgdelim_filter *mfilter;

    mfilter = o->zalloc(o, sizeof(*mfilter));
    if (!mfilter)
	return NULL;

    mfilter->o = o;

    max_read_size += 2; /* Add CRC */

    mfilter->max_write_size = max_write_size;
    mfilter->max_read_size = max_read_size;
    mfilter->crc = crc;

    /*
     * Room to double every byte (worst case) including the CRC and
     * add two separators (first one only for the first sent packet).
     */
    mfilter->buf_max_write = ((max_write_size + 2) * 2) + 4;

    mfilter->lock = o->alloc_lock(o);
    if (!mfilter->lock)
	goto out_nomem;

    mfilter->read_data = o->zalloc(o, max_read_size);
    if (!mfilter->read_data)
	goto out_nomem;

    mfilter->write_data = o->zalloc(o, mfilter->buf_max_write);
    if (!mfilter->write_data)
	goto out_nomem;

    mfilter->filter = gensio_filter_alloc_data(o, gensio_msgdelim_filter_func,
					       mfilter);
    if (!mfilter->filter)
	goto out_nomem;

    /* Add a separator at the beginning of the first message. */
    mfilter->write_data[0] = 254;
    mfilter->write_data[1] = 1; /* message separator */
    mfilter->write_data_len = 2;

    return mfilter->filter;

 out_nomem:
    mfilter_free(mfilter);
    return NULL;
}

int
gensio_msgdelim_filter_alloc(struct gensio_os_funcs *o,
			     const char * const args[],
			     struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    unsigned int i;
    gensiods max_read_size = 128; /* FIXME - magic number. */
    gensiods max_write_size = 128; /* FIXME - magic number. */
    bool crc = true;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "writebuf", &max_write_size) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "crc", &crc) > 0)
	    continue;
	return GE_INVAL;
    }

    filter = gensio_msgdelim_filter_raw_alloc(o, max_read_size, max_write_size,
					      crc);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}
