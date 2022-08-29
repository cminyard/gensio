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

static const uint16_t crc16_table[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
};

static void
crc16(const unsigned char *buf, unsigned int len, uint16_t *icrc)
{
    unsigned int i;
    uint16_t crc = *icrc;

    for (i = 0; i < len; i++)
	crc = (crc << 8) ^ crc16_table[((crc >> 8) ^ buf[i]) & 0xff];

    *icrc = crc;
}

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

/*
 * The basic protocol is pretty simple here.  A 254 is a command byte,
 * followed by 0 for sending a single 254, and 1 for a message
 * separator.  There is a 16 bit CRC at the end of every message,
 * unless disabled.
 */

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
