/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <gensio/gensio_buffer.h>

#include <gensio/gensio_err.h>

static int
do_write(gensio_buffer_do_write tdo_write, void *cb_data,
	 void *buf, unsigned int buflen, unsigned int *written)
{
    int err = 0;
    unsigned int write_count;

    err = tdo_write(cb_data, buf, buflen, &write_count);
    if (!err)
	*written = write_count;

    return err;
}

int
gensio_buffer_write(gensio_buffer_do_write tdo_write, void *cb_data,
		    struct gensio_buffer *buf)
{
    int err;
    unsigned int write_count;
    int towrite1;
    int towrite2 = 0;

    if (buf->pos + buf->cursize > buf->maxsize) {
	towrite1 = buf->maxsize - buf->pos;
	towrite2 = buf->cursize - towrite1;
    } else {
	towrite1 = buf->cursize;
    }

    if (towrite1 > 0) {
	err = do_write(tdo_write, cb_data,
		       buf->buf + buf->pos, towrite1, &write_count);
	if (err)
	    return err;

	buf->pos += write_count;
	buf->cursize -= write_count;
	if (write_count < towrite1)
	    return 0;
    }

    if (towrite2 > 0) {
	/* We wrapped */
	buf->pos = 0;
	err = do_write(tdo_write, cb_data, buf->buf, towrite2, &write_count);
	if (err)
	    return err;
	buf->pos += write_count;
	buf->cursize -= write_count;
    }

    return 0;
}

unsigned int
gensio_buffer_output(struct gensio_buffer *buf,
		     const unsigned char *data, unsigned int len)
{
    int end;

    if (gensio_buffer_left(buf) < len)
	len = gensio_buffer_left(buf);

    end = buf->pos + buf->cursize;
    if (end > buf->maxsize)
	end -= buf->maxsize;
    if (end + len > buf->maxsize) {
	int availend = buf->maxsize - end;

	memcpy(buf->buf + end, data, availend);
	buf->cursize += availend;
	end = 0;
	len -= availend;
	data += availend;
    }
    memcpy(buf->buf + end, data, len);
    buf->cursize += len;

    return len;
}

unsigned int
gensio_buffer_outchar(struct gensio_buffer *buf, unsigned char data)
{
    int end;

    if (gensio_buffer_left(buf) < 1)
	return 0;

    end = buf->pos + buf->cursize;
    if (end >= buf->maxsize)
	end -= buf->maxsize;
    buf->buf[end] = data;
    buf->cursize += 1;

    return 1;
}

int
gensio_buffer_init(struct gensio_buffer *buf,
		   unsigned char *data, unsigned int datasize)
{
    if (data) {
	buf->buf = data;
    } else {
	buf->buf = malloc(datasize);
	if (!buf->buf)
	    return GE_NOMEM;
    }
    buf->maxsize = datasize;
    buf->cursize = 0;
    buf->pos = 0;

    return 0;
}
