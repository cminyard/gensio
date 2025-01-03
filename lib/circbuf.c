/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <string.h>
#include <assert.h>
#include <gensio/gensio_circbuf.h>
#include <gensio/gensio_os_funcs.h>

struct gensio_circbuf {
    struct gensio_os_funcs *o;
    gensiods pos;
    gensiods size;
    gensiods bufsize;
    unsigned char *cbuf;
};

gensiods
gensio_circbuf_room_left(struct gensio_circbuf *c)
{
    return c->bufsize - c->size;
}

void
gensio_circbuf_next_write_area(struct gensio_circbuf *c,
			       void **pos, gensiods *size)
{
    gensiods end;

    end = (c->pos + c->size) % c->bufsize;
    if (c->size == c->bufsize)
	*size = 0;
    else if (end >= c->pos)
	/* Unwrapped or empty buffer, write to the end. */
	*size = c->bufsize - end;
    else
	/* Wrapped or full buffer, write between end and iopos. */
	*size = c->pos - end;
    *pos = c->cbuf + end;
}

void
gensio_circbuf_data_added(struct gensio_circbuf *c, gensiods len)
{
    assert(len + c->size <= c->bufsize);
    c->size += len;
}

void
gensio_circbuf_next_read_area(struct gensio_circbuf *c,
			      void **pos, gensiods *size)
{
    gensiods end;

    end = (c->pos + c->size) % c->bufsize;
    if (c->size == 0)
	*size = 0;
    else if (end > c->pos)
	/* Unwrapped buffer, read the whole thing. */
	*size = c->size;
    else
	/* Wrapped buffer, read to end. */
	*size = c->bufsize - c->pos;
    *pos = c->cbuf + c->pos;
}

void
gensio_circbuf_data_removed(struct gensio_circbuf *c, gensiods len)
{
    assert(len <= c->size);
    c->size -= len;
    c->pos = (c->pos + len) % c->bufsize;
}

gensiods
gensio_circbuf_datalen(struct gensio_circbuf *c)
{
    return c->size;
}

void
gensio_circbuf_reset(struct gensio_circbuf *c)
{
    c->pos = 0;
    c->size = 0;
}

void
gensio_circbuf_sg_write(struct gensio_circbuf *c,
			const struct gensio_sg *sg, gensiods sglen,
			gensiods *rcount)
{
    gensiods i, count = 0;

    for (i = 0; i < sglen && gensio_circbuf_room_left(c) > 0; i++) {
	gensiods buflen = sg[i].buflen;
	const unsigned char *buf = sg[i].buf;

	while (gensio_circbuf_room_left(c) && buflen > 0) {
	    gensiods size;
	    void *pos;

	    gensio_circbuf_next_write_area(c, &pos, &size);
	    if (size > buflen)
		size = buflen;
	    memcpy(pos, buf, size);
	    gensio_circbuf_data_added(c, size);
	    buf += size;
	    buflen -= size;
	    count += size;
	}
    }
    if (rcount)
	*rcount = count;
}

void
gensio_circbuf_read(struct gensio_circbuf *c,
		    void *ibuf, gensiods buflen, gensiods *rcount)
{
    gensiods count = 0;
    unsigned char *buf = ibuf;

    while (buflen > 0 && gensio_circbuf_datalen(c)) {
	void *pos;
	gensiods size;

	gensio_circbuf_next_read_area(c, &pos, &size);
	if (size > buflen)
	    size = buflen;
	memcpy(buf, pos, size);
	buflen -= size;
	count += size;
	buf += size;
	gensio_circbuf_data_removed(c, size);
    }
    if (rcount)
	*rcount = count;
}

struct gensio_circbuf *
gensio_circbuf_alloc(struct gensio_os_funcs *o, gensiods size)
{
    struct gensio_circbuf *c;

    c = o->zalloc(o, sizeof(*c));
    if (!c)
	return NULL;
    c->o = o;
    c->cbuf = o->zalloc(o, size);
    if (!c->cbuf) {
	o->free(o, c);
	return NULL;
    }
    c->bufsize = size;
    return c;
}

void
gensio_circbuf_free(struct gensio_circbuf *c)
{
    c->o->free(c->o, c->cbuf);
    c->o->free(c->o, c);
}
