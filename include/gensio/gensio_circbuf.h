/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * A circular buffer implementation.
 */

#ifndef GENSIO_CIRCBUF_H
#define GENSIO_CIRCBUF_H

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

struct gensio_circbuf;

/*
 * Return the number of free bytes left in the buffer.
 */
GENSIO_DLL_PUBLIC
gensiods gensio_circbuf_room_left(struct gensio_circbuf *c);

/*
 * Get the next writable section of the circular buffer.  Returns a
 * pointer to the next writable area and the size of the area.  You
 * should call gensio_circbuf_room_left() before calling this to make
 * sure there is room.
 *
 * Note that this may not be all the room available in the buffer, it
 * is just the next section.  If you write all the data returned by
 * this, then call gensio_circbuf_data_added(), you should call
 * gensio_circbuf_room_left() again to see if more room is available.
 */
GENSIO_DLL_PUBLIC
void gensio_circbuf_next_write_area(struct gensio_circbuf *c,
				    void **pos, gensiods *size);

/*
 * Report that data was added to the buffer.
 */
GENSIO_DLL_PUBLIC
void gensio_circbuf_data_added(struct gensio_circbuf *c, gensiods len);

/*
 * Return the number of bytes available to be read out of the buffer.
 */
GENSIO_DLL_PUBLIC
gensiods gensio_circbuf_datalen(struct gensio_circbuf *c);

/*
 * Get the next block of data to read out of the buffer.  It returns a
 * pointer to the data and a size.  You can get up to size bytes.
 * After taking data data out of the buffer, you should call
 * gensio_circbuf_data_removed() for the amount of data removed.
 *
 * If you remove size bytes from buffer, you should call
 * gensio_circbuf_datalen() again if you can take more data, as this
 * may not report all available data, just the next available chunk.
 */
GENSIO_DLL_PUBLIC
void gensio_circbuf_next_read_area(struct gensio_circbuf *c,
				   void **pos, gensiods *size);

/*
 * Report that len bytes were read out of the buffer.  len should not
 * exceed the size returned by gensio_circbuf_next_read_area().
 */
GENSIO_DLL_PUBLIC
void gensio_circbuf_data_removed(struct gensio_circbuf *c, gensiods len);

/*
 * Set the circbuf data length to zero.
 */
GENSIO_DLL_PUBLIC
void gensio_circbuf_reset(struct gensio_circbuf *c);

/*
 * Add data from a scatter-gather structure to a circular buffer.
 * Return the number of bytes put into the buffer in rcount;
 */
GENSIO_DLL_PUBLIC
void gensio_circbuf_sg_write(struct gensio_circbuf *c,
			     const struct gensio_sg *sg, gensiods sglen,
			     gensiods *rcount);

/*
 * Read data from a scatter-gather buffer.  The number of bytes
 * returned is put into rcount.
 */
GENSIO_DLL_PUBLIC
void gensio_circbuf_read(struct gensio_circbuf *c,
			 void *ibuf, gensiods buflen, gensiods *rcount);

/* Allocate a circbuf. */
GENSIO_DLL_PUBLIC
struct gensio_circbuf *gensio_circbuf_alloc(struct gensio_os_funcs *o,
					    gensiods size);

/* Free an allocated circbuf. */
GENSIO_DLL_PUBLIC
void gensio_circbuf_free(struct gensio_circbuf *c);

#endif /* GENSIO_CIRCBUF_H */
