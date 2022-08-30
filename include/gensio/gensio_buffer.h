/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_BUFFER_H
#define GENSIO_BUFFER_H

#include <gensio/gensio_dllvisibility.h>

struct gensio_buffer {
    unsigned char *buf;
    unsigned int maxsize;
    unsigned int cursize;
    unsigned int pos;
};

typedef int (*gensio_buffer_do_write)(void *cbdata, void *buf,
				      unsigned int buflen,
				      unsigned int *written);

/*
 * Call do_write() with all the data in the buffer.  This may take
 * multiple calls to do_write() if the data wraps.
 * If do_write() returns an error, buffer_write will exit immediately.
 * It may have written some data.
 */
GENSIO_DLL_PUBLIC
int gensio_buffer_write(gensio_buffer_do_write do_write, void *cb_data,
			struct gensio_buffer *buf);

/*
 * Add the data to the buffer.  If there is not enough room for the data,
 * part of the data is added.  The number of bytes added is returned.
 */
GENSIO_DLL_PUBLIC
unsigned int gensio_buffer_output(struct gensio_buffer *buf,
				  const unsigned char *data, unsigned int len);

/*
 * Add a single character to the buffer.  Returns the number of
 * characters added.
 */
GENSIO_DLL_PUBLIC
unsigned int gensio_buffer_outchar(struct gensio_buffer *buf,
				   unsigned char data);

/*
 * Initialize the buffer.  If data is NULL, it is allocated.
 */
GENSIO_DLL_PUBLIC
int gensio_buffer_init(struct gensio_buffer *buf,
		       unsigned char *data, unsigned int datalen);

/*
 * Number of bytes left in the buffer.
 */
#define gensio_buffer_left(buf) ((buf)->maxsize - (buf)->cursize)

/*
 * Number of bytes currently held in the buffer.
 */
#define gensio_buffer_cursize(buf) ((buf)->cursize)

/*
 * Consume the given number of bytes in the buffer.
 */
#define gensio_buffer_advance(bufp, count) \
    do { \
	(bufp)->pos += (count);			\
	while ((bufp)->pos >= (bufp)->maxsize)	\
	    (bufp)->pos -= (bufp)->maxsize;	\
    }

/*
 * Set the buffer to have no data.
 */
#define gensio_buffer_reset(buf) \
    do {			\
	(buf)->cursize = 0;	\
	(buf)->pos = 0;		\
    } while(0)

#endif /* _SER2NET_BUFFER_H */
