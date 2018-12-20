/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.  These licenses are available
 *  in the root directory of this package named COPYING.LIB and
 *  COPYING.BSD, respectively.
 */

#ifndef _SER2NET_BUFFER_H
#define _SER2NET_BUFFER_H

struct sbuf {
    unsigned char *buf;
    unsigned int maxsize;
    unsigned int cursize;
    unsigned int pos;
};

typedef int (*buffer_do_write)(void *cbdata, void *buf, unsigned int buflen,
			       unsigned int *written);

/*
 * Call do_write() with all the data in the buffer.  This may take
 * multiple calls to do_write() if the data wraps.
 * If do_write() returns an error, buffer_write will exit immediately.
 * It may have written some data.
 */
int buffer_write(buffer_do_write do_write, void *cb_data, struct sbuf *buf);

/*
 * Add the data to the buffer.  If there is not enough room for the data,
 * part of the data is added.  The number of bytes added is returned.
 */
unsigned int buffer_output(struct sbuf *buf, const unsigned char *data,
			   unsigned int len);

/*
 * Add a single character to the buffer.  Returns the number of
 * characters added.
 */
unsigned int buffer_outchar(struct sbuf *buf, unsigned char data);

/*
 * Initialize the buffer.  If data is NULL, it is allocated.
 */
int buffer_init(struct sbuf *buf, unsigned char *data, unsigned int datalen);

/*
 * Number of bytes left in the buffer.
 */
#define buffer_left(buf) ((buf)->maxsize - (buf)->cursize)

/*
 * Number of bytes currently held in the buffer.
 */
#define buffer_cursize(buf) ((buf)->cursize)

/*
 * Consume the given number of bytes in the buffer.
 */
#define buffer_advance(bufp, count) \
    do { \
	(bufp)->pos += (count);			\
	while ((bufp)->pos >= (bufp)->maxsize)	\
	    (bufp)->pos -= (bufp)->maxsize;	\
    }

/*
 * Set the buffer to have no data.
 */
#define buffer_reset(buf) \
    do {			\
	(buf)->cursize = 0;	\
	(buf)->pos = 0;		\
    } while(0)

#endif /* _SER2NET_BUFFER_H */
