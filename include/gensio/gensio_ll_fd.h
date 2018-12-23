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

#ifndef GENSIO_LL_FD_H
#define GENSIO_LL_FD_H

#include <gensio/gensio_base.h>

enum gensio_ll_close_state {
    GENSIO_LL_CLOSE_STATE_START,
    GENSIO_LL_CLOSE_STATE_DONE
};

struct gensio_fd_ll_ops {
    int (*sub_open)(void *handler_data, int *fd);

    int (*check_open)(void *handler_data, int fd);

    int (*retry_open)(void *handler_data, int *fd);

    int (*raddr_to_str)(void *handler_data, unsigned int *pos,
			char *buf, unsigned int buflen);

    int (*get_raddr)(void *handler_data, void *addr, unsigned int *addrlen);

    int (*remote_id)(void *handler_data, int *id);

    /*
     * When GENSIO_LL_CLOSE_STATE_START, timeout will be NULL and the
     * return value is ignored.  Return 0.  When
     * GENSIO_LL_CLOSE_STATE_DONE, return EAGAIN to get called again
     * after next_timeout microseconds, zero to continue the close.
     */
    int (*check_close)(void *handler_data, enum gensio_ll_close_state state,
		       struct timeval *next_timeout);

    void (*free)(void *handler_data);

    int (*control)(void *handler_data, int fd, unsigned int option,
		   void *auxdata);

    void (*read_ready)(void *handler_data, int fd);

    void (*write_ready)(void *handler_data, int fd);

    void (*except_ready)(void *handler_data, int fd);

    int (*write)(void *handler_data, int fd, unsigned int *count,
		 const unsigned char *buf, unsigned int buflen,
		 void *auxdata);
};

unsigned  gensio_fd_ll_callback(struct gensio_ll *ll, int op, int val,
				void *buf, unsigned int buflen, void *data);

struct gensio_ll *fd_gensio_ll_alloc(struct gensio_os_funcs *o,
				     int fd,
				     const struct gensio_fd_ll_ops *ops,
				     void *handler_data,
				     unsigned int max_read_size);


#endif /* GENSIO_LL_FD_H */
