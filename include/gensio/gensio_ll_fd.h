/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
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

    int (*raddr_to_str)(void *handler_data, gensiods *pos,
			char *buf, gensiods buflen);

    int (*get_raddr)(void *handler_data, void *addr, gensiods *addrlen);

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

    int (*control)(void *handler_data, int fd, bool get, unsigned int option,
		   char *data, gensiods *datalen);

    void (*read_ready)(void *handler_data, int fd);

    void (*write_ready)(void *handler_data, int fd);

    void (*except_ready)(void *handler_data, int fd);

    int (*write)(void *handler_data, int fd, gensiods *count,
		 const unsigned char *buf, gensiods buflen,
		 const char *const *auxdata);
};

gensiods gensio_fd_ll_callback(struct gensio_ll *ll, int op, int val,
			       void *buf, gensiods buflen, void *data);

void gensio_fd_ll_handle_incoming(struct gensio_ll *ll,
				  ssize_t (*doread)(int fd, void *buf,
						    size_t count,
						    const char **auxdata,
						    void *cb_data),
				  const char **auxdata,
				  void *cb_data);

struct gensio_ll *fd_gensio_ll_alloc(struct gensio_os_funcs *o,
				     int fd,
				     const struct gensio_fd_ll_ops *ops,
				     void *handler_data,
				     gensiods max_read_size);


#endif /* GENSIO_LL_FD_H */
