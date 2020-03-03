/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
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
     * GENSIO_LL_CLOSE_STATE_DONE, return EINPROGRESS to get called again
     * after next_timeout microseconds, zero to continue the close.
     */
    int (*check_close)(void *handler_data, enum gensio_ll_close_state state,
		       gensio_time *next_timeout);

    void (*free)(void *handler_data);

    int (*control)(void *handler_data, int fd, bool get, unsigned int option,
		   char *data, gensiods *datalen);

    void (*read_ready)(void *handler_data, int fd);

    void (*write_ready)(void *handler_data, int fd);

    void (*except_ready)(void *handler_data, int fd);

    int (*write)(void *handler_data, int fd, gensiods *count,
		 const struct gensio_sg *sg, gensiods sglen,
		 const char *const *auxdata);
};

gensiods gensio_fd_ll_callback(struct gensio_ll *ll, int op, int val,
			       void *buf, gensiods buflen, void *data);

void gensio_fd_ll_handle_incoming(struct gensio_ll *ll,
				  int (*doread)(int fd, void *buf,
						gensiods count,
						gensiods *rcount,
						const char **auxdata,
						void *cb_data),
				  const char **auxdata,
				  void *cb_data);

struct gensio_ll *fd_gensio_ll_alloc(struct gensio_os_funcs *o,
				     int fd,
				     const struct gensio_fd_ll_ops *ops,
				     void *handler_data,
				     gensiods max_read_size,
				     bool write_only);


#endif /* GENSIO_LL_FD_H */
