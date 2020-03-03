/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_FILTER_TELNET_H
#define GENSIO_FILTER_TELNET_H

#include <gensio/gensio_base.h>

struct gensio_telnet_filter_callbacks {
    void (*got_sync)(void *handler_data);
    void (*got_cmd)(void *handler_data, unsigned char cmd);
    int (*com_port_will_do)(void *handler_data, unsigned char cmd);
    void (*com_port_cmd)(void *handler_data, const unsigned char *option,
			 unsigned int len);
    void (*timeout)(void *handler_data);
    void (*free)(void *handler_data);
};

struct gensio_telnet_filter_rops {
    void (*send_option)(struct gensio_filter *filter,
			const unsigned char *buf, unsigned int len);
    void (*send_cmd)(struct gensio_filter *filter,
		     const unsigned char *buf, unsigned int len);
    void (*start_timer)(struct gensio_filter *filter, gensio_time *timeout);
};

int gensio_telnet_filter_alloc(struct gensio_os_funcs *o,
			       const char * const args[],
			       bool default_is_client,
			       const struct gensio_telnet_filter_callbacks *cbs,
			       void *handler_data,
			       const struct gensio_telnet_filter_rops **rops,
			       struct gensio_filter **rfilter);

#endif /* GENSIO_FILTER_TELNET_H */
