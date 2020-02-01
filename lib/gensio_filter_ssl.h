/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_FILTER_SSL_H
#define GENSIO_FILTER_SSL_H

#include <gensio/gensio_base.h>

struct gensio_ssl_filter_data;

int gensio_ssl_filter_config(struct gensio_os_funcs *o,
			     const char * const args[],
			     bool default_is_client,
			     struct gensio_ssl_filter_data **data);

void gensio_ssl_filter_config_free(struct gensio_ssl_filter_data *data);

int gensio_ssl_filter_alloc(struct gensio_ssl_filter_data *data,
			    struct gensio_filter **rfilter);

#endif /* GENSIO_FILTER_SSL_H */
