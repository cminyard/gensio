/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_FILTER_RELPKT_H
#define GENSIO_FILTER_RELPKT_H

#include <gensio/gensio_base.h>

int gensio_relpkt_filter_alloc(struct gensio_os_funcs *o,
			       const char * const args[],
			       bool default_is_server,
			       struct gensio_filter **rfilter);

#endif /* GENSIO_FILTER_RELPKT_H */
