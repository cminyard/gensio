/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_FILTER_PERF_H
#define GENSIO_FILTER_PERF_H

#include <gensio/gensio_base.h>

int gensio_perf_filter_alloc(struct gensio_os_funcs *o,
			     const char * const args[],
			     struct gensio_filter **rfilter);

#endif /* GENSIO_FILTER_PERF_H */
