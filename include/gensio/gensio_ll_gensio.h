/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_LL_GENSIO_H
#define GENSIO_LL_GENSIO_H

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_base.h>

GENSIO_DLL_PUBLIC
struct gensio_ll *gensio_gensio_ll_alloc(struct gensio_os_funcs *o,
					 struct gensio *child);

#endif /* GENSIO_LL_GENSIO_H */
