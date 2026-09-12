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

/*
 * Like the above, but separate gensio children for input and output.
 * If you pass in NULL for out_child, it calls
 * gensio_gensio_ll_alloc() with in_child.
 *
 * If discard is set, input is turned on in the output child and
 * any received data is discarded.
 */
GENSIO_DLL_PUBLIC
struct gensio_ll *gensio_2gensio_ll_alloc(struct gensio_os_funcs *o,
					  struct gensio *in_child,
					  struct gensio *out_child,
					  bool discard);

#endif /* GENSIO_LL_GENSIO_H */
