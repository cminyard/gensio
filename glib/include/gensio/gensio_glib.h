/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_GLIB_H
#define GENSIO_GLIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gensio/gensio_glib_dllvisibility.h>
#include <gensio/gensio_types.h>

/*
 * Allocate a glib-based os funcs.
 */
GENSIOGLIB_DLL_PUBLIC
int gensio_glib_funcs_alloc(struct gensio_os_funcs **o);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_GLIB_H */
