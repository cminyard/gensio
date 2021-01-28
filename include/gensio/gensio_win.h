/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_WIN_H
#define GENSIO_WIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_os_funcs.h>

/*
 * Allocate a windows os funcs.
 */
GENSIO_DLL_PUBLIC
struct gensio_os_funcs *gensio_win_funcs_alloc(void);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_WIN_H */
