/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_SELECTOR_H
#define GENSIO_SELECTOR_H

#include <gensio/gensio_dllvisibility.h>

struct selector_s; /* Don't include selector.h to reduce namespace pollution. */

/*
 * DEPRECATED.
 *
 * Same as gensio_unix_func_alloc(), use that function instead.  This
 * is here for backwards compatibility.
 */
GENSIO_DLL_PUBLIC
struct gensio_os_funcs *gensio_selector_alloc(struct selector_s *sel,
					      int wake_sig);

#endif /* GENSIO_SELECTOR_H */
