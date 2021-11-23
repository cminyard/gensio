/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_UNIX_H
#define GENSIO_UNIX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

struct selector_s; /* Don't include selector.h to reduce namespace pollution. */

/*
 * Allocate a selector-based os funcs.
 *
 * If you pass in NULL for sel, this will allocate a selector along
 * with it.  The default thread model is chosen.  In this case the
 * selector allocated is freed when the os funcs are freed, since you
 * can't get to it :-).
 *
 * If you pass in a selector, it will not be freed when the os funcs
 * is freed.
 */
GENSIO_DLL_PUBLIC
int gensio_unix_funcs_alloc(struct selector_s *sel, int wake_sig,
			    struct gensio_os_funcs **ro);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_UNIX_H */
