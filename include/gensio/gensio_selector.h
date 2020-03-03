/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_SELECTOR_H
#define GENSIO_SELECTOR_H

#include <gensio/gensio.h>
#include <gensio/selector.h>

/*
 * Allocate a selector-based os funcs.  Noe that the selector will
 * *not* be freed when the os funcs are freed, you must do that if
 * necessary.
 */
struct gensio_os_funcs *gensio_selector_alloc_sel(struct selector_s *sel,
						  int wake_sig);

/*
 * Allcoate a selector-based os funcs, allocating a selector along
 * with it.  The default thread model is chosen.  The selector
 * allocated is freed when the os funcs are freed, since you can't get
 * to it :-).
 */
struct gensio_os_funcs *gensio_selector_alloc(int wake_sig);

/* For testing, do not use in normal code. */
void gensio_sel_exit(int rv);

#endif /* GENSIO_SELECTOR_H */
