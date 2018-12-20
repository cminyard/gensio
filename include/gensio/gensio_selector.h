/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.  These licenses are available
 *  in the root directory of this package named COPYING.LIB and
 *  COPYING.BSD, respectively.
 */

#ifndef GENSIO_SELECTOR_H
#define GENSIO_SELECTOR_H

#include <gensio/gensio.h>
#include <gensio/selector.h>

struct gensio_os_funcs *gensio_selector_alloc(struct selector_s *sel,
					      int wake_sig);

#endif /* GENSIO_SELECTOR_H */
