
/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _GENSIO_BASEN_PARMS_H
#define _GENSIO_BASEN_PARMS_H

#include <gensio/gensio_os_funcs.h>

struct gensio_base_parms {
    struct gensio_os_funcs *o;
    int drain_timeout;
};

void i_gensio_base_parms_set(struct gensio *io,
			     const struct gensio_base_parms *parms);

#endif /* _GENSIO_BASEN_PARMS_H */
