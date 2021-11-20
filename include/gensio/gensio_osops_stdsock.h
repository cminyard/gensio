/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NOTE: DO NOT USE THIS IS APPLICATION CODE!
 *
 * This is only for use if you are creating your own OS handler and
 * using addrinfo based addresses and standard sockets.  If you use
 * this and the OS handler doesn't use addrinfo based addresses, bad
 * things will happen.
 */

#ifndef GENSIO_OSOPS_STDSOCK_H
#define GENSIO_OSOPS_STDSOCK_H

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>


/* Set up the osops with addrinfo based standard socket handling. */
GENSIO_DLL_PUBLIC
int gensio_stdsock_set_os_funcs(struct gensio_os_funcs *o);
GENSIO_DLL_PUBLIC
void gensio_stdsock_cleanup(struct gensio_os_funcs *o);

#endif /* GENSIO_OSOPS_STDSOCK_H */
