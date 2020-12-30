/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>

#include <gensio/gensio.h>

void uucp_rm_lock(char *devname);

/* Returns gensio errno. */
int uucp_mk_lock(struct gensio_os_funcs *o, char *devname);
