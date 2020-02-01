/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>

extern bool gensio_uucp_locking_enabled;

void uucp_rm_lock(char *devname);

/* returns 0=OK, -1=error (errno will be set), >0=pid of locking process */
int uucp_mk_lock(char *devname);
