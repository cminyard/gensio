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

#include <stdbool.h>

extern bool gensio_uucp_locking_enabled;

void uucp_rm_lock(char *devname);

/* returns 0=OK, -1=error (errno will be set), >0=pid of locking process */
int uucp_mk_lock(char *devname);
