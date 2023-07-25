/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>

#include <gensio/gensio_os_funcs.h>

void serial_rm_lock(struct gensio_os_funcs *o,
		    bool do_uucp_lock, bool do_flock,
		    int fd, const char *devname);

/* Returns gensio errno. */
int serial_mk_lock(struct gensio_os_funcs *o,
		   bool do_uucp_lock, bool do_flock,
		   int fd, const char *devname);
