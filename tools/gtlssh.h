/*
 *  gensiotools - General tools using gensio
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef GTLSSH_H
#define GTLSSH_H
#include <gensio/gensio.h>

int checkout_file(const char *filename, bool expect_dir, bool check_private);
bool file_is_readable(char *filename);
int write_file_to_gensio(const char *filename, struct gensio *io,
			 struct gensio_os_funcs *o, gensio_time *timeout,
			 bool xlatnl);
int write_buf_to_gensio(const char *buf, gensiods len, struct gensio *io,
			gensio_time *timeout, bool xlatnl);
int write_str_to_gensio(const char *str, struct gensio *io,
			gensio_time *timeout, bool xlatnl);
int read_rsp_from_gensio(char *buf, gensiods *len, struct gensio *io,
			 gensio_time *timeout, bool echo);

#endif /* GENSIOTOOL_UTILS_H */
