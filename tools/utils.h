/*
 *  gensiotools - General tools using gensio
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef GENSIOTOOL_UTILS_H
#define GENSIOTOOL_UTILS_H
#include <stdarg.h>
#include <stdbool.h>
#include <gensio/gensio.h>

int strtocc(const char *str, int *rc);
int cmparg(int argc, char *argv[], int *arg, char *sarg, char *larg, char **opt);
int cmparg_int(int argc, char *argv[], int *arg, char *sarg,
		      char *larg, int *rc);
char *alloc_sprintf(const char *fmt, ...);
char *alloc_vsprintf(const char *fmt, va_list ap);
int checkout_file(const char *filename, bool expect_dir, bool check_private);
bool file_is_readable(char *filename);
int write_file_to_gensio(const char *filename, struct gensio *io,
			 struct gensio_os_funcs *o, struct timeval *timeout,
			 bool xlatnl);
int write_buf_to_gensio(const char *buf, gensiods len, struct gensio *io,
			struct timeval *timeout, bool xlatnl);
int write_str_to_gensio(const char *str, struct gensio *io,
			struct timeval *timeout, bool xlatnl);
int read_rsp_from_gensio(char *buf, gensiods *len, struct gensio *io,
			 struct timeval *timeout, bool echo);

bool strstartswith(const char *str, const char *cmp);

#endif /* GENSIOTOOL_UTILS_H */
