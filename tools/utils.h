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

int strtocc(const char *str, int *rc);
int cmparg(int argc, char *argv[], int *arg, char *sarg, char *larg,
		  const char **opt);
int cmparg_int(int argc, char *argv[], int *arg, char *sarg,
		      char *larg, int *rc);
char *alloc_sprintf(const char *fmt, ...);
char *alloc_vsprintf(const char *fmt, va_list ap);
int checkout_file(const char *filename, bool expect_dir);

#endif /* GENSIOTOOL_UTILS_H */
