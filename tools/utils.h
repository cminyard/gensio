/*
 *  gensiotools - General tools using gensio
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  gensio give you permission to combine gensio with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for gensio and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of gensio are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
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
int cmparg_uint(int argc, char *argv[], int *arg, char *sarg,
	        char *larg, unsigned int *rc);
char *alloc_sprintf(const char *fmt, ...);
char *alloc_vsprintf(const char *fmt, va_list ap);

bool strstartswith(const char *str, const char *cmp);

#if defined(_WIN32)
bool can_do_raw(void);
#elif defined(HAVE_ISATTY)
# include <unistd.h>
# define can_do_raw() isatty(0)
#else
# define can_do_raw() false
#endif

#endif /* GENSIOTOOL_UTILS_H */
