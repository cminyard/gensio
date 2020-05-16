/*
 *  gensiotools - General tools using gensio
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef GENSIOTOOL_UTILS_H
#define GENSIOTOOL_UTILS_H
#include <stdarg.h>
#include <stdbool.h>

int strtocc(const char *str, int *rc);
int cmparg(int argc, char *argv[], int *arg, char *sarg, char *larg, char **opt);
int cmparg_int(int argc, char *argv[], int *arg, char *sarg,
		      char *larg, int *rc);
char *alloc_sprintf(const char *fmt, ...);
char *alloc_vsprintf(const char *fmt, va_list ap);

bool strstartswith(const char *str, const char *cmp);

#endif /* GENSIOTOOL_UTILS_H */
