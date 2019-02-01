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

#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"

int
strtocc(const char *str, int *rc)
{
    int c;

    if (!*str || str[1] != '\0') {
	fprintf(stderr, "Empty string for ^x\n");
	return -1;
    }
    c = toupper(str[0]);
    if (c < 'A' || c > '_') {
	fprintf(stderr, "Invalid character for ^x\n");
	return -1;
    }
    *rc = c - '@';
    return 1;
}

char *
alloc_sprintf(char *fmt, ...)
{
    va_list va, va2;
    int len;
    char c, *str;

    va_start(va, fmt);
    va_copy(va2, va);
    len = vsnprintf(&c, 0, fmt, va);
    va_end(va);
    str = malloc(len + 1);
    if (!str)
	return NULL;
    vsnprintf(str, len + 1, fmt, va2);
    va_end(va2);
    return str;
}

int
cmparg(int argc, char *argv[], int *arg, char *sarg, char *larg,
       const char **opt)
{
    char *a = argv[*arg];

    if (strcmp(a, sarg) == 0 || strcmp(a, larg) == 0) {
	if (!opt)
	    return 1;
	(*arg)++;
	if (*arg >= argc) {
	    fprintf(stderr, "No argument given for option %s\n", a);
	    return -1;
	}
	*opt = argv[*arg];
	return 1;
    } else {
	unsigned int len = strlen(larg);

	if (strncmp(a, larg, len) == 0 && a[len] == '=') {
	    *opt = a + len + 1;
	    return 1;
	}
    }

    return 0;
}

int
cmparg_int(int argc, char *argv[], int *arg, char *sarg, char *larg, int *rc)
{
    const char *str;
    char *end;
    int rv = cmparg(argc, argv, arg, sarg, larg, &str);
    long v;

    if (rv <= 0)
	return rv;
    if (!str[0]) {
	fprintf(stderr, "No string given for character\n");
	return -1;
    }
    if (str[0] == '^')
	return strtocc(str + 1, rc);
    v = strtol(str, &end, 0);
    if (*end != '\0') {
	fprintf(stderr, "Invalid string given for character\n");
	return -1;
    }
    *rc = v;
    return 1;
}
