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

#include "config.h"
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
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
alloc_vsprintf(const char *fmt, va_list va)
{
    va_list va2;
    int len;
    char c[1], *str;

    va_copy(va2, va);
    len = vsnprintf(c, 0, fmt, va);
    str = malloc(len + 1);
    if (str)
	vsnprintf(str, len + 1, fmt, va2);
    va_end(va2);
    return str;
}

char *
alloc_sprintf(const char *fmt, ...)
{
    va_list va;
    char *s;

    va_start(va, fmt);
    s = alloc_vsprintf(fmt, va);
    va_end(va);
    return s;
}

int
cmparg(int argc, char *argv[], int *arg, char *sarg, char *larg,
       const char **opt)
{
    char *a = argv[*arg];

    if ((sarg && strcmp(a, sarg) == 0) || (larg && strcmp(a, larg) == 0)) {
	if (!opt)
	    return 1;
	(*arg)++;
	if (*arg >= argc) {
	    fprintf(stderr, "No argument given for option %s\n", a);
	    return -1;
	}
	*opt = argv[*arg];
	return 1;
    } else if (larg && opt) {
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

int
cmparg_uint(int argc, char *argv[], int *arg, char *sarg, char *larg,
	    unsigned int *rc)
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
    v = strtoul(str, &end, 0);
    if (*end != '\0') {
	fprintf(stderr, "Invalid string given for character\n");
	return -1;
    }
    *rc = v;
    return 1;
}

bool
strstartswith(const char *str, const char *cmp)
{
    if (strncmp(str, cmp, strlen(cmp)) == 0)
	return true;
    return false;
}


#ifdef _WIN32
#include <windows.h>
bool
can_do_raw(void)
{
    DWORD mode;

    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
}
#endif
