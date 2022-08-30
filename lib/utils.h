/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef UTILS
#define UTILS

#include <stdbool.h>
#include <gensio/gensio_os_funcs.h>

#include <gensio/argvutils.h>

#ifndef HAVE_STRCASECMP
int strcasecmp(const char *s1, const char *s2);
#endif
#ifndef HAVE_STRNCASECMP
int strncasecmp(const char *s1, const char *s2, int n);
#endif

struct enum_val
{
    char *str;
    int val;
};

#if ENABLE_PRBUF
#include <stdio.h>
static void prbuf(const unsigned char *buf, unsigned int len)
{
    unsigned int i;

    for (i = 0; i < len; i++) {
       if (i % 16 == 0)
           printf("\r\n");
       printf(" %2.2x", buf[i]);
    }
    printf("\r\n");
    fflush(stdout);
}
#endif

#endif /* UTILS */
