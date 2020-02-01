/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef UTILS
#define UTILS

#include <stdbool.h>
#include <sys/time.h> /* struct timeval */

#include <gensio/argvutils.h>

/*
 * Returns true if the first strlen(prefix) characters of s are the
 * same as prefix.  If true is returned, val is set to the character
 * after the last byte that compares.
 */
int cmpstrval(const char *s, const char *prefix, const char **val);

struct enum_val
{
    char *str;
    int val;
};

/*
 * Given an enum table (terminated by a NULL str entry), find the
 * given string in the table.  If "len" is not -1, use it to only
 * compare the first "len" chars of str.
 */
int lookup_enum(struct enum_val *enums, const char *str, int len);

/* Return -1 if tv1 < tv2, 0 if tv1 == tv2, and 1 if tv1 > tv2 */
int cmp_timeval(struct timeval *tv1, struct timeval *tv2);

/* Add tv2 to tv1 */
void add_to_timeval(struct timeval *tv1, struct timeval *tv2);

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
