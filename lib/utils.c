/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include <gensio/gensio_class.h>
#include "utils.h"

char *
gensio_strdup(struct gensio_os_funcs *o, const char *str)
{
    char *s;

    if (!str)
	return NULL;

    s = o->zalloc(o, strlen(str) + 1);
    if (!s)
	return NULL;
    strcpy(s, str);
    return s;
}

int
cmpstrval(const char *s, const char *prefix, const char **val)
{
    size_t len = strlen(prefix);

    if (strncmp(s, prefix, len))
	return 0;
    *val = s + len;

    return 1;
}

int
gensio_argv_copy(struct gensio_os_funcs *o,
		 const char * const oargv[],
		 int *r_argc, const char ***r_argv)
{
    unsigned int len;
    const char **argv;

    for (len = 0; oargv[len]; len++)
	;
    argv = o->zalloc(o, (len + 1) * sizeof(*argv));
    if (!argv)
	return GE_NOMEM;
    for (len = 0; oargv[len]; len++) {
	argv[len] = gensio_strdup(o, oargv[len]);
	if (!argv[len])
	    goto out_nomem;
    }
    argv[len] = NULL;
    if (r_argc)
	*r_argc = len;
    *r_argv = argv;
    return 0;

 out_nomem:
    while (len > 0) {
	len--;
	o->free(o, (void *) argv[len]);
    }
    o->free(o, argv);
    return GE_NOMEM;
}

void
gensio_argv_free(struct gensio_os_funcs *o,
		 const char **argv)
{
    unsigned int i;

    if (!argv)
	return;
    for (i = 0; argv[i]; i++)
	o->free(o, (void *) argv[i]);
    o->free(o, argv);
}

static bool
is_sep(char c, const char *seps)
{
    return c && strchr(seps, c);
}

static const char *
skip_seps(const char *s, const char *seps)
{
    while (is_sep(*s, seps))
	s++;
    return s;
}

static bool
isodigit(char c)
{
    return isdigit(c) && c != '8' && c != '9';
}

static void
set_out(char **o, char s, unsigned int *len)
{
    if (*o) {
	**o = s;
	(*o)++;
    }
    (*len)++;
}

static int
gettok(struct gensio_os_funcs *o,
       const char **s, char **tok, const char *seps, const char *endchars)
{
    const char *p = skip_seps(*s, seps);
    const char *t = p;
    char *out = NULL;
    char inquote = '\0';
    unsigned int escape = 0;
    unsigned int base = 8;
    char cval = 0;
    unsigned int len = 0;

    if (!*p || strchr(endchars, *p)) {
	*s = p;
	*tok = NULL;
	return 0;
    }

 restart:
    for (; *p; p++) {
	if (escape) {
	    if (escape == 1) {
		cval = 0;
		if (isodigit(*p)) {
		    base = 8;
		    cval = *p - '0';
		    escape++;
		} else if (*p == 'x') {
		    base = 16;
		    escape++;
		} else {
		    switch (*p) {
		    case 'a': set_out(&out, '\a', &len); break;
		    case 'b': set_out(&out, '\b', &len); break;
		    case 'f': set_out(&out, '\f', &len); break;
		    case 'n': set_out(&out, '\n', &len); break;
		    case 'r': set_out(&out, '\r', &len); break;
		    case 't': set_out(&out, '\t', &len); break;
		    case 'v': set_out(&out, '\v', &len); break;
		    default:  set_out(&out, *p, &len);
		    }
		    escape = 0;
		}
	    } else if (escape >= 2) {
		if ((base == 16 && isxdigit(*p)) || isodigit(*p)) {
		    if (isodigit(*p))
			cval = cval * base + *p - '0';
		    else if (isupper(*p))
			cval = cval * base + *p - 'A';
		    else
			cval = cval * base + *p - 'a';
		    if (escape >= 3) {
			set_out(&out, cval, &len);
			escape = 0;
		    } else {
			escape++;
		    }
		} else {
		    set_out(&out, cval, &len);
		    escape = 0;
		    goto process_char;
		}
	    }
	    continue;
	}
    process_char:
	if (*p == inquote) {
	    inquote = '\0';
	} else if (!inquote && (*p == '\'' || *p == '"')) {
	    inquote = *p;
	} else if (*p == '\\') {
	    escape = 1;
	} else if (!inquote) {
	    if (is_sep(*p, seps)) {
		p++;
		break;
	    } else if (strchr(endchars, *p)) {
		/* Don't skip endchars. */
		break;
	    } else {
		set_out(&out, *p, &len);
	    }
	} else {
	    set_out(&out, *p, &len);
	}
    }

    if ((base == 8 && escape > 1) || (base == 16 && escape > 2)) {
	set_out(&out, cval, &len);
	escape = 0;
    }

    if (inquote || escape)
	return GE_INVAL;

    if (!out) {
	out = o->zalloc(o, len + 1);
	if (!out)
	    return GE_NOMEM;
	*tok = out;
	len = 0;
	p = t;
	goto restart;
    }

    *s = p;
    *out = '\0';

    return 0;
}

int
gensio_str_to_argv_endchar(struct gensio_os_funcs *o,
			   const char *ins, int *r_argc, const char ***r_argv,
			   const char *seps, const char *endchars,
			   const char **nextptr)
{
    const char **argv = NULL;
    char *tok = NULL;
    unsigned int argc = 0;
    unsigned int args = 0;
    int err;

    if (!seps)
	seps = " \f\n\r\t\v";

    if (!endchars)
	endchars = "";

    args = 10;
    argv = o->zalloc(o, sizeof(*argv) * args);
    if (!argv)
	return GE_NOMEM;

    err = gettok(o, &ins, &tok, seps, endchars);
    while (tok && !err) {
	/* - 1 leaves a space for the NULL terminator. */
	if (argc >= args - 1) {
	    const char **nargv;

	    args += 10;
	    nargv = realloc(argv, sizeof(*argv) * args);
	    if (!nargv) {
		err = GE_NOMEM;
		goto out;
	    }
	    argv = nargv;
	}
	argv[argc++] = tok;

	err = gettok(o, &ins, &tok, seps, endchars);
    }

    argv[argc] = NULL; /* NULL terminate the array. */

 out:
    if (err) {
	while (argc > 0) {
	    argc--;
	    o->free(o, (void *) argv[argc]);
	}
	o->free(o, argv);
    } else {
	if (r_argc)
	    *r_argc = argc;
	*r_argv = argv;
	if (nextptr) {
	    if (*ins)
		ins++;
	    *nextptr = ins;
	}
    }
    return err;
}

int
gensio_str_to_argv(struct gensio_os_funcs *o,
		   const char *ins, int *r_argc, const char ***r_argv,
		   const char *seps)
{
    return gensio_str_to_argv_endchar(o, ins, r_argc, r_argv, seps, NULL, NULL);
}

int
lookup_enum(struct enum_val *enums, const char *str, size_t len)
{
    while (enums->str != NULL) {
	if (len == -1 && strcmp(enums->str, str) == 0)
	    return enums->val;
	if (strlen(enums->str) == len && strncmp(enums->str, str, len) == 0)
	    return enums->val;
	enums++;
    }
    return -1;
}

int
cmp_timeval(struct timeval *tv1, struct timeval *tv2)
{
    if (tv1->tv_sec > tv2->tv_sec)
	return 1;
    else if (tv1->tv_sec < tv2->tv_sec)
	return -1;
    else if (tv1->tv_usec > tv2->tv_usec)
	return 1;
    else if (tv1->tv_usec < tv2->tv_usec)
	return -1;
    else
	return 0;
}

void
add_to_timeval(struct timeval *tv1, struct timeval *tv2)
{
    tv1->tv_sec += tv2->tv_sec;
    tv1->tv_usec += tv2->tv_usec;
    while (tv1->tv_usec > 1000000) {
	tv1->tv_usec -= 1000000;
	tv1->tv_sec += 1;
    }
    while (tv1->tv_usec < 0) {
	tv1->tv_usec += 1000000;
	tv1->tv_sec -= 1;
    }
}

#ifndef HAVE_STRCASECMP
int
strcasecmp(const char *s1, const char *s2)
{
    while (s1 && s2) {
	char c1 = tolower(*s1);
	char c2 = tolower(*s2);

	if (c1 < c2)
	    return -1;
	if (c1 > c2)
	    return 1;

	if (!c1 || !c2)
	    break;

	s1++;
	s2++;
    }
    return 0;
}
#endif

#ifndef HAVE_STRNCASECMP
int
strncasecmp(const char *s1, const char *s2, int n)
{
    while (s1 && s2 && n) {
	char c1 = tolower(*s1);
	char c2 = tolower(*s2);

	if (c1 < c2)
	    return -1;
	if (c1 > c2)
	    return 1;

	if (!c1 || !c2)
	    break;

	s1++;
	s2++;
	n--;
    }
    return 0;
}
#endif
