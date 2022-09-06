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
#include <assert.h>
#include <ctype.h>

#include <gensio/gensio.h>
#include <gensio/gensio_list.h>
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

char *
gensio_strndup(struct gensio_os_funcs *o, const char *str, gensiods len)
{
    char *s;
    gensiods slen = strlen(str);

    if (len > slen)
	len = slen;

    s = o->zalloc(o, len + 1);
    if (!s)
	return NULL;
    memcpy(s, str, len);
    return s;
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
    o->free(o, (void *) argv);
    return GE_NOMEM;
}

int
gensio_argv_append(struct gensio_os_funcs *o, const char ***argv,
		   const char *str, gensiods *args, gensiods *argc,
		   bool allocstr)
{
    if (!*argv) {
	*args = 10;
	*argc = 0;
	*argv = o->zalloc(o, *args * sizeof(char *));
	if (!*argv)
	    return GE_NOMEM;
    }
    /* + 1 to leave room for the ending NULL. */
    if (*argc + 1 >= *args) {
	const char **nargv;

	nargv = o->zalloc(o, sizeof(char *) * (*args + 10));
	if (!nargv)
	    return GE_NOMEM;
	memcpy((void *) nargv, *argv, sizeof(char *) * *args);
	o->free(o, (void *) *argv);
	*argv = nargv;
	*args += 10;
    }
    if (str) {
	if (allocstr) {
	    (*argv)[*argc] = gensio_strdup(o, str);
	    if (!(*argv)[*argc])
		return GE_NOMEM;
	} else {
	    (*argv)[*argc] = str;
	}
	(*argc)++;
    } else {
	(*argv)[*argc] = NULL;
    }
    return 0;
}

int
gensio_argv_vappend(struct gensio_os_funcs *o, const char ***argv,
		    gensiods *args, gensiods *argc, const char *fmt,
		    va_list ap)
{
    int err;
    char *s;

    s = gensio_alloc_vsprintf(o, fmt, ap);
    if (!s)
	return GE_NOMEM;
    err = gensio_argv_append(o, argv, s, args, argc, false);
    if (err)
	o->free(o, s);

    return err;
}

int
gensio_argv_sappend(struct gensio_os_funcs *o, const char ***argv,
		    gensiods *args, gensiods *argc, const char *fmt, ...)
{
    va_list ap;
    int err;

    va_start(ap, fmt);
    err = gensio_argv_vappend(o, argv, args, argc, fmt, ap);
    va_end(ap);

    return err;
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
    o->free(o, (void *) argv);
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
		    if (isdigit(*p))
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
    gensiods argc = 0;
    gensiods args = 0;
    int err;

    if (!seps)
	seps = " \f\n\r\t\v";

    if (!endchars)
	endchars = "";

    err = gettok(o, &ins, &tok, seps, endchars);
    while (tok && !err) {
	err = gensio_argv_append(o, &argv, tok, &args, &argc, false);
	if (err)
	    goto out;
	tok = NULL;
	err = gettok(o, &ins, &tok, seps, endchars);
    }

    /* NULL terminate the array. */
    if (!err)
	err = gensio_argv_append(o, &argv, NULL, &args, &argc, false);

 out:
    if (err) {
	if (tok)
	    o->free(o, tok);
	if (argv) {
	    while (argc > 0) {
		argc--;
		o->free(o, (void *) argv[argc]);
	    }
	    o->free(o, (void *) argv);
	}
    } else {
	if (r_argc)
	    *r_argc = argc;
	*r_argv = argv;
	if (nextptr)
	    *nextptr = ins;
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
gensio_scan_args(struct gensio_os_funcs *o,
		 const char **rstr, int *argc, const char ***args)
{
    const char *str = *rstr;
    int err = 0;

    if (*str == '(') {
	err = gensio_str_to_argv_endchar(o, str + 1, argc, args,
					 " \f\n\r\t\v,", ")", &str);
	if (!err) {
	    if (*str != ')') {
		err = GE_INVAL; /* Didn't end in ')'. */
	    } else {
		str++;
		if (*str != ',' && *str)
		    err = GE_INVAL; /* Not a ',' or end of string after */
		else if (*str)
		    str++;
	    }
	}
    } else {
	if (*str)
	    str += 1; /* skip the comma */
	err = gensio_str_to_argv(o, "", argc, args, ")");
    }

    if (!err)
	*rstr = str;

    return err;
}

int
gensio_time_cmp(gensio_time *t1, gensio_time *t2)
{
    if (t1->secs < t2->secs)
	return -1;

    if (t1->secs > t2->secs)
	return 1;

    if (t1->nsecs < t2->nsecs)
	return -1;

    if (t1->nsecs > t2->nsecs)
	return 1;

    return 0;
}

bool
gensio_str_in_auxdata(const char *const *auxdata, const char *str)
{
    unsigned int i;

    if (!auxdata)
	return false;
    for (i = 0; auxdata[i]; i++) {
	if (strcmp(auxdata[i], str) == 0)
	    return true;
    }
    return false;
}

uint32_t
gensio_buf_to_u32(unsigned char *data)
{
    return (data[0] << 24 |
	    data[1] << 16 |
	    data[2] << 8 |
	    data[3]);
}

void
gensio_u32_to_buf(unsigned char *data, uint32_t v)
{
    data[0] = v >> 24;
    data[1] = v >> 16;
    data[2] = v >> 8;
    data[3] = v;
}

uint16_t
gensio_buf_to_u16(unsigned char *data)
{
    return (data[0] << 8 | data[1]);
}

void
gensio_u16_to_buf(unsigned char *data, uint16_t v)
{
    data[0] = v >> 8;
    data[1] = v;
}

gensiods
gensio_pos_snprintf(char *buf, gensiods len, gensiods *pos, char *format, ...)
{
    va_list ap;
    int rv;
    gensiods size = len;
    gensiods lpos = 0;

    if (!pos)
	pos = &lpos;
    if (*pos > len) {
	/*
	 * If we are past the end of buffer, go to the end and don't
	 * output anything, just get the return from vsnprintf().
	 */
	size = 0;
	buf += len;
    } else {
	size = len - *pos;
	buf += *pos;
    }

    va_start(ap, format);
    rv = vsnprintf(buf, size, format, ap);
    va_end(ap);
    *pos += rv;
    return rv;
}

static gensiods
gensio_quote_str(char *buf, gensiods len, gensiods *pos, const char *arg)
{
    gensiods olen = 0;

    olen = gensio_pos_snprintf(buf, len, pos, "\"");
    while (*arg) {
	if (*arg == '"')
	    olen += gensio_pos_snprintf(buf, len, pos, "\\\"");
	else if (*arg == '\\')
	    olen += gensio_pos_snprintf(buf, len, pos, "\\\\");
	else
	    olen += gensio_pos_snprintf(buf, len, pos, "%c", *arg);
	arg++;
    }
    olen += gensio_pos_snprintf(buf, len, pos, "\"");

    if (*pos < len)
	buf[*pos] = '\0';

    return olen;
}

gensiods
gensio_argv_snprintf(char *buf, gensiods len, gensiods *pos, const char **argv)
{
    gensiods olen = 0;
    bool first = true;
    gensiods lpos = 0;

    if (!pos)
	pos = &lpos;
    while (argv && *argv) {
	if (!first) {
	    olen += gensio_pos_snprintf(buf, len, pos, " ");
	} else {
	    first = false;
	}

	olen += gensio_quote_str(buf, len, pos, *argv);
	argv++;
    }

    if (*pos < len)
	buf[*pos] = '\0';

    return olen;
}

char *
gensio_alloc_vsprintf(struct gensio_os_funcs *o, const char *fmt, va_list va)
{
    va_list va2;
    size_t len;
    char c[1], *str;

    va_copy(va2, va);
    len = (size_t) vsnprintf(c, 0, fmt, va) + 1L;
    str = o->zalloc(o, len);
    if (str)
	vsnprintf(str, len, fmt, va2);
    va_end(va2);

    return str;
}

char *
gensio_alloc_sprintf(struct gensio_os_funcs *o, const char *fmt, ...)
{
    va_list va;
    char *s;

    va_start(va, fmt);
    s = gensio_alloc_vsprintf(o, fmt, va);
    va_end(va);

    return s;
}

char *
gensio_quote_string(struct gensio_os_funcs *o, const char *str)
{
    const char *ic;
    char *ostr, *oc;
    gensiods count = 3; /* Space for two quotes and a \0. */

    /* We need two characters for all \ and ". */
    for (ic = str; *ic; ic++) {
	count++;
	if (*ic == '\\' || *ic == '"')
	    count++;
    }

    ostr = o->zalloc(o, count);
    if (!ostr)
	return NULL;

    oc = ostr;
    *oc++ = '"';
    for (ic = str; *ic; ic++) {
	if (*ic == '\\' || *ic == '"')
	    *oc++ = '\\';
	*oc++ = *ic;
    }
    *oc++ = '"';

    return ostr;
}

static const char *gensio_errs[] = {
    /*   0 */    "No error",
    /*   1 */    "Out of memory",
    /*   2 */    "Operation not supported",
    /*   3 */    "Invalid data to parameter",
    /*   4 */    "Value or file not found",
    /*   5 */    "Value already exists",
    /*   6 */    "Value out of range",
    /*   7 */    "Parameters inconsistent in call",
    /*   8 */    "No data was available for the function",
    /*   9 */	 "OS error, see logs",
    /*  10 */    "Object was already in use",
    /*  11 */    "Operation is in progress",
    /*  12 */    "Object was not ready for operation",
    /*  13 */    "Value was too large for data",
    /*  14 */    "Operation timed out",
    /*  15 */    "Retry operation later",
    /*  16 */    "Invalid error number 1",
    /*  17 */    "Unable to find the given key",
    /*  18 */    "Key was revoked",
    /*  19 */    "Key was expired",
    /*  20 */    "Key is not valid",
    /*  21 */    "Certificate not provided",
    /*  22 */    "Certificate is not valid",
    /*  23 */    "Protocol error",
    /*  24 */    "Communication error",
    /*  25 */    "Internal I/O error",
    /*  26 */    "Remote end closed connection",
    /*  27 */    "Host could not be reached",
    /*  28 */    "Connection refused",
    /*  29 */    "Data was missing",
    /*  30 */    "Unable to find given certificate",
    /*  31 */    "Authentication tokens rejected",
    /*  32 */    "Address already in use",
    /*  33 */    "Operation was interrupted by a signal",
    /*  34 */    "Operation on shutdown fd",
    /*  35 */    "Local end closed connection",
    /*  36 */    "Permission denied",
    /*  37 */    "Application error",
    /*  38 */	 "Unknown name server lookup failure",
    /*  39 */	 "Unable to find a valid name on the name server",
    /*  40 */	 "Serious name server failure",
    /*  41 */	 "Invalid name server information",
    /*  42 */	 "Network address for the given name is not available"
};
const unsigned int errno_len = sizeof(gensio_errs) / sizeof(char *);

const char *
gensio_err_to_str(int err)
{
    if (err < 0 || err >= errno_len)
	return "Unknown error";
    return gensio_errs[err];
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

void
gensio_list_rm(struct gensio_list *list, struct gensio_link *link)
{
    assert(link->list == list);
    link->next->prev = link->prev;
    link->prev->next = link->next;
    link->next = NULL;
    link->prev = NULL;
    link->list = NULL;
}

void
gensio_list_add_head(struct gensio_list *list, struct gensio_link *link)
{
    assert(link->list == NULL && link->next == NULL && link->prev == NULL);
    link->next = list->link.next;
    link->prev = &list->link;
    list->link.next->prev = link;
    list->link.next = link;
    link->list = list;
}

void
gensio_list_add_tail(struct gensio_list *list, struct gensio_link *link)
{
    assert(link->list == NULL && link->next == NULL && link->prev == NULL);
    link->prev = list->link.prev;
    link->next = &list->link;
    list->link.prev->next = link;
    list->link.prev = link;
    link->list = list;
}

void
gensio_list_add_next(struct gensio_list *list, struct gensio_link *curr,
		     struct gensio_link *link)
{
    assert(link->list == NULL && link->next == NULL && link->prev == NULL);
    link->next = curr->next;
    link->prev = curr;
    curr->next->prev = link;
    curr->next = link;
    link->list = list;
}

void
gensio_list_add_prev(struct gensio_list *list, struct gensio_link *curr,
		     struct gensio_link *link)
{
    assert(link->list == NULL && link->next == NULL && link->prev == NULL);
    link->prev = curr->prev;
    link->next = curr;
    curr->prev->next = link;
    curr->prev = link;
    link->list = list;
}

void
gensio_list_init(struct gensio_list *list)
{
    list->link.next = &list->link;
    list->link.prev = &list->link;
    list->link.list = list;
}

bool
gensio_list_empty(struct gensio_list *list)
{
    return list->link.next == &list->link;
}

static unsigned int gensio_log_mask =
    (1 << GENSIO_LOG_FATAL) | (1 << GENSIO_LOG_ERR);

void
gensio_set_log_mask(unsigned int mask)
{
    gensio_log_mask = mask;
}

unsigned int
gensio_get_log_mask(void)
{
    return gensio_log_mask;
}

void
gensio_vlog(struct gensio_os_funcs *o, enum gensio_log_levels level,
	    const char *str, va_list args)
{
    if (!(gensio_log_mask & (1 << level)))
	return;

    if (o->vlog)
	o->vlog(o, level, str, args);
}

void
gensio_log(struct gensio_os_funcs *o, enum gensio_log_levels level,
	   const char *str, ...)
{
    va_list args;

    va_start(args, str);
    gensio_vlog(o, level, str, args);
    va_end(args);
}

const char *
gensio_log_level_to_str(enum gensio_log_levels level)
{
    switch (level) {
    case GENSIO_LOG_FATAL: return "fatal"; break;
    case GENSIO_LOG_ERR: return "err"; break;
    case GENSIO_LOG_WARNING: return "warning"; break;
    case GENSIO_LOG_INFO: return "info"; break;
    case GENSIO_LOG_DEBUG: return "debug"; break;
    default: return "invalid";
    }
}
