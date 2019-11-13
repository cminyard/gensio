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
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

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
cmparg(int argc, char *argv[], int *arg, char *sarg, char *larg, char **opt)
{
    char *a = argv[*arg];

    if ((sarg && strcmp(a, sarg) == 0) || larg && strcmp(a, larg) == 0) {
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
    char *str;
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
checkout_file(const char *filename, bool expect_dir, bool check_private)
{
    struct stat sb;
    int rv;

    rv = stat(filename, &sb);
    if (rv == -1) {
	fprintf(stderr, "Unable to examine %s: %s\n",
		filename, strerror(errno));
	return errno;
    }

    if (sb.st_uid != getuid()) {
	fprintf(stderr, "You do not own %s, giving up\n", filename);
	return EPERM;
    }

    if (check_private && sb.st_mode & 077) {
	fprintf(stderr, "%s is accessible by others, giving up\n", filename);
	return EPERM;
    }

    if (expect_dir) {
	if (!S_ISDIR(sb.st_mode)) {
	    fprintf(stderr, "%s is not a directory\n", filename);
	    return EINVAL;
	}
    } else {
	if (!S_ISREG(sb.st_mode)) {
	    fprintf(stderr, "%s is not a regular file\n", filename);
	    return EINVAL;
	}
    }

    return 0;
}

bool
file_is_readable(char *filename)
{
    struct stat sb;
    int rv;

    rv = stat(filename, &sb);
    if (rv == -1)
	return false;

    if (!S_ISREG(sb.st_mode))
	return false;

    if (sb.st_uid == getuid()) {
	if (sb.st_mode & 0400)
	    return true;
    }
    if (sb.st_gid == getgid()) {
	if (sb.st_mode & 0040)
	    return true;
    }
    if (sb.st_mode & 0004)
	return true;

    return false;
}

static int
write_s_nl_addc(struct gensio *io, char *obuf, char c,
		gensiods *pos, gensiods len, struct timeval *timeout)
{
    int err = 0;

    obuf[(*pos)++] = c;
    if (*pos >= len) {
	err = gensio_write_s(io, NULL, obuf, len, timeout);
	*pos = 0;
    }
    return err;
}

static int
write_s_nl(struct gensio *io, const char *buf, gensiods len,
	   struct timeval *timeout)
{
    char buf2[100];
    gensiods i, j;
    int err;

    for (i = 0, j = 0; i < len; i++) {
	if (buf[i] == '\n') {
	    err = write_s_nl_addc(io, buf2, '\r', &j, sizeof(buf2), timeout);
	    if (err)
		break;
	}
	err = write_s_nl_addc(io, buf2, buf[i], &j, sizeof(buf2), timeout);
	if (err)
	    break;
    }
    if (!err && j)
	err = gensio_write_s(io, NULL, buf2, j, timeout);

    return err;
}

int
write_file_to_gensio(const char *filename, struct gensio *io,
		     struct gensio_os_funcs *o, struct timeval *timeout,
		     bool xlatnl)
{
    int err;
    int fd;
    char buf[100];
    int count;

    err = gensio_set_sync(io);
    if (err)
	return err;

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
	err = gensio_os_err_to_err(o, errno);
	goto out_unsync;
    }

    while (true) {
	count = read(fd, buf, sizeof(buf));
	if (count == -1) {
	    err = gensio_os_err_to_err(o, errno);
	    break;
	}
	if (count == 0)
	    break;
	if (xlatnl)
	    err = write_s_nl(io, buf, count, timeout);
	else
	    err = gensio_write_s(io, NULL, buf, count, timeout);
	if (err)
	    break;
    }

    close(fd);

 out_unsync:
    gensio_clear_sync(io);

    return err;
}

int
write_buf_to_gensio(const char *buf, gensiods len, struct gensio *io,
		    struct timeval *timeout, bool xlatnl)
{
    int err;

    err = gensio_set_sync(io);
    if (err)
	return err;

    if (xlatnl)
	err = write_s_nl(io, buf, len, timeout);
    else
	err = gensio_write_s(io, NULL, buf, len, timeout);

    gensio_clear_sync(io);

    return err;
}

int
write_str_to_gensio(const char *str, struct gensio *io,
		    struct timeval *timeout, bool xlatnl)
{
    return write_buf_to_gensio(str, strlen(str), io, timeout, xlatnl);
}

int
read_rsp_from_gensio(char *buf, gensiods *len, struct gensio *io,
		     struct timeval *timeout, bool echo)
{
    int err;
    gensiods pos = 0, count;
    gensiods size = *len;
    char c;

    err = gensio_set_sync(io);
    if (err)
	return err;

    while (true) {
	err = gensio_read_s(io, &count, &c, 1, timeout);
	if (err)
	    break;
	if (count == 0) {
	    err = GE_TIMEDOUT;
	    break;
	}
	if (c == '\r' || c == '\n')
	    break;
	if (c == '\b' || c == 0x7f) {
	    if (pos > 0)
		pos--;
	    if (echo)
		gensio_write_s(io, NULL, "\b \b", 3, timeout);
	    continue;
	}
	if (pos < size - 1) {
	    buf[pos++] = c;
	    if (echo)
		gensio_write_s(io, NULL, &c, 1, timeout);
	}
    }

    gensio_clear_sync(io);
    buf[pos] = '\0';
    *len = pos;

    return err;
}
