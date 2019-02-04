/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

/* This code handles running a child process using a pty. */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <pwd.h>
#include <sys/wait.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_osops.h>

struct pty_data {
    struct gensio_os_funcs *o;

    struct gensio_ll *ll;

    pid_t pid;
    int ptym;
    char *progargs;
    char **argv;

    int last_err;
};

static int pty_check_open(void *handler_data, int fd)
{
    return 0;
}

static int
pty_sub_open(void *handler_data, int *fd)
{
    struct pty_data *tdata = handler_data;
    int err;

    err = gensio_setup_child_on_pty(tdata->argv, &tdata->ptym, &tdata->pid);
    if (!err)
	*fd = tdata->ptym;

    return err;
}

static int
pty_raddr_to_str(void *handler_data, gensiods *epos,
		 char *buf, gensiods buflen)
{
    struct pty_data *tdata = handler_data;
    gensiods pos = 0;

    if (epos)
	pos = *epos;

    pos = snprintf(buf + pos, buflen - pos, "%s", tdata->progargs);
    if (epos)
	*epos = pos;
    return 0;
}

static int
pty_remote_id(void *handler_data, int *id)
{
    struct pty_data *tdata = handler_data;

    *id = tdata->pid;
    return 0;
}

static int
pty_check_close(void *handler_data, enum gensio_ll_close_state state,
		struct timeval *timeout)
{
    struct pty_data *tdata = handler_data;
    int wstatus;
    pid_t rv;

    if (state != GENSIO_LL_CLOSE_STATE_DONE)
	return 0;

    if (tdata->ptym != -1) {
	close(tdata->ptym);
	tdata->ptym = -1;
    }

    rv = waitpid(tdata->pid, &wstatus, WNOHANG);
    if (rv < 0)
	return errno;
    if (rv == 0) {
	timeout->tv_sec = 0;
	timeout->tv_usec = 10000;
	return EINPROGRESS;
    }
    return 0;
}

static void
pty_free(void *handler_data)
{
    struct pty_data *tdata = handler_data;

    if (tdata->argv) {
	int i;

	for (i = 0; tdata->argv[i]; i++)
	    tdata->o->free(tdata->o, tdata->argv[i]);
	tdata->o->free(tdata->o, tdata->argv);
    }

    tdata->o->free(tdata->o, tdata);
}

static int
pty_write(void *handler_data, int fd, gensiods *rcount,
	  const unsigned char *buf, gensiods buflen,
	  const char *const *auxdata)
{
    int rv = gensio_os_write(fd, buf, buflen, rcount);

    if (rv == EIO)
	rv = EPIPE; /* We don't seem to get EPIPE from ptys */
    return rv;
}

static int
pty_do_read(int fd, void *data, gensiods count, gensiods *rcount,
	    const char **auxdata, void *cb_data)
{
    int rv = gensio_os_read(fd, data, count, rcount);

    if (rv == EIO)
	rv = EPIPE; /* We don't seem to get EPIPE from ptys */
    return rv;
}

static void
pty_read_ready(void *handler_data, int fd)
{
    struct pty_data *tdata = handler_data;

    gensio_fd_ll_handle_incoming(tdata->ll, pty_do_read, NULL, NULL);
}

static const struct gensio_fd_ll_ops pty_fd_ll_ops = {
    .sub_open = pty_sub_open,
    .check_open = pty_check_open,
    .read_ready = pty_read_ready,
    .raddr_to_str = pty_raddr_to_str,
    .remote_id = pty_remote_id,
    .check_close = pty_check_close,
    .free = pty_free,
    .write = pty_write
};

int
pty_gensio_alloc(const char * const argv[], const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
    struct pty_data *tdata = NULL;
    struct gensio *io;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    unsigned int i, argc;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata)
	return ENOMEM;

    tdata->o = o;
    tdata->ptym = -1;

    for (argc = 0; argv[argc]; argc++)
	;
    tdata->argv = o->zalloc(o, (argc + 1) * sizeof(*tdata->argv));
    if (!tdata->argv)
	goto out_nomem;
    for (i = 0; i < argc; i++) {
	tdata->argv[i] = gensio_strdup(o, argv[i]);
	if (!tdata->argv[i])
	    goto out_nomem;
    }

    tdata->ll = fd_gensio_ll_alloc(o, -1, &pty_fd_ll_ops, tdata, max_read_size);
    if (!tdata->ll)
	goto out_nomem;

    io = base_gensio_alloc(o, tdata->ll, NULL, NULL, "pty", cb, user_data);
    if (!io) {
	gensio_ll_free(tdata->ll);
	goto out_nomem;
    }
    gensio_set_is_reliable(io, true);

    *new_gensio = io;
    return 0;

 out_nomem:
    pty_free(tdata);
    return ENOMEM;
}

int
str_to_pty_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    int err, argc;
    const char **argv;

    err = str_to_argv(str, &argc, &argv, NULL);
    if (!err) {
	err = pty_gensio_alloc(argv, args, o, cb, user_data, new_gensio);
	str_to_argv_free(argv);
    }

    return err;
}
