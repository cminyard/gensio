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

#define _POSIX_C_SOURCE 200112L /* Get addrinfo and friends. */
#define _XOPEN_SOURCE 600 /* Get posix_openpt() and friends. */
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
#include <termios.h>
#include <sys/ioctl.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/argvutils.h>

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
setup_child_on_pty(char *const argv[], int *rptym, pid_t *rpid)
{
    pid_t pid;
    int ptym, err = 0;

    ptym = posix_openpt(O_RDWR | O_NOCTTY);
    if (ptym == -1)
	return errno;

    if (unlockpt(ptym) < 0) {
	err = errno;
	close(ptym);
	return err;
    }

    pid = fork();
    if (pid < 0) {
	err = errno;
	close(ptym);
	return err;
    }

    if (pid == 0) {
	/*
	 * Delay getting the slave until here becase ptsname is not
	 * thread-safe, but after the fork we are single-threaded.
	 */
	char *slave = ptsname(ptym);
	int i, openfiles = sysconf(_SC_OPEN_MAX);
	int fd;

	/* Set the owner of the slave PT. */
	/* FIXME - This should not be necessary, can we remove? */
	if (grantpt(ptym) < 0)
	    exit(1);

	fd = open("/dev/tty", O_RDWR);
	if (fd == -1) {
	    fprintf(stderr, "pty fork: Unable to open /dev/tty: %s\n",
		    strerror(errno));
	    exit(1);
	}
	ioctl(fd, TIOCNOTTY, NULL);
	close(fd);

	fd = open("/dev/tty", O_RDWR);
	if (fd != -1) {
	    fprintf(stderr, "pty fork: failed to drop control term: %s\n",
		    strerror(errno));
	    exit(1);
	}

	if (setsid() == -1) {
	    fprintf(stderr, "pty fork: failed to start new session: %s\n",
		    strerror(errno));
	    exit(1);
	}

#if 0 /* FIXME = do we need this? */
	if (setpgid(0, 0) == -1) {
	    exit(1);
	}
#endif

	fd = open(slave, O_RDWR);
	if (fd == -1) {
	    fprintf(stderr, "pty fork: failed to open slave terminal: %s\n",
		    strerror(errno));
	    exit(1);
	}

	/* fd will be closed by the loop to close everything. */
	if (open("/dev/tty", O_RDWR) == -1) {
	    fprintf(stderr, "pty fork: failed to set control term: %s\n",
		    strerror(errno));
	    exit(1);
	}

	if (dup2(fd, 0) == -1) {
	    fprintf(stderr, "pty fork: stdin open fail\n");
	    exit(1);
	}

	if (dup2(fd, 1) == -1) {
	    fprintf(stderr, "pty fork: stdout open fail\n");
	    exit(1);
	}

	if (dup2(fd, 2) == -1) {
	    fprintf(stderr, "pty fork: stderr open fail\n");
	    exit(1);
	}

	/* Close everything. */
	for (i = 3; i < openfiles; i++)
		close(i);

	execvp(argv[0], argv);
	exit(1); /* Only reached on error. */
    }

    *rpid = pid;
    *rptym = ptym;
    return 0;
}


static int
pty_sub_open(void *handler_data, int *fd)
{
    struct pty_data *tdata = handler_data;
    int err;

    err = setup_child_on_pty(tdata->argv, &tdata->ptym, &tdata->pid);
    if (err)
	return err;

    if (fcntl(tdata->ptym, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	close(tdata->ptym);
	tdata->ptym = -1;
    } else {
	*fd = tdata->ptym;
    }

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
    int rv, err = 0;

 retry:
    rv = write(fd, buf, buflen);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EWOULDBLOCK || errno == EAGAIN)
	    rv = 0; /* Handle like a zero-byte write. */
	else
	    err = errno;
    } else if (rv == 0) {
	err = EPIPE;
    }

    if (!err && rcount)
	*rcount = rv;

    return err;
}

static ssize_t
pty_do_read(int fd, void *data, size_t count, const char **auxdata,
	    void *cb_data)
{
    int rv = read(fd, data, count);

    if (rv >= 0)
	return rv;
    return 0; /* Treat any error like it was EPIPE. */
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
	str_to_argv_free(argc, argv);
    }

    return err;
}
