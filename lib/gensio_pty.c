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

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/argvutils.h>

struct pty_data {
    struct gensio_os_funcs *o;

    struct gensio_ll *ll;

    int uid;
    int gid;

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
setup_child_on_pty(char *const argv[], int uid, int gid,
		   int *rptym, pid_t *rpid)
{
    pid_t pid;
    int ptym, err = 0, myuid, mygid;
    int oldeuid, oldegid;

    myuid = getuid();
    mygid = getgid();
    oldeuid = geteuid();
    oldegid = getegid();

    /* FIXME - need better capabilities checking than this. */
    if (myuid != uid && myuid != 0)
	return EPERM;

    if (mygid != gid && myuid != 0)
	return EPERM;

    /* Switch the euid and egid to create the pty. */
    if (gid != mygid) {
	if (setegid(gid) < 0)
	    return errno;
    }

    if (uid != myuid) {
	if (seteuid(uid) < 0) {
	    err = errno;
	    setegid(oldegid);
	    return err;
	}
    }

    ptym = posix_openpt(O_RDWR | O_NOCTTY);
    if (ptym == -1)
	err = errno;

    /* Switch back now. */
    setegid(oldegid);
    seteuid(oldeuid);

    if (err) {
	close(ptym);
	return errno;
    }

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
	unsigned int i, openfiles = sysconf(_SC_OPEN_MAX);

	/*
	 * Set the GID then the UID first, keeping euid, or grantpt
	 * will fail.
	 */
	if (gid != mygid) {
	    if (setgid(gid) < 0)
		exit(1);
	}

	if (uid != myuid) {
	    if (setuid(uid) < 0)
		exit(1);
	}

	/* Set the owner of the slave PT. */
	if (grantpt(ptym) < 0)
	    exit(1);

	/* Now we can set euid and egid. */
	if (gid != mygid) {
	    if (setegid(gid) < 0)
		exit(1);
	}

	if (uid != myuid) {
	    if (seteuid(uid) < 0)
		exit(1);
	}

	/* Close everything. */
	for (i = 0; i < openfiles; i++)
	    close(i);

	/* stdin */
	if (open(slave, O_RDONLY) != 0)
	    exit(1);

	/* stdout */
	if (open(slave, O_WRONLY) != 1)
	    exit(1);

	/* stderr */
	if (open(slave, O_WRONLY) != 2)
	    exit(1);

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

    err = setup_child_on_pty(tdata->argv, tdata->uid, tdata->gid,
			     &tdata->ptym, &tdata->pid);
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
    int uid = getuid(), gid = getgid();
    const char *username;
    int err;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "userid", &username) > 0) {
	    struct passwd pwd, *pwdr;
	    char buf[1024]; /* Should be plenty of space. */

	    err = getpwnam_r(username, &pwd, buf, sizeof(buf), &pwdr);
	    if (err)
		return err;
	    uid = pwd.pw_uid;
	    gid = pwd.pw_gid;
	    continue;
	}
	return EINVAL;
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata)
	return ENOMEM;

    tdata->o = o;
    tdata->ptym = -1;
    tdata->uid = uid;
    tdata->gid = gid;

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
