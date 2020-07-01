/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code handles running a child process using a pty. */

#include "config.h"
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
#include <sys/ioctl.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_builtins.h>

struct pty_data {
    struct gensio_os_funcs *o;

    struct gensio_ll *ll;

    pid_t pid;
    int ptym;
    const char **argv;
    const char **env;

    int last_err;

    /* exit code from the sub-program, after close. */
    int exit_code;
    bool exit_code_set;
};

static int pty_check_open(void *handler_data, int fd)
{
    return 0;
}

/*
 * This is ugly, but it's by far the simplest way.
 */
extern char **environ;

static int
gensio_setup_child_on_pty(struct gensio_os_funcs *o,
			  char *const argv[], const char **env,
			  int *rptym, pid_t *rpid)
{
    pid_t pid;
    int ptym, err = 0;
    const char *pgm;

    ptym = posix_openpt(O_RDWR | O_NOCTTY);
    if (ptym == -1)
	return gensio_os_err_to_err(o, errno);

    if (fcntl(ptym, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	close(ptym);
	return gensio_os_err_to_err(o, err);
    }

    if (unlockpt(ptym) < 0) {
	err = errno;
	close(ptym);
	return gensio_os_err_to_err(o, err);
    }

    pid = fork();
    if (pid < 0) {
	err = errno;
	close(ptym);
	return gensio_os_err_to_err(o, err);
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

	/* setsid() does this, but just in case... */
	fd = open("/dev/tty", O_RDWR);
	if (fd != -1) {
	    ioctl(fd, TIOCNOTTY, NULL);
	    close(fd);

	    fd = open("/dev/tty", O_RDWR);
	    if (fd != -1) {
		fprintf(stderr, "pty fork: failed to drop control term: %s\r\n",
			strerror(errno));
		exit(1);
	    }
	}

	if (setsid() == -1) {
	    fprintf(stderr, "pty fork: failed to start new session: %s\r\n",
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
	    fprintf(stderr, "pty fork: failed to open slave terminal: %s\r\n",
		    strerror(errno));
	    exit(1);
	}

	/* fd will be closed by the loop to close everything. */
	if (open("/dev/tty", O_RDWR) == -1) {
	    fprintf(stderr, "pty fork: failed to set control term: %s\r\n",
		    strerror(errno));
	    exit(1);
	}

	if (dup2(fd, 0) == -1) {
	    fprintf(stderr, "pty fork: stdin open fail\r\n");
	    exit(1);
	}

	if (dup2(fd, 1) == -1) {
	    fprintf(stderr, "pty fork: stdout open fail\r\n");
	    exit(1);
	}

	if (dup2(fd, 2) == -1) {
	    fprintf(stderr, "pty fork: stderr open fail\r\n");
	    exit(1);
	}

	/* Close everything. */
	for (i = 3; i < openfiles; i++)
		close(i);

	err = gensio_os_setupnewprog();
	if (err) {
	    fprintf(stderr, "Unable to set groups or user: %s\r\n",
		    strerror(err));
	    exit(1);
	}

	if (env)
	    environ = (char **) env;

	pgm = argv[0];
	if (*pgm == '-')
	    pgm++;
	execvp(pgm, argv);
	fprintf(stderr, "Unable to exec %s: %s\r\n", argv[0], strerror(errno));
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

    err = gensio_setup_child_on_pty(tdata->o,
				    (char * const *) tdata->argv, tdata->env,
				    &tdata->ptym, &tdata->pid);
    if (!err)
	*fd = tdata->ptym;

    return err;
}

static int
pty_check_close(void *handler_data, enum gensio_ll_close_state state,
		gensio_time *timeout)
{
    struct pty_data *tdata = handler_data;
    pid_t rv;

    if (state != GENSIO_LL_CLOSE_STATE_DONE)
	return 0;

    if (tdata->ptym != -1) {
	close(tdata->ptym);
	tdata->ptym = -1;
    }

    if (tdata->pid != -1) {
	rv = waitpid(tdata->pid, &tdata->exit_code, WNOHANG);
	if (rv < 0)
	    return gensio_os_err_to_err(tdata->o, errno);
	if (rv == 0) {
	    timeout->secs = 0;
	    timeout->nsecs = 10000000;
	    return GE_INPROGRESS;
	}
	tdata->exit_code_set = true;
	tdata->pid = -1;
    }
    return 0;
}

static void
pty_free(void *handler_data)
{
    struct pty_data *tdata = handler_data;

    if (tdata->argv)
	gensio_argv_free(tdata->o, tdata->argv);
    if (tdata->env)
	gensio_argv_free(tdata->o, tdata->env);
    tdata->o->free(tdata->o, tdata);
}

static int
pty_write(void *handler_data, int fd, gensiods *rcount,
	  const struct gensio_sg *sg, gensiods sglen,
	  const char *const *auxdata)
{
    struct pty_data *tdata = handler_data;
    int rv = gensio_os_write(tdata->o, fd, sg, sglen, rcount);

    if (rv && rv == GE_IOERR)
	return GE_REMCLOSE; /* We don't seem to get EPIPE from ptys */
    return rv;
}

static int
pty_do_read(int fd, void *data, gensiods count, gensiods *rcount,
	    const char ***auxdata, void *cb_data)
{
    struct pty_data *tdata = cb_data;
    int rv = gensio_os_read(tdata->o, fd, data, count, rcount);

    if (rv && rv == GE_IOERR)
	return GE_REMCLOSE; /* We don't seem to get EPIPE from ptys */
    return rv;
}

static void
pty_read_ready(void *handler_data, int fd)
{
    struct pty_data *tdata = handler_data;

    gensio_fd_ll_handle_incoming(tdata->ll, pty_do_read, NULL, tdata);
}

static int
pty_control(void *handler_data, int fd, bool get, unsigned int option,
	    char *data, gensiods *datalen)
{
    struct pty_data *tdata = handler_data;
    const char **env, **argv;
    int err, status;

    switch (option) {
    case GENSIO_CONTROL_ENVIRONMENT:
	if (get)
	    return GE_NOTSUP;
	err = gensio_argv_copy(tdata->o, (const char **) data, NULL, &env);
	if (err)
	    return err;
	if (tdata->env)
	    gensio_argv_free(tdata->o, tdata->env);
	tdata->env = env;
	return 0;

    case GENSIO_CONTROL_ARGS:
	if (get)
	    return GE_NOTSUP;
	err = gensio_argv_copy(tdata->o, (const char **) data, NULL, &argv);
	if (err)
	    return err;
	if (tdata->argv)
	    gensio_argv_free(tdata->o, tdata->argv);
	tdata->argv = argv;
	return 0;

    case GENSIO_CONTROL_EXIT_CODE:
	if (!get)
	    return GE_NOTSUP;
	if (!tdata->exit_code_set)
	    return GE_NOTREADY;
	*datalen = snprintf(data, *datalen, "%d", tdata->exit_code);
	return 0;

    case GENSIO_CONTROL_WAIT_TASK:
	if (!get)
	    return GE_NOTSUP;
	if (tdata->pid == -1)
	    return GE_NOTREADY;
	err = waitpid(tdata->pid, &status, WNOHANG | WNOWAIT);
	if (err <= 0)
	    return GE_NOTREADY;
	*datalen = snprintf(data, *datalen, "%d", status);
	return 0;

    case GENSIO_CONTROL_RADDR:
	if (!get)
	    return GE_NOTSUP;
	if (strtoul(data, NULL, 0) > 0)
	    return GE_NOTFOUND;
	*datalen = gensio_argv_snprintf(data, *datalen, NULL, tdata->argv);
	return 0;

    case GENSIO_CONTROL_RADDR_BIN:
	if (!get)
	    return GE_NOTSUP;
	if (*datalen >= sizeof(int))
	    *((int *) data) = tdata->ptym;
	*datalen = 4;
	return 0;

    case GENSIO_CONTROL_REMOTE_ID:
	if (!get)
	    return GE_NOTSUP;
	*datalen = snprintf(data, *datalen, "%d", tdata->pid);
	return 0;
    }

    return GE_NOTSUP;
}

static const struct gensio_fd_ll_ops pty_fd_ll_ops = {
    .sub_open = pty_sub_open,
    .check_open = pty_check_open,
    .read_ready = pty_read_ready,
    .check_close = pty_check_close,
    .free = pty_free,
    .write = pty_write,
    .control = pty_control
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
    unsigned int i;
    int err;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return GE_INVAL;
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata)
	return GE_NOMEM;

    tdata->o = o;
    tdata->ptym = -1;

    err = gensio_argv_copy(o, argv, NULL, &tdata->argv);
    if (err)
	goto out_nomem;

    tdata->ll = fd_gensio_ll_alloc(o, -1, &pty_fd_ll_ops, tdata, max_read_size,
				   false);
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
    return GE_NOMEM;
}

int
str_to_pty_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    int err, argc;
    const char **argv;

    err = gensio_str_to_argv(o, str, &argc, &argv, NULL);
    if (!err) {
	err = pty_gensio_alloc(argv, args, o, cb, user_data, new_gensio);
	gensio_argv_free(o, argv);
    }

    return err;
}
