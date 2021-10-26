/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code handles running a child process using a pty. */

#include "config.h"

#if HAVE_PTY

#ifdef linux
#define _XOPEN_SOURCE 600 /* Get posix_openpt() and friends. */
#define _GNU_SOURCE /* Get ptsname_r(). */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <limits.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_builtins.h>

struct pty_data {
    struct gensio_os_funcs *o;

    struct gensio_ll *ll;

    struct gensio_lock *lock;

    pid_t pid;
    int ptym;
    struct gensio_iod *iod;
    const char **argv;
    const char **env;

    mode_t mode;
    bool mode_set;
    char *owner;
    char *group;

    /* Symbolic link to create (if not NULL). */
    char *link;
    bool forcelink;
    bool raw;

    int last_err;

    /* exit code from the sub-program, after close. */
    int exit_code;
    bool exit_code_set;
};

static int pty_check_open(void *handler_data, struct gensio_iod *iod)
{
    return 0;
}

#ifndef HAVE_CFMAKERAW
static void
cfmakeraw(struct termios *termios_p) {
    termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    termios_p->c_oflag &= ~OPOST;
    termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    termios_p->c_cflag &= ~(CSIZE|PARENB);
    termios_p->c_cflag |= CS8;
    termios_p->c_cc[VMIN] = 1;
}
#endif

static int
pty_make_raw(int ptym)
{
    struct termios t;
    int err;

    err = tcgetattr(ptym, &t);
    if (err)
	return err;

    cfmakeraw(&t);
    return tcsetattr(ptym, TCSANOW, &t);
}

/*
 * This is ugly, but it's by far the simplest way.
 */
extern char **environ;

static int
gensio_setup_child_on_pty(struct pty_data *tdata)
{
    struct gensio_os_funcs *o = tdata->o;
    pid_t pid = -1;
    int ptym, err = 0;
    struct gensio_iod *iod = NULL;
    uid_t ownerid = -1;
    uid_t groupid = -1;
    const char *pgm;
    bool link_created = false;
#if HAVE_PTSNAME_R
    char ptsstr[PATH_MAX];
    char pwbuf[16384];
#endif

    ptym = posix_openpt(O_RDWR | O_NOCTTY);
    if (ptym == -1)
	return gensio_os_err_to_err(o, errno);

    err = o->add_iod(o, GENSIO_IOD_DEV, ptym, &iod);
    if (err)
	goto out_err_noconv;

    err = o->set_non_blocking(iod);
    if (err)
	goto out_err_noconv;

#if HAVE_PTSNAME_R
    err = ptsname_r(ptym, ptsstr, sizeof(ptsstr));
    if (err)
	goto out_errno;

    if (tdata->mode_set) {
	err = chmod(ptsstr, tdata->mode);
	if (err)
	    goto out_errno;
    }

    if (tdata->owner) {
	struct passwd pwdbuf, *pwd;

	err = getpwnam_r(tdata->owner, &pwdbuf, pwbuf, sizeof(pwbuf), &pwd);
	if (err)
	    goto out_errno;
	if (!pwd) {
	    err = ENOENT;
	    goto out_err;
	}
	ownerid = pwd->pw_uid;
    }

    if (tdata->group) {
	struct group grpbuf, *grp;

	err = getgrnam_r(tdata->group, &grpbuf, pwbuf, sizeof(pwbuf), &grp);
	if (err)
	    goto out_errno;
	if (!grp) {
	    err = ENOENT;
	    goto out_err;
	}
	groupid = grp->gr_gid;
    }

    if (ownerid != -1 || groupid != -1) {
	err = chown(ptsstr, ownerid, groupid);
	if (err)
	    goto out_errno;
    }

    if (tdata->link) {
	bool delretry = false;

    retry:
	err = symlink(ptsstr, tdata->link);
	if (err) {
	    if (errno == EEXIST && tdata->forcelink && !delretry) {
		err = unlink(tdata->link);
		if (!err) {
		    delretry = true;
		    goto retry;
		}
	    }
	    goto out_errno;
	}

	link_created = true;
    }
#endif

    if (tdata->raw) {
	err = pty_make_raw(ptym);
	if (err)
	    goto out_errno;
    }

    if (unlockpt(ptym) < 0)
	goto out_errno;

    if (!tdata->argv)
	goto skip_child;

    pid = fork();
    if (pid < 0)
	goto out_errno;

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

	if (setsid() == -1) {
	    fprintf(stderr, "pty fork: failed to start new session: %s\r\n",
		    strerror(errno));
	    exit(1);
	}

#if 0 /* FIXME = do we need this? */
	if (setpgid(0, 0) == -1) {
	    fprintf(stderr, "pty fork: failed setpgid: %s\r\n",
		    strerror(errno));
	    exit(1);
	}
#endif

	fd = open(slave, O_RDWR);
	if (fd == -1) {
	    fprintf(stderr, "pty fork: failed to open slave terminal: %s\r\n",
		    strerror(errno));
	    exit(1);
	}

#if defined(TIOCSCTTY) && !defined(linux)
	/* Linux sets the first opened TTY to the controlling terminal. */
	if (ioctl(fd, TIOCSCTTY, NULL) == -1) {
	    fprintf(stderr, "pty fork: failed to set controlling tty: %s\r\n",
		    strerror(errno));
	    exit(1);
	}
#endif

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

	err = gensio_unix_os_setupnewprog();
	if (err) {
	    fprintf(stderr, "Unable to set groups or user: %s\r\n",
		    strerror(err));
	    exit(1);
	}

	if (tdata->env)
	    environ = (char **) tdata->env;

	pgm = tdata->argv[0];
	if (*pgm == '-')
	    pgm++;
	execvp(pgm, (char **) tdata->argv);
	fprintf(stderr, "Unable to exec %s: %s\r\n", tdata->argv[0],
		strerror(errno));
	exit(1); /* Only reached on error. */
    }
 skip_child:
    tdata->pid = pid;
    tdata->ptym = ptym;
    tdata->iod = iod;
    return 0;
 out_errno:
    err = errno;
 out_err:
    err = gensio_os_err_to_err(o, err);
 out_err_noconv:
    if (link_created)
	unlink(tdata->link);
    if (iod)
	o->close(&iod);
    close(ptym);
    return err;
}

static int
pty_sub_open(void *handler_data, struct gensio_iod **riod)
{
    struct pty_data *tdata = handler_data;
    int err;

    err = gensio_setup_child_on_pty(tdata);
    if (!err)
	*riod = tdata->iod;

    return err;
}

static int
pty_check_exit_code(struct pty_data *tdata)
{
    struct gensio_os_funcs *o = tdata->o;
    pid_t rv;
    int err;

    err = 0;
    o->lock(tdata->lock);
    if (tdata->pid != -1) {
	rv = waitpid(tdata->pid, &tdata->exit_code, WNOHANG);
	if (rv < 0) {
	    err = gensio_os_err_to_err(o, errno);
	    goto out_unlock;
	}
	if (rv == 0) {
	    err = GE_INPROGRESS;
	    goto out_unlock;
	}
	tdata->exit_code_set = true;
	tdata->pid = -1;
    }
 out_unlock:
    o->unlock(tdata->lock);
    return err;
}

static int
pty_check_close(void *handler_data, struct gensio_iod *iod,
		enum gensio_ll_close_state state,
		gensio_time *timeout)
{
    struct pty_data *tdata = handler_data;
    int err;

    if (state != GENSIO_LL_CLOSE_STATE_DONE)
	return 0;

    /* The ptym will be closed in the fd ll, it owns the fd. */
    if (tdata->ptym != -1) {
	tdata->ptym = -1;
	gensio_fd_ll_close_now(tdata->ll);
	if (tdata->link)
	    unlink(tdata->link);
    }

    err = pty_check_exit_code(tdata);
    if (err == GE_INPROGRESS) {
	timeout->secs = 0;
	timeout->nsecs = 10000000;
    }

    return err;
}

static void
pty_free(void *handler_data)
{
    struct pty_data *tdata = handler_data;
    struct gensio_os_funcs *o = tdata->o;

    if (tdata->link)
	o->free(o, tdata->link);
    if (tdata->owner)
	o->free(o, tdata->owner);
    if (tdata->group)
	o->free(o, tdata->group);
    if (tdata->argv)
	gensio_argv_free(o, tdata->argv);
    if (tdata->env)
	gensio_argv_free(o, tdata->env);
    if (tdata->lock)
	o->free_lock(tdata->lock);
    o->free(o, tdata);
}

static int
pty_write(void *handler_data, struct gensio_iod *iod, gensiods *rcount,
	  const struct gensio_sg *sg, gensiods sglen,
	  const char *const *auxdata)
{
    int rv = iod->f->write(iod, sg, sglen, rcount);

    if (rv && rv == GE_IOERR)
	return GE_REMCLOSE; /* We don't seem to get EPIPE from ptys */
    return rv;
}

static int
pty_do_read(struct gensio_iod *iod, void *data, gensiods count,
	    gensiods *rcount, const char ***auxdata, void *cb_data)
{
    int rv = iod->f->read(iod, data, count, rcount);

    if (rv && rv == GE_IOERR)
	return GE_REMCLOSE; /* We don't seem to get EPIPE from ptys */
    return rv;
}

static void
pty_read_ready(void *handler_data, struct gensio_iod *iod)
{
    struct pty_data *tdata = handler_data;

    gensio_fd_ll_handle_incoming(tdata->ll, pty_do_read, NULL, tdata);
}

static int
pty_control(void *handler_data, struct gensio_iod *iod, bool get,
	    unsigned int option, char *data, gensiods *datalen)
{
    struct pty_data *tdata = handler_data;
    struct gensio_os_funcs *o = tdata->o;
    const char **env, **argv;
    int err, val;

    switch (option) {
    case GENSIO_CONTROL_ENVIRONMENT:
	if (get)
	    return GE_NOTSUP;
	if (!tdata->argv)
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
	if (tdata->ptym != -1)
	    return GE_NOTREADY; /* Have to do this while closed. */
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
	err = 0;
	o->lock(tdata->lock);
	if (!tdata->exit_code_set)
	    err = GE_NOTREADY;
	o->unlock(tdata->lock);
	if (!err)
	    *datalen = snprintf(data, *datalen, "%d", tdata->exit_code);
	return err;

    case GENSIO_CONTROL_KILL_TASK:
	if (get)
	    return GE_NOTSUP;
	o->lock(tdata->lock);
	if (tdata->pid == -1) {
	    err = GE_NOTREADY;
	} else {
	    val = strtoul(data, NULL, 0);
	    err = kill(tdata->pid, val ? SIGKILL : SIGTERM);
	    if (err)
		err = gensio_os_err_to_err(o, errno);
	}
	o->unlock(tdata->lock);
	return err;

    case GENSIO_CONTROL_WAIT_TASK:
	if (!get)
	    return GE_NOTSUP;
	err = pty_check_exit_code(tdata);
	if (err)
	    return err;
	*datalen = snprintf(data, *datalen, "%d", tdata->exit_code);
	return 0;

#if HAVE_PTSNAME_R
    case GENSIO_CONTROL_LADDR:
    case GENSIO_CONTROL_LPORT:
    {
	char ptsstr[PATH_MAX];

	if (!get)
	    return GE_NOTSUP;
	if (strtoul(data, NULL, 0) > 0)
	    return GE_NOTFOUND;
	if (tdata->ptym == -1)
	    return GE_NOTREADY;
	err = ptsname_r(tdata->ptym, ptsstr, sizeof(ptsstr));
	if (err)
	    err = gensio_os_err_to_err(tdata->o, errno);
	else
	    *datalen = snprintf(data, *datalen, "%s", ptsstr);
	return err;
    }
#endif

    case GENSIO_CONTROL_RADDR:
	if (!get)
	    return GE_NOTSUP;
	if (strtoul(data, NULL, 0) > 0)
	    return GE_NOTFOUND;
	if (!tdata->argv)
	    return GE_NODATA;
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
    unsigned int umode = 6, gmode = 6, omode = 6, i, mode;
    bool mode_set = false;
    const char *owner = NULL, *group = NULL, *link = NULL;
    int err;
    bool forcelink = false;
    bool raw = false;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
#if HAVE_PTSNAME_R
	if (gensio_check_keyvalue(args[i], "link", &link))
	    continue;
	if (gensio_check_keybool(args[i], "forcelink", &forcelink) > 0)
	    continue;
	if (gensio_check_keymode(args[i], "umode", &umode) > 0) {
	    mode_set = true;
	    continue;
	}
	if (gensio_check_keymode(args[i], "gmode", &gmode) > 0) {
	    mode_set = true;
	    continue;
	}
	if (gensio_check_keymode(args[i], "omode", &omode) > 0) {
	    mode_set = true;
	    continue;
	}
	if (gensio_check_keyperm(args[i], "perm", &mode) > 0) {
	    mode_set = true;
	    umode = mode >> 6 & 7;
	    gmode = mode >> 3 & 7;
	    omode = mode & 7;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "owner", &owner))
	    continue;
	if (gensio_check_keyvalue(args[i], "group", &group))
	    continue;
#endif
	if (gensio_check_keybool(args[i], "raw", &raw) > 0)
	    continue;
	return GE_INVAL;
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata)
	return GE_NOMEM;

    tdata->o = o;
    tdata->ptym = -1;

    tdata->lock = o->alloc_lock(o);
    if (!tdata->lock)
	goto out_nomem;

    if (link) {
	tdata->link = gensio_strdup(o, link);
	if (!tdata->link)
	    goto out_nomem;
    }

    if (argv && argv[0]) {
	if (mode_set || owner || group) {
	    /* These are only for non-subprogram ptys. */
	    err = GE_INCONSISTENT;
	    goto out_err;
	}
	err = gensio_argv_copy(o, argv, NULL, &tdata->argv);
	if (err)
	    goto out_nomem;
    }

    tdata->forcelink = forcelink;
    tdata->raw = raw;
    tdata->mode = umode << 6 | gmode << 3 | omode;
    tdata->mode_set = mode_set;
    if (owner) {
	tdata->owner = gensio_strdup(o, owner);
	if (!tdata->owner)
	    goto out_nomem;
    }
    if (group) {
	tdata->group = gensio_strdup(o, group);
	if (!tdata->group)
	    goto out_nomem;
    }

    tdata->ll = fd_gensio_ll_alloc(o, NULL, &pty_fd_ll_ops, tdata,
				   max_read_size, false);
    if (!tdata->ll)
	goto out_nomem;

    io = base_gensio_alloc(o, tdata->ll, NULL, NULL, "pty", cb, user_data);
    if (!io)
	goto out_nomem;

    gensio_set_is_reliable(io, true);

    *new_gensio = io;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (tdata->ll)
	gensio_ll_free(tdata->ll);
    else
	pty_free(tdata);
    return err;
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

#else

#include <gensio/gensio_class.h>
#include <gensio/gensio_builtins.h>

int
pty_gensio_alloc(const char * const argv[], const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
    return GE_NOTSUP;
}

int
str_to_pty_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return GE_NOTSUP;
}

#endif
