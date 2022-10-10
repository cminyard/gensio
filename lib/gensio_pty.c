/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code handles running a child process using a pty. */

#ifdef linux
#define _GNU_SOURCE /* Get ptsname_r(). */
#endif

#include "config.h"
#include <gensio/gensio_err.h>

#include <stdio.h>
#include <stdlib.h>
#if HAVE_PTSNAME_R
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <sys/stat.h>
#endif

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_osops.h>
#ifdef _WIN32
#include <windows.h>
#endif

struct pty_data {
    struct gensio_os_funcs *o;

    struct gensio_ll *ll;

    struct gensio_lock *lock;

    struct gensio_iod *iod;
    intptr_t pid;
    const char **argv;
    const char **env;
    char *start_dir;

#if HAVE_PTSNAME_R
    mode_t mode;
    bool mode_set;
    char *owner;
    char *group;

    /* Symbolic link to create (if not NULL). */
    char *link;
    bool forcelink;
    bool link_created;
#endif

#ifdef _WIN32
    char *user;
    char *passwd;
    char *module;
    HANDLE userh;
#endif

    unsigned int check_close_count;

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

static int
gensio_setup_pty(struct pty_data *tdata, struct gensio_iod *iod)
{
    int err = 0;

#if HAVE_PTSNAME_R
    uid_t ownerid = -1;
    uid_t groupid = -1;
    char ptsstr[PATH_MAX];
    char pwbuf[16384];

    err = ptsname_r(tdata->o->iod_get_fd(iod), ptsstr, sizeof(ptsstr));
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

	tdata->link_created = true;
    }
    return 0;

 out_errno:
    err = errno;
 out_err:
    err = gensio_os_err_to_err(tdata->o, err);
#endif
    return err;
}

static void
gensio_cleanup_pty(struct pty_data *tdata)
{
#if HAVE_PTSNAME_R
    if (tdata->link_created) {
	unlink(tdata->link);
	tdata->link_created = false;
    }
#endif
}

#ifndef _WIN32
static int
setup_for_user(struct pty_data *tdata) {
    return 0;
}

static void
cleanup_for_user(struct pty_data *tdata) {}

#else

static int
setup_for_user(struct pty_data *tdata) {
    DWORD err;

    if (!tdata->user)
	return 0;

    err = gensio_win_get_user_token(tdata->user, tdata->passwd,
				    tdata->module, NULL, true, &tdata->userh);
    if (err)
	goto out_win_err;

#if 0
    /*
     * Password authenticated logins are normal Interactive logins and
     * can be used directly.  S4U logins are Network logins and not
     * set up as such.
     */
    if (!tdata->passwd) {
	err = setup_network_token(&tdata->userh, tdata->privileged);
	if (err) {
	    char errbuf[128];

	    CloseHandle(tdata->userh);
	    tdata->userh = NULL;
	    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
			  err, 0, errbuf, sizeof(errbuf), NULL);
	    log_event(LOG_ERR, "Could not setup process token '%s': %s",
		      tdata->user, errbuf);
	    goto out_win_err;
	}
    }
#endif

    if (!SetThreadToken(NULL, tdata->userh)) {
	CloseHandle(tdata->userh);
	tdata->userh = NULL;
	err = GetLastError();
    }
 out_win_err:
    if (err)
	return gensio_os_err_to_err(tdata->o, err);
    return 0;
}

static void
cleanup_for_user(struct pty_data *tdata) {
    if (!tdata->userh)
	return;
    CloseHandle(tdata->userh);
    tdata->userh = NULL;
    RevertToSelf();
}
#endif

static int
gensio_setup_child_on_pty(struct pty_data *tdata)
{
    struct gensio_os_funcs *o = tdata->o;
    int err = 0;
    struct gensio_iod *iod = NULL;

    err = o->add_iod(o, GENSIO_IOD_PTY, 0, &iod);
    if (err)
	goto out_err;

    err = o->set_non_blocking(iod);
    if (err)
	goto out_err;

    err = gensio_setup_pty(tdata, iod);

    if (tdata->raw) {
	err = o->makeraw(iod);
	if (err)
	    goto out_err;
    }

    if (tdata->argv)
	err = o->iod_control(iod, GENSIO_IOD_CONTROL_ARGV, false,
			     (intptr_t) tdata->argv);
    if (!err && tdata->env)
	err = o->iod_control(iod, GENSIO_IOD_CONTROL_ENV, false,
			     (intptr_t) tdata->env);
    if (!err && tdata->start_dir)
	err = o->iod_control(iod, GENSIO_IOD_CONTROL_START_DIR, false,
			     (intptr_t) tdata->start_dir);

    if (!err) {
	err = setup_for_user(tdata);
	if (err)
	    goto out_err;
    }
    if (!err) {
	err = o->iod_control(iod, GENSIO_IOD_CONTROL_START, false, 0);
	cleanup_for_user(tdata);
    }
    if (err)
	goto out_err;

    if (tdata->argv) {
	err = o->iod_control(iod, GENSIO_IOD_CONTROL_PID, true,
			     (intptr_t) &tdata->pid);
	if (err)
	    goto out_err;
    }

    tdata->iod = iod;
    return 0;

 out_err:
    gensio_cleanup_pty(tdata);
    if (iod)
	o->close(&iod);
    return err;
}

static int
pty_sub_open(void *handler_data, struct gensio_iod **riod)
{
    struct pty_data *tdata = handler_data;
    int err;

    tdata->check_close_count = 0;
    err = gensio_setup_child_on_pty(tdata);
    if (!err)
	*riod = tdata->iod;

    return err;
}

static int
pty_check_exit_code(struct pty_data *tdata)
{
    struct gensio_os_funcs *o = tdata->o;
    int err = 0;

    o->lock(tdata->lock);
    if (tdata->exit_code_set)
	goto out_unlock;
    if (tdata->pid == -1) {
	err = GE_NOTREADY;
    } else {
	err = o->wait_subprog(o, tdata->pid, &tdata->exit_code);
	if (!err)
	    tdata->exit_code_set = true;
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
    struct gensio_os_funcs *o = tdata->o;
    int err;

    if (state != GENSIO_LL_CLOSE_STATE_DONE)
	return 0;

    gensio_cleanup_pty(tdata);
    if (tdata->iod) {
	err = o->iod_control(iod, GENSIO_IOD_CONTROL_STOP, false, 0);
	if (err)
	    goto out_finish;
    }

    err = pty_check_exit_code(tdata);
    if (err == GE_INPROGRESS) {
	/* FIXME - this should probably be configurable. */
	if (tdata->check_close_count >= 500) /* Wait for 5 seconds. */
	    goto out_finish;
	tdata->check_close_count++;
	timeout->secs = 0;
	timeout->nsecs = 10000000;
	return err;
    }

 out_finish:
    if (tdata->iod) {
	tdata->iod = NULL;
	gensio_fd_ll_close_now(tdata->ll);
    }

    return err;
}

static void
pty_free(void *handler_data)
{
    struct pty_data *tdata = handler_data;
    struct gensio_os_funcs *o = tdata->o;

#ifdef _WIN32
    if (tdata->user)
	free(tdata->user);
    if (tdata->module)
	free(tdata->module);
    if (tdata->passwd) {
	memset(tdata->passwd, 0, strlen(tdata->passwd));
	free(tdata->passwd);
    }
#endif
#if HAVE_PTSNAME_R
    if (tdata->link)
	o->free(o, tdata->link);
    if (tdata->owner)
	o->free(o, tdata->owner);
    if (tdata->group)
	o->free(o, tdata->group);
#endif
    if (tdata->argv)
	gensio_argv_free(o, tdata->argv);
    if (tdata->env)
	gensio_argv_free(o, tdata->env);
    if (tdata->start_dir)
	o->free(o, tdata->start_dir);
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
	if (data) {
	    err = gensio_argv_copy(o, (const char **) data, NULL, &env);
	    if (err)
		return err;
	} else {
	    env = NULL;
	}
	if (tdata->env)
	    gensio_argv_free(o, tdata->env);
	tdata->env = env;
	return 0;

    case GENSIO_CONTROL_ARGS:
	if (get)
	    return GE_NOTSUP;
	if (tdata->iod)
	    return GE_NOTREADY; /* Have to do this while closed. */
	if (data) {
	    err = gensio_argv_copy(o, (const char **) data, NULL, &argv);
	    if (err)
		return err;
	} else {
	    argv = NULL;
	}
	if (tdata->argv)
	    gensio_argv_free(o, tdata->argv);
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
	    err = o->kill_subprog(o, tdata->pid, !!val);
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
	if (!tdata->iod)
	    return GE_NOTREADY;
	err = ptsname_r(o->iod_get_fd(tdata->iod), ptsstr, sizeof(ptsstr));
	if (err)
	    err = gensio_os_err_to_err(o, errno);
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
	if (!tdata->iod)
	    return GE_NOTREADY;
	if (*datalen >= sizeof(int))
	    *((int *) data) = o->iod_get_fd(tdata->iod);
	*datalen = sizeof(int);
	return 0;

    case GENSIO_CONTROL_REMOTE_ID:
	if (!get)
	    return GE_NOTSUP;
	if (tdata->pid == -1)
	    return GE_NOTREADY;
	*datalen = snprintf(data, *datalen, "%llu",
			    (unsigned long long) tdata->pid);
	return 0;

    case GENSIO_CONTROL_WIN_SIZE: {
	struct gensio_winsize ws;
	int c;

	if (get)
	    return GE_NOTSUP;
	if (!tdata->iod)
	    return GE_NOTREADY;

	c = sscanf(data, "%d:%d:%d:%d", &ws.ws_row, &ws.ws_col,
		   &ws.ws_xpixel, &ws.ws_ypixel);
	if (c < 0)
	    return gensio_os_err_to_err(o, errno);
	if (c < 2)
	    return GE_INVAL;
	return o->iod_control(tdata->iod, GENSIO_IOD_CONTROL_WIN_SIZE, get,
			      (intptr_t) &ws);
    }

    case GENSIO_CONTROL_START_DIRECTORY:
	if (get) {
	    *datalen = snprintf(data, *datalen, "%s", tdata->start_dir);
	} else {
	    char *dir;

	    dir = gensio_strdup(o, (char *) data);
	    if (!dir)
		return GE_NOMEM;
	    if (tdata->start_dir)
		o->free(o, tdata->start_dir);
	    tdata->start_dir = dir;
	}
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

static int
pty_gensio_alloc(const void *gdata, const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
    const char * const *argv = gdata;
    struct pty_data *tdata = NULL;
    struct gensio *io;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    unsigned int i;
#if HAVE_PTSNAME_R
    unsigned int umode = 6, gmode = 6, omode = 6, mode;
    bool mode_set = false;
    const char *owner = NULL, *group = NULL, *link = NULL;
    bool forcelink = false;
#endif
#ifdef _WIN32
    const char *user = NULL, *passwd = NULL, *module = NULL;
#endif
    const char *start_dir = NULL;
    bool raw = false;
    int err;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "start-dir", &start_dir) > 0)
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
#ifdef _WIN32
	if (gensio_check_keyvalue(args[i], "user", &user))
	    continue;
	if (gensio_check_keyvalue(args[i], "passwd", &passwd))
	    continue;
#endif
	if (gensio_check_keybool(args[i], "raw", &raw) > 0)
	    continue;
	return GE_INVAL;
    }

#ifdef _WIN32
    /* Must be running a program if specifying a user. */
    if (user && !argv)
	return GE_INVAL;
    /* passwd and module require user to be set. */
    if ((passwd || module) && !user)
	return GE_INVAL;
#endif

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata)
	return GE_NOMEM;

    tdata->o = o;
    tdata->pid = -1;

    if (start_dir) {
	tdata->start_dir = gensio_strdup(o, start_dir);
	if (!tdata->start_dir)
	    goto out_nomem;
    }

    tdata->lock = o->alloc_lock(o);
    if (!tdata->lock)
	goto out_nomem;

#if HAVE_PTSNAME_R
    if (link) {
	tdata->link = gensio_strdup(o, link);
	if (!tdata->link)
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
#endif

#ifdef _WIN32
    if (user) {
	tdata->user = gensio_strdup(o, user);
	if (!tdata->user)
	    goto out_nomem;
    }
    if (passwd) {
	tdata->passwd = gensio_strdup(o, passwd);
	if (!tdata->passwd)
	    goto out_nomem;
    }
    if (!module)
	module = "gensio";
    tdata->module = gensio_strdup(o, module);
    if (!tdata->module)
	goto out_nomem;
#endif

    if (argv && argv[0]) {
#if HAVE_PTSNAME_R
	if (mode_set || owner || group) {
	    /* These are only for non-subprogram ptys. */
	    err = GE_INCONSISTENT;
	    goto out_err;
	}
#endif
	err = gensio_argv_copy(o, argv, NULL, &tdata->argv);
	if (err)
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
#if HAVE_PTSNAME_R
 out_err:
#endif
    if (tdata->ll)
	gensio_ll_free(tdata->ll);
    else
	pty_free(tdata);
    return err;
}

static int
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

int
gensio_init_pty(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "pty", str_to_pty_gensio, pty_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
