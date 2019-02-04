/*
 *  gtlsshd - An secure shell server over TS
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <gensio/gensio.h>

#include "ioinfo.h"
#include "ser_ioinfo.h"
#include "utils.h"

unsigned int debug;
static const char *progname;

struct gdata {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    struct gensio *io;
    const char *key;
    const char *cert;

    bool can_close;
};

static const char *default_keyfile = SYSCONFDIR "/gtlsshd/gtlsshd.key";
static const char *default_certfile = SYSCONFDIR "/gtlsshd/gtlsshd.crt";
static const char *default_configfile = SYSCONFDIR "/gtlsshd/gtlsshd.conf";

static void
gshutdown(struct ioinfo *ioinfo)
{
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    ginfo->o->wake(ginfo->waiter);
}

static void
gerr(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    vsyslog(LOG_ERR, fmt, ap);
}

static void
gout(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    /* We shouldn't get any of these. */
}

static struct ioinfo_user_handlers guh = {
    .shutdown = gshutdown,
    .err = gerr,
    .out = gout
};

static void
io_close(struct gensio *io, void *close_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    struct gensio_waiter *closewaiter = close_data;

    ginfo->o->wake(closewaiter);
}

static void
acc_shutdown(struct gensio_accepter *acc, void *done_data)
{
    struct ioinfo *ioinfo = gensio_acc_get_user_data(acc);
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    struct gensio_waiter *closewaiter = done_data;

    ginfo->o->wake(closewaiter);
}

static pam_handle_t *pamh;
static char *passwd;

/*
 * Ambiguity in spec: is it an array of pointers or a pointer to an array?
 * Stolen from openssh.
 */
#ifdef PAM_SUN_CODEBASE
# define PAM_MSG_MEMBER(msg, n, member) ((*(msg))[(n)].member)
#else
# define PAM_MSG_MEMBER(msg, n, member) ((msg)[(n)]->member)
#endif

static int
pam_cb(int num_msg, const struct pam_message **msg,
       struct pam_response **resp, void *appdata_ptr)
{
    int i, j;
    struct pam_response *reply = NULL;

    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
	return PAM_CONV_ERR;

    reply = malloc(sizeof(*reply) * num_msg);
    if (!reply)
	return PAM_CONV_ERR;

    for (i = 0; i < num_msg; i++) {
	reply[i].resp = NULL;
	reply[i].resp_retcode = 0;

	switch (PAM_MSG_MEMBER(msg, i, msg_style)) {
	case PAM_PROMPT_ECHO_OFF:
	    if (passwd) {
		reply[i].resp = strdup(passwd);
		if (!reply[i].resp)
		    goto out_err;
	    }
	    break;

	case PAM_PROMPT_ECHO_ON:
	    break;

	case PAM_ERROR_MSG:
	    syslog(LOG_ERR, "Error from pam: %s",
		   PAM_MSG_MEMBER(msg, i, msg));
	    break;

	case PAM_TEXT_INFO:
	    break;

	default:
	    goto out_err;
	}
    }
    *resp = reply;
    return PAM_SUCCESS;

 out_err:
    for (j = 0; j < i; j++) {
	if (reply[j].resp)
	    free(reply[j].resp);
    }
    free(reply);
    return PAM_CONV_ERR;
}

struct pam_conv auth_conv = { pam_cb, NULL };
static bool pam_cred_set = false;
static bool pam_session_open = false;
static char username[100];
static char *userpgm;

static int
certauth_event(struct gensio *io, int event, int ierr,
	       unsigned char *buf, gensiods *buflen,
	       const char *const *auxdata)
{
    int err;

    switch (event) {
    case GENSIO_EVENT_AUTH_BEGIN: {
	char authdir[1000];
	gensiods len;
	struct passwd *pw;

	len = sizeof(username);
	err = gensio_control(io, 0, true, GENSIO_CONTROL_USERNAME, username,
			     &len);
	if (err) {
	    syslog(LOG_ERR, "No username provided by remote: %s",
		   strerror(err));
	    return EKEYREJECTED;
	}
	pw = getpwnam(username);
	if (!pw) {
	    syslog(LOG_ERR, "Invalid username provided by remote: %s",
		   username);
	    return EKEYREJECTED;
	}

	err = pam_start(progname, username, &auth_conv, &pamh);
	if (err != PAM_SUCCESS) {
	    syslog(LOG_ERR, "pam_start failed for %s: %s", username,
		   pam_strerror(pamh, err));
	    return EINVAL;
	}

	len = snprintf(authdir, sizeof(authdir), "%s/.gtlssh/allowed_certs/",
		       pw->pw_dir);
	err = gensio_control(io, 0, false, GENSIO_CONTROL_CERT_AUTH,
			     authdir, &len);
	if (err) {
	    syslog(LOG_ERR, "Could not set authdir %s: %s", authdir,
		   strerror(err));
	    return EKEYREJECTED;
	}
	userpgm = pw->pw_shell;
	return ENOTSUP;
    }

    case GENSIO_EVENT_PRECERT_VERIFY:
	return ENOTSUP;

    case GENSIO_EVENT_POSTCERT_VERIFY:
	return ENOTSUP;

    case GENSIO_EVENT_PASSWORD_VERIFY:
	passwd = (char *) buf;
	err = pam_authenticate(pamh, PAM_SILENT);
	passwd = NULL;
	if (err != PAM_SUCCESS) {
	    syslog(LOG_ERR, "pam_authenticate failed for %s: %s", username,
		   pam_strerror(pamh, err));
	    return EINVAL;
	}
	return 0;

    default:
	return ENOTSUP;
    }
}

static void
tcp_handle_new(struct gensio_runner *r, void *cb_data)
{
    struct gensio *io = cb_data;
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    int err;
    const char *ssl_args[] = { ginfo->key, ginfo->cert, "mode=server", NULL };
    const char *certauth_args[] = { "mode=server", "allow-authfail", NULL };
    struct gensio *ssl_io, *certauth_io, *pty_io;
    struct ioinfo *pty_ioinfo;
    struct gdata *pty_ginfo;
    char *s;

    ginfo->o->free_runner(r);
    err = ssl_gensio_alloc(io, ssl_args, ginfo->o, NULL, NULL, &ssl_io);
    if (err) {
	syslog(LOG_ERR, "Unable to allocate SSL gensio: %s", strerror(errno));
	exit(1);
    }

    err = gensio_open_nochild_s(ssl_io);
    if (err) {
	syslog(LOG_ERR, "SSL open failed: %s", strerror(errno));
	exit(1);
    }

    err = certauth_gensio_alloc(ssl_io, certauth_args, ginfo->o,
				certauth_event, ioinfo, &certauth_io);
    if (err) {
	syslog(LOG_ERR, "Unable to allocate certauth gensio: %s",
	       strerror(errno));
	exit(1);
    }

    err = gensio_open_nochild_s(certauth_io);
    if (err) {
	syslog(LOG_ERR, "certauth open failed: %s", strerror(errno));
	exit(1);
    }

    ginfo->can_close = true;
    ginfo->io = certauth_io;
    ioinfo_set_ready(ioinfo, certauth_io);

    pty_ioinfo = ioinfo_otherioinfo(ioinfo);
    pty_ginfo = ioinfo_userdata(pty_ioinfo);

    err = pam_acct_mgmt(pamh, PAM_SILENT);
    if (err != PAM_SUCCESS) {
	/* FIXME - handle PAM_NEW_AUTHTOK_REQD */
	syslog(LOG_ERR, "pam_acct_mgmt failed for %s: %s", username,
	       pam_strerror(pamh, err));
	goto out_err;
    }

    err = pam_setcred(pamh, PAM_ESTABLISH_CRED | PAM_SILENT);
    if (err != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_setcred establish failed for %s: %s", username,
	       pam_strerror(pamh, err));
	goto out_err;
    }
    pam_cred_set = true;

    err = pam_open_session(pamh, PAM_SILENT);
    if (err != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_open_session failed for %s: %s", username,
	       pam_strerror(pamh, err));
	goto out_err;
    }
    pam_session_open = true;

    s = alloc_sprintf("pty,%s", userpgm);
    if (!s) {
	syslog(LOG_ERR, "Out of memory allocating program name");
	goto out_err;
    }
    err = str_to_gensio(s, ginfo->o, NULL, NULL, &pty_io);
    free(s);
    if (err) {
	syslog(LOG_ERR, "pty alloc failed: %s", strerror(errno));
	goto out_err;
    }
    err = gensio_open_s(pty_io);
    if (err) {
	syslog(LOG_ERR, "pty open failed: %s", strerror(errno));
	goto out_err;
    }

    pty_ginfo->can_close = true;
    pty_ginfo->io = pty_io;
    ioinfo_set_ready(pty_ioinfo, pty_io);

    return;

 out_err:
    gshutdown(ioinfo);
}

static struct gensio_accepter *tcp_acc;

static int
tcp_acc_event(struct gensio_accepter *accepter, int event, void *data)
{
    struct ioinfo *ioinfo = gensio_acc_get_user_data(accepter);
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    struct gensio *io;
    struct gensio_runner *r;
    int pid, err;

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return ENOTSUP;

    io = data;

    switch ((pid = fork())) {
    case -1:
	syslog(LOG_ERR, "Could not fork: %s", strerror(errno));
	gensio_close(io, NULL, NULL);
	return 0;

    case 0:
	/*
	 * The fork, let the parent have the accepter and double fork
	 * so parent doesn't own us.  We have to tell the os handler,
	 * too that we worked, or epoll() misbehaves.
	 */
	err = ginfo->o->handle_fork(ginfo->o);
	if (err) {
	    syslog(LOG_ERR, "Could not fork gensio handler: %s",
		   strerror(err));
	    exit(1);
	}

	gensio_acc_disable(tcp_acc);
	gensio_acc_free(tcp_acc);
	tcp_acc = NULL;
	setsid();
	switch (fork()) {
	case -1:
	    syslog(LOG_ERR, "Could not fork twice: %s", strerror(errno));
	    exit(1);
	case 0:
	    break;
	default:
	    exit(0);
	}

	/* Since tcp_handle_new does blocking calls, can't do it here. */
	gensio_set_user_data(io, ioinfo);
	r = ginfo->o->alloc_runner(ginfo->o, tcp_handle_new, io);
	if (!r) {
	    syslog(LOG_ERR, "Could not allocate runner");
	    exit(1);
	}
	err = ginfo->o->run(r);
	if (err) {
	    syslog(LOG_ERR, "Could not run runner: %s", strerror(errno));
	    exit(1);
	}
	break;

    default:
	/* The parent, let the child have the gensio. */
	gensio_disable(io);
	gensio_free(io);
	waitpid(pid, NULL, 0);
	break;
    }

    return 0;
}

static const char *io1_default_tty = "serialdev,/dev/tty";
static const char *io1_default_notty = "stdio(self)";

static void
help(int err)
{
    printf("%s [options] io2\n", progname);
    printf("\nA program to connect gensios together.  This programs has two\n");
    printf("gensios, io1 (default is local terminal) and io2 (must be set).\n");
    printf("\noptions are:\n");
    printf("  -i, --input <gensio) - Set the io1 device, default is\n"
	   "    %s for tty or %s for non-tty stdin\n",
	   io1_default_tty, io1_default_notty);
    printf("  -d, --debug - Enable debug.  Specify more than once to increase\n"
	   "    the debug level\n");
    printf("  -a, --accepter - Accept a connection on io2 instead of"
	   " initiating a connection\n");
    printf("  -e, --escchar - Set the local terminal escape character.\n"
	   "    Set to 0 to disable the escape character\n"
	   "    Default is ^\\ for tty stdin and disabled for non-tty stdin\n");
    printf("  -h, --help - This help\n");
    exit(err);
}

static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    if (!debug)
	return;
    syslog(LOG_ERR, "gensio %s log: ", gensio_log_level_to_str(level));
    vsyslog(LOG_ERR, log, args);
}

int
main(int argc, char *argv[])
{
    int arg, rv;
    struct gensio_waiter *closewaiter;
    unsigned int closecount = 0;
    struct gensio_os_funcs *o;
    struct ioinfo *ioinfo1, *ioinfo2;
    struct gdata userdata1, userdata2;
    const char *keyfile = default_keyfile;
    const char *certfile = default_certfile;
    const char *configfile = default_configfile;
    int port = 2190;
    char *s;

    if ((progname = strrchr(argv[0], '/')) == NULL)
	progname = argv[0];
    else
	progname++;

    openlog(progname, 0, LOG_AUTH);
    syslog(LOG_INFO, "%s start", progname);

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != '-')
	    break;
	if (strcmp(argv[arg], "--") == 0) {
	    arg++;
	    break;
	}
	if ((rv = cmparg_int(argc, argv, &arg, "-p", "--port",
			     &port)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-f", "--configfile",
			      &configfile)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-c", "--certfile",
			      &certfile)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-h", "--keyfile",
			      &keyfile)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-d", "--debug", NULL))) {
	    debug++;
	    if (debug > 1)
		gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else if ((rv = cmparg(argc, argv, &arg, "-h", "--help", NULL)))
	    help(0);
	else {
	    fprintf(stderr, "Unknown argument: %s\n", argv[arg]);
	    help(1);
	}
	if (rv < 0)
	    return 1;
    }

    if (checkout_file(keyfile, false))
	return 1;
    if (checkout_file(certfile, false))
	return 1;

    memset(&userdata1, 0, sizeof(userdata1));
    memset(&userdata2, 0, sizeof(userdata2));

    rv = gensio_default_os_hnd(0, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n", strerror(rv));
	return 1;
    }
    o->vlog = do_vlog;

    userdata1.o = o;
    userdata2.o = o;

    userdata1.key = alloc_sprintf("key=%s", keyfile);
    if (!userdata1.key) {
	fprintf(stderr, "Could not allocate keyfile data\n");
	return 1;
    }
    userdata1.cert = alloc_sprintf("cert=%s", certfile);
    if (!userdata1.key) {
	fprintf(stderr, "Could not allocate certfile data\n");
	return 1;
    }

    userdata1.waiter = o->alloc_waiter(o);
    if (!userdata1.waiter) {
	fprintf(stderr, "Could not allocate OS waiter: %s\n", strerror(rv));
	return 1;
    }
    userdata2.waiter = userdata1.waiter;

    closewaiter = o->alloc_waiter(o);
    if (!closewaiter) {
	fprintf(stderr, "Could not allocate close waiter: %s\n", strerror(rv));
	return 1;
    }

    ioinfo1 = alloc_ioinfo(o, -1, NULL, NULL, &guh, &userdata1);
    if (!ioinfo1) {
	fprintf(stderr, "Could not allocate ioinfo 1\n");
	return 1;
    }

    ioinfo2 = alloc_ioinfo(o, -1, NULL, NULL, &guh, &userdata2);
    if (!ioinfo2) {
	fprintf(stderr, "Could not allocate ioinfo 2\n");
	return 1;
    }

    ioinfo_set_otherioinfo(ioinfo1, ioinfo2);

    s = alloc_sprintf("tcp,%d", port);

    rv = str_to_gensio_accepter(s, o, tcp_acc_event, ioinfo1, &tcp_acc);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", s, strerror(rv));
	return 1;
    }

    rv = gensio_acc_startup(tcp_acc);
    if (rv) {
	fprintf(stderr, "Could not start %s: %s\n", s, strerror(rv));
	return 1;
    }

    o->wait(userdata1.waiter, 1, NULL);

    if (tcp_acc) {
	rv = gensio_acc_shutdown(tcp_acc, acc_shutdown, closewaiter);
	if (rv)
	    syslog(LOG_ERR, "Unable to close accepter: %s", strerror(rv));
	else
	    closecount++;
    }

    if (userdata1.can_close) {
	rv = gensio_close(userdata1.io, io_close, closewaiter);
	if (rv)
	    syslog(LOG_ERR, "Unable to close net connection: %s",
		   strerror(rv));
	else
	    closecount++;
    }

    if (userdata2.can_close) {
	rv = gensio_close(userdata2.io, io_close, closewaiter);
	if (rv)
	    syslog(LOG_ERR, "Unable to close pty: %s", strerror(rv));
	else
	    closecount++;
    }

    if (closecount > 0) {
	o->wait(closewaiter, closecount, NULL);
    }

    if (userdata1.io)
	gensio_free(userdata1.io);
    if (userdata2.io)
	gensio_free(userdata2.io);
    if (tcp_acc)
	gensio_acc_free(tcp_acc);

    o->free_waiter(closewaiter);
    o->free_waiter(userdata1.waiter);

    free_ioinfo(ioinfo1);
    free_ioinfo(ioinfo2);

    if (pam_session_open) {
	rv = pam_close_session(pamh, PAM_SILENT);
	if (rv != PAM_SUCCESS)
	    syslog(LOG_ERR, "pam_close_session failed for %s: %s", username,
		   pam_strerror(pamh, rv));
    }

    if (pam_cred_set) {
	rv = pam_setcred(pamh, PAM_DELETE_CRED | PAM_SILENT);
	if (rv != PAM_SUCCESS)
	    syslog(LOG_ERR, "pam_setcred delete failed for %s: %s", username,
		   pam_strerror(pamh, rv));
    }

    return 0;
}
