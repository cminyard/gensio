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
#include <assert.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <gensio/gensio.h>
#include <gensio/gensio_builtins.h>
#include <gensio/gensio_list.h>

#include "ioinfo.h"
#include "ser_ioinfo.h"
#include "utils.h"

unsigned int debug;
bool oneshot;
static const char *progname;

struct gdata {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    char *key;
    char *cert;

    struct gensio *rem_io;

    unsigned int closecount;
    struct gensio_list cons;
};

struct per_con_info {
    struct gdata *ginfo;

    /* Incoming connection from the remote. */
    struct gensio *io1;
    bool io1_can_close;
    struct ioinfo *ioinfo1;

    /* Local connection. */
    struct gensio *io2;
    bool io2_can_close;
    struct ioinfo *ioinfo2;

    struct gensio_link link;
};

static char *default_keyfile = SYSCONFDIR "/gtlssh/gtlsshd.key";
static char *default_certfile = SYSCONFDIR "/gtlssh/gtlsshd.crt";
static char *default_configfile = SYSCONFDIR "/gtlssh/gtlsshd.conf";

static char *pid_file = NULL;

static void
make_pidfile(void)
{
    FILE *fpidfile;

    if (!pid_file)
	return;
    fpidfile = fopen(pid_file, "w");
    if (!fpidfile) {
	syslog(LOG_WARNING,
	       "Error opening pidfile '%s': %m, pidfile not created",
	       pid_file);
	pid_file = NULL;
	return;
    }
    fprintf(fpidfile, "%d\n", getpid());
    fclose(fpidfile);
}

static void
closecount_decr(struct gdata *ginfo)
{
    assert(ginfo->closecount > 0);
    ginfo->closecount--;
    if (ginfo->closecount == 0)
	ginfo->o->wake(ginfo->waiter);
}

static void
io_close(struct gensio *io, void *close_data)
{
    struct per_con_info *pcinfo = close_data;
    struct gdata *ginfo = pcinfo->ginfo;

    if (io == pcinfo->io1)
	pcinfo->io1 = NULL;
    else if (io == pcinfo->io2)
	pcinfo->io2 = NULL;
    else
	abort();

    gensio_free(io);

    if (pcinfo->io1 == NULL && pcinfo->io2 == NULL) {
	free(pcinfo->ioinfo1);
	free(pcinfo->ioinfo2);
	free(pcinfo);
    }

    closecount_decr(ginfo);
}

static void
close_con_info(struct per_con_info *pcinfo)
{
    struct gdata *ginfo = pcinfo->ginfo;
    int err;

    gensio_list_rm(&ginfo->cons, &pcinfo->link);
    if (pcinfo->io1_can_close) {
	pcinfo->io1_can_close = false;
	err = gensio_close(pcinfo->io1, io_close, pcinfo);
	if (err) {
	    syslog(LOG_ERR, "Unable to close remote: %s",
		   gensio_err_to_str(err));
	    ginfo->closecount--;
	}
    }

    if (pcinfo->io2_can_close) {
	pcinfo->io2_can_close = false;
	err = gensio_close(pcinfo->io2, io_close, pcinfo);
	if (err) {
	    syslog(LOG_ERR, "Unable to close local: %s",
		   gensio_err_to_str(err));
	    ginfo->closecount--;
	}
    }
}

static void
gshutdown(struct ioinfo *ioinfo, bool user_req)
{
    struct per_con_info *pcinfo = ioinfo_userdata(ioinfo);
    struct gdata *ginfo = pcinfo->ginfo;

    if (user_req) {
	ginfo->o->wake(ginfo->waiter);
    } else {
	close_con_info(pcinfo);
	if (ginfo->closecount == 0)
	    ginfo->o->wake(ginfo->waiter);
    }
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
acc_shutdown(struct gensio_accepter *acc, void *done_data)
{
    struct gdata *ginfo = done_data;

    closecount_decr(ginfo);
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

static bool
strstartswith(const char *str, const char *cmp)
{
    if (strncmp(str, cmp, strlen(cmp)) == 0)
	return true;
    return false;
}

static struct pam_conv auth_conv = { pam_cb, NULL };

static bool permit_root = false;
static bool pw_login = false;

static bool pam_started = false;
static bool pam_cred_set = false;
static char username[100];
static char *homedir;
static int pam_err;
static uid_t uid = -1;
static gid_t gid = -1;

static int
get_vals_from_service(char ***rvals, unsigned int *rvlen,
		      char *str, gensiods len)
{
    unsigned int i;
    static char **vals = NULL;
    unsigned int vlen = 0;

    /*
     * Scan for a double nil that marks the end, counting the number
     * of items we find along the way.
     */
    for (i = 0; str[i]; ) {
	for (; str[i]; i++) {
	    if (i >= len)
		return GE_INVAL;
	}
	if (++i >= len)
	    return GE_INVAL;
	vlen++;
    }
    if (vlen == 0)
	return 0;

    vals = malloc((vlen + 1) * sizeof(char *));
    if (!vals)
	return GE_NOMEM;

    /* Rescan, setting the variable array items. */
    *rvals = vals;
    if (rvlen)
	*rvlen = vlen;
    for (i = 0; str[i]; ) {
	*vals++ = str + i;
	for (; str[i]; i++)
	    ;
	i++;
    }
    *vals = NULL;
    return 0;
}

static int
certauth_event(struct gensio *io, void *user_data, int event, int ierr,
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
		   gensio_err_to_str(err));
	    return GE_AUTHREJECT;
	}
	pw = getpwnam(username);
	if (!pw) {
	    syslog(LOG_ERR, "Invalid username provided by remote: %s",
		   username);
	    return GE_AUTHREJECT;
	}
	if (!permit_root &&
			(strcmp(username, "root") == 0 || pw->pw_uid == 0)) {
	    syslog(LOG_ERR, "Root login not permitted");
	    return GE_AUTHREJECT;
	}
	uid = pw->pw_uid;
	gid = pw->pw_gid;

	pam_err = pam_start(progname, username, &auth_conv, &pamh);
	if (pam_err != PAM_SUCCESS) {
	    syslog(LOG_ERR, "pam_start failed for %s: %s", username,
		   pam_strerror(pamh, pam_err));
	    return GE_AUTHREJECT;
	}
	pam_started = true;
	homedir = pw->pw_dir;

	len = snprintf(authdir, sizeof(authdir), "%s/.gtlssh/allowed_certs/",
		       pw->pw_dir);
	err = gensio_control(io, 0, false, GENSIO_CONTROL_CERT_AUTH,
			     authdir, &len);
	if (err) {
	    syslog(LOG_ERR, "Could not set authdir %s: %s", authdir,
		   gensio_err_to_str(err));
	    return GE_NOTSUP;
	}

	return GE_NOTSUP;
    }

    case GENSIO_EVENT_PRECERT_VERIFY:
	return GE_NOTSUP;

    case GENSIO_EVENT_POSTCERT_VERIFY:
	if (ierr && !pw_login) {
	    syslog(LOG_ERR, "certificate failed verify for %s, "
		   "passwords disabled: %s\n", username,
		   auxdata[0] ? auxdata[0] : "");
	    return GE_AUTHREJECT;
	}
	if (!ierr)
	    syslog(LOG_INFO, "Accepted certificate for %s\n", username);
	return GE_NOTSUP;

    case GENSIO_EVENT_PASSWORD_VERIFY:
	passwd = (char *) buf;
	pam_err = pam_authenticate(pamh, PAM_SILENT);
	passwd = NULL;
	if (pam_err == PAM_AUTH_ERR) {
	    return GE_NOTSUP;
	} else if (pam_err != PAM_SUCCESS) {
	    syslog(LOG_ERR, "pam_authenticate failed for %s: %s", username,
		   pam_strerror(pamh, pam_err));
	    return GE_INVAL;
	}
	syslog(LOG_INFO, "Accepted password for %s\n", username);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
gensio_pam_cb(int num_msg, const struct pam_message **msg,
	      struct pam_response **resp, void *appdata_ptr)
{
    int i, j, err;
    struct pam_response *reply = NULL;
    struct gdata *ginfo = appdata_ptr;
    struct gensio *io = ginfo->rem_io;
    char buf[100];
    struct timeval timeout = { 60, 0 };

    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG)
	return PAM_CONV_ERR;

    reply = malloc(sizeof(*reply) * num_msg);
    if (!reply)
	return PAM_CONV_ERR;

    for (i = 0; i < num_msg; i++) {
	int style = PAM_MSG_MEMBER(msg, i, msg_style);
	const char *msgdata = PAM_MSG_MEMBER(msg, i, msg);
	gensiods len;

	reply[i].resp = NULL;
	reply[i].resp_retcode = 0;

	switch (style) {
	case PAM_PROMPT_ECHO_OFF:
	case PAM_PROMPT_ECHO_ON:
	    if (msgdata) {
		err = write_str_to_gensio(msgdata, io, &timeout, true);
		if (err)
		    goto out_err;
	    }
	    len = sizeof(buf);
	    err = read_rsp_from_gensio(buf, &len, io, &timeout,
				       style == PAM_PROMPT_ECHO_ON);
	    write_str_to_gensio("\n", io, &timeout, true);
	    if (err == GE_TIMEDOUT)
		write_str_to_gensio("Timed out waiting for respnse\n",
				    io, &timeout, true);
	    if (err)
		goto out_err;
	    reply[i].resp = strdup(buf);
	    memset(buf, 0, len);
	    /*
	     * FIXME - we scrub the above buffer, but should we scrub
	     * the buffers from io?  gensio currently doesn't have a
	     * way to do it, and the bytes generally come in one at a
	     * time, and will be overwritten pretty quickly, anyway.
	     */
	    if (!reply[i].resp)
		goto out_err;
	    break;

	case PAM_ERROR_MSG:
	case PAM_TEXT_INFO:
	    write_str_to_gensio(msgdata, io, &timeout, true);
	    write_str_to_gensio("\n", io, &timeout, true);
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

static struct pam_conv gensio_conv = { gensio_pam_cb, NULL };
static char **pam_env;

static void
new_rem_io(struct gensio *io, struct gdata *ginfo)
{
    struct gensio_os_funcs *o = ginfo->o;
    struct per_con_info *pcinfo;
    struct gensio *pty_io;
    gensiods len;
    char *s;
    int err;
    char **progv = NULL; /* If set in the service. */
    char *service = NULL;
    char **env = NULL;
    unsigned int env_len;
    unsigned int i, j;

    len = 0;
    err = gensio_control(io, 0, true, GENSIO_CONTROL_SERVICE,
			 NULL, &len);
    if (err) {
	struct timeval timeout = {10, 0};

	write_str_to_gensio("No service set on this connection\n",
			    io, &timeout, true);
	goto out_free;
    }
    len++; /* Add terminating nil. */
    service = malloc(len);
    if (!service) {
	syslog(LOG_ERR, "Could not allocate service memory");
	goto out_free;
    }
    err = gensio_control(io, 0, true, GENSIO_CONTROL_SERVICE,
			 service, &len);
    if (err) {
	syslog(LOG_ERR, "Could not get service(2): %s",
	       gensio_err_to_str(err));
	goto out_free;
    }
    if (strstartswith(service, "program:")) {
	char *str = strchr(service, ':') + 1;

	len -= str - service;
	err = get_vals_from_service(&progv, NULL, str, len);
    out_bad_vals:
	if (err) {
	    struct timeval timeout = {10, 0};

	    write_str_to_gensio("Could not get vals from service",
				io, &timeout, true);
	    goto out_free;
	}
    } else if (strstartswith(service, "login:")) {
	char *str = strchr(service, ':') + 1;

	len -= str - service;
	err = get_vals_from_service(&env, &env_len, str, len);
	if (err)
	    goto out_bad_vals;
    } else {
	struct timeval timeout = {10, 0};

	write_str_to_gensio("Unknown service", io, &timeout, true);
	goto out_free;
    }

    if (env_len > 0) {
	char **penv2;

	for (i = 0; pam_env[i]; i++)
	    ;
	penv2 = malloc((i + env_len + 1) * sizeof(char *));
	if (!penv2) {
	    syslog(LOG_ERR, "Failure to reallocate env for %s", username);
	    exit(1);
	}
	for (i = 0; pam_env[i]; i++)
	    penv2[i] = pam_env[i];
	for (j = 0; j < env_len; i++, j++)
	    penv2[i] = env[j];
	penv2[i] = NULL;
	free(env);
	env = penv2;
    }

    pcinfo = malloc(sizeof(*pcinfo));
    if (!pcinfo) {
	syslog(LOG_ERR, "Unable to allocate SSL pc info");
	goto out_free;
    }
    memset(pcinfo, 0, sizeof(*pcinfo));
    pcinfo->ginfo = ginfo;

    pcinfo->ioinfo1 = alloc_ioinfo(o, -1, NULL, NULL, &guh, pcinfo);
    if (!pcinfo->ioinfo1) {
	syslog(LOG_ERR, "Could not allocate ioinfo 1\n");
	goto out_free;
    }

    pcinfo->ioinfo2 = alloc_ioinfo(o, -1, NULL, NULL, &guh, pcinfo);
    if (!pcinfo->ioinfo2) {
	syslog(LOG_ERR, "Could not allocate ioinfo 2\n");
	goto out_free;
    }

    ioinfo_set_otherioinfo(pcinfo->ioinfo1, pcinfo->ioinfo2);

    gensio_set_user_data(io, pcinfo->ioinfo1);

    ginfo->rem_io = NULL;
    gensio_list_add_tail(&ginfo->cons, &pcinfo->link);
    pcinfo->io1_can_close = true;
    ginfo->closecount++;
    pcinfo->io1 = io;

    if (progv) {
	/* Dummy out the program, we will set it later with a control. */
	s = alloc_sprintf("stdio(stderr-to-stdout),dummy");
    } else {
	err = gensio_control(io, GENSIO_CONTROL_DEPTH_ALL, false,
			     GENSIO_CONTROL_NODELAY, "1", NULL);
	if (err) {
	    fprintf(stderr, "Could not set nodelay: %s\n",
		    gensio_err_to_str(err));
	    goto out_err;
	}

	/*
	 * Let login handle everything else.  If the password
	 * authentication from pam succeeded, don't ask for password.
	 */
	s = alloc_sprintf("pty,/bin/login -f -p %s", username);
    }
    if (!s) {
	syslog(LOG_ERR, "Out of memory allocating program name");
	goto out_err;
    }
    err = str_to_gensio(s, o, NULL, NULL, &pty_io);
    free(s);
    if (err) {
	syslog(LOG_ERR, "pty alloc failed: %s", gensio_err_to_str(err));
	goto out_err;
    }
    pcinfo->io2 = pty_io;

    if (progv) {
	err = gensio_control(pty_io, 0, false, GENSIO_CONTROL_ARGS,
			     (char *) progv, NULL);
	if (err) {
		syslog(LOG_ERR, "Setting program arguments failed: %s",
		       gensio_err_to_str(err));
		goto out_err;
	}
    }

    err = gensio_control(pty_io, 0, false, GENSIO_CONTROL_ENVIRONMENT,
			 (char *) pam_env, NULL);
    if (err) {
	syslog(LOG_ERR, "set env failed for %s: %s", username,
	       gensio_err_to_str(err));
	goto out_err;
    }

    if (progv) {
	err = setegid(gid);
	if (err) {
	    syslog(LOG_ERR, "setgid failed: %s", strerror(errno));
	    goto out_err;
	}
	err = seteuid(uid);
	if (err) {
	    syslog(LOG_ERR, "setuid failed: %s", strerror(errno));
	    goto out_err;
	}
    }
    err = gensio_open_s(pty_io);
    if (progv) {
	int err2;
	err2 = seteuid(getuid());
	if (err2)
	    syslog(LOG_WARNING, "reset setuid failed: %s", strerror(errno));
	err2 = setegid(getgid());
	if (err2)
	    syslog(LOG_WARNING, "reset setgid failed: %s", strerror(errno));
    }
    if (err) {
	syslog(LOG_ERR, "pty open failed: %s", gensio_err_to_str(err));
	goto out_err;
    }
    pcinfo->io2_can_close = true;
    ginfo->closecount++;

    ioinfo_set_ready(pcinfo->ioinfo1, io);
    ioinfo_set_ready(pcinfo->ioinfo2, pty_io);
    io = NULL;
    goto out_free;

 out_err:
    gshutdown(pcinfo->ioinfo1, false);
    io = NULL;

 out_free:
    if (io)
	gensio_free(io);
    if (env)
	free(env);
    if (progv)
	free(progv);
    if (service)
	free(service);
}

static void
handle_new(struct gensio_runner *r, void *cb_data)
{
    struct gensio *net_io = cb_data;
    struct gdata *ginfo = gensio_get_user_data(net_io);
    struct gensio_os_funcs *o = ginfo->o;
    int err;
    const char *ssl_args[] = { ginfo->key, ginfo->cert, "mode=server", NULL };
    const char *certauth_args[] = { "mode=server", "allow-authfail", NULL,
				    NULL };
    struct gensio *ssl_io, *certauth_io;
    gensiods len;
    char tmpservice[20];
    bool interactive = false;

    o->free_runner(r);

    err = ssl_gensio_alloc(net_io, ssl_args, o, NULL, NULL, &ssl_io);
    if (err) {
	syslog(LOG_ERR, "Unable to allocate SSL gensio: %s",
	       gensio_err_to_str(errno));
	exit(1);
    }

    err = gensio_open_nochild_s(ssl_io);
    if (err) {
	syslog(LOG_ERR, "SSL open failed: %s", gensio_err_to_str(errno));
	exit(1);
    }

    if (pw_login)
	certauth_args[2] = "enable-password";
    err = certauth_gensio_alloc(ssl_io, certauth_args, o,
				certauth_event, NULL, &certauth_io);
    if (err) {
	syslog(LOG_ERR, "Unable to allocate certauth gensio: %s",
	       gensio_err_to_str(errno));
	exit(1);
    }

    err = gensio_open_nochild_s(certauth_io);
    if (err) {
	syslog(LOG_ERR, "certauth open failed: %s", gensio_err_to_str(err));
	exit(1);
    }

    /* FIXME - figure out a way to unstack certauth_io after authentication */

    ginfo->rem_io = certauth_io;

    gensio_conv.appdata_ptr = ginfo;
    pam_err = pam_set_item(pamh, PAM_CONV, &gensio_conv);
    if (pam_err) {
	syslog(LOG_ERR, "Unable to set PAM_CONV");
	exit(1);
    }

    if (!gensio_is_authenticated(certauth_io)) {
	int tries = 3;

	do {
	    struct timeval timeout = {10, 0};

	    write_str_to_gensio("Permission denied, please try again\n",
				certauth_io, &timeout, true);
	    pam_err = pam_authenticate(pamh, 0);
	    tries--;
	} while (pam_err != PAM_SUCCESS && tries > 0);

	if (pam_err != PAM_SUCCESS) {
	    struct timeval timeout = {10, 0};

	    write_str_to_gensio("Too many tries, giving up\n", certauth_io,
				&timeout, true);
	    syslog(LOG_ERR, "Too many login tries for %s\n", username);
	    exit(1);
	}
	syslog(LOG_INFO, "Accepted password for %s\n", username);
	/* FIXME - gensio_set_is_authenticated(certauth_io, true); */
    }

    len = sizeof(tmpservice);
    err = gensio_control(certauth_io, 0, true, GENSIO_CONTROL_SERVICE,
			 tmpservice, &len);
    if (err) {
	struct timeval timeout = {10, 0};
	write_str_to_gensio("Could not get service\n", certauth_io,
			    &timeout, true);
	exit(1);
    }
    if (strstartswith(tmpservice, "login:"))
	interactive = true;

    if (file_is_readable("/etc/nologin") && uid != 0) {
	struct timeval timeout = {10, 0};
	if (interactive)
	    /* Don't send this to non-interactive logins. */
	    write_file_to_gensio("/etc/nologin", certauth_io, o, &timeout, true);
	exit(1);
    }

    pam_err = pam_acct_mgmt(pamh, 0);
    if (pam_err == PAM_NEW_AUTHTOK_REQD) {
	if (interactive) {
	    syslog(LOG_ERR, "user %s password expired, non-interactive login",
		   username);
	    exit(1);
	}
	pam_err = pam_chauthtok(pamh, 0);
	if (pam_err != PAM_SUCCESS) {
	    syslog(LOG_ERR, "Changing password for %s failed", username);
	    exit(1);
	}
    } else if (pam_err != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_acct_mgmt failed for %s: %s", username,
	       pam_strerror(pamh, pam_err));
	exit(1);
    }

    pam_err = pam_setcred(pamh, PAM_ESTABLISH_CRED | PAM_SILENT);
    if (pam_err != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_setcred failed for %s: %s", username,
	       pam_strerror(pamh, pam_err));
	exit(1);
    }
    pam_cred_set = true;

    if (chdir(homedir)) {
	syslog(LOG_WARNING, "chdir failed for %s to %s: %s", username,
	       homedir, strerror(errno));
    }

    pam_env = pam_getenvlist(pamh);
    if (!pam_env) {
	syslog(LOG_ERR, "pam_getenvlist failed for %s", username);
	exit(1);
    }
    /* login will open the session, don't do it here. */

    /* At this point we are fully authenticated and have all global info. */

    new_rem_io(certauth_io, ginfo);
    return;
}

static struct gensio_accepter *tcp_acc, *sctp_acc;

static int
acc_event(struct gensio_accepter *accepter, void *user_data,
	  int event, void *data)
{
    struct gdata *ginfo = gensio_acc_get_user_data(accepter);
    struct gensio_os_funcs *o = ginfo->o;
    struct gensio *io;
    struct gensio_runner *r;
    int pid, err;

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return ENOTSUP;

    io = data;

    if (oneshot)
	goto skip_fork;

    switch ((pid = fork())) {
    case -1:
	syslog(LOG_ERR, "Could not fork: %s", strerror(errno));
	err = gensio_close(io, NULL, NULL);
	if (err)
	    syslog(LOG_ERR, "Could not close after fork: %s",
		   gensio_err_to_str(err));
	return 0;

    case 0:
	/*
	 * The fork, let the parent have the accepter and double fork
	 * so parent doesn't own us.  We have to tell the os handler,
	 * too that we forked, or epoll() misbehaves.
	 */
	err = o->handle_fork(o);
	if (err) {
	    syslog(LOG_ERR, "Could not fork gensio handler: %s",
		   gensio_err_to_str(err));
	    exit(1);
	}

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

    skip_fork:
	if (tcp_acc) {
	    gensio_acc_disable(tcp_acc);
	    gensio_acc_free(tcp_acc);
	    tcp_acc = NULL;
	}
	if (sctp_acc) {
	    gensio_acc_disable(sctp_acc);
	    gensio_acc_free(sctp_acc);
	    sctp_acc = NULL;
	}

	/* Since handle_new does blocking calls, can't do it here. */
	gensio_set_user_data(io, ginfo); /* Just temporarily. */
	r = o->alloc_runner(o, handle_new, io);
	if (!r) {
	    syslog(LOG_ERR, "Could not allocate runner");
	    exit(1);
	}
	err = o->run(r);
	if (err) {
	    syslog(LOG_ERR, "Could not run runner: %s",
		   gensio_err_to_str(errno));
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

static void
help(int err)
{
    printf("%s [options]\n", progname);
    printf("\nA program to connect gensios together.  This programs has two\n");
    printf("gensios, io1 (default is local terminal) and io2 (must be set).\n");
    printf("\noptions are:\n");
    printf("  -p, --port <port>) - Use the given port instead of "
	   "the default\n");
    printf("  -d, --debug - Enable debug.  Specify more than once to increase\n"
	   "    the debug level\n");
    printf("  -c, --certfile <file> - The certificate file to use.\n");
    printf("  -h, --keyfile <file> - The private key file to use.\n");
    printf("  --permit-root - Allow root logins.\n");
    printf("  --allow-password - Allow password-based logins.\n");
    printf("  --oneshot - Do not fork new connections, do one and exit.\n");
    printf("  --nodaemon - Do not daemonize.\n");
    printf("  --nosctp - Disable SCTP support.\n");
    printf("  --notcp - Disable TCP support.\n");
    printf("  -P, --pidfile <file> - Create the given pidfile.\n");
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

static void
close_cons(struct gdata *ginfo)
{
    struct gensio_link *l;

    gensio_list_for_each(&ginfo->cons, l) {
	struct per_con_info *pcinfo = gensio_container_of(l, struct per_con_info,
							  link);

	close_con_info(pcinfo);
    }
}

int
main(int argc, char *argv[])
{
    int arg, rv;
    struct gensio_os_funcs *o;
    struct gdata ginfo;
    char *keyfile = default_keyfile;
    char *certfile = default_certfile;
    char *configfile = default_configfile;
    int port = 852;
    char *s;
    bool notcp = false, nosctp = false;
    bool daemonize = true;

    if ((progname = strrchr(argv[0], '/')) == NULL)
	progname = argv[0];
    else
	progname++;

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
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--notcp", NULL)))
	    notcp = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--nosctp", NULL)))
	    nosctp = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--permit-root", NULL)))
	    permit_root = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--allow-password", NULL)))
	    pw_login = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--oneshot", NULL)))
	    oneshot = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--nodaemon", NULL)))
	    daemonize = false;
	else if ((rv = cmparg(argc, argv, &arg, "-P", "--pidfile", &pid_file)))
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

    if (nosctp && notcp) {
	fprintf(stderr, "You cannot disable both TCP and SCTP\n");
	exit(1);
    }

    if (checkout_file(keyfile, false, true))
	return 1;
    if (checkout_file(certfile, false, false))
	return 1;

    memset(&ginfo, 0, sizeof(ginfo));
    gensio_list_init(&ginfo.cons);

    rv = gensio_default_os_hnd(0, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    o->vlog = do_vlog;

    ginfo.o = o;

    ginfo.key = alloc_sprintf("key=%s", keyfile);
    if (!ginfo.key) {
	fprintf(stderr, "Could not allocate keyfile data\n");
	return 1;
    }
    ginfo.cert = alloc_sprintf("cert=%s", certfile);
    if (!ginfo.key) {
	fprintf(stderr, "Could not allocate certfile data\n");
	return 1;
    }

    ginfo.waiter = o->alloc_waiter(o);
    if (!ginfo.waiter) {
	fprintf(stderr, "Could not allocate OS waiter\n");
	return 1;
    }

    if (!notcp) {
	s = alloc_sprintf("tcp,%d", port);
	if (!s) {
	    fprintf(stderr, "Could not allocate tcp descriptor\n");
	    return 1;
	}

	rv = str_to_gensio_accepter(s, o, acc_event, &ginfo, &tcp_acc);
	if (rv) {
	    fprintf(stderr, "Could not allocate %s: %s\n", s,
		    gensio_err_to_str(rv));
	    free(s);
	    return 1;
	}
	free(s);

	rv = gensio_acc_startup(tcp_acc);
	if (rv) {
	    fprintf(stderr, "Could not start TCP accepter: %s\n",
		    gensio_err_to_str(rv));
	    return 1;
	}
    }

    if (!nosctp) {
	s = alloc_sprintf("sctp,%d", port);
	if (!s) {
	    fprintf(stderr, "Could not allocate sctp descriptor\n");
	    return 1;
	}

	rv = str_to_gensio_accepter(s, o, acc_event, &ginfo, &sctp_acc);
	if (rv == GE_NOTSUP) {
	    /* No SCTP support */
	    free(s);
	    goto start_io;
	}

	if (rv) {
	    fprintf(stderr, "Could not allocate %s: %s\n", s,
		    gensio_err_to_str(rv));
	    free(s);
	    return 1;
	}
	free(s);

	rv = gensio_acc_startup(sctp_acc);
	if (rv) {
	    fprintf(stderr, "Could not start SCTP accepter: %s\n",
		    gensio_err_to_str(rv));
	    return 1;
	}
    }

 start_io:
    if (!oneshot)
	openlog(progname, 0, LOG_AUTH);
    else
	openlog(progname, LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
    syslog(LOG_NOTICE, "gtlsshd startup");
    if (!oneshot && daemonize) {
	pid_t pid;

	if ((pid = fork()) > 0) {
	    exit(0);
	} else if (pid < 0) {
	    fprintf(stderr, "Error forking first fork: %s", strerror(errno));
	    exit(1);
	} else {
	    /* setsid() is necessary if we really want to demonize */
	    setsid();
	    /* Second fork to really deamonize me. */
	    if ((pid = fork()) > 0) {
		exit(0);
	    } else if (pid < 0) {
		syslog(LOG_ERR, "Error forking second fork: %s",
		       strerror(errno));
		exit(1);
	    }
	}
	o->handle_fork(o);

	/* Close all my standard I/O. */
	if (chdir("/") < 0) {
	    syslog(LOG_ERR, "unable to chdir to '/': %s", strerror(errno));
	    exit(1);
	}
	close(0);
	close(1);
	close(2);

	make_pidfile();
    }

    o->wait(ginfo.waiter, 1, NULL);

    if (tcp_acc) {
	ginfo.closecount++;
	rv = gensio_acc_shutdown(tcp_acc, acc_shutdown, &ginfo);
	if (rv) {
	    syslog(LOG_ERR, "Unable to close accepter: %s",
		   gensio_err_to_str(rv));
	    ginfo.closecount--;
	}
    }

    if (sctp_acc) {
	ginfo.closecount++;
	rv = gensio_acc_shutdown(sctp_acc, acc_shutdown, &ginfo);
	if (rv) {
	    syslog(LOG_ERR, "Unable to close accepter: %s",
		   gensio_err_to_str(rv));
	    ginfo.closecount--;
	}
    }

    close_cons(&ginfo);

    if (ginfo.closecount > 0)
	o->wait(ginfo.waiter, 1, NULL);

    if (tcp_acc)
	gensio_acc_free(tcp_acc);
    if (sctp_acc)
	gensio_acc_free(sctp_acc);

    free(ginfo.key);
    free(ginfo.cert);

    o->free_waiter(ginfo.waiter);

    if (pam_cred_set) {
	pam_err = pam_setcred(pamh, PAM_DELETE_CRED | PAM_SILENT);
	if (pam_err != PAM_SUCCESS)
	    syslog(LOG_ERR, "pam_setcred delete failed for %s: %s", username,
		   pam_strerror(pamh, pam_err));
    }

    if (pam_started) {
	rv = pam_end(pamh, pam_err);
	if (rv != PAM_SUCCESS)
	    syslog(LOG_ERR, "pam_en failed for %s: %s", username,
		   pam_strerror(pamh, rv));
    }

    if (pam_env) {
	unsigned int i;

	for (i = 0; pam_env[i]; i++)
	    free(pam_env[i]);
	free(pam_env);
    }

    if (pid_file)
	unlink(pid_file);

    return 0;
}
