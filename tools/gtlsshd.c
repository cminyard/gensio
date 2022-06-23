/*
 *  gtlsshd - An secure shell server over TS
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  gensio give you permission to combine gensio with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for gensio and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of gensio are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h> /* For htonl and friends. */

#include <security/pam_appl.h>

#include <gensio/gensio.h>
#include <gensio/gensio_builtins.h>
#include <gensio/gensio_list.h>

#include "ioinfo.h"
#include "localports.h"
#include "ser_ioinfo.h"
#include "utils.h"
#include "gtlssh.h"

/* Default the program to this path. */
#define STANDARD_PATH "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

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

    bool is_pty;

    /* A 3-byte header and a 65535 byte payload. */
    unsigned char oobbuf[65538];
    unsigned int ooblen;
    unsigned int oobpos;
};

static const char *default_keyfile = SYSCONFDIR "/gtlssh/gtlsshd.key";
static const char *default_certfile = SYSCONFDIR "/gtlssh/gtlsshd.crt";
static const char *default_configfile = SYSCONFDIR "/gtlssh/gtlsshd.conf";

static const char *pid_file = NULL;

static int
write_s_nl_addc(struct gensio *io, char *obuf, char c,
		gensiods *pos, gensiods len, gensio_time *timeout)
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
	   gensio_time *timeout)
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

static int
write_file_to_gensio(const char *filename, struct gensio *io,
		     struct gensio_os_funcs *o, gensio_time *timeout,
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

static int
write_buf_to_gensio(const char *buf, gensiods len, struct gensio *io,
		    gensio_time *timeout, bool xlatnl)
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

static int
write_str_to_gensio(const char *str, struct gensio *io,
		    gensio_time *timeout, bool xlatnl)
{
    return write_buf_to_gensio(str, strlen(str), io, timeout, xlatnl);
}

static int
read_rsp_from_gensio(char *buf, gensiods *len, struct gensio *io,
		     gensio_time *timeout, bool echo)
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
	gensio_os_funcs_wake(ginfo->o, ginfo->waiter);
}

static void
io_finish_close(struct per_con_info *pcinfo)
{
    if (pcinfo->io1 == NULL && pcinfo->io2 == NULL) {
	free(pcinfo->ioinfo1);
	free(pcinfo->ioinfo2);
	free(pcinfo);
    }
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
    io_finish_close(pcinfo);

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
	    gensio_free(pcinfo->io1);
	    pcinfo->io1 = NULL;
	}
    } else if (pcinfo->io1) {
	gensio_free(pcinfo->io1);
	pcinfo->io1 = NULL;
    }

    if (pcinfo->io2_can_close) {
	pcinfo->io2_can_close = false;
	err = gensio_close(pcinfo->io2, io_close, pcinfo);
	if (err) {
	    syslog(LOG_ERR, "Unable to close local: %s",
		   gensio_err_to_str(err));
	    ginfo->closecount--;
	    gensio_free(pcinfo->io2);
	    pcinfo->io2 = NULL;
	}
    } else if (pcinfo->io2) {
	gensio_free(pcinfo->io2);
	pcinfo->io2 = NULL;
    }
    io_finish_close(pcinfo);
}

static void
gshutdown(struct ioinfo *ioinfo, bool user_req)
{
    struct per_con_info *pcinfo = ioinfo_userdata(ioinfo);
    struct gdata *ginfo = pcinfo->ginfo;

    if (user_req) {
	gensio_os_funcs_wake(ginfo->o, ginfo->waiter);
    } else {
	close_con_info(pcinfo);
	if (ginfo->closecount == 0)
	    gensio_os_funcs_wake(ginfo->o, ginfo->waiter);
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

static int mux_event(struct gensio *io, void *user_data, int event, int ierr,
		     unsigned char *buf, gensiods *buflen,
		     const char *const *auxdata);

static int gevent(struct ioinfo *ioinfo, struct gensio *io, int event,
		  int ierr, unsigned char *buf, gensiods *buflen,
		  const char *const *auxdata)
{
    struct per_con_info *pcinfo = ioinfo_userdata(ioinfo);
    struct gdata *ginfo = pcinfo->ginfo;

    return mux_event(io, ginfo, event, ierr, buf, buflen, auxdata);
}

static void
handle_winch(struct per_con_info *pcinfo,
	     unsigned char *msg, unsigned int msglen)
{
    int err, ptym;
    struct winsize win;
    gensiods len = sizeof(int);

    if (msglen < 8)
	return;

    err = gensio_control(pcinfo->io2, 0, GENSIO_CONTROL_GET,
			 GENSIO_CONTROL_RADDR_BIN, (char *) &ptym, &len);
    if (err)
	return;

    win.ws_row = gensio_buf_to_u16(msg + 0);
    win.ws_col = gensio_buf_to_u16(msg + 2);
    win.ws_xpixel = gensio_buf_to_u16(msg + 4);
    win.ws_ypixel = gensio_buf_to_u16(msg + 6);
    ioctl(ptym, TIOCSWINSZ, &win);
}

static void
handle_remote_socket(struct per_con_info *pcinfo,
		     unsigned char *msg, unsigned int msglen)
{
    char service[5], *accepter;
    unsigned int len;

    if (msglen < 5)
	return;
    memcpy(service, msg, 4);
    service[4] = '\0';
    accepter = (char *) (msg + 4);
    len = msglen - 4;
    accepter[len - 1] = '\0'; /* It's supposed to be nil, but just in case. */

    if (!strstartswith(accepter, "tcp,") &&
		!strstartswith(accepter, "sctp,") &&
		!strstartswith(accepter, "unix,")) {
	syslog(LOG_ERR, "Unknown accepter type: %s\n", accepter);
	return;
    }
    add_local_port(pcinfo->ginfo->o, accepter, service, accepter);
}

/*
 * The OOB data has a 3 byte header:
 *
 *  <msgid> <len msb> <len lsb>
 *
 * followed by len bytes.
 */
static void
goobdata(struct ioinfo *ioinfo, unsigned char *buf, gensiods *buflen)
{
    struct per_con_info *pcinfo = ioinfo_userdata(ioinfo);
    gensiods pos = 0;

    while (pos < *buflen ) {
	pcinfo->oobbuf[pcinfo->oobpos++] = buf[pos];
	if (pcinfo->oobpos == 3)
	    /* Get the number of bytes in the message. */
	    pcinfo->ooblen = gensio_buf_to_u16(pcinfo->oobbuf + 1) + 3;
	if (pcinfo->oobpos >= pcinfo->ooblen) {
	    pcinfo->oobpos = 0;
	    if (pcinfo->oobbuf[0] == 'w') {
		/* window change. */
		if (pcinfo->is_pty)
		    handle_winch(pcinfo, pcinfo->oobbuf + 3,
				 pcinfo->ooblen - 3);
	    } else if (pcinfo->oobbuf[0] == 'r') {
		/* Remote socket request. */
		handle_remote_socket(pcinfo, pcinfo->oobbuf + 3,
				     pcinfo->ooblen - 3);
	    }
	    pcinfo->ooblen = 3; /* Give enough room for the next 3 bytes. */
	}
	pos++;
    }
}

static struct ioinfo_user_handlers guh = {
    .shutdown = gshutdown,
    .err = gerr,
    .out = gout,
    .event = gevent,
    .oobdata = goobdata
};

static void
acc_shutdown(struct gensio_accepter *acc, void *done_data)
{
    struct gdata *ginfo = done_data;

    closecount_decr(ginfo);
}

static pam_handle_t *pamh;
static char *passwd;
static char *val_2fa;
static gensiods len_2fa;
static bool pam_started = false;
static bool pam_cred_set = false;
static bool pam_session_open = false;
static bool authed_by_cert = false;
static char username[100];
static char *homedir;
static char *ushell;
static int pam_err;
static uid_t uid = -1;
static gid_t gid = -1;
static bool interactive_login = true;

static struct gtlssh_aux_data aux_data;
static gensiods aux_data_len;

/*
 * If this is set and a certificate auth happens, we use this to start
 * PAM.  This way we can do 2-factor auth with certificates.
 */
static const char *pam_cert_auth_progname;

/*
 * Ambiguity in spec: is it an array of pointers or a pointer to an array?
 * Stolen from openssh.
 */
#ifdef PAM_SUN_CODEBASE
# define PAM_MSG_MEMBER(msg, n, member) ((*(msg))[(n)].member)
#else
# define PAM_MSG_MEMBER(msg, n, member) ((msg)[(n)]->member)
#endif

static bool permit_root = false;
static bool pw_login = false;
static bool do_2fa = false;

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
get_2fa(struct gensio *io)
{
    int err;
    char dummy;

    len_2fa = 0;
    err = gensio_control(io, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_2FA,
			 &dummy, &len_2fa);
    if (err) {
	if (err == GE_DATAMISSING)
	    return 0;
	return err;
    }
    val_2fa = malloc(len_2fa + 1);
    if (!val_2fa)
	return GE_NOMEM;
    val_2fa[len_2fa] = '\0'; /* nil terminate, 2fa may be binary. */
    err = gensio_control(io, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_2FA,
			 val_2fa, &len_2fa);
    if (err) {
	free(val_2fa);
	val_2fa = NULL;
    }
    return err;
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
	err = gensio_control(io, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_USERNAME,
			     username, &len);
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
	homedir = pw->pw_dir;
	ushell = pw->pw_shell;
	if (ushell[0] == '\0')
	    ushell = "/bin/sh";

	len = snprintf(authdir, sizeof(authdir), "%s/.gtlssh/allowed_certs/",
		       pw->pw_dir);
	err = gensio_control(io, 0, GENSIO_CONTROL_SET,
			     GENSIO_CONTROL_CERT_AUTH, authdir, &len);
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
	if (!ierr) {
	    syslog(LOG_INFO, "Accepted certificate for %s\n", username);
	    authed_by_cert = true;
	}
	return GE_NOTSUP;

    case GENSIO_EVENT_PASSWORD_VERIFY:
	passwd = strdup((char *) buf);
	if (!passwd)
	    return GE_NOMEM;
	err = get_2fa(io);
	if (err)
	    return err;
	return GE_NOTSUP;

    case GENSIO_EVENT_2FA_VERIFY:
	len_2fa = *buflen;
	val_2fa = malloc(len_2fa + 1);
	if (!val_2fa)
	    return GE_NOMEM;
	memcpy(val_2fa, buf, len_2fa);
	val_2fa[len_2fa] = '\0';
	return GE_NOTSUP;

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
    gensio_time timeout = { 60, 0 };

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
	    /* If we have passwd or 2fa data, just supply it. */
	    if (passwd) {
		reply[i].resp = passwd;
		if (!reply[i].resp)
		    goto out_err;
		passwd = NULL;
		break;
	    } else if (val_2fa) {
		reply[i].resp = val_2fa;
		if (!reply[i].resp)
		    goto out_err;
		val_2fa = NULL;
		break;
	    }
	    if (!interactive_login)
		goto out_err;

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
    struct per_con_info *pcinfo = NULL;
    struct gensio *pty_io;
    gensiods len;
    char *s = NULL;
    int err, err2;
    char **progv = NULL; /* If set in the service. */
    bool login = false;
    char *service = NULL;
    char **env = NULL, **penv2;
    unsigned int env_len = 0;
    unsigned int i, j;

    len = 0;
    err = gensio_control(io, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_SERVICE,
			 NULL, &len);
    if (err) {
	gensio_time timeout = {10, 0};

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
    err = gensio_control(io, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_SERVICE,
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
	    gensio_time timeout = {10, 0};

	    write_str_to_gensio("Could not get vals from service",
				io, &timeout, true);
	    goto out_free;
	}
	/* Dummy out the program, we will set it later with a control. */
	s = alloc_sprintf("stdio(stderr-to-stdout,readbuf=16384),dummy");
    } else if (strstartswith(service, "login:")) {
	char *str = strchr(service, ':') + 1;

	len -= str - service;
	err = get_vals_from_service(&env, &env_len, str, len);
	if (err)
	    goto out_bad_vals;
	s = alloc_sprintf("pty,%s -i", ushell);
	login = true;
    } else if (strstartswith(service, "tcp,") ||
	       strstartswith(service, "sctp,")) {
	char *host = strchr(service, ',');
	char *end, *portstr;
	unsigned long port;

	*host++ = '\0';
	portstr = strchr(host, ',');
	if (!portstr) {
	    gensio_time timeout = {1, 0};

	    write_str_to_gensio("Invalid port in tcp service",
				io, &timeout, true);
	    goto out_free;
	}
	*portstr++ = '\0';
	end = strchr(portstr, ','); /* Ignore anything after the next ':' */
	if (end)
	    *end = '\0';
	port = strtoul(portstr, &end, 0);
	if (*portstr == '\0' || *end != '\0' || port > 65535) {
	    gensio_time timeout = {1, 0};

	    write_str_to_gensio("Invalid port number in tcp service",
				io, &timeout, true);
	    goto out_free;
	}

	s = alloc_sprintf("%s,%s,%ld", service, host, port);
    } else if (strstartswith(service, "unix,")) {
	char *path = strchr(service, ',') + 1;

	s = alloc_sprintf("unix,%s", service, path);
    } else {
	gensio_time timeout = {10, 0};

	write_str_to_gensio("Unknown service", io, &timeout, true);
	goto out_free;
    }
    if (!s) {
	syslog(LOG_ERR, "Out of memory allocating program name");
	goto out_free;
    }

    if (login || progv) {
	for (i = 0; pam_env[i]; i++)
	    ;
	i += 4; /* Add a slot for minimal environment */
	penv2 = malloc((i + env_len + 1) * sizeof(char *));
	if (!penv2) {
	    syslog(LOG_ERR, "Failure to reallocate env for %s", username);
	    exit(1);
	}

	penv2[0] = alloc_sprintf("HOME=%s", homedir);
	if (!penv2[0]) {
	    syslog(LOG_ERR, "Failure to alloc HOME env space for %s", username);
	    exit(1);
	}
	penv2[1] = alloc_sprintf("USER=%s", username);
	if (!penv2[1]) {
	    syslog(LOG_ERR, "Failure to alloc USER env space for %s", username);
	    exit(1);
	}
	penv2[2] = alloc_sprintf("LOGNAME=%s", username);
	if (!penv2[2]) {
	    syslog(LOG_ERR, "Failure to alloc LOGNAME env space for %s",
		   username);
	    exit(1);
	}
	penv2[3] = alloc_sprintf("PATH=%s", STANDARD_PATH);
	if (!penv2[3]) {
	    syslog(LOG_ERR, "Failure to alloc PATH env space for %s", username);
	    exit(1);
	}
	for (i = 4, j = 0; pam_env[j]; i++, j++)
	    penv2[i] = pam_env[i];
	if (env) {
	    for (j = 0; j < env_len; i++, j++)
		penv2[i] = env[j];
	    free(env);
	}
	penv2[i] = NULL;
	env = penv2;
    }

    pcinfo = malloc(sizeof(*pcinfo));
    if (!pcinfo) {
	syslog(LOG_ERR, "Unable to allocate SSL pc info");
	goto out_free;
    }
    memset(pcinfo, 0, sizeof(*pcinfo));
    pcinfo->ginfo = ginfo;
    pcinfo->ooblen = 3;

    pcinfo->ioinfo1 = alloc_ioinfo(o, -1, NULL, NULL, &guh, pcinfo);
    if (!pcinfo->ioinfo1) {
	syslog(LOG_ERR, "Could not allocate ioinfo 1\n");
	free(pcinfo);
	goto out_free;
    }

    pcinfo->ioinfo2 = alloc_ioinfo(o, -1, NULL, NULL, &guh, pcinfo);
    if (!pcinfo->ioinfo2) {
	free_ioinfo(pcinfo->ioinfo1);
	free(pcinfo);
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

    if (login) {
	err = gensio_control(io, GENSIO_CONTROL_DEPTH_ALL, GENSIO_CONTROL_SET,
			     GENSIO_CONTROL_NODELAY, "1", NULL);
	if (err) {
	    fprintf(stderr, "Could not set nodelay: %s\n",
		    gensio_err_to_str(err));
	    goto out_err;
	}

	pcinfo->is_pty = true;
    }
    err = str_to_gensio(s, o, NULL, NULL, &pty_io);
    free(s);
    s = NULL;
    if (err) {
	syslog(LOG_ERR, "pty alloc failed: %s", gensio_err_to_str(err));
	goto out_err;
    }
    pcinfo->io2 = pty_io;

    if (progv) {
	err = gensio_control(pty_io, 0, GENSIO_CONTROL_SET, GENSIO_CONTROL_ARGS,
			     (char *) progv, NULL);
	if (err) {
		syslog(LOG_ERR, "Setting program arguments failed: %s",
		       gensio_err_to_str(err));
		goto out_err;
	}
    }

    if (progv || login) {
	err = gensio_control(pty_io, 0, GENSIO_CONTROL_SET,
			     GENSIO_CONTROL_ENVIRONMENT, (char *) env, NULL);
	if (err) {
	    syslog(LOG_ERR, "set env failed for %s: %s", username,
		   gensio_err_to_str(err));
	    goto out_err;
	}
    }

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
    err = gensio_open_s(pty_io);
    err2 = seteuid(getuid());
    if (err2)
	syslog(LOG_WARNING, "reset setuid failed: %s", strerror(errno));
    err2 = setegid(getgid());
    if (err2)
	syslog(LOG_WARNING, "reset setgid failed: %s", strerror(errno));
    if (err) {
	syslog(LOG_ERR, "pty open failed: %s", gensio_err_to_str(err));
	goto out_err;
    }
    pcinfo->io2_can_close = true;
    ginfo->closecount++;

    ioinfo_set_ready(pcinfo->ioinfo1, io);
    ioinfo_set_ready(pcinfo->ioinfo2, pty_io);

    {
	/* Send a single oob "r" to the other end to say we are ready. */
	static const char *oobaux[2] = { "oob", NULL };
	char cmd = 'r';

	/* Tell the other end we are ready. */
	gensio_write(io, NULL, &cmd, 1, oobaux);
    }

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
    if (s)
	free(s);
}

static int
mux_event(struct gensio *io, void *user_data, int event, int ierr,
	  unsigned char *buf, gensiods *buflen,
	  const char *const *auxdata)
{
    gensiods len;

    switch (event) {
    case GENSIO_EVENT_READ:
    case GENSIO_EVENT_WRITE_READY:
	abort();

    case GENSIO_EVENT_NEW_CHANNEL:
	/* Enable oob data from the new channel. */
	len = 1;
	gensio_control((struct gensio *) buf,
		       0, false, GENSIO_CONTROL_ENABLE_OOB, "1", &len);

	new_rem_io((struct gensio *) buf, user_data);
	return 0;
    }

    return GE_NOTSUP;
}

static struct gensio *
open_mux(struct gensio *io, struct gdata *ginfo)
{
    struct gensio_os_funcs *o = ginfo->o;
    struct gensio *mux_io;
    gensiods len;
    int err;
    /*
     * The buffer sizes are carefully chosen here to mesh with ssl and
     * mux.  ssl can encrypt up to 16384 bytes at a time, and the
     * overhead of a mux data packet is 10 bytes.  So we set this up
     * so writes can be up to 16384 * 4 bytes total.  On the read size of
     * mux, each read packet has a 3-byte overhead in the buffer, so
     * we will be getting 16374 bytes of data, + 3 for overhead, 64
     * packets is 1048128 bytes.
     */
    static const char *isclient[4] = { "mode=server",
				       "writebuf=65496",
				       "readbuf=1048128",
				       NULL };

    err = mux_gensio_alloc(io, isclient, o, mux_event, ginfo, &mux_io);
    if (err) {
	syslog(LOG_ERR, "Unable to allocate mux gensio: %s",
	       gensio_err_to_str(err));
	exit(1);
    }

    /* Enable OOB data from the mux. */
    len = 1;
    gensio_control(mux_io, 0, false, GENSIO_CONTROL_ENABLE_OOB, "1", &len);

    err = gensio_open_nochild_s(mux_io);
    if (err) {
	syslog(LOG_ERR, "mux open failed: %s", gensio_err_to_str(err));
	exit(1);
    }

    return mux_io;
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
				    NULL, NULL };
    struct gensio *ssl_io, *certauth_io, *top_io;
    gensiods len;
    char tmpservice[20];
    const char *pn;
    bool interactive = false;
    unsigned int i;
    char dummy;
    int pamflags = 0;

    gensio_os_funcs_free_runner(o, r);

    err = ssl_gensio_alloc(net_io, ssl_args, o, NULL, NULL, &ssl_io);
    if (err) {
	syslog(LOG_ERR, "Unable to allocate SSL gensio: %s",
	       gensio_err_to_str(err));
	exit(1);
    }

    err = gensio_open_nochild_s(ssl_io);
    if (err) {
	syslog(LOG_ERR, "SSL open failed: %s", gensio_err_to_str(err));
	exit(1);
    }

    i = 2;
    if (pw_login)
	certauth_args[i++] = "enable-password";

    if (do_2fa)
	certauth_args[i++] = "enable-2fa";

    err = certauth_gensio_alloc(ssl_io, certauth_args, o,
				certauth_event, NULL, &certauth_io);
    if (err) {
	syslog(LOG_ERR, "Unable to allocate certauth gensio: %s",
	       gensio_err_to_str(err));
	exit(1);
    }

    err = gensio_open_nochild_s(certauth_io);
    if (err) {
	syslog(LOG_ERR, "certauth open failed: %s", gensio_err_to_str(err));
	exit(1);
    }

    aux_data_len = sizeof(aux_data);
    err = gensio_control(certauth_io, 0, GENSIO_CONTROL_GET,
			 GENSIO_CONTROL_REM_AUX_DATA,
			 (char *) &aux_data, &aux_data_len);
    if (err)
	aux_data_len = 0;

    if (aux_data_len >= sizeof(aux_data)) {
	aux_data.flags = ntohl(aux_data.flags);

	if (aux_data.flags & GTLSSH_AUX_FLAG_NO_INTERACTIVE)
	    interactive_login = false;
    }

    /* FIXME - figure out a way to unstack certauth_io after authentication */

    len = sizeof(tmpservice);
    err = gensio_control(certauth_io, 0, GENSIO_CONTROL_GET,
			 GENSIO_CONTROL_SERVICE, tmpservice, &len);
    if (err) {
	gensio_time timeout = {10, 0};
	write_str_to_gensio("Could not get service\n", certauth_io,
			    &timeout, true);
	exit(1);
    }

    if (strstartswith(tmpservice, "mux")) {
	top_io = open_mux(certauth_io, ginfo);
	len = sizeof(tmpservice);
	err = gensio_control(top_io, 0, GENSIO_CONTROL_GET,
			     GENSIO_CONTROL_SERVICE, tmpservice, &len);
	if (err) {
	    gensio_time timeout = {10, 0};
	    write_str_to_gensio("Could not get service(2)\n", top_io,
				&timeout, true);
	    exit(1);
	}
    } else {
	top_io = certauth_io;
    }

    pn = progname;
    if (pam_cert_auth_progname && authed_by_cert)
	pn = pam_cert_auth_progname;
    ginfo->rem_io = top_io;
    gensio_conv.appdata_ptr = ginfo;
    pam_err = pam_start(pn, username, &gensio_conv, &pamh);
    if (pam_err != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_start failed for %s: %s", username,
	       pam_strerror(pamh, pam_err));
	exit(1);
    }
    pam_started = true;

    /* Set rhost.  If any of thils fails, we just go on. */
    len = 0;
    err = gensio_control(net_io, 0, GENSIO_CONTROL_GET,
			 GENSIO_CONTROL_RADDR, &dummy, &len);
    if (!err && len > 0) {
	char *rhost = malloc(len + 1), *c2;

	if (!rhost)
	    goto skip_rhost;
	err = gensio_control(net_io, 0, GENSIO_CONTROL_GET,
			     GENSIO_CONTROL_RADDR, rhost, &len);
	if (err)
	    goto skip_rhost;

	/* Pull the address out, it's between the first and last comma. */
	c2 = strrchr(rhost, ',');
	if (c2)
	    *c2 = '\0';
	c2 = strchr(rhost, ',');
	if (c2)
	    c2++;
	else
	    c2 = rhost;

	pam_set_item(pamh, PAM_RHOST, c2);

    skip_rhost:
	if (rhost)
	    free(rhost);
    }

    if (strstartswith(tmpservice, "login:"))
	interactive = true;
    else
	pamflags |= PAM_SILENT;

    /*
     * We need to do this because authorization in pam is skipped if
     * we do a certificate login.
     */
    if (file_is_readable("/etc/nologin") && uid != 0) {
	gensio_time timeout = {10, 0};
	if (interactive)
	    /* Don't send this to non-interactive logins. */
	    write_file_to_gensio("/etc/nologin", top_io, o, &timeout, true);
	exit(1);
    }

    if (!gensio_is_authenticated(top_io) || pam_cert_auth_progname) {
	int tries = 3;

	if (!interactive_login)
	    tries = 1;
	pam_err = pam_authenticate(pamh, pamflags);
	while (pam_err != PAM_SUCCESS && tries > 0) {
	    gensio_time timeout = {10, 0};

	    err = write_str_to_gensio("Permission denied, please try again\n",
				      top_io, &timeout, true);
	    if (err) {
		syslog(LOG_INFO, "Error writing password prompt: %s\n",
		       gensio_err_to_str(err));
		exit(1);
	    }
	    pam_err = pam_authenticate(pamh, pamflags);
	    tries--;
	}

	if (pam_err != PAM_SUCCESS) {
	    gensio_time timeout = {10, 0};

	    if (interactive_login) {
		err = write_str_to_gensio("Too many tries, giving up\n",
					  top_io, &timeout, true);
		syslog(LOG_ERR, "Too many login tries for %s\n", username);
	    } else {
		err = write_str_to_gensio("Non-interactive login only\n",
					  top_io, &timeout, true);
		syslog(LOG_ERR, "Non-interactive login only %s\n", username);
	    }
	    if (err) {
		syslog(LOG_INFO, "Error writing login error: %s\n",
		       gensio_err_to_str(err));
	    }
	    exit(1);
	}
	syslog(LOG_INFO, "Accepted password for %s\n", username);
	/* FIXME - gensio_set_is_authenticated(certauth_io, true); */
    }

    pam_err = pam_acct_mgmt(pamh, pamflags);
    if (pam_err == PAM_NEW_AUTHTOK_REQD) {
	if (interactive) {
	    syslog(LOG_ERR, "user %s password expired, non-interactive login",
		   username);
	    exit(1);
	}
	pam_err = pam_chauthtok(pamh, pamflags);
	if (pam_err != PAM_SUCCESS) {
	    syslog(LOG_ERR, "Changing password for %s failed", username);
	    exit(1);
	}
    } else if (pam_err != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_acct_mgmt failed for %s: %s", username,
	       pam_strerror(pamh, pam_err));
	exit(1);
    }

    pam_err = pam_setcred(pamh, PAM_ESTABLISH_CRED | pamflags);
    if (pam_err != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_setcred failed for %s: %s", username,
	       pam_strerror(pamh, pam_err));
	exit(1);
    }
    pam_cred_set = true;

    pam_err = pam_open_session(pamh, pamflags);
    if (pam_err != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_open_session failed for %s: %s", username,
	       pam_strerror(pamh, pam_err));
	exit(1);
    }
    pam_session_open = true;

    pam_env = pam_getenvlist(pamh);
    if (!pam_env) {
	syslog(LOG_ERR, "pam_getenvlist failed for %s", username);
	exit(1);
    }
    /* login will open the session, don't do it here. */

    if (chdir(homedir)) {
	syslog(LOG_WARNING, "chdir failed for %s to %s: %s", username,
	       homedir, strerror(errno));
    }

    /* At this point we are fully authenticated and have all global info. */

    start_local_ports(top_io);
    new_rem_io(top_io, ginfo);
    return;
}

static struct gensio_accepter *tcp_acc, *sctp_acc, *other_acc;

static int
acc_event(struct gensio_accepter *accepter, void *user_data,
	  int event, void *data)
{
    struct gdata *ginfo = gensio_acc_get_user_data(accepter);
    struct gensio_os_funcs *o = ginfo->o;
    struct gensio *io;
    struct gensio_runner *r;
    int pid, err;

    if (event == GENSIO_ACC_EVENT_LOG) {
	struct gensio_loginfo *li = data;
	int level = LOG_INFO;

	switch (li->level) {
	case GENSIO_LOG_FATAL:	level = LOG_CRIT; break;
	case GENSIO_LOG_ERR:	level = LOG_ERR; break;
	case GENSIO_LOG_WARNING:level = LOG_WARNING; break;
	case GENSIO_LOG_INFO:	level = LOG_INFO; break;
	case GENSIO_LOG_DEBUG:	level = LOG_DEBUG; break;
	}
	vsyslog(LOG_DAEMON | level, li->str, li->args);
	return 0;
    }

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return GE_NOTSUP;

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
	err = gensio_os_funcs_handle_fork(o);
	if (err) {
	    syslog(LOG_ERR, "Could not fork gensio handler: %s",
		   gensio_err_to_str(err));
	    exit(1);
	}
	pid_file = NULL; /* Make sure children don't delete this. */

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
	if (other_acc) {
	    gensio_acc_disable(other_acc);
	    gensio_acc_free(other_acc);
	    other_acc = NULL;
	}

	/* Since handle_new does blocking calls, can't do it here. */
	gensio_set_user_data(io, ginfo); /* Just temporarily. */
	r = gensio_os_funcs_alloc_runner(o, handle_new, io);
	if (!r) {
	    syslog(LOG_ERR, "Could not allocate runner");
	    exit(1);
	}
	err = gensio_os_funcs_run(o, r);
	if (err) {
	    syslog(LOG_ERR, "Could not run runner: %s",
		   gensio_err_to_str(err));
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
    printf("  --nointeractive - Do not do interactive login queries.\n");
    printf("  --nosctp - Disable SCTP support.\n");
    printf("  --notcp - Disable TCP support.\n");
    printf("  --other_acc <accepter> - Allows the user to specify the\n");
    printf("     accepter used by gtlsshd, in addition to sctp and tcp.\n");
    printf("  -4 - Do IPv4 only.\n");
    printf("  -6 - Do IPv6 only.\n");
    printf("  --do-2fa - Have the client get 2-factor auth data.\n");
    printf("  --pam-cert-auth <name> - When doing a certificate auth,\n");
    printf("     use the name as the PAM program name and run the PAM auth\n");
    printf("     after the certificate auth succeeds.  For 2-factor auth.\n");
    printf("  -P, --pidfile <file> - Create the given pidfile.\n");
    printf("  --version - Print the version number and exit.\n");
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
    struct gensio_link *l, *l2;

    gensio_list_for_each_safe(&ginfo->cons, l, l2) {
	struct per_con_info *pcinfo = gensio_container_of(l, struct per_con_info,
							  link);

	close_con_info(pcinfo);
    }
}

static void
pr_localport(const char *fmt, va_list ap)
{
    vsyslog(LOG_ERR, fmt, ap);
}

int
main(int argc, char *argv[])
{
    int arg, rv;
    struct gensio_os_funcs *o;
    struct gdata ginfo;
    const char *keyfile = default_keyfile;
    const char *certfile = default_certfile;
    const char *configfile = default_configfile;
    unsigned int port = 852;
    char *s;
    bool notcp = false, nosctp = false;
    bool daemonize = true;
    const char *iptype = ""; /* Try both IPv4 and IPv6 by default. */
    const char *other_acc_str = NULL;
    struct gensio_os_proc_data *proc_data;

    localport_err = pr_localport;

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
	if ((rv = cmparg_uint(argc, argv, &arg, "-p", "--port",
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
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--other_acc",
			      &other_acc_str)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--permit-root", NULL)))
	    permit_root = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--allow-password", NULL)))
	    pw_login = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--do-2fa", NULL)))
	    do_2fa = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--pam-cert-auth",
			      &pam_cert_auth_progname)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--oneshot", NULL)))
	    oneshot = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--nodaemon", NULL)))
	    daemonize = false;
	else if ((rv = cmparg(argc, argv, &arg, "-P", "--pidfile", &pid_file)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--nointeractive", NULL)))
	    interactive_login = false;
	else if ((rv = cmparg(argc, argv, &arg, "-4", NULL, NULL)))
	    iptype = "ipv4,0.0.0.0,";
	else if ((rv = cmparg(argc, argv, &arg, "-6", NULL, NULL)))
	    iptype = "ipv6,::,";
	else if ((rv = cmparg(argc, argv, &arg, "-d", "--debug", NULL))) {
	    debug++;
	    if (debug > 1)
		gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else if ((rv = cmparg(argc, argv, &arg, NULL, "--version", NULL))) {
	    printf("Version %s\n", gensio_version_string);
	    exit(0);
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
    gensio_os_funcs_set_vlog(o, do_vlog);

    rv = gensio_os_proc_setup(o, &proc_data);
    if (rv) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	gensio_os_funcs_free(o);
	return 1;
    }

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

    ginfo.waiter = gensio_os_funcs_alloc_waiter(o);
    if (!ginfo.waiter) {
	fprintf(stderr, "Could not allocate OS waiter\n");
	return 1;
    }

    if (!notcp) {
	s = alloc_sprintf("tcp(readbuf=20000),%s%d", iptype, port);
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
	s = alloc_sprintf("sctp(readbuf=20000),%s%d", iptype, port);
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

    if (other_acc_str) {
	s = alloc_sprintf(other_acc_str, iptype, port);
	if (!s) {
	    fprintf(stderr, "Could not allocate '%s' descriptor\n",
		    other_acc_str);
	    return 1;
	}

	rv = str_to_gensio_accepter(s, o, acc_event, &ginfo, &other_acc);
	if (rv) {
	    fprintf(stderr, "Could not allocate %s: %s\n", s,
		    gensio_err_to_str(rv));
	    free(s);
	    return 1;
	}
	free(s);

	rv = gensio_acc_startup(other_acc);
	if (rv) {
	    fprintf(stderr, "Could not start '%s' accepter: %s\n",
		    other_acc_str, gensio_err_to_str(rv));
	    return 1;
	}
    }

 start_io:
    if (!debug)
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
	gensio_os_funcs_handle_fork(o);

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

    gensio_os_funcs_wait(o, ginfo.waiter, 1, NULL);

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

    if (other_acc) {
	ginfo.closecount++;
	rv = gensio_acc_shutdown(other_acc, acc_shutdown, &ginfo);
	if (rv) {
	    syslog(LOG_ERR, "Unable to close '%s' accepter: %s",
		   other_acc_str, gensio_err_to_str(rv));
	    ginfo.closecount--;
	}
    }

    close_cons(&ginfo);

    if (ginfo.closecount > 0)
	gensio_os_funcs_wait(o, ginfo.waiter, 1, NULL);

    if (tcp_acc)
	gensio_acc_free(tcp_acc);
    if (sctp_acc)
	gensio_acc_free(sctp_acc);
    if (other_acc)
	gensio_acc_free(other_acc);

    free(ginfo.key);
    free(ginfo.cert);

    gensio_os_funcs_free_waiter(o, ginfo.waiter);

    gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(o);

    if (passwd) {
	memset(passwd, 0, strlen(passwd));
	free(passwd);
    }
    if (val_2fa) {
	memset(val_2fa, 0, len_2fa);
	free(val_2fa);
    }

    if (pam_session_open) {
	pam_err = pam_close_session(pamh, PAM_SILENT);
	if (pam_err != PAM_SUCCESS)
	    syslog(LOG_ERR, "pam_close_session failed for %s: %s", username,
		   pam_strerror(pamh, pam_err));
    } else if (pam_cred_set) {
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
