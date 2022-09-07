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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_list.h>
#include <gensio/argvutils.h>

/* For htonl and friends. */
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

//#define _WIN32

#ifndef _WIN32
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <security/pam_appl.h>
#ifdef HAVE_SETUTXENT
#include <utmpx.h>
#endif
#else
#include <windows.h>
#include <userenv.h>
#include <psapi.h>
#include <accctrl.h>
#include <aclapi.h>
#include <gensio/gensio_osops.h>
#endif

#include "ioinfo.h"
#include "localports.h"
#include "ser_ioinfo.h"
#include "utils.h"
#include "gtlssh.h"


/* Global config options. */
static const char *progname;
static unsigned int debug;
static bool oneshot;
static bool permit_root = false;
static bool pw_login = false;
static bool do_2fa = false;
static bool ginteractive_login = true;

#ifndef _WIN32
/*
 * If this is set and a certificate auth happens, we use this to start
 * PAM.  This way we can do 2-factor auth with certificates.
 */
static const char *pam_cert_auth_progname;
static const char *pid_file = NULL;

/* We fork in *nix. */
#define DO_FORK 1

#include <syslog.h>
#define log_event syslog
#define vlog_event vsyslog
static void
start_log(bool debug)
{
    if (!debug)
	openlog(progname, 0, LOG_AUTH);
    else
	openlog(progname, LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
}

#else
/* In windows we do threads. */
#define DO_FORK 0

#define LOG_NOTICE      EVENTLOG_SUCCESS
#define LOG_INFO        EVENTLOG_INFORMATION_TYPE
#define LOG_WARNING     EVENTLOG_WARNING_TYPE
#define LOG_ERR         EVENTLOG_ERROR_TYPE
#define LOG_CRIT        EVENTLOG_AUDIT_FAILURE
#define LOG_DEBUG       EVENTLOG_INFORMATION_TYPE

static HANDLE evlog;

static void
vlog_event(int level, const char *format, va_list va)
{
    char buf[128];

    vsnprintf(buf, sizeof(buf), format, va);
    if (!debug) {
	DWORD event_id = 0;
	const char *strs[2] = { buf, NULL };;

	switch(level) {
	case LOG_NOTICE:  event_id = 0; break;
	case LOG_INFO:    event_id = 1; break; /* and LOG_DEBUG */
	case LOG_WARNING: event_id = 2; break;
	case LOG_ERR:     event_id = 3; break;
	case LOG_CRIT:    event_id = 3; break;
	}
	event_id <<= 1;
	event_id |= 1;
	event_id <<= 29;
	ReportEventA(evlog, level, 0, event_id, NULL, 1, 0, strs, NULL);
    } else {
	const char *levelstr;

	switch(level) {
	case LOG_NOTICE:  levelstr = "notice"; break;
	case LOG_INFO:    levelstr = "info"; break; /* and LOG_DEBUG */
	case LOG_WARNING: levelstr = "warning"; break;
	case LOG_ERR:     levelstr = "error"; break;
	case LOG_CRIT:    levelstr = "critical"; break;
	}
	fprintf(stderr, "%s: %s\n", levelstr, buf);
    }
}

static void
log_event(int level, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    vlog_event(level, format, args);
    va_end(args);
}

static void
start_log(bool debug)
{
    evlog = OpenEventLogA(NULL, progname);
    if (!evlog) {
	char errbuf[128];

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      GetLastError(), 0, errbuf, sizeof(errbuf), NULL);
	fprintf(stderr, "Could not get user: %s\n", errbuf);
	exit(1);
    }
}
#endif

static void
glogger(void *cbdata, const char *format, ...)
{
    va_list va;

    va_start(va, format);
    vlog_event(LOG_ERR, format, va);
    va_end(va);
}

/* Default the program to this path. */
#define STANDARD_PATH "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

struct gdata {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    char *key;
    char *cert;

    unsigned int gclosecount;
    struct gensio_lock *lock;

    struct gensio_list auths;
};

static void
ginfo_lock(struct gdata *ginfo)
{
    ginfo->o->lock(ginfo->lock);
}

static void
ginfo_unlock(struct gdata *ginfo)
{
    ginfo->o->unlock(ginfo->lock);
}

struct auth_data {
    struct gensio_link link;

    struct gensio_lock *lock;

    struct gdata *ginfo;
    struct gensio *rem_io;
    struct gensio *local_io;

    char username[100];
    char *homedir;
    char *ushell;
    bool interactive_login;
    bool interactive;
    bool privileged;

    /*
     * Note that passwd and val_2fa are passed to pam, so they must be
     * allocated with malloc.
     */
    char *passwd;
    char *val_2fa;
    gensiods len_2fa;

    char *raddr; /* From GETSIO_CONTROL_RADDR */
    char *rhost; /* Host part, points into raddr, don't free */
    bool authed_by_cert;

    struct gtlssh_aux_data aux_data;
    gensiods aux_data_len;

    unsigned int closecount;

    char **env;

#ifdef HAVE_LIBPAM
    pam_handle_t *pamh;
    bool pam_started;
    bool pam_cred_set;
    bool pam_session_open;
    int pam_err;
    uid_t uid;
    gid_t gid;
    struct pam_conv pam_conv;
#endif
#ifdef _WIN32
    HANDLE userh;
#endif

    struct gensio_list cons;
    struct local_ports *locport;
};

static void
auth_lock(struct auth_data *auth)
{
    auth->ginfo->o->lock(auth->lock);
}

static void
auth_unlock(struct auth_data *auth)
{
    auth->ginfo->o->unlock(auth->lock);
}

struct per_con_info {
    struct auth_data *auth;

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

static const char *default_keyfile =
    SYSCONFDIR DIRSEPS "gtlssh" DIRSEPS "gtlsshd.key";
static const char *default_certfile =
    SYSCONFDIR DIRSEPS "gtlssh" DIRSEPS "gtlsshd.crt";
static const char *default_configfile =
    SYSCONFDIR DIRSEPS "gtlssh" DIRSEPS "gtlsshd.conf";

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

#ifdef HAVE_LIBPAM
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
#endif

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

static void
write_utmp(struct auth_data *auth, bool is_login)
{
#ifdef HAVE_SETUTXENT
    struct utmpx u;
    gensiods len;
    int err;
    struct timeval tv;

    if (!auth->interactive_login)
	return;

    memset(&u, 0, sizeof(u));
    gettimeofday(&tv, NULL);
    u.ut_tv.tv_sec = tv.tv_sec;
    u.ut_tv.tv_usec = tv.tv_usec;
    if (is_login)
	u.ut_type = USER_PROCESS;
    else
	u.ut_type = DEAD_PROCESS;
    u.ut_pid = getpid();
    if (auth->rhost)
	/* Don't nil terminate if full. */
	strncpy(u.ut_host, auth->rhost, sizeof(u.ut_host));
    strncpy(u.ut_user, auth->username, sizeof(u.ut_user));
    len = sizeof(u.ut_line);
    err = gensio_control(auth->local_io, 0, GENSIO_CONTROL_GET,
			 GENSIO_CONTROL_LADDR, u.ut_line, &len);
    if (err || len == 0) {
	strncpy(u.ut_id, "~", sizeof(u.ut_id));
    } else {
	if (strncmp(u.ut_line, "/dev/", 5) == 0) {
	    memmove(u.ut_line, u.ut_line + 5, len - 5);
	    len -= 5;
	    u.ut_line[len] = '\0';
	}
	if (len < 4)
	    len = 0;
	else
	    len -= 4;
	strncpy(u.ut_id, u.ut_line + len, sizeof(u.ut_id));
    }

    setutxent();
    pututxline(&u);
    endutxent();
#ifdef WTMPX_FILE
    updwtmpx(WTMPX_FILE, &u);
#endif
#endif
}

static void
closecount_decr_ginfo(struct gdata *ginfo)
{
    ginfo_lock(ginfo);
    assert(ginfo->gclosecount > 0);
    ginfo->gclosecount--;
    if (ginfo->gclosecount == 0 && (oneshot || DO_FORK))
	/* All connections are closed, shut down the process. */
	gensio_os_funcs_wake(ginfo->o, ginfo->waiter);
    ginfo_unlock(ginfo);
}

static void
auth_free(struct auth_data *auth)
{
    struct gensio_os_funcs *o = auth->ginfo->o;

    if (auth->locport)
	free_local_ports(auth->locport);
    if (auth->homedir)
	o->free(o, auth->homedir);
    if (auth->ushell)
	o->free(o, auth->ushell);
    if (auth->passwd) {
	memset(auth->passwd, 0, strlen(auth->passwd));
	free(auth->passwd);
    }
    if (auth->val_2fa) {
	memset(auth->val_2fa, 0, auth->len_2fa);
	free(auth->val_2fa);
    }
    if (auth->raddr)
	o->free(o, auth->raddr);
#ifdef HAVE_LIBPAM
    if (auth->pam_session_open) {
	auth->pam_err = pam_close_session(auth->pamh, PAM_SILENT);
	if (auth->pam_err != PAM_SUCCESS)
	    log_event(LOG_ERR, "pam_close_session failed for %s: %s",
		      auth->username,
		      pam_strerror(auth->pamh, auth->pam_err));
    } else if (auth->pam_cred_set) {
	auth->pam_err = pam_setcred(auth->pamh, PAM_DELETE_CRED | PAM_SILENT);
	if (auth->pam_err != PAM_SUCCESS)
	    log_event(LOG_ERR, "pam_setcred delete failed for %s: %s",
		      auth->username,
		      pam_strerror(auth->pamh, auth->pam_err));
    }
    if (auth->pamh)
	pam_end(auth->pamh, auth->pam_err);
#endif
    if (auth->env) {
	unsigned int i;

	for (i = 0; auth->env[i]; i++)
	    free(auth->env[i]);
	free(auth->env);
    }
    o->free(o, auth);
}

static void
closecount_decr(struct auth_data *auth)
{
    bool do_free;

    auth_lock(auth);
    assert(gensio_list_empty(&auth->cons));
    assert(auth->closecount > 0);
    auth->closecount--;
    do_free = auth->closecount == 0;
    auth_unlock(auth);
    if (do_free) {
	struct gdata *ginfo = auth->ginfo;

	ginfo_lock(ginfo);
	gensio_list_rm(&ginfo->auths, &auth->link);
	ginfo_unlock(ginfo);
	log_event(LOG_INFO, "User %s logged out", auth->username);
	auth_free(auth);
	closecount_decr_ginfo(ginfo);
    }
}

static void
closecount_incr(struct auth_data *auth)
{
    auth_lock(auth);
    auth->closecount++;
    auth_unlock(auth);
}

static void
io_finish_close(struct per_con_info *pcinfo)
{
    if (pcinfo->io1 == NULL && pcinfo->io2 == NULL) {
	struct gensio_os_funcs *o = pcinfo->auth->ginfo->o;

	free_ioinfo(pcinfo->ioinfo1);
	free_ioinfo(pcinfo->ioinfo2);
	o->free(o, pcinfo);
    }
}

static void
io_close(struct gensio *io, void *close_data)
{
    struct per_con_info *pcinfo = close_data;
    struct auth_data *auth = pcinfo->auth;

    if (io == pcinfo->io1)
	pcinfo->io1 = NULL;
    else if (io == pcinfo->io2)
	pcinfo->io2 = NULL;
    else
	abort();

    gensio_free(io);
    io_finish_close(pcinfo);

    closecount_decr(auth);
}

static void
close_con_info(struct per_con_info *pcinfo)
{
    struct auth_data *auth = pcinfo->auth;
    unsigned int do_local_close = 0;
    int err;

    auth_lock(auth);
    gensio_list_rm(&auth->cons, &pcinfo->link);
    auth_unlock(auth);
    if (pcinfo->io1_can_close) {
	pcinfo->io1_can_close = false;
	err = gensio_close(pcinfo->io1, io_close, pcinfo);
	if (err) {
	    log_event(LOG_ERR, "Unable to close remote: %s",
		      gensio_err_to_str(err));
	    do_local_close++;
	    gensio_free(pcinfo->io1);
	    pcinfo->io1 = NULL;
	}
    } else if (pcinfo->io1) {
	gensio_free(pcinfo->io1);
	pcinfo->io1 = NULL;
    }

    if (pcinfo->io2_can_close) {
	write_utmp(auth, false);
	pcinfo->io2_can_close = false;
	err = gensio_close(pcinfo->io2, io_close, pcinfo);
	if (err) {
	    log_event(LOG_ERR, "Unable to close local: %s",
		      gensio_err_to_str(err));
	    do_local_close++;
	    gensio_free(pcinfo->io2);
	    pcinfo->io2 = NULL;
	}
    } else if (pcinfo->io2) {
	gensio_free(pcinfo->io2);
	pcinfo->io2 = NULL;
    }
    io_finish_close(pcinfo);

    while (do_local_close > 0) {
	closecount_decr(auth);
	do_local_close--;
    }
}

static void
gshutdown(struct ioinfo *ioinfo, enum ioinfo_shutdown_reason reason)
{
    struct per_con_info *pcinfo = ioinfo_userdata(ioinfo);
    struct auth_data *auth = pcinfo->auth;

    if (reason == IOINFO_SHUTDOWN_USER_REQ)
	gensio_os_funcs_wake(auth->ginfo->o, auth->ginfo->waiter);
    else
	close_con_info(pcinfo);
}

static void
gerr(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    vlog_event(LOG_ERR, fmt, ap);
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

    return mux_event(io, pcinfo->auth, event, ierr, buf, buflen, auxdata);
}

static void
handle_winch(struct per_con_info *pcinfo,
	     unsigned char *msg, unsigned int msglen)
{
    int col, row, xpixel, ypixel;
    char *str;

    if (msglen < 8)
	return;

    row = gensio_buf_to_u16(msg + 0);
    col = gensio_buf_to_u16(msg + 2);
    xpixel = gensio_buf_to_u16(msg + 4);
    ypixel = gensio_buf_to_u16(msg + 6);
    str = alloc_sprintf("%d:%d:%d:%d", row, col, xpixel, ypixel);
    if (!str)
	return;
    gensio_control(pcinfo->io2, 0, GENSIO_CONTROL_SET, GENSIO_CONTROL_WIN_SIZE,
		   str, 0);
    free(str);
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
	log_event(LOG_ERR, "Unknown accepter type: %s", accepter);
	return;
    }
    add_local_port(pcinfo->auth->locport, accepter, service, accepter);
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
    closecount_decr_ginfo(done_data);
}

#ifdef HAVE_LIBPAM
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
gensio_pam_cb(int num_msg, const struct pam_message **msg,
	      struct pam_response **resp, void *appdata_ptr)
{
    int i, j, err;
    struct pam_response *reply = NULL;
    struct auth_data *auth = appdata_ptr;
    struct gensio *io = auth->rem_io;
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
	    if (auth->passwd) {
		reply[i].resp = auth->passwd;
		if (!reply[i].resp)
		    goto out_err;
		auth->passwd = NULL;
		break;
	    } else if (auth->val_2fa) {
		reply[i].resp = auth->val_2fa;
		if (!reply[i].resp)
		    goto out_err;
		auth->val_2fa = NULL;
		auth->len_2fa = 0;
		break;
	    }
	    if (!auth->interactive_login)
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
#endif

static int
get_vals_from_service(struct gensio_os_funcs *o,
		      char ***rvals, unsigned int *rvlen,
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

    vals = o->zalloc(o, (vlen + 1) * sizeof(char *));
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
get_2fa(struct auth_data *auth, struct gensio *io)
{
    int err;
    char dummy;

    auth->len_2fa = 0;
    err = gensio_control(io, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_2FA,
			 &dummy, &auth->len_2fa);
    if (err) {
	if (err == GE_DATAMISSING)
	    return 0;
	return err;
    }
    /* Note: We must use malloc here, it goes to pam. */
    auth->val_2fa = malloc(auth->len_2fa + 1);
    if (!auth->val_2fa)
	return GE_NOMEM;
    auth->val_2fa[auth->len_2fa] = '\0'; /* nil terminate, 2fa may be binary. */
    err = gensio_control(io, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_2FA,
			 auth->val_2fa, &auth->len_2fa);
    if (err) {
	free(auth->val_2fa);
	auth->val_2fa = NULL;
    }
    return err;
}

#ifndef _WIN32

static int
setup_process(struct gensio_os_funcs *o)
{
    return 0;
}

static int
setup_user(struct auth_data *auth)
{
    struct gensio_os_funcs *o = auth->ginfo->o;
    struct passwd *pw;

    pw = getpwnam(auth->username);
    if (!pw) {
	log_event(LOG_ERR, "Invalid username provided by remote: %s",
		  auth->username);
	return GE_AUTHREJECT;
    }
    if (!permit_root &&
		(strcmp(auth->username, "root") == 0 || pw->pw_uid == 0)) {
	log_event(LOG_ERR, "Root login not permitted");
	return GE_AUTHREJECT;
    }
    auth->uid = pw->pw_uid;
    auth->gid = pw->pw_gid;
    auth->homedir = gensio_strdup(o, pw->pw_dir);
    if (!auth->homedir) {
	log_event(LOG_ERR, "Out of memory allocating home dir");
	return GE_NOMEM;
    }
    if (pw->pw_shell[0] == '\0')
	auth->ushell = gensio_strdup(o, "/bin/sh");
    else
	auth->ushell = gensio_strdup(o, pw->pw_shell);
    if (!auth->ushell) {
	log_event(LOG_ERR, "Out of memory allocating shell");
	return GE_NOMEM;
    }
    return 0;
}

static int
switch_to_user(struct auth_data *auth)
{
    int err, err2;

    err = setregid(auth->gid, -1);
    if (err) {
	log_event(LOG_ERR, "setgid failed: %s", strerror(errno));
	return err;
    }
    err = setreuid(auth->uid, -1);
    if (err) {
	err2 = setgid(getegid());
	if (err2)
	    log_event(LOG_WARNING, "err reset setgid failed: %s",
		      strerror(errno));
	log_event(LOG_ERR, "setuid failed: %s", strerror(errno));
	return err;
    }
    return 0;
}

static void
switch_from_user(struct auth_data *auth)
{
    int err;

    err = setuid(geteuid());
    if (err)
	log_event(LOG_WARNING, "reset setuid failed: %s", strerror(errno));
    err = setgid(getegid());
    if (err)
	log_event(LOG_WARNING, "reset setgid failed: %s", strerror(errno));
}

static int
setup_auth(struct auth_data *auth)
{
    const char *pn;

    pn = progname;
    if (pam_cert_auth_progname && auth->authed_by_cert)
	pn = pam_cert_auth_progname;
    auth->pam_conv.appdata_ptr = auth;
    auth->pam_err = pam_start(pn, auth->username, &auth->pam_conv, &auth->pamh);
    if (auth->pam_err != PAM_SUCCESS) {
	log_event(LOG_ERR, "pam_start failed for %s: %s", auth->username,
		  pam_strerror(auth->pamh, auth->pam_err));
	return GE_AUTHREJECT;
    }
    auth->pam_started = true;
    return 0;
}

static int
finish_auth(struct auth_data *auth)
{
    struct gensio_os_funcs *o = auth->ginfo->o;
    int pamflags = 0, err;

    if (auth->rhost)
	pam_set_item(auth->pamh, PAM_RHOST, auth->rhost);

    if (!auth->interactive)
	pamflags |= PAM_SILENT;

    /*
     * We need to do this because authorization in pam is skipped if
     * we do a certificate login.
     */
    if (file_is_readable("/etc/nologin") && auth->uid != 0) {
	gensio_time timeout = {10, 0};
	if (auth->interactive)
	    /* Don't send this to non-interactive logins. */
	    write_file_to_gensio("/etc/nologin", auth->rem_io,
				 o, &timeout, true);
	return GE_AUTHREJECT;
    }

    if (!gensio_is_authenticated(auth->rem_io) || pam_cert_auth_progname) {
	int tries = 3;

	if (!auth->interactive_login)
	    tries = 1;
	auth->pam_err = pam_authenticate(auth->pamh, pamflags);
	while (auth->pam_err != PAM_SUCCESS && tries > 0) {
	    gensio_time timeout = {10, 0};

	    err = write_str_to_gensio("Permission denied, please try again\r\n",
				      auth->rem_io, &timeout, true);
	    if (err) {
		log_event(LOG_INFO, "Error writing password prompt: %s",
			  gensio_err_to_str(err));
		return err;
	    }
	    auth->pam_err = pam_authenticate(auth->pamh, pamflags);
	    tries--;
	}

	if (auth->pam_err != PAM_SUCCESS) {
	    gensio_time timeout = {10, 0};

	    if (auth->interactive_login) {
		err = write_str_to_gensio("Too many tries, giving up\r\n",
					  auth->rem_io, &timeout, true);
		log_event(LOG_ERR, "Too many login tries for %s",
			  auth->username);
	    } else {
		err = write_str_to_gensio("Non-interactive login only\r\n",
					  auth->rem_io, &timeout, true);
		log_event(LOG_ERR, "Non-interactive login only %s",
			  auth->username);
	    }
	    if (err) {
		log_event(LOG_INFO, "Error writing login error: %s",
			  gensio_err_to_str(err));
	    }
	    return GE_AUTHREJECT;
	}
	log_event(LOG_INFO, "Accepted password for %s", auth->username);
	/* FIXME - gensio_set_is_authenticated(certauth_io, true); */
    }

    auth->pam_err = pam_acct_mgmt(auth->pamh, pamflags);
    if (auth->pam_err == PAM_NEW_AUTHTOK_REQD) {
	if (auth->interactive) {
	    log_event(LOG_ERR,
		      "user %s password expired, non-interactive login",
		      auth->username);
	    return GE_CONNREFUSE;
	}
	auth->pam_err = pam_chauthtok(auth->pamh, pamflags);
	if (auth->pam_err != PAM_SUCCESS) {
	    log_event(LOG_ERR, "Changing password for %s failed",
		      auth->username);
	    return GE_AUTHREJECT;
	}
    } else if (auth->pam_err != PAM_SUCCESS) {
	log_event(LOG_ERR, "pam_acct_mgmt failed for %s: %s", auth->username,
		  pam_strerror(auth->pamh, auth->pam_err));
	return GE_AUTHREJECT;
    }

    auth->pam_err = pam_setcred(auth->pamh, PAM_ESTABLISH_CRED | pamflags);
    if (auth->pam_err != PAM_SUCCESS) {
	log_event(LOG_ERR, "pam_setcred failed for %s: %s", auth->username,
		  pam_strerror(auth->pamh, auth->pam_err));
	return GE_AUTHREJECT;
    }
    auth->pam_cred_set = true;

    auth->pam_err = pam_open_session(auth->pamh, pamflags);
    if (auth->pam_err != PAM_SUCCESS) {
	log_event(LOG_ERR, "pam_open_session failed for %s: %s", auth->username,
		  pam_strerror(auth->pamh, auth->pam_err));
	return GE_AUTHREJECT;
    }
    auth->pam_session_open = true;

    auth->env = pam_getenvlist(auth->pamh);
    if (!auth->env) {
	log_event(LOG_ERR, "pam_getenvlist failed for %s", auth->username);
	return GE_NOMEM;
    }

    return 0;
}

#else
#include <sddl.h>
#include <winnt.h>

static DWORD
set_privilege(HANDLE tok, char *privilege, bool enable)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueA(NULL, privilege, &luid))
	return GetLastError();

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (enable)
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
	tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL))
	return GetLastError();
    else if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	return GetLastError();

   return 0;
}

static int
setup_process(struct gensio_os_funcs *o)
{
    DWORD err;
    HANDLE tok;

   OpenProcessToken(GetCurrentProcess(),
		    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok);
   err = set_privilege(tok, SE_TCB_NAME, true);
   if (err)
       goto out_err;
   err = set_privilege(tok, SE_INCREASE_QUOTA_NAME, true);
   if (err)
       goto out_err;
   err = set_privilege(tok, SE_ASSIGNPRIMARYTOKEN_NAME, true);
   if (err)
       goto out_err;

 out_err:
   CloseHandle(tok);
   if (err)
       return gensio_os_err_to_err(o, err);
   return 0;
}

static int
setup_user(struct auth_data *auth)
{
    auth->homedir = get_homedir(glogger, NULL, auth->username, NULL);
    if (!auth->homedir)
	return GE_NOMEM;
    if (!auth->ushell) {
	auth->ushell = gensio_strdup(auth->ginfo->o,
				     "C:\\\\Windows\\\\System32\\\\cmd.exe");
	if (!auth->ushell) {
	    log_event(LOG_ERR, "Could not allocate shell string");
	    return GE_NOMEM;
	}
    }
    return 0;
}

struct priv_data {
    LPCTSTR name;
    bool found;
    LUID_AND_ATTRIBUTES priv;
};

/*
 * These are the only privileges, and their attributes, that we keep
 * in a non-privileged login.
 */
static struct priv_data std_privs[] = {
    { .name = SE_SHUTDOWN_NAME, .priv = { .Attributes = 0 } },
    { .name = SE_CHANGE_NOTIFY_NAME,
      .priv = { .Attributes = SE_PRIVILEGE_ENABLED } },
    { .name = SE_UNDOCK_NAME, .priv = { .Attributes = 0 } },
    { .name = SE_INC_WORKING_SET_NAME, .priv = { .Attributes = 0 } },
    { .name = SE_TIME_ZONE_NAME, .priv = { .Attributes = 0 } },
    {}
};

static struct priv_data *
alloc_priv_array(struct priv_data *iprivs, unsigned int *len)
{
    unsigned int i;
    struct priv_data *privs;

    for (i = 0; iprivs[i].name; i++)
	;
    privs = (struct priv_data *) malloc(i * sizeof(struct priv_data));
    if (!privs)
	return NULL;
    for (i = 0; iprivs[i].name; i++) {
	privs[i] = iprivs[i];
	if (!LookupPrivilegeValue(NULL, privs[i].name, &privs[i].priv.Luid)) {
	    free(privs);
	    return NULL;
	}
    }
    *len = i;
    return privs;
}

static bool
luid_equal(LUID a, LUID b)
{
    return a.LowPart == b.LowPart && a.HighPart == b.HighPart;
}

static DWORD
read_token_info(HANDLE h, TOKEN_INFORMATION_CLASS type, void **rval,
		DWORD *rlen)
{
    DWORD err, len = 0;
    void *val;

    if (GetTokenInformation(h, type, NULL, 0, &len))
	/* This should fail. */
	return ERROR_INVALID_DATA;
    err = GetLastError();
    if (err != ERROR_INSUFFICIENT_BUFFER)
	return err;
    val = malloc(len);
    if (!val)
	return STATUS_NO_MEMORY;
    if (!GetTokenInformation(h, type, val, len, &len)) {
	free(val);
	return GetLastError();
    }
    *rval = val;
    if (rlen)
	*rlen = len;
    return 0;
}

static DWORD
update_privileges(HANDLE h, struct priv_data *privs, unsigned int privs_len)
{
    DWORD err;
    TOKEN_PRIVILEGES *hpriv = NULL, *nhpriv = NULL;
    unsigned int i, j;

    err = read_token_info(h, TokenPrivileges, (void **) &hpriv, NULL);
    if (err)
	return err;

    nhpriv = (TOKEN_PRIVILEGES *)
	malloc(sizeof(TOKEN_PRIVILEGES) +
	       sizeof(LUID_AND_ATTRIBUTES) * (hpriv->PrivilegeCount +
					      privs_len));
    nhpriv->PrivilegeCount = hpriv->PrivilegeCount;

    for (j = 0; j < privs_len; j++)
	privs[j].found = false;
    for (i = 0; i < hpriv->PrivilegeCount; i++) {
	nhpriv->Privileges[i] = hpriv->Privileges[i];
	for (j = 0; j < privs_len; j++) {
	    if (luid_equal(nhpriv->Privileges[i].Luid, privs[j].priv.Luid)) {
		nhpriv->Privileges[i].Attributes = privs[j].priv.Attributes;
		privs[j].found = true;
		break;
	    }
	}
	if (j == privs_len)
	    /* Not found, remove it. */
	    nhpriv->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
    }
    for (j = 0; j < privs_len; j++) {
	if (!privs[j].found)
	    nhpriv->Privileges[nhpriv->PrivilegeCount++] = privs[j].priv;
    }

    if (!AdjustTokenPrivileges(h, FALSE, nhpriv, 0, NULL, NULL)) {
	err = GetLastError();
	goto out_err;
    }
    err = 0;
 out_err:
    if (hpriv)
	free(hpriv);
    if (nhpriv)
	free(nhpriv);
    return err;
}

static DWORD
medium_mandatory_policy(HANDLE h)
{
    DWORD err = 0;
    TOKEN_MANDATORY_LABEL *integrity;
    SID *integrity_sid;

    err = read_token_info(h, TokenIntegrityLevel, (void **) &integrity, NULL);
    if (err)
	return err;

    integrity_sid = (SID *) integrity->Label.Sid;
    if (integrity_sid->SubAuthority[0] <= SECURITY_MANDATORY_MEDIUM_RID) {
	free(integrity);
	return 0;
    }
    integrity_sid->SubAuthority[0] = SECURITY_MANDATORY_MEDIUM_RID;

    if (!SetTokenInformation(h, TokenIntegrityLevel,
			     integrity, sizeof(*integrity)))
	err = GetLastError();
    free(integrity);
    return err;
}

static DWORD
get_sid_from_type(WELL_KNOWN_SID_TYPE type, SID **rsid)
{
    DWORD err, len = 0;
    SID *sid;

    if (CreateWellKnownSid(type, NULL, NULL, &len))
	/* This should fail. */
	return ERROR_INVALID_DATA;
    err = GetLastError();
    if (err != ERROR_INSUFFICIENT_BUFFER)
	return err;
    sid = (SID *) malloc(len);
    if (!CreateWellKnownSid(type, NULL, sid, &len)) {
	err = GetLastError();
	free(sid);
	return err;
    }
    *rsid = sid;
    return 0;
}

/*
 * Find the lsass.exe program, verify that it has SE_CREATE_TOKEN_NAME
 * privilege, and return it's token.
 */
DWORD
find_lsass_tok(HANDLE *rtok)
{
    DWORD *processes, len = 1000, newlen, count, err = 0, i;
    LUID luid;
    bool found = false;
    HANDLE tokh = NULL;

    if (!LookupPrivilegeValue(NULL, SE_CREATE_TOKEN_NAME, &luid))
	return GetLastError();

 restart:
    processes = (DWORD *) malloc(len);
    if (!processes)
	return STATUS_NO_MEMORY;
    if (!EnumProcesses(processes, len, &newlen))
	return GetLastError();
    if (len == newlen) {
	/* May not have gotten all the processes, try again. */
	free(processes);
	len += 1000;
	goto restart;
    }

    count = len / sizeof(DWORD);
    for (i = 0; !found && i < count; i++) {
	HANDLE proch = OpenProcess(PROCESS_QUERY_INFORMATION |
				   PROCESS_VM_READ,
				   FALSE, processes[i]);
        HMODULE modh;
	TOKEN_PRIVILEGES *hpriv = NULL;
	char procname[MAX_PATH];
	unsigned int j;

	if (!proch)
	    continue;

        if (!EnumProcessModules(proch, &modh, sizeof(modh), &len))
	    goto nextproc;

	if (!GetModuleBaseNameA(proch, modh, procname, sizeof(procname)))
	    goto nextproc;

	if (strcmp(procname, "lsass.exe") != 0)
	    goto nextproc;

	if (!OpenProcessToken(proch, TOKEN_ALL_ACCESS, &tokh))
	    goto nextproc;

	err = read_token_info(tokh, TokenPrivileges, (void **) &hpriv, NULL);
	if (err)
	    goto nextproc;

	for (j = 0; j < hpriv->PrivilegeCount; j++) {
	    if (luid_equal(hpriv->Privileges[j].Luid, luid))
		found = true;
	}

    nextproc:
	CloseHandle(proch);
	if (!found && tokh) {
	    CloseHandle(tokh);
	    tokh = NULL;
	}
	if (hpriv)
	    free(hpriv);
    }

    err = 0;
    if (tokh) {
	if (!DuplicateToken(tokh, SecurityImpersonation, rtok))
	    err = GetLastError();
	CloseHandle(tokh);
	return err;
    }

    return ERROR_PROC_NOT_FOUND;
}

static DWORD
deny_admin_groups(HANDLE *ioh)
{
    DWORD err;
    HANDLE resh = NULL;
    SID *admin_sid = NULL, *admin_member_sid = NULL;
    SID_AND_ATTRIBUTES disable_sids[2];
    TOKEN_GROUPS *grps = NULL;
    unsigned int i;
    HANDLE lstok;
    TOKEN_LINKED_TOKEN link;

    /* NT AUTHORITY\Local account and member of Administrators group */
    err = get_sid_from_type(WinNTLMAuthenticationSid, &admin_member_sid);
    if (err)
	return err;

    /* BUILTIN\Administrators */
    err = get_sid_from_type(WinBuiltinAdministratorsSid, &admin_sid);
    if (err)
	goto out_err;

    /* Check if we have admin access. */
    err = read_token_info(*ioh, TokenGroups, (void **) &grps, NULL);
    if (err)
	goto out_err;
    for (i = 0; i < grps->GroupCount; i++) {
	if (EqualSid(admin_sid, grps->Groups[i].Sid))
	    goto is_admin;
	if (EqualSid(admin_member_sid, grps->Groups[i].Sid))
	    goto is_admin;
    }

    goto out_err;

 is_admin:

    disable_sids[0].Sid = admin_member_sid;
    disable_sids[1].Sid = admin_sid;

    if (!CreateRestrictedToken(*ioh, 0, 2, disable_sids,
			       0, NULL, 0, NULL, &resh)) {
	err = GetLastError();
	goto out_err;
    }

    /*
     * Link the privileged token to the restricted one so the
     * privileged one can be used for escalation.  This requires
     * SE_CREATE_TOKEN_NAME access, which we can only get from
     * lsass.exe, so we steal it's token and impersonate it.
     */
    err = find_lsass_tok(&lstok);
    if (err)
	goto out_err;

    if (!SetThreadToken(NULL, lstok)) {
	CloseHandle(lstok);
	err = GetLastError();
	goto out_err;
    }
    CloseHandle(lstok);

    /* FIXME - this succeeds, but the new token doesn't work. */
    link.LinkedToken = *ioh;
    if (!SetTokenInformation(resh, TokenLinkedToken, &link, sizeof(link))) {
	RevertToSelf();
	err = GetLastError();
	goto out_err;
    }

    RevertToSelf();

    err = 0;
    *ioh = resh;
    resh = NULL;
 out_err:
    if (grps)
	free(grps);
    if (admin_sid)
	free(admin_sid);
    if (admin_member_sid)
	free(admin_member_sid);
    if (resh)
	CloseHandle(resh);
    return err;
}

/*
 * Why isn't there a windows function to do this?
 */
static DWORD
dup_sid(SID *in, SID **out)
{
    DWORD len;
    SID *sid;

    len = GetLengthSid(in);
    sid = (SID *) malloc(len);
    if (!sid)
	return STATUS_NO_MEMORY;
    if (!CopySid(len, sid, in)) {
	free(sid);
	return GetLastError();
    }
    *out = sid;
    return 0;
}

static DWORD
get_tok_user(HANDLE h, SID **rsid)
{
    DWORD err;
    TOKEN_USER *user;

    err = read_token_info(h, TokenUser, (void **) &user, NULL);
    if (err)
	return err;
    err = dup_sid((SID *) user->User.Sid, rsid);
    free(user);
    return err;
}

static DWORD
get_tok_prim_group(HANDLE h, SID **rsid)
{
    DWORD err;
    TOKEN_PRIMARY_GROUP *pgroup;

    err = read_token_info(h, TokenPrimaryGroup, (void **) &pgroup, NULL);
    if (err)
	return err;
    err = dup_sid((SID *) pgroup->PrimaryGroup, rsid);
    free(pgroup);
    return err;
}

static DWORD
set_tok_prim_group(HANDLE h, SID *sid)
{
    TOKEN_PRIMARY_GROUP pgroup;

    pgroup.PrimaryGroup = sid;
    if (!SetTokenInformation(h, TokenPrimaryGroup, &pgroup, sizeof(pgroup)))
	return GetLastError();
    return 0;
}

/*
 * An Admin ACL will be in place, convert it to as user one.
 */
static DWORD
fix_user_acl(HANDLE h, SID *user)
{
    DWORD err;
    TOKEN_DEFAULT_DACL *dacl = NULL, ndacl;
    ACL *acl, *nacl = NULL;
    SID *admin_sid = NULL;
    EXPLICIT_ACCESS_A *exa = NULL;
    ULONG exa_len = 0, i;

    if (!ConvertStringSidToSidA("S-1-5-32-544", ((void **) &admin_sid)))
	return GetLastError();

    err = read_token_info(h, TokenDefaultDacl, (void **) &dacl, NULL);
    if (err)
	goto out_err;
    acl = dacl->DefaultDacl;

    if (!GetExplicitEntriesFromAclA(acl, &exa_len, &exa)) {
	err = GetLastError();
	/* This return an error for some reason. */
	if (err != ERROR_INSUFFICIENT_BUFFER)
	    goto out_err;
	err = 0;
    }

    /* Look for the allowed admin ACE. */
    for (i = 0; i < exa_len; i++) {
	if (exa[i].Trustee.TrusteeForm != TRUSTEE_IS_SID)
	    continue;
	if (!EqualSid((SID *) exa[i].Trustee.ptstrName, admin_sid))
	    continue;

	/* Found it, change the SID. */
	exa[i].Trustee.ptstrName = (LPSTR) user;
	err = SetEntriesInAclA(exa_len, exa, NULL, &nacl);
	if (err)
	    goto out_err;
	break;
    }

    if (nacl) {
	ndacl.DefaultDacl = nacl;
	if (!SetTokenInformation(h, TokenDefaultDacl, &ndacl, sizeof(ndacl))) {
	    err = GetLastError();
	    goto out_err;
	}
    }

 out_err:
    if (exa)
	LocalFree(exa);
    if (nacl)
	LocalFree(nacl);
    if (admin_sid)
	LocalFree(admin_sid);
    if (dacl)
	free(dacl);
    return err;
}

static DWORD
setup_network_token(HANDLE *inh, bool priv)
{
    DWORD err = 0;
    HANDLE h;
    struct priv_data *privs = NULL;
    unsigned int privs_len;
    SID *user = NULL;
    SID *prim_grp = NULL;

    err = get_tok_user(*inh, &user);
    if (err)
	goto out_err;

    err = get_tok_prim_group(*inh, &prim_grp);
    if (err)
	goto out_err;

    err = set_tok_prim_group(*inh, user);
    if (err)
	goto out_err;

    if (!priv) {
	h = *inh;
	err = deny_admin_groups(&h);
	if (err) {
	    h = NULL;
	    goto out_err;
	}

	err = fix_user_acl(h, user);
	if (err)
	    goto out_err;

	err = medium_mandatory_policy(h);
	if (err)
	    goto out_err;

	privs = alloc_priv_array(std_privs, &privs_len);
	if (!privs) {
	    err = STATUS_NO_MEMORY;
	    goto out_err;
	}
	err = update_privileges(h, privs, privs_len);
	if (err)
	    goto out_err;

	*inh = h;
    }
    h = NULL;

 out_err:
    if (user)
	free(user);
    if (prim_grp)
	free(prim_grp);
    if (privs)
	free(privs);
    if (h)
	CloseHandle(h);
    return err;
}

static const char *more_groups[] = {
    "S-1-5-14", /* NT AUTHORITY\REMOTE INTERACTIVE LOGON */
    NULL
};

static int
switch_to_user(struct auth_data *auth)
{
    DWORD err;

    err = gensio_win_get_user_token(auth->username, auth->passwd,
				    "gtlsshd", more_groups, true,
				    &auth->userh);
    if (err) {
	char errbuf[128];

	CloseHandle(auth->userh);
	auth->userh = NULL;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	log_event(LOG_ERR, "Could not get user '%s': %s",
		  auth->username, errbuf);
	goto out_win_err;
    }

    /*
     * Password authenticated logins are normal Interactive logins and
     * can be used directly.  S4U logins are Network logins and not
     * set up as such.
     */
    if (!auth->passwd) {
	err = setup_network_token(&auth->userh, auth->privileged);
	if (err) {
	    char errbuf[128];

	    CloseHandle(auth->userh);
	    auth->userh = NULL;
	    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
			  err, 0, errbuf, sizeof(errbuf), NULL);
	    log_event(LOG_ERR, "Could not setup process token '%s': %s",
		      auth->username, errbuf);
	    goto out_win_err;
	}
    }

    if (!SetThreadToken(NULL, auth->userh)) {
	char errbuf[128];

	CloseHandle(auth->userh);
	auth->userh = NULL;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      GetLastError(), 0, errbuf, sizeof(errbuf), NULL);
	log_event(LOG_ERR, "Could not set thread user: %s", errbuf);
	return gensio_os_err_to_err(auth->ginfo->o, GetLastError());
    }
 out_win_err:
    if (err)
	return gensio_os_err_to_err(auth->ginfo->o, err);
    return 0;
}

static void
switch_from_user(struct auth_data *auth)
{
    CloseHandle(auth->userh);
    auth->userh = NULL;
    if (!RevertToSelf()) {
	char errbuf[128];

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      GetLastError(), 0, errbuf, sizeof(errbuf), NULL);
	log_event(LOG_ERR, "Could not revert user: %s", errbuf);
    }
}

static int
setup_auth(struct auth_data *auth)
{
    return 0;
}

static int
handle_comspec(struct auth_data *auth, struct gensio_os_funcs *o, wchar_t *str)
{
    size_t i, len;
    char *comspec;

    /* Get the size, allowing for doubling each \. */
    for (i = 0, len = 0; str[i]; i++, len++) {
	if (str[i] == L'\\')
	    len++;
    }
    if (len == 0)
	return 0;

    comspec = o->zalloc(o, len + 1);
    if (!comspec)
	return GE_NOMEM;

    /* Copy the data, doubling each \. */
    /* FIXME - we ignore unicode here. */
    for (i = 0, len = 0; str[i]; i++) {
	comspec[len++] = str[i];
	if (str[i] == L'\\')
	    comspec[len++] = str[i];
    }
    comspec[len] = 0;
    if (auth->ushell)
	o->free(o, auth->ushell);
    auth->ushell = comspec;

    return 0;
}

static int
get_wvals_from_service(struct auth_data *auth, struct gensio_os_funcs *o,
		       char ***rvals, unsigned int *rvlen,
		       wchar_t *str)
{
    unsigned int i, j;
    static char **vals = NULL, **v, *s;
    unsigned int vlen = 0;
    int err;

    /*
     * Scan for a double nil that marks the end, counting the number
     * of items we find along the way.
     */
    for (i = 0; str[i]; ) {
	if (_wcsnicmp(str + i, L"COMSPEC=", 8) == 0) {
	    err = handle_comspec(auth, o, str + i + 8);
	    if (err)
		return err;
	}
	for (; str[i]; i++)
	    ;
	vlen++;
	i++;
    }
    if (vlen == 0)
	return 0;

    vals = malloc((vlen + 1) * sizeof(char *));
    if (!vals)
	return GE_NOMEM;

    /* Rescan, setting the variable array items. */
    v = vals;
    for (i = 0; str[i]; ) {
	size_t slen = wcslen(str + i);

	*v = malloc(slen + 1);
	if (!*v)
	    goto out_nomem;
	s = *v;
	v++;
	for (j = 0; str[i]; i++, j++)
	    s[j] = str[i];
	s[j] = '\0';
	i++;
    }
    *v = NULL;

    *rvals = vals;
    if (rvlen)
	*rvlen = vlen;
    return 0;

 out_nomem:
    for (i = 0; vals[i]; i++)
	free(vals[i]);
    free(vals);
    return GE_NOMEM;
}

static int
finish_auth(struct auth_data *auth)
{
    struct gensio_os_funcs *o = auth->ginfo->o;
    DWORD err;
    HANDLE userh;
    int rv;
    void *envblock;

    err = gensio_win_get_user_token(auth->username, auth->passwd,
				    "gtlsshd", NULL, false, &userh);
    if (err) {
	char errbuf[128];

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	log_event(LOG_ERR, "Could not get user '%s': %s",
		  auth->username, errbuf);
	return gensio_os_err_to_err(o, err);
    }
    if (!CreateEnvironmentBlock(&envblock, userh, FALSE)) {
	char errbuf[128];

	err = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	log_event(LOG_ERR, "Could not get env for user '%s': %s",
		  auth->username, errbuf);
	CloseHandle(userh);
	return gensio_os_err_to_err(o, err);
    }
    rv = get_wvals_from_service(auth, o, &auth->env, NULL, envblock);
    DestroyEnvironmentBlock(envblock);
    CloseHandle(userh);
    if (rv) {
	log_event(LOG_ERR, "Error processing environgment for user '%s': %s",
		  auth->username, gensio_err_to_str(rv));
	return rv;
    }

    return 0;
}

#endif

static int
certauth_event(struct gensio *io, void *user_data, int event, int ierr,
	       unsigned char *buf, gensiods *buflen,
	       const char *const *auxdata)
{
    struct auth_data *auth = user_data;
    int err;

    switch (event) {
    case GENSIO_EVENT_AUTH_BEGIN: {
	char authdir[1000];
	gensiods len;

	len = sizeof(auth->username);
	err = gensio_control(io, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_USERNAME,
			     auth->username, &len);
	if (err) {
	    log_event(LOG_ERR, "No username provided by remote: %s",
		      gensio_err_to_str(err));
	    return GE_AUTHREJECT;
	}
	err = setup_user(auth);
	if (err)
	    return err;

	len = snprintf(authdir, sizeof(authdir), "%s%c.gtlssh%callowed_certs%c",
		       auth->homedir, DIRSEP, DIRSEP, DIRSEP);
	err = gensio_control(io, 0, GENSIO_CONTROL_SET,
			     GENSIO_CONTROL_CERT_AUTH, authdir, &len);
	if (err) {
	    log_event(LOG_ERR, "Could not set authdir %s: %s", authdir,
		      gensio_err_to_str(err));
	    return GE_NOTSUP;
	}

	return GE_NOTSUP;
    }

    case GENSIO_EVENT_PRECERT_VERIFY:
	return GE_NOTSUP;

    case GENSIO_EVENT_POSTCERT_VERIFY:
	if (ierr && !pw_login) {
	    log_event(LOG_ERR, "certificate failed verify for %s, "
		      "passwords disabled: %s\n", auth->username,
		      auxdata[0] ? auxdata[0] : "");
	    return GE_AUTHREJECT;
	}
	if (!ierr) {
	    log_event(LOG_INFO, "Accepted certificate for %s",
		      auth->username);
#ifdef _WIN32
	    /*
	     * On windows, we cache the password in .gtlssh.  Not
	     * ideal, but Windows logons don't work very well if you
	     * don't log on with a password, and we don't want to have
	     * to ask for one on certificate logons.
	     */
	    {
		char *pwfile = alloc_sprintf("%s%c.gtlssh%cpassword",
					     auth->homedir, DIRSEP, DIRSEP);
		size_t flen = 100;
		if (!pwfile)
		    return GE_NOMEM;
		auth->passwd = malloc(100);
		if (!auth->passwd) {
		    free(pwfile);
		    return GE_NOMEM;
		}
		err = read_file(glogger, NULL, pwfile, auth->passwd, &flen);
		if (err) {
		    /* Assume the file doesn't exist, just go on. */
		    free(auth->passwd);
		    auth->passwd = NULL;
		} else {
		    /* Remove any trailing newlines. */
		    while (flen > 0 &&
			   (auth->passwd[flen - 1] == '\r'
			    || auth->passwd[flen - 1] == '\n')) {
			flen--;
			auth->passwd[flen] = '\0';
		    }
		}
		free(pwfile);
	    }
#endif
	    auth->authed_by_cert = true;
	}
	return GE_NOTSUP;

    case GENSIO_EVENT_PASSWORD_VERIFY:
	auth->passwd = strdup((char *) buf);
	if (!auth->passwd)
	    return GE_NOMEM;
	err = get_2fa(auth, io);
	if (err)
	    return err;
	return GE_NOTSUP;

    case GENSIO_EVENT_2FA_VERIFY:
	auth->len_2fa = *buflen;
	auth->val_2fa = malloc(auth->len_2fa + 1);
	if (!auth->val_2fa)
	    return GE_NOMEM;
	memcpy(auth->val_2fa, buf, auth->len_2fa);
	auth->val_2fa[auth->len_2fa] = '\0';
	return GE_NOTSUP;

    default:
	return GE_NOTSUP;
    }
}

/* Returns true if successful, false if not. */
static bool
new_rem_io(struct gensio *io, struct auth_data *auth)
{
    struct gensio_os_funcs *o = auth->ginfo->o;
    struct per_con_info *pcinfo = NULL;
    struct gensio *pty_io;
    gensiods len;
    char *s = NULL;
    int err;
    char **progv = NULL; /* If set in the service. */
    bool login = false;
    bool do_chdir = false;
    char *service = NULL;
    char **env = NULL;
    unsigned int env_len = 0;
    const char **penv2 = NULL;
    bool rv = false;

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
    service = o->zalloc(o, len);
    if (!service) {
	log_event(LOG_ERR, "Could not allocate service memory");
	goto out_free;
    }
    err = gensio_control(io, 0, GENSIO_CONTROL_GET, GENSIO_CONTROL_SERVICE,
			 service, &len);
    if (err) {
	log_event(LOG_ERR, "Could not get service(2): %s",
		  gensio_err_to_str(err));
	goto out_free;
    }
    if (strstartswith(service, "program:")) {
	char *str = strchr(service, ':') + 1;

	len -= str - service;
	err = get_vals_from_service(o, &progv, NULL, str, len);
    out_bad_vals:
	if (err) {
	    gensio_time timeout = {10, 0};

	    write_str_to_gensio("Could not get vals from service",
				io, &timeout, true);
	    goto out_free;
	}
	/* Dummy out the program, we will set it later with a control. */
	s = gensio_alloc_sprintf(o,
				 "stdio(stderr-to-stdout,readbuf=16384),dummy");
	do_chdir = true;
    } else if (strstartswith(service, "login:")) {
	char *str = strchr(service, ':') + 1;

	len -= str - service;
	err = get_vals_from_service(o, &env, &env_len, str, len);
	if (err)
	    goto out_bad_vals;
#ifdef _WIN32
	s = gensio_alloc_sprintf(o, "pty,%s -i", auth->ushell);
#else
	s = gensio_alloc_sprintf(o, "pty,-%s -i", auth->ushell);
#endif
	login = true;
	do_chdir = true;
    } else if (strstartswith(service, "tcp,") ||
	       strstartswith(service, "sctp,")) {
	char *host = strchr(service, ',');
	char *end, *portstr;
	unsigned long port;

	*host++ = '\0';
	portstr = strchr(host, ',');
	if (!portstr) {
	    gensio_time timeout = {1, 0};

	    write_str_to_gensio("Invalid port in tcp service\r\n",
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

	    write_str_to_gensio("Invalid port number in tcp service\r\n",
				io, &timeout, true);
	    goto out_free;
	}

	s = gensio_alloc_sprintf(o, "%s,%s,%ld", service, host, port);
    } else if (strstartswith(service, "unix,")) {
	char *path = strchr(service, ',') + 1;

	s = gensio_alloc_sprintf(o, "unix,%s", service, path);
    } else {
	gensio_time timeout = {10, 0};

	write_str_to_gensio("Unknown service", io, &timeout, true);
	goto out_free;
    }
    if (!s) {
	log_event(LOG_ERR, "Out of memory allocating program name");
	goto out_free;
    }

    if (login || progv) {
	unsigned int i = 0, j;

	for (i = 0; auth->env && auth->env[i]; i++)
	    ;
#ifndef _WIN32
	i += 4;
#endif
	i += env_len;
	if (i == 0)
	    goto skip_env;

	penv2 = o->zalloc(o, (i + 1) * sizeof(char *));
	if (!penv2) {
	    log_event(LOG_ERR, "Failure to reallocate env for %s",
		      auth->username);
	    goto out_free;
	}

	i = 0;
#ifndef _WIN32
	penv2[i] = gensio_alloc_sprintf(o, "HOME=%s", auth->homedir);
	if (!penv2[i]) {
	    log_event(LOG_ERR, "Failure to alloc HOME env space for %s",
		      auth->username);
	    goto out_free;
	}
	i++;
	penv2[i] = gensio_alloc_sprintf(o, "USER=%s", auth->username);
	if (!penv2[i]) {
	    log_event(LOG_ERR, "Failure to alloc USER env space for %s",
		      auth->username);
	    goto out_free;
	}
	i++;
	penv2[i] = gensio_alloc_sprintf(o, "LOGNAME=%s", auth->username);
	if (!penv2[i]) {
	    log_event(LOG_ERR, "Failure to alloc LOGNAME env space for %s",
		      auth->username);
	    goto out_free;
	}
	i++;
	penv2[i] = gensio_alloc_sprintf(o, "PATH=%s", STANDARD_PATH);
	if (!penv2[i]) {
	    log_event(LOG_ERR, "Failure to alloc PATH env space for %s",
		      auth->username);
	    goto out_free;
	}
	i++;
#endif
	for (j = 0; auth->env[j]; i++, j++) {
	    penv2[i] = gensio_strdup(o, auth->env[j]);
	    if (!penv2[i]) {
		log_event(LOG_ERR, "Failure to alloc env space for %s",
			  auth->username);
		goto out_free;
	    }
	}
	if (env) {
	    for (j = 0; j < env_len; i++, j++) {
		penv2[i] = gensio_strdup(o, env[j]);
		if (!penv2[i]) {
		    log_event(LOG_ERR, "Failure to alloc env space for %s",
			      auth->username);
		    goto out_free;
		}
	    }
	}
	penv2[i] = NULL;
    }
 skip_env:

    pcinfo = o->zalloc(o, sizeof(*pcinfo));
    if (!pcinfo) {
	log_event(LOG_ERR, "Unable to allocate SSL pc info");
	goto out_free;
    }
    pcinfo->auth = auth;
    pcinfo->ooblen = 3;

    pcinfo->ioinfo1 = alloc_ioinfo(o, -1, NULL, NULL, &guh, pcinfo);
    if (!pcinfo->ioinfo1) {
	log_event(LOG_ERR, "Could not allocate ioinfo 1");
	o->free(o, pcinfo);
	goto out_free;
    }

    pcinfo->ioinfo2 = alloc_ioinfo(o, -1, NULL, NULL, &guh, pcinfo);
    if (!pcinfo->ioinfo2) {
	free_ioinfo(pcinfo->ioinfo1);
	o->free(o, pcinfo);
	log_event(LOG_ERR, "Could not allocate ioinfo 2");
	goto out_free;
    }

    /* After this point we use out_err, which will free pcinfo. */

    ioinfo_set_otherioinfo(pcinfo->ioinfo1, pcinfo->ioinfo2);

    gensio_set_user_data(io, pcinfo->ioinfo1);

    auth->rem_io = NULL;
    pcinfo->io1_can_close = true;
    pcinfo->io1 = io;

    auth_lock(auth);
    gensio_list_add_tail(&auth->cons, &pcinfo->link);
    auth_unlock(auth);

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
    closecount_incr(auth);

    err = str_to_gensio(s, o, NULL, NULL, &pty_io);
    o->free(o, s);
    s = NULL;
    if (err) {
	log_event(LOG_ERR, "pty alloc failed: %s", gensio_err_to_str(err));
	goto out_err;
    }
    pcinfo->io2 = pty_io;
    auth->local_io = pty_io;

    if (do_chdir) {
	err = gensio_control(pty_io, 0, GENSIO_CONTROL_SET,
			     GENSIO_CONTROL_START_DIRECTORY,
			     auth->homedir, NULL);
	if (err) {
		log_event(LOG_ERR, "Setting start directory failed: %s",
			  gensio_err_to_str(err));
		goto out_err;
	}
    }

    if (progv) {
	err = gensio_control(pty_io, 0, GENSIO_CONTROL_SET, GENSIO_CONTROL_ARGS,
			     (char *) progv, NULL);
	if (err) {
		log_event(LOG_ERR, "Setting program arguments failed: %s",
			  gensio_err_to_str(err));
		goto out_err;
	}
    }

    if (progv || login) {
	char *use_env = (char *) env;

	if (penv2)
	    use_env = (char *) penv2;

	err = gensio_control(pty_io, 0, GENSIO_CONTROL_SET,
			     GENSIO_CONTROL_ENVIRONMENT, use_env, NULL);
	if (err) {
	    log_event(LOG_ERR, "set env failed for %s: %s", auth->username,
		      gensio_err_to_str(err));
	    goto out_err;
	}
    }

    err = switch_to_user(auth);
    if (err)
	goto out_err;
    err = gensio_open_s(pty_io);
    switch_from_user(auth);
    if (err) {
	log_event(LOG_ERR, "pty open failed: %s", gensio_err_to_str(err));
	goto out_err;
    }
    pcinfo->io2_can_close = true;
    closecount_incr(auth);

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
    rv = true;

    goto out_free;

 out_err:
    gshutdown(pcinfo->ioinfo1, IOINFO_SHUTDOWN_ERR);
    io = NULL;

 out_free:
    if (io)
	gensio_free(io);
    if (env)
	o->free(o, env); /* Entries are from the service string. */
    if (penv2)
	gensio_argv_free(o, penv2);
    if (progv)
	o->free(o, progv); /* Entries are from the service string. */
    if (service)
	o->free(o, service);
    if (s)
	o->free(o, s);
    return rv;
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

static int
open_mux(struct gensio **io, struct auth_data *auth, struct gensio **nio)
{
    struct gensio_os_funcs *o = auth->ginfo->o;
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

    err = gensio_filter_alloc("mux", *io, isclient, o, mux_event, auth,
			      &mux_io);
    if (err) {
	log_event(LOG_ERR, "Unable to allocate mux gensio: %s",
		  gensio_err_to_str(err));
	return err;
    }
    *io = NULL;

    /* Enable OOB data from the mux. */
    len = 1;
    gensio_control(mux_io, 0, false, GENSIO_CONTROL_ENABLE_OOB, "1", &len);

    err = gensio_open_nochild_s(mux_io);
    if (err) {
	gensio_free(mux_io);
	log_event(LOG_ERR, "mux open failed: %s", gensio_err_to_str(err));
	return err;
    }

    *nio = mux_io;
    return 0;
}

static void
pr_localport(void *cb_data, const char *fmt, va_list ap)
{
    vlog_event(LOG_ERR, fmt, ap);
}

static void
handle_new(struct gensio *net_io)
{
    bool free_net_io = true;
    struct gdata *ginfo = gensio_get_user_data(net_io);
    struct gensio_os_funcs *o = ginfo->o;
    int err;
    const char *ssl_args[] = { ginfo->key, ginfo->cert, "mode=server", NULL };
    const char *certauth_args[] = { "mode=server", "allow-authfail", NULL,
				    NULL, NULL };
    struct gensio *ssl_io = NULL, *certauth_io = NULL, *top_io = NULL;
    struct auth_data *auth;
    gensiods len;
    char tmpservice[20];
    unsigned int i;
    char dummy;

    auth = o->zalloc(o, sizeof(*auth));
    if (!auth) {
	gensio_free(net_io);
	log_event(LOG_ERR, "Unable to allocate auth data");
	return;
    }
    gensio_list_init(&auth->cons);
    auth->ginfo = ginfo;
    /* After this errors to to out_err. */

    auth->lock = o->alloc_lock(o);
    if (!auth->lock)
	goto out_err;

    auth->locport = alloc_local_ports(o, pr_localport, NULL);
    if (!auth->locport) {
	log_event(LOG_ERR, "Could not allocate local port data");
	goto out_err;
    }

    auth->interactive_login = ginteractive_login;
#ifdef HAVE_LIBPAM
    auth->uid = -1;
    auth->gid = -1;
    auth->pam_conv.conv = gensio_pam_cb;
    auth->pam_conv.appdata_ptr = auth;
#endif

    err = gensio_filter_alloc("ssl", net_io, ssl_args, o, NULL, NULL, &ssl_io);
    if (err) {
	log_event(LOG_ERR, "Unable to allocate SSL gensio: %s",
		  gensio_err_to_str(err));
	goto out_err;
    }
    free_net_io = false;

    err = gensio_open_nochild_s(ssl_io);
    if (err) {
	log_event(LOG_ERR, "SSL open failed: %s", gensio_err_to_str(err));
	goto out_err;
    }

    i = 2;
    if (pw_login)
	certauth_args[i++] = "enable-password";

    if (do_2fa)
	certauth_args[i++] = "enable-2fa";

    err = gensio_filter_alloc("certauth", ssl_io, certauth_args, o,
			      certauth_event, auth, &certauth_io);
    if (err) {
	log_event(LOG_ERR, "Unable to allocate certauth gensio: %s",
		  gensio_err_to_str(err));
	goto out_err;
    }
    ssl_io = NULL;

    err = gensio_open_nochild_s(certauth_io);
    if (err) {
	log_event(LOG_ERR, "certauth open failed: %s", gensio_err_to_str(err));
	goto out_err;
    }

    auth->aux_data_len = sizeof(auth->aux_data);
    err = gensio_control(certauth_io, 0, GENSIO_CONTROL_GET,
			 GENSIO_CONTROL_REM_AUX_DATA,
			 (char *) &auth->aux_data, &auth->aux_data_len);
    if (err)
	auth->aux_data_len = 0;

    if (auth->aux_data_len >= sizeof(auth->aux_data)) {
	auth->aux_data.flags = ntohl(auth->aux_data.flags);

	if (auth->aux_data.flags & GTLSSH_AUX_FLAG_NO_INTERACTIVE)
	    auth->interactive_login = false;
	if ((auth->aux_data.flags & GTLSSH_AUX_FLAG_PRIVILEGED) &&
		permit_root)
	    auth->privileged = true;
    }

    /* FIXME - figure out a way to unstack certauth_io after authentication */

    len = sizeof(tmpservice);
    err = gensio_control(certauth_io, 0, GENSIO_CONTROL_GET,
			 GENSIO_CONTROL_SERVICE, tmpservice, &len);
    if (err) {
	gensio_time timeout = {10, 0};
	write_str_to_gensio("Could not get service\n", certauth_io,
			    &timeout, true);
	goto out_err;
    }

    if (strstartswith(tmpservice, "mux")) {
	err = open_mux(&certauth_io, auth, &top_io);
	if (err)
	    goto out_err;
	len = sizeof(tmpservice);
	err = gensio_control(top_io, 0, GENSIO_CONTROL_GET,
			     GENSIO_CONTROL_SERVICE, tmpservice, &len);
	if (err) {
	    gensio_time timeout = {10, 0};
	    write_str_to_gensio("Could not get service(2)\n", top_io,
				&timeout, true);
	    goto out_err;
	}
    } else {
	top_io = certauth_io;
	certauth_io = NULL;
    }

    auth->rem_io = top_io;

    err = setup_auth(auth);
    if (err)
	goto out_err;

    /* Set rhost.  If any of thils fails, we just go on. */
    len = 0;
    err = gensio_control(net_io, 0, GENSIO_CONTROL_GET,
			 GENSIO_CONTROL_RADDR, &dummy, &len);
    if (!err && len > 0) {
	char *c2;

	auth->raddr = o->zalloc(o, len + 1);
	if (!auth->raddr)
	    goto skip_rhost;
	err = gensio_control(net_io, 0, GENSIO_CONTROL_GET,
			     GENSIO_CONTROL_RADDR, auth->raddr, &len);
	if (err) {
	    o->free(o, auth->raddr);
	    auth->raddr = NULL;
	    goto skip_rhost;
	}

	/* Pull the address out, it's between the first and last comma. */
	c2 = strrchr(auth->raddr, ',');
	if (c2)
	    *c2 = '\0';
	c2 = strchr(auth->raddr, ',');
	if (c2)
	    c2++;
	else
	    c2 = auth->raddr;

	auth->rhost = c2;
    }
 skip_rhost:

    if (strstartswith(tmpservice, "login:"))
	auth->interactive = true;

    err = finish_auth(auth);
    if (err)
	goto out_err;

    /* At this point we are fully authenticated and have all global info. */
    ginfo_lock(ginfo);
    gensio_list_add_tail(&ginfo->auths, &auth->link);
    ginfo->gclosecount++;
    ginfo_unlock(ginfo);

    start_local_ports(auth->locport, top_io);
    if (new_rem_io(top_io, auth))
	write_utmp(auth, true);

    return;

 out_err:
    if (free_net_io)
	gensio_free(net_io);
    if (ssl_io)
	gensio_free(ssl_io);
    if (certauth_io)
	gensio_free(certauth_io);
    if (top_io)
	gensio_free(top_io);
    auth_free(auth);
    if (oneshot)
	gensio_os_funcs_wake(o, ginfo->waiter);
}

static struct gensio_accepter *tcp_acc, *sctp_acc, *other_acc;

#ifndef _WIN32
static void
handle_new_runner(struct gensio_runner *r, void *cb_data)
{
    struct gensio *net_io = cb_data;
    struct gdata *ginfo = gensio_get_user_data(net_io);
    struct gensio_os_funcs *o = ginfo->o;

    gensio_os_funcs_free_runner(o, r);
    handle_new(net_io);
}

static void
setup_new_connection(struct gdata *ginfo, struct gensio *io)
{
    struct gensio_os_funcs *o = ginfo->o;
    struct gensio_runner *r;
    pid_t pid;
    int err;

    if (oneshot)
	goto skip_fork;

    switch ((pid = fork())) {
    case -1:
	log_event(LOG_ERR, "Could not fork: %s", strerror(errno));
	gensio_free(io);
	return;

    case 0:
	/*
	 * The fork, let the parent have the accepter and double fork
	 * so parent doesn't own us.  We have to tell the os handler,
	 * too that we forked, or epoll() misbehaves.
	 */
	err = gensio_os_funcs_handle_fork(o);
	if (err) {
	    log_event(LOG_ERR, "Could not fork gensio handler: %s",
		      gensio_err_to_str(err));
	    exit(1);
	    return;
	}
	pid_file = NULL; /* Make sure children don't delete this. */

	setsid();
	switch (fork()) {
	case -1:
	    log_event(LOG_ERR, "Could not fork twice: %s", strerror(errno));
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
	r = gensio_os_funcs_alloc_runner(o, handle_new_runner, io);
	if (!r) {
	    log_event(LOG_ERR, "Could not allocate runner");
	    exit(1);
	}
	err = gensio_os_funcs_run(o, r);
	if (err) {
	    log_event(LOG_ERR, "Could not run runner: %s",
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
}

static void
make_pidfile(void)
{
    FILE *fpidfile;

    if (!pid_file)
	return;
    fpidfile = fopen(pid_file, "w");
    if (!fpidfile) {
	log_event(LOG_WARNING,
		  "Error opening pidfile '%s': %m, pidfile not created",
		  pid_file);
	pid_file = NULL;
	return;
    }
    fprintf(fpidfile, "%d\n", getpid());
    fclose(fpidfile);
}

static void
do_daemonize(struct gensio_os_funcs *o)
{
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
	    log_event(LOG_ERR, "Error forking second fork: %s",
		      strerror(errno));
	    exit(1);
	}
    }
    gensio_os_funcs_handle_fork(o);

    /* Close all my standard I/O. */
    if (chdir("/") < 0) {
	log_event(LOG_ERR, "unable to chdir to '/': %s", strerror(errno));
	exit(1);
    }
    close(0);
    close(1);
    close(2);

    make_pidfile();
}

static void
sys_cleanup(void)
{
    if (pid_file)
	unlink(pid_file);
}

#else

static void
thread_handle_new(void *data) {
    handle_new(data);
}

static void
setup_new_connection(struct gdata *ginfo, struct gensio *io)
{
    int err;
    struct gensio_thread *id;

    gensio_set_user_data(io, ginfo); /* Just temporarily. */
    err = gensio_os_new_thread(ginfo->o, thread_handle_new, io, &id);
    if (err) {
	gensio_free(io);
	log_event(LOG_ERR, "Unable to start handling thread: %s",
		  gensio_err_to_str(err));
    }
}

static void
do_daemonize(struct gensio_os_funcs *o)
{
}

static void
sys_cleanup(void)
{
    CloseEventLog(evlog);
}

#endif

static int
acc_event(struct gensio_accepter *accepter, void *user_data,
	  int event, void *data)
{
    struct gdata *ginfo = gensio_acc_get_user_data(accepter);
    struct gensio *io;

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
	vlog_event(level, li->str, li->args);
	return 0;
    }

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return GE_NOTSUP;

    io = data;

    if (oneshot) {
	if (tcp_acc) {
	    gensio_acc_free(tcp_acc);
	    tcp_acc = NULL;
	}
	if (sctp_acc) {
	    gensio_acc_free(sctp_acc);
	    sctp_acc = NULL;
	}
	if (other_acc) {
	    gensio_acc_free(other_acc);
	    other_acc = NULL;
	}
    }

    setup_new_connection(ginfo, io);

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
    printf("  --sctp - Enable SCTP support.\n");
    printf("  --notcp - Disable TCP support.\n");
    printf("  --other_acc <accepter> - Allows the user to specify the\n");
    printf("     accepter used by gtlsshd, in addition to sctp and tcp.\n");
    printf("  -4 - Do IPv4 only.\n");
    printf("  -6 - Do IPv6 only.\n");
    printf("  --do-2fa - Have the client get 2-factor auth data.\n");
#ifdef HAVE_LIBPAM
    printf("  --pam-cert-auth <name> - When doing a certificate auth,\n");
    printf("     use the name as the PAM program name and run the PAM auth\n");
    printf("     after the certificate auth succeeds.  For 2-factor auth.\n");
    printf("  -P, --pidfile <file> - Create the given pidfile.\n");
#endif
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
    log_event(LOG_ERR, "gensio %s log: ", gensio_log_level_to_str(level));
    vlog_event(LOG_ERR, log, args);
}

static void
close_auth_cons(struct auth_data *auth)
{
    struct gensio_link *l, *l2;

    gensio_list_for_each_safe(&auth->cons, l, l2) {
	struct per_con_info *pcinfo =
	    gensio_container_of(l, struct per_con_info, link);

	close_con_info(pcinfo);
    }
}

static void
close_cons(struct gdata *ginfo)
{
    struct gensio_link *l, *l2;

    gensio_list_for_each_safe(&ginfo->auths, l, l2) {
	struct auth_data *auth = gensio_container_of(l, struct auth_data, link);
	close_auth_cons(auth);
    }
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
    bool notcp = false, sctp = false;
    bool daemonize = true;
    const char *iptype = ""; /* Try both IPv4 and IPv6 by default. */
    const char *other_acc_str = NULL;
    struct gensio_os_proc_data *proc_data;

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
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--sctp", NULL)))
	    sctp = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--other_acc",
			      &other_acc_str)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--permit-root", NULL)))
	    permit_root = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--allow-password", NULL)))
	    pw_login = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--do-2fa", NULL)))
	    do_2fa = true;
#ifdef HAVE_LIBPAM
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--pam-cert-auth",
			      &pam_cert_auth_progname)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-P", "--pidfile", &pid_file)))
	    ;
#endif
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--oneshot", NULL)))
	    oneshot = true;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--nodaemon", NULL)))
	    daemonize = false;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--nointeractive", NULL)))
	    ginteractive_login = false;
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

    start_log(debug);
    log_event(LOG_NOTICE, "gtlsshd startup");

    if (!sctp && notcp) {
	log_event(LOG_ERR, "You cannot disable both TCP and SCTP\n");
	exit(1);
    }

    if (checkout_file(glogger, NULL, keyfile, false, true))
	return 1;
    if (checkout_file(glogger, NULL, certfile, false, false))
	return 1;

    memset(&ginfo, 0, sizeof(ginfo));
    gensio_list_init(&ginfo.auths);

    rv = gensio_default_os_hnd(0, &o);
    if (rv) {
	log_event(LOG_ERR, "Could not allocate OS handler: %s\n",
		  gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_set_vlog(o, do_vlog);

    rv = setup_process(o);
    if (rv) {
	log_event(LOG_ERR, "Could not setup process: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    ginfo.lock = o->alloc_lock(o);
    if (!ginfo.lock) {
	log_event(LOG_ERR, "Could not allocate global lock.\n");
	gensio_os_funcs_free(o);
	return 1;
    }

    rv = gensio_os_proc_setup(o, &proc_data);
    if (rv) {
	log_event(LOG_ERR, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	gensio_os_funcs_free(o);
	return 1;
    }

    ginfo.o = o;

    ginfo.key = gensio_alloc_sprintf(o, "key=%s", keyfile);
    if (!ginfo.key) {
	log_event(LOG_ERR, "Could not allocate keyfile data\n");
	return 1;
    }
    ginfo.cert = gensio_alloc_sprintf(o, "cert=%s", certfile);
    if (!ginfo.key) {
	log_event(LOG_ERR, "Could not allocate certfile data\n");
	return 1;
    }

    ginfo.waiter = gensio_os_funcs_alloc_waiter(o);
    if (!ginfo.waiter) {
	log_event(LOG_ERR, "Could not allocate OS waiter\n");
	return 1;
    }

    if (!notcp) {
	s = gensio_alloc_sprintf(o, "tcp(readbuf=20000),%s%d", iptype, port);
	if (!s) {
	    log_event(LOG_ERR, "Could not allocate tcp descriptor\n");
	    return 1;
	}

	rv = str_to_gensio_accepter(s, o, acc_event, &ginfo, &tcp_acc);
	if (rv) {
	    log_event(LOG_ERR, "Could not allocate %s: %s\n", s,
		      gensio_err_to_str(rv));
	    return 1;
	}
	o->free(o, s);

	rv = gensio_acc_startup(tcp_acc);
	if (rv) {
	    log_event(LOG_ERR, "Could not start TCP accepter: %s\n",
		      gensio_err_to_str(rv));
	    return 1;
	}
    }

    if (sctp) {
	s = gensio_alloc_sprintf(o, "sctp(readbuf=20000),%s%d", iptype, port);
	if (!s) {
	    log_event(LOG_ERR, "Could not allocate sctp descriptor\n");
	    return 1;
	}

	rv = str_to_gensio_accepter(s, o, acc_event, &ginfo, &sctp_acc);
	if (rv == GE_NOTSUP) {
	    /* No SCTP support */
	    o->free(o, s);
	    goto start_io;
	}

	if (rv) {
	    log_event(LOG_ERR, "Could not allocate %s: %s\n", s,
		      gensio_err_to_str(rv));
	    return 1;
	}
	o->free(o, s);

	rv = gensio_acc_startup(sctp_acc);
	if (rv) {
	    log_event(LOG_ERR, "Could not start SCTP accepter: %s\n",
		      gensio_err_to_str(rv));
	    return 1;
	}
    }

    if (other_acc_str) {
	s = gensio_alloc_sprintf(o, other_acc_str, iptype, port);
	if (!s) {
	    log_event(LOG_ERR, "Could not allocate '%s' descriptor\n",
		      other_acc_str);
	    return 1;
	}

	rv = str_to_gensio_accepter(s, o, acc_event, &ginfo, &other_acc);
	if (rv) {
	    log_event(LOG_ERR, "Could not allocate %s: %s\n", s,
		      gensio_err_to_str(rv));
	    return 1;
	}
	o->free(o, s);

	rv = gensio_acc_startup(other_acc);
	if (rv) {
	    log_event(LOG_ERR, "Could not start '%s' accepter: %s\n",
		      other_acc_str, gensio_err_to_str(rv));
	    return 1;
	}
    }

 start_io:
    if (!oneshot && daemonize)
	do_daemonize(o);

    gensio_os_funcs_wait(o, ginfo.waiter, 1, NULL);

    /* FIXME - shutdown threads first. */

    if (tcp_acc) {
	ginfo.gclosecount++;
	rv = gensio_acc_shutdown(tcp_acc, acc_shutdown, &ginfo);
	if (rv) {
	    log_event(LOG_ERR, "Unable to close accepter: %s",
		   gensio_err_to_str(rv));
	    ginfo.gclosecount--;
	}
    }

    if (sctp_acc) {
	ginfo.gclosecount++;
	rv = gensio_acc_shutdown(sctp_acc, acc_shutdown, &ginfo);
	if (rv) {
	    log_event(LOG_ERR, "Unable to close accepter: %s",
		   gensio_err_to_str(rv));
	    ginfo.gclosecount--;
	}
    }

    if (other_acc) {
	ginfo.gclosecount++;
	rv = gensio_acc_shutdown(other_acc, acc_shutdown, &ginfo);
	if (rv) {
	    log_event(LOG_ERR, "Unable to close '%s' accepter: %s",
		      other_acc_str, gensio_err_to_str(rv));
	    ginfo.gclosecount--;
	}
    }

    close_cons(&ginfo);

    if (ginfo.gclosecount > 0)
	gensio_os_funcs_wait(o, ginfo.waiter, 1, NULL);

    if (tcp_acc)
	gensio_acc_free(tcp_acc);
    if (sctp_acc)
	gensio_acc_free(sctp_acc);
    if (other_acc)
	gensio_acc_free(other_acc);

    o->free(o, ginfo.key);
    o->free(o, ginfo.cert);

    gensio_os_funcs_free_waiter(o, ginfo.waiter);

    gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(o);

    sys_cleanup();

    return 0;
}
