/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#define _DEFAULT_SOURCE /* Get getgrouplist(), setgroups() */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#ifdef HAVE_TCPD_H
#include <tcpd.h>
#endif /* HAVE_TCPD_H */

#include <gensio/gensio_osops.h>
#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>

#include "errtrig.h"

static const char *progname = "gensio";

bool gensio_set_progname(const char *iprogname)
{
    progname = iprogname;
    return true;
}


#ifdef _WIN32
#include <winsock2.h> /* For AF_UNSPEC */
#else
#include <arpa/inet.h> /* For AF_UNSPEC */
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>

int
gensio_os_setupnewprog(void)
{
    struct passwd *pw;
    int err;
    uid_t uid = geteuid();
    gid_t *groups = NULL;
    int ngroup = 0;

    if (do_errtrig())
	return GE_NOMEM;

    if (uid == getuid())
	return 0;

    err = seteuid(getuid());
    if (err)
	return errno;

    pw = getpwuid(uid);
    if (!pw)
	return errno;

    getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroup);
    if (ngroup > 0) {
	groups = malloc(sizeof(gid_t) * ngroup);
	if (!groups)
	    return ENOMEM;

	err = getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroup);
	if (err == -1) {
	    err = errno;
	    free(groups);
	    return err;
	}

	err = setgroups(err, groups);
	if (err) {
	    err = errno;
	    free(groups);
	    return err;
	}
	free(groups);
    }

    err = setgid(getegid());
    if (err)
	return errno;

    err = setuid(uid);
    if (err)
	return errno;
    return 0;
}
#endif

int
gensio_os_open_listen_sockets(struct gensio_os_funcs *o,
		      struct gensio_addr *addr,
		      void (*readhndlr)(struct gensio_iod *, void *),
		      void (*writehndlr)(struct gensio_iod *, void *),
		      void (*fd_handler_cleared)(struct gensio_iod *, void *),
		      int (*call_b4_listen)(struct gensio_iod *, void *),
		      void *data, unsigned int opensock_flags,
		      struct gensio_opensocks **rfds, unsigned int *rnr_fds)
{
    struct gensio_opensocks *fds;
    unsigned int nr_fds, i;
    int rv;

    rv = o->open_listen_sockets(o, addr, call_b4_listen, data,
				opensock_flags, &fds, &nr_fds);
    if (rv)
	return rv;

    for (i = 0; i < nr_fds; i++) {
	rv = o->set_fd_handlers(fds[i].iod, data,
				readhndlr, writehndlr, NULL,
				fd_handler_cleared);
	if (rv)
	    break;
    }

    if (!rv) {
	*rfds = fds;
	*rnr_fds = nr_fds;
	return 0;
    }

    for (i = 0; i < nr_fds; i++) {
	o->clear_fd_handlers_norpt(fds[i].iod);
	o->close(&fds[i].iod);
    }
    o->free(o, fds);

    return rv;
}

int
gensio_scan_network_port(struct gensio_os_funcs *o, const char *str,
			 bool listen, struct gensio_addr **raddr,
			 int *rprotocol,
			 bool *is_port_set,
			 int *rargc, const char ***rargs)
{
    int err = 0, family = AF_UNSPEC, argc = 0;
    const char **args = NULL;
    bool doskip = true;
    int protocol;

    if (strncmp(str, "ipv4,", 5) == 0) {
	family = AF_INET;
	str += 5;
    } else if (strncmp(str, "ipv6,", 5) == 0) {
#ifdef AF_INET6
	family = AF_INET6;
	str += 5;
#else
	return GE_NOTSUP;
#endif
    }

    if (strncmp(str, "unix,", 4) == 0 ||
		(rargs && strncmp(str, "unix(", 4) == 0)) {
	if (family != AF_UNSPEC)
	    return GE_INVAL;
	str += 4;
    handle_unix:
	protocol = GENSIO_NET_PROTOCOL_UNIX;
    } else if (strncmp(str, "tcp,", 4) == 0 ||
		(rargs && strncmp(str, "tcp(", 4) == 0)) {
	str += 3;
    handle_tcp:
	protocol = GENSIO_NET_PROTOCOL_TCP;
    } else if (strncmp(str, "udp,", 4) == 0 ||
	       (rargs && strncmp(str, "udp(", 4) == 0)) {
	str += 3;
    handle_udp:
	protocol = GENSIO_NET_PROTOCOL_UDP;
    } else if (strncmp(str, "sctp,", 5) == 0 ||
	       (rargs && strncmp(str, "sctp(", 5) == 0)) {
	str += 4;
    handle_sctp:
#if HAVE_LIBSCTP
	protocol = GENSIO_NET_PROTOCOL_SCTP;
#else
	return GE_NOTSUP;
#endif
    } else if (rprotocol && *rprotocol != 0) {
	doskip = false;
	switch (*rprotocol) {
	case GENSIO_NET_PROTOCOL_UNIX:
	    goto handle_unix;
	case GENSIO_NET_PROTOCOL_TCP:
	    goto handle_tcp;
	case GENSIO_NET_PROTOCOL_UDP:
	    goto handle_udp;
	case GENSIO_NET_PROTOCOL_SCTP:
	    goto handle_sctp;
	default:
	    goto default_protocol;
	}
    } else {
    default_protocol:
	doskip = false;
	protocol = GENSIO_NET_PROTOCOL_TCP;
    }

    if (doskip) {
	if (*str == '(') {
	    if (!rargs)
		return GE_INVAL;
	    err = gensio_scan_args(o, &str, &argc, &args);
	    if (err)
		return err;
	} else if (*str != ',') {
	    return GE_INVAL;
	} else {
	    str++; /* Skip the ',' */
	}
    }

    err = o->addr_scan_ips(o, str, listen, family,
			   protocol, is_port_set, true, raddr);
    if (err) {
	if (args)
	    gensio_argv_free(o, args);
	return err;
    }

    if (rargc)
	*rargc = argc;
    if (rargs)
	*rargs = args;
    if (rprotocol)
	*rprotocol = protocol;

    return 0;
}

int
gensio_scan_network_addr(struct gensio_os_funcs *o, const char *str,
			 int protocol, struct gensio_addr **raddr)
{
    return o->addr_scan_ips(o, str, false, AF_UNSPEC, protocol,
			    NULL, false, raddr);
}

int
gensio_os_scan_netaddr(struct gensio_os_funcs *o, const char *str, bool listen,
		       int protocol, struct gensio_addr **raddr)
{
    bool is_port_set;
    struct gensio_addr *addr;
    int rv;

    rv = o->addr_scan_ips(o, str, listen, AF_UNSPEC,
			  protocol, &is_port_set, true, &addr);
    if (!rv && !listen && !is_port_set &&
		protocol != GENSIO_NET_PROTOCOL_UNIX) {
	gensio_addr_free(addr);
	rv = GE_INVAL;
    } else if (!rv) {
	*raddr = addr;
    }
    return rv;
}

const char *
gensio_os_check_tcpd_ok(struct gensio_iod *iod, const char *iprogname)
{
#ifdef HAVE_TCPD_H
    struct request_info req;

    if (!iprogname)
	iprogname = progname;
    request_init(&req, RQ_DAEMON, iprogname, RQ_FILE,
		 iod->f->iod_get_fd(iod), NULL);
    fromhost(&req);

    if (!hosts_access(&req))
	return "Access denied\r\n";
#endif

    return NULL;
}

/*
 * Serial port handling.
 */
#include <gensio/sergensio.h>

#ifdef _WIN32

struct stdio_mode {
    DWORD old_mode_flags;
};

int
gensio_win_stdio_makeraw(struct gensio_os_funcs *o, HANDLE h,
			 struct stdio_mode **rm)
{
    DWORD mode, omode;
    struct stdio_mode *m = NULL;

    if (!GetConsoleMode(h, &omode))
	return GE_NOTSUP;

    if (!*rm) {
	m = o->zalloc(o, sizeof(*m));
	if (!m)
	    return GE_NOMEM;
	m->old_mode_flags = omode;
    }

    mode = omode & ~(ENABLE_LINE_INPUT |
		     ENABLE_INSERT_MODE |
		     ENABLE_ECHO_INPUT |
		     ENABLE_PROCESSED_INPUT);

    if (!SetConsoleMode(h, mode)) {
	if (m)
	    o->free(o, m);
	return gensio_os_err_to_err(o, GetLastError());
    }

    if (m)
	*rm = m;

    return 0;
}

void
gensio_win_stdio_cleanup(struct gensio_os_funcs *o, HANDLE h,
			 struct stdio_mode **m)
{
    if (!*m)
	return;
    SetConsoleMode(h, (*m)->old_mode_flags);
    o->free(o, *m);
    *m = NULL;
}

struct gensio_win_commport
{
    BOOL orig_dcb_set;
    DCB orig_dcb;
    DCB curr_dcb;

    BOOL orig_timeouts_set;
    COMMTIMEOUTS orig_timeouts;

    BOOL hupcl; /* FIXME - implement this. */
    BOOL break_set;
    BOOL dtr_set;
    BOOL rts_set;

    BOOL break_timer_running;
    HANDLE break_timer;
};

int
gensio_win_setup_commport(struct gensio_os_funcs* o, HANDLE h,
    struct gensio_win_commport** rc, HANDLE* break_timer)
{
    DCB* t;
    COMMTIMEOUTS timeouts;
    int rv = 0;
    struct gensio_win_commport* c;

    if (*rc)
	return GE_INUSE;
    c = o->zalloc(o, sizeof(*c));
    if (!c)
	return GE_NOMEM;

    t = &c->curr_dcb;
    if (!GetCommTimeouts(h, &c->orig_timeouts))
	goto out_err;

    c->orig_timeouts_set = TRUE;

    timeouts.ReadIntervalTimeout = 1;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.ReadTotalTimeoutConstant = 0;
    timeouts.WriteTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 0;
    if (!SetCommTimeouts(h, &timeouts))
	goto out_err;

    if (!GetCommState(h, &c->orig_dcb))
	goto out_err;
    c->orig_dcb_set = TRUE;
    *t = c->orig_dcb;
    t->fBinary = TRUE;
    t->BaudRate = 9600;
    t->fParity = NOPARITY;
    t->fDtrControl = DTR_CONTROL_ENABLE;
    t->fDsrSensitivity = TRUE;
    t->fTXContinueOnXoff = FALSE;
    t->fOutX = FALSE;
    t->fInX = FALSE;
    t->fErrorChar = FALSE;
    t->fNull = FALSE;
    t->fRtsControl = RTS_CONTROL_ENABLE;
    t->fOutxCtsFlow = FALSE;
    t->fAbortOnError = FALSE;
    t->XonLim = 50;
    t->XoffLim = 50;
    t->ByteSize = 8;
    t->StopBits = ONESTOPBIT;
    if (!SetCommState(h, &c->curr_dcb))
	goto out_err;
    /* FIXME - Can the following be restored? */
    if (!EscapeCommFunction(h, CLRBREAK))
	goto out_err;
    c->break_set = FALSE;
    if (!EscapeCommFunction(h, CLRRTS))
	goto out_err;
    c->rts_set = FALSE;
    if (!EscapeCommFunction(h, CLRDTR))
	goto out_err;
    c->dtr_set = FALSE;

    /* Break timer */
    c->break_timer = CreateWaitableTimer(NULL, FALSE, NULL);
    if (!c->break_timer) {
	rv = GE_NOMEM;
    } else {
	*break_timer = c->break_timer;
	*rc = c;
    }

    return rv;

 out_err:
    return gensio_os_err_to_err(o, GetLastError());
}

DWORD
gensio_win_commport_break_done(struct gensio_os_funcs *o, HANDLE h,
			       struct gensio_win_commport **c)
{
    if (!(*c)->break_set)
	if (!EscapeCommFunction(h, CLRBREAK))
	    return GetLastError();
    (*c)->break_timer_running = FALSE;
    return 0;
}

void
gensio_win_cleanup_commport(struct gensio_os_funcs *o, HANDLE h,
			    struct gensio_win_commport **c)
{
    if (!*c)
	return;
    CloseHandle((*c)->break_timer);
    if ((*c)->orig_dcb_set)
	SetCommState(h, &(*c)->orig_dcb);
    if ((*c)->orig_timeouts_set)
	SetCommTimeouts(h, &(*c)->orig_timeouts);
}

int
gensio_win_commport_control(struct gensio_os_funcs *o, int op, bool get,
			    intptr_t val,
			    struct gensio_win_commport **c, HANDLE h)
{
    DCB *t = &(*c)->curr_dcb;
    int rv = 0;

    switch (op) {
    case GENSIO_IOD_CONTROL_SERDATA:
	if (get) {
	    t = o->zalloc(o, sizeof(*t));
	    if (!t) {
		rv = GE_NOMEM;
	    } else {
		*t = (*c)->curr_dcb;
		*((void **) val) = t;
	    }
	} else {
	    (*c)->curr_dcb = *((DCB *) val);
	}
	break;

    case GENSIO_IOD_CONTROL_FREE_SERDATA:
	o->free(o, (void *) val);
	break;

    case GENSIO_IOD_CONTROL_BAUD:
	if (get)
	    *((int *) val) = t->BaudRate;
	else
	    t->BaudRate = val;
	break;

    case GENSIO_IOD_CONTROL_PARITY:
	if (get) {
	    if (t->fParity) {
		switch (t->Parity) {
		case NOPARITY: *((int *) val) = SERGENSIO_PARITY_NONE; break;
		case EVENPARITY: *((int *) val) = SERGENSIO_PARITY_EVEN; break;
		case ODDPARITY: *((int *) val) = SERGENSIO_PARITY_ODD; break;
		case MARKPARITY: *((int *) val) = SERGENSIO_PARITY_MARK; break;
		case SPACEPARITY:
		    *((int *) val) = SERGENSIO_PARITY_SPACE;
		    break;
		default:
		    rv = GE_IOERR;
		}
	    } else {
		*((int *) val) = SERGENSIO_PARITY_NONE;
	    }
	} else {
	    t->fParity = 1;
	    switch (val) {
	    case SERGENSIO_PARITY_NONE:
		t->fParity = 0;
		t->Parity = NOPARITY;
		break;
	    case SERGENSIO_PARITY_EVEN: t->Parity = EVENPARITY; break;
	    case SERGENSIO_PARITY_ODD: t->Parity = ODDPARITY; break;
	    case SERGENSIO_PARITY_MARK: t->Parity = MARKPARITY; break;
	    case SERGENSIO_PARITY_SPACE: t->Parity = SPACEPARITY; break;
	    default:
		rv = GE_INVAL;
	    }
	}
	break;

    case GENSIO_IOD_CONTROL_XONXOFF:
	if (get)
	    *((int *) val) = t->fOutX;
	else {
	    t->XonChar = 17;
	    t->XoffChar = 19;
	    t->fOutX = !!val;
	}
	break;

    case GENSIO_IOD_CONTROL_RTSCTS:
	if (get) {
	    *((int *) val) = t->fOutxCtsFlow;
	} else {
	    t->fOutxCtsFlow = !!val;
	    if (val)
		t->fRtsControl = RTS_CONTROL_HANDSHAKE;
	}
	break;

    case GENSIO_IOD_CONTROL_DATASIZE:
	if (get)
	    *((int *) val) = t->ByteSize;
	else
	    t->ByteSize = val;
	break;

    case GENSIO_IOD_CONTROL_STOPBITS:
	if (get) {
	    switch (t->StopBits) {
	    case ONESTOPBIT: *((int *) val) = 1; break;
	    case TWOSTOPBITS: *((int *) val) = 2; break;
	    default:
		rv = GE_INVAL;
	    }
	} else {
	    switch (val) {
	    case 1: t->StopBits = ONESTOPBIT; break;
	    case 2: t->StopBits = TWOSTOPBITS; break;
	    default:
		rv = GE_INVAL;
	    }
	}
	break;

    case GENSIO_IOD_CONTROL_LOCAL:
	if (get)
	    *((int *) val) = t->fDsrSensitivity;
	else
	    t->fDsrSensitivity = val;
	break;

    case GENSIO_IOD_CONTROL_HANGUP_ON_DONE:
	if (get) {
	    *((int *) val) = (*c)->hupcl;
	} else {
	    (*c)->hupcl = val;
	}
	break;

    case GENSIO_IOD_CONTROL_RS485:
	rv = GE_NOTSUP;
	break;

    case GENSIO_IOD_CONTROL_IXONXOFF:
	if (get) {
	    *((int *) val) = t->fInX;
	} else {
	    t->fInX = !!val;
	    t->XonChar = 17;
	    t->XoffChar = 19;
	}
	break;

    case GENSIO_IOD_CONTROL_APPLY:
	if (!SetCommState(h, &(*c)->curr_dcb))
	    goto out_err;
	break;

    case GENSIO_IOD_CONTROL_SET_BREAK:
	if (get) {
	    *((int *) val) = (*c)->break_set;
	} else {
	    if (val) {
		if (!EscapeCommFunction(h, SETBREAK))
		    goto out_err;
	    } else {
		if (!EscapeCommFunction(h, CLRBREAK))
		    goto out_err;
	    }
	    (*c)->break_set = val;
	}
	break;

    case GENSIO_IOD_CONTROL_SEND_BREAK:
	if (!((*c)->break_set || (*c)->break_timer_running)) {
	    LARGE_INTEGER timeout;

	    /* .25 seconds. */
	    timeout.QuadPart = 2500000LL;
	    if (!EscapeCommFunction(h, SETBREAK))
		goto out_err;
	    if (!SetWaitableTimer((*c)->break_timer, &timeout,
				  0, NULL, NULL, 0)) {
		EscapeCommFunction(h, CLRBREAK);
		goto out_err;
	    }
	    (*c)->break_timer_running = true;
	}
	break;

    case GENSIO_IOD_CONTROL_DTR:
	if (get) {
	    *((int *) val) = (*c)->dtr_set;
	} else {
	    if (val) {
		if (!EscapeCommFunction(h, SETDTR))
		    goto out_err;
	    } else {
		if (!EscapeCommFunction(h, CLRDTR))
		    goto out_err;
	    }
	    (*c)->dtr_set = val;
	}
	break;

    case GENSIO_IOD_CONTROL_RTS:
	if (get) {
	    *((int *) val) = (*c)->rts_set;
	} else {
	    if (val) {
		if (!EscapeCommFunction(h, SETRTS))
		    goto out_err;
	    } else {
		if (!EscapeCommFunction(h, CLRRTS))
		    goto out_err;
	    }
	    (*c)->rts_set = val;
	}
	break;

    case GENSIO_IOD_CONTROL_MODEMSTATE: {
	DWORD dval;
	int rval = 0;

	if (!GetCommModemStatus(h, &dval))
	    goto out_err;
	if (dval & MS_CTS_ON)
	    rval |= SERGENSIO_MODEMSTATE_CTS;
	if (dval & MS_DSR_ON)
	    rval |= SERGENSIO_MODEMSTATE_DSR;
	if (dval & MS_RING_ON)
	    rval |= SERGENSIO_MODEMSTATE_RI;
	if (dval & MS_RLSD_ON)
	    rval |= SERGENSIO_MODEMSTATE_CD;
	*((int *) val) = rval;
	break;
    }

    case GENSIO_IOD_CONTROL_FLOWCTL_STATE:
	rv = GE_NOTSUP;

    default:
	rv = GE_NOTSUP;
    }
    return rv;

 out_err:
    return gensio_os_err_to_err(o, GetLastError());
}

static int
argv_to_win_cmdline(struct gensio_os_funcs *o, const char *argv[],
		    char **rcmdline)
{
    unsigned int cmdlen = 0, i, j, k, l, p = 0;
    char *cmdline;

    /*
     * We quote all arguments to be sure, which means we have to
     * manipulate things inside for quotes.  However, the quoting
     * rules of Windows are bizarre.  A \" is a quote.  But the \ is
     * only valid that way before a quote, a \ without a " following
     * is just a \.  But any number of \ before a " will be converted
     * from two \ to a single \.  So "\\\" is \", but \\" is \ and the
     * " terminates the string.
     */
    for (i = 0; argv[i]; i++) {
	const char *s = argv[i];

	cmdlen += 3; /* Room for two quotes and a space. */
	for (j = 0; s[j]; j++) {
	    if (s[j] == '"') {
		cmdlen += 2; /* Add room for the \ */
		for (k = j; k > 0; ) {
		    k--;
		    if (s[k] == '\\')
			cmdlen++; /* Double every \ before a " */
		    else
			break;
		}
	    } else {
		cmdlen++;
	    }
	}
	for (k = j; k > 0; ) {
	    k--;
	    if (s[k] == '\\')
		cmdlen++; /* Double every \ at the end, as we are adding a " */
	}
    }

    if (cmdlen >= 32766) /* Maximum size for Windows. */
	return GE_TOOBIG;

    cmdline = o->zalloc(o, cmdlen + 1);
    if (!cmdline)
	return GE_NOMEM;

    for (i = 0; argv[i]; i++) {
	const char *s = argv[i];

	cmdline[p++] = '"';
	for (j = 0; s[j]; j++) {
	    if (s[j] == '"') {
		l = 0;
		for (k = j; k > 0; ) {
		    k--;
		    if (s[k] == '\\') {
			l++;
			p--; /* Back up over the \s */
		    } else {
			break;
		    }
		}
		for (; l > 0; l--) {
		    cmdline[p++] = '\\';
		    cmdline[p++] = '\\';
		}
		cmdline[p++] = '\\';
		cmdline[p++] = '"';
	    } else {
		cmdline[p++] = s[j];
	    }
	}
	l = 0;
	for (k = j; k > 0; ) {
	    k--;
	    if (s[k] == '\\') {
		l++;
		p--; /* Back up over the \s */
	    } else {
		break;
	    }
	}
	for (; l > 0; l--) {
	    cmdline[p++] = '\\';
	    cmdline[p++] = '\\';
	}
	cmdline[p++] = '"';
	if (argv[i + 1])
	    cmdline[p++] = ' ';
    }
    cmdline[p++] = '\0';

    *rcmdline = cmdline;
    return 0;;
}

int
gensio_win_do_exec(struct gensio_os_funcs *o,
		   const char *argv[], const char **env,
		   bool stderr_to_stdout,
		   HANDLE *phandle,
		   HANDLE *rin, HANDLE *rout, HANDLE *rerr)
{
    int rv = 0;
    char *cmdline;
    SECURITY_ATTRIBUTES sattr;
    STARTUPINFOA suinfo;
    PROCESS_INFORMATION procinfo;
    HANDLE stdin_m = NULL, stdin_s = NULL;
    HANDLE stdout_m = NULL, stdout_s = NULL;
    HANDLE stderr_m = NULL, stderr_s = NULL;

    if (rerr && stderr_to_stdout)
	return GE_INVAL;

    rv = argv_to_win_cmdline(o, argv, &cmdline);
    if (rv)
	return rv;

    memset(&sattr, 0, sizeof(sattr));
    memset(&suinfo, 0, sizeof(suinfo));
    memset(&procinfo, 0, sizeof(procinfo));

    sattr.nLength = sizeof(sattr);
    sattr.bInheritHandle = TRUE;
    sattr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&stdin_s, &stdin_m, &sattr, 0))
	goto out_err_conv;
    if (!SetHandleInformation(stdin_m, HANDLE_FLAG_INHERIT, 0))
	goto out_err_conv;

    if (!CreatePipe(&stdout_m, &stdout_s, &sattr, 0))
	goto out_err_conv;
    if (!SetHandleInformation(stdout_m, HANDLE_FLAG_INHERIT, 0))
	goto out_err_conv;

    if (stderr_to_stdout) {
	if (!DuplicateHandle(GetCurrentProcess(),
			     stdout_s,
			     GetCurrentProcess(),
			     &stderr_s,
			     0, TRUE, DUPLICATE_SAME_ACCESS))
	    goto out_err_conv;
    } else if (rerr) {
	if (!CreatePipe(&stderr_m, &stderr_s, &sattr, 0))
	    goto out_err_conv;
	if (!SetHandleInformation(stderr_m, HANDLE_FLAG_INHERIT, 0))
	    goto out_err_conv;
    } else {
	if (!DuplicateHandle(GetCurrentProcess(),
			     GetStdHandle(STD_ERROR_HANDLE),
			     GetCurrentProcess(),
			     &stderr_s,
			     0, TRUE, DUPLICATE_SAME_ACCESS))
	    goto out_err_conv;
    }

    suinfo.cb = sizeof(STARTUPINFO);
    suinfo.hStdInput = stdin_s;
    suinfo.hStdOutput = stdout_s;
    suinfo.hStdError = stderr_s;
    suinfo.dwFlags |= STARTF_USESTDHANDLES;

    if (!CreateProcess(NULL,
		       cmdline,
		       NULL,
		       NULL,
		       TRUE,
		       0,
		       NULL,
		       NULL,
		       &suinfo,
		       &procinfo))
	goto out_err_conv;

    /* We have to close these here or we won't see the child process die. */
    CloseHandle(stdin_s);
    CloseHandle(stdout_s);
    CloseHandle(stderr_s);

    CloseHandle(procinfo.hThread);

    *phandle = procinfo.hProcess;
    *rin = stdin_m;
    *rout = stdout_m;
    if (rerr)
	*rerr = stderr_m;

    goto out;

 out_err_conv:
    rv = gensio_os_err_to_err(o, GetLastError());

    if (stdin_m)
	CloseHandle(stdin_m);
    if (stdout_m)
	CloseHandle(stdout_m);
    if (stderr_m)
	CloseHandle(stderr_m);
    if (stdin_s)
	CloseHandle(stdin_s);
    if (stdout_s)
	CloseHandle(stdout_s);
    if (stderr_s)
	CloseHandle(stderr_s);
    return rv;

 out:
    if (cmdline)
	o->free(o, cmdline);
    return rv;
}

#else /* _WIN32 */

#include <fcntl.h>
#include <sys/stat.h>

struct stdio_mode {
    int orig_file_flags;
};

int
gensio_unix_do_nonblock(struct gensio_os_funcs *o, int fd,
			struct stdio_mode **rm)
{
    int rv;
    struct stdio_mode *r;

    rv = fcntl(fd, F_GETFL, 0);
    if (rv == -1)
	return gensio_os_err_to_err(o, errno);

    if (!*rm) {
	r = o->zalloc(o, sizeof(*r));
	if (!r)
	    return GE_NOMEM;
	r->orig_file_flags = rv;
    }

    rv |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, rv) == -1) {
	if (r)
	    o->free(o, r);
	return gensio_os_err_to_err(o, errno);
    }

    if (r)
	*rm = r;

    return 0;
}

void
gensio_unix_do_cleanup_nonblock(struct gensio_os_funcs *o, int fd,
				struct stdio_mode **m)
{
    if (!*m)
	return;
    fcntl(fd, F_SETFL, (*m)->orig_file_flags);
    o->free(o, *m);
    *m = NULL;
}

#if HAVE_DECL_TIOCSRS485
#include <linux/serial.h>
#endif

#ifdef HAVE_TERMIOS2
#include <asm/termios.h>
typedef struct termios2 g_termios;
#else
#include <sys/ioctl.h>
#include <termios.h>

typedef struct termios g_termios;
#endif

struct gensio_unix_termios {
    g_termios orig_termios;
    g_termios curr_termios;
    bool break_set;
#if HAVE_DECL_TIOCSRS485
    bool rs485_applied;
    struct serial_rs485 rs485;
#endif
};

#ifdef HAVE_TERMIOS2

int ioctl(int fd, int op, ...);

/*
 * termios2 allows the setting of custom serial port speeds.
 *
 * There is unfortunate complexity with handling termios2 on Linux.
 * You cannot include asm/termios.h and termios.h or sys/ioctl.h at
 * the same time.  So that means a lot of stuff has to be be handled
 * by hand, not with the tcxxx() functions.  The standard tcxxx()
 * function do not use the termios2 ioctls when talking to the
 * kernel (at the current time).  It's kind of a mess.
 */
static int
set_termios(int fd, struct termios2 *t)
{
    return ioctl(fd, TCSETS2, t);
}

static int
get_termios(int fd, struct termios2 *t)
{
    return ioctl(fd, TCGETS2, t);
}

static int
do_flush(int fd, int val)
{
    return ioctl(fd, TCFLSH, val);
}

static int
set_flowcontrol(int fd, bool val)
{
    return ioctl(fd, TCXONC, val ? TCOOFF : TCOON);
}

static void
do_break(int fd)
{
    ioctl(fd, TCSBRK, 0);
}
#else

static int
set_termios(int fd, struct termios *t)
{
    return tcsetattr(fd, TCSANOW, t);
}

static int
get_termios(int fd, struct termios *t)
{
    return tcgetattr(fd, t);
}

static int
do_flush(int fd, int val)
{
    return tcflush(fd, val);
}

static int
set_flowcontrol(int fd, bool val)
{
    return tcflow(fd, val ? TCOOFF : TCOON);
}

static void
do_break(int fd)
{
    tcsendbreak(fd, 0);
}
#endif

#if !defined(HAVE_CFMAKERAW) || defined(HAVE_TERMIOS2)
static void s_cfmakeraw(g_termios *termios_p) {
    termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    termios_p->c_oflag &= ~OPOST;
    termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    termios_p->c_cflag &= ~(CSIZE|PARENB);
    termios_p->c_cflag |= CS8;
    termios_p->c_cc[VMIN] = 1;
}
#else
#define s_cfmakeraw cfmakeraw
#endif

int
gensio_unix_setup_termios(struct gensio_os_funcs *o, int fd,
			  struct gensio_unix_termios **it)
{
    struct gensio_unix_termios *t;
    int rv;

    if (*it)
	return 0;

    t = o->zalloc(o, sizeof(*t));
    if (!t)
	return GE_NOMEM;

    rv = get_termios(fd, &t->curr_termios);
    if (rv) {
	o->free(o, t);
	return gensio_os_err_to_err(o, errno);
    }

    t->orig_termios = t->curr_termios;

    s_cfmakeraw(&t->curr_termios);
    t->curr_termios.c_cflag &= ~(CRTSCTS | PARODD);
    t->curr_termios.c_cflag |= CREAD;
    t->curr_termios.c_cc[VSTART] = 17;
    t->curr_termios.c_cc[VSTOP] = 19;
    t->curr_termios.c_iflag &= ~(IXOFF | IXANY);
    t->curr_termios.c_iflag |= IGNBRK;

    rv = set_termios(fd, &t->curr_termios);
    if (rv) {
	o->free(o, t);
	return gensio_os_err_to_err(o, errno);
    }

    *it = t;

    return 0;
}

void
gensio_unix_cleanup_termios(struct gensio_os_funcs *o,
			    struct gensio_unix_termios **it, int fd)
{
    if (!*it)
	return;
    set_termios(fd, &(*it)->orig_termios);
    o->free(o, *it);
    *it = NULL;
}

static struct baud_rates_s {
    int real_rate;
    int val;
} baud_rates[] =
{
    { 50, B50 },
    { 75, B75 },
    { 110, B110 },
    { 134, B134 },
    { 150, B150 },
    { 200, B200 },
    { 300, B300 },
    { 600, B600 },
    { 1200, B1200 },
    { 1800, B1800 },
    { 2400, B2400 },
    { 4800, B4800 },
    { 9600, B9600 },
    /* We don't support 14400 baud */
    { 19200, B19200 },
    /* We don't support 28800 baud */
    { 38400, B38400 },
    { 57600, B57600 },
    { 115200, B115200 },
#ifdef B230400
    { 230400, B230400 },
#endif
#ifdef B460800
    { 460800, B460800 },
#endif
#ifdef B500000
    { 500000, B500000 },
#endif
#ifdef B576000
    { 576000, B576000 },
#endif
#ifdef B921600
    { 921600, B921600 },
#endif
#ifdef B1000000
    { 1000000, B1000000 },
#endif
#ifdef B1152000
    { 1152000, B1152000 },
#endif
#ifdef B1500000
    { 1500000, B1500000 },
#endif
#ifdef B2000000
    { 2000000, B2000000 },
#endif
#ifdef B2500000
    { 2500000, B2500000 },
#endif
#ifdef B3000000
    { 3000000, B3000000 },
#endif
#ifdef B3500000
    { 3500000, B3500000 },
#endif
#ifdef B4000000
    { 4000000, B4000000 },
#endif
};
#define BAUD_RATES_LEN ((sizeof(baud_rates) / sizeof(struct baud_rates_s)))

static int
set_baud_rate(g_termios *t, int rate)
{
    unsigned int i;

    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (rate == baud_rates[i].real_rate) {
#ifdef HAVE_TERMIOS2
	    t->c_cflag &= ~CBAUD;
	    t->c_cflag |= baud_rates[i].val;
	    t->c_ispeed = rate;
	    t->c_ospeed = rate;
#else
	    cfsetispeed(t, baud_rates[i].val);
	    cfsetospeed(t, baud_rates[i].val);
#endif
	    return 0;
	}
    }

#ifdef HAVE_TERMIOS2
    t->c_cflag &= ~CBAUD;
    t->c_cflag |= CBAUDEX;
    t->c_ispeed = rate;
    t->c_ospeed = rate;
    return 0;
#endif

    return GE_INVAL;
}

static int
get_baud_rate(g_termios *t)
{
    unsigned int i;
    int baud_rate;

#ifdef HAVE_TERMIOS2
    if ((t->c_cflag & CBAUD) == CBAUDEX)
	return t->c_ospeed;
    baud_rate = t->c_cflag & CBAUD;
#else
    baud_rate = cfgetospeed(t);
#endif

    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (baud_rate == baud_rates[i].val)
	    return baud_rates[i].real_rate;
    }

    return 0;
}

static int
process_rs485(struct gensio_os_funcs *o, struct gensio_unix_termios *t, int fd,
	      const char *str)
{
#if HAVE_DECL_TIOCSRS485
    int argc, i;
    const char **argv;
    char *end;
    int err;

    if (!str || strcasecmp(str, "off") == 0) {
	t->rs485.flags &= ~SER_RS485_ENABLED;
	return 0;
    }

    err = gensio_str_to_argv(o, str, &argc, &argv, ":");

    if (err)
	return err;
    if (argc < 2)
	return GE_INVAL;

    t->rs485.delay_rts_before_send = strtoul(argv[0], &end, 10);
    if (end == argv[0] || *end != '\0')
	goto out_inval;

    t->rs485.delay_rts_after_send = strtoul(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0')
	goto out_inval;

    for (i = 2; i < argc; i++) {
	if (strcmp(argv[i], "rts_on_send") == 0) {
	    t->rs485.flags |= SER_RS485_RTS_ON_SEND;
	} else if (strcmp(argv[i], "rts_after_send") == 0) {
	    t->rs485.flags |= SER_RS485_RTS_AFTER_SEND;
	} else if (strcmp(argv[i], "rx_during_tx") == 0) {
	    t->rs485.flags |= SER_RS485_RX_DURING_TX;
#ifdef SER_RS485_TERMINATE_BUS
	} else if (strcmp(argv[i], "terminate_bus") == 0) {
	    t->rs485.flags |= SER_RS485_TERMINATE_BUS;
#endif
	} else {
	    goto out_inval;
	}
    }

    t->rs485.flags |= SER_RS485_ENABLED;

 out:
    gensio_argv_free(o, argv);
    return err;

 out_inval:
    err = GE_INVAL;
    goto out;
#else
    return GE_NOTSUP;
#endif
}

int
gensio_unix_termios_control(struct gensio_os_funcs *o, int op, bool get,
			    intptr_t val,
			    struct gensio_unix_termios **it, int fd)
{
    int rv = 0, nval, modemstate;
    struct gensio_unix_termios *t;

    switch (op) {
    case GENSIO_IOD_CONTROL_SERDATA:
    case GENSIO_IOD_CONTROL_BAUD:
    case GENSIO_IOD_CONTROL_PARITY:
    case GENSIO_IOD_CONTROL_XONXOFF:
    case GENSIO_IOD_CONTROL_RTSCTS:
    case GENSIO_IOD_CONTROL_DATASIZE:
    case GENSIO_IOD_CONTROL_STOPBITS:
    case GENSIO_IOD_CONTROL_LOCAL:
    case GENSIO_IOD_CONTROL_HANGUP_ON_DONE:
    case GENSIO_IOD_CONTROL_IXONXOFF:
    case GENSIO_IOD_CONTROL_RS485:
    case GENSIO_IOD_CONTROL_APPLY:
	rv = gensio_unix_setup_termios(o, fd, it);
	if (rv)
	    return rv;
	break;

    case GENSIO_IOD_CONTROL_FREE_SERDATA:
	o->free(o, (void *) val);
	return 0;

    default:
	break;
    }

    t = *it;

    switch (op) {
    case GENSIO_IOD_CONTROL_SERDATA:
	if (get) {
	    g_termios *rt;

	    rt = o->zalloc(o, sizeof(*t));
	    if (!rt)
		return GE_NOMEM;
	    *rt = t->curr_termios;
	    *((void **) val) = rt;
	} else {
	    t->curr_termios = *((g_termios *) val);
	    return 0;
	}
	break;

    case GENSIO_IOD_CONTROL_BAUD:
	if (get) {
	    rv = get_baud_rate(&t->curr_termios);
	    if (rv == 0)
		return GE_IOERR;
	    *((int *) val) = rv;
	    rv = 0;
	} else {
	    rv = set_baud_rate(&t->curr_termios, val);
	}
	break;

    case GENSIO_IOD_CONTROL_PARITY:
	if (get) {
	    if (t->curr_termios.c_cflag & PARENB) {
#ifdef CMSPAR
		if (t->curr_termios.c_cflag & CMSPAR) {
		    if (t->curr_termios.c_cflag & PARODD)
			*((int *) val) = SERGENSIO_PARITY_MARK;
		    else
			*((int *) val) = SERGENSIO_PARITY_SPACE;
		    break;
		}
#endif
		if (t->curr_termios.c_cflag & PARODD)
		    *((int *) val) = SERGENSIO_PARITY_ODD;
		else
		    *((int *) val) = SERGENSIO_PARITY_EVEN;
	    } else {
		*((int *) val) = SERGENSIO_PARITY_NONE;
	    }
	} else {
	    switch (val) {
	    case SERGENSIO_PARITY_NONE:
		t->curr_termios.c_cflag &= ~PARENB;
		break;

	    case SERGENSIO_PARITY_ODD:
		t->curr_termios.c_cflag |= PARENB | PARODD;
		break;

	    case SERGENSIO_PARITY_EVEN:
		t->curr_termios.c_cflag |= PARENB;
		t->curr_termios.c_cflag &= ~PARODD;
		break;

#ifdef CMSPAR
	    case SERGENSIO_PARITY_MARK:
		t->curr_termios.c_cflag |= PARENB | PARODD | CMSPAR;
		break;

	    case SERGENSIO_PARITY_SPACE:
		t->curr_termios.c_cflag |= PARENB | CMSPAR;
		t->curr_termios.c_cflag &= ~PARODD;
		break;
#endif
	    default:
		return GE_NOTSUP;
	    }
	}
	break;

    case GENSIO_IOD_CONTROL_XONXOFF:
	if (get) {
	    if (t->curr_termios.c_iflag & IXON)
		*((int *) val) = 1;
	    else
		*((int *) val) = 0;
	} else {
	    if (val) {
		t->curr_termios.c_iflag |= IXON;
		t->curr_termios.c_cc[VSTART] = 17;
		t->curr_termios.c_cc[VSTOP] = 19;
	    } else {
		t->curr_termios.c_iflag &= ~IXON;
	    }
	}
	break;

    case GENSIO_IOD_CONTROL_RTSCTS:
	if (get) {
	    if (t->curr_termios.c_cflag & CRTSCTS)
		*((int *) val) = 1;
	    else
		*((int *) val) = 0;
	} else {
	    if (val)
		t->curr_termios.c_cflag |= CRTSCTS;
	    else
		t->curr_termios.c_cflag &= ~CRTSCTS;
	}
	break;

    case GENSIO_IOD_CONTROL_DATASIZE:
	if (get) {
	    switch (t->curr_termios.c_cflag & CSIZE) {
	    case CS5: *((int *) val) = 5; break;
	    case CS6: *((int *) val) = 6; break;
	    case CS7: *((int *) val) = 7; break;
	    case CS8: *((int *) val) = 8; break;
	    }
	} else {
	    switch (val) {
	    case 5: nval = CS5; break;
	    case 6: nval = CS6; break;
	    case 7: nval = CS7; break;
	    case 8: nval = CS8; break;
	    default:
		return GE_INVAL;
	    }
	    t->curr_termios.c_cflag &= ~CSIZE;
	    t->curr_termios.c_cflag |= nval;
	}
	break;

    case GENSIO_IOD_CONTROL_STOPBITS:
	if (get) {
	    if (t->curr_termios.c_cflag & CSTOPB)
		*((int *) val) = 2;
	    else
		*((int *) val) = 1;
	} else {
	    if (val == 1)
		t->curr_termios.c_cflag &= ~CSTOPB;
	    else if (val == 2)
		t->curr_termios.c_cflag |= CSTOPB;
	    else
		return GE_INVAL;
	}
	break;

    case GENSIO_IOD_CONTROL_LOCAL:
	if (get) {
	    *((int *) val) = !!(t->curr_termios.c_cflag & CLOCAL);
	} else {
	    if (val)
		t->curr_termios.c_cflag |= CLOCAL;
	    else
		t->curr_termios.c_cflag &= ~CLOCAL;
	}
	break;

    case GENSIO_IOD_CONTROL_HANGUP_ON_DONE:
	if (get) {
	    *((int *) val) = !!(t->curr_termios.c_cflag & HUPCL);
	} else {
	    if (val)
		t->curr_termios.c_cflag |= HUPCL;
	    else
		t->curr_termios.c_cflag &= ~HUPCL;
	}
	break;

    case GENSIO_IOD_CONTROL_IXONXOFF:
	if (get) {
	    if (t->curr_termios.c_iflag & IXOFF)
		*((int *) val) = 1;
	    else
		*((int *) val) = 0;
	} else {
	    if (val) {
		t->curr_termios.c_iflag |= IXOFF;
		t->curr_termios.c_cc[VSTART] = 17;
		t->curr_termios.c_cc[VSTOP] = 19;
	    } else {
		t->curr_termios.c_iflag &= ~IXOFF;
	    }
	}
	break;

    case GENSIO_IOD_CONTROL_RS485:
	rv = process_rs485(o, t, fd, (const char *) val);
	break;

    case GENSIO_IOD_CONTROL_APPLY:
	rv = set_termios(fd, &t->curr_termios);
	if (rv) {
	    rv = gensio_os_err_to_err(o, errno);
#if HAVE_DECL_TIOCSRS485
	} else {
	    bool enabled = !!(t->rs485.flags & SER_RS485_ENABLED);

	    if (enabled != t->rs485_applied) {
		if (ioctl(fd, TIOCSRS485, &t->rs485) < 0) {
		    rv = gensio_os_err_to_err(o, errno);
		    if (!rv)
			enabled = t->rs485_applied;
		}
	    }
#endif
	}
	break;

    case GENSIO_IOD_CONTROL_SET_BREAK:
	if (get) {
	    *((int *) val) = t->break_set;
	} else {
	    if (val)
		nval = TIOCSBRK;
	    else
		nval = TIOCCBRK;
	    if (ioctl(fd, nval) == -1)
		return gensio_os_err_to_err(o, errno);
	    t->break_set = nval;
	}
	break;

    case GENSIO_IOD_CONTROL_SEND_BREAK:
	if (get)
	    *((int *) val) = 0;
	else
	    do_break(fd);
	break;

    case GENSIO_IOD_CONTROL_DTR:
	if (ioctl(fd, TIOCMGET, &nval) == -1)
	    return gensio_os_err_to_err(o, errno);
	if (get) {
	    *((int *) val) = !!(nval & TIOCM_DTR);
	} else {
	    if (val)
		nval |= TIOCM_DTR;
	    else
		nval &= ~TIOCM_DTR;
	    if (ioctl(fd, TIOCMSET, &nval) == -1)
		return gensio_os_err_to_err(o, errno);
	}
	break;

    case GENSIO_IOD_CONTROL_RTS:
	if (ioctl(fd, TIOCMGET, &nval) == -1)
	    return gensio_os_err_to_err(o, errno);
	if (get) {
	    *((int *) val) = !!(nval & TIOCM_RTS);
	} else {
	    if (val)
		nval |= TIOCM_RTS;
	    else
		nval &= ~TIOCM_RTS;
	    if (ioctl(fd, TIOCMSET, &nval) == -1)
		return gensio_os_err_to_err(o, errno);
	}
	break;

    case GENSIO_IOD_CONTROL_MODEMSTATE:
	if (!get)
	    return GE_NOTSUP;
	if (ioctl(fd, TIOCMGET, &nval) == -1)
	    return gensio_os_err_to_err(o, errno);
	modemstate = 0;
	if (nval & TIOCM_CD)
	    modemstate |= SERGENSIO_MODEMSTATE_CD;
	if (nval & TIOCM_RI)
	    modemstate |= SERGENSIO_MODEMSTATE_RI;
	if (nval & TIOCM_DSR)
	    modemstate |= SERGENSIO_MODEMSTATE_DSR;
	if (nval & TIOCM_CTS)
	    modemstate |= SERGENSIO_MODEMSTATE_CTS;
	*((int *) val) = modemstate;
	break;

    case GENSIO_IOD_CONTROL_FLOWCTL_STATE:
	if (get)
	    return GE_NOTSUP;
	set_flowcontrol(fd, val);
	break;
    }

    return rv;
}

void
gensio_unix_do_flush(struct gensio_os_funcs *o, int fd, int whichbuf)
{
    int arg;

    if ((whichbuf & (GENSIO_IN_BUF | GENSIO_OUT_BUF)) ==
			(GENSIO_IN_BUF | GENSIO_OUT_BUF))
	arg = TCIOFLUSH;
    else if (whichbuf & GENSIO_IN_BUF)
	arg = TCIFLUSH;
    else if (whichbuf & GENSIO_OUT_BUF)
	arg = TCIOFLUSH;
    else
	return;

    do_flush(fd, arg);
}

int
gensio_unix_get_bufcount(struct gensio_os_funcs *o,
			 int fd, int whichbuf, gensiods *rcount)
{
    int rv = 0, count;

    if (isatty(fd)) {
	switch (whichbuf) {
	case GENSIO_IN_BUF:
	    rv = ioctl(fd, TIOCINQ, &count);
	    break;

	case GENSIO_OUT_BUF:
	    rv = ioctl(fd, TIOCOUTQ, &count);
	    break;

	default:
	    return GE_NOTSUP;
	}
    } else {
	count = 0; /* Doesn't matter for anything else. */
    }
    if (rv)
	rv = gensio_os_err_to_err(o, errno);
    else
	*rcount = count;
    return rv;
}

extern char **environ;

int
gensio_unix_do_exec(struct gensio_os_funcs *o,
		    const char *argv[], const char **env,
		    bool stderr_to_stdout,
		    int *rpid,
		    int *rin, int *rout, int *rerr)
{
    int err;
    int stdinpipe[2] = {-1, -1};
    int stdoutpipe[2] = {-1, -1};
    int stderrpipe[2] = {-1, -1};
    int pid = -1;

    if (stderr_to_stdout && rerr)
	return GE_INVAL;

    err = pipe(stdinpipe);
    if (err) {
	err = errno;
	goto out_err;
    }

    err = pipe(stdoutpipe);
    if (err) {
	err = errno;
	goto out_err;
    }

    if (rerr) {
	err = pipe(stderrpipe);
	if (err) {
	    err = errno;
	    goto out_err;
	}
    }

    pid = fork();
    if (pid < 0) {
	err = errno;
	goto out_err;
    }
    if (pid == 0) {
	int i, openfiles = sysconf(_SC_OPEN_MAX);

	dup2(stdinpipe[0], 0);
	dup2(stdoutpipe[1], 1);
	if (stderr_to_stdout)
	    dup2(stdoutpipe[1], 2);
	else if (rerr)
	    dup2(stderrpipe[1], 2);

	/* Close everything but stdio. */
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

	execvp(argv[0], (char * const *) argv);
	fprintf(stderr, "Err: %s %s\r\n", argv[0], strerror(errno));
	exit(1); /* Only reached on error. */
    }

    close(stdinpipe[0]);
    close(stdoutpipe[1]);
    if (rerr)
	close(stderrpipe[1]);

    *rpid = pid;
    *rin = stdinpipe[1];
    *rout = stdoutpipe[0];
    if (rerr)
	*rerr = stderrpipe[0];
    return 0;

 out_err:
    err = gensio_os_err_to_err(o, err);
    if (stdinpipe[0] != -1)
	close(stdinpipe[0]);
    if (stdinpipe[1] != -1)
	close(stdinpipe[1]);
    if (stdoutpipe[0] != -1)
	close(stdoutpipe[0]);
    if (stdoutpipe[1] != -1)
	close(stdoutpipe[1]);
    if (stderrpipe[0] != -1)
	close(stderrpipe[0]);
    if (stderrpipe[1] != -1)
	close(stderrpipe[1]);

    return err;
}

#endif /* _WIN32 */

#ifdef ENABLE_INTERNAL_TRACE

#include <pthread_handler.h>

#define TRACEBACK_DEPTH 1

#define MEM_MAGIC 0xddf0983aec9320b0
#define MEM_BUFFER 32
struct mem_header {
    uint64_t magic;
    struct gensio_link link;
    int32_t freed;
    int32_t size;
    void *alloc_bt[4];
    void* free_bt[4];
    unsigned char filler[MEM_BUFFER];
};

struct gensio_memtrack {
    bool abort_on_err;
    bool check_on_all;
    lock_type lock;
    struct gensio_list alloced;
    struct gensio_list freed;
};

static void
mem_fill(unsigned char *d)
{
    unsigned int i;

    for (i = 0; i < MEM_BUFFER; i++)
	d[i] = 0xfd;
}

static bool
mem_check(unsigned char *d)
{
    unsigned int i;

    for (i = 0; i < MEM_BUFFER; i++) {
	if (d[i] != 0xfd)
	    return false;
    }
    return true;
}

static void
print_meminfo(const char *msg, struct mem_header *h)
{
    fprintf(stderr, "%s at %p allocated at %p %p %p %p\n", msg,
	    ((char *) h) + sizeof(*h), h->alloc_bt[0], h->alloc_bt[1],
	    h->alloc_bt[2], h->alloc_bt[3]);
    if (h->freed)
	fprintf(stderr, "  freed at at %p %p %p %p\n",
		h->free_bt[0], h->free_bt[1],
		h->free_bt[2], h->free_bt[3]);
}

static bool
check_mem(struct gensio_memtrack *m, struct mem_header *h, int32_t freed)
{
    unsigned char *b = ((unsigned char *) h) + sizeof(*h);
    bool err = false;

    if (h->magic != MEM_MAGIC) {
	fprintf(stderr, "Magic mismatch at %p\n", h);
	err = true;
    } else if (h->freed != freed) {
	if (freed)
	    print_meminfo("Free in allocated list", h);
	else
	    print_meminfo("Double free", h);
	err = true;
    } else if (!mem_check(h->filler)) {
	print_meminfo("Memory underrun", h);
	err = true;
    } else if (!mem_check(b + h->size)) {
	print_meminfo("Memory overrun", h);
	err = true;
    }

    assert(!(err && m->abort_on_err));

    return err;
}

struct gensio_memtrack *
gensio_memtrack_alloc(void)
{
    char *s = getenv("GENSIO_MEMTRACK");
    struct gensio_memtrack *m;

    if (!s)
	return NULL;

    m = malloc(sizeof(*m));
    if (!m)
	return NULL;

    LOCK_INIT(&m->lock);
    gensio_list_init(&m->alloced);
    gensio_list_init(&m->freed);

    if (strstr(s, "abort"))
	m->abort_on_err = true;
    if (strstr(s, "checkall"))
	m->check_on_all = true;

    return m;
}

void
gensio_memtrack_cleanup(struct gensio_memtrack *m)
{
    struct gensio_link* l;

    if (!m)
	return;

    gensio_list_for_each(&m->alloced, l) {
	struct mem_header *h = gensio_container_of(l, struct mem_header,
						   link);

	print_meminfo("Lost memory", h);
    }
    assert(!(m->abort_on_err && !gensio_list_empty(&m->alloced)));

    LOCK_DESTROY(&m->lock);
    free(m);
}

void *
gensio_i_zalloc(struct gensio_memtrack *m, unsigned int size)
{
    unsigned char *b;

    if (do_errtrig())
	return NULL;

    if (m) {
	struct mem_header *h;

	b = malloc(size + sizeof(*h) + MEM_BUFFER);
	if (!b)
	    return NULL;
	h = (struct mem_header *) b;
	memset(h, 0, sizeof(*h));
	gensio_list_link_init(&h->link);
	h->magic = MEM_MAGIC;
	h->freed = 0;
	h->size = size;
#if _MSC_VER
	h->alloc_bt[0] = _ReturnAddress();
#else
	h->alloc_bt[0] = __builtin_return_address(0);
#if TRACEBACK_DEPTH > 1
	h->alloc_bt[1] = __builtin_return_address(1);
#if TRACEBACK_DEPTH > 2
	h->alloc_bt[2] = __builtin_return_address(2);
#if TRACEBACK_DEPTH > 3
	h->alloc_bt[3] = __builtin_return_address(3);
#endif
#endif
#endif
#endif
	b += sizeof(struct mem_header);
	mem_fill(h->filler);
	mem_fill(b + size);
	LOCK(&m->lock);
	gensio_list_add_tail(&m->alloced, &h->link);
	UNLOCK(&m->lock);
    } else {
	b = malloc(size);
    }
    if (b)
	memset(b, 0, size);
    return b;
}

void
gensio_i_free(struct gensio_memtrack *m, void *data)
{
    if (m) {
	unsigned char *b = data;
	struct mem_header *h = (struct mem_header*)(b - sizeof(*h));
	struct gensio_link *l;
	bool err;

#if _MSC_VER
	h->free_bt[0] = _ReturnAddress();
#else
	h->free_bt[0] = __builtin_return_address(0);
#if TRACEBACK_DEPTH > 1
	h->free_bt[1] = __builtin_return_address(1);
#if TRACEBACK_DEPTH > 2
	h->free_bt[2] = __builtin_return_address(2);
#if TRACEBACK_DEPTH > 3
	h->free_bt[3] = __builtin_return_address(3);
#endif
#endif
#endif
#endif
	err = check_mem(m, h, 0);
	if (!err) {
	    LOCK(&m->lock);
	    gensio_list_rm(&m->alloced, &h->link);

	    if (m->check_on_all) {
		/* The following does more serious but costly memory checking */
		gensio_list_for_each(&m->alloced, l) {
		    struct mem_header *h2 = gensio_container_of(l,
							    struct mem_header,
							    link);

		    check_mem(m, h2, 0);
		}
		gensio_list_for_each(&m->freed, l) {
		    struct mem_header *h2 = gensio_container_of(l,
							    struct mem_header,
							    link);

		    check_mem(m, h2, 1);
		}
	    }

	    gensio_list_add_tail(&m->freed, &h->link);
	    h->freed = 1;
	    UNLOCK(&m->lock);
	}
    } else {
	free(data);
    }
}

#else /* ENABLE_INTERNAL_TRACE */

struct gensio_memtrack *
gensio_memtrack_alloc(void)
{
    return NULL;
}

void
gensio_memtrack_cleanup(struct gensio_memtrack *m)
{
}

void *
gensio_i_zalloc(struct gensio_memtrack *m, unsigned int size)
{
    return malloc(size);
}

void
gensio_i_free(struct gensio_memtrack *m, void *data)
{
    free(data);
}

#endif /* ENABLE_INTERNAL_TRACE */
