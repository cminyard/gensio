/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifdef linux
#define _XOPEN_SOURCE 600 /* Get posix_openpt() and friends. */
#define _GNU_SOURCE /* Get ptsname_r(). */
#endif

#include "config.h"
#define _DEFAULT_SOURCE /* Get getgrouplist(), setgroups() */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#ifdef HAVE_TCPD_H
#include <tcpd.h>
#endif /* HAVE_TCPD_H */

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_os_funcs_public.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_list.h>

#include "errtrig.h"

static const char *progname = "gensio";

bool gensio_set_progname(const char *iprogname)
{
    progname = iprogname;
    return true;
}

const char *gensio_get_progname(void)
{
    return progname;
}


#ifdef _WIN32
#include <winsock2.h> /* For AF_UNSPEC */
#include <windows.h>
#include <iphlpapi.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h> /* For AF_UNSPEC */
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/if.h>
#include <limits.h>
#include <dlfcn.h>

int
gensio_unix_os_setupnewprog(void)
{
    struct passwd *pw;
    int err;
    uid_t uid = getuid();
    gid_t *groups = NULL;
    int ngroup = 0;

    if (do_errtrig())
	return GE_NOMEM;

    if (uid == geteuid())
	return 0;

    pw = getpwuid(uid);
    if (!pw)
	return errno;

    /* Sets the real, effective, and saved group. */
    err = setgid(getgid());
    if (err)
	return errno;

    getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroup);
    if (ngroup > 0) {
	int ngroup2 = ngroup;

	groups = malloc(sizeof(gid_t) * ngroup);
	if (!groups)
	    return ENOMEM;

	err = getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroup2);
	if (err == -1) {
	    err = errno;
	    free(groups);
	    return err;
	}
	/*
	 * There is some possibility that the number of groups will
	 * change between the calls.  If the new on is bigger than the
	 * old, use the old one to avoid accessing past the end of the
	 * buffer.  If the new one is smaller, use that.
	 */
	if (ngroup2 < ngroup)
	    ngroup = ngroup2;

	err = setgroups(ngroup, groups);
	if (err) {
	    err = errno;
	    free(groups);
	    return err;
	}
	free(groups);
    }

    /* Sets the real, effective, and saved userid. */
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


void
gensio_os_free_net_ifs(struct gensio_os_funcs *o,
		       struct gensio_net_if **ifs, unsigned int nifs)
{
    unsigned int i, j;

    for (i = 0; i < nifs; i++) {
	if (!ifs)
	    continue;
	if (ifs[i]->name)
	    gensio_os_funcs_zfree(o, ifs[i]->name);
	if (ifs[i]->addrs) {
	    for (j = 0; j < ifs[i]->naddrs; j++) {
		if (ifs[i]->addrs[j].addrstr)
		    gensio_os_funcs_zfree(o, ifs[i]->addrs[j].addrstr);
	    }
	    gensio_os_funcs_zfree(o, ifs[i]->addrs);
	}
	gensio_os_funcs_zfree(o, ifs[i]);
    }
    gensio_os_funcs_zfree(o, ifs);
}

#ifndef _WIN32
static bool
is_inet_family(struct sockaddr *s)
{
    if (!s) /* This can happen on down interfaces. */
	return false;
    return (s->sa_family == AF_INET || s->sa_family == AF_INET6);
}
#endif

int
gensio_os_get_net_ifs(struct gensio_os_funcs *o,
		      struct gensio_net_if ***rifs, unsigned int *rnifs)
{
    struct gensio_net_if **ifs = NULL;
    char buf[100], *addrtype;
#ifdef _WIN32
    IP_ADAPTER_ADDRESSES *t, *c;
    ULONG err;
    unsigned int i, j, nifs;
    ULONG buflen = 15 * 1024;

    while (true) {
	t = o->zalloc(o, buflen);
	if (!t)
	    return GE_NOMEM;
	err = GetAdaptersAddresses(AF_UNSPEC,
				   (GAA_FLAG_SKIP_ANYCAST |
				    GAA_FLAG_SKIP_MULTICAST |
				    GAA_FLAG_SKIP_DNS_SERVER |
				    GAA_FLAG_SKIP_FRIENDLY_NAME),
				   NULL, t, &buflen);
	if (err == NO_ERROR)
	    break;
	o->free(o, t);
	if (err == ERROR_BUFFER_OVERFLOW) {
	    /* Just retry */
	} else if (err == ERROR_NOT_ENOUGH_MEMORY) {
	    return GE_NOMEM;
	} else {
	    return GE_OSERR;
	}
    }

    i = 0;
    for (c = t; c; c = c->Next) {
	if (c->IfIndex != c->Ipv6IfIndex && c->Ipv6IfIndex != 0)
	    continue; /* FIXME - Not sure what to do with these. */
	i++;
    }
    nifs = i;

    ifs = gensio_os_funcs_zalloc(o, sizeof(*ifs) * (nifs + 1));
    if (!ifs)
	goto out_err;

    i = 0;
    for (c = t; c; c = c->Next) {
	IP_ADAPTER_UNICAST_ADDRESS *al;
	unsigned int slen;
	size_t rlen;

	if (c->IfIndex != c->Ipv6IfIndex && c->Ipv6IfIndex != 0)
	    continue; /* FIXME - Not sure what to do with these. */

	ifs[i] = gensio_os_funcs_zalloc(o, sizeof(**ifs));
	if (!ifs[i])
	    goto out_err;

	ifs[i]->ifindex = c->IfIndex;
	if (c->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
	    ifs[i]->flags |= GENSIO_NET_IF_LOOPBACK;
	if (c->OperStatus == IfOperStatusUp)
	    ifs[i]->flags |= GENSIO_NET_IF_UP;
	if (!c->NoMulticast)
	    ifs[i]->flags |= GENSIO_NET_IF_MULTICAST;
	slen = wcslen(c->FriendlyName) * 2;
	ifs[i]->name = o->zalloc(o, slen + 1);
	if (!ifs[i]->name)
	    goto out_err;
	wcstombs_s(&rlen, ifs[i]->name, slen + 1, c->FriendlyName, slen);

	for (j = 0, al = c->FirstUnicastAddress; al; j++, al = al->Next)
	    ;
	ifs[i]->addrs = o->zalloc(o, sizeof(struct gensio_net_addr) * j);
	if (!ifs[i]->addrs)
	    goto out_err;
	for (j = 0, al = c->FirstUnicastAddress; al; al = al->Next) {
	    struct sockaddr *a = (void *) al->Address.lpSockaddr;

	    if (a->sa_family == AF_INET) {
		struct sockaddr_in *ia = (void *) a;

		ifs[i]->addrs[j].family = GENSIO_NETTYPE_IPV4;
		ifs[i]->addrs[j].netbits = al->OnLinkPrefixLength;
		ifs[i]->addrs[j].addrlen = 4;
		memcpy(ifs[i]->addrs[j].addr, &ia->sin_addr, 4);
		addrtype = "ipv4:";
	    } else if (a->sa_family == AF_INET6) {
		struct sockaddr_in6 *ia = (void *) a;

		ifs[i]->addrs[j].family = GENSIO_NETTYPE_IPV6;
		ifs[i]->addrs[j].netbits = al->OnLinkPrefixLength;
		ifs[i]->addrs[j].addrlen = 16;
		memcpy(ifs[i]->addrs[j].addr, &ia->sin6_addr, 16);
		addrtype = "ipv6:";
	    } else {
		continue;
	    }
	    memcpy(buf, addrtype, 5);
	    inet_ntop(a->sa_family, ifs[i]->addrs[j].addr,
		      buf + 5, sizeof(buf) - 5);
	    ifs[i]->addrs[j].addrstr = gensio_strdup(o, buf);
	    if (!ifs[i]->addrs[j].addrstr)
		goto out_err;
	    j++;
	}
	ifs[i]->naddrs = j;

	i++;
	assert(i <= nifs);
    }

    o->free(o, t);
    *rifs = ifs;
    *rnifs = i;

    return 0;
 out_err:
    o->free(o, t);
    if (ifs)
	gensio_os_free_net_ifs(o, ifs, nifs);
    return GE_NOMEM;
#else
    struct ifaddrs *ifap, *ifp, *ifp2;
    unsigned int i, j, k, nifs = 0, naddrs, addrlen, nbits;
    unsigned char *addr, *netmask;
    int rv;
    bool found;

    rv = getifaddrs(&ifap);
    if (rv) {
	rv = gensio_os_err_to_err(o, errno);
	return rv;
    }

    /* Count the number of unique interfaces by name. */
    for (ifp = ifap; ifp; ifp = ifp->ifa_next) {
	if (!is_inet_family(ifp->ifa_addr))
	    continue;

	found = false;
	for (ifp2 = ifap; ifp2 != ifp; ifp2 = ifp2->ifa_next) {
	    if (!is_inet_family(ifp2->ifa_addr))
		continue;
	    if (strcmp(ifp2->ifa_name, ifp->ifa_name) == 0) {
		found = true;
		break;
	    }
	}
	if (found)
	    continue;
	nifs++;
    }
    rv = GE_NOMEM;
    ifs = gensio_os_funcs_zalloc(o, sizeof(*ifs) * (nifs + 1));
    if (!ifs)
	goto out_err;
    for (ifp = ifap; ifp; ifp = ifp->ifa_next) {
	if (!is_inet_family(ifp->ifa_addr))
	    continue;

	for (i = 0; i < nifs && ifs[i]; i++) {
	    if (strcmp(ifs[i]->name, ifp->ifa_name) == 0)
		break;
	}
	if (!ifs[i]) {
	    /*
	     * First occurence of this name, allocate info and the
	     * if address array.
	     */
	    ifs[i] = gensio_os_funcs_zalloc(o, sizeof(**ifs));
	    if (!ifs[i])
		goto out_err;
	    ifs[i]->name = gensio_strdup(o, ifp->ifa_name);
	    if (!ifs[i]->name)
		goto out_err;
	    ifs[i]->ifindex = if_nametoindex(ifp->ifa_name);
	    if (!ifs[i]->ifindex) {
		rv = gensio_os_err_to_err(o, errno);
		goto out_err;
	    }

	    /* Count the number of addresses for this interface. */
	    naddrs = 1;
	    for (ifp2 = ifp->ifa_next; ifp2; ifp2 = ifp2->ifa_next) {
		if (!is_inet_family(ifp2->ifa_addr))
		    continue;

		if (strcmp(ifp2->ifa_name, ifp->ifa_name) == 0)
		    naddrs++;
	    }
	    ifs[i]->addrs = gensio_os_funcs_zalloc(o,
				  naddrs * sizeof(struct gensio_net_addr));
	    if (!ifs[i]->addrs)
		goto out_err;
	}
	if (ifp->ifa_flags & IFF_UP)
	    ifs[i]->flags |= GENSIO_NET_IF_UP;
	if (ifp->ifa_flags & IFF_LOOPBACK)
	    ifs[i]->flags |= GENSIO_NET_IF_LOOPBACK;
	if (ifp->ifa_flags & IFF_MULTICAST)
	    ifs[i]->flags |= GENSIO_NET_IF_MULTICAST;
	if (ifp->ifa_addr->sa_family == AF_INET) {
	    struct sockaddr_in *s;

	    s = (struct sockaddr_in *) ifp->ifa_addr;
	    addr = (unsigned char *) &s->sin_addr;
	    s = (struct sockaddr_in *) ifp->ifa_netmask;
	    netmask = (unsigned char *) &s->sin_addr;
	    addrlen = 4;
	    addrtype = "ipv4:";
	} else {
	    struct sockaddr_in6 *s;

	    s = (struct sockaddr_in6 *) ifp->ifa_addr;
	    addr = s->sin6_addr.s6_addr;
	    s = (struct sockaddr_in6 *) ifp->ifa_netmask;
	    netmask = s->sin6_addr.s6_addr;
	    addrlen = 16;
	    addrtype = "ipv6:";
	}

	j = (ifs[i]->naddrs)++;
	memcpy(ifs[i]->addrs[j].addr, addr, addrlen);
	ifs[i]->addrs[j].addrlen = addrlen;
	if (ifp->ifa_addr->sa_family == AF_INET)
	    ifs[i]->addrs[j].family = GENSIO_NETTYPE_IPV4;
	else
	    ifs[i]->addrs[j].family = GENSIO_NETTYPE_IPV6;
	for (nbits = 0, k = 0; k < addrlen && netmask[k] == 0xff; k++)
	    nbits += 8;
	if (k < addrlen) {
	    unsigned char v = netmask[k];

	    while (v & 0xff) {
		if (v & 0x80)
		    nbits++;
		else
		    break;
		v <<= 1;
	    }
	}
	ifs[i]->addrs[j].netbits = nbits;
	memcpy(buf, addrtype, 5);
	inet_ntop(ifp->ifa_addr->sa_family, addr, buf + 5, sizeof(buf) - 5);
	ifs[i]->addrs[j].addrstr = gensio_strdup(o, buf);
	if (!ifs[i]->addrs[j].addrstr)
	    goto out_err;
    }
    freeifaddrs(ifap);
    *rifs = ifs;
    *rnifs = nifs;

    return 0;

 out_err:
    freeifaddrs(ifap);
    if (ifs)
	gensio_os_free_net_ifs(o, ifs, nifs);
    return rv;
#endif
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

#include <wtsapi32.h>
#include <ntsecapi.h>
#include <userenv.h>
#include <sddl.h>

struct stdio_mode {
    DWORD old_mode_flags;
};

int
gensio_win_stdin_makeraw(struct gensio_os_funcs *o, HANDLE h,
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
    mode |= ENABLE_WINDOW_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT;

    if (!SetConsoleMode(h, mode)) {
	if (m)
	    o->free(o, m);
	return gensio_os_err_to_err(o, GetLastError());
    }

    if (m)
	*rm = m;

    return 0;
}

int
gensio_win_stdout_makeraw(struct gensio_os_funcs *o, HANDLE h,
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

    mode = omode;
    mode |= (ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING
	     | ENABLE_WRAP_AT_EOL_OUTPUT);

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
    o->free(o, *c);
    *c = NULL;
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

/*
 * Convert a normal env array to a Windows environment block, which is
 * a single block of memory with each entry separated by a \0, and
 * terminated by two \0.
 */
static char *
win_env_to_block(struct gensio_os_funcs *o,
		 const char **env,
		 gensiods *rsize)
{
    /*
     * Start with size=2 because this must be terminated with two nil
     * chars.  If the environment was empty, we would only get one nil
     * char otherwise.  We waste a byte, but no big deal.
     */
    gensiods i, size = 2, len;
    char *envb, *pos;

    for (i = 0; env[i]; i++)
	size += strlen(env[i]) + 1;

    envb = o->zalloc(o, size);
    if (!envb)
	return NULL;
    for (i = 0, pos = envb; env[i]; i++) {
	len = strlen(env[i]);
	memcpy(pos, env[i], len);
	pos += len + 1;
    }
    if (rsize)
	*rsize = size;
    return envb;
}

int
gensio_win_do_exec(struct gensio_os_funcs *o,
		   const char *argv[], const char **env,
		   const char *start_dir,
		   unsigned int flags,
		   HANDLE *phandle,
		   HANDLE *rin, HANDLE *rout, HANDLE *rerr)
{
    int rv = 0;
    char *cmdline, *envb = NULL;
    SECURITY_ATTRIBUTES sattr;
    STARTUPINFOA suinfo;
    PROCESS_INFORMATION procinfo;
    HANDLE stdin_m = NULL, stdin_s = NULL;
    HANDLE stdout_m = NULL, stdout_s = NULL;
    HANDLE stderr_m = NULL, stderr_s = NULL;

    if (rerr && (flags & GENSIO_EXEC_STDERR_TO_STDOUT))
	return GE_INVAL;

    rv = argv_to_win_cmdline(o, argv, &cmdline);
    if (rv)
	return rv;

    if (env) {
	envb = win_env_to_block(o, env, NULL);
	if (!envb) {
	    rv = GE_NOMEM;
	    goto out;
	}
    }

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

    if (flags & GENSIO_EXEC_STDERR_TO_STDOUT) {
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
    if (!SetHandleInformation(stderr_s, HANDLE_FLAG_INHERIT,
			      HANDLE_FLAG_INHERIT))
	goto out_err_conv;

    suinfo.cb = sizeof(STARTUPINFO);
    suinfo.hStdInput = stdin_s;
    suinfo.hStdOutput = stdout_s;
    suinfo.hStdError = stderr_s;
    suinfo.dwFlags |= STARTF_USESTDHANDLES;

    if (!CreateProcess(NULL,
		       cmdline,
		       NULL,
		       NULL,
		       FALSE,
		       NORMAL_PRIORITY_CLASS,
		       envb,
		       start_dir,
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

 out:
    if (envb)
	o->free(o, envb);
    if (cmdline)
	o->free(o, cmdline);
    return rv;
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
get_logon_sid_from_token(HANDLE h, SID **logon_sid, bool *found)
{
    DWORD err;
    unsigned int i;
    TOKEN_GROUPS *grps = NULL;
    SID *sid;

    err = read_token_info(h, TokenGroups, (void **) &grps, NULL);
    if (err) {
	/* Not an error if the token doesn't have groups. */
	err = 0;
	goto out_err;
    }

    /* Now scan for a logon id SID. */
    for (i = 0; i < grps->GroupCount; i++) {
	if ((grps->Groups[i].Attributes & SE_GROUP_LOGON_ID) ==
	    SE_GROUP_LOGON_ID) {
	    int len = GetLengthSid(grps->Groups[i].Sid);

	    sid = (SID *) malloc(len);
	    if (!sid) {
		err = STATUS_NO_MEMORY;
		goto out_err;
	    }
	    if (!CopySid(len, sid, grps->Groups[i].Sid)) {
		err = GetLastError();
		goto out_err;
	    }
	    *logon_sid = sid;
	    sid = NULL;
	    *found = true;
	    break;
	}
    }

 out_err:
    if (grps)
	free(grps);
    if (sid)
	free(sid);

    return err;
}

static DWORD
get_logon_sid(SID *user, SID **logon_sid, bool *rfound)
{
    DWORD err;
    unsigned int i;
    bool found = false;
    WTS_SESSION_INFOA *sesinfo = NULL;
    DWORD sescount;
    TOKEN_USER *usid = NULL;
    HANDLE h = NULL;

    /*
     * Try the calling user's token first.
     */
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h);
    err = get_logon_sid_from_token(h, logon_sid, &found);
    CloseHandle(h);
    if (!err && found) {
	*rfound = true;
	return 0;
    }
    /*
     * Find a session with the same user SID as the passed in user.
     */
    if (!WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1,
			       &sesinfo, &sescount)) {
	err = GetLastError();
	goto out_err;
    }

    for (i = 0; !found && i < sescount; i++) {
	if (!WTSQueryUserToken(sesinfo[i].SessionId, &h))
	    continue;

	/* Check to make sure it's our user. */
	err = read_token_info(h, TokenUser, (void **) &usid, NULL);
	if (err)
	    goto continue_scan;
	if (!EqualSid(usid->User.Sid, user))
	    goto continue_scan;

	err = get_logon_sid_from_token(h, logon_sid, &found);
	if (err)
	    goto out_err;

    continue_scan:
	if (h) {
	    CloseHandle(h);
	    h = NULL;
	}
	if (usid) {
	    free(usid);
	    usid = NULL;
	}
    }

    /* Not finding is not an error, we just report it. */
    *rfound = found;
    err = 0;

 out_err:
    if (h)
	CloseHandle(h);
    if (sesinfo)
	WTSFreeMemory(sesinfo);
    if (usid)
	free(usid);
    return err;
}

static void
set_lsa_string(LSA_STRING *a, const char *b)
{
    a->Length = (USHORT) strlen(b);
    a->MaximumLength = (USHORT)(a->Length + sizeof(*b));
    a->Buffer = (char *) b;
}

static void
add_unicode_str(UNICODE_STRING *ustr, const char *str, unsigned int len,
		char **pos)
{
    unsigned int blen = len * sizeof(wchar_t);

    ustr->Buffer = (wchar_t *) *pos;
    mbstowcs(ustr->Buffer, str, len);
    ustr->Length = blen;
    ustr->MaximumLength = blen;
    *pos += blen;
}

static DWORD
get_kerb_logon(const char *user, const char *password, bool interactive,
	       void **logon_info, DWORD *logon_info_len,
	       SECURITY_LOGON_TYPE *logon_type)
{
    DWORD user_chars = mbstowcs(NULL, user, strlen(user));
    DWORD user_bytes = user_chars * sizeof(wchar_t);
    DWORD domain_chars = strchr(user, '\\') - user;
    DWORD real_user_chars = strlen(user + domain_chars + 1);
    DWORD logon_len;
    char *pos;

    if (password) {
	DWORD pw_chars = mbstowcs(NULL, password, strlen(password));
	DWORD pw_bytes = pw_chars * sizeof(wchar_t);
	KERB_INTERACTIVE_LOGON *int_logon;

	/*
	 * KERB_S4U_LOGON must be passed as a single contiguous buffer
	 * that includes all strings, otherwise LsaLogonUser will
	 * complain.  Add an extra char for the termination, just in
	 * case.
	 */
	logon_len = sizeof(KERB_INTERACTIVE_LOGON) + user_bytes + pw_bytes;
	int_logon = calloc(logon_len + sizeof(wchar_t), 1);
	if (!int_logon)
	    return STATUS_NO_MEMORY;
	int_logon->MessageType = KerbInteractiveLogon;
	pos = (char *) (int_logon + 1);
	add_unicode_str(&int_logon->LogonDomainName, user, domain_chars, &pos);
	user += domain_chars + 1; /* SKip over domain\ */
	add_unicode_str(&int_logon->UserName, user, real_user_chars, &pos);
	add_unicode_str(&int_logon->Password, password, pw_chars, &pos);
	*logon_info = int_logon;
	*logon_type = Interactive;
    } else {
	/* look up the Kerb authentication provider's index */
	KERB_S4U_LOGON *s4u_logon;
	char *tmpstr, *upnstr;

	upnstr = malloc(user_chars + 1);
	if (!upnstr)
	    return STATUS_NO_MEMORY;
	tmpstr = upnstr;
	memcpy(tmpstr, user + domain_chars + 1, real_user_chars);
	tmpstr += real_user_chars;
	*tmpstr++ = '@';
	memcpy(tmpstr, user, domain_chars);
	tmpstr += domain_chars;
	*tmpstr = '\0';

	/*
	 * KERB_S4U_LOGON must be passed as a single contiguous buffer
	 * that includes all strings, otherwise LsaLogonUser will
	 * complain.  Add an extra char for the termination, just in
	 * case.
	 */
	logon_len = sizeof(KERB_S4U_LOGON) + user_bytes;
	s4u_logon = calloc(logon_len + sizeof(wchar_t), 1);
	if (!s4u_logon) {
	    free(upnstr);
	    return STATUS_NO_MEMORY;
	}
	s4u_logon->MessageType = KerbS4ULogon;
	if (interactive)
	    s4u_logon->Flags = KERB_S4U_LOGON_FLAG_IDENTIFY;
	pos = (char *) (s4u_logon + 1);
	add_unicode_str(&s4u_logon->ClientUpn, upnstr, user_chars, &pos);
	free(upnstr);
	*logon_info = s4u_logon;
	*logon_type = Network;
    }
    *logon_info_len = logon_len;
    return 0;
}

static DWORD
get_local_logon(const char *user, const char *password,
		void **logon_info, DWORD *logon_info_len,
		SECURITY_LOGON_TYPE *logon_type)
{
    DWORD user_chars = mbstowcs(NULL, user, strlen(user));
    DWORD user_bytes = user_chars * sizeof(wchar_t);
    DWORD logon_len;
    char *pos;

    if (password) {
	DWORD pw_chars = mbstowcs(NULL, password, strlen(password));
	DWORD pw_bytes = pw_chars * sizeof(wchar_t);
	MSV1_0_INTERACTIVE_LOGON *mi_logon;

	/*
	 * MSV1_0_INTERACTIVE_LOGON must be passed as a single
	 * contiguous buffer that includes all strings, otherwise
	 * LsaLogonUser will complain.  Add an extra char for the
	 * termination, just in case.
	 */
	logon_len = (sizeof(*mi_logon) + user_bytes + pw_bytes +
		     sizeof(wchar_t));
	mi_logon = (MSV1_0_INTERACTIVE_LOGON *) malloc(logon_len);
	if (!mi_logon)
	    return STATUS_NO_MEMORY;
	mi_logon->MessageType = MsV1_0InteractiveLogon;

	pos = (char *) (mi_logon + 1);
	add_unicode_str(&mi_logon->LogonDomainName, ".", 1, &pos);
	add_unicode_str(&mi_logon->UserName, user, user_chars, &pos);
	add_unicode_str(&mi_logon->Password, password, pw_chars, &pos);

	*logon_info = mi_logon;
	*logon_type = Interactive;
    } else {
	MSV1_0_S4U_LOGON *s4u_logon;

	/*
	 * MSV1_0_S4U_LOGON must be passed as a single contiguous
	 * buffer that includes all strings, otherwise LsaLogonUser
	 * will complain.  Add an extra char for the termination, just
	 * in case.
	 */
	logon_len = sizeof(MSV1_0_S4U_LOGON) + user_bytes + sizeof(wchar_t);
	s4u_logon = (MSV1_0_S4U_LOGON *) calloc(logon_len +
						sizeof(wchar_t), 1);
	if (!s4u_logon)
	    return STATUS_NO_MEMORY;
	s4u_logon->MessageType = MsV1_0S4ULogon;
	pos = (char *) (s4u_logon + 1);

	add_unicode_str(&s4u_logon->UserPrincipalName, user, user_chars, &pos);
	add_unicode_str(&s4u_logon->DomainName, ".", 1, &pos);

	*logon_info = s4u_logon;
	*logon_type = Network;
    }
    *logon_info_len = logon_len;
    return 0;
}

static const char *add_groups[] = {
    "S-1-2-0", /* LOCAL */
    NULL
};

/* Supply either isid or sidstr, not both. */
static DWORD
append_group(TOKEN_GROUPS *grps, SID *sid, const char *sidstr, DWORD attrs)
{
    SID *new_sid, *free_sid = NULL;
    size_t len;
    unsigned int i = grps->GroupCount;
    int err = 0;

    if (sidstr) {
	if (!ConvertStringSidToSid(sidstr, (void **) &free_sid))
	    return GetLastError();
	/* Can't use free_sid directly, it's allocated with LocalAlloc(). */
	sid = free_sid;
    }

    len = GetLengthSid(sid);
    new_sid = malloc(len);
    if (!new_sid) {
	err = STATUS_NO_MEMORY;
	goto out_err;
    }
    if (!CopySid(len, new_sid, sid)) {
	err = GetLastError();
	free(new_sid);
	goto out_err;
    }

    grps->Groups[i].Attributes = attrs;
    grps->Groups[i].Sid = new_sid;
    grps->GroupCount++;
 out_err:
    if (free_sid)
	LocalFree(free_sid);
    return err;
}

static void
free_groups(TOKEN_GROUPS *grps)
{
    unsigned int i;

    for (i = 0; i < grps->GroupCount; i++)
	free(grps->Groups[i].Sid);
    free(grps);
}

#if 0
static void
pr_sid(int indent, const char *str, SID *sid)
{
    char *sidstr;

    if (!sid) {
	printf("%*s%s: NULL Sid\n", indent, "", str);
    } else if (ConvertSidToStringSidA(sid, &sidstr)) {
	printf("%*s%s: %s\n", indent, "", str, sidstr);
	LocalFree(sidstr);
    } else {
	printf("%*s%s: Bad Sid\n", indent, "", str);
    }
}

static void
print_sid(const char *str, SID *sid)
{
    pr_sid(0, str, sid);
}
#endif

static wchar_t *
str_to_wstr(const char *str)
{
    DWORD nchars;
    DWORD nbytes;
    wchar_t *wstr;

    if (!str)
	return NULL;
    nchars = mbstowcs(NULL, str, strlen(str));
    nbytes = nchars * sizeof(wchar_t);
    wstr = calloc(nbytes + sizeof(wchar_t), 1);
    if (!wstr)
	return NULL;
    mbstowcs(wstr, str, nchars);
    return wstr;
}

int
gensio_win_get_user_token(const char *user, const char *password,
			  const char *src_module, const char **groups,
			  bool interactive, HANDLE *userh)
{
    HANDLE lsah;
    NTSTATUS rv;
    DWORD err = 0;
    void *logon_info = NULL;
    LSA_STRING package_name;
    ULONG package_auth;
    wchar_t *wuser = NULL;
    bool domain_user;
    DWORD logon_len;
    TOKEN_SOURCE token_source;
    LSA_STRING origin_name;
    void *profile = NULL;
    DWORD profile_len = 0;
    LUID logon_id;
    HANDLE htok = NULL, tmptok;
    QUOTA_LIMITS quota_limits;
    NTSTATUS sub_status;
    PROFILEINFOW profile_info = { 0 };
    SECURITY_LOGON_TYPE logon_type;
    TOKEN_USER *usersid = NULL;
    SID *logon_sid = NULL;
    TOKEN_GROUPS *extra_groups = NULL;
    MSV1_0_INTERACTIVE_PROFILE *iprofile;
    bool found;
    DWORD len;
    const char **grpp;

    domain_user = strchr(user, '\\');

    if (interactive && domain_user) {
	LSA_STRING name;
	LSA_OPERATIONAL_MODE dummy1;

	/* Interactive, get a token we can use for that. */
	set_lsa_string(&name, src_module);
	rv = LsaRegisterLogonProcess(&name, &lsah, &dummy1);
    } else {
	/* Just getting information, no need for a token requiring auth. */
	rv = LsaConnectUntrusted(&lsah);
    }
    if (rv)
	return LsaNtStatusToWinError(rv);

    if (domain_user)
	set_lsa_string(&package_name, MICROSOFT_KERBEROS_NAME_A);
    else
	set_lsa_string(&package_name, MSV1_0_PACKAGE_NAME);
    rv = LsaLookupAuthenticationPackage(lsah, &package_name, &package_auth);
    if (rv) {
	err = LsaNtStatusToWinError(rv);
	goto out_err;
    }

    if (domain_user)
	err = get_kerb_logon(user, password, interactive,
			     &logon_info, &logon_len, &logon_type);
    else
	err = get_local_logon(user, password, &logon_info, &logon_len,
			      &logon_type);
    if (err)
	goto out_err;

    /*
     * This information is copied into the resulting token.  Note that
     * SourceName is an 8 character ASCII buffer.
     */
    AllocateLocallyUniqueId(&token_source.SourceIdentifier);
    strncpy(token_source.SourceName, src_module, 7);
    token_source.SourceName[7] = 0;

    set_lsa_string(&origin_name, src_module);

    /*
     * Do a first run.  For just query request (not interactive) this
     * is all we need, but for interactive, we use this to pull
     * information from for the real logon.
     *
     * Pass in NULL for groups so this will generate a new logon sid,
     * which we may or may not use.
     */
    rv = LsaLogonUser(lsah, &origin_name, logon_type, package_auth,
		      logon_info, logon_len, NULL, &token_source,
		      &profile, &profile_len, &logon_id, &htok,
		      &quota_limits, &sub_status);
    if (rv) {
	err = LsaNtStatusToWinError(rv);
	goto out_err;
    }
    if (profile)
	LsaFreeReturnBuffer(profile);

    if (!interactive)
	/* We have all we need, no setup is necessary. */
	goto out_finish;

    /*
     * For interactive, the created handle does not have a proper
     * logon SID (maybe) and doesn't have the extra groups.  So we
     * will need to find the right SID and use that.  If the user is
     * currently logged on, we will pull that logon sid.  If they are
     * not, we will use the logon SID from the token we just created.
     */

    /* First find the proper logon sid. */
    err = read_token_info(htok, TokenUser, (void **) &usersid, NULL);
    if (err)
	goto out_err;
    err = get_logon_sid(usersid->User.Sid, &logon_sid, &found);
    if (err)
	goto out_err;
    if (!found) {
	/*
	 * The user isn't logged on, use the logon sid from the token.
	 * we just created.
	 */
	err = get_logon_sid_from_token(htok, &logon_sid, &found);
	if (err)
	    goto out_err;
	if (!found) {
	    err = ERROR_INVALID_DATA;
	    goto out_err;
	}
    }

    /*
     * Now add the logon sid to the extra groups.  If it's a network
     * logon, convert it to interactive by adding the proper sids.
     */
    len = sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES);
    for (grpp = add_groups; grpp && *grpp; grpp++)
	len += sizeof(SID_AND_ATTRIBUTES);
    for (grpp = groups; grpp && *grpp; grpp++)
	len += sizeof(SID_AND_ATTRIBUTES);
    extra_groups = (TOKEN_GROUPS *) malloc(len);
    if (!extra_groups) {
	err = STATUS_NO_MEMORY;
	goto out_err;
    }
    memset(extra_groups, 0, len);
    append_group(extra_groups, logon_sid, NULL,
		 (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT |
		  SE_GROUP_MANDATORY | SE_GROUP_LOGON_ID));
    for (grpp = add_groups; grpp && *grpp; grpp++) {
	err = append_group(extra_groups, NULL, *grpp,
			   (SE_GROUP_ENABLED |
			    SE_GROUP_ENABLED_BY_DEFAULT |
			    SE_GROUP_MANDATORY));
	if (err)
	    goto out_err;
    }
    for (grpp = groups; grpp && *grpp; grpp++) {
	err = append_group(extra_groups, NULL, *grpp,
			   (SE_GROUP_ENABLED |
			    SE_GROUP_ENABLED_BY_DEFAULT |
			    SE_GROUP_MANDATORY));
	if (err)
	    goto out_err;
    }

    /* Now get the actual token. */
    rv = LsaLogonUser(lsah, &origin_name, logon_type, package_auth,
		      logon_info, logon_len, extra_groups, &token_source,
		      &profile, &profile_len, &logon_id, &tmptok,
		      &quota_limits, &sub_status);
    if (rv) {
	err = LsaNtStatusToWinError(rv);
	goto out_err;
    }
    CloseHandle(htok);
    htok = tmptok;

    /* Interactive logons should have the profile loaded. */
    iprofile = (MSV1_0_INTERACTIVE_PROFILE *) profile;
    if (iprofile->MessageType == MsV1_0InteractiveProfile)
	profile_info.lpServerName = iprofile->LogonServer.Buffer;

    profile_info.dwSize = sizeof(profile_info);
    profile_info.dwFlags = PI_NOUI;
    wuser = str_to_wstr(user);
    if (!wuser) {
	err = STATUS_NO_MEMORY;
	goto out_err;
    }
    profile_info.lpUserName = wuser;
    if (!LoadUserProfileW(htok, &profile_info)) {
	err = GetLastError();
	goto out_err;
    }

 out_finish:
    if (logon_type != Network) {
	/*
	 * We want an impersonation token.  Network tokens do that,
	 * but others do not.
	 */
	if (!DuplicateToken(htok, SecurityImpersonation, &tmptok))
	    err = GetLastError();
	CloseHandle(htok);
	htok = tmptok;
    }

    *userh = htok;
    htok = NULL;

 out_err:
    if (extra_groups)
	free_groups(extra_groups);
    if (htok)
	CloseHandle(htok);
    if (usersid)
	free(usersid);
    if (wuser)
	free(wuser);
    if (logon_info)
	free(logon_info);
    if (profile_info.hProfile)
	UnloadUserProfile(htok, profile_info.hProfile);
    if (profile)
	LsaFreeReturnBuffer(profile);
    if (lsah)
	LsaDeregisterLogonProcess(lsah);
    LsaClose(lsah);

    return err;
}

int
gensio_win_pty_alloc(struct gensio_os_funcs *o,
		     HANDLE *rreadh, HANDLE *rwriteh,
		     HANDLE *child_in, HANDLE *child_out,
		     HPCON *rptyh)
{
    HANDLE readh_m = NULL, readh_s = NULL;
    HANDLE writeh_m = NULL, writeh_s = NULL;
    HANDLE imptokh;
    HPCON ptyh = NULL;
    COORD winsize;
    HRESULT hr;
    int err;

    if (!CreatePipe(&writeh_s, &writeh_m, NULL, 0))
	goto out_err_conv;
    if (!SetHandleInformation(writeh_s, HANDLE_FLAG_INHERIT,
			      HANDLE_FLAG_INHERIT))
	goto out_err_conv;
    if (!CreatePipe(&readh_m, &readh_s, NULL, 0))
	goto out_err_conv;
    if (!SetHandleInformation(readh_s, HANDLE_FLAG_INHERIT,
			      HANDLE_FLAG_INHERIT))
	goto out_err_conv;

    if (!OpenThreadToken(GetCurrentThread(),
			 TOKEN_ALL_ACCESS,
			 TRUE,
			 &imptokh)) {
	if (GetLastError() != ERROR_NO_TOKEN)
	    /* Error getting the token. */
	    goto out_err_conv;
	/* No token was present, just create the pseudo console. */
    } else {
	/*
	 * An impersonation token is present, the pseudo console will
	 * be created in a special child process.
	 */
	CloseHandle(imptokh);
	goto out;
    }


    winsize.X = 80;
    winsize.Y = 25;
    hr = CreatePseudoConsole(winsize, writeh_s, readh_s, 0, &ptyh);
    if (hr != S_OK) {
	if (HRESULT_FACILITY(hr) == FACILITY_WIN32)
	    err = gensio_os_err_to_err(o, HRESULT_CODE(hr));
	else
	    err = gensio_os_err_to_err(o, hr); /* Force an OS_ERR. */
	goto out_err;
    }

 out:
    *child_in = writeh_s;
    *child_out = readh_s;
    *rwriteh = writeh_m;
    *rreadh = readh_m;
    *rptyh = ptyh;

    return 0;

 out_err_conv:
    err = gensio_os_err_to_err(o, GetLastError());
 out_err:
    if (readh_m)
	CloseHandle(readh_m);
    if (readh_s)
	CloseHandle(readh_s);
    if (writeh_m)
	CloseHandle(writeh_m);
    if (writeh_s)
	CloseHandle(writeh_s);
    if (ptyh)
	ClosePseudoConsole(ptyh);
    return err;
}

/*
 * Start a special process that will be an intermediary between this
 * process and the main user process.
 *
 * If you create a pseudo console under Windows, it will be created
 * with the integrity level of the calling process, even if the
 * impersonation token is set.  This means that the child process will
 * not be able to do certain operations on the console handles, like
 * WriteConsoleInput.  A discussion of the security limitiations is at
 * https://learn.microsoft.com/en-us/windows/console/console-buffer-security-and-access-rights
 *
 * This was discussed by me with others at:
 *
 * https://learn.microsoft.com/en-us/answers/questions/1040676/createpseudoconsole-with-reduced-integrity-level.html
 *
 * The only reasonable approach seems to be to create another process
 * with the user's token and have it create the pty.  That process is
 * gensio_pty_helper in tools.  That way the pty gets created at the
 * user's integrity level.  We talk to that process over it's stdio,
 * which is relayed to the real child process.
 *
 * The environment and starting directory can be set here and it will
 * propagate down.  However, the command line is a different issue.
 * That is passed in some shared memory.
 *
 * There is yet another snag, though.  The console resize events need
 * to be done on the pty.  So another pipe is created to send commands
 * to gensio_pty_helper to handle resize events.
 *
 * The command line shared memory handle, size, and the rcontrol
 * shared memory handle is passed on the command line to
 * gensio_pty_helper.
 *
 * Also, the exit code must be propagated back through gensio_pty_helper.
 *
 * This is not really ideal, as the subprocess is not directly
 * attached to us and the pid really isn't right.  But there's not
 * much else we can do.
 */
static int
start_pty_helper(struct gensio_os_funcs *o,
		 HANDLE tokh, const char *cmdline, char *envb,
		 const char *start_dir, STARTUPINFO *si,
		 PROCESS_INFORMATION *procinfo, HANDLE *rcontrol)
{
    SECURITY_ATTRIBUTES secattr;
    HANDLE shmem = NULL, ctl_s = NULL, ctl_m = NULL;
    DWORD cmdline_len;
    char *buf = NULL;
    char cmd[50];
    int err = 0;

    if (!CreatePipe(&ctl_s, &ctl_m, NULL, 0))
	goto out_err_conv;
    if (!SetHandleInformation(ctl_s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
	goto out_err_conv;

    cmdline_len = strlen(cmdline) + 1;

    memset(&secattr, 0, sizeof(secattr));
    secattr.nLength = sizeof(secattr);
    secattr.bInheritHandle = TRUE;

    /* Add 1 to the length for the version. */
    shmem = CreateFileMappingA(INVALID_HANDLE_VALUE, &secattr, PAGE_READWRITE,
			       0, cmdline_len + 1, NULL);
    if (!shmem)
	goto out_err_conv;

    buf = (char *) MapViewOfFile(shmem,
				 FILE_MAP_ALL_ACCESS,
				 0,
				 0,
				 cmdline_len + 1);
    if (!buf)
	goto out_err_conv;
    buf[0] = 1; /* Version */
    memcpy(buf + 1, cmdline, cmdline_len);
    UnmapViewOfFile(buf);

    /* Pass the handle in the command line. */
    snprintf(cmd, sizeof(cmd), "gensio_pty_helper %lld %lu %lld",
	     (intptr_t) shmem, (unsigned long) cmdline_len + 1,
	     (intptr_t) ctl_s);

    if (!CreateProcessAsUserA(tokh,
			      NULL,
			      cmd,
			      NULL,
			      NULL,
			      TRUE,
			      (NORMAL_PRIORITY_CLASS |
			       CREATE_NEW_PROCESS_GROUP),
			      envb,
			      start_dir,
			      si,
			      procinfo))
	goto out_err_conv;

 out:
    if (shmem)
	CloseHandle(shmem);
    if (ctl_s)
	CloseHandle(ctl_s);
    if (err && ctl_m)
	CloseHandle(ctl_m);
    else
	*rcontrol = ctl_m;
    return err;

 out_err_conv:
    err = gensio_os_err_to_err(o, GetLastError());
    goto out;
}

int
gensio_win_pty_start(struct gensio_os_funcs *o,
		     HPCON ptyh, HANDLE *child_in, HANDLE *child_out,
		     const char **argv, const char **env,
		     const char *start_dir, HANDLE *child, HANDLE *rcontrol)
{
    char *cmdline, *envb = NULL;
    STARTUPINFOEX si;
    PROCESS_INFORMATION procinfo;
    size_t len;
    HANDLE tokh = NULL, imptokh = NULL, control = NULL;
    int err;
    bool setuser = true;
    bool attrs_added = false;

    memset(&si, 0, sizeof(si));

    err = argv_to_win_cmdline(o, argv, &cmdline);
    if (err)
	return err;

    if (env) {
	envb = win_env_to_block(o, env, NULL);
	if (!envb) {
	    err = GE_NOMEM;
	    goto out_err;
	}
    }

    si.StartupInfo.cb = sizeof(STARTUPINFOEX);

    /*
     * This is not in any of the examples on Microsoft's site, but if
     * the application has stdio relocated, anything that uses stdio
     * in the child will get the parent's stdio.  If the child opens
     * the console, all is good, but that's not the normal case.
     *
     * So set the stdio to the pipe, too.
     *
     * Plus this is necessary if we are using the pty helper.
     */
    si.StartupInfo.hStdInput = *child_in;
    si.StartupInfo.hStdOutput = *child_out;
    si.StartupInfo.hStdError = *child_out;
    si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;


    /*
     * Get the impersonation token, convert it to a real token, and
     * create the process as that user.
     */
    if (!OpenThreadToken(GetCurrentThread(),
			 TOKEN_ALL_ACCESS,
			 TRUE,
			 &imptokh)) {
	if (GetLastError() == ERROR_NO_TOKEN)
	    /* Impersonation token not set, just do a normal create process. */
	    setuser = false;
	else
	    goto out_err_conv;
    }

    if (setuser) {
	if (!DuplicateTokenEx(imptokh, 0, NULL, SecurityImpersonation,
			      TokenPrimary, &tokh))
	    goto out_err_conv;

	err = start_pty_helper(o, tokh, cmdline, envb, start_dir,
			       &si.StartupInfo, &procinfo, &control);
	if (err)
	    goto out_err;
    } else {
	InitializeProcThreadAttributeList(NULL, 1, 0, &len);
	si.lpAttributeList = o->zalloc(o, len);
	if (!si.lpAttributeList) {
	    err = GE_NOMEM;
	    goto out_err;
	}
	if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &len))
	    goto out_err_conv;
	if (!UpdateProcThreadAttribute(si.lpAttributeList,
				       0,
				       PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
				       ptyh,
				       sizeof(ptyh),
				       NULL,
				       NULL))
	    goto out_err_conv;
	attrs_added = true;

	if (!CreateProcess(NULL,
			   cmdline,
			   NULL,
			   NULL,
			   FALSE,
			   (NORMAL_PRIORITY_CLASS |
			    EXTENDED_STARTUPINFO_PRESENT |
			    CREATE_NEW_PROCESS_GROUP),
			   envb,
			   start_dir,
			   &si.StartupInfo,
			   &procinfo))
	    goto out_err_conv;
    }

    CloseHandle(*child_in);
    *child_in = NULL;
    CloseHandle(*child_out);
    *child_out = NULL;
    if (imptokh)
	CloseHandle(imptokh);
    if (tokh)
	CloseHandle(tokh);
    CloseHandle(procinfo.hThread);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    o->free(o, si.lpAttributeList);
    *child = procinfo.hProcess;
    *rcontrol = control;
    return 0;

 out_err_conv:
    err = gensio_os_err_to_err(o, GetLastError());
 out_err:
    if (imptokh)
	CloseHandle(imptokh);
    if (tokh)
	CloseHandle(tokh);
    if (attrs_added)
	DeleteProcThreadAttributeList(si.lpAttributeList);
    if (si.lpAttributeList)
	o->free(o, si.lpAttributeList);
    if (cmdline)
	o->free(o, cmdline);
    if (envb)
	o->free(o, envb);
    return err;
}

bool
gensio_os_loadlib(struct gensio_os_funcs *o, const char *name)
{
    char *dllname;
    char *initfuncname;
    int (*initfunc)(struct gensio_os_funcs *);
    HINSTANCE handle;
    int err;

    dllname = gensio_alloc_sprintf(o, "libgensio_%s.DLL", name);
    if (!dllname)
	return false;
    initfuncname = gensio_alloc_sprintf(o, "gensio_init_%s", name);
    if (!initfuncname) {
	o->free(o, dllname);
	return false;
    }
    handle = LoadLibrary(dllname);
    o->free(o, dllname);
    if (!handle) {
	o->free(o, initfuncname);
	return false;
    }
    initfunc = (int (*)(struct gensio_os_funcs *))
	GetProcAddress(handle, initfuncname);
    o->free(o, initfuncname);
    if (!initfunc) {
	FreeLibrary(handle);
	return false;
    }
    err = initfunc(o);
    if (err) {
	FreeLibrary(handle);
	return false;
    }
    return true;
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
    struct stdio_mode *r = NULL;

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
    int orig_mctl;
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

static void s_cfmakeraw(g_termios *termios_p) {
    unsigned int i;

    /* Zero out the c_cc array. */
    for (i = 0; i < sizeof(termios_p->c_cc); i++)
	termios_p->c_cc[i] = 0;

    /* Standard make raw. */
    termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    termios_p->c_oflag &= ~OPOST;
    termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    termios_p->c_cflag &= ~(CSIZE|PARENB);
    termios_p->c_cflag |= CS8;
    termios_p->c_cc[VMIN] = 1;

    /* Our additions to makeraw, to make things always consistent. */
    termios_p->c_iflag &= ~(IXOFF | IXANY);
    termios_p->c_iflag |= IGNBRK;
    termios_p->c_oflag &= ~(ONLCR);
    termios_p->c_lflag &= ~(ECHOK|ECHOE|ECHONL);
#ifdef ECHOCTL
    termios_p->c_lflag &= ~ECHOCTL;
#endif
#ifdef ECHOPRT
    termios_p->c_lflag &= ~ECHOPRT;
#endif
#ifdef ECHOKE
    termios_p->c_lflag &= ~ECHOKE;
#endif
    termios_p->c_cflag &= ~(CRTSCTS | PARODD);
    termios_p->c_cflag |= CREAD;
    termios_p->c_cc[VSTART] = 17;
    termios_p->c_cc[VSTOP] = 19;
}

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
    ioctl(fd, TIOCMGET, &t->orig_mctl);

    s_cfmakeraw(&t->curr_termios);

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
    ioctl(fd, TIOCMSET, &(*it)->orig_mctl);
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
    case GENSIO_IOD_CONTROL_SET_BREAK:
	rv = gensio_unix_setup_termios(o, fd, it);
	if (rv)
	    return rv;
	assert(*it);
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
		if (ioctl(fd, TIOCSRS485, &t->rs485) < 0)
		    rv = gensio_os_err_to_err(o, errno);
		else
		    t->rs485_applied = enabled;
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
	    if (ioctl(fd, nval) == -1) {
		if (errno != ENOTTY) /* Happens with PTYs. */
		    return gensio_os_err_to_err(o, errno);
	    }
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
	if (ioctl(fd, TIOCMGET, &nval) == -1) {
	    if (errno == ENOTTY)
		nval = 0; /* Happens with PTYs. */
	    else
		return gensio_os_err_to_err(o, errno);
	}
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
#ifdef TIOCINQ
	    rv = ioctl(fd, TIOCINQ, &count);
#elif defined(FIONREAD)
	    rv = ioctl(fd, FIONREAD, &count);
#else
#error "No way to read tty bufcount"
#endif
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
		    const char *start_dir,
		    unsigned int flags,
		    int *rpid,
		    int *rin, int *rout, int *rerr)
{
    int err;
    int stdinpipe[2] = {-1, -1};
    int stdoutpipe[2] = {-1, -1};
    int stderrpipe[2] = {-1, -1};
    int pid = -1;

    if (rerr && (flags & GENSIO_EXEC_STDERR_TO_STDOUT))
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
	if (flags & GENSIO_EXEC_STDERR_TO_STDOUT)
	    dup2(stdoutpipe[1], 2);
	else if (rerr)
	    dup2(stderrpipe[1], 2);

	/* Close everything but stdio. */
	for (i = 3; i < openfiles; i++)
	    close(i);

	if (start_dir) {
	    if (chdir(start_dir)) {
		fprintf(stderr, "stdio fork: chdir to %s failed: %s",
			start_dir, strerror(errno));
		exit(1);
	    }
	}

	err = gensio_unix_os_setupnewprog();
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

int
gensio_unix_pty_alloc(struct gensio_os_funcs *o, int *rfd)
{
    int fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (fd == -1)
	return gensio_os_err_to_err(o, errno);
    *rfd = fd;
    return 0;
}

int
gensio_unix_pty_start(struct gensio_os_funcs *o,
		      int pfd, const char **argv, const char **env,
		      const char *start_dir, pid_t *rpid)
{
    const char *pgm;
    pid_t pid = -1;
    int err;

    if (unlockpt(pfd) < 0)
	goto out_errno;

    if (!argv)
	goto skip_child;

    pid = fork();
    if (pid < 0)
	goto out_errno;

    if (pid == 0) {
	/*
	 * Delay getting the slave until here becase ptsname is not
	 * thread-safe, but after the fork we are single-threaded.
	 */
	char *slave = ptsname(pfd);
	int i, openfiles = sysconf(_SC_OPEN_MAX);
	int fd;

	/* Set the owner of the slave PT. */
	if (grantpt(pfd) < 0)
	    exit(1);

	if (start_dir) {
	    if (chdir(start_dir)) {
		fprintf(stderr, "pty fork: chdir to %s failed: %s",
			start_dir, strerror(errno));
		exit(1);
	    }
	}

	if (setsid() == -1) {
	    fprintf(stderr, "pty fork: failed to start new session: %s\r\n",
		    strerror(errno));
	    exit(1);
	}

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

	if (env)
	    environ = (char **) env;

	pgm = argv[0];
	if (*pgm == '-')
	    pgm++;
	execvp(pgm, (char **) argv);
	fprintf(stderr, "Unable to exec %s: %s\r\n", argv[0],
		strerror(errno));
	exit(1); /* Only reached on error. */
    }
 skip_child:
    *rpid = pid;
    return 0;
 out_errno:
    return gensio_os_err_to_err(o, errno);
}

static bool
pathendswith(const char *str, const char *endstr)
{
    const char *end1 = str + strlen(str) - 1;
    const char *end2 = endstr + strlen(endstr) - 1;

    /* Ignore trailing '/' */
    while (end1 != str && *end1 == '/')
	end1--;
    if (*end1 == '/')
	return false; /* It was all /'s */

    while (end1 != str && end2 != endstr && *end1 == *end2) {
	end1--;
	end2--;
    }
    return end2 == endstr && *end1 == *end2;
}

static bool
try_loaddir(struct gensio_os_funcs *o, const char *name, const char *path,
	    bool check_libtool_dir)
{
    gensiods len;
    char fname[PATH_MAX];
    void *handle;
    int (*initfunc)(struct gensio_os_funcs *);
    int err;

    if (check_libtool_dir) {
	/*
	 * Only allow libtool libraries, so when running from in the
	 * build directory it will find it.)
	 */
	if (!pathendswith(path, "/lib/.libs"))
	    return false;
    }
    len = snprintf(fname, sizeof(fname), "%s/libgensio_%s.so", path, name);
    if (len >= sizeof(fname))
	return false;

    handle = dlopen(fname, RTLD_LAZY | RTLD_GLOBAL);
    if (!handle)
	return false;
    snprintf(fname, sizeof(fname), "gensio_init_%s", name);
    initfunc = (int (*)(struct gensio_os_funcs *)) dlsym(handle, fname);
    if (!initfunc) {
	dlclose(handle);
	return false;
    }
    err = initfunc(o);
    if (err) {
	dlclose(handle);
	return false;
    }
    return true;
}

static bool
try_loaddirs(struct gensio_os_funcs *o, const char *name, const char *paths,
	     bool check_libtool_dir)
{
    char path[PATH_MAX];
    const char *start, *end;
    gensiods len;

    start = paths;
    while (*start) {
	end = strchr(start, ':');
	if (!end) {
	    if (try_loaddir(o, name, start, check_libtool_dir))
		return true;
	    return false;
	}

	len = end - start;
	if (len < sizeof(path)) {
	    memcpy(path, start, len);
	    path[len] = '\0';
	    if (try_loaddir(o, name, path, check_libtool_dir))
		return true;
	}
	start = end + 1;
    }
    return false;
}

static const char *default_libdir = PKG_LIBEXEC;

bool
gensio_os_loadlib(struct gensio_os_funcs *o, const char *name)
{
    const char *paths;

    paths = getenv("LD_LIBRARY_PATH");
    if (paths) {
	if (try_loaddirs(o, name, paths, true))
	    return true;
    }
    paths = getenv("GENSIO_LIBRARY_PATH");
    if (paths) {
	if (try_loaddirs(o, name, paths, false))
	    return true;
    }
    return try_loaddirs(o, name, default_libdir, false);
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

    if (err && m->abort_on_err) {
	fflush(stderr);
	assert(false);
    }

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
    memset(m, 0, sizeof(*m));

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
    if (m->abort_on_err && !gensio_list_empty(&m->alloced)) {
	fflush(stderr);
	assert(false);
    }

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
    void *d = malloc(size);
    if (d)
	memset(d, 0, size);
    return d;
}

void
gensio_i_free(struct gensio_memtrack *m, void *data)
{
    free(data);
}

#endif /* ENABLE_INTERNAL_TRACE */

void
gensio_os_funcs_set_vlog(struct gensio_os_funcs *o, gensio_vlog_func func)
{
    o->vlog = func;
}

gensio_vlog_func *
gensio_os_funcs_get_vlog(struct gensio_os_funcs *o)
{
    return o->vlog;
}

void
gensio_os_funcs_free(struct gensio_os_funcs *o)
{
    o->free_funcs(o);
}

void *
gensio_os_funcs_zalloc(struct gensio_os_funcs *o, gensiods size)
{
    return o->zalloc(o, size);
}

void
gensio_os_funcs_zfree(struct gensio_os_funcs *o, void *data)
{
    o->free(o, data);
}

struct gensio_waiter *
gensio_os_funcs_alloc_waiter(struct gensio_os_funcs *o)
{
    return o->alloc_waiter(o);
}

void
gensio_os_funcs_free_waiter(struct gensio_os_funcs *o,
			    struct gensio_waiter *waiter)
{
    o->free_waiter(waiter);
}

int
gensio_os_funcs_wait(struct gensio_os_funcs *o,
		     struct gensio_waiter *waiter, unsigned int count,
		     gensio_time *timeout)
{
    return o->wait(waiter, count, timeout);
}

int
gensio_os_funcs_wait_intr(struct gensio_os_funcs *o,
			  struct gensio_waiter *waiter, unsigned int count,
			  gensio_time *timeout)
{
    return o->wait_intr(waiter, count, timeout);
}

int
gensio_os_funcs_wait_intr_sigmask(struct gensio_os_funcs *o,
				  struct gensio_waiter *waiter,
				  unsigned int count,
				  gensio_time *timeout,
				  struct gensio_os_proc_data *proc_data)
{
    return o->wait_intr_sigmask(waiter, count, timeout, proc_data);
}

void
gensio_os_funcs_wake(struct gensio_os_funcs *o,
		     struct gensio_waiter *waiter)
{
    o->wake(waiter);
}

struct gensio_lock *
gensio_os_funcs_alloc_lock(struct gensio_os_funcs *o)
{
    return o->alloc_lock(o);
}

void
gensio_os_funcs_free_lock(struct gensio_os_funcs *o,
			  struct gensio_lock *lock)
{
    o->free_lock(lock);
}

void
gensio_os_funcs_lock(struct gensio_os_funcs *o,
		     struct gensio_lock *lock)
{
    o->lock(lock);
}

void
gensio_os_funcs_unlock(struct gensio_os_funcs *o,
		       struct gensio_lock *lock)
{
    o->unlock(lock);
}

void
gensio_os_funcs_get_monotonic_time(struct gensio_os_funcs *o,
				   gensio_time *time)
{
    o->get_monotonic_time(o, time);
}

struct gensio_timer *
gensio_os_funcs_alloc_timer(struct gensio_os_funcs *o,
			    void (*handler)(struct gensio_timer *t,
					    void *cb_data),
			    void *cb_data)
{
    return o->alloc_timer(o, handler, cb_data);
}

void
gensio_os_funcs_free_timer(struct gensio_os_funcs *o,
			   struct gensio_timer *timer)
{
    o->free_timer(timer);
}

int
gensio_os_funcs_start_timer(struct gensio_os_funcs *o,
			    struct gensio_timer *timer,
			    gensio_time *timeout)
{
    return o->start_timer(timer, timeout);
}

int gensio_os_funcs_start_timer_abs(struct gensio_os_funcs *o,
				    struct gensio_timer *timer,
				    gensio_time *timeout)
{
    return o->start_timer_abs(timer, timeout);
}

int
gensio_os_funcs_stop_timer(struct gensio_os_funcs *o,
			   struct gensio_timer *timer)
{
    return o->stop_timer(timer);
}

int
gensio_os_funcs_stop_timer_with_done(struct gensio_os_funcs *o,
				 struct gensio_timer *timer,
				 void (*done_handler)(struct gensio_timer *t,
						      void *cb_data),
				 void *cb_data)
{
    return o->stop_timer_with_done(timer, done_handler, cb_data);
}

struct gensio_runner *
gensio_os_funcs_alloc_runner(struct gensio_os_funcs *o,
			     void (*handler)(struct gensio_runner *r,
					     void *cb_data),
			     void *cb_data)
{
    return o->alloc_runner(o, handler, cb_data);
}

void
gensio_os_funcs_free_runner(struct gensio_os_funcs *o,
			    struct gensio_runner *runner)
{
    o->free_runner(runner);
}

int
gensio_os_funcs_run(struct gensio_os_funcs *o,
		    struct gensio_runner *runner)
{
    return o->run(runner);
}

int
gensio_os_funcs_service(struct gensio_os_funcs *o, gensio_time *timeout)
{
    return o->service(o, timeout);
}

int
gensio_os_funcs_handle_fork(struct gensio_os_funcs *o)
{
    return o->handle_fork(o);
}

void
gensio_os_funcs_set_data(struct gensio_os_funcs *o, void *data)
{
    o->other_data = data;
}

void *
gensio_os_funcs_get_data(struct gensio_os_funcs *o)
{
    return o->other_data;
}
