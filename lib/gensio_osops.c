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
#include "gensio_osops_win.h"
void
gensio_osops_set_os_funcs(struct gensio_os_funcs *o)
{
    o->set_non_blocking = gensio_os_set_non_blocking;
    o->close = gensio_os_close;
    o->write = gensio_os_write;
    o->read = gensio_os_read;
    o->is_regfile = gensio_os_is_regfile;
}

#else
#include "gensio_osops_unix.h"
void
gensio_osops_set_os_funcs(struct gensio_os_funcs *o)
{
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
	o->close_socket(&fds[i].iod);
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
