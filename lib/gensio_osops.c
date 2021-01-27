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

#ifndef _WIN32

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
    int rv, count;

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
    if (rv)
	rv = gensio_os_err_to_err(o, errno);
    else
	*rcount = count;
    return rv;
}

#endif
