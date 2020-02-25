/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#define _XOPEN_SOURCE 600 /* Get posix_openpt() and friends. */
#define _DEFAULT_SOURCE /* Get getgrouplist(), setgroups() */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <grp.h>
#include <pwd.h>

#include <arpa/inet.h>
#if HAVE_LIBSCTP
#include <netinet/sctp.h>
#endif
#include <sys/un.h>

#ifdef HAVE_TCPD_H
#include <tcpd.h>
#endif /* HAVE_TCPD_H */

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <gensio/gensio_osops.h>
#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>
#include "gensio_addrinfo.h"

static const char *progname = "gensio";

bool gensio_set_progname(const char *iprogname)
{
    progname = iprogname;
    return true;
}

static int
check_ipv6_only(int family, int protocol, int flags, int fd)
{
    int val;

    if (family != AF_INET6)
	return 0;

    if (flags & AI_V4MAPPED)
	val = 0;
    else
	val = 1;

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) == -1)
	return -1;

#if HAVE_LIBSCTP
    if (protocol == IPPROTO_SCTP) {
	val = !val;
	if (setsockopt(fd, SOL_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, &val,
		       sizeof(val)) == -1)
	    return -1;
    }
#endif
    return 0;
}

#define ERRHANDLE()			\
do {								\
    int err = 0;						\
    if (rv < 0) {						\
	if (errno == EINTR)					\
	    goto retry;						\
	if (errno == EWOULDBLOCK || errno == EAGAIN)		\
	    rv = 0; /* Handle like a zero-byte write. */	\
	else							\
	    err = errno;					\
    } else if (rv == 0) {					\
	err = EPIPE;						\
    }								\
    if (!err && rcount)						\
	*rcount = rv;						\
    return gensio_os_err_to_err(o, err);			\
} while(0)

int
gensio_os_write(struct gensio_os_funcs *o,
		int fd, const struct gensio_sg *sg, gensiods sglen,
		gensiods *rcount)
{
    ssize_t rv;

    if (sglen == 0) {
	if (rcount)
	    *rcount = 0;
	return 0;
    }
 retry:
    rv = writev(fd, (struct iovec *) sg, sglen);
    ERRHANDLE();
}

int
gensio_os_read(struct gensio_os_funcs *o,
	       int fd, void *buf, gensiods buflen, gensiods *rcount)
{
    ssize_t rv;

    if (buflen == 0) {
	if (rcount)
	    *rcount = 0;
	return 0;
    }
 retry:
    rv = read(fd, buf, buflen);
    ERRHANDLE();
}

int
gensio_os_recv(struct gensio_os_funcs *o,
	       int fd, void *buf, gensiods buflen, gensiods *rcount, int flags)
{
    ssize_t rv;

 retry:
    rv = recv(fd, buf, buflen, flags);
    ERRHANDLE();
}

int
gensio_os_send(struct gensio_os_funcs *o,
	       int fd, const struct gensio_sg *sg, gensiods sglen,
	       gensiods *rcount, int flags)
{
    ssize_t rv;
    struct msghdr hdr;

    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_iov = (struct iovec *) sg;
    hdr.msg_iovlen = sglen;

 retry:
    rv = sendmsg(fd, &hdr, flags);
    ERRHANDLE();
}

int
gensio_os_sendto(struct gensio_os_funcs *o,
		 int fd, const struct gensio_sg *sg, gensiods sglen,
		 gensiods *rcount,
		 int flags, const struct sockaddr *raddr, socklen_t raddrlen)
{
    ssize_t rv;
    struct msghdr hdr;

    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_name = (void *) raddr;
    hdr.msg_namelen = raddrlen;
    hdr.msg_iov = (struct iovec *) sg;
    hdr.msg_iovlen = sglen;
 retry:
    rv = sendmsg(fd, &hdr, flags);
    ERRHANDLE();
}

int
gensio_os_recvfrom(struct gensio_os_funcs *o,
		   int fd, void *buf, gensiods buflen, gensiods *rcount,
		   int flags, struct sockaddr *raddr, socklen_t *raddrlen)
{
    ssize_t rv;

 retry:
    rv = recvfrom(fd, buf, buflen, flags, raddr, raddrlen);
    ERRHANDLE();
}

int
gensio_os_accept(struct gensio_os_funcs *o,
		 int fd, struct sockaddr *addr, socklen_t *addrlen,
		 int *newsock)
{
    int rv = accept(fd, addr, addrlen);

    if (rv >= 0) {
	*newsock = rv;
	return 0;
    }
    if (errno == EAGAIN && errno == EWOULDBLOCK)
	return GE_NODATA;
    return gensio_os_err_to_err(o, errno);
}

#if HAVE_LIBSCTP
int
gensio_os_sctp_recvmsg(struct gensio_os_funcs *o,
		       int fd, void *msg, gensiods len, gensiods *rcount,
		       struct sctp_sndrcvinfo *sinfo, int *flags)
{
    int rv;

 retry:
    rv = sctp_recvmsg(fd, msg, len, NULL, NULL, sinfo, flags);
    ERRHANDLE();
}

static int
l_sctp_send(struct gensio_os_funcs *o,
	    int fd, const void *msg, size_t len, gensiods *rcount,
	    const struct sctp_sndrcvinfo *sinfo, uint32_t flags)
{
    int rv;

 retry:
    rv = sctp_send(fd, msg, len, sinfo, flags);
    ERRHANDLE();
}

int
gensio_os_sctp_send(struct gensio_os_funcs *o,
		    int fd, const struct gensio_sg *sg, gensiods sglen,
		    gensiods *rcount,
		    const struct sctp_sndrcvinfo *sinfo, uint32_t flags)
{
    int err = 0;
    gensiods i, count = 0, total_write = 0;

    /* Without sctp_sendv, this is really hard to do. */
    for (i = 0; i < sglen; i++) {
	err = l_sctp_send(o, fd, sg[i].buf, sg[i].buflen, &count, sinfo, flags);
	if (err || count == 0)
	    break;
	total_write += count;
    }
    if (rcount)
	*rcount = total_write;
    return err;
}
#endif

int
gensio_setupnewprog(void)
{
    struct passwd *pw;
    int err;
    uid_t uid = geteuid();
    gid_t *groups = NULL;
    int ngroup = 0;

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

/*
 * This is ugly, but it's by far the simplest way.
 */
extern char **environ;

int
gensio_setup_child_on_pty(struct gensio_os_funcs *o,
			  char *const argv[], const char **env,
			  int *rptym, pid_t *rpid)
{
    pid_t pid;
    int ptym, err = 0;
    const char *pgm;

    ptym = posix_openpt(O_RDWR | O_NOCTTY);
    if (ptym == -1)
	return gensio_os_err_to_err(o, errno);

    if (fcntl(ptym, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	close(ptym);
	return gensio_os_err_to_err(o, err);
    }

    if (unlockpt(ptym) < 0) {
	err = errno;
	close(ptym);
	return gensio_os_err_to_err(o, err);
    }

    pid = fork();
    if (pid < 0) {
	err = errno;
	close(ptym);
	return gensio_os_err_to_err(o, err);
    }

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

	/* setsid() does this, but just in case... */
	fd = open("/dev/tty", O_RDWR);
	if (fd != -1) {
	    ioctl(fd, TIOCNOTTY, NULL);
	    close(fd);

	    fd = open("/dev/tty", O_RDWR);
	    if (fd != -1) {
		fprintf(stderr, "pty fork: failed to drop control term: %s\r\n",
			strerror(errno));
		exit(1);
	    }
	}

	if (setsid() == -1) {
	    fprintf(stderr, "pty fork: failed to start new session: %s\r\n",
		    strerror(errno));
	    exit(1);
	}

#if 0 /* FIXME = do we need this? */
	if (setpgid(0, 0) == -1) {
	    exit(1);
	}
#endif

	fd = open(slave, O_RDWR);
	if (fd == -1) {
	    fprintf(stderr, "pty fork: failed to open slave terminal: %s\r\n",
		    strerror(errno));
	    exit(1);
	}

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

	err = gensio_setupnewprog();
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
	execvp(pgm, argv);
	fprintf(stderr, "Unable to exec %s: %s\r\n", argv[0], strerror(errno));
	exit(1); /* Only reached on error. */
    }

    *rpid = pid;
    *rptym = ptym;
    return 0;
}

int
gensio_get_random(struct gensio_os_funcs *o,
		  void *data, unsigned int len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    int rv;

    if (fd == -1)
	return gensio_os_err_to_err(o, errno);

    while (len > 0) {
	rv = read(fd, data, len);
	if (rv < 0) {
	    rv = errno;
	    goto out;
	}
	len -= rv;
	data += rv;
    }

    rv = 0;

 out:
    close(fd);
    return gensio_os_err_to_err(o, rv);
}

/*
 * For assigning zero ports.
 */
#define IP_DYNRANGE_START	49152
#define IP_DYNRANGE_END		65535

unsigned int gensio_dyn_scan_next(unsigned int port)
{
    if (port == IP_DYNRANGE_END)
	return IP_DYNRANGE_START;
    else
	return port + 1;
}

int
gensio_open_socket(struct gensio_os_funcs *o,
		   struct gensio_addrinfo *ai,
		   void (*readhndlr)(int, void *),
		   void (*writehndlr)(int, void *),
		   void (*fd_handler_cleared)(int, void *),
		   void *data,
		   struct opensocks **rfds, unsigned int *nr_fds)
{
    struct addrinfo *rp;
    int family = AF_INET6; /* Try IPV6 first, then IPV4. */
    struct opensocks *fds;
    unsigned int curr_fd = 0, i;
    unsigned int max_fds = 0;
    int rv = 0;
    struct gensio_listen_scan_info scaninfo;

    for (rp = ai->a; rp != NULL; rp = rp->ai_next)
	max_fds++;

    if (max_fds == 0)
	return GE_INVAL;

    fds = o->zalloc(o, sizeof(*fds) * max_fds);
    if (!fds)
	return GE_NOMEM;

    memset(&scaninfo, 0, sizeof(scaninfo));

 restart:
    for (rp = ai->a; rp != NULL; rp = rp->ai_next) {
	if (family != rp->ai_family)
	    continue;

	rv = gensio_setup_listen_socket(o, rp->ai_socktype == SOCK_STREAM,
					rp->ai_family, rp->ai_socktype,
					rp->ai_protocol, rp->ai_flags,
					rp->ai_addr, rp->ai_addrlen,
					readhndlr, writehndlr, data,
					fd_handler_cleared, NULL,
					&fds[curr_fd].fd, &fds[curr_fd].port,
					&scaninfo);
	if (rv)
	    goto out_close;
	fds[curr_fd].family = rp->ai_family;
	curr_fd++;
    }
    if (family == AF_INET6) {
	family = AF_INET;
	goto restart;
    }
    if (family == AF_INET) {
	family = AF_UNIX;
	goto restart;
    }

    if (curr_fd == 0) {
	o->free(o, fds);
	if (rv)
	    return rv;
	return GE_NOTFOUND;
    }

    *nr_fds = curr_fd;
    *rfds = fds;

    return 0;

 out_close:
    for (i = 0; i < curr_fd; i++) {
	o->clear_fd_handlers_norpt(o, fds[i].fd);
	close(fds[i].fd);
    }

    if (rv == GE_ADDRINUSE && scaninfo.start != 0 &&
		scaninfo.curr != scaninfo.start) {
	/* We need to keep scanning. */
	curr_fd = 0;
	scaninfo.reqport = 0;
	family = AF_INET6;
	goto restart;
    }

    o->free(o, fds);
    return rv;
}

static int
gensio_socket_get_port(struct gensio_os_funcs *o, int fd, unsigned int *port)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    int rv;

    rv = getsockname(fd, (struct sockaddr *) &sa, &len);
    if (rv)
	return gensio_os_err_to_err(o, errno);

    rv = gensio_sockaddr_get_port((struct sockaddr *) &sa, port);
    if (rv)
	return rv;

    return 0;
}

int
gensio_setup_listen_socket(struct gensio_os_funcs *o, bool do_listen,
			   int family, int socktype, int protocol, int flags,
			   struct sockaddr *addr, socklen_t addrlen,
			   void (*readhndlr)(int, void *),
			   void (*writehndlr)(int, void *), void *data,
			   void (*fd_handler_cleared)(int, void *),
			   int (*call_b4_listen)(int, void *),
			   int *rfd, unsigned int *rport,
			   struct gensio_listen_scan_info *rsi)
{
    int optval = 1;
    int fd, rv = 0;
    unsigned int port;
    struct sockaddr_storage sa;

    rv = gensio_sockaddr_get_port(addr, &port);
    if (rv == -1)
	return GE_INVAL;

    if (addrlen > sizeof(sa))
	return GE_TOOBIG;
    memcpy(&sa, addr, addrlen);
    addr = (struct sockaddr *) &sa;

    if (rsi && rsi->reqport != 0 && port == 0) {
	rv = gensio_sockaddr_set_port(addr, rsi->reqport);
	if (rv)
	    return rv;
	port = rsi->reqport;
    }

    fd = socket(family, socktype, protocol);
    if (fd == -1)
	return gensio_os_err_to_err(o, errno);

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
	goto out_err;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		   (void *)&optval, sizeof(optval)) == -1)
	goto out_err;

    if (check_ipv6_only(family, protocol, flags, fd) == -1)
	goto out_err;

    if (port == 0 && (family == AF_INET || family == AF_INET6)) {
	struct gensio_listen_scan_info lsi;
	struct gensio_listen_scan_info *si = rsi;

	if (!si) {
	    si = &lsi;
	    memset(si, 0, sizeof(*si));
	}

	if (si->start == 0) {
	    /* Get a random port in the dynamic range. */
	    gensio_get_random(o, &si->start, sizeof(si->start));
	    si->start %= IP_DYNRANGE_END - IP_DYNRANGE_START + 1;
	    si->start += IP_DYNRANGE_START;
	    si->curr = si->start;
	}

	do {
	    rv = gensio_sockaddr_set_port(addr, si->curr);
	    if (rv)
		goto out;
	    if (bind(fd, addr, addrlen) == 0) {
		goto got_it;
	    } else {
		if (errno != EADDRINUSE)
		    goto out_err;
	    }

	    si->curr = gensio_dyn_scan_next(si->curr);
	} while (si->curr != si->start);
	/* Unable to find an open port, give up. */
	rv = GE_ADDRINUSE;
	goto out;
    } else {
	if (bind(fd, addr, addrlen) != 0) {
	    if (rsi)
		rsi->curr = gensio_dyn_scan_next(rsi->curr);
	    goto out_err;
	}
    }
 got_it:
    if (family == AF_INET || family == AF_INET6) {
	rv = gensio_socket_get_port(o, fd, &port);
	if (rv)
	    goto out;
	if (rsi && rsi->reqport == 0)
	    rsi->reqport = port;
	*rport = port;
    } else {
	*rport = 0;
    }

    if (call_b4_listen) {
	rv = call_b4_listen(fd, data);
	if (rv)
	    goto out;
    }

    if (do_listen && listen(fd, 5) != 0)
	goto out_err;

    rv = o->set_fd_handlers(o, fd, data,
			    readhndlr, writehndlr, NULL,
			    fd_handler_cleared);
 out:
    if (rv)
	close(fd);
    else
	*rfd = fd;
    return rv;

 out_err:
    rv = gensio_os_err_to_err(o, errno);
    goto out;
}

const char *
gensio_check_tcpd_ok(int new_fd)
{
#ifdef HAVE_TCPD_H
    struct request_info req;

    request_init(&req, RQ_DAEMON, progname, RQ_FILE, new_fd, NULL);
    fromhost(&req);

    if (!hosts_access(&req))
	return "Access denied\r\n";
#endif

    return NULL;
}

const char *gensio_errs[] = {
    /*   0 */    "No error",
    /*   1 */    "Out of memory",
    /*   2 */    "Operation not supported",
    /*   3 */    "Invalid data to parameter",
    /*   4 */    "Value or file not found",
    /*   5 */    "Value already exists",
    /*   6 */    "Value out of range",
    /*   7 */    "Parameters inconsistent in call",
    /*   8 */    "No data was available for the function",
    /*   9 */	 "OS error, see logs",
    /*  10 */    "Object was already in use",
    /*  11 */    "Operation is in progress",
    /*  12 */    "Object was not ready for operation",
    /*  13 */    "Value was too large for data",
    /*  14 */    "Operation timed out",
    /*  15 */    "Retry operation later",
    /*  16 */    "Invalid error number 1",
    /*  17 */    "Unable to find the given key",
    /*  18 */    "Key was revoked",
    /*  19 */    "Key was expired",
    /*  20 */    "Key is not valid",
    /*  21 */    "Certificate not provided",
    /*  22 */    "Certificate is not valid",
    /*  23 */    "Protocol error",
    /*  24 */    "Communication error",
    /*  25 */    "Internal I/O error",
    /*  26 */    "Remote end closed connection",
    /*  27 */    "Host could not be reached",
    /*  28 */    "Connection refused",
    /*  29 */    "Data was missing",
    /*  30 */    "Unable to find given certificate",
    /*  31 */    "Authentication tokens rejected",
    /*  32 */    "Address already in use",
    /*  33 */    "Operation was interrupted by a signal",
    /*  34 */    "Operation on shutdown fd",
    /*  35 */    "Local end closed connection"
};
const unsigned int errno_len = sizeof(gensio_errs) / sizeof(char *);

const char *
gensio_err_to_str(int err)
{
    if (err < 0 || err >= errno_len)
	return "Unknown error";
    return gensio_errs[err];
}

#include <assert.h>
int
gensio_i_os_err_to_err(struct gensio_os_funcs *o,
		       int oserr, const char *caller, const char *file,
		       unsigned int lineno)
{
    int err;

    if (oserr == 0)
	return 0;

    switch(oserr) {
    case ENOMEM:	err = GE_NOMEM; break;
    case EINVAL:	err = GE_INVAL; break;
    case ENOENT:	err = GE_NOTFOUND; break;
    case EEXIST:	err = GE_EXISTS; break;
    case EBUSY:		err = GE_INUSE; break;
    case EINPROGRESS:	err = GE_INPROGRESS; break;
    case ETIMEDOUT:	err = GE_TIMEDOUT; break;
    case EPIPE:		err = GE_REMCLOSE; break;
    case ECONNRESET:	err = GE_REMCLOSE; break;
    case EHOSTUNREACH:	err = GE_HOSTDOWN; break;
    case ECONNREFUSED:	err = GE_CONNREFUSE; break;
    case EIO:		err = GE_IOERR; break;
    case EADDRINUSE:	err = GE_ADDRINUSE; break;
    case EINTR:		err = GE_INTERRUPTED; break;
    case ESHUTDOWN:     err = GE_SHUTDOWN; break;
    case EMSGSIZE:      err = GE_TOOBIG; break;
    default:		err = GE_OSERR;
    }

    if (err == GE_OSERR) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled OS error in %s:%d: %s (%d)", caller, lineno,
		   strerror(oserr), oserr);
    }

    return err;
}

bool
gensio_sockaddr_equal(const struct sockaddr *a1, socklen_t l1,
		      const struct sockaddr *a2, socklen_t l2,
		      bool compare_ports)
{
    if (l1 != l2)
	return false;
    if (a1->sa_family != a2->sa_family)
	return false;
    switch (a1->sa_family) {
    case AF_INET:
	{
	    struct sockaddr_in *s1 = (struct sockaddr_in *) a1;
	    struct sockaddr_in *s2 = (struct sockaddr_in *) a2;
	    if (compare_ports && s1->sin_port != s2->sin_port)
		return false;
	    if (s1->sin_addr.s_addr != s2->sin_addr.s_addr)
		return false;
	}
	break;

    case AF_INET6:
	{
	    struct sockaddr_in6 *s1 = (struct sockaddr_in6 *) a1;
	    struct sockaddr_in6 *s2 = (struct sockaddr_in6 *) a2;
	    if (compare_ports && s1->sin6_port != s2->sin6_port)
		return false;
	    if (memcmp(s1->sin6_addr.s6_addr, s2->sin6_addr.s6_addr,
		       sizeof(s1->sin6_addr.s6_addr)) != 0)
		return false;
	}
	break;

    case AF_UNIX:
	{
	    struct sockaddr_un *s1 = (struct sockaddr_un *) a1;
	    struct sockaddr_un *s2 = (struct sockaddr_un *) a2;
	    if (strcmp(s1->sun_path, s2->sun_path) != 0)
		return false;
	}
	break;

    default:
	/* Unknown family. */
	return false;
    }

    return true;
}

int
gensio_sockaddr_get_port(const struct sockaddr *s, unsigned int *port)
{
    switch (s->sa_family) {
    case AF_INET:
	*port = ntohs(((struct sockaddr_in *) s)->sin_port);
	break;

    case AF_INET6:
	*port = ntohs(((struct sockaddr_in6 *) s)->sin6_port);
	break;

    default:
	return GE_INVAL;
    }

    return 0;
}

int
gensio_sockaddr_set_port(const struct sockaddr *s, unsigned int port)
{
    switch (s->sa_family) {
    case AF_INET:
	((struct sockaddr_in *) s)->sin_port = htons(port);
	break;

    case AF_INET6:
	((struct sockaddr_in6 *) s)->sin6_port = htons(port);
	break;

    default:
	return GE_INVAL;
    }

    return 0;
}

int
gensio_sockaddr_to_str(const struct sockaddr *addr, socklen_t *addrlen,
		       char *buf, gensiods *pos, gensiods buflen)
{
    if (addr->sa_family == AF_INET) {
	struct sockaddr_in *a4 = (struct sockaddr_in *) addr;
	char ibuf[INET_ADDRSTRLEN];

	if (addrlen && *addrlen && *addrlen != sizeof(struct sockaddr_in))
	    goto out_err;
	gensio_pos_snprintf(buf, buflen, pos, "ipv4,%s,%d",
			inet_ntop(AF_INET, &a4->sin_addr, ibuf, sizeof(ibuf)),
			ntohs(a4->sin_port));
	if (addrlen)
	    *addrlen = sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) addr;
	char ibuf[INET6_ADDRSTRLEN];

	if (addrlen && *addrlen && *addrlen != sizeof(struct sockaddr_in6))
	    goto out_err;
	gensio_pos_snprintf(buf, buflen, pos, "ipv6,%s,%d",
			inet_ntop(AF_INET6, &a6->sin6_addr, ibuf, sizeof(ibuf)),
			ntohs(a6->sin6_port));
	if (addrlen)
	    *addrlen = sizeof(struct sockaddr_in6);
    } else if (addr->sa_family == AF_UNIX) {
	struct sockaddr_un *au = (struct sockaddr_un *) addr;

	gensio_pos_snprintf(buf, buflen, pos, "unix,%s", au->sun_path);
    } else {
    out_err:
	if (*pos < buflen)
	    buf[*pos] = '\0';
	return GE_INVAL;
    }

    return 0;
}

static int
scan_ips(struct gensio_os_funcs *o, const char *str, bool listen, int ifamily,
	 int socktype, int protocol, bool *is_port_set,
	 struct gensio_addrinfo **rai)
{
    char *strtok_data, *strtok_buffer;
    struct gensio_addrinfo ai = { NULL }, *ai2 = NULL, *ai3;
    struct addrinfo hints, *ai4;
    char *ip;
    char *port;
    unsigned int portnum;
    bool first = true, portset = false;
    int rv = 0;
    int bflags = AI_ADDRCONFIG;

    if (listen)
	bflags |= AI_PASSIVE;

    strtok_buffer = gensio_strdup(o, str);
    if (!strtok_buffer)
	return GE_NOMEM;

    ip = strtok_r(strtok_buffer, ",", &strtok_data);
    while (ip) {
	int family = ifamily, rflags = 0;

	if (strcmp(ip, "ipv4") == 0) {
	    family = AF_INET;
	    ip = strtok_r(NULL, ",", &strtok_data);
	} else if (strcmp(ip, "ipv6") == 0) {
	    family = AF_INET6;
	    ip = strtok_r(NULL, ",", &strtok_data);
	} else if (strcmp(ip, "ipv6n4") == 0) {
	    family = AF_INET6;
	    rflags |= AI_V4MAPPED;
	    ip = strtok_r(NULL, ",", &strtok_data);
	}

	if (ip == NULL) {
	    rv = GE_INVAL;
	    goto out_err;
	}

	port = strtok_r(NULL, ",", &strtok_data);
	if (port == NULL) {
	    port = ip;
	    ip = NULL;
	}

	if (ip && *ip == '\0')
	    ip = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = bflags | rflags;
	hints.ai_family = family;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;
	if (getaddrinfo(ip, port, &hints, &ai.a)) {
	    rv = GE_INVAL;
	    goto out_err;
	}

	/*
	 * If a port was/was not set, this must be consistent for all
	 * addresses.
	 */
	rv = gensio_sockaddr_get_port(ai.a->ai_addr, &portnum);
	if (rv)
	    goto out_err;
	if (first) {
	    portset = portnum != 0;
	} else {
	    if ((portnum != 0) != portset) {
		/* One port was set and the other wasn't. */
		rv = GE_INCONSISTENT;
		goto out_err;
	    }
	}

	ai3 = gensio_dup_addrinfo(o, &ai);
	if (!ai3) {
	    rv = GE_NOMEM;
	    goto out_err;
	}

	for (ai4 = ai3->a; ai4; ai4 = ai4->ai_next)
	    ai4->ai_flags = rflags;

	if (ai2)
	    ai2 = gensio_cat_addrinfo(o, ai2, ai3);
	else
	    ai2 = ai3;
	ip = strtok_r(NULL, ",", &strtok_data);
	first = false;
    }

    if (!ai2) {
	rv = GE_NOTFOUND;
	goto out_err;
    }

    if (is_port_set)
	*is_port_set = portset;

    *rai = ai2;

 out_err:
    if (ai.a)
	freeaddrinfo(ai.a);
    o->free(o, strtok_buffer);
    if (rv && ai2)
	gensio_free_addrinfo(o, ai2);

    return rv;
}

int
gensio_scan_network_port(struct gensio_os_funcs *o, const char *str,
			 bool listen, struct gensio_addrinfo **rai,
			 int *rprotocol,
			 bool *is_port_set,
			 int *rargc, const char ***rargs)
{
    int err = 0, family = AF_UNSPEC, argc = 0;
    const char **args = NULL;
    bool doskip = true;
    int protocol, socktype, irprotocol;

    if (strncmp(str, "ipv4,", 5) == 0) {
	family = AF_INET;
	str += 5;
    } else if (strncmp(str, "ipv6,", 5) == 0) {
	family = AF_INET6;
	str += 5;
    }

    if (strncmp(str, "tcp,", 4) == 0 ||
		(rargs && strncmp(str, "tcp(", 4) == 0)) {
	str += 3;
	socktype = SOCK_STREAM;
	protocol = IPPROTO_TCP;
	irprotocol = GENSIO_NET_PROTOCOL_TCP;
    } else if (strncmp(str, "udp,", 4) == 0 ||
	       (rargs && strncmp(str, "udp(", 4) == 0)) {
	str += 3;
	socktype = SOCK_DGRAM;
	protocol = IPPROTO_UDP;
	irprotocol = GENSIO_NET_PROTOCOL_UDP;
    } else if (strncmp(str, "sctp,", 5) == 0 ||
	       (rargs && strncmp(str, "sctp(", 5) == 0)) {
	str += 4;
	socktype = SOCK_SEQPACKET;
	protocol = IPPROTO_SCTP;
	irprotocol = GENSIO_NET_PROTOCOL_SCTP;
    } else {
	doskip = false;
	socktype = SOCK_STREAM;
	protocol = IPPROTO_TCP;
	irprotocol = GENSIO_NET_PROTOCOL_TCP;
    }

    if (doskip) {
	if (*str == '(') {
	    if (!rargs)
		return GE_INVAL;
	    err = gensio_scan_args(o, &str, &argc, &args);
	    if (err)
		return err;
	} else {
	    str++; /* Skip the ',' */
	}
    }

    err = scan_ips(o, str, listen, family, socktype, protocol,
		   is_port_set, rai);
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
	*rprotocol = irprotocol;

    return 0;
}

int
gensio_scan_netaddr(struct gensio_os_funcs *o, const char *str, bool listen,
		    int gprotocol, struct gensio_addrinfo **rai)
{
    int family = AF_UNSPEC, protocol, socktype;
    bool is_port_set;
    int rv;

    if (strncmp(str, "ipv4,", 5) == 0) {
	family = AF_INET;
	str += 5;
    } else if (strncmp(str, "ipv6,", 5) == 0) {
	family = AF_INET6;
	str += 5;
    }

    switch (gprotocol) {
    case GENSIO_NET_PROTOCOL_TCP:
	socktype = SOCK_STREAM;
	protocol = IPPROTO_TCP;
	break;

    case GENSIO_NET_PROTOCOL_UDP:
	socktype = SOCK_DGRAM;
	protocol = IPPROTO_UDP;
	break;

    case GENSIO_NET_PROTOCOL_SCTP:
	socktype = SOCK_SEQPACKET;
	protocol = IPPROTO_SCTP;
	break;

    default:
	return GE_INVAL;
    }

    rv = scan_ips(o, str, listen, family, socktype, protocol,
		  &is_port_set, rai);
    if (!rv && !listen && !is_port_set)
	rv = GE_INVAL;
    return rv;
}

struct gensio_addrinfo *
gensio_dup_addrinfo(struct gensio_os_funcs *o, struct gensio_addrinfo *igai)
{
    struct addrinfo *iai, *aic, *aip = NULL;
    struct gensio_addrinfo *ai = NULL;

    if (!igai)
	return NULL;

    iai = igai->a;

    ai = o->zalloc(o, sizeof(*ai));
    if (!ai)
	return NULL;

    while (iai) {
	aic = o->zalloc(o, sizeof(*aic));
	if (!aic)
	    goto out_nomem;
	memcpy(aic, iai, sizeof(*aic));
	aic->ai_next = NULL;
	aic->ai_addr = o->zalloc(o, iai->ai_addrlen);
	if (!aic->ai_addr) {
	    o->free(o, aic);
	    goto out_nomem;
	}
	memcpy(aic->ai_addr, iai->ai_addr, iai->ai_addrlen);
	if (iai->ai_canonname) {
	    aic->ai_canonname = gensio_strdup(o, iai->ai_canonname);
	    if (!aic->ai_canonname) {
		o->free(o, aic->ai_addr);
		o->free(o, aic);
		goto out_nomem;
	    }
	}
	if (aip) {
	    aip->ai_next = aic;
	    aip = aic;
	} else {
	    aip = aic;
	    ai->a = aic;
	}
	iai = iai->ai_next;
    }

    return ai;

 out_nomem:
    gensio_free_addrinfo(o, ai);
    return NULL;
}

struct gensio_addrinfo *gensio_cat_addrinfo(struct gensio_os_funcs *o,
					    struct gensio_addrinfo *ai1,
					    struct gensio_addrinfo *ai2)
{
    struct addrinfo *ai = ai1->a;

    while (ai->ai_next)
	ai = ai->ai_next;
    ai->ai_next = ai2->a;
    o->free(o, ai2);

    return ai1;
}

bool
gensio_addrinfo_addr_present(const struct gensio_addrinfo *gai,
			     const void *addr, int addrlen,
			     bool compare_ports)
{
    struct addrinfo *ai = gai->a;

    while (ai) {
	if (gensio_sockaddr_equal(addr, addrlen, ai->ai_addr, ai->ai_addrlen,
				  compare_ports))
	    return true;
	ai = ai->ai_next;
    }
    return false;
}

void
gensio_free_addrinfo(struct gensio_os_funcs *o, struct gensio_addrinfo *gai)
{
    struct addrinfo *ai;

    if (!gai)
	return;

    ai = gai->a;
    o->free(o, gai);
    while (ai) {
	struct addrinfo *aic = ai;

	ai = ai->ai_next;
	o->free(o, aic->ai_addr);
	if (aic->ai_canonname)
	    o->free(o, aic->ai_canonname);
	o->free(o, aic);
    }
}
