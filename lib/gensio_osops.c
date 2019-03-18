/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include "config.h"
#define _XOPEN_SOURCE 600 /* Get posix_openpt() and friends. */
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

#ifdef HAVE_LIBSCTP
#include <netinet/sctp.h>
#endif

#include <gensio/gensio_osops.h>

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

#ifdef HAVE_LIBSCTP
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

 retry:
    rv = writev(fd, (struct iovec *) sg, sglen);
    ERRHANDLE();
}

int
gensio_os_read(struct gensio_os_funcs *o,
	       int fd, void *buf, gensiods buflen, gensiods *rcount)
{
    ssize_t rv;

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

#ifdef HAVE_LIBSCTP
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
    gensiods i, count, total_write = 0;

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

	err = seteuid(getuid());
	if (err == -1) {
	    fprintf(stderr, "pty fork: Unable to set euid: %s\r\n",
		    strerror(errno));
	    exit(1);
	}

	err = setegid(getgid());
	if (err == -1) {
	    fprintf(stderr, "pty fork: Unable to set egid: %s\r\n",
		    strerror(errno));
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

int
gensio_open_socket(struct gensio_os_funcs *o,
		   struct addrinfo *ai,
		   void (*readhndlr)(int, void *),
		   void (*writehndlr)(int, void *),
		   void (*fd_handler_cleared)(int, void *),
		   void *data,
		   struct opensocks **rfds, unsigned int *nr_fds)
{
    struct addrinfo *rp;
    int family = AF_INET6; /* Try IPV6 first, then IPV4. */
    struct opensocks *fds;
    unsigned int curr_fd = 0;
    unsigned int max_fds = 0;
    int rv = 0;

    for (rp = ai; rp != NULL; rp = rp->ai_next)
	max_fds++;

    if (max_fds == 0)
	return GE_INVAL;

    fds = o->zalloc(o, sizeof(*fds) * max_fds);
    if (!fds)
	return GE_NOMEM;

  restart:
    for (rp = ai; rp != NULL; rp = rp->ai_next) {
	if (family != rp->ai_family)
	    continue;

	rv = gensio_setup_listen_socket(o, rp->ai_socktype == SOCK_STREAM,
					rp->ai_family, rp->ai_socktype,
					rp->ai_protocol, rp->ai_flags,
					rp->ai_addr, rp->ai_addrlen,
					readhndlr, writehndlr, data,
					fd_handler_cleared, NULL,
					&fds[curr_fd].fd);
	if (!rv) {
	    fds[curr_fd].family = rp->ai_family;
	    curr_fd++;
	}
    }
    if (family == AF_INET6) {
	family = AF_INET;
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
}

int
gensio_setup_listen_socket(struct gensio_os_funcs *o, bool do_listen,
			   int family, int socktype, int protocol, int flags,
			   struct sockaddr *addr, socklen_t addrlen,
			   void (*readhndlr)(int, void *),
			   void (*writehndlr)(int, void *), void *data,
			   void (*fd_handler_cleared)(int, void *),
			   int (*call_b4_listen)(int, void *),
			   int *rfd)
{
    int optval = 1;
    int fd, rv = 0;

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

    if (bind(fd, addr, addrlen) != 0)
	goto out_err;

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
    /*  33 */    "Operation was interrupted by a signal"
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
    default:		err = GE_OSERR;
    }

    if (err == GE_OSERR) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled OS error in %s: %s (%d)", caller,
		   strerror(oserr), oserr);
    }

    return err;
}
