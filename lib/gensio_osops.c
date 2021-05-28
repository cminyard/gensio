/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#define _DEFAULT_SOURCE /* Get getgrouplist(), setgroups() */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <sys/uio.h>
#include <grp.h>
#include <pwd.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/tcp.h>
#if HAVE_LIBSCTP
#include <netinet/sctp.h>
#endif
#if HAVE_UNIX
#include <sys/un.h>
#endif

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

#include "errtrig.h"

/* MacOS doesn't have IPV6_ADD_MEMBERSHIP, but has an equivalent. */
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif

static const char *progname = "gensio";

struct gensio_addr {
    struct gensio_os_funcs *o;
    struct addrinfo *a;
    struct addrinfo *curr;
#if HAVE_GCC_ATOMICS
    int *refcount;
#endif
    bool is_getaddrinfo; /* Allocated with getaddrinfo()? */
};

struct gensio_listen_scan_info {
    unsigned int curr;
    unsigned int start;
    unsigned int reqport;
};

/*
 * Setup a receiving socket given the socket() parameters.  If do_listen
 * is true, call listen on the socket.  This sets nonblocking, reuse,
 * does a bind, etc.  Works on the current address in addr.
 *
 * The new file descriptor is returned in rfd, and the chosen port is
 * returned in port.  If the address has a port set to 0, this
 * function choose random port from the IANA dynamic range.
 *
 * The rsi parameter is used for handling port 0 for multiple sockets.
 * Pass in a zero-ed structure here.  If the code encounters a zero
 * port, it will set some information int the rsi structure and for
 * every other zero port in future calls it will choose the same port.
 * If it chooses a port that is already in use on one of the later
 * addresses with a zero port, you can clear the reqport member, close
 * everything, and start over.  The function will continue scanning
 * from the next port.  If it returns GE_ADDRINUSE and the curr and
 * start value are the same, then no port was found that could be
 * opened on all addresses.  Errors besides GE_ADDRINUSE should be
 * treated as immediate errors, something else went wrong.
 */
static int gensio_setup_listen_socket(struct gensio_os_funcs *o, bool do_listen,
			       int family, int socktype, int protocol,
			       int flags,
			       struct sockaddr *addr, socklen_t addrlen,
			       void (*readhndlr)(int, void *),
			       void (*writehndlr)(int, void *), void *data,
			       void (*fd_handler_cleared)(int, void *),
			       int (*call_b4_listen)(int, void *),
			       unsigned int opensock_flags,
			       int *rfd, unsigned int *port,
			       struct gensio_listen_scan_info *rsi);

static int addrinfo_list_dup(struct gensio_os_funcs *o,
			     struct addrinfo *ai, struct addrinfo **rai,
			     struct addrinfo **rpai);

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

static bool sockaddr_equal(const struct sockaddr *a1, socklen_t l1,
			   const struct sockaddr *a2, socklen_t l2,
			   bool compare_ports);

/* Does sa have an equivalent address in the list before this address? */
static bool
sockaddr_in_list_b4(struct addrinfo *sa, struct addrinfo *l)
{
    for (; l; l = l->ai_next) {
	if (sa == l)
	    break;
	if (sockaddr_equal(sa->ai_addr, sa->ai_addrlen,
			   l->ai_addr, l->ai_addrlen,
			   true))
	    return true;
    }
    return false;
}

#define ERRHANDLE()			\
do {								\
    int err = 0;						\
    if (rv < 0) {						\
	if (errno == EINTR)					\
	    goto retry;						\
	if (errno == EWOULDBLOCK || errno == EAGAIN)		\
	    rv = 0; /* Handle like a zero-byte write. */	\
	else {							\
	    err = errno;					\
	    assert(err);					\
	}							\
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

    if (do_errtrig())
	return GE_NOMEM;

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

    if (do_errtrig())
	return GE_NOMEM;

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
	       int fd, void *buf, gensiods buflen, gensiods *rcount, int gflags)
{
    ssize_t rv;
    int flags = (gflags & GENSIO_MSG_OOB) ? MSG_OOB : 0;

    if (do_errtrig())
	return GE_NOMEM;

 retry:
    rv = recv(fd, buf, buflen, flags);
    ERRHANDLE();
}

int
gensio_os_send(struct gensio_os_funcs *o,
	       int fd, const struct gensio_sg *sg, gensiods sglen,
	       gensiods *rcount, int gflags)
{
    ssize_t rv;
    struct msghdr hdr;
    int flags = (gflags & GENSIO_MSG_OOB) ? MSG_OOB : 0;

    if (do_errtrig())
	return GE_NOMEM;

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
		 int flags, const struct gensio_addr *raddr)
{
    ssize_t rv;
    struct msghdr hdr;

    if (do_errtrig())
	return GE_NOMEM;

    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_name = (void *) raddr->curr->ai_addr;
    hdr.msg_namelen = raddr->curr->ai_addrlen;
    hdr.msg_iov = (struct iovec *) sg;
    hdr.msg_iovlen = sglen;
 retry:
    rv = sendmsg(fd, &hdr, flags);
    ERRHANDLE();
}

static struct gensio_addr *
gensio_addr_make(struct gensio_os_funcs *o, socklen_t size, bool do_refcount)
{
    struct gensio_addr *addr = o->zalloc(o, sizeof(*addr));
    struct addrinfo *ai = NULL;

    if (!addr)
	return NULL;

#if HAVE_GCC_ATOMICS
    if (do_refcount) {
	addr->refcount = o->zalloc(o, sizeof(*addr->refcount));
	if (!addr->refcount) {
	    o->free(o, addr);
	    return NULL;
	}
	*addr->refcount = 1;
    }
#endif

    if (size > 0) {
	ai = o->zalloc(o, sizeof(*ai));
	if (!ai) {
#if HAVE_GCC_ATOMICS
	    if (addr->refcount)
		o->free(o, addr->refcount);
#endif
	    o->free(o, addr);
	    return NULL;
	}

	ai->ai_addr = o->zalloc(o, size);
	if (!ai->ai_addr) {
#if HAVE_GCC_ATOMICS
	    if (addr->refcount)
		o->free(o, addr->refcount);
#endif
	    o->free(o, addr);
	    o->free(o, ai);
	    return NULL;
	}
	ai->ai_addrlen = size;
    }
    addr->o = o;
    addr->a = ai;
    addr->curr = ai;

    return addr;
}

int
gensio_addr_create(struct gensio_os_funcs *o,
		   int nettype, const void *iaddr, gensiods len,
		   unsigned int port, struct gensio_addr **newaddr)
{
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
    struct sockaddr_un su;
    struct sockaddr *s;
    unsigned int slen;
    struct gensio_addr *a;

    switch (nettype) {
    case GENSIO_NETTYPE_IPV4:
	if (len != sizeof(struct in_addr))
	    return GE_INVAL;
	memset(&s4, 0, sizeof(s4));
	s4.sin_family = AF_INET;
	s4.sin_port = htons(port);
	memcpy(&s4.sin_addr, iaddr, len);
	s = (struct sockaddr *) &s4;
	slen = sizeof(s4);
	break;

    case GENSIO_NETTYPE_IPV6:
	if (len != sizeof(struct in6_addr))
	    return GE_INVAL;
	memset(&s6, 0, sizeof(s6));
	s6.sin6_family = AF_INET6;
	s6.sin6_port = htons(port);
	memcpy(&s6.sin6_addr, iaddr, len);
	s = (struct sockaddr *) &s6;
	slen = sizeof(s6);
	break;

    case GENSIO_NETTYPE_UNIX:
	memset(&su, 0, sizeof(su));
	if (len > sizeof(su.sun_path) - 1)
	    return GE_TOOBIG;
	su.sun_family = AF_UNIX;
	memcpy(su.sun_path, iaddr, len);
	s = (struct sockaddr *) &su;
	slen = sizeof(su);
	break;

    default:
	return GE_INVAL;
    }

    a = gensio_addr_make(o, slen, true);
    if (!a)
	return GE_NOMEM;
    a->a->ai_family = s->sa_family;

    memcpy(a->a->ai_addr, s, slen);
    *newaddr = a;
    return 0;
}

struct gensio_addr *
gensio_addr_alloc_recvfrom(struct gensio_os_funcs *o)
{
    /*
     * Addresses used for recvfrom cannot be duplicated with refcounts
     * because the storage is reused.  So allocate them without a
     * refcount to mark them to always do a full replication.
     */
    return gensio_addr_make(o, sizeof(struct sockaddr_storage), false);
}

int
gensio_os_recvfrom(struct gensio_os_funcs *o,
		   int fd, void *buf, gensiods buflen, gensiods *rcount,
		   int flags, struct gensio_addr *addr)
{
    ssize_t rv;
    int err = 0;

    if (do_errtrig())
	return GE_NOMEM;

 retry:
    rv = recvfrom(fd, buf, buflen, flags,
		  addr->curr->ai_addr, &addr->curr->ai_addrlen);
    if (rv >= 0) {
	addr->curr->ai_family = addr->curr->ai_addr->sa_family;
    } else {
	if (errno == EINTR)
	    goto retry;
	if (errno == EWOULDBLOCK || errno == EAGAIN)
	    rv = 0; /* Handle like a zero-byte write. */
	else
	    err = errno;
    }
    if (!err && rcount)
	*rcount = rv;
    return gensio_os_err_to_err(o, err);
}

int
gensio_os_accept(struct gensio_os_funcs *o, int fd,
		 struct gensio_addr **raddr, int *newsock)
{
    struct gensio_addr *addr = NULL;
    int rv;
    struct sockaddr *sa;
    struct sockaddr_storage sadata;
    socklen_t len;

    if (do_errtrig())
	return GE_NOMEM;

    if (raddr) {
	addr = gensio_addr_make(o, sizeof(struct sockaddr_storage), true);
	if (!addr)
	    return GE_NOMEM;
	sa = addr->curr->ai_addr;
	len = addr->curr->ai_addrlen;
    } else {
	sa = (struct sockaddr *) &sadata;
	len = sizeof(sadata);
    }

    rv = accept(fd, sa, &len);

    if (rv >= 0) {
	if (addr) {
	    addr->curr->ai_family = addr->curr->ai_addr->sa_family;
	    *raddr = addr;
	}
	*newsock = rv;
	return 0;
    } else if (addr) {
	gensio_addr_free(addr);
    }
    if (errno == EAGAIN && errno == EWOULDBLOCK)
	return GE_NODATA;
    return gensio_os_err_to_err(o, errno);
}

static int
sockaddr_get_port(const struct sockaddr *s, unsigned int *port)
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

static int
sockaddr_set_port(const struct sockaddr *s, unsigned int port)
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

#if HAVE_LIBSCTP
static void
sctp_shutdown_fds(struct gensio_os_funcs *o,
		  struct opensocks *fds, unsigned int nrfds)
{
    unsigned int i;

    if (!fds)
	return;

    for (i = 0; i < nrfds; i++) {
	o->clear_fd_handlers_norpt(o, fds[i].fd);
	close(fds[i].fd);
    }
    o->free(o, fds);
}

int
gensio_os_sctp_open_socket(struct gensio_os_funcs *o,
			   struct gensio_addr *addr,
			   void (*readhndlr)(int, void *),
			   void (*writehndlr)(int, void *),
			   void (*fd_handler_cleared)(int, void *),
			   int (*setup_socket)(int fd, void *data),
			   void *data, unsigned int opensock_flags,
			   struct opensocks **rfds, unsigned int *rnr_fds)
{
    struct addrinfo *ai, *rp;
    unsigned int i;
    int family = AF_INET6;
    int rv = 0;
    struct gensio_listen_scan_info scaninfo;
    struct opensocks *fds = NULL, *tfds;
    int nr_fds = 0;

    memset(&scaninfo, 0, sizeof(scaninfo));

    ai = addr->a;
 retry:
    for (rp = ai; rp; rp = rp->ai_next) {
	unsigned int port;

	if (family != rp->ai_family)
	    continue;
	/*
	 * getaddrinfo() will return the same address twice in the
	 * list if ::1 and 127.0.0.1 are both set for localhost in
	 * /etc/hosts.  So the second open attempt will fail if we
	 * don't ignore this.  In general, it's probably better to
	 * ignore duplicates in this function, anyway.
	 */
	if (sockaddr_in_list_b4(rp, ai))
            continue;

	rv = sockaddr_get_port(rp->ai_addr, &port);
	if (rv)
	    goto out_err;

	for (i = 0; i < nr_fds; i++) {
	    if (port == fds[i].port && (fds[i].family == family)) {
		if (sctp_bindx(fds[i].fd, rp->ai_addr, 1,
			       SCTP_BINDX_ADD_ADDR)) {
		    rv = gensio_os_err_to_err(o, errno);
		    goto out_err;
		}
		break;
	    }
	}
	if (i < nr_fds)
	    continue; /* Port matched, already did bind. */

	/* Increment the fds array and open a new socket. */
	tfds = o->zalloc(o, sizeof(*tfds) * (i + 1));
	if (!tfds) {
	    rv = GE_NOMEM;
	    goto out_err;
	}
	if (fds)
	    memcpy(tfds, fds, sizeof(*tfds) * i);

	rv = gensio_setup_listen_socket(o, true, rp->ai_family,
					SOCK_STREAM, IPPROTO_SCTP, rp->ai_flags,
					rp->ai_addr, rp->ai_addrlen,
					readhndlr, NULL, data,
					fd_handler_cleared,
					setup_socket, opensock_flags,
					&tfds[i].fd, &tfds[i].port, &scaninfo);
	if (rv) {
	    o->free(o, tfds);
	    goto out_err;
	}
	tfds[i].family = rp->ai_family;
	tfds[i].flags = rp->ai_flags;
	if (fds)
	    o->free(o, fds);
	fds = tfds;
	nr_fds++;
    }
    if (family == AF_INET6) {
	family = AF_INET;
	goto retry;
    }

    if (nr_fds == 0) {
	rv = GE_INVAL;
	goto out;
    }

    *rfds = fds;
    *rnr_fds = nr_fds;

 out:
    return rv;

 out_err:
    sctp_shutdown_fds(o, fds, nr_fds);
    fds = NULL;
    nr_fds = 0;
#if !HAVE_WORKING_PORT0
    if (rv == GE_ADDRINUSE && scaninfo.start != 0 &&
		scaninfo.curr != scaninfo.start) {
	/* We need to keep scanning. */
	scaninfo.reqport = 0;
	family = AF_INET6;
	goto retry;
    }
#endif
    goto out;
}

int
gensio_os_sctp_recvmsg(struct gensio_os_funcs *o,
		       int fd, void *msg, gensiods len, gensiods *rcount,
		       struct sctp_sndrcvinfo *sinfo, int *flags)
{
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

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

#if HAVE_SCTP_SENDV
#define gensio_os_sctp_send l_gensio_os_sctp_send
#endif

int
gensio_os_sctp_send(struct gensio_os_funcs *o,
		    int fd, const struct gensio_sg *sg, gensiods sglen,
		    gensiods *rcount,
		    const struct sctp_sndrcvinfo *sinfo, uint32_t flags)
{
    int err = 0;
    gensiods i, count = 0, total_write = 0;

    if (do_errtrig())
	return GE_NOMEM;

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

#if HAVE_SCTP_SENDV
#undef gensio_os_sctp_send
static bool sctp_sendv_broken;
int
gensio_os_sctp_send(struct gensio_os_funcs *o,
		    int fd, const struct gensio_sg *sg, gensiods sglen,
		    gensiods *rcount,
		    const struct sctp_sndrcvinfo *sinfo, uint32_t flags)
{
    int rv = 0;
    struct sctp_sndinfo *sndinfo = NULL, sdata;

    if (do_errtrig())
	return GE_NOMEM;

    if (sctp_sendv_broken) {
    broken:
	return l_gensio_os_sctp_send(o, fd, sg, sglen, rcount, sinfo, flags);
    }
    if (sinfo) {
	sdata.snd_sid = sinfo->sinfo_stream;
	sdata.snd_flags = sinfo->sinfo_flags;
	sdata.snd_ppid = sinfo->sinfo_ppid;
	sdata.snd_context = sinfo->sinfo_context;
	sdata.snd_assoc_id = sinfo->sinfo_assoc_id;
	sndinfo = &sdata;
    }
 retry:
    rv = sctp_sendv(fd, (struct iovec *) sg, sglen, NULL, 0,
		    sndinfo, sizeof(*sndinfo), SCTP_SENDV_SNDINFO, flags);
    if (rv == -1 && errno == EINVAL) {
	/* No sendv support, fall back. */
	sctp_sendv_broken = true;
	goto broken;
    }
    ERRHANDLE();
}
#endif

static int
gensio_addr_to_sockarray(struct gensio_os_funcs *o, struct gensio_addr *addrs,
			 struct sockaddr **rsaddrs, unsigned int *rslen,
			 bool *ripv6_only)
{
    struct addrinfo *ai;
    char *saddrs, *s;
    unsigned int slen = 0, i, memlen = 0;
    int ipv6_only = 1;

    for (ai = addrs->a; ai; ai = ai->ai_next) {
	unsigned int len;

	if (ai->ai_addr->sa_family == AF_INET6) {
	    len = sizeof(struct sockaddr_in6);
	} else if (ai->ai_addr->sa_family == AF_INET) {
	    len = sizeof(struct sockaddr_in);
	    ipv6_only = 0;
	} else {
	    return GE_INVAL;
	}
	memlen += len;
	slen++;
    }

    if (memlen == 0)
	return GE_NOTFOUND;

    saddrs = o->zalloc(o, memlen);
    if (!saddrs)
	return GE_NOMEM;

    s = saddrs;
    for (ai = addrs->a, i = 0; i < slen; ai = ai->ai_next) {
	unsigned int len;

	if (ai->ai_addr->sa_family == AF_INET6)
	    len = sizeof(struct sockaddr_in6);
	else if (ai->ai_addr->sa_family == AF_INET)
	    len = sizeof(struct sockaddr_in);
	else
	    assert(0);

	memcpy(s, ai->ai_addr, len);
	s += len;
	i++;
    }

    *rsaddrs = (struct sockaddr *) saddrs;
    *rslen = slen;
    *ripv6_only = ipv6_only;
    return 0;
}

int
gensio_os_sctp_connectx(struct gensio_os_funcs *o,
			int fd, struct gensio_addr *addrs)
{
    struct sockaddr *saddrs;
    unsigned int naddrs;
    int err;
    bool ipv6_only;

    if (do_errtrig())
	return GE_NOMEM;

    err = gensio_addr_to_sockarray(o, addrs, &saddrs, &naddrs, &ipv6_only);
    if (err)
	return err;

    if (ipv6_only) {
	int val = 1;

	err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
	if (err)
	    goto out_err;
	val = !val;
	err = setsockopt(fd, SOL_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, &val,
			 sizeof(val));
	if (err)
	    goto out_err;
    }
    err = sctp_connectx(fd, saddrs, naddrs, NULL);
 out_err:
    o->free(o, saddrs);
    if (err == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

static int
sctp_getraddr(struct gensio_os_funcs *o,
	      int fd, struct sockaddr **addr, gensiods *addrlen)
{
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    rv = sctp_getpaddrs(fd, 0, addr);
    if (rv < 0) {
	return gensio_os_err_to_err(o, errno);
    } if (rv == 0) {
	return GE_NOTFOUND;
    }
    *addrlen = rv;
    return 0;
}

int
gensio_os_sctp_getraddr(struct gensio_os_funcs *o, int fd,
			void *addr, gensiods *addrlen)
{
    struct sockaddr *saddr;
    gensiods len = 0, clen = *addrlen;
    int rv = sctp_getraddr(o, fd, &saddr, &len);

    if (rv)
	return rv;

    if (len > clen)
	len = clen;

    memcpy(addr, saddr, clen);
    *addrlen = len;

    sctp_freepaddrs(saddr);

    return 0;
}

static int
sctp_addr_to_addr(struct gensio_os_funcs *o,
		  struct sockaddr *saddr, gensiods len,
		  struct gensio_addr **raddr)
{
    struct sockaddr *s;
    gensiods i, size;
    struct addrinfo *ai = NULL, *aip = NULL;
    struct gensio_addr *addr;
    char *d;
    int rv;

    addr = gensio_addr_make(o, 0, true);
    if (!addr)
	return GE_NOMEM;

    rv = GE_NOMEM;
    d = (char *) saddr;
    for (i = 0; i < len; i++) {
	s = (struct sockaddr *) d;

	ai = o->zalloc(o, sizeof(*ai));
	if (!ai)
	    goto out;
	if (!aip)
	    addr->a = ai;
	else
	    aip->ai_next = ai;
	aip = ai;

	switch (s->sa_family) {
	case AF_INET6:
	    size = sizeof(struct sockaddr_in6);
	    break;
	case AF_INET:
	    size = sizeof(struct sockaddr_in);
	    break;
	default:
	    rv = GE_INVAL;
	    goto out;
	}

	ai->ai_addr = o->zalloc(o, size);
	if (!ai->ai_addr)
	    goto out;
	memcpy(ai->ai_addr, d, size);
	ai->ai_family = s->sa_family;
	d += size;
    }
    rv = 0;
    addr->curr = addr->a;
    *raddr = addr;

 out:
    if (rv && addr)
	gensio_addr_free(addr);
    return rv;
}

int
gensio_os_sctp_getpaddrs(struct gensio_os_funcs *o, int fd,
			 struct gensio_addr **raddr)
{
    struct sockaddr *saddr;
    gensiods len = 0;
    int rv = sctp_getraddr(o, fd, &saddr, &len);

    if (rv)
	return rv;

    rv = sctp_addr_to_addr(o, saddr, len, raddr);
    sctp_freepaddrs(saddr);
    return rv;
}

int
gensio_os_sctp_getladdrs(struct gensio_os_funcs *o, int fd,
			 struct gensio_addr **raddr)
{
    int rv;
    struct sockaddr *saddr;

    if (do_errtrig())
	return GE_NOMEM;

    rv = sctp_getladdrs(fd, 0, &saddr);
    if (rv < 0) {
	return gensio_os_err_to_err(o, errno);
    } if (rv == 0) {
	return GE_NOTFOUND;
    }

    rv = sctp_addr_to_addr(o, saddr, rv, raddr);
    sctp_freeladdrs(saddr);
    return rv;
}

#endif

int gensio_os_close(struct gensio_os_funcs *o, int *fd)
{
    int err;

    /* Don't do errtrig on close, it can fail and not cause any issues. */

    assert(*fd != -1);
    err = close(*fd);
#ifdef ENABLE_INTERNAL_TRACE
    /* Close should never fail, but don't crash in production builds. */
    if (err) {
	err = errno;
	assert(0);
    }
#endif
    *fd = -1;

    if (err == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int gensio_os_check_socket_open(struct gensio_os_funcs *o, int fd)
{
    int err, optval;
    socklen_t len = sizeof(optval);

    if (do_errtrig())
	return GE_NOMEM;

    err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &len);
    if (err)
	return gensio_os_err_to_err(o, errno);
    return gensio_os_err_to_err(o, optval);
}

int
gensio_os_set_non_blocking(struct gensio_os_funcs *o, int fd)
{
    if (do_errtrig())
	return GE_NOMEM;

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_socket_open(struct gensio_os_funcs *o,
		      const struct gensio_addr *addr, int protocol,
		      int *fd)
{
    int sockproto, socktype, family;
    int newfd;

    family = addr->curr->ai_family;

    if (do_errtrig())
	return GE_NOMEM;

    switch (protocol) {
    case GENSIO_NET_PROTOCOL_TCP:
    case GENSIO_NET_PROTOCOL_UNIX:
	sockproto = 0;
	socktype = SOCK_STREAM;
	break;

    case GENSIO_NET_PROTOCOL_UDP:
	sockproto = 0;
	socktype = SOCK_DGRAM;
	break;

#if HAVE_LIBSCTP
    case GENSIO_NET_PROTOCOL_SCTP:
	sockproto = IPPROTO_SCTP;
	socktype = SOCK_STREAM;
#ifdef AF_INET6
	/*
	 * For SCTP, always use AF_INET6 if available.  sctp_connectx()
	 * can use ipv4 addresses, too, on an AF_INET6 socket.
	 */
	family = AF_INET6;
#endif
	break;
#endif

    default:
	return GE_INVAL;
    }

    newfd = socket(family, socktype, sockproto);
    if (newfd == -1)
	return gensio_os_err_to_err(o, errno);
    *fd = newfd;
    return 0;
}

int
gensio_os_socket_setup(struct gensio_os_funcs *o, int fd,
		       int protocol, bool keepalive, bool nodelay,
		       unsigned int opensock_flags,
		       struct gensio_addr *bindaddr)
{
    int err;
    int val = 1;

    err = gensio_os_set_non_blocking(o, fd);
    if (err)
	return err;

    if (keepalive) {
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		       (void *)&val, sizeof(val)) == -1)
	    return gensio_os_err_to_err(o, errno);
    }

    if (opensock_flags & GENSIO_OPENSOCK_REUSEADDR) {
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		       (void *)&val, sizeof(val)) == -1)
	    return gensio_os_err_to_err(o, errno);
    }

    if (nodelay) {
	if (protocol == GENSIO_NET_PROTOCOL_TCP)
	    err = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
#if HAVE_LIBSCTP
	else if (protocol == GENSIO_NET_PROTOCOL_SCTP)
	    err = setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &val, sizeof(val));
#endif
	else
	    err = 0;
	if (err)
	    return gensio_os_err_to_err(o, errno);
    }

    if (bindaddr) {
	struct addrinfo *ai;

	switch (protocol) {
#if HAVE_LIBSCTP
	case GENSIO_NET_PROTOCOL_SCTP:
	    ai = bindaddr->a;
	    while (ai) {
		if (sctp_bindx(fd, ai->ai_addr, 1, SCTP_BINDX_ADD_ADDR) == -1)
		    return gensio_os_err_to_err(o, errno);
		ai = ai->ai_next;
	    }
	    break;
#endif

	case GENSIO_NET_PROTOCOL_TCP:
	case GENSIO_NET_PROTOCOL_UDP:
	case GENSIO_NET_PROTOCOL_UNIX:
	    ai = bindaddr->curr;
	    if (bind(fd, ai->ai_addr, ai->ai_addrlen) == -1)
		return gensio_os_err_to_err(o, errno);
	    break;

	default:
	    return GE_INVAL;
	}
    }

    return 0;
}

int
gensio_os_mcast_add(struct gensio_os_funcs *o, int fd,
		    struct gensio_addr *mcast_addrs, int interface,
		    bool curr_only)
{
    struct addrinfo *ai;
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    if (curr_only)
	ai = mcast_addrs->curr;
    else
	ai = mcast_addrs->a;

    while (ai) {
	switch (ai->ai_addr->sa_family) {
	case AF_INET:
	    {
		struct sockaddr_in *a = (struct sockaddr_in *) ai->ai_addr;
		struct ip_mreqn m;

		m.imr_multiaddr = a->sin_addr;
		m.imr_address.s_addr = INADDR_ANY;
		m.imr_ifindex = interface;
		rv = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				&m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, errno);
	    }
	    break;

	case AF_INET6:
	    {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *) ai->ai_addr;
		struct ipv6_mreq m;

		m.ipv6mr_multiaddr = a->sin6_addr;
		m.ipv6mr_interface = interface;
		rv = setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				&m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, errno);
	    }
	    break;

	default:
	    return GE_INVAL;
	}

	if (curr_only)
	    break;
	ai = ai->ai_next;
    }

    return 0;
}

int
gensio_os_mcast_del(struct gensio_os_funcs *o, int fd,
		    struct gensio_addr *mcast_addrs, int interface,
		    bool curr_only)
{
    struct addrinfo *ai;
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    if (curr_only)
	ai = mcast_addrs->curr;
    else
	ai = mcast_addrs->a;

    while (ai) {
	switch (ai->ai_addr->sa_family) {
	case AF_INET:
	    {
		struct sockaddr_in *a = (struct sockaddr_in *) ai->ai_addr;
		struct ip_mreqn m;

		m.imr_multiaddr = a->sin_addr;
		m.imr_address.s_addr = INADDR_ANY;
		m.imr_ifindex = interface;
		rv = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				&m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, errno);
	    }
	    break;

	case AF_INET6:
	    {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *) ai->ai_addr;
		struct ipv6_mreq m;

		m.ipv6mr_multiaddr = a->sin6_addr;
		m.ipv6mr_interface = interface;
		rv = setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				&m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, errno);
	    }
	    break;

	default:
	    return GE_INVAL;
	}

	if (curr_only)
	    break;
	ai = ai->ai_next;
    }

    return 0;
}

int
gensio_os_set_mcast_loop(struct gensio_os_funcs *o, int fd,
			 const struct gensio_addr *addr, bool ival)
{
    int rv, val = ival;

    if (do_errtrig())
	return GE_NOMEM;

    switch (addr->curr->ai_addr->sa_family) {
    case AF_INET:
	rv = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &val, sizeof(val));
	if (rv == -1)
	    return gensio_os_err_to_err(o, errno);
	break;

    case AF_INET6:
	rv = setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			&val, sizeof(val));
	if (rv == -1)
	    return gensio_os_err_to_err(o, errno);
	break;

    default:
	return GE_INVAL;
    }

    return 0;
}

int
gensio_os_connect(struct gensio_os_funcs *o, int fd,
		  const struct gensio_addr *addr)
{
    int err;

    if (do_errtrig())
	return GE_NOMEM;

    err = check_ipv6_only(addr->curr->ai_family,
			  addr->curr->ai_protocol,
			  addr->curr->ai_flags,
			  fd);
    if (err == 0)
	err = connect(fd, addr->curr->ai_addr, addr->curr->ai_addrlen);
    if (err == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_get_nodelay(struct gensio_os_funcs *o, int fd, int protocol, int *val)
{
    socklen_t vallen = sizeof(*val);
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    if (protocol == GENSIO_NET_PROTOCOL_TCP)
	rv = getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, val, &vallen);
#if HAVE_LIBSCTP
    else if (protocol == GENSIO_NET_PROTOCOL_SCTP)
	rv = getsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &val, &vallen);
#endif
    else
	return GE_INVAL;

    if (rv == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_set_nodelay(struct gensio_os_funcs *o, int fd, int protocol, int val)
{
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    if (protocol == GENSIO_NET_PROTOCOL_TCP)
	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
#if HAVE_LIBSCTP
    else if (protocol == GENSIO_NET_PROTOCOL_SCTP)
	rv = setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &val, sizeof(val));
#endif
    else
	return GE_INVAL;

    if (rv == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_getsockname(struct gensio_os_funcs *o, int fd,
		      struct gensio_addr **raddr)
{
    struct gensio_addr *addr;
    int err;

    if (do_errtrig())
	return GE_NOMEM;

    addr = gensio_addr_make(o, sizeof(struct sockaddr_storage), true);
    if (!addr)
	return GE_NOMEM;

    err = getsockname(fd, addr->curr->ai_addr, &addr->curr->ai_addrlen);
    if (err)
	return gensio_os_err_to_err(o, errno);

    addr->curr->ai_family = addr->curr->ai_addr->sa_family;
    *raddr = addr;

    return 0;
}

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

int
gensio_os_get_random(struct gensio_os_funcs *o,
		     void *data, unsigned int len)
{
    int fd;
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    fd = open("/dev/urandom", O_RDONLY);
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

static unsigned int
gensio_dyn_scan_next(unsigned int port)
{
    if (port == IP_DYNRANGE_END)
	return IP_DYNRANGE_START;
    else
	return port + 1;
}

int
gensio_os_open_socket(struct gensio_os_funcs *o,
		      struct gensio_addr *ai,
		      void (*readhndlr)(int, void *),
		      void (*writehndlr)(int, void *),
		      void (*fd_handler_cleared)(int, void *),
		      int (*call_b4_listen)(int, void *),
		      void *data, unsigned int opensock_flags,
		      struct opensocks **rfds, unsigned int *nr_fds)
{
    struct addrinfo *rp;
    int family = AF_INET6; /* Try IPV6 first, then IPV4. */
    struct opensocks *fds;
    unsigned int curr_fd = 0, i;
    unsigned int max_fds = 0;
    int rv = 0;
    struct gensio_listen_scan_info scaninfo;

    if (do_errtrig())
	return GE_NOMEM;

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
	/*
	 * getaddrinfo() will return the same address twice in the
	 * list if ::1 and 127.0.0.1 are both set for localhost in
	 * /etc/hosts.  So the second open attempt will fail if we
	 * don't ignore this.  In general, it's probably better to
	 * ignore duplicates in this function, anyway.
	 */
	if (sockaddr_in_list_b4(rp, ai->a))
            continue;

	rv = gensio_setup_listen_socket(o, rp->ai_socktype == SOCK_STREAM,
					rp->ai_family, rp->ai_socktype,
					rp->ai_protocol, rp->ai_flags,
					rp->ai_addr, rp->ai_addrlen,
					readhndlr, writehndlr, data,
					fd_handler_cleared, call_b4_listen,
					opensock_flags,
					&fds[curr_fd].fd, &fds[curr_fd].port,
					&scaninfo);
	if (rv)
	    goto out_close;
	fds[curr_fd].family = rp->ai_family;
	fds[curr_fd].flags = rp->ai_flags;
	curr_fd++;
    }
    if (family == AF_INET6) {
	family = AF_INET;
	goto restart;
    }
#if HAVE_UNIX
    if (family == AF_INET) {
	family = AF_UNIX;
	goto restart;
    }
#endif

    if (curr_fd == 0) {
	o->free(o, fds);
	if (rv)
	    return rv;
	assert(0);
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
#if !HAVE_WORKING_PORT0
    if (rv == GE_ADDRINUSE && scaninfo.start != 0 &&
		scaninfo.curr != scaninfo.start) {
	/* We need to keep scanning. */
	curr_fd = 0;
	scaninfo.reqport = 0;
	family = AF_INET6;
	goto restart;
    }
#endif
    o->free(o, fds);
    return rv;
}

int
gensio_os_socket_get_port(struct gensio_os_funcs *o, int fd, unsigned int *port)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    rv = getsockname(fd, (struct sockaddr *) &sa, &len);
    if (rv)
	return gensio_os_err_to_err(o, errno);

    rv = sockaddr_get_port((struct sockaddr *) &sa, port);
    if (rv)
	return rv;

    return 0;
}

static int
gensio_setup_listen_socket(struct gensio_os_funcs *o, bool do_listen,
			   int family, int socktype, int protocol, int flags,
			   struct sockaddr *addr, socklen_t addrlen,
			   void (*readhndlr)(int, void *),
			   void (*writehndlr)(int, void *), void *data,
			   void (*fd_handler_cleared)(int, void *),
			   int (*call_b4_listen)(int, void *),
			   unsigned int opensock_flags,
			   int *rfd, unsigned int *rport,
			   struct gensio_listen_scan_info *rsi)
{
    int optval = 1;
    int fd, rv = 0;
    unsigned int port;
    struct sockaddr_storage sa;

    rv = sockaddr_get_port(addr, &port);
    if (rv == -1)
	return GE_INVAL;

    if (addrlen > sizeof(sa))
	return GE_TOOBIG;
    memcpy(&sa, addr, addrlen);
    addr = (struct sockaddr *) &sa;

    if (rsi && rsi->reqport != 0 && port == 0) {
	rv = sockaddr_set_port(addr, rsi->reqport);
	if (rv)
	    return rv;
	port = rsi->reqport;
    }

    fd = socket(family, socktype, protocol);
    if (fd == -1)
	return gensio_os_err_to_err(o, errno);

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
	goto out_err;

    if (opensock_flags & GENSIO_OPENSOCK_REUSEADDR) {
	if (family == AF_UNIX) {
	    /* We remove an existing socket with reuseaddr and AF_UNIX. */
	    struct sockaddr_un *unaddr = (struct sockaddr_un *) addr;
	    char unpath[sizeof(unaddr->sun_path) + 1];

	    /*
	     * Make sure the path is nil terminated.  See discussions
	     * in the unix(7) man page on Linux for details.
	     */
	    assert(addrlen <= sizeof(*unaddr));
	    memcpy(unpath, unaddr->sun_path, addrlen - sizeof(sa_family_t));
	    unpath[addrlen - sizeof(sa_family_t)] = '\0';

	    unlink(unpath);
	    /*
	     * Ignore errors, it may not exist, and we'll get errors
	     * later on problems.
	     */
	} else {
	    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			   (void *)&optval, sizeof(optval)) == -1)
		goto out_err;
	}
    }

    if (check_ipv6_only(family, protocol, flags, fd) == -1)
	goto out_err;
#if !HAVE_WORKING_PORT0
    if (port == 0 && (family == AF_INET || family == AF_INET6)) {
	struct gensio_listen_scan_info lsi;
	struct gensio_listen_scan_info *si = rsi;

	if (!si) {
	    si = &lsi;
	    memset(si, 0, sizeof(*si));
	}

	if (si->start == 0) {
	    /* Get a random port in the dynamic range. */
	    gensio_os_get_random(o, &si->start, sizeof(si->start));
	    si->start %= IP_DYNRANGE_END - IP_DYNRANGE_START + 1;
	    si->start += IP_DYNRANGE_START;
	    si->curr = si->start;
	}

	do {
	    rv = sockaddr_set_port(addr, si->curr);
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
    }
#endif
    if (bind(fd, addr, addrlen) != 0) {
	if (rsi)
	    rsi->curr = gensio_dyn_scan_next(rsi->curr);
	goto out_err;
    }
#if !HAVE_WORKING_PORT0
 got_it:
#endif
    if (family == AF_INET || family == AF_INET6) {
	rv = gensio_os_socket_get_port(o, fd, &port);
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
gensio_os_check_tcpd_ok(int new_fd, const char *iprogname)
{
#ifdef HAVE_TCPD_H
    struct request_info req;

    if (!iprogname)
	iprogname = progname;
    request_init(&req, RQ_DAEMON, iprogname, RQ_FILE, new_fd, NULL);
    fromhost(&req);

    if (!hosts_access(&req))
	return "Access denied\r\n";
#endif

    return NULL;
}

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
    case EPERM:         err = GE_PERM; break;
    case EACCES:        err = GE_PERM; break;
    default:		err = GE_OSERR;
    }

    if (err == GE_OSERR) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled OS error in %s:%d: %s (%d)", caller, lineno,
		   strerror(oserr), oserr);
    }

    return err;
}

static bool
sockaddr_inet6_inet4_equal(const struct sockaddr *a1, socklen_t l1,
			   const struct sockaddr *a2, socklen_t l2,
			   bool compare_ports)
{
    struct sockaddr_in6 *s1 = (struct sockaddr_in6 *) a1;
    struct sockaddr_in *s2 = (struct sockaddr_in *) a2;

    /* a1 is an IF_NET6 address. */

    if (a2->sa_family != AF_INET)
	return false;

    if (!IN6_IS_ADDR_V4MAPPED(&s1->sin6_addr))
	return false;

    if (compare_ports && s1->sin6_port != s2->sin_port)
	return false;

    return ((const uint32_t *) &s1->sin6_addr)[3] == s2->sin_addr.s_addr;
}

static bool
sockaddr_equal(const struct sockaddr *a1, socklen_t l1,
	       const struct sockaddr *a2, socklen_t l2,
	       bool compare_ports)
{
    if (a1->sa_family != a2->sa_family) {
	if (a1->sa_family == AF_INET6)
	    return sockaddr_inet6_inet4_equal(a1, l1, a2, l2, compare_ports);
	else if (a2->sa_family == AF_INET6)
	    return sockaddr_inet6_inet4_equal(a2, l2, a1, l1, compare_ports);
	return false;
    }
    if (l1 != l2)
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

#if HAVE_UNIX
    case AF_UNIX:
	{
	    struct sockaddr_un *s1 = (struct sockaddr_un *) a1;
	    struct sockaddr_un *s2 = (struct sockaddr_un *) a2;
	    if (strcmp(s1->sun_path, s2->sun_path) != 0)
		return false;
	}
	break;
#endif

    default:
	/* Unknown family. */
	return false;
    }

    return true;
}

bool
gensio_addr_equal(const struct gensio_addr *a1,
		  const struct gensio_addr *a2,
		  bool compare_ports, bool compare_all)
{
    struct addrinfo *ai1 = a1->a, *ai2 = a2->a;

    if (compare_all) {
	ai1 = a1->a;
	ai2 = a2->a;
    } else {
	ai1 = a1->curr;
	ai2 = a2->curr;
    }

    while (ai1 && ai2) {
	if (!sockaddr_equal(ai1->ai_addr, ai1->ai_addrlen,
			    ai2->ai_addr, ai2->ai_addrlen,
			    compare_ports))
	    return false;
	if (!compare_all)
	    return true;
	ai1 = ai1->ai_next;
	ai2 = ai2->ai_next;
    }
    if (ai1 != NULL || ai2 != NULL)
	return false;
    return true;
}

static int
gensio_sockaddr_to_str(const struct sockaddr *addr, int flags,
		       char *buf, gensiods *pos, gensiods buflen)
{
    if (addr->sa_family == AF_INET) {
	struct sockaddr_in *a4 = (struct sockaddr_in *) addr;
	char ibuf[INET_ADDRSTRLEN];

	gensio_pos_snprintf(buf, buflen, pos, "ipv4,%s,%d",
			inet_ntop(AF_INET, &a4->sin_addr, ibuf, sizeof(ibuf)),
			ntohs(a4->sin_port));
    } else if (addr->sa_family == AF_INET6) {
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) addr;
	char ibuf[INET6_ADDRSTRLEN];

	gensio_pos_snprintf(buf, buflen, pos, "%s,%s,%d",
			flags & AI_V4MAPPED ? "ipv6n4" : "ipv6",
			inet_ntop(AF_INET6, &a6->sin6_addr, ibuf, sizeof(ibuf)),
			ntohs(a6->sin6_port));
#if HAVE_UNIX
    } else if (addr->sa_family == AF_UNIX) {
	struct sockaddr_un *au = (struct sockaddr_un *) addr;

	gensio_pos_snprintf(buf, buflen, pos, "unix,%s", au->sun_path);
#endif
    } else {
	if (*pos < buflen)
	    buf[*pos] = '\0';
	return GE_INVAL;
    }

    return 0;
}

int
gensio_addr_to_str(const struct gensio_addr *addr,
		   char *buf, gensiods *pos, gensiods buflen)
{
    gensiods tmppos = 0;

    if (!pos)
	pos = &tmppos;
    return gensio_sockaddr_to_str(addr->curr->ai_addr, addr->curr->ai_flags,
				  buf, pos, buflen);
}

int
gensio_addr_to_str_all(const struct gensio_addr *addr,
		       char *buf, gensiods *pos, gensiods buflen)
{
    struct gensio_addr a = *addr;
    bool first = true;
    int rv;
    gensiods tmppos = 0;

    if (!pos)
	pos = &tmppos;

    for (a.curr = a.a; a.curr; a.curr = a.curr->ai_next) {
	if (!first)
	    /* Add the semicolons between the addresses. */
	    gensio_pos_snprintf(buf, buflen, pos, ";");
	first = false;

	rv = gensio_addr_to_str(&a, buf, pos, buflen);
	if (rv)
	    return rv;
    }

    return 0;
}

static int
scan_ips(struct gensio_os_funcs *o, const char *str, bool listen, int ifamily,
	 int socktype, int protocol, bool *is_port_set, bool scan_port,
	 struct gensio_addr **raddr)
{
    char *strtok_data, *strtok_buffer;
    struct gensio_addr *addr;
    struct addrinfo hints, *ai = NULL, *ai2, *pai = NULL;
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

    addr = gensio_addr_make(o, 0, true);
    if (!addr) {
	o->free(o, strtok_buffer);
	return GE_NOMEM;
    }

    ip = strtok_r(strtok_buffer, ",", &strtok_data);
    while (ip) {
	int family = ifamily, rflags = 0;
	bool notype = false, gotaddr = false;

	if (strcmp(ip, "ipv4") == 0) {
	    if (family != AF_UNSPEC && family != AF_INET) {
		rv = GE_INVAL;
		goto out_err;
	    }
	    family = AF_INET;
	    ip = strtok_r(NULL, ",", &strtok_data);
	} else if (strcmp(ip, "ipv6") == 0) {
#ifdef AF_INET6
	    if (family != AF_UNSPEC && family != AF_INET6) {
		rv = GE_INVAL;
		goto out_err;
	    }
	    family = AF_INET6;
	    ip = strtok_r(NULL, ",", &strtok_data);
#else
	    rv = GE_NOTSUP;
	    goto out_err;
#endif
	} else if (strcmp(ip, "ipv6n4") == 0) {
#ifdef AF_INET6
	    if (family != AF_UNSPEC && family != AF_INET6) {
		rv = GE_INVAL;
		goto out_err;
	    }
	    family = AF_INET6;
	    rflags |= AI_V4MAPPED;
	    ip = strtok_r(NULL, ",", &strtok_data);
#else
	    rv = GE_NOTSUP;
	    goto out_err;
#endif
	} else {
#ifdef AF_INET6
	    /*
	     * If IPV6 is present, we will try both IPV6 and IPV4
	     * addresses if an address is specified, or use
	     * AI_V4MAPPED if no ip is specified.
	     *
	     * This is a bit strange.  My reading of the getaddrinfo()
	     * man page says that if family == AF_UNSPEC, it's
	     * supposed to return IPV4 and IPV6 addresses.  It's not,
	     * even if AI_V4MAPPED is not set or AI_ALL is set, at
	     * least for localhost.
	     *
	     * It only matters if the user specifies an IP address (or
	     * host).  If the user does not specify an IP address, use
	     * AF_INET6 and AI_V4MAPPED and it works fine.  If the
	     * user specifies an IP address, pull the V6 addresses
	     * then the V4 addresses.  Do this for TCP connect
	     * sockets, too, as the connection will be tried on each
	     * address.
	     */
	    if (family == AF_UNSPEC) {
		notype = true;
		family = AF_INET6;
	    }
#endif
	}

	if (ip == NULL) {
	    rv = GE_INVAL;
	    goto out_err;
	}

	if (scan_port) {
	    port = strtok_r(NULL, ",", &strtok_data);
	    if (port == NULL) {
		port = ip;
		ip = NULL;
	    }

	    if (ip && *ip == '\0')
		ip = NULL;
	} else {
	    port = "0";
	}

#ifdef AF_INET6
 	/*
 	 * If the user specified something like "tcp,0", ip will be
 	 * NULL and getaddrinfo will return IPv4 and IPv6 addresses if
	 * they are available.  AF_V4MAPPED will be set, so we really
 	 * only want IPv6 addresses (if any are available) as once you
 	 * open the IPv6 address you can't open the IPv4 address.
	 */
	if (!ip && notype)
	    rflags |= AI_V4MAPPED;

    redo_getaddrinfo:
#endif
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = bflags | rflags;
	hints.ai_family = family;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;
	rv = getaddrinfo(ip, port, &hints, &ai);
	if (rv) {
#ifdef AF_INET6
	    if (notype && family == AF_INET6) {
		/* No IPV6, try just IPV4. */
		family = AF_INET;
		goto redo_getaddrinfo;
	    }
#endif
	    if (gotaddr) {
		/* We got some address earlier, go with it. */
		rv = 0;
		goto ignore_getaddr_error;
	    }
 
	    rv = GE_INVAL;
	    goto out_err;
	}
	gotaddr = true;

	/*
	 * If a port was/was not set, this must be consistent for all
	 * addresses.
	 */
	rv = sockaddr_get_port(ai->ai_addr, &portnum);
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

	for (ai2 = ai; ai2; ai2 = ai2->ai_next)
	    ai2->ai_flags = rflags;

	if (!addr->a) {
	    addr->a = ai;
	    ai = NULL;
	    addr->is_getaddrinfo = true;
	} else {
	    if (!pai) {
		rv = addrinfo_list_dup(o, addr->a, &ai2, &pai);
		if (rv)
		    goto out_err;
		freeaddrinfo(addr->a);
		addr->is_getaddrinfo = false;
		addr->a = ai2;
	    }
	    rv = addrinfo_list_dup(o, ai, NULL, &pai);
	    freeaddrinfo(ai);
	    ai = NULL;
	    if (rv)
		goto out_err;
	}
#ifdef AF_INET6
	if (ip && notype && ifamily == AF_UNSPEC && family == AF_INET6) {
	    /* See comments above on why this is done.  Yes, it's strange. */
	    family = AF_INET;
	    goto redo_getaddrinfo;
	}
#endif
    ignore_getaddr_error:
	ip = strtok_r(NULL, ",", &strtok_data);
	first = false;
    }

    if (!addr->a) {
	rv = GE_NOTFOUND;
	goto out_err;
    }

    addr->curr = addr->a;

    if (is_port_set)
	*is_port_set = portset;

    *raddr = addr;

 out_err:
    if (ai)
	freeaddrinfo(ai);
    if (rv)
	gensio_addr_free(addr);
    o->free(o, strtok_buffer);

    return rv;
}

static int
gensio_scan_unixaddr(struct gensio_os_funcs *o, const char *str,
		     struct gensio_addr **raddr)
{
#if HAVE_UNIX
    struct sockaddr_un *saddr;
    struct gensio_addr *addr = NULL;
    size_t len;

    len = strlen(str);
    if (len >= sizeof(saddr->sun_path) - 1)
	return GE_TOOBIG;

    addr = gensio_addr_make(o, sizeof(socklen_t) + len + 1, true);
    if (!addr)
	return GE_NOMEM;

    saddr = (struct sockaddr_un *) addr->a->ai_addr;
    saddr->sun_family = AF_UNIX;
    memcpy(saddr->sun_path, str, len);
    addr->a->ai_family = AF_UNIX;
    addr->a->ai_socktype = SOCK_STREAM;
    addr->a->ai_addrlen = sizeof(socklen_t) + len + 1;
    addr->a->ai_addr = (struct sockaddr *) saddr;

    *raddr = addr;

    return 0;
#else
    return GE_NOTSUP;
#endif
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
    int protocol, socktype, irprotocol;

    if (strncmp(str, "unix,", 4) == 0 ||
		(rargs && strncmp(str, "unix(", 4) == 0)) {
	if (str[4] == '(') {
	    if (!rargs)
		return GE_INVAL;
	    str += 4;
	    err = gensio_scan_args(o, &str, &argc, &args);
	    if (err)
		return err;
	} else {
	    str += 5;
	}

    handle_unix:
	err = gensio_scan_unixaddr(o, str, raddr);
	if (!err) {
	    irprotocol = GENSIO_NET_PROTOCOL_UNIX;
	    if (is_port_set)
		*is_port_set = false;
	}
	goto out;
    }

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
    handle_tcp:
	socktype = SOCK_STREAM;
	protocol = IPPROTO_TCP;
	irprotocol = GENSIO_NET_PROTOCOL_TCP;
    } else if (strncmp(str, "udp,", 4) == 0 ||
	       (rargs && strncmp(str, "udp(", 4) == 0)) {
	str += 3;
    handle_udp:
	socktype = SOCK_DGRAM;
	protocol = IPPROTO_UDP;
	irprotocol = GENSIO_NET_PROTOCOL_UDP;
    } else if (strncmp(str, "sctp,", 5) == 0 ||
	       (rargs && strncmp(str, "sctp(", 5) == 0)) {
	str += 4;
    handle_sctp:
#if HAVE_LIBSCTP
	socktype = SOCK_SEQPACKET;
	protocol = IPPROTO_SCTP;
	irprotocol = GENSIO_NET_PROTOCOL_SCTP;
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
	} else if (*str != ',') {
	    return GE_INVAL;
	} else {
	    str++; /* Skip the ',' */
	}
    }

    err = scan_ips(o, str, listen, family, socktype, protocol,
		   is_port_set, true, raddr);
 out:
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
gensio_scan_network_addr(struct gensio_os_funcs *o, const char *str,
			 int iprotocol, struct gensio_addr **raddr)
{
    int protocol;

    switch (iprotocol) {
    case GENSIO_NET_PROTOCOL_TCP: protocol = IPPROTO_TCP; break;
    case GENSIO_NET_PROTOCOL_UDP: protocol = IPPROTO_UDP; break;
    case GENSIO_NET_PROTOCOL_SCTP: protocol = IPPROTO_SCTP; break;
    default:
	return GE_INVAL;
    }

    return scan_ips(o, str, false, 0, 0, protocol, NULL, false, raddr);
}

int
gensio_os_scan_netaddr(struct gensio_os_funcs *o, const char *str, bool listen,
		       int gprotocol, struct gensio_addr **raddr)
{
    int protocol, socktype;
    bool is_port_set;
    struct gensio_addr *addr;
    int rv;

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
#if HAVE_LIBSCTP
	socktype = SOCK_SEQPACKET;
	protocol = IPPROTO_SCTP;
	break;
#else
	return GE_NOTSUP;
#endif

    case GENSIO_NET_PROTOCOL_UNIX:
	return gensio_scan_unixaddr(o, str, raddr);

    default:
	return GE_INVAL;
    }

    rv = scan_ips(o, str, listen, AF_UNSPEC, socktype, protocol,
		  &is_port_set, true, &addr);
    if (!rv && !listen && !is_port_set) {
	gensio_addr_free(addr);
	rv = GE_INVAL;
    } else {
	*raddr = addr;
    }
    return rv;
}

static struct addrinfo *
addrinfo_dup(struct gensio_os_funcs *o, struct addrinfo *iai)
{
    struct addrinfo *aic;

    aic = o->zalloc(o, sizeof(*aic));
    if (!aic)
	return NULL;
    memcpy(aic, iai, sizeof(*aic));
    aic->ai_next = NULL;
    aic->ai_addr = o->zalloc(o, iai->ai_addrlen);
    if (!aic->ai_addr) {
	o->free(o, aic);
	return NULL;
    }
    memcpy(aic->ai_addr, iai->ai_addr, iai->ai_addrlen);
    if (iai->ai_canonname) {
	aic->ai_canonname = gensio_strdup(o, iai->ai_canonname);
	if (!aic->ai_canonname) {
	    o->free(o, aic->ai_addr);
	    o->free(o, aic);
	    return NULL;
	}
    }

    return aic;
}

static void
addrinfo_list_free(struct gensio_os_funcs *o, struct addrinfo *ai)
{
    struct addrinfo *tai;

    while (ai) {
	tai = ai->ai_next;
	if (ai->ai_addr)
	    o->free(o, ai->ai_addr);
	if (ai->ai_canonname)
	    o->free(o, ai->ai_canonname);
	o->free(o, ai);
	ai = tai;
    }
}

static int
addrinfo_list_dup(struct gensio_os_funcs *o,
		  struct addrinfo *ai, struct addrinfo **rai,
		  struct addrinfo **rpai)
{
    struct addrinfo *cai, *pai = NULL;

    if (rpai)
	pai = *rpai;

    while (ai) {
	cai = addrinfo_dup(o, ai);
	if (!cai)
	    return GE_NOMEM;
	if (pai)
	    pai->ai_next = cai;
	else
	    *rai = cai;
	pai = cai;
	ai = ai->ai_next;
    }

    if (rpai)
	*rpai = pai;

    return 0;
}

struct gensio_addr *
gensio_addr_dup(const struct gensio_addr *iaddr)
{
    struct gensio_os_funcs *o;
    struct gensio_addr *addr;

    if (!iaddr)
	return NULL;

    o = iaddr->o;
    addr = o->zalloc(o, sizeof(*addr));
    if (!addr)
	return NULL;
    addr->o = o;

#if HAVE_GCC_ATOMICS
    if (iaddr->refcount) {
	addr->refcount = iaddr->refcount;
	addr->a = iaddr->a;
	addr->is_getaddrinfo = iaddr->is_getaddrinfo;
	__atomic_add_fetch(addr->refcount, 1, __ATOMIC_SEQ_CST);
    } else {
#endif
	do {
	    int rv;

	    rv = addrinfo_list_dup(o, iaddr->a, &addr->a, NULL);
	    if (rv) {
		addrinfo_list_free(o, addr->a);
		o->free(o, addr);
		return NULL;
	    }
#if HAVE_GCC_ATOMICS
	    addr->refcount = o->zalloc(o, sizeof(*addr->refcount));
	    if (!addr->refcount) {
		addrinfo_list_free(o, addr->a);
		o->free(o, addr);
		return NULL;
	    }
	    *addr->refcount = 1;
#endif
	} while(false);
#if HAVE_GCC_ATOMICS
    }
#endif
    addr->curr = addr->a;

    return addr;
}

struct gensio_addr *
gensio_addr_cat(const struct gensio_addr *addr1,
		const struct gensio_addr *addr2)
{
    struct gensio_os_funcs *o = addr1->o;
    struct gensio_addr *addr;
    struct addrinfo *aip = NULL;
    int rv;

    addr = gensio_addr_make(o, 0, true);
    if (!addr)
	return NULL;

    rv = addrinfo_list_dup(o, addr1->a, &addr->a, &aip);
    if (rv)
	goto out_err;

    rv = addrinfo_list_dup(o, addr2->a, NULL, &aip);
    if (rv)
	goto out_err;

    addr->curr = addr->a;

    return addr;

 out_err:
    addrinfo_list_free(o, addr->a);
    o->free(o, addr);
    return NULL;
}

bool
gensio_addr_cmp(const struct gensio_addr *addr1,
		const struct gensio_addr *addr2,
		bool compare_ports, bool all_addr)
{
    if (all_addr) {
	struct addrinfo *ai1 = addr1->a;
	struct addrinfo *ai2 = addr2->a;

	while (ai1 && ai2) {
	    if (!sockaddr_equal(ai1->ai_addr, ai1->ai_addrlen,
				ai2->ai_addr, ai2->ai_addrlen,
				compare_ports))
		return false;
	    ai1 = ai1->ai_next;
	    ai2 = ai2->ai_next;
	}
	return ai1 == ai2; /* Same if they are both NULL. */
    }

    return sockaddr_equal(addr1->curr->ai_addr, addr1->curr->ai_addrlen,
			  addr2->curr->ai_addr, addr2->curr->ai_addrlen,
			  compare_ports);
}

bool
gensio_addr_addr_present(const struct gensio_addr *gai,
			 const void *addr, gensiods addrlen,
			 bool compare_ports)
{
    struct addrinfo *ai = gai->a;

    while (ai) {
	if (sockaddr_equal(addr, addrlen, ai->ai_addr, ai->ai_addrlen,
			   compare_ports))
	    return true;
	ai = ai->ai_next;
    }
    return false;
}

void
gensio_addr_free(struct gensio_addr *addr)
{
    struct gensio_os_funcs *o;

    if (!addr)
	return;

    o = addr->o;
#if HAVE_GCC_ATOMICS
    if (addr->refcount) {
	if (__atomic_sub_fetch(addr->refcount, 1, __ATOMIC_SEQ_CST) != 0) {
	    o->free(o, addr);
	    return;
	}
	o->free(o, addr->refcount);
    }
#endif
    if (addr->a) {
	if (addr->is_getaddrinfo)
	    freeaddrinfo(addr->a);
	else
	    addrinfo_list_free(o, addr->a);
    }
    o->free(o, addr);
}

bool
gensio_addr_next(struct gensio_addr *addr)
{
    if (!addr->curr->ai_next)
	return false;
    addr->curr = addr->curr->ai_next;
    return true;
}

void
gensio_addr_rewind(struct gensio_addr *addr)
{
    addr->curr = addr->a;
}

int
gensio_addr_get_nettype(const struct gensio_addr *addr)
{
    return addr->curr->ai_addr->sa_family;
}

bool
gensio_addr_family_supports(const struct gensio_addr *addr, int family,
			    int flags)
{
    if (addr->curr->ai_addr->sa_family == family)
	return true;
    if (addr->curr->ai_addr->sa_family == AF_INET && family == AF_INET6 &&
		flags & AI_V4MAPPED)
	return true;
    return false;
}

void
gensio_addr_getaddr(const struct gensio_addr *addr,
		    void *oaddr, gensiods *rlen)
{
    gensiods len;

    len = *rlen;
    if (len > addr->curr->ai_addrlen)
	len = addr->curr->ai_addrlen;
    memcpy(oaddr, addr->curr->ai_addr, len);
    *rlen = addr->curr->ai_addrlen;
}
