/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#define _GNU_SOURCE /* Get in6_pktinfo. */
#include "config.h"
#define _DEFAULT_SOURCE /* Get getgrouplist(), setgroups() */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int taddrlen;
typedef int sockret;
#define sock_errno WSAGetLastError()
#define SOCK_EINTR WSAEINTR
#define SOCK_EWOULDBLOCK WSAEWOULDBLOCK
#define SOCK_EAGAIN WSAEWOULDBLOCK
#define SOCK_EADDRINUSE WSAEADDRINUSE
#define SOCK_EPIPE WSAECONNRESET
#define SOCK_EINVAL WSAEINVAL
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <unistd.h>
typedef socklen_t taddrlen;
typedef ssize_t sockret;
#define sock_errno errno
#define SOCK_EINTR EINTR
#define SOCK_EWOULDBLOCK EWOULDBLOCK
#define SOCK_EAGAIN EWOULDBLOCK
#define SOCK_EADDRINUSE EADDRINUSE
#define SOCK_EPIPE EPIPE
#define SOCK_EINVAL EINVAL
#endif
#if HAVE_UNIX
#include <sys/un.h>
#endif

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>

#include "errtrig.h"

#include <gensio/gensio_osops_addrinfo.h>
#include <gensio/gensio_osops_stdsock.h>

/* MacOS doesn't have IPV6_ADD_MEMBERSHIP, but has an equivalent. */
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif

/* For older systems that don't have this. */
#ifndef AI_V4MAPPED
#define AI_V4MAPPED 0
#endif

struct gensio_stdsock_info {
    int protocol;
    int family;
    /*
     * Has the connect completed?  Windows shutdown will not return an
     * FD_CLOSE after a shutdown if the socket has not finished
     * opening, so if open is not complete, use this to just close the
     * socket.
     */
    bool connected;

#ifdef HAVE_RECVMSG
    /* Is the extrainfo flag set? */
    bool extrainfo;
#endif
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
			       int (*call_b4_listen)(struct gensio_iod *,
						     void *),
			       void *data,
			       unsigned int opensock_flags,
			       struct gensio_iod **iod, unsigned int *port,
			       struct gensio_listen_scan_info *rsi);

bool sockaddr_equal(const struct sockaddr *a1, socklen_t l1,
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
	if (sock_errno == SOCK_EINTR)				\
	    goto retry;						\
	if (sock_errno == SOCK_EWOULDBLOCK || sock_errno == SOCK_EAGAIN) \
	    rv = 0; /* Handle like a zero-byte write. */	\
	else {							\
	    err = sock_errno;					\
	    assert(err);					\
	}							\
    } else if (rv == 0) {					\
	err = SOCK_EPIPE;					\
    }								\
    if (!err && rcount)						\
	*rcount = rv;						\
    rv = gensio_os_err_to_err(o, err);				\
} while(0)

static int
close_socket(struct gensio_os_funcs *o, int fd)
{
    int err;

    /* Don't do errtrig on close, it can fail and not cause any issues. */

    assert(fd != -1);
#ifdef _WIN32
    err = closesocket(fd);
#else
    err = close(fd);
#endif
#if defined(ENABLE_INTERNAL_TRACE) && !defined(_WIN32)
    /*
     * Close should never fail (well, except for windows), but don't crash
     * in production builds.
     */
    assert(err == 0);
#endif

    if (err == -1)
	return gensio_os_err_to_err(o, sock_errno);
    return 0;
}

#if HAVE_LIBSCTP
#include <netinet/sctp.h>

static void
sctp_shutdown_fds(struct gensio_os_funcs *o,
		  struct gensio_opensocks *fds, unsigned int nrfds)
{
    unsigned int i;

    if (!fds)
	return;

    for (i = 0; i < nrfds; i++) {
	o->clear_fd_handlers_norpt(fds[i].iod);
	o->close(&fds[i].iod);
    }
    o->free(o, fds);
}

static int
gensio_os_sctp_open_sockets(struct gensio_os_funcs *o,
			    struct gensio_addr *addr,
			    int (*call_b4_listen)(struct gensio_iod *iod,
						  void *data),
			    void *data, unsigned int opensock_flags,
			    struct gensio_opensocks **rfds,
			    unsigned int *rnr_fds)
{
    struct addrinfo *ai, *rp;
    unsigned int i;
    int family = AF_INET6;
    int rv = 0;
    struct gensio_listen_scan_info scaninfo;
    struct gensio_opensocks *fds = NULL, *tfds;
    int nr_fds = 0;

    memset(&scaninfo, 0, sizeof(scaninfo));

    ai = gensio_addr_addrinfo_get(addr);
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

	rv = gensio_sockaddr_get_port(rp->ai_addr, &port);
	if (rv)
	    goto out_err;

	for (i = 0; i < nr_fds; i++) {
	    if (port == fds[i].port && (fds[i].family == family)) {
		if (sctp_bindx(o->iod_get_fd(fds[i].iod), rp->ai_addr, 1,
			       SCTP_BINDX_ADD_ADDR)) {
		    rv = gensio_os_err_to_err(o, sock_errno);
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
					call_b4_listen, data, opensock_flags,
					&tfds[i].iod, &tfds[i].port, &scaninfo);
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

static int
gensio_stdsock_sctp_recvmsg(struct gensio_iod *iod, void *msg, gensiods len,
			    gensiods *rcount,
			    struct sctp_sndrcvinfo *sinfo, int *flags)
{
    struct gensio_os_funcs *o = iod->f;
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

 retry:
    rv = sctp_recvmsg(o->iod_get_fd(iod), msg, len, NULL, NULL, sinfo, flags);
    ERRHANDLE();
    return rv;
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
    return rv;
}

#if HAVE_SCTP_SENDV
#define gensio_stdsock_sctp_send l_gensio_stdsock_sctp_send
#endif

static int
gensio_stdsock_sctp_send(struct gensio_iod *iod,
			 const struct gensio_sg *sg, gensiods sglen,
			 gensiods *rcount,
			 const struct sctp_sndrcvinfo *sinfo, uint32_t flags)
{
    struct gensio_os_funcs *o = iod->f;
    int err = 0;
    gensiods i, count = 0, total_write = 0;

    if (do_errtrig())
	return GE_NOMEM;

    /* Without sctp_sendv, this is really hard to do. */
    for (i = 0; i < sglen; i++) {
	err = l_sctp_send(o, o->iod_get_fd(iod),
			  sg[i].buf, sg[i].buflen, &count, sinfo, flags);
	if (err || count == 0)
	    break;
	total_write += count;
    }
    if (rcount)
	*rcount = total_write;
    return err;
}

#if HAVE_SCTP_SENDV
#undef gensio_stdsock_sctp_send
static bool sctp_sendv_broken;
static int
gensio_stdsock_sctp_send(struct gensio_iod *iod,
			 const struct gensio_sg *sg, gensiods sglen,
			 gensiods *rcount,
			 const struct sctp_sndrcvinfo *sinfo, uint32_t flags)
{
    struct gensio_os_funcs *o = iod->f;
    int rv = 0;
    struct sctp_sndinfo *sndinfo = NULL, sdata;

    if (do_errtrig())
	return GE_NOMEM;

    if (sctp_sendv_broken) {
    broken:
	return l_gensio_stdsock_sctp_send(iod, sg, sglen, rcount, sinfo, flags);
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
    rv = sctp_sendv(o->iod_get_fd(iod), (struct iovec *) sg, sglen, NULL, 0,
		    sndinfo, sizeof(*sndinfo), SCTP_SENDV_SNDINFO, flags);
    if (rv == -1 && sock_errno == SOCK_EINVAL) {
	/* No sendv support, fall back. */
	sctp_sendv_broken = true;
	goto broken;
    }
    ERRHANDLE();
    return rv;
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

    for (ai = gensio_addr_addrinfo_get(addrs); ai; ai = ai->ai_next) {
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
    for (ai = gensio_addr_addrinfo_get(addrs), i = 0;
	 i < slen; ai = ai->ai_next) {
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

static int
gensio_stdsock_sctp_connectx(struct gensio_iod *iod, struct gensio_addr *addrs)
{
    struct gensio_os_funcs *o = iod->f;
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

	err = setsockopt(o->iod_get_fd(iod), IPPROTO_IPV6, IPV6_V6ONLY,
			 &val, sizeof(val));
	if (err)
	    goto out_err;
	val = !val;
	err = setsockopt(o->iod_get_fd(iod), SOL_SCTP,
			 SCTP_I_WANT_MAPPED_V4_ADDR, &val, sizeof(val));
	if (err)
	    goto out_err;
    }
    err = sctp_connectx(o->iod_get_fd(iod), saddrs, naddrs, NULL);
    if (err == -1)
	err = gensio_os_err_to_err(o, sock_errno);
    else
	err = 0;
 out_err:
    o->free(o, saddrs);
    return err;
}

static int
sctp_getraddr(struct gensio_os_funcs *o,
	      int fd, struct sockaddr **addr, gensiods *addrlen)
{
    int rv;

    rv = sctp_getpaddrs(fd, 0, addr);
    if (rv < 0) {
	return gensio_os_err_to_err(o, sock_errno);
    } if (rv == 0) {
	return GE_NOTFOUND;
    }
    *addrlen = rv;
    return 0;
}

static int
gensio_os_sctp_getraddr(struct gensio_iod *iod, void *addr, gensiods *addrlen)
{
    struct gensio_os_funcs *o = iod->f;
    struct sockaddr *saddr;
    gensiods len = 0, clen = *addrlen;
    int rv = sctp_getraddr(o, o->iod_get_fd(iod), &saddr, &len);

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

    addr = gensio_addr_addrinfo_make(o, 0, false);
    if (!addr)
	return GE_NOMEM;

    rv = GE_NOMEM;
    d = (char *) saddr;
    for (i = 0; i < len; i++) {
	s = (struct sockaddr *) d;

	ai = o->zalloc(o, sizeof(*ai));
	if (!ai)
	    goto out;
	if (!aip) {
	    gensio_addr_addrinfo_set(addr, ai);
	} else {
	    aip->ai_next = ai;
	}
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
    *raddr = addr;

 out:
    if (rv && addr)
	gensio_addr_free(addr);
    return rv;
}

static int
gensio_os_sctp_getpaddrs(struct gensio_iod *iod, struct gensio_addr **raddr)
{
    struct gensio_os_funcs *o = iod->f;
    struct sockaddr *saddr;
    gensiods len = 0;
    int rv = sctp_getraddr(o, o->iod_get_fd(iod), &saddr, &len);

    if (rv)
	return rv;

    rv = sctp_addr_to_addr(o, saddr, len, raddr);
    sctp_freepaddrs(saddr);
    return rv;
}

static int
gensio_os_sctp_getladdrs(struct gensio_iod *iod, struct gensio_addr **raddr)
{
    struct gensio_os_funcs *o = iod->f;
    int rv;
    struct sockaddr *saddr;

    rv = sctp_getladdrs(o->iod_get_fd(iod), 0, &saddr);
    if (rv < 0) {
	return gensio_os_err_to_err(o, sock_errno);
    } if (rv == 0) {
	return GE_NOTFOUND;
    }

    rv = sctp_addr_to_addr(o, saddr, rv, raddr);
    sctp_freeladdrs(saddr);
    return rv;
}

static int
gensio_stdsock_sctp_socket_setup(struct gensio_iod *iod, bool events,
				 struct sctp_initmsg *initmsg,
				 struct sctp_sack_info *sackinfo)
{
    int err = 0, fd = iod->f->iod_get_fd(iod);

    if (initmsg) {
	err = setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG,
			 initmsg, sizeof(*initmsg));
	if (err)
	    return err;
    }

    if (sackinfo) {
	err = setsockopt(fd, IPPROTO_SCTP, SCTP_DELAYED_SACK,
			 sackinfo, sizeof(*sackinfo));
	if (err)
	return err;
    }

    if (events) {
	struct sctp_event_subscribe event_sub;

	memset(&event_sub, 0, sizeof(event_sub));
	event_sub.sctp_data_io_event = 1;
	err = setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS,
			 &event_sub, sizeof(event_sub));
    }

    return err;
}

static int
gensio_stdsock_sctp_get_socket_status(struct gensio_iod *iod,
				      struct sctp_status *status)
{
    int err, fd = iod->f->iod_get_fd(iod);
    taddrlen stat_size = sizeof(*status);

    err = getsockopt(fd, IPPROTO_SCTP, SCTP_STATUS, status, &stat_size);
    if (err)
	/*
	 * If the remote end closes, this fails with EINVAL.  Just
	 * assume the remote end closed on error.
	 */
	return GE_REMCLOSE;

    return 0;
}

#endif

static int
check_ipv6_only(int family, int protocol, int flags, int fd)
{
    int val;

#ifdef AF_INET6
    if (family != AF_INET6)
	return 0;
#endif

    if (flags & AI_V4MAPPED)
	val = 0;
    else
	val = 1;

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &val,
		   sizeof(val)) == -1)
	return -1;

#if HAVE_LIBSCTP
    if (protocol == IPPROTO_SCTP) {
	val = !val;
	if (setsockopt(fd, SOL_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, (void *) &val,
		       sizeof(val)) == -1)
	    return -1;
    }
#endif
    return 0;
}

static int
gensio_stdsock_recv(struct gensio_iod *iod, void *buf, gensiods buflen,
		    gensiods *rcount, int gflags)
{
    struct gensio_os_funcs *o = iod->f;
    sockret rv;
    int flags = (gflags & GENSIO_MSG_OOB) ? MSG_OOB : 0;

    if (do_errtrig())
	return GE_NOMEM;

 retry:
    rv = recv(o->iod_get_fd(iod), buf, buflen, flags);
    ERRHANDLE();
    return rv;
}

#ifndef HAVE_SENDMSG
static unsigned char *
gensio_sg_to_buf(const struct gensio_sg *sg, gensiods sglen, gensiods *rlen)
{
    gensiods len = 0, pos = 0, i;
    unsigned char *buf;

    for (i = 0; i < sglen; i++)
	len += sg[i].buflen;
    buf = malloc(len);
    if (!buf)
	return NULL;
    for (i = 0; i < sglen; i++) {
	memcpy(buf + pos, sg[i].buf, sg[i].buflen);
	pos += sg[i].buflen;
    }
    *rlen = len;
    return buf;
}
#endif

static int
gensio_stdsock_send(struct gensio_iod *iod,
		    const struct gensio_sg *sg, gensiods sglen,
		    gensiods *rcount, int gflags)
{
    struct gensio_os_funcs *o = iod->f;
    sockret rv;
    int flags = (gflags & GENSIO_MSG_OOB) ? MSG_OOB : 0;

    if (do_errtrig())
	return GE_NOMEM;

    {
#ifdef HAVE_SENDMSG
	struct msghdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = (struct iovec *) sg;
	hdr.msg_iovlen = sglen;

    retry:
	rv = sendmsg(o->iod_get_fd(iod), &hdr, flags);
	ERRHANDLE();
#else
	gensiods len;
	void *buf;

	buf = gensio_sg_to_buf(sg, sglen, &len);
	if (!buf)
	    return GE_NOMEM;
    retry:
	rv = send(o->iod_get_fd(iod), buf, len, flags);
	ERRHANDLE();
	free(buf);
#endif
    }
    return rv;
}

static int
gensio_stdsock_sendto(struct gensio_iod *iod,
		      const struct gensio_sg *sg, gensiods sglen,
		      gensiods *rcount,
		      int gflags, const struct gensio_addr *raddr)
{
    struct gensio_os_funcs *o = iod->f;
    sockret rv;
    int flags = (gflags & GENSIO_MSG_OOB) ? MSG_OOB : 0;

    if (do_errtrig())
	return GE_NOMEM;

    {
#ifdef HAVE_SENDMSG
	struct msghdr hdr;
	struct addrinfo *ai;

	ai = gensio_addr_addrinfo_get_curr(raddr);
	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_name = (void *) ai->ai_addr;
	hdr.msg_namelen = ai->ai_addrlen;
	hdr.msg_iov = (struct iovec *) sg;
	hdr.msg_iovlen = sglen;
    retry:
	rv = sendmsg(o->iod_get_fd(iod), &hdr, flags);
	ERRHANDLE();
#else
	gensiods len;
	void *buf;
	struct addrinfo *ai;

	ai = gensio_addr_addrinfo_get_curr(raddr);
	buf = gensio_sg_to_buf(sg, sglen, &len);
	if (!buf)
	    return GE_NOMEM;
    retry:
	rv = sendto(o->iod_get_fd(iod), buf, len, flags,
		    (void *) ai->ai_addr, ai->ai_addrlen);
	ERRHANDLE();
	free(buf);
#endif
    }
    return rv;
}

static struct gensio_addr *
gensio_addr_addrinfo_alloc_recvfrom(struct gensio_os_funcs *o)
{
    /*
     * Addresses used for recvfrom cannot be duplicated with refcounts
     * because the storage is reused.  So allocate them without a
     * refcount to mark them to always do a full replication.
     */
    return gensio_addr_addrinfo_make(o, sizeof(struct sockaddr_storage),
				     true);
}

static int
gensio_stdsock_recvfrom(struct gensio_iod *iod,
			void *buf, gensiods buflen, gensiods *rcount,
			int flags, struct gensio_addr *addr)
{
    struct gensio_os_funcs *o = iod->f;
    sockret rv;
    int err = 0;
    taddrlen len;
    struct addrinfo *ai;
#ifdef HAVE_RECVMSG
    struct gensio_stdsock_info *gsi;
    struct msghdr hdr;
    struct iovec iov;
    unsigned char ctrlinfo[128];
#endif

    if (do_errtrig())
	return GE_NOMEM;

    gensio_addr_rewind(addr);
    ai = gensio_addr_addrinfo_get_curr(addr);
 retry:
    len = sizeof(struct sockaddr_storage);
#ifdef HAVE_RECVMSG
    err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			 (intptr_t) &gsi);
    if (err)
	return err;

    memset(&hdr, 0, sizeof(hdr));
    hdr.msg_name = ai->ai_addr;
    hdr.msg_namelen = len;
    iov.iov_base = buf;
    iov.iov_len = buflen;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = ctrlinfo;
    hdr.msg_controllen = sizeof(ctrlinfo);
    rv = recvmsg(o->iod_get_fd(iod), &hdr, flags);
    len = hdr.msg_namelen;
#else
    rv = recvfrom(o->iod_get_fd(iod), buf, buflen, flags, ai->ai_addr, &len);
#endif
    if (rv >= 0) {
	ai->ai_addrlen = len;
	ai->ai_family = ai->ai_addr->sa_family;
    } else {
	if (sock_errno == SOCK_EINTR)
	    goto retry;
	if (sock_errno == SOCK_EWOULDBLOCK || sock_errno == SOCK_EAGAIN)
	    rv = 0; /* Handle like a zero-byte write. */
	else
	    err = sock_errno;
    }
#ifdef HAVE_RECVMSG
    if (!err && gsi->extrainfo) {
	struct cmsghdr *cmsg;

#ifdef IP_PKTINFO
	for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
	    if (cmsg->cmsg_level == IPPROTO_IP &&
			cmsg->cmsg_type == IP_PKTINFO) {
		struct in_pktinfo *pi;

		pi = (struct in_pktinfo *) CMSG_DATA(cmsg);
		if (gensio_addr_next(addr)) {
		    struct sockaddr *inaddr;

		    ai = gensio_addr_addrinfo_get_curr(addr);
		    ai->ai_family = GENSIO_AF_IFINDEX;
		    inaddr = (struct sockaddr *) ai->ai_addr;
		    inaddr->sa_family = GENSIO_AF_IFINDEX;
		    *((unsigned int *) inaddr->sa_data) = pi->ipi_ifindex;
		}
		if (gensio_addr_next(addr)) {
		    struct sockaddr_in *inaddr;

		    ai = gensio_addr_addrinfo_get_curr(addr);
		    ai->ai_family = AF_INET;
		    inaddr = (struct sockaddr_in *) ai->ai_addr;
		    inaddr->sin_family = AF_INET;
		    inaddr->sin_port = 0;
		    inaddr->sin_addr = pi->ipi_addr;
		}
	    }
	}
#elif defined(IP_RECVIF) && defined(IP_RECVDSTADDR)
	for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
	    if (cmsg->cmsg_level == IPPROTO_IP &&
			cmsg->cmsg_type == IP_RECVIF) {
		uint16_t *iptr;
		struct sockaddr *inaddr;

		/*
		 * There's no docs on this that I could find, but the
		 * value seems to be in the second 16-bit value in the
		 * data.  Not sure if it will work on big endian, or
		 * if this is even right.
		 */
		iptr = (uint16_t *) CMSG_DATA(cmsg);
		if (gensio_addr_next(addr)) {
		    ai = gensio_addr_addrinfo_get_curr(addr);
		    ai->ai_family = GENSIO_AF_IFINDEX;
		    inaddr = (struct sockaddr *) ai->ai_addr;
		    inaddr->sa_family = GENSIO_AF_IFINDEX;
		    *((unsigned int *) inaddr->sa_data) = iptr[1];
		}
	    }
	}
	for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
	    if (cmsg->cmsg_level == IPPROTO_IP &&
		       cmsg->cmsg_type == IP_RECVDSTADDR) {
		struct sockaddr_in *inaddr;

		if (gensio_addr_next(addr)) {
		    struct in_addr *iptr;

		    iptr = (struct in_addr *) CMSG_DATA(cmsg);
		    ai = gensio_addr_addrinfo_get_curr(addr);
		    ai->ai_family = AF_INET;
		    inaddr = (struct sockaddr_in *) ai->ai_addr;
		    inaddr->sin_family = AF_INET;
		    inaddr->sin_port = 0;
		    inaddr->sin_addr = *iptr;
		}
	    }
	}
#endif
#ifdef IPV6_RECVPKTINFO
	for (cmsg = CMSG_FIRSTHDR(&hdr); cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
	    if (cmsg->cmsg_level == IPPROTO_IPV6 &&
			cmsg->cmsg_type == IPV6_PKTINFO) {
		struct in6_pktinfo *pi;

		pi = (struct in6_pktinfo *) CMSG_DATA(cmsg);
		if (gensio_addr_next(addr)) {
		    struct sockaddr *inaddr;

		    ai = gensio_addr_addrinfo_get_curr(addr);
		    ai->ai_family = GENSIO_AF_IFINDEX;
		    inaddr = (struct sockaddr *) ai->ai_addr;
		    inaddr->sa_family = GENSIO_AF_IFINDEX;
		    *((unsigned int *) inaddr->sa_data) = pi->ipi6_ifindex;
		}
		if (gensio_addr_next(addr)) {
		    struct sockaddr_in6 *inaddr;

		    ai = gensio_addr_addrinfo_get_curr(addr);
		    ai->ai_family = AF_INET6;
		    inaddr = (struct sockaddr_in6 *) ai->ai_addr;
		    memset(inaddr, 0, sizeof(*inaddr));
		    inaddr->sin6_family = AF_INET6;
		    inaddr->sin6_addr = pi->ipi6_addr;
		}
	    }
	}
	gensio_addr_rewind(addr);
#endif
    }
#endif
    if (!err && rcount)
	*rcount = rv;
    return gensio_os_err_to_err(o, err);
}

static int
gensio_stdsock_accept(struct gensio_iod *iod,
		      struct gensio_addr **raddr, struct gensio_iod **newiod)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_addr *addr = NULL;
    int rv, err;
    struct sockaddr *sa;
    struct sockaddr_storage sadata;
    taddrlen len;
    struct gensio_iod *riod = NULL;
    struct addrinfo *ai = NULL;
    struct gensio_stdsock_info *gsi = NULL, *ogsi = NULL;

    if (do_errtrig())
	return GE_NOMEM;

    if (raddr) {
	addr = gensio_addr_addrinfo_make(o, sizeof(struct sockaddr_storage),
					 false);
	if (!addr)
	    return GE_NOMEM;
	ai = gensio_addr_addrinfo_get_curr(addr);
	sa = ai->ai_addr;
	len = ai->ai_addrlen;
    } else {
	sa = (struct sockaddr *) &sadata;
	len = sizeof(sadata);
    }

    rv = accept(o->iod_get_fd(iod), sa, &len);

    if (rv >= 0) {
	gsi = o->zalloc(o, sizeof(*gsi));
	if (!gsi) {
	    close_socket(o, rv);
	    err = GE_NOMEM;
	    goto out;
	}

	err = o->add_iod(o, GENSIO_IOD_SOCKET, rv, &riod);
	if (err) {
	    close_socket(o, rv);
	    goto out;
	}

	err = o->set_non_blocking(riod);
	if (err)
	    goto out;

	o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
		       (intptr_t) &ogsi);
	*gsi = *ogsi;
	gsi->connected = true;
	o->iod_control(riod, GENSIO_IOD_CONTROL_SOCKINFO, false,
		       (intptr_t) gsi);

	if (ai) {
	    ai->ai_family = ai->ai_addr->sa_family;
	    ai->ai_addrlen = len;
	    *raddr = addr;
	}
	*newiod = riod;
    } else {
	rv = sock_errno;
	if (rv == SOCK_EAGAIN && rv == SOCK_EWOULDBLOCK)
	    err = GE_NODATA;
	else
	    err = gensio_os_err_to_err(o, rv);
    }
 out:
    if (err) {
	if (gsi)
	    o->free(o, gsi);
	if (riod)
	    o->close(&riod);
	if (addr)
	    gensio_addr_free(addr);
    }
    return err;
}

static int
gensio_stdsock_check_socket_open(struct gensio_iod *iod)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_stdsock_info *gsi;
    int err, optval;
    socklen_t len = sizeof(optval);

    if (do_errtrig())
	return GE_NOMEM;

    err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			 (intptr_t) &gsi);
    if (err)
	return err;

    err = getsockopt(o->iod_get_fd(iod), SOL_SOCKET, SO_ERROR,
		     (void *) &optval, &len);
    if (err)
	err = gensio_os_err_to_err(o, sock_errno);
    else
	err = gensio_os_err_to_err(o, optval);
    if (!err)
	gsi->connected = true;
    return err;
}

static int
gensio_stdsock_socket_open(struct gensio_os_funcs *o,
			   const struct gensio_addr *addr, int protocol,
			   struct gensio_iod **riod)
{
    int sockproto, socktype, family;
    int newfd, err;
    struct addrinfo *ai;
    struct gensio_iod *iod;
    struct gensio_stdsock_info *gsi;

    if (do_errtrig())
	return GE_NOMEM;

    ai = gensio_addr_addrinfo_get_curr(addr);
    family = ai->ai_family;

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
	return gensio_os_err_to_err(o, sock_errno);
    err = o->add_iod(o, GENSIO_IOD_SOCKET, newfd, &iod);
    if (err) {
	close_socket(o, newfd);
	return err;
    }
    err = o->set_non_blocking(iod);
    if (err) {
	o->close(&iod);
	return err;
    }
    gsi = o->zalloc(o, sizeof(*gsi));
    if (!gsi) {
	o->close(&iod);
	return GE_NOMEM;
    }

    gsi->protocol = protocol;
    gsi->family = family;
    o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, false, (intptr_t) gsi);

    *riod = iod;
    return 0;
}

static int
gensio_stdsock_socket_set_setup(struct gensio_iod *iod,
				unsigned int opensock_flags,
				struct gensio_addr *bindaddr)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_stdsock_info *gsi = NULL;
    int err, val, fd;

    fd = o->iod_get_fd(iod);

    if (opensock_flags & GENSIO_SET_OPENSOCK_KEEPALIVE) {
	val = !!(opensock_flags & GENSIO_OPENSOCK_KEEPALIVE);
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		       (void *)&val, sizeof(val)) == -1)
	    return gensio_os_err_to_err(o, sock_errno);
    }

    if (opensock_flags & GENSIO_SET_OPENSOCK_NODELAY) {
	struct gensio_stdsock_info *gsi = NULL;

	err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			     (intptr_t) &gsi);
	if (err)
	    return err;

	val = !!(opensock_flags & GENSIO_OPENSOCK_NODELAY);

	if (gsi->protocol == GENSIO_NET_PROTOCOL_TCP)
	    err = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
			     (void *) &val, sizeof(val));
#if HAVE_LIBSCTP
	else if (gsi->protocol == GENSIO_NET_PROTOCOL_SCTP)
	    err = setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY,
			     (void *) &val, sizeof(val));
#endif
	else
	    err = 0;
	if (err)
	    return gensio_os_err_to_err(o, sock_errno);
    }

    if (opensock_flags & GENSIO_SET_OPENSOCK_REUSEADDR) {
	val = !!(opensock_flags & GENSIO_OPENSOCK_REUSEADDR);
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		       (void *)&val, sizeof(val)) == -1)
	    return gensio_os_err_to_err(o, sock_errno);
    }

    if (bindaddr) {
	struct addrinfo *ai;

	if (!gsi) {
	    err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
				 (intptr_t) &gsi);
	    if (err)
		return err;
	}
	switch (gsi->protocol) {
#if HAVE_LIBSCTP
	case GENSIO_NET_PROTOCOL_SCTP:
	    ai = gensio_addr_addrinfo_get(bindaddr);
	    while (ai) {
		if (sctp_bindx(fd, ai->ai_addr, 1, SCTP_BINDX_ADD_ADDR) == -1)
		    return gensio_os_err_to_err(o, sock_errno);
		ai = ai->ai_next;
	    }
	    break;
#endif

	case GENSIO_NET_PROTOCOL_TCP:
	case GENSIO_NET_PROTOCOL_UDP:
	case GENSIO_NET_PROTOCOL_UNIX:
	    ai = gensio_addr_addrinfo_get_curr(bindaddr);
	    if (bind(fd, ai->ai_addr, ai->ai_addrlen) == -1)
		return gensio_os_err_to_err(o, sock_errno);
	    break;

	default:
	    return GE_INVAL;
	}
    }

    return 0;
}

static int
gensio_stdsock_socket_get_setup(struct gensio_iod *iod,
				unsigned int *iopensock_flags)
{
    struct gensio_os_funcs *o = iod->f;
    int err;
    int val;
    taddrlen len;
    unsigned int opensock_flags = 0;
    struct gensio_stdsock_info *gsi = NULL;

    if (*iopensock_flags & GENSIO_SET_OPENSOCK_KEEPALIVE) {
	len = sizeof(val);
	if (getsockopt(o->iod_get_fd(iod), SOL_SOCKET, SO_KEEPALIVE,
		       (void *)&val, &len) == -1)
	    return gensio_os_err_to_err(o, sock_errno);
	opensock_flags |= GENSIO_SET_OPENSOCK_KEEPALIVE;
	if (val)
	    opensock_flags |= GENSIO_OPENSOCK_KEEPALIVE;
    }

    if (*iopensock_flags & GENSIO_SET_OPENSOCK_NODELAY) {
	if (!gsi) {
	    err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
				 (intptr_t) &gsi);
	    if (err)
		return err;
	}
	val = 0;
	len = sizeof(val);
	if (gsi->protocol == GENSIO_NET_PROTOCOL_TCP)
	    err = getsockopt(o->iod_get_fd(iod), IPPROTO_TCP, TCP_NODELAY,
			     (void *) &val, &len);
#if HAVE_LIBSCTP
	else if (gsi->protocol == GENSIO_NET_PROTOCOL_SCTP)
	    err = getsockopt(o->iod_get_fd(iod), IPPROTO_SCTP, SCTP_NODELAY,
			     (void *) &val, &len);
#endif
	else
	    err = 0;
	if (err)
	    return gensio_os_err_to_err(o, sock_errno);
	opensock_flags |= GENSIO_SET_OPENSOCK_NODELAY;
	if (val)
	    opensock_flags |= GENSIO_OPENSOCK_NODELAY;
    }

    if (*iopensock_flags & GENSIO_SET_OPENSOCK_REUSEADDR) {
	len = sizeof(val);
	if (getsockopt(o->iod_get_fd(iod), SOL_SOCKET, SO_REUSEADDR,
		       (void *)&val, &len) == -1)
	    return gensio_os_err_to_err(o, sock_errno);
	opensock_flags |= GENSIO_SET_OPENSOCK_REUSEADDR;
	if (val)
	    opensock_flags |= GENSIO_OPENSOCK_REUSEADDR;
    }

    *iopensock_flags = opensock_flags;
    return 0;
}

static int
gensio_stdsock_connect(struct gensio_iod *iod, const struct gensio_addr *addr)
{
    struct gensio_os_funcs *o = iod->f;
    struct addrinfo *ai;
    int err;

    if (do_errtrig())
	return GE_NOMEM;

    ai = gensio_addr_addrinfo_get_curr(addr);
    err = check_ipv6_only(ai->ai_family,
			  ai->ai_protocol,
			  ai->ai_flags,
			  o->iod_get_fd(iod));
    if (err == 0)
	err = connect(o->iod_get_fd(iod), ai->ai_addr, ai->ai_addrlen);
    if (err == -1)
	return gensio_os_err_to_err(o, sock_errno);
    return 0;
}

static int
gensio_stdsock_close_socket(struct gensio_iod *iod, bool retry, bool force)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_stdsock_info *gsi;
    int err;
#ifdef _WIN32
    bool closed;
#endif

    err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			 (intptr_t) &gsi);
    if (err)
	return err;

#ifdef _WIN32
    if (force || !gsi->connected) {
	err = close_socket(o, o->iod_get_fd(iod));
	if (!gsi->connected)
	    err = 0; /* Windows can return non-zero here, just force success. */
	goto out;
    }

    if (!retry) {
	err = shutdown(o->iod_get_fd(iod), SD_SEND);
	if (err == 0)
	    err = GE_INPROGRESS;
	else if (sock_errno == WSAENOTCONN ||
		 sock_errno == WSAECONNRESET ||
		 sock_errno == WSAECONNABORTED)
	    /* Other end has already closed. */
	    err = close_socket(o, o->iod_get_fd(iod));
	else
	    err = gensio_os_err_to_err(o, sock_errno);
	goto out;
    }

    err = o->iod_control(iod, GENSIO_IOD_CONTROL_IS_CLOSED, true,
			 (intptr_t) &closed);
    if (err)
	close_socket(o, o->iod_get_fd(iod));
    else if (closed)
	err = close_socket(o, o->iod_get_fd(iod));
    else
	err = GE_INPROGRESS;
 out:
#else
    err = close_socket(o, o->iod_get_fd(iod));
#endif
    if (err != GE_INPROGRESS && gsi)
	o->free(o, gsi);
    return err;
}

static int
gensio_stdsock_mcast_add(struct gensio_iod *iod,
			 struct gensio_addr *mcast_addrs, int iface,
			 bool curr_only)
{
    struct gensio_os_funcs *o = iod->f;
    struct addrinfo *ai;
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    if (curr_only)
	ai = gensio_addr_addrinfo_get_curr(mcast_addrs);
    else
	ai = gensio_addr_addrinfo_get(mcast_addrs);

    while (ai) {
	switch (ai->ai_addr->sa_family) {
	case AF_INET:
	    {
		struct sockaddr_in *a = (struct sockaddr_in *) ai->ai_addr;
#ifdef _WIN32
		struct ip_mreq m;
#else
		struct ip_mreqn m;
#endif

		memset(&m, 0, sizeof(m));
		m.imr_multiaddr = a->sin_addr;
#ifndef _WIN32
		m.imr_address.s_addr = INADDR_ANY;
		m.imr_ifindex = iface;
#endif
		rv = setsockopt(o->iod_get_fd(iod), IPPROTO_IP,
				IP_ADD_MEMBERSHIP,
				(void *) &m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, sock_errno);
	    }
	    break;

#ifdef AF_INET6
	case AF_INET6:
	    {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *) ai->ai_addr;
		struct ipv6_mreq m;

		m.ipv6mr_multiaddr = a->sin6_addr;
		m.ipv6mr_interface = iface;
		rv = setsockopt(o->iod_get_fd(iod), IPPROTO_IPV6,
				IPV6_ADD_MEMBERSHIP,
				(void *) &m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, sock_errno);
	    }
	    break;
#endif

	default:
	    return GE_INVAL;
	}

	if (curr_only)
	    break;
	ai = ai->ai_next;
    }

    return 0;
}

static int
gensio_stdsock_mcast_del(struct gensio_iod *iod,
			 struct gensio_addr *mcast_addrs, int iface,
			 bool curr_only)
{
    struct gensio_os_funcs *o = iod->f;
    struct addrinfo *ai;
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    if (curr_only)
	ai = gensio_addr_addrinfo_get_curr(mcast_addrs);
    else
	ai = gensio_addr_addrinfo_get(mcast_addrs);

    while (ai) {
	switch (ai->ai_addr->sa_family) {
	case AF_INET:
	    {
		struct sockaddr_in *a = (struct sockaddr_in *) ai->ai_addr;
#ifdef _WIN32
		struct ip_mreq m;
#else
		struct ip_mreqn m;
#endif

		memset(&m, 0, sizeof(m));
		m.imr_multiaddr = a->sin_addr;
#ifndef _WIN32
		m.imr_address.s_addr = INADDR_ANY;
		m.imr_ifindex = iface;
#endif
		rv = setsockopt(o->iod_get_fd(iod), IPPROTO_IP,
				IP_ADD_MEMBERSHIP,
				(void *) &m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, sock_errno);
	    }
	    break;

#ifdef AF_INET6
	case AF_INET6:
	    {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *) ai->ai_addr;
		struct ipv6_mreq m;

		m.ipv6mr_multiaddr = a->sin6_addr;
		m.ipv6mr_interface = iface;
		rv = setsockopt(o->iod_get_fd(iod), IPPROTO_IPV6,
				IPV6_ADD_MEMBERSHIP,
				(void *) &m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, sock_errno);
	    }
	    break;
#endif

	default:
	    return GE_INVAL;
	}

	if (curr_only)
	    break;
	ai = ai->ai_next;
    }

    return 0;
}

static int
gensio_stdsock_set_mcast_loop(struct gensio_iod *iod, bool ival)
{
    struct gensio_os_funcs *o = iod->f;
    int rv, val = ival;
    struct gensio_stdsock_info *gsi;

    if (do_errtrig())
	return GE_NOMEM;

    rv = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			(intptr_t) &gsi);
    if (rv)
	return rv;
    switch (gsi->family) {
    case AF_INET:
	rv = setsockopt(o->iod_get_fd(iod), IPPROTO_IP, IP_MULTICAST_LOOP,
			(void *) &val, sizeof(val));
	if (rv == -1)
	    return gensio_os_err_to_err(o, sock_errno);
	break;

#ifdef AF_INET6
    case AF_INET6:
	rv = setsockopt(o->iod_get_fd(iod), IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			(void *) &val, sizeof(val));
	if (rv == -1)
	    return gensio_os_err_to_err(o, sock_errno);
	break;
#endif

    default:
	return GE_INVAL;
    }

    return 0;
}

static int
gensio_stdsock_get_mcast_loop(struct gensio_iod *iod, bool *ival)
{
    struct gensio_os_funcs *o = iod->f;
    int rv, val;
    socklen_t size;
    struct gensio_stdsock_info *gsi;

    if (do_errtrig())
	return GE_NOMEM;

    rv = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			(intptr_t) &gsi);
    if (rv)
	return rv;
    switch (gsi->family) {
    case AF_INET:
	size = sizeof(val);
	rv = getsockopt(o->iod_get_fd(iod), IPPROTO_IP, IP_MULTICAST_LOOP,
			(void *) &val, &size);
	if (rv == -1)
	    return gensio_os_err_to_err(o, sock_errno);
	break;

#ifdef AF_INET6
    case AF_INET6:
	size = sizeof(val);
	rv = getsockopt(o->iod_get_fd(iod), IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			(void *) &val, &size);
	if (rv == -1)
	    return gensio_os_err_to_err(o, sock_errno);
	break;
#endif

    default:
	return GE_INVAL;
    }

    *ival = !!val;
    return 0;
}

static int
gensio_stdsock_getsockname(struct gensio_iod *iod, struct gensio_addr **raddr)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_addr *addr;
    struct addrinfo *ai;
    int err;
    taddrlen len;

    if (do_errtrig())
	return GE_NOMEM;

#if HAVE_LIBSCTP
    {
	struct gensio_stdsock_info *gsi;

	err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			     (intptr_t) &gsi);
	if (err)
	    return err;
	if (gsi->protocol == GENSIO_NET_PROTOCOL_SCTP)
	    return gensio_os_sctp_getladdrs(iod, raddr);
    }
#endif
    addr = gensio_addr_addrinfo_make(o, sizeof(struct sockaddr_storage),
				     false);
    if (!addr)
	return GE_NOMEM;

    ai = gensio_addr_addrinfo_get_curr(addr);
    len = ai->ai_addrlen;
    err = getsockname(o->iod_get_fd(iod), ai->ai_addr, &len);
    if (err) {
	gensio_addr_free(addr);
	return gensio_os_err_to_err(o, sock_errno);
    }

    ai->ai_family = ai->ai_addr->sa_family;
    ai->ai_addrlen = len;
    *raddr = addr;

    return 0;
}

static int
gensio_stdsock_getpeername(struct gensio_iod *iod, struct gensio_addr **raddr)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_addr *addr;
    struct addrinfo *ai;
    int err;
    taddrlen len;

    if (do_errtrig())
	return GE_NOMEM;
#if HAVE_LIBSCTP
    {
	struct gensio_stdsock_info *gsi;

	err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			     (intptr_t) &gsi);
	if (err)
	    return err;
	if (gsi->protocol == GENSIO_NET_PROTOCOL_SCTP)
	    return gensio_os_sctp_getpaddrs(iod, raddr);
    }
#endif
    addr = gensio_addr_addrinfo_make(o, sizeof(struct sockaddr_storage),
				     false);
    if (!addr)
	return GE_NOMEM;

    ai = gensio_addr_addrinfo_get_curr(addr);
    len = ai->ai_addrlen;
    err = getpeername(o->iod_get_fd(iod), ai->ai_addr, &len);
    if (err) {
	gensio_addr_free(addr);
	return gensio_os_err_to_err(o, sock_errno);
    }

    ai->ai_family = ai->ai_addr->sa_family;
    ai->ai_addrlen = len;
    *raddr = addr;

    return 0;
}

static int
gensio_stdsock_getpeerraw(struct gensio_iod *iod, void *addr, gensiods *addrlen)
{
    struct gensio_os_funcs *o = iod->f;
    int err;
    taddrlen len;

    if (do_errtrig())
	return GE_NOMEM;
#if HAVE_LIBSCTP
    {
	struct gensio_stdsock_info *gsi;

	err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			     (intptr_t) &gsi);
	if (err)
	    return err;
	if (gsi->protocol == GENSIO_NET_PROTOCOL_SCTP)
	    return gensio_os_sctp_getraddr(iod, addr, addrlen);
    }
#endif
    len = *addrlen;
    err = getpeername(o->iod_get_fd(iod), addr, &len);
    if (err)
	return gensio_os_err_to_err(o, sock_errno);
    else
	*addrlen = len;
    return 0;
}

static int
socket_get_port(struct gensio_os_funcs *o, int fd, unsigned int *port)
{
    struct sockaddr_storage sa;
    socklen_t len = sizeof(sa);
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    rv = getsockname(fd, (struct sockaddr *) &sa, &len);
    if (rv)
	return gensio_os_err_to_err(o, sock_errno);

    rv = gensio_sockaddr_get_port((struct sockaddr *) &sa, port);
    if (rv)
	return rv;

    return 0;
}

static int
gensio_stdsock_get_port(struct gensio_iod *iod, unsigned int *port)
{
    return socket_get_port(iod->f, iod->f->iod_get_fd(iod), port);
}

static int
gensio_stdsock_set_mcast_ttl(struct gensio_iod *iod, unsigned int ttl)
{
    struct gensio_os_funcs *o = iod->f;
    int rv, val = ttl;
    struct gensio_stdsock_info *gsi;

    if (do_errtrig())
	return GE_NOMEM;

    rv = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			(intptr_t) &gsi);
    if (rv)
	return rv;
    switch (gsi->family) {
    case AF_INET:
	rv = setsockopt(o->iod_get_fd(iod), IPPROTO_IP, IP_MULTICAST_TTL,
			(void *) &val, sizeof(val));
	if (rv == -1)
	    return gensio_os_err_to_err(o, sock_errno);
	break;

#ifdef AF_INET6
    case AF_INET6:
	rv = setsockopt(o->iod_get_fd(iod), IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			(void *) &val, sizeof(val));
	if (rv == -1)
	    return gensio_os_err_to_err(o, sock_errno);
	break;
#endif

    default:
	return GE_INVAL;
    }

    return 0;
}

static int
gensio_stdsock_get_mcast_ttl(struct gensio_iod *iod, unsigned int *ttl)
{
    struct gensio_os_funcs *o = iod->f;
    int rv, val;
    socklen_t size;
    struct gensio_stdsock_info *gsi;

    if (do_errtrig())
	return GE_NOMEM;

    rv = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			(intptr_t) &gsi);
    if (rv)
	return rv;
    switch (gsi->family) {
    case AF_INET:
	size = sizeof(val);
	rv = getsockopt(o->iod_get_fd(iod), IPPROTO_IP, IP_MULTICAST_TTL,
			(void *) &val, &size);
	if (rv == -1)
	    return gensio_os_err_to_err(o, sock_errno);
	break;

#ifdef AF_INET6
    case AF_INET6:
	size = sizeof(val);
	rv = getsockopt(o->iod_get_fd(iod), IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			(void *) &val, &size);
	if (rv == -1)
	    return gensio_os_err_to_err(o, sock_errno);
	break;
#endif

    default:
	return GE_INVAL;
    }

    *ttl = val;
    return 0;
}

static int
gensio_stdsock_set_extrainfo(struct gensio_iod *iod, unsigned int val)
{
#ifndef HAVE_RECVMSG
    return GE_NOTSUP;
#else
    struct gensio_os_funcs *o = iod->f;
    struct gensio_stdsock_info *gsi;
    int fd, err;

    err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			 (intptr_t) &gsi);
    if (err)
	return err;

    if (gsi->protocol != GENSIO_NET_PROTOCOL_UDP)
	return GE_INVAL;

    fd = o->iod_get_fd(iod);

    if (gsi->family == AF_UNSPEC || gsi->family == AF_INET) {
#ifdef IP_PKTINFO
	err = setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val));
	if (err)
	    return gensio_os_err_to_err(o, sock_errno);
#elif defined(IP_RECVIF) && defined(IP_RECVDSTADDR)
	err = setsockopt(fd, IPPROTO_IP, IP_RECVIF, &val, sizeof(val));
	if (err)
	    return gensio_os_err_to_err(o, sock_errno);
	err = setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &val, sizeof(val));
	if (err)
	    return gensio_os_err_to_err(o, sock_errno);
#else
	return GE_NOTSUP;
#endif
    }
#ifdef AF_INET6
    if (gsi->family == AF_UNSPEC || gsi->family == AF_INET6) {
#ifdef IPV6_RECVPKTINFO
	err = setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
			 &val, sizeof(val));
	if (err)
	    return gensio_os_err_to_err(o, sock_errno);
#else
	return GE_NOTSUP;
#endif
    }
#endif
    gsi->extrainfo = val;
    return 0;
#endif
}

static int
gensio_stdsock_get_extrainfo(struct gensio_iod *iod, unsigned int *val)
{
#ifndef HAVE_RECVMSG
    return GE_NOTSUP;
#else
    struct gensio_os_funcs *o = iod->f;
    struct gensio_stdsock_info *gsi;
    int err;

    err = o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, true,
			 (intptr_t) &gsi);
    if (err)
	return err;

    *val = gsi->extrainfo;
    return 0;
#endif
}

static int
gensio_stdsock_control(struct gensio_iod *iod, int func,
		       void *data, gensiods *datalen)
{
    switch (func) {
    case GENSIO_SOCKCTL_SET_MCAST_LOOP:
	if (*datalen != sizeof(bool))
	    return GE_INVAL;
	return gensio_stdsock_set_mcast_loop(iod, *((bool *) data));
    case GENSIO_SOCKCTL_GET_MCAST_LOOP:
	if (*datalen != sizeof(bool))
	    return GE_INVAL;
	return gensio_stdsock_get_mcast_loop(iod, ((bool *) data));
    case GENSIO_SOCKCTL_GET_SOCKNAME:
	return gensio_stdsock_getsockname(iod, data);
    case GENSIO_SOCKCTL_GET_PEERNAME:
	return gensio_stdsock_getpeername(iod, data);
    case GENSIO_SOCKCTL_GET_PEERRAW:
	return gensio_stdsock_getpeerraw(iod, data, datalen);
    case GENSIO_SOCKCTL_GET_PORT:
	if (*datalen != sizeof(unsigned int))
	    return GE_INVAL;
	return gensio_stdsock_get_port(iod, ((unsigned int *) data));
    case GENSIO_SOCKCTL_CHECK_OPEN:
	return gensio_stdsock_check_socket_open(iod);
    case GENSIO_SOCKCTL_SET_MCAST_TTL:
	if (*datalen != sizeof(unsigned int))
	    return GE_INVAL;
	return gensio_stdsock_set_mcast_ttl(iod, *((unsigned int *) data));
    case GENSIO_SOCKCTL_GET_MCAST_TTL:
	if (*datalen != sizeof(unsigned int))
	    return GE_INVAL;
	return gensio_stdsock_get_mcast_ttl(iod, ((unsigned int *) data));
    case GENSIO_SOCKCTL_SET_EXTRAINFO:
	if (*datalen != sizeof(unsigned int))
	    return GE_INVAL;
	return gensio_stdsock_set_extrainfo(iod, *((unsigned int *) data));
    case GENSIO_SOCKCTL_GET_EXTRAINFO:
	if (*datalen != sizeof(unsigned int))
	    return GE_INVAL;
	return gensio_stdsock_get_extrainfo(iod, ((unsigned int *) data));
    default:
	return GE_NOTSUP;
    }
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

static int
gensio_stdsock_open_listen_sockets(struct gensio_os_funcs *o,
		       struct gensio_addr *addr,
		       int (*call_b4_listen)(struct gensio_iod *, void *),
		       void *data, unsigned int opensock_flags,
		       struct gensio_opensocks **rfds, unsigned int *nr_fds)
{
    struct addrinfo *rp;
    int family;
    struct gensio_opensocks *fds;
    unsigned int curr_fd = 0, i;
    unsigned int max_fds = 0;
    struct addrinfo *ai;
    int rv = 0;
    struct gensio_listen_scan_info scaninfo;

    if (do_errtrig())
	return GE_NOMEM;

    ai = gensio_addr_addrinfo_get(addr);
#if HAVE_LIBSCTP
    if (ai->ai_protocol == IPPROTO_SCTP)
	return gensio_os_sctp_open_sockets(o, addr, call_b4_listen, data,
					   opensock_flags, rfds, nr_fds);
#endif
    for (rp = ai; rp != NULL; rp = rp->ai_next)
	max_fds++;

    if (max_fds == 0)
	return GE_INVAL;

    fds = o->zalloc(o, sizeof(*fds) * max_fds);
    if (!fds)
	return GE_NOMEM;

    memset(&scaninfo, 0, sizeof(scaninfo));

#if !HAVE_WORKING_PORT0
 restart_family:
#endif
#ifdef AF_INET6
    family = AF_INET6; /* Try IPV6 first, then IPV4. */
#else
    family = AF_INET;
#endif

#if defined(AF_INET6) || HAVE_UNIX
 restart:
#endif
    for (rp = ai; rp != NULL; rp = rp->ai_next) {
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

	rv = gensio_setup_listen_socket(o, rp->ai_socktype == SOCK_STREAM,
					rp->ai_family, rp->ai_socktype,
					rp->ai_protocol, rp->ai_flags,
					rp->ai_addr, rp->ai_addrlen,
					call_b4_listen, data,
					opensock_flags,
					&fds[curr_fd].iod, &fds[curr_fd].port,
					&scaninfo);
	if (rv)
	    goto out_close;
	fds[curr_fd].family = rp->ai_family;
	fds[curr_fd].flags = rp->ai_flags;
	curr_fd++;
    }
#ifdef AF_INET6
    if (family == AF_INET6) {
	family = AF_INET;
	goto restart;
    }
#endif
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
	o->clear_fd_handlers_norpt(fds[i].iod);
	o->close(&fds[i].iod);
    }
#if !HAVE_WORKING_PORT0
    if (rv == GE_ADDRINUSE && scaninfo.start != 0 &&
		scaninfo.curr != scaninfo.start) {
	/* We need to keep scanning. */
	curr_fd = 0;
	scaninfo.reqport = 0;
	goto restart_family;
    }
#endif
    o->free(o, fds);
    return rv;
}

static bool
family_is_inet(int family)
{
    if (family == AF_INET)
	return true;
#ifdef AF_INET6
    if (family == AF_INET6)
	return true;
#endif
    return false;
}

static int
gensio_setup_listen_socket(struct gensio_os_funcs *o, bool do_listen,
			   int family, int socktype, int sockproto, int flags,
			   struct sockaddr *addr, socklen_t addrlen,
			   int (*call_b4_listen)(struct gensio_iod *, void *),
			   void *data,
			   unsigned int opensock_flags,
			   struct gensio_iod **riod, unsigned int *rport,
			   struct gensio_listen_scan_info *rsi)
{
    int optval = 1;
    int fd, rv = 0;
    unsigned int port;
    struct sockaddr_storage sa;
    struct gensio_iod *iod = NULL;
    int protocol;
    struct gensio_stdsock_info *gsi = NULL;

    if (family == AF_UNIX)
	protocol = GENSIO_NET_PROTOCOL_UNIX;
    else if (sockproto == IPPROTO_SCTP)
	protocol = GENSIO_NET_PROTOCOL_SCTP;
    else if (sockproto == 0 && socktype == SOCK_DGRAM)
	protocol = GENSIO_NET_PROTOCOL_UDP;
    else if (sockproto == 0 && socktype == SOCK_STREAM)
	protocol = GENSIO_NET_PROTOCOL_TCP;
    else if (sockproto == IPPROTO_TCP)
	protocol = GENSIO_NET_PROTOCOL_TCP;
    else if (sockproto == IPPROTO_UDP)
	protocol = GENSIO_NET_PROTOCOL_UDP;
    else
	return GE_INVAL;

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

    fd = socket(family, socktype, sockproto);
    if (fd == -1)
	return gensio_os_err_to_err(o, sock_errno);

    if (opensock_flags & GENSIO_OPENSOCK_REUSEADDR) {
	switch (family) {
#if HAVE_UNIX
	case AF_UNIX: {
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
	    break;
	}
#endif
	default:
	    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			   (void *) &optval, sizeof(optval)) == -1)
		goto out_err;
	}
    }

    if (check_ipv6_only(family, sockproto, flags, fd) == -1)
	goto out_err;
#if !HAVE_WORKING_PORT0
    if (port == 0 && family_is_inet(family)) {
	struct gensio_listen_scan_info lsi;
	struct gensio_listen_scan_info *si = rsi;

	if (!si) {
	    si = &lsi;
	    memset(si, 0, sizeof(*si));
	}

	if (si->start == 0) {
	    /* Get a random port in the dynamic range. */
	    o->get_random(o, &si->start, sizeof(si->start));
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
		if (sock_errno != SOCK_EADDRINUSE)
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
    if (family_is_inet(family)) {
	rv = socket_get_port(o, fd, &port);
	if (rv)
	    goto out;
	if (rsi && rsi->reqport == 0)
	    rsi->reqport = port;
	*rport = port;
    } else {
	*rport = 0;
    }

    rv = o->add_iod(o, GENSIO_IOD_SOCKET, fd, &iod);
    if (rv)
	goto out;

    gsi = o->zalloc(o, sizeof(*gsi));
    if (!gsi) {
	rv = GE_NOMEM;
	goto out;
    }

    gsi->protocol = protocol;
    gsi->family = family;
    o->iod_control(iod, GENSIO_IOD_CONTROL_SOCKINFO, false, (intptr_t) gsi);

    rv = o->set_non_blocking(iod);
    if (rv)
	goto out;

    if (call_b4_listen) {
	rv = call_b4_listen(iod, data);
	if (rv)
	    goto out;
    }

    if (do_listen && listen(fd, 5) != 0)
	goto out_err;

 out:
    if (rv) {
	if (iod)
	    o->release_iod(iod);
	if (gsi)
	    o->free(o, gsi);
	close_socket(o, fd);
    } else {
	*riod = iod;
    }
    return rv;

 out_err:
    rv = gensio_os_err_to_err(o, sock_errno);
    goto out;
}

int
gensio_stdsock_set_os_funcs(struct gensio_os_funcs *o)
{
#ifdef _WIN32
    WSADATA wsa_data;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data))
	return GE_NOMEM;
#endif
    o->recv = gensio_stdsock_recv;
    o->send = gensio_stdsock_send;
    o->sendto = gensio_stdsock_sendto;
    o->addr_alloc_recvfrom = gensio_addr_addrinfo_alloc_recvfrom;
    o->recvfrom = gensio_stdsock_recvfrom;
    o->accept = gensio_stdsock_accept;
    o->socket_open = gensio_stdsock_socket_open;
    o->socket_set_setup = gensio_stdsock_socket_set_setup;
    o->socket_get_setup = gensio_stdsock_socket_get_setup;
    o->connect = gensio_stdsock_connect;
    o->close_socket = gensio_stdsock_close_socket;
    o->mcast_add = gensio_stdsock_mcast_add;
    o->mcast_del = gensio_stdsock_mcast_del;
    o->sock_control = gensio_stdsock_control;
    o->open_listen_sockets = gensio_stdsock_open_listen_sockets;
#if HAVE_LIBSCTP
    o->sctp_connectx = gensio_stdsock_sctp_connectx;
    o->sctp_recvmsg = gensio_stdsock_sctp_recvmsg;
    o->sctp_send = gensio_stdsock_sctp_send;
    o->sctp_socket_setup = gensio_stdsock_sctp_socket_setup;
    o->sctp_get_socket_status = gensio_stdsock_sctp_get_socket_status;
#endif
    return 0;
}

void
gensio_stdsock_cleanup(struct gensio_os_funcs *o)
{
#ifdef _WIN32
    WSACleanup();
#endif
}
