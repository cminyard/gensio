/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* MacOS doesn't have IPV6_ADD_MEMBERSHIP, but has an equivalent. */
#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif

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
			       void (*readhndlr)(struct gensio_iod *, void *),
			       void (*writehndlr)(struct gensio_iod *, void *),
			       void *data,
			       void (*fd_handler_cleared)(struct gensio_iod *,
							  void *),
			       int (*call_b4_listen)(struct gensio_iod *,
						     void *),
			       unsigned int opensock_flags,
			       struct gensio_iod **iod, unsigned int *port,
			       struct gensio_listen_scan_info *rsi);

#if HAVE_LIBSCTP
#include "gensio_osops_sctp.h"
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

int
gensio_os_recv(struct gensio_iod *iod, void *buf, gensiods buflen,
	       gensiods *rcount, int gflags)
{
    struct gensio_os_funcs *o = iod->f;
    ssize_t rv;
    int flags = (gflags & GENSIO_MSG_OOB) ? MSG_OOB : 0;

    if (do_errtrig())
	return GE_NOMEM;

 retry:
    rv = recv(iod->fd, buf, buflen, flags);
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

int
gensio_os_send(struct gensio_iod *iod,
	       const struct gensio_sg *sg, gensiods sglen,
	       gensiods *rcount, int gflags)
{
    struct gensio_os_funcs *o = iod->f;
    ssize_t rv;
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
	rv = sendmsg(iod->fd, &hdr, flags);
	ERRHANDLE();
#else
	gensiods len;
	void *buf;

	buf = gensio_sg_to_buf(sg, sglen, &len);
	if (!buf)
	    return GE_NOMEM;
    retry:
	rv = send(iod->fd, buf, len, flags);
	ERRHANDLE();
	free(buf);
#endif
    }
    return rv;
}

int
gensio_os_sendto(struct gensio_iod *iod,
		 const struct gensio_sg *sg, gensiods sglen,
		 gensiods *rcount,
		 int gflags, const struct gensio_addr *raddr)
{
    struct gensio_os_funcs *o = iod->f;
    ssize_t rv;
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
	rv = sendmsg(iod->fd, &hdr, flags);
	ERRHANDLE();
#else
	gensiods len;
	void *buf;

	buf = gensio_sg_to_buf(sg, sglen, &len);
	if (!buf)
	    return GE_NOMEM;
    retry:
	rv = sendto(iod->fd, buf, len, flags, (void *) raddr->curr->ai_addr,
		    raddr->curr->ai_addrlen);
	ERRHANDLE();
	free(buf);
#endif
    }
    return rv;
}

struct gensio_addr *
gensio_addr_alloc_recvfrom(struct gensio_os_funcs *o)
{
    return gensio_addr_addrinfo_make(o, sizeof(struct sockaddr_storage));
}

int
gensio_os_recvfrom(struct gensio_iod *iod,
		   void *buf, gensiods buflen, gensiods *rcount,
		   int flags, struct gensio_addr *addr)
{
    struct gensio_os_funcs *o = iod->f;
    ssize_t rv;
    int err = 0;
    taddrlen len;
    struct addrinfo *ai;

    if (do_errtrig())
	return GE_NOMEM;

    ai = gensio_addr_addrinfo_get_curr(addr);
 retry:
    len = sizeof(struct sockaddr_storage);
    rv = recvfrom(iod->fd, buf, buflen, flags, ai->ai_addr, &len);
    if (rv >= 0) {
	ai->ai_addrlen = len;
	ai->ai_family = ai->ai_addr->sa_family;
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
gensio_os_accept(struct gensio_iod *iod,
		 struct gensio_addr **raddr, struct gensio_iod **newiod)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_addr *addr = NULL;
    int rv, err;
    struct sockaddr *sa;
    struct sockaddr_storage sadata;
    taddrlen len;
    struct gensio_iod *riod;
    struct addrinfo *ai = NULL;

    if (do_errtrig())
	return GE_NOMEM;

    if (raddr) {
	addr = gensio_addr_addrinfo_make(o, sizeof(struct sockaddr_storage));
	if (!addr)
	    return GE_NOMEM;
	ai = gensio_addr_addrinfo_get_curr(addr);
	sa = ai->ai_addr;
	len = ai->ai_addrlen;
    } else {
	sa = (struct sockaddr *) &sadata;
	len = sizeof(sadata);
    }

    rv = accept(iod->fd, sa, &len);

    if (rv >= 0) {
	err = o->add_iod(o, GENSIO_IOD_SOCKET, rv, &riod);
	if (err) {
	    close_socket(o, rv);
	    if (addr)
		gensio_addr_free(addr);
	    return err;
	}

	riod->protocol = iod->protocol;

	if (ai) {
	    ai->ai_family = ai->ai_addr->sa_family;
	    ai->ai_addrlen = len;
	    *raddr = addr;
	}
	*newiod = riod;
	return 0;
    } else if (addr) {
	gensio_addr_free(addr);
    }
    if (errno == EAGAIN && errno == EWOULDBLOCK)
	return GE_NODATA;
    return gensio_os_err_to_err(o, errno);
}

int
gensio_os_check_socket_open(struct gensio_iod *iod)
{
    struct gensio_os_funcs *o = iod->f;
    int err, optval;
    socklen_t len = sizeof(optval);

    if (do_errtrig())
	return GE_NOMEM;

    err = getsockopt(iod->fd, SOL_SOCKET, SO_ERROR, (void *) &optval, &len);
    if (err)
	return gensio_os_err_to_err(o, errno);
    return gensio_os_err_to_err(o, optval);
}

int
gensio_os_socket_open(struct gensio_os_funcs *o,
		      const struct gensio_addr *addr, int protocol,
		      struct gensio_iod **iod)
{
    int sockproto, socktype;
    int newfd, err;
    struct addrinfo *ai;

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
	break;
#endif

    default:
	return GE_INVAL;
    }

    ai = gensio_addr_addrinfo_get(addr);
    newfd = socket(ai->ai_family, socktype, sockproto);
    if (newfd == -1)
	return gensio_os_err_to_err(o, errno);
    err = o->add_iod(o, GENSIO_IOD_SOCKET, newfd, iod);
    if (err)
	close_socket(o, newfd);
    else
	(*iod)->protocol = protocol;
    return err;
}

int
gensio_os_socket_setup(struct gensio_iod *iod,
		       bool keepalive, bool nodelay,
		       unsigned int opensock_flags,
		       struct gensio_addr *bindaddr)
{
    struct gensio_os_funcs *o = iod->f;
    int err;
    int val = 1;

    err = gensio_os_set_non_blocking(iod);
    if (err)
	return err;

    if (keepalive) {
	if (setsockopt(iod->fd, SOL_SOCKET, SO_KEEPALIVE,
		       (void *)&val, sizeof(val)) == -1)
	    return gensio_os_err_to_err(o, errno);
    }

    if (opensock_flags & GENSIO_OPENSOCK_REUSEADDR) {
	if (setsockopt(iod->fd, SOL_SOCKET, SO_REUSEADDR,
		       (void *)&val, sizeof(val)) == -1)
	    return gensio_os_err_to_err(o, errno);
    }

    if (nodelay) {
	if (iod->protocol == GENSIO_NET_PROTOCOL_TCP)
	    err = setsockopt(iod->fd, IPPROTO_TCP, TCP_NODELAY, (void *) &val,
			     sizeof(val));
#if HAVE_LIBSCTP
	else if (iod->protocol == GENSIO_NET_PROTOCOL_SCTP)
	    err = setsockopt(iod->fd, IPPROTO_SCTP, SCTP_NODELAY, (void *) &val,
			     sizeof(val));
#endif
	else
	    err = 0;
	if (err)
	    return gensio_os_err_to_err(o, errno);
    }

    if (bindaddr) {
	struct addrinfo *ai = gensio_addr_addrinfo_get(bindaddr);

	switch (iod->protocol) {
#if HAVE_LIBSCTP
	case GENSIO_NET_PROTOCOL_SCTP:
	    while (ai) {
		if (sctp_bindx(iod->fd, ai->ai_addr, 1,
			       SCTP_BINDX_ADD_ADDR) == -1)
		    return gensio_os_err_to_err(o, errno);
		ai = ai->ai_next;
	    }
	    break;
#endif

	case GENSIO_NET_PROTOCOL_TCP:
	case GENSIO_NET_PROTOCOL_UDP:
	case GENSIO_NET_PROTOCOL_UNIX:
	    if (bind(iod->fd, ai->ai_addr, ai->ai_addrlen) == -1)
		return gensio_os_err_to_err(o, errno);
	    break;

	default:
	    return GE_INVAL;
	}
    }

    return 0;
}

int
gensio_os_mcast_add(struct gensio_iod *iod,
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
		rv = setsockopt(iod->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				(void *) &m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, errno);
	    }
	    break;

#ifdef AF_INET6
	case AF_INET6:
	    {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *) ai->ai_addr;
		struct ipv6_mreq m;

		m.ipv6mr_multiaddr = a->sin6_addr;
		m.ipv6mr_interface = iface;
		rv = setsockopt(iod->fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				(void *) &m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, errno);
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

int
gensio_os_mcast_del(struct gensio_iod *iod,
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
		rv = setsockopt(iod->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
				(void *) &m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, errno);
	    }
	    break;

#ifdef AF_INET6
	case AF_INET6:
	    {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *) ai->ai_addr;
		struct ipv6_mreq m;

		m.ipv6mr_multiaddr = a->sin6_addr;
		m.ipv6mr_interface = iface;
		rv = setsockopt(iod->fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
				(void *) &m, sizeof(m));
		if (rv == -1)
		    return gensio_os_err_to_err(o, errno);
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

int
gensio_os_set_mcast_loop(struct gensio_iod *iod,
			 const struct gensio_addr *addr, bool ival)
{
    struct gensio_os_funcs *o = iod->f;
    int rv, val = ival;

    if (do_errtrig())
	return GE_NOMEM;

    switch (gensio_addr_addrinfo_get_curr(addr)->ai_addr->sa_family) {
    case AF_INET:
	rv = setsockopt(iod->fd, IPPROTO_IP, IP_MULTICAST_LOOP, (void *) &val,
			sizeof(val));
	if (rv == -1)
	    return gensio_os_err_to_err(o, errno);
	break;

#ifdef AF_INET6
    case AF_INET6:
	rv = setsockopt(iod->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			(void *) &val, sizeof(val));
	if (rv == -1)
	    return gensio_os_err_to_err(o, errno);
	break;
#endif

    default:
	return GE_INVAL;
    }

    return 0;
}

int
gensio_os_setsockopt(struct gensio_iod *iod,
		     int level, int optname,
		     const void *optval, int optlen)
{
    struct gensio_os_funcs *o = iod->f;

    if (setsockopt(iod->fd, level, optname, optval, optlen) == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_getsockopt(struct gensio_iod *iod, int level, int optname,
		     void *optval, int *optlen)
{
    struct gensio_os_funcs *o = iod->f;
    socklen_t slen = *optlen;

    if (getsockopt(iod->fd, level, optname, optval, &slen) == -1)
	return gensio_os_err_to_err(o, errno);
    *optlen = slen;
    return 0;
}

int
gensio_os_connect(struct gensio_iod *iod, const struct gensio_addr *addr)
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
			  iod->fd);
    if (err == 0)
	err = connect(iod->fd, ai->ai_addr, ai->ai_addrlen);
    if (err == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_get_nodelay(struct gensio_iod *iod, int protocol, int *val)
{
    struct gensio_os_funcs *o = iod->f;
    socklen_t vallen = sizeof(*val);
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    if (protocol == GENSIO_NET_PROTOCOL_TCP)
	rv = getsockopt(iod->fd, IPPROTO_TCP, TCP_NODELAY, (void *) val,
			&vallen);
#if HAVE_LIBSCTP
    else if (protocol == GENSIO_NET_PROTOCOL_SCTP)
	rv = getsockopt(iod->fd, IPPROTO_SCTP, SCTP_NODELAY, &val, &vallen);
#endif
    else
	return GE_INVAL;

    if (rv == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_set_nodelay(struct gensio_iod *iod, int protocol, int val)
{
    struct gensio_os_funcs *o = iod->f;
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    if (protocol == GENSIO_NET_PROTOCOL_TCP)
	rv = setsockopt(iod->fd, IPPROTO_TCP, TCP_NODELAY,
			(void *) &val, sizeof(val));
#if HAVE_LIBSCTP
    else if (protocol == GENSIO_NET_PROTOCOL_SCTP)
	rv = setsockopt(iod->fd, IPPROTO_SCTP, SCTP_NODELAY,
			(void *) &val, sizeof(val));
#endif
    else
	return GE_INVAL;

    if (rv == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_getsockname(struct gensio_iod *iod, struct gensio_addr **raddr)
{
    struct gensio_os_funcs *o = iod->f;
    struct gensio_addr *addr;
    struct addrinfo *ai;
    int err;
    taddrlen len;

    if (do_errtrig())
	return GE_NOMEM;

    addr = gensio_addr_addrinfo_make(o, sizeof(struct sockaddr_storage));
    if (!addr)
	return GE_NOMEM;

    ai = gensio_addr_addrinfo_get_curr(addr);
    len = ai->ai_addrlen;
    err = getsockname(iod->fd, ai->ai_addr, &len);
    if (err) {
	gensio_addr_free(addr);
	return gensio_os_err_to_err(o, errno);
    }

    ai->ai_family = ai->ai_addr->sa_family;
    ai->ai_addrlen = len;
    *raddr = addr;

    return 0;
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
		      struct gensio_addr *addr,
		      void (*readhndlr)(struct gensio_iod *, void *),
		      void (*writehndlr)(struct gensio_iod *, void *),
		      void (*fd_handler_cleared)(struct gensio_iod *, void *),
		      int (*call_b4_listen)(struct gensio_iod *, void *),
		      void *data, unsigned int opensock_flags,
		      struct opensocks **rfds, unsigned int *nr_fds)
{
    struct addrinfo *rp;
    int family;
    struct opensocks *fds;
    unsigned int curr_fd = 0, i;
    unsigned int max_fds = 0;
    struct addrinfo *ai;
    int rv = 0;
    struct gensio_listen_scan_info scaninfo;

    if (do_errtrig())
	return GE_NOMEM;

    ai = gensio_addr_addrinfo_get(addr);

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

	rv = gensio_setup_listen_socket(o, rp->ai_socktype == SOCK_STREAM,
					rp->ai_family, rp->ai_socktype,
					rp->ai_protocol, rp->ai_flags,
					rp->ai_addr, rp->ai_addrlen,
					readhndlr, writehndlr, data,
					fd_handler_cleared, call_b4_listen,
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
	gensio_os_close(&fds[i].iod);
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
	return gensio_os_err_to_err(o, errno);

    rv = gensio_sockaddr_get_port((struct sockaddr *) &sa, port);
    if (rv)
	return rv;

    return 0;
}

int
gensio_os_socket_get_port(struct gensio_iod *iod, unsigned int *port)
{
    return socket_get_port(iod->f, iod->fd, port);
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
			   void (*readhndlr)(struct gensio_iod *, void *),
			   void (*writehndlr)(struct gensio_iod *, void *),
			   void *data,
			   void (*fd_handler_cleared)(struct gensio_iod *,
						      void *),
			   int (*call_b4_listen)(struct gensio_iod *, void *),
			   unsigned int opensock_flags,
			   struct gensio_iod **riod, unsigned int *rport,
			   struct gensio_listen_scan_info *rsi)
{
    int optval = 1;
    int fd, rv = 0;
    unsigned int port;
    struct sockaddr_storage sa;
    struct gensio_iod *iod;
    int protocol;

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
	return gensio_os_err_to_err(o, errno);

    rv = set_non_blocking(o, fd);
    if (rv)
	goto out_err_noconv;

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

    iod->protocol = protocol;

    if (call_b4_listen) {
	rv = call_b4_listen(iod, data);
	if (rv)
	    goto out;
    }

    if (do_listen && listen(fd, 5) != 0)
	goto out_err;

    rv = o->set_fd_handlers(iod, data,
			    readhndlr, writehndlr, NULL,
			    fd_handler_cleared);
 out:
    if (rv) {
	if (iod)
	    o->release_iod(iod);
	close_socket(o, fd);
    } else {
	*riod = iod;
    }
    return rv;

 out_err:
    rv = gensio_os_err_to_err(o, errno);
 out_err_noconv:
    goto out;
}

static int
gensio_scan_unixaddr(struct gensio_os_funcs *o, const char *str,
		     struct gensio_addr **raddr)
{
#if HAVE_UNIX
    struct sockaddr_un *saddr;
    struct gensio_addr *addr = NULL;
    struct addrinfo *ai;
    size_t len;

    len = strlen(str);
    if (len >= sizeof(saddr->sun_path) - 1)
	return GE_TOOBIG;

    addr = gensio_addr_addrinfo_make(o, sizeof(socklen_t) + len + 1);
    if (!addr)
	return GE_NOMEM;

    ai = gensio_addr_addrinfo_get(addr);
    saddr = (struct sockaddr_un *) ai->ai_addr;
    saddr->sun_family = AF_UNIX;
    memcpy(saddr->sun_path, str, len);
    ai->ai_family = AF_UNIX;
    ai->ai_socktype = SOCK_STREAM;
    ai->ai_addrlen = sizeof(socklen_t) + len + 1;
    ai->ai_addr = (struct sockaddr *) saddr;

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
#ifdef AF_INET6
	family = AF_INET6;
	str += 5;
#else
	return GE_NOTSUP;
#endif
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

    err = gensio_addr_addrinfo_scan_ips(o, str, listen, family, socktype,
					protocol, is_port_set, true, raddr);
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

    return gensio_addr_addrinfo_scan_ips(o, str, false, 0, 0, protocol, NULL,
					 false, raddr);
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

    rv = gensio_addr_addrinfo_scan_ips(o, str, listen, AF_UNSPEC, socktype,
				       protocol, &is_port_set, true, &addr);
    if (!rv && !listen && !is_port_set) {
	gensio_addr_free(addr);
	rv = GE_INVAL;
    } else if (!rv) {
	*raddr = addr;
    }
    return rv;
}
