/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <netinet/sctp.h>

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
    struct addrinfo *ai;
    unsigned int i;
    int family = AF_INET6;
    int rv = 0;
    struct gensio_listen_scan_info scaninfo;
    struct opensocks *fds = NULL, *tfds;
    int nr_fds = 0;

    memset(&scaninfo, 0, sizeof(scaninfo));

 retry:
    for (ai = addr->a; ai; ai = ai->ai_next) {
	unsigned int port;

	if (family != ai->ai_family)
	    continue;

	rv = sockaddr_get_port(ai->ai_addr, &port);
	if (rv)
	    goto out_err;

	for (i = 0; i < nr_fds; i++) {
	    if (port == fds[i].port && (fds[i].family == family)) {
		if (sctp_bindx(fds[i].fd, ai->ai_addr, 1,
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

	rv = gensio_setup_listen_socket(o, true, ai->ai_family,
					SOCK_STREAM, IPPROTO_SCTP, ai->ai_flags,
					ai->ai_addr, ai->ai_addrlen,
					readhndlr, NULL, data,
					fd_handler_cleared,
					setup_socket, opensock_flags,
					&tfds[i].fd, &tfds[i].port, &scaninfo);
	if (rv) {
	    o->free(o, tfds);
	    goto out_err;
	}
	tfds[i].family = ai->ai_family;
	tfds[i].flags = ai->ai_flags;
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
    int ipv6_only = -1;

    for (ai = addrs->a; ai; ai = ai->ai_next) {
	unsigned int len;

	if (ai->ai_addr->sa_family == AF_INET6) {
	    len = sizeof(struct sockaddr_in6);
	    if (ai->ai_flags & AI_V4MAPPED) {
		if (ipv6_only == 1)
		    /* Can't mix IPV6-only with IPV4 mapped. */
		    return GE_INVAL;
		ipv6_only = 0;
	    } else if (ipv6_only == 0) {
		/* Can't mix IPV6-only with IPV4 mapped. */
		return GE_INVAL;
	    } else {
		ipv6_only = 1;
	    }
	} else if (ai->ai_addr->sa_family == AF_INET) {
	    len = sizeof(struct sockaddr_in);
	    if (ipv6_only == 1)
		/* Can't mix IPV6-only with IPV4. */
		return GE_INVAL;
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

    addr = gensio_addr_make(o, 0);
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
