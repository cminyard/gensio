/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#define _GNU_SOURCE /* Get extended getaddrinfo errors. */
#include "config.h"
#include <stdbool.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <netioapi.h>
#else
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#endif
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if HAVE_UNIX
#include <sys/un.h>
#endif


#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_addr.h>
#include <gensio/gensio_err.h>
#include <gensio/gensio_osops_addrinfo.h>

/* For older systems that don't have this. */
#ifndef AI_V4MAPPED
#define AI_V4MAPPED 0
#endif

struct gensio_addr_addrinfo {
    struct gensio_addr r;
    struct gensio_os_funcs *o;
    struct addrinfo *a;
    struct addrinfo *curr;
#if HAVE_GCC_ATOMICS
    int *refcount;
#endif
    bool is_getaddrinfo; /* Allocated with getaddrinfo()? */
};

static struct gensio_addr_funcs addrinfo_funcs;

static void gensio_addr_addrinfo_free(struct gensio_addr *addr);

#define a_to_info(a) gensio_container_of(a, struct gensio_addr_addrinfo, r);

struct addrinfo *
gensio_addr_addrinfo_get(const struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    return addr->a;
}

struct addrinfo *
gensio_addr_addrinfo_get_curr(const struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    return addr->curr;
}

void
gensio_addr_addrinfo_set(struct gensio_addr *aaddr,
			 struct addrinfo *ai)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    assert(addr->a == NULL);
    addr->a = ai;
    addr->curr = ai;
}

static struct gensio_addr_addrinfo *
gensio_addrinfo_make(struct gensio_os_funcs *o, unsigned int size,
		     bool is_recvfrom)
{
    struct gensio_addr_addrinfo *addr = o->zalloc(o, sizeof(*addr));
    struct addrinfo *ai = NULL, *nai;

    if (!addr)
	return NULL;

#if HAVE_GCC_ATOMICS
    if (!is_recvfrom) {
	addr->refcount = o->zalloc(o, sizeof(*addr->refcount));
	if (!addr->refcount)
	    goto out_err;
	*addr->refcount = 1;
    }
#endif

    if (size > 0) {
	ai = o->zalloc(o, sizeof(*ai));
	if (!ai)
	    goto out_err;

	ai->ai_addr = o->zalloc(o, size);
	if (!ai->ai_addr)
	    goto out_err;
	ai->ai_addrlen = size;
    }
    if (is_recvfrom && ai) {
	/* Tack on two more for room for ifindex and dest addr. */
	unsigned int i;

	nai = ai;
	for (i = 0; i < 2; i++) {
	    nai->ai_next = o->zalloc(o, sizeof(*ai));
	    if (!nai->ai_next)
		goto out_err;
	    nai->ai_next->ai_addr = o->zalloc(o, size);
	    if (!nai->ai_next->ai_addr)
		goto out_err;
	    nai = nai->ai_next;
	}
    }
    addr->o = o;
    addr->r.funcs = &addrinfo_funcs;
    addr->a = ai;
    addr->curr = ai;

    return addr;
 out_err:
#if HAVE_GCC_ATOMICS
    if (addr->refcount)
	o->free(o, addr->refcount);
#endif
    while (ai) {
	nai = ai->ai_next;
	if (ai->ai_addr)
	    o->free(o, ai->ai_addr);
	o->free(o, ai);
	ai = nai;
    }
    o->free(o, addr);
    return NULL;
}

struct gensio_addr *
gensio_addr_addrinfo_make(struct gensio_os_funcs *o, unsigned int size,
			  bool is_recvfrom)
{
    struct gensio_addr_addrinfo *addr = gensio_addrinfo_make(o, size,
							     is_recvfrom);

    if (addr)
	return &addr->r;
    else
	return NULL;
}

static int
gensio_addr_addrinfo_create(struct gensio_os_funcs *o,
			    int nettype, const void *iaddr, gensiods len,
			    unsigned int port, struct gensio_addr **newaddr)
{
    struct sockaddr_in s4 = { .sin_family = AF_INET };
#ifdef AF_INET6
    struct sockaddr_in6 s6 = { .sin6_family = AF_INET6 };
#endif
#if HAVE_UNIX
    struct sockaddr_un su = { .sun_family = AF_UNIX };
#endif
    struct sockaddr *s;
    unsigned int slen;
    struct gensio_addr_addrinfo *a;

    switch (nettype) {
    case GENSIO_NETTYPE_IPV4:
	if (len != sizeof(struct in_addr))
	    return GE_INVAL;
	s4.sin_port = htons(port);
	memcpy(&s4.sin_addr, iaddr, len);
	s = (struct sockaddr *) &s4;
	slen = sizeof(s4);
	break;

    case GENSIO_NETTYPE_IPV6:
#ifdef AF_INET6
	if (len == sizeof(struct in6_addr)) {
	    memcpy(&s6.sin6_addr, iaddr, len);
	} else if (len == sizeof(s6)) {
	    /* Full sockaddr_in6, so we can get scope. */
	    const struct sockaddr_in6 *is6 = iaddr;

	    memcpy(&s6.sin6_addr, &is6->sin6_addr, sizeof(struct in6_addr));
	    s6.sin6_scope_id = is6->sin6_scope_id;
	} else {
	    return GE_INVAL;
	}
	s6.sin6_port = htons(port);
	s = (struct sockaddr *) &s6;
	slen = sizeof(s6);
	break;
#else
	return GE_NOTSUP;
#endif

    case GENSIO_NETTYPE_UNIX:
#if HAVE_UNIX
	if (len > sizeof(su.sun_path) - 1)
	    return GE_TOOBIG;
	memcpy(su.sun_path, iaddr, len);
	s = (struct sockaddr *) &su;
	slen = sizeof(su);
	break;
#else
	return GE_NOTSUP;
#endif

    default:
	return GE_INVAL;
    }

    a = gensio_addrinfo_make(o, slen, false);
    if (!a)
	return GE_NOMEM;
    a->a->ai_family = s->sa_family;

    memcpy(a->a->ai_addr, s, slen);
    *newaddr = &a->r;
    return 0;
}

int
gensio_sockaddr_get_port(const struct sockaddr *s, unsigned int *port)
{
    switch (s->sa_family) {
    case AF_INET:
	*port = ntohs(((struct sockaddr_in *) s)->sin_port);
	break;

#ifdef AF_INET6
    case AF_INET6:
	*port = ntohs(((struct sockaddr_in6 *) s)->sin6_port);
	break;
#endif

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

#ifdef AF_INET6
    case AF_INET6:
	((struct sockaddr_in6 *) s)->sin6_port = htons(port);
	break;
#endif

    default:
	return GE_INVAL;
    }

    return 0;
}

#ifdef AF_INET6
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
#endif

bool
sockaddr_equal(const struct sockaddr *a1, socklen_t l1,
	       const struct sockaddr *a2, socklen_t l2,
	       bool compare_ports)
{
    if (a1->sa_family != a2->sa_family) {
#ifdef AF_INET6
	if (a1->sa_family == AF_INET6)
	    return sockaddr_inet6_inet4_equal(a1, l1, a2, l2, compare_ports);
	else if (a2->sa_family == AF_INET6)
	    return sockaddr_inet6_inet4_equal(a2, l2, a1, l1, compare_ports);
#endif
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

#ifdef AF_INET6
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
#endif

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

static bool
gensio_addr_addrinfo_equal(const struct gensio_addr *aa1,
			   const struct gensio_addr *aa2,
			   bool compare_ports, bool compare_all)
{
    struct gensio_addr_addrinfo *a1 = a_to_info(aa1);
    struct gensio_addr_addrinfo *a2 = a_to_info(aa2);
    struct addrinfo *ai1, *ai2;

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
#ifdef AF_INET6
    } else if (addr->sa_family == AF_INET6) {
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) addr;
	char ibuf[INET6_ADDRSTRLEN];
	char ifbuf[IF_NAMESIZE + 1];

	if (IN6_IS_ADDR_LINKLOCAL(&a6->sin6_addr) &&
		if_indextoname(a6->sin6_scope_id, &(ifbuf[1])) != NULL)
	    ifbuf[0] = '%';
	else
	    ifbuf[0] = '\0';
	gensio_pos_snprintf(buf, buflen, pos, "%s,%s%s,%d",
			flags & AI_V4MAPPED ? "ipv6n4" : "ipv6",
			inet_ntop(AF_INET6, &a6->sin6_addr, ibuf, sizeof(ibuf)),
			ifbuf,
			ntohs(a6->sin6_port));
#endif
#if HAVE_UNIX
    } else if (addr->sa_family == AF_UNIX) {
	struct sockaddr_un *au = (struct sockaddr_un *) addr;

	gensio_pos_snprintf(buf, buflen, pos, "unix,%s", au->sun_path);
#endif
    } else if (addr->sa_family == GENSIO_AF_IFINDEX) {
	struct sockaddr *as = (struct sockaddr *) addr;
	unsigned int *iptr = (unsigned int *) as->sa_data;

	gensio_pos_snprintf(buf, buflen, pos, "ifidx:%u", *iptr);
    } else {
	if (*pos < buflen)
	    buf[*pos] = '\0';
	return GE_INVAL;
    }

    return 0;
}

static int
gensio_addr_addrinfo_to_str(const struct gensio_addr *aaddr,
			    char *buf, gensiods *pos, gensiods buflen)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    gensiods tmppos = 0;

    if (!pos)
	pos = &tmppos;
    return gensio_sockaddr_to_str(addr->curr->ai_addr, addr->curr->ai_flags,
				  buf, pos, buflen);
}

static int
gensio_addr_addrinfo_to_str_all(const struct gensio_addr *aaddr,
				char *buf, gensiods *pos, gensiods buflen)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    struct gensio_addr_addrinfo a = *addr;
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

	rv = gensio_addr_to_str(&a.r, buf, pos, buflen);
	if (rv)
	    return rv;
    }

    return 0;
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

    addr = gensio_addr_addrinfo_make(o, sizeof(socklen_t) + len + 1, false);
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

#ifdef _MSC_VER
/* On Windows, strtok is thread-safe. */
static char *
strtok_r(char *str, const char *delim, char **saveptr)
{
    return strtok(str, delim);
}
#endif

static void
addrinfo_item_free(struct gensio_os_funcs *o, struct addrinfo *ai)
{
    if (ai->ai_addr)
	o->free(o, ai->ai_addr);
    if (ai->ai_canonname)
	o->free(o, ai->ai_canonname);
    o->free(o, ai);
}

static void
addrinfo_list_free(struct gensio_os_funcs *o, struct addrinfo *ai)
{
    struct addrinfo *tai;

    while (ai) {
	tai = ai->ai_next;
	addrinfo_item_free(o, ai);
	ai = tai;
    }
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
    if (!aic->ai_addr)
	goto err;
    memcpy(aic->ai_addr, iai->ai_addr, iai->ai_addrlen);
    if (iai->ai_canonname) {
	aic->ai_canonname = gensio_strdup(o, iai->ai_canonname);
	if (!aic->ai_canonname)
	    goto err;
    }

    return aic;
 err:
    addrinfo_item_free(o, aic);
    return NULL;
}

/*
 * Duplicate list ai.  If rpai is set, it is a pointer to the last
 * element of another list, add the duplicated list onto the end of
 * that list.  Return the duplicated list in rai if it is set.
 */
static int
addrinfo_list_dup(struct gensio_os_funcs *o,
		  struct addrinfo *ai, struct addrinfo **rai,
		  struct addrinfo **rpai)
{
    struct addrinfo *cai, *pai = NULL, *tai = NULL;

    if (!rpai && !rai)
	return GE_INVAL;

    while (ai) {
	cai = addrinfo_dup(o, ai);
	if (!cai)
	    goto out_nomem;
	if (!tai)
	    tai = cai;
	else
	    pai->ai_next = cai;
	pai = cai;
	ai = ai->ai_next;
    }

    if (rai)
	*rai = tai;
    if (rpai) {
	if (*rpai)
	    (*rpai)->ai_next = tai;
	*rpai = pai;
    }

    return 0;
out_nomem:
    addrinfo_list_free(o, tai);
    return GE_NOMEM;
}

static int
gensio_addr_dedup(struct gensio_os_funcs *o,
		  struct gensio_addr_addrinfo **iaddr)
{
    struct gensio_addr_addrinfo *addr = *iaddr;
    struct addrinfo *ai, *ai2, *pai;

 restart:
    for (ai = addr->a; ai; ai = ai->ai_next) {
	for (ai2 = ai->ai_next, pai = ai; ai2; pai = ai2, ai2 = ai2->ai_next) {
	    if (sockaddr_equal(ai->ai_addr, ai->ai_addrlen,
			       ai2->ai_addr, ai2->ai_addrlen,
			       true)) {
		if (addr->is_getaddrinfo) {
		    int err;

		    /*
		     * To delete the dup, we need to convert it into a
		     * list not allocated by getaddrinfo so we can
		     * modify it.
		     */
		    err = addrinfo_list_dup(o, addr->a, &ai, NULL);
		    if (err)
			return err;
		    freeaddrinfo(addr->a);
		    addr->is_getaddrinfo = false;
		    addr->a = ai;
		    addr->curr = ai;
		    goto restart;
		}
		pai->ai_next = ai2->ai_next;
		addrinfo_item_free(o, ai2);
		ai2 = pai;
	    }
	}
    }

    *iaddr = addr;
    return 0;
}

static int
gensio_addr_addrinfo_scan_ips(struct gensio_os_funcs *o, const char *str,
			      bool listen, int ifamily,
			      int gprotocol, bool *is_port_set, bool scan_port,
			      struct gensio_addr **raddr)
{
    char *strtok_data, *strtok_buffer;
    struct gensio_addr_addrinfo *addr;
    struct addrinfo hints, *ai = NULL, *ai2, *pai = NULL;
    char *ip;
    char *port;
    unsigned int portnum;
    bool first = true, portset = false;
    int rv = 0, socktype, protocol;
    int bflags = AI_ADDRCONFIG;

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
	rv = gensio_scan_unixaddr(o, str, raddr);
	if (!rv && is_port_set)
	    *is_port_set = false;
	return rv;

    default:
	return GE_INVAL;
    }

    if (listen)
	bflags |= AI_PASSIVE;

    strtok_buffer = gensio_strdup(o, str);
    if (!strtok_buffer)
	return GE_NOMEM;

    addr = gensio_addrinfo_make(o, 0, false);
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
	 * they are available.  AI_V4MAPPED will be set, so we really
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
	    switch (rv) {
#ifdef EAI_INTR
	    case EAI_INTR:
		goto redo_getaddrinfo;
#endif
	    case EAI_AGAIN:
		rv = GE_RETRY;
		break;
#ifdef EAI_ADDRFAMILY
	    case EAI_ADDRFAMILY:
		rv = GE_NAME_NET_NOT_UP;
		break;
#endif
	    case EAI_BADFLAGS:
	    case EAI_FAMILY:
	    case EAI_SOCKTYPE:
		/* These mean the code here did something wrong. */
		rv = GE_NAME_INVALID;
		break;
	    case EAI_FAIL:
		rv = GE_NAME_SERVER_FAILURE;
		break;
	    case EAI_MEMORY:
		rv = GE_NOMEM;
		break;
#ifdef EAI_ADDRFAMILY
	    case EAI_NODATA:
#endif
	    case EAI_NONAME:
		rv = GE_NAME_ERROR;
		break;
#ifdef EAI_SYSTEM
	    case EAI_SYSTEM:
		rv = gensio_os_err_to_err(o, errno);
		break;
#endif
	    default:
		rv = GE_UNKNOWN_NAME_ERROR;
		break;
	    }
	    goto out_err;
	}
	gotaddr = true;

	/*
	 * If a port was/was not set, this must be consistent for all
	 * addresses.
	 */
	rv = gensio_sockaddr_get_port(ai->ai_addr, &portnum);
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

    rv = gensio_addr_dedup(o, &addr);
    if (!rv)
	*raddr = &addr->r;

 out_err:
    if (ai)
	freeaddrinfo(ai);
    if (rv)
	gensio_addr_addrinfo_free(&addr->r);
    o->free(o, strtok_buffer);

    return rv;
}

static struct gensio_addr *
gensio_addr_addrinfo_dup(const struct gensio_addr *iaaddr)
{
    struct gensio_addr_addrinfo *iaddr;
    struct gensio_os_funcs *o;
    struct gensio_addr_addrinfo *addr;

    if (!iaaddr)
	return NULL;
    iaddr = a_to_info(iaaddr);
    o = iaddr->o;
    addr = o->zalloc(o, sizeof(*addr));
    if (!addr)
	return NULL;
    addr->o = o;
    addr->r.funcs = &addrinfo_funcs;

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

    return &addr->r;
}

static struct gensio_addr *
gensio_addr_addrinfo_cat(const struct gensio_addr *aaddr1,
			 const struct gensio_addr *aaddr2)
{
    struct gensio_addr_addrinfo *addr1 = a_to_info(aaddr1);
    struct gensio_addr_addrinfo *addr2 = a_to_info(aaddr2);
    struct gensio_os_funcs *o = addr1->o;
    struct gensio_addr_addrinfo *addr;
    struct addrinfo *aip = NULL;
    int rv;

    addr = gensio_addrinfo_make(o, 0, false);
    if (!addr)
	return NULL;

    rv = addrinfo_list_dup(o, addr1->a, &addr->a, &aip);
    if (rv)
	goto out_err;

    rv = addrinfo_list_dup(o, addr2->a, NULL, &aip);
    if (rv)
	goto out_err;

    rv = gensio_addr_dedup(o, &addr);
    if (rv)
	goto out_err;

    addr->curr = addr->a;

    return &addr->r;

 out_err:
    addrinfo_list_free(o, addr->a);
    o->free(o, addr);
    return NULL;
}

static bool
gensio_addr_addrinfo_addr_present(const struct gensio_addr *agai,
				  const void *addr, gensiods addrlen,
				  bool compare_ports)
{
    struct gensio_addr_addrinfo *gai = a_to_info(agai);
    struct addrinfo *ai = gai->a;

    while (ai) {
	if (sockaddr_equal(addr, addrlen, ai->ai_addr, ai->ai_addrlen,
			   compare_ports))
	    return true;
	ai = ai->ai_next;
    }
    return false;
}

static void
gensio_addr_addrinfo_free(struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    struct gensio_os_funcs *o = addr->o;

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
gensio_addr_addrinfo_next(struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);

    if (!addr->curr->ai_next)
	return false;
    addr->curr = addr->curr->ai_next;
    return true;
}

void
gensio_addr_addrinfo_rewind(struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);

    addr->curr = addr->a;
}

static int
gensio_addr_addrinfo_get_nettype(const struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);

    return addr->curr->ai_addr->sa_family;
}

static bool
gensio_addr_addrinfo_family_supports(const struct gensio_addr *aaddr,
				     int family, int flags)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);

    if (addr->curr->ai_addr->sa_family == family)
	return true;
#ifdef AF_INET6
    if (addr->curr->ai_addr->sa_family == AF_INET && family == AF_INET6 &&
		flags & AI_V4MAPPED)
	return true;
#endif
    return false;
}

static void
gensio_addr_addrinfo_getaddr(const struct gensio_addr *aaddr,
			     void *oaddr, gensiods *rlen)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    gensiods len;

    len = *rlen;
    if (len > addr->curr->ai_addrlen)
	len = addr->curr->ai_addrlen;
    memcpy(oaddr, addr->curr->ai_addr, len);
    *rlen = addr->curr->ai_addrlen;
}

static struct gensio_addr_funcs addrinfo_funcs = {
    .addr_equal = gensio_addr_addrinfo_equal,
    .addr_to_str = gensio_addr_addrinfo_to_str,
    .addr_to_str_all = gensio_addr_addrinfo_to_str_all,
    .addr_dup = gensio_addr_addrinfo_dup,
    .addr_cat = gensio_addr_addrinfo_cat,
    .addr_addr_present = gensio_addr_addrinfo_addr_present,
    .addr_free = gensio_addr_addrinfo_free,
    .addr_next = gensio_addr_addrinfo_next,
    .addr_rewind = gensio_addr_addrinfo_rewind,
    .addr_get_nettype = gensio_addr_addrinfo_get_nettype,
    .addr_family_supports = gensio_addr_addrinfo_family_supports,
    .addr_getaddr = gensio_addr_addrinfo_getaddr
};

void
gensio_addr_addrinfo_set_os_funcs(struct gensio_os_funcs *o)
{
    o->addr_create = gensio_addr_addrinfo_create;
    o->addr_scan_ips = gensio_addr_addrinfo_scan_ips;
}
