/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

struct gensio_addr {
    struct gensio_os_funcs *o;
    struct addrinfo *a;
    struct addrinfo *curr;
#if HAVE_GCC_ATOMICS
    int *refcount;
#endif
    bool is_getaddrinfo; /* Allocated with getaddrinfo()? */
};

static int addrinfo_list_dup(struct gensio_os_funcs *o,
			     struct addrinfo *ai, struct addrinfo **rai,
			     struct addrinfo **rpai);

static struct gensio_addr *
gensio_addr_make(struct gensio_os_funcs *o, socklen_t size)
{
    struct gensio_addr *addr = o->zalloc(o, sizeof(*addr));
    struct addrinfo *ai = NULL;

    if (!addr)
	return NULL;

#if HAVE_GCC_ATOMICS
    addr->refcount = o->zalloc(o, sizeof(*addr->refcount));
    if (!addr->refcount) {
	o->free(o, addr);
	return NULL;
    }
    *addr->refcount = 1;
#endif

    if (size > 0) {
	ai = o->zalloc(o, sizeof(*ai));
	if (!ai) {
#if HAVE_GCC_ATOMICS
	    o->free(o, addr->refcount);
#endif
	    o->free(o, addr);
	    return NULL;
	}

	ai->ai_addr = o->zalloc(o, size);
	if (!ai->ai_addr) {
#if HAVE_GCC_ATOMICS
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
#ifdef AF_INET6
    struct sockaddr_in6 s6;
#endif
#if HAVE_UNIX
    struct sockaddr_un su;
#endif
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
#ifdef AF_INET6
	if (len != sizeof(struct in6_addr))
	    return GE_INVAL;
	memset(&s6, 0, sizeof(s6));
	s6.sin6_family = AF_INET6;
	s6.sin6_port = htons(port);
	memcpy(&s6.sin6_addr, iaddr, len);
	s = (struct sockaddr *) &s6;
	slen = sizeof(s6);
	break;
#else
	return GE_NOTSUP;
#endif

    case GENSIO_NETTYPE_UNIX:
#if HAVE_UNIX
	memset(&su, 0, sizeof(su));
	if (len > sizeof(su.sun_path) - 1)
	    return GE_TOOBIG;
	su.sun_family = AF_UNIX;
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

    a = gensio_addr_make(o, slen);
    if (!a)
	return GE_NOMEM;
    a->a->ai_family = s->sa_family;

    memcpy(a->a->ai_addr, s, slen);
    *newaddr = a;
    return 0;
}

static int
sockaddr_get_port(const struct sockaddr *s, unsigned int *port)
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

static int
sockaddr_set_port(const struct sockaddr *s, unsigned int port)
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

static bool
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
#ifdef AF_INET6
    } else if (addr->sa_family == AF_INET6) {
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) addr;
	char ibuf[INET6_ADDRSTRLEN];

	gensio_pos_snprintf(buf, buflen, pos, "%s,%s,%d",
			flags & AI_V4MAPPED ? "ipv6n4" : "ipv6",
			inet_ntop(AF_INET6, &a6->sin6_addr, ibuf, sizeof(ibuf)),
			ntohs(a6->sin6_port));
#endif
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

    addr = gensio_addr_make(o, 0);
    if (!addr) {
	o->free(o, strtok_buffer);
	return GE_NOMEM;
    }

    ip = strtok_r(strtok_buffer, ",", &strtok_data);
    while (ip) {
	int family = ifamily, rflags = 0;
	bool notype = false;

	if (strcmp(ip, "ipv4") == 0) {
	    family = AF_INET;
	    ip = strtok_r(NULL, ",", &strtok_data);
	} else if (strcmp(ip, "ipv6") == 0) {
#ifdef AF_INET6
	    family = AF_INET6;
	    ip = strtok_r(NULL, ",", &strtok_data);
#else
	    rv = GE_NOTSUP;
	    goto out_err;
#endif
	} else if (strcmp(ip, "ipv6n4") == 0) {
#ifdef AF_INET6
	    family = AF_INET6;
	    rflags |= AI_V4MAPPED;
	    ip = strtok_r(NULL, ",", &strtok_data);
#else
	    rv = GE_NOTSUP;
	    goto out_err;
#endif
	} else {
	    /* Default to V4 mapped. */
	    rflags |= AI_V4MAPPED;
	    notype = true;
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

	/*
	 * If the user specified something like "tcp,0", ip will be
	 * NULL and getaddrinfo will return IPv4 and IPv6 addresses if
	 * the are available.  AF_V4MAPPED will be set, so we really
	 * only want IPv6 addresses (if any are available) as once you
	 * open the IPv6 address you can't open the IPv4 address.
	 *
	 * To fix this, in this special case we try IPv6 addresses
	 * first, as they will be mapped and work for IPv4 addresses.
	 * If we get no network addresses in IPv4, then try IPv4.
	 */
	if (!ip && notype)
#ifdef AF_INET6
	    family = AF_INET6;
#else
	    family = AF_INET;
#endif

#ifdef AF_INET6
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
		family = AF_INET;
		goto redo_getaddrinfo;
	    }
#endif
	    rv = GE_INVAL;
	    goto out_err;
	}

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
    addr->refcount = iaddr->refcount;
    addr->a = iaddr->a;
    addr->is_getaddrinfo = iaddr->is_getaddrinfo;
    __atomic_add_fetch(addr->refcount, 1, __ATOMIC_SEQ_CST);
#else
    do {
	int rv;

	rv = addrinfo_list_dup(o, iaddr->a, &addr->a, NULL);
	if (rv) {
	    addrinfo_list_free(o, addr->a);
	    o->free(o, addr);
	    return NULL;
	}
    } while(false);
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

    addr = gensio_addr_make(o, 0);
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
    if (__atomic_sub_fetch(addr->refcount, 1, __ATOMIC_SEQ_CST) != 0) {
	o->free(o, addr);
	return;
    }
    o->free(o, addr->refcount);
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
#ifdef AF_INET6
    if (addr->curr->ai_addr->sa_family == AF_INET && family == AF_INET6 &&
		flags & AI_V4MAPPED)
	return true;
#endif
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
