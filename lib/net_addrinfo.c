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
#include <afunix.h>
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

#define SIZEOF_SOCKADDR_UN_HEADER \
    (sizeof(struct sockaddr_un) - \
     sizeof(((struct sockaddr_un *) 0)->sun_path))

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_addr.h>
#include <gensio/gensio_err.h>
#include <gensio/gensio_osops_addrinfo.h>
#include <gensio/gensio_refcount.h>

/* For older systems that don't have this. */
#ifndef AI_V4MAPPED
#define AI_V4MAPPED 0
#endif

struct gensio_addr_addrinfo_list {
    unsigned int subnet_mask : 8;
    unsigned int is_getaddrinfo : 1; /* Allocated with getaddrinfo()? */
    unsigned int onlycopy : 1;
    struct addrinfo *a;
    struct addrinfo *curr;
    gensio_refcount *refcount; /* For the addrinfo above, NULL if not duped. */
    struct gensio_addr_addrinfo_list *next;
};

struct gensio_addr_addrinfo {
    struct gensio_addr r;
    struct gensio_os_funcs *o;
    struct gensio_addr_addrinfo_list a;
    struct gensio_addr_addrinfo_list *curr;
};

struct gensio_addrinfo_iter {
    struct gensio_addr_addrinfo *addr;
    struct gensio_addr_addrinfo_list *list_curr;
    struct addrinfo *a_curr;
};

static struct gensio_addr_funcs addrinfo_funcs;

static void gensio_addr_addrinfo_free(struct gensio_addr *addr);

#define a_to_info(a) gensio_container_of(a, struct gensio_addr_addrinfo, r)

static void
gensio_addrinfo_setup_iter(struct gensio_addrinfo_iter *iter,
			   struct gensio_addr_addrinfo *addr)
{
    iter->addr = addr;
    iter->list_curr = &addr->a;
    iter->a_curr = iter->list_curr->a;
}

struct gensio_addrinfo_iter *
gensio_addr_addrinfo_get_iter(const struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    struct gensio_addrinfo_iter *iter;

    iter = addr->o->zalloc(addr->o, sizeof(*iter));
    if (!iter)
	return NULL;
    gensio_addrinfo_setup_iter(iter, addr);
    return iter;
}

struct addrinfo *
gensio_addrinfo_iter_next(struct gensio_addrinfo_iter *iter)
{
    struct addrinfo *rv = iter->a_curr;

    if (!rv)
	return NULL;

    if (iter->a_curr->ai_next) {
	iter->a_curr = iter->a_curr->ai_next;
    } else if (iter->list_curr->next) {
	iter->list_curr = iter->list_curr->next;
	iter->a_curr = iter->list_curr->a;
    } else {
	iter->a_curr = NULL;
    }

    return rv;
}

void
gensio_addrinfo_iter_rewind(struct gensio_addrinfo_iter *iter)
{
    gensio_addrinfo_setup_iter(iter, iter->addr);
}

void
gensio_addrinfo_iter_free(struct gensio_addrinfo_iter *iter)
{
    struct gensio_os_funcs *o = iter->addr->o;

    o->free(o, iter);
}

struct addrinfo *
gensio_addr_addrinfo_get_curr(const struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);

    return addr->curr->curr;
}

void
gensio_addr_addrinfo_set(struct gensio_addr *aaddr,
			 struct addrinfo *ai)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);

    assert(addr->a.a == NULL);
    addr->a.a = ai;
    addr->a.curr = ai;
}

static struct gensio_addr_addrinfo *
gensio_addrinfo_make(struct gensio_os_funcs *o, unsigned int size,
		     bool is_recvfrom)
{
    struct gensio_addr_addrinfo *addr = o->zalloc(o, sizeof(*addr));
    struct addrinfo *ai = NULL, *nai;

    if (!addr)
	return NULL;

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

	/* On duplication we never share addresses for recvfrom. */
	addr->a.onlycopy = true;
    }

    addr->a.a = ai;
    addr->a.curr = ai;
    addr->o = o;
    addr->r.funcs = &addrinfo_funcs;
    addr->curr = &addr->a;

    return addr;

 out_err:
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
    struct sockaddr_un su = { .sun_family = AF_UNIX };
    struct sockaddr *s;
    unsigned int slen;
    struct gensio_addr_addrinfo *a;
    struct addrinfo *ai;

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
	if (len > sizeof(su.sun_path) - 1)
	    return GE_TOOBIG;
	memcpy(su.sun_path, iaddr, len);
	s = (struct sockaddr *) &su;
	slen = sizeof(su);
	break;

    default:
	return GE_INVAL;
    }

    a = gensio_addrinfo_make(o, slen, false);
    if (!a)
	return GE_NOMEM;
    ai = gensio_addr_addrinfo_get_curr(&a->r);
    ai->ai_family = s->sa_family;

    memcpy(ai->ai_addr, s, slen);
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

static int
gensio_addr_addrinfo_get_port(const struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    unsigned int port;
    int rv = gensio_sockaddr_get_port(addr->curr->curr->ai_addr, &port);
    if (rv)
	return -1;
    return port;
}

static void
gensio_addr_addrinfo_get_data(const struct gensio_addr *aaddr,
			      void *oaddr, gensiods *olen)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    char dummy;
    void *data;
    gensiods len, ilen = *olen;

    switch (addr->curr->curr->ai_addr->sa_family) {
    case AF_INET: {
	struct sockaddr_in *s4 = (struct sockaddr_in *) addr->curr->curr->ai_addr;
	data = &s4->sin_addr;
	len = sizeof(s4->sin_addr);
	break;
    }

    case AF_INET6: {
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) addr->curr->curr->ai_addr;
	data = &s6->sin6_addr;
	len = sizeof(s6->sin6_addr);
	break;
    }

    case AF_UNIX: {
	struct sockaddr_un *su = (struct sockaddr_un *) addr->curr->curr->ai_addr;
	data = su->sun_path;
	len = strlen(data) + 1;
	break;
    }

    default:
	data = &dummy;
	len = 0;
	break;
    }

    *olen = len;
    if (len > ilen)
	len = ilen;
    memcpy(oaddr, data, len);
}

/* Note this also converts the value to host order. */
static uint32_t
apply_32bit_mask(unsigned int subnet_mask, uint32_t value)
{
    value = ntohl(value);
    if (subnet_mask && subnet_mask < 32) {
	uint32_t mask = 0;

	mask = ~mask;
	mask <<= 32 - subnet_mask;

	value &= mask;
    }
    return value;
}

#ifdef AF_INET6
static bool
sockaddr_inet6_inet4_equal(const struct sockaddr *a1, socklen_t l1,
			   const struct sockaddr *a2, socklen_t l2,
			   bool compare_ports, unsigned int subnet_mask)
{
    struct sockaddr_in6 *s1 = (struct sockaddr_in6 *) a1;
    struct sockaddr_in *s2 = (struct sockaddr_in *) a2;
    struct in_addr addr1, addr2;

    /* a1 is an IF_NET6 address. */

    if (a2->sa_family != AF_INET)
	return false;

    if (!IN6_IS_ADDR_V4MAPPED(&s1->sin6_addr))
	return false;

    if (compare_ports && s1->sin6_port != s2->sin_port)
	return false;

    addr1.s_addr = apply_32bit_mask(subnet_mask,
				    ((const uint32_t *) &s1->sin6_addr)[3]);
    addr2.s_addr = apply_32bit_mask(subnet_mask, s2->sin_addr.s_addr);

    return addr1.s_addr == addr2.s_addr;
}

static bool
compare_128bit_mask(unsigned int subnet_mask,
		    struct in6_addr a1, struct in6_addr a2)
{
    unsigned int i, mask;

    if (subnet_mask == 0 || subnet_mask > 128)
	subnet_mask = 128;

    for (i = 0; subnet_mask >= 8; i++) {
	if (a1.s6_addr[i] != a2.s6_addr[i])
	    return false;
	subnet_mask -= 8;
    }
    if (subnet_mask > 0) {
	mask = ~0 << (8 - subnet_mask);
	if ((a1.s6_addr[i] & mask) != (a2.s6_addr[i] & mask))
	    return false;
    }
    return true;
}
#endif

bool
sockaddr_equal(const struct sockaddr *a1, socklen_t l1,
	       const struct sockaddr *a2, socklen_t l2,
	       bool compare_ports, unsigned int subnet_mask)
{
    if (a1->sa_family != a2->sa_family) {
#ifdef AF_INET6
	if (a1->sa_family == AF_INET6)
	    return sockaddr_inet6_inet4_equal(a1, l1, a2, l2, compare_ports,
					      subnet_mask);
	if (a2->sa_family == AF_INET6) {
	    if (subnet_mask) {
		/*
		 * The subnet mask is always associated with the
		 * second address.
		 * Need to convert the 128 bit ipv6 subnet mask to a
		 * 32-bit one.
		 */
		if (subnet_mask > 96)
		    subnet_mask -= 96;
		else
		    subnet_mask = 0;
	    }
	    return sockaddr_inet6_inet4_equal(a2, l2, a1, l1, compare_ports,
					      subnet_mask);
	}
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
	    if (apply_32bit_mask(subnet_mask, s1->sin_addr.s_addr)
			!= apply_32bit_mask(subnet_mask, s2->sin_addr.s_addr))
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
	    return compare_128bit_mask(subnet_mask,
				       s1->sin6_addr, s2->sin6_addr);
	}
	break;
#endif

    case AF_UNIX:
	{
	    struct sockaddr_un *s1 = (struct sockaddr_un *) a1;
	    struct sockaddr_un *s2 = (struct sockaddr_un *) a2;

	    if (strncmp(s1->sun_path, s2->sun_path,
			sizeof(s1->sun_path)) != 0)
		return false;
	}
	break;

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
    struct gensio_addrinfo_iter it1, it2;

    if (!compare_all) {
	ai1 = gensio_addr_addrinfo_get_curr(&a1->r);
	ai2 = gensio_addr_addrinfo_get_curr(&a2->r);
	return sockaddr_equal(ai1->ai_addr, ai1->ai_addrlen,
			      ai2->ai_addr, ai2->ai_addrlen,
			      compare_ports, 0);
    }

    gensio_addrinfo_setup_iter(&it1, a1);
    gensio_addrinfo_setup_iter(&it2, a2);

    ai1 = gensio_addrinfo_iter_next(&it1);
    ai2 = gensio_addrinfo_iter_next(&it2);
    while (ai1 && ai2) {
	if (!sockaddr_equal(ai1->ai_addr, ai1->ai_addrlen,
			    ai2->ai_addr, ai2->ai_addrlen,
			    compare_ports, 0))
	    return false;
	ai1 = gensio_addrinfo_iter_next(&it1);
	ai2 = gensio_addrinfo_iter_next(&it2);
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
    } else if (addr->sa_family == AF_UNIX) {
	struct sockaddr_un *au = (struct sockaddr_un *) addr;

	gensio_pos_snprintf(buf, buflen, pos, "unix,%s", au->sun_path);
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
    return gensio_sockaddr_to_str(addr->curr->curr->ai_addr,
				  addr->curr->curr->ai_flags,
				  buf, pos, buflen);
}

static int
gensio_addr_addrinfo_to_str_all(const struct gensio_addr *aaddr,
				char *buf, gensiods *pos, gensiods buflen)
{
    struct gensio_addr_addrinfo *a = a_to_info(aaddr);
    struct gensio_addrinfo_iter it;
    struct addrinfo *ai;
    bool first = true;
    int rv;
    gensiods tmppos = 0;

    if (!pos)
	pos = &tmppos;

    gensio_addrinfo_setup_iter(&it, a);
    ai = gensio_addrinfo_iter_next(&it);

    while (ai) {
	if (!first)
	    /* Add the semicolons between the addresses. */
	    gensio_pos_snprintf(buf, buflen, pos, ";");
	first = false;

	rv = gensio_sockaddr_to_str(ai->ai_addr, ai->ai_flags,
				    buf, pos, buflen);
	if (rv)
	    return rv;
	ai = gensio_addrinfo_iter_next(&it);
    }

    return 0;
}

static int
gensio_scan_unixaddr(struct gensio_os_funcs *o, int socktype, const char *str,
		     struct gensio_addr **raddr)
{
    struct sockaddr_un *saddr;
    struct gensio_addr *addr = NULL;
    struct addrinfo *ai;
    size_t len;

    len = strlen(str);
    if (len >= sizeof(saddr->sun_path) - 1)
	return GE_TOOBIG;

    addr = gensio_addr_addrinfo_make(o, SIZEOF_SOCKADDR_UN_HEADER + len + 1,
				     false);
    if (!addr)
	return GE_NOMEM;

    ai = gensio_addr_addrinfo_get_curr(addr);
    saddr = (struct sockaddr_un *) ai->ai_addr;
    saddr->sun_family = AF_UNIX;
    memcpy(saddr->sun_path, str, len);
    ai->ai_family = AF_UNIX;
    ai->ai_socktype = socktype;
    ai->ai_addrlen = SIZEOF_SOCKADDR_UN_HEADER + len + 1;
    ai->ai_addr = (struct sockaddr *) saddr;

    *raddr = addr;

    return 0;
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
addrinfo_free(struct gensio_os_funcs *o, struct addrinfo *ai)
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
	addrinfo_free(o, ai);
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
    addrinfo_free(o, aic);
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

static void
gensio_addrinfo_list_one_cleanup(struct gensio_os_funcs *o,
				 struct gensio_addr_addrinfo_list *list)
{
    int newval = 0;

    if (list->refcount)
	newval = gensio_refcount_dec(list->refcount);

    if (newval == 0) {
	/* No one else is using curr->a. */
	if (list->refcount) {
	    gensio_refcount_cleanup(list->refcount);
	    o->free(o, list->refcount);
	}
	if (list->is_getaddrinfo)
	    freeaddrinfo(list->a);
	else
	    addrinfo_list_free(o, list->a);
    }
}

static void
gensio_addrinfo_list_free(struct gensio_os_funcs *o,
			  struct gensio_addr_addrinfo_list *list)
{
    struct gensio_addr_addrinfo_list *next = list->next;

    /* Don't free the first item. */
    gensio_addrinfo_list_one_cleanup(o, list);
    while (next) {
	list = next;
	next = list->next;
	gensio_addrinfo_list_one_cleanup(o, list);
	o->free(o, list);
    }
    list->next = NULL;
    list->a = NULL;
    list->refcount = NULL;
}

/* Returns true on error, false on success. */
static bool
gensio_addrinfo_list_dup(struct gensio_os_funcs *o,
			 struct gensio_addr_addrinfo_list *olist,
			 struct gensio_addr_addrinfo_list *nlist,
			 struct gensio_addr_addrinfo_list **end)
{
    struct gensio_addr_addrinfo_list *l1, *l2, *pl = NULL;

    for (l1 = olist, l2 = nlist; l1; l1 = l1->next) {
	if (pl) {
	    l2 = o->zalloc(o, sizeof(*l2));
	    pl->next = l2;
	}
	if (l1->onlycopy) {
	    *l2 = *l1;
	    if (addrinfo_list_dup(o, l1->a, &l2->a, NULL))
		goto out_err;
	} else {
	    if (!l1->refcount) {
		l1->refcount = o->zalloc(o, sizeof(*l1->refcount));
		if (!l1->refcount)
		    goto out_err;
		if (gensio_refcount_init(o, l1->refcount, 1) != 0)
		    goto out_err;
	    }
	    *l2 = *l1;
	    gensio_refcount_inc(l2->refcount);
	}
	l2->curr = l2->a;
	l2->next = NULL;

	pl = l2;
    }

    if (end)
	*end = l2;
    return false;

 out_err:
    gensio_addrinfo_list_free(o, nlist);
    nlist->a = NULL;
    nlist->refcount = NULL;
    return true;
}

static int
gensio_addr_dedup(struct gensio_os_funcs *o,
		  struct gensio_addr_addrinfo **iaddr)
{
    struct gensio_addr_addrinfo *addr = *iaddr;
    struct addrinfo *ai, *ai2, *tai;
    struct gensio_addrinfo_iter it1, it2, pit, pit2;

 restart:
    gensio_addrinfo_setup_iter(&it1, addr);
    for (ai = gensio_addrinfo_iter_next(&it1); ai;
		ai = gensio_addrinfo_iter_next(&it1)) {
	it2 = it1;
	pit2 = it1;
	gensio_addrinfo_iter_next(&it2); /* Skip the current item. */
	for (pit = it2, ai2 = gensio_addrinfo_iter_next(&it2); ai2;
		pit2 = pit, pit = it2, ai2 = gensio_addrinfo_iter_next(&it2)) {
	    if (sockaddr_equal(ai->ai_addr, ai->ai_addrlen,
			       ai2->ai_addr, ai2->ai_addrlen,
			       true, 0)) {
		struct gensio_addr_addrinfo_list *prev = pit2.list_curr;
		struct gensio_addr_addrinfo_list *curr = pit.list_curr;

		if (curr->is_getaddrinfo) {
		    int err;

		    /*
		     * To delete the dup, we need to convert it into a
		     * list not allocated by getaddrinfo so we can
		     * modify it.
		     */
		    err = addrinfo_list_dup(o, curr->a, &tai, NULL);
		    if (err)
			return err;
		    gensio_addrinfo_list_one_cleanup(o, curr);
		    curr->refcount = NULL;
		    curr->is_getaddrinfo = false;
		    curr->a = tai;
		    curr->curr = tai;
		    goto restart;
		}

		if (ai2 == curr->a) {
		    curr->a = ai2->ai_next;
		    if (!curr->a) {
			/* No more addrinfos in curr, delete it. */
			prev->next = curr->next;
			/*
			 * You can never delete the first list item here,
			 * so no need to check for that.
			 */
			o->free(o, curr);
		    }
		} else {
		    pit.a_curr->ai_next = ai2->ai_next;
		}
		addrinfo_free(o, ai2);
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
    struct addrinfo hints, *ai = NULL, *ai2;
    struct gensio_addr_addrinfo_list *listend = NULL, *link;
    char *ip;
    char *port;
    unsigned int portnum, subnet_mask;
    bool first = true, portset = false;
    int rv = 0, socktype, protocol;
    int bflags = AI_ADDRCONFIG;
    struct sockaddr_storage iaddr;
    char *end;

    switch (gprotocol) {
    case GENSIO_NET_PROTOCOL_UNSPEC:
	socktype = 0;
	protocol = 0;
	break;

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

    case GENSIO_NET_PROTOCOL_UNIX_DGRAM:
	socktype = SOCK_DGRAM;
	goto do_unix;
#ifdef SOCK_SEQPACKET
    case GENSIO_NET_PROTOCOL_UNIX_SEQPACKET:
	socktype = SOCK_SEQPACKET;
	goto do_unix;
#endif
    case GENSIO_NET_PROTOCOL_UNIX:
	socktype = SOCK_STREAM;
    do_unix:
	rv = gensio_scan_unixaddr(o, socktype, str, raddr);
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
#endif
	subnet_mask = 0;

	/*
	 * If the host address is a valid IP address, skip the
	 * nameserver lookup and just tell getaddrinfo to convert the
	 * numeric value.
	 */
	if (ip) {
	    if (family == AF_INET || family == AF_INET6) {
		char *slash = strchr(ip, '/'), *end;

		if (slash) {
		    *slash = '\0';
		    if (*(slash + 1) == '\0') {
			rv = GE_INVAL;
			goto out_err;
		    }
		    subnet_mask = strtoul(slash + 1, &end, 10);
		    if (*end != '\0') {
			rv = GE_INVAL;
			goto out_err;
		    }
		}
	    }

	    if (family == AF_INET && inet_pton(AF_INET, ip, &iaddr) == 1) {
		if (subnet_mask > 32) {
		    rv = GE_INVAL;
		    goto out_err;
		}
		rflags |= AI_NUMERICHOST;
#ifdef AF_INET6
	    } else if (family == AF_INET6) {
		if (subnet_mask > 128) {
		    rv = GE_INVAL;
		    goto out_err;
		}
		if (inet_pton(AF_INET6, ip, &iaddr) == 1)
		    rflags |= AI_NUMERICHOST;
		else if (rflags & AI_V4MAPPED &&
			inet_pton(AF_INET, ip, &iaddr) == 1)
		    rflags |= AI_NUMERICHOST;
#endif
	    }
	}
	/*
	 * If the port string is a number, just use the number and don't
	 * do the nameserver lookup for the service.
	 */
	if (port && strtoul(port, &end, 10) < 65536 && *end == '\0')
	    rflags |= AI_NUMERICSERV;
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
		/* No IPV6, try just IPV4. */
		family = AF_INET;
		goto redo_getaddrinfo;
	    }
#endif
	    if (gotaddr)
		/* We got some address earlier, go with it. */
		goto ignore_getaddr_error;

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

	if (!listend) {
	    link = &addr->a;
	} else {
	    link = o->zalloc(o, sizeof(*link));
	    if (!link) {
		rv = GE_NOMEM;
		goto out_err;
	    }
	    listend->next = link;
	}
	link->subnet_mask = subnet_mask;
	link->a = ai;
	ai = NULL;
	link->curr = link->a;
	link->is_getaddrinfo = true;
	listend = link;

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

    if (!addr->a.a) {
	rv = GE_NOTFOUND;
	goto out_err;
    }

    addr->curr = &addr->a;

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

    if (gensio_addrinfo_list_dup(o, &iaddr->a, &addr->a, NULL)) {
	o->free(o, addr);
	return NULL;
    }
    addr->curr = &addr->a;

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
    struct gensio_addr_addrinfo_list *end, *start;
    int rv;

    addr = gensio_addrinfo_make(o, 0, false);
    if (!addr)
	return NULL;

    rv = gensio_addrinfo_list_dup(o, &addr1->a, &addr->a, &end);
    if (rv)
	goto out_err;

    start = o->zalloc(o, sizeof(*start));
    if (!start)
	goto out_err;

    rv = gensio_addrinfo_list_dup(o, &addr2->a, start, NULL);
    if (rv) {
	o->free(o, start);
	goto out_err;
    }

    end->next = start;

    rv = gensio_addr_dedup(o, &addr);
    if (rv)
	goto out_err;

    addr->curr = &addr->a;

    return &addr->r;

 out_err:
    gensio_addrinfo_list_free(o, &addr->a);
    o->free(o, addr);
    return NULL;
}

static bool
gensio_addr_addrinfo_addr_present(const struct gensio_addr *agai,
				  const void *addr, gensiods addrlen,
				  bool compare_ports)
{
    struct gensio_addr_addrinfo *gai = a_to_info(agai);
    struct gensio_addr_addrinfo_list *list;
    struct addrinfo *ai;

    for (list = &gai->a; list; list = list->next) {
	for (ai = list->a; ai; ai = ai->ai_next) {
	    if (sockaddr_equal(addr, addrlen, ai->ai_addr, ai->ai_addrlen,
			       compare_ports, list->subnet_mask))
		return true;
	}
    }
    return false;
}

static void
gensio_addr_addrinfo_free(struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);
    struct gensio_os_funcs *o = addr->o;

    gensio_addrinfo_list_free(o, &addr->a);
    o->free(o, addr);
}

bool
gensio_addr_addrinfo_next(struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);

    if (addr->curr->curr->ai_next) {
	addr->curr->curr = addr->curr->curr->ai_next;
	return true;
    }

    if (addr->curr->next) {
	addr->curr = addr->curr->next;
	addr->curr->curr = addr->curr->a;
	return true;
    }

    return false;
}

void
gensio_addr_addrinfo_rewind(struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);

    addr->curr = &addr->a;
    addr->curr->curr = addr->curr->a;
}

static int
gensio_addr_addrinfo_get_nettype(const struct gensio_addr *aaddr)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);

    switch (addr->curr->curr->ai_addr->sa_family) {
    case AF_INET: return GENSIO_NETTYPE_IPV4;
    case AF_INET6: return GENSIO_NETTYPE_IPV6;
    case AF_UNIX: return GENSIO_NETTYPE_UNIX;
    default: return GENSIO_NETTYPE_UNSPEC;
    }
}

static bool
gensio_addr_addrinfo_family_supports(const struct gensio_addr *aaddr,
				     int family, int flags)
{
    struct gensio_addr_addrinfo *addr = a_to_info(aaddr);

    if (addr->curr->curr->ai_addr->sa_family == family)
	return true;
#ifdef AF_INET6
    if (addr->curr->curr->ai_addr->sa_family == AF_INET && family == AF_INET6 &&
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
    if (len > addr->curr->curr->ai_addrlen)
	len = addr->curr->curr->ai_addrlen;
    memcpy(oaddr, addr->curr->curr->ai_addr, len);
    *rlen = addr->curr->curr->ai_addrlen;
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
    .addr_getaddr = gensio_addr_addrinfo_getaddr,
    .addr_get_port = gensio_addr_addrinfo_get_port,
    .addr_get_data = gensio_addr_addrinfo_get_data
};

void
gensio_addr_addrinfo_set_os_funcs(struct gensio_os_funcs *o)
{
    o->addr_create = gensio_addr_addrinfo_create;
    o->addr_scan_ips = gensio_addr_addrinfo_scan_ips;
}
