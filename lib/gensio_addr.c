/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_addr.h>

int
gensio_addr_create(struct gensio_os_funcs *o,
		   int nettype, const void *iaddr, gensiods len,
		   unsigned int port, struct gensio_addr **newaddr)
{
    return o->addr_create(o, nettype, iaddr, len, port, newaddr);
}

bool
gensio_addr_equal(const struct gensio_addr *a1,
		  const struct gensio_addr *a2,
		  bool compare_ports, bool compare_all)
{
    if (a1->funcs != a2->funcs)
	return false;
    return a1->funcs->addr_equal(a1, a2, compare_ports, compare_all);
}

int
gensio_addr_to_str(const struct gensio_addr *addr,
		   char *buf, gensiods *pos, gensiods buflen)
{
    gensiods dummypos = 0;

    if (!pos)
	pos = &dummypos;
    return addr->funcs->addr_to_str(addr, buf, pos, buflen);
}

int
gensio_addr_to_str_all(const struct gensio_addr *addr,
		       char *buf, gensiods *pos, gensiods buflen)
{
    return addr->funcs->addr_to_str_all(addr, buf, pos, buflen);
}

struct gensio_addr *
gensio_addr_dup(const struct gensio_addr *iaddr)
{
    return iaddr->funcs->addr_dup(iaddr);
}

struct gensio_addr *
gensio_addr_cat(const struct gensio_addr *addr1,
		const struct gensio_addr *addr2)
{
    if (addr1->funcs != addr2->funcs)
	return NULL;
    return addr1->funcs->addr_cat(addr1, addr2);
}

bool
gensio_addr_addr_present(const struct gensio_addr *gai,
			 const void *addr, gensiods addrlen,
			 bool compare_ports)
{
    return gai->funcs->addr_addr_present(gai, addr, addrlen, compare_ports);
}

void
gensio_addr_free(struct gensio_addr *addr)
{
    addr->funcs->addr_free(addr);
}

bool
gensio_addr_next(struct gensio_addr *addr)
{
    return addr->funcs->addr_next(addr);
}

void
gensio_addr_rewind(struct gensio_addr *addr)
{
    addr->funcs->addr_rewind(addr);
}

int
gensio_addr_get_nettype(const struct gensio_addr *addr)
{
    return addr->funcs->addr_get_nettype(addr);
}

bool
gensio_addr_family_supports(const struct gensio_addr *addr,
			    int family, int flags)
{
    return addr->funcs->addr_family_supports(addr, family, flags);
}

void
gensio_addr_getaddr(const struct gensio_addr *addr,
		    void *oaddr, gensiods *rlen)
{
    addr->funcs->addr_getaddr(addr, oaddr, rlen);
}
