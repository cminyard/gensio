/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_ADDR_H
#define GENSIO_ADDR_H

#include <stdint.h>
#include <gensio/gensio_types.h>

struct gensio_addr;

/*
 *
 */
struct gensio_addr_funcs {
    bool (*addr_equal)(const struct gensio_addr *a1,
		       const struct gensio_addr *a2,
		       bool compare_ports, bool compare_all);
    int (*addr_to_str)(const struct gensio_addr *addr,
		       char *buf, gensiods *pos, gensiods buflen);
    int (*addr_to_str_all)(const struct gensio_addr *addr,
			   char *buf, gensiods *pos, gensiods buflen);
    struct gensio_addr *(*addr_dup)(const struct gensio_addr *iaddr);
    struct gensio_addr *(*addr_cat)(const struct gensio_addr *addr1,
				    const struct gensio_addr *addr2);
    bool (*addr_addr_present)(const struct gensio_addr *gai,
			      const void *addr, gensiods addrlen,
			      bool compare_ports);
    void (*addr_free)(struct gensio_addr *addr);
    bool (*addr_next)(struct gensio_addr *addr);
    void (*addr_rewind)(struct gensio_addr *addr);
    int (*addr_get_nettype)(const struct gensio_addr *addr);
    bool (*addr_family_supports)(const struct gensio_addr *addr,
				 int family, int flags);
    void (*addr_getaddr)(const struct gensio_addr *addr,
			 void *oaddr, gensiods *rlen);
};

/*
 * Gensio address structure
 *
 * This is used to hide the details of address handling for network
 * gensios.  A gensio_addr has a set of addresses embedded in it.  The
 * list is immutable after allocation.
 *
 * The address has the concept of a current address in it that can be
 * iterated.  You get an address, and you can use the iterator
 * function to iterate over it and extract information from the
 * individual addresses.
 *
 * Note that some function use the current address, and some use all
 * the addresses.
 */
struct gensio_addr {
    const struct gensio_addr_funcs *funcs;
};

#endif /* GENSIO_ADDR_H */
