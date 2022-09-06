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
#include <gensio/gensioosh_dllvisibility.h>

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

/*
 * These are the low-level network protocol that gensio support.  Used
 * mostly in interacting with addresses, anything named protocol.
 * zero is reserved.
 */
#define GENSIO_NET_PROTOCOL_TCP 1
#define GENSIO_NET_PROTOCOL_UDP 2
#define GENSIO_NET_PROTOCOL_SCTP 3
#define GENSIO_NET_PROTOCOL_UNIX 4

/*
 * Dealing with iterators.
 */
GENSIOOSH_DLL_PUBLIC
void gensio_addr_rewind(struct gensio_addr *addr);
/* Return false if no more addresses exist. */
GENSIOOSH_DLL_PUBLIC
bool gensio_addr_next(struct gensio_addr *addr);
/*
 * Gets the current address.  len must be provided, it is the size of
 * the buffer and is updated to the actual size (which may be larger
 * than len).  The copy may be partial if len is not enough.
 */
GENSIOOSH_DLL_PUBLIC
void gensio_addr_getaddr(const struct gensio_addr *addr,
			 void *oaddr, gensiods *len);

#define GENSIO_NETTYPE_UNSPEC	0
#define GENSIO_NETTYPE_IPV4	1
#define GENSIO_NETTYPE_IPV6	2
#define GENSIO_NETTYPE_UNIX	3
#define GENSIO_NETTYPE_AX25	4

/*
 * Create a gensio address from raw address data.  Note that the iaddr
 * data is type in_addr for ipv4, in6_addr for ipv6, and the path for
 * unix.  ipv6 also takes a sockaddr_in6 (it can tell by the length)
 * and it will pull the address and scope id from that.  That way you
 * can set the scope id.
 */
GENSIOOSH_DLL_PUBLIC
int gensio_addr_create(struct gensio_os_funcs *o,
		       int nettype, const void *iaddr, gensiods len,
		       unsigned int port, struct gensio_addr **newaddr);

/*
 * Return the network type (ipv4, ipv6, unix socket, etc.) for the
 * current address.
 */
GENSIOOSH_DLL_PUBLIC
int gensio_addr_get_nettype(const struct gensio_addr *addr);

/*
 * If the address can be supported by a socket with the given
 * family/flags combo, return true.  This will return true if the
 * families match or if address ipv4, family is IPv6, and flags has
 * AI_V4MAPPED.
 */
GENSIOOSH_DLL_PUBLIC
bool gensio_addr_family_supports(const struct gensio_addr *addr, int family,
				 int flags);

/*
 * A routine for converting a current address to a string representation
 *
 * The output is put into buf starting at *epos (or zero if epos is NULL)
 * and will fill in buf up to buf + buflen.  If the buffer is not large
 * enough, it is truncated, but if epos is not NULL, it will be set to the
 * byte position where the ending NIL character would have been, one less
 * than the buflen that would have been required to hold the entire buffer.
 */
GENSIOOSH_DLL_PUBLIC
int gensio_addr_to_str(const struct gensio_addr *addr,
		       char *buf, gensiods *epos, gensiods buflen);

/*
 * Like the above, but does all the addresses, not just the current
 * one, separated by ';'.
 */
GENSIOOSH_DLL_PUBLIC
int gensio_addr_to_str_all(const struct gensio_addr *addr,
			   char *buf, gensiods *epos, gensiods buflen);

/*
 * Compare two addresses and return TRUE if they are equal and FALSE
 * if not.  If compare_ports is false, then the port comparison is
 * ignored.
 *
 * If compare_all is true, verify that all the addresses are the same.
 * If it is false, only compare the current address.
 */
GENSIOOSH_DLL_PUBLIC
bool gensio_addr_equal(const struct gensio_addr *a1,
		       const struct gensio_addr *a2,
		       bool compare_ports, bool compare_all);

/*
 * Create a new address structure with the same addresses.
 */
GENSIOOSH_DLL_PUBLIC
struct gensio_addr *gensio_addr_dup(const struct gensio_addr *ai);

/*
 * Concatenate two addr structures and return a new one.
 */
GENSIOOSH_DLL_PUBLIC
struct gensio_addr *gensio_addr_cat(const struct gensio_addr *ai1,
				    const struct gensio_addr *ai2);

/*
 * Decrement the refcount on the structure and free if not in use.
 */
GENSIOOSH_DLL_PUBLIC
void gensio_addr_free(struct gensio_addr *ai);

/*
 * See if addr is present in ai.  Ports are not compared unless
 * compare_ports is true.
 */
GENSIOOSH_DLL_PUBLIC
bool gensio_addr_addr_present(const struct gensio_addr *ai,
			      const void *addr, gensiods addrlen,
			      bool compare_ports);

#endif /* GENSIO_ADDR_H */
