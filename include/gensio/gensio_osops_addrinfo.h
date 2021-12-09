/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NOTE: DO NOT USE THIS IS APPLICATION CODE!
 *
 * This is only for use if you are creating your own OS handler and
 * using addrinfo based addresses.  If you use this and the OS handler
 * doesn't use addrinfo based addresses, bad things will happen.
 */

#ifndef GENSIO_OSOPS_ADDRINFO_H
#define GENSIO_OSOPS_ADDRINFO_H

/* Avoid including net headers. */
struct addrinfo;
struct sockaddr;

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

/* Get the entire addrinfo list for the address. */
GENSIO_DLL_PUBLIC
struct addrinfo *gensio_addr_addrinfo_get(const struct gensio_addr *addr);

/* Get the current addrinfo. */
GENSIO_DLL_PUBLIC
struct addrinfo *gensio_addr_addrinfo_get_curr(const struct gensio_addr *addr);

/*
 * Create an address.  If size is zero, the addrinfo list is NULL and
 * must be set with gensio_addr_addrinfo_set().  Othersize an addrinfo
 * with an address of the given size is allocated.
 *
 * An address used for recvfrom is special, it cannot be duplicated
 * with a refcount because the addrinfo memory is reused.  So allow it
 * to be specially allocated.
 */
GENSIO_DLL_PUBLIC
struct gensio_addr *gensio_addr_addrinfo_make(struct gensio_os_funcs *o,
					      unsigned int size,
					      bool is_recvfrom);

/*
 * Set the addrinfo list.  The current list must be NULL.  All the
 * data in ai must be allocated with o->zalloc();
 */
GENSIO_DLL_PUBLIC
void gensio_addr_addrinfo_set(struct gensio_addr *addr,
			      struct addrinfo *ai);

/* Get/set the port for a sockaddr. */
GENSIO_DLL_PUBLIC
int gensio_sockaddr_get_port(const struct sockaddr *s, unsigned int *port);
GENSIO_DLL_PUBLIC
int gensio_sockaddr_set_port(const struct sockaddr *s, unsigned int port);

/* Set up the osops with addrinfo based address handling. */
GENSIO_DLL_PUBLIC
void gensio_addr_addrinfo_set_os_funcs(struct gensio_os_funcs *o);

/*
 * This is a special value for family that is used for returning the
 * ifindex from a recvfrom.
 */
#define GENSIO_AF_IFINDEX	236

#endif /* GENSIO_OSOPS_ADDRINFO_H */
