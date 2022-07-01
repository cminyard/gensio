/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_NETIF_H
#define GENSIO_NETIF_H

/*
 * Generic ways to get to network interface information.
 */

#include <stdint.h>
#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum gensio_net_if_flags {
    GENSIO_NET_IF_UP = (1 << 0),
    GENSIO_NET_IF_LOOPBACK = (1 << 1),
    GENSIO_NET_IF_MULTICAST = (1 << 2),
};

struct gensio_net_addr
{
    unsigned int family; /* GENSIO_NETTTYPE_xxx */
    unsigned int flags;
    uint8_t netbits; /* Bits in netmask */
    uint8_t addrlen; /* Bytes in addr. */
    unsigned char addr[16];
    char *addrstr;
};

struct gensio_net_if
{
    char *name;
    enum gensio_net_if_flags flags;
    unsigned int ifindex;
    unsigned int naddrs;
    struct gensio_net_addr *addrs;
};

/*
 * Return information about the network interfaces on the system.
 */
GENSIO_DLL_PUBLIC
int gensio_os_get_net_ifs(struct gensio_os_funcs *o,
			  struct gensio_net_if ***rifs, unsigned int *rnifs);

GENSIO_DLL_PUBLIC
void gensio_os_free_net_ifs(struct gensio_os_funcs *o,
			    struct gensio_net_if **ifs, unsigned int nifs);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_NETIF_H */
