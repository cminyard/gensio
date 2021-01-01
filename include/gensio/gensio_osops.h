/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_OSOPS_H
#define GENSIO_OSOPS_H

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio.h>

/* For the open_socket calls */
struct opensocks
{
    struct gensio_iod *iod;
    int family;
    unsigned int port;
    int flags;
};

/* Flags for opensock_flags. */
#define GENSIO_OPENSOCK_REUSEADDR	(1 << 0)

/* For recv and send */
#define GENSIO_MSG_OOB 1

GENSIO_DLL_PUBLIC
int gensio_os_recv(struct gensio_iod *iod, void *buf, gensiods buflen,
		   gensiods *rcount, int flags);

GENSIO_DLL_PUBLIC
int gensio_os_send(struct gensio_iod *iod, const struct gensio_sg *sg,
		   gensiods sglen, gensiods *rcount, int flags);

GENSIO_DLL_PUBLIC
int gensio_os_sendto(struct gensio_iod *iod, const struct gensio_sg *sg,
		     gensiods sglen, gensiods *rcount, int flags,
		     const struct gensio_addr *addr);

/*
 * Allocate one of these to pass to gensio_os_recvfrom()'s addr field.
 */
GENSIO_DLL_PUBLIC
struct gensio_addr *gensio_addr_alloc_recvfrom(struct gensio_os_funcs *o);

GENSIO_DLL_PUBLIC
int gensio_os_recvfrom(struct gensio_iod *iod, void *buf, gensiods buflen,
		       gensiods *rcount, int flags, struct gensio_addr *addr);

GENSIO_DLL_PUBLIC
int gensio_os_accept(struct gensio_iod *iod,
		     struct gensio_addr **addr, struct gensio_iod **newiod);

GENSIO_DLL_PUBLIC
int gensio_os_socket_get_port(struct gensio_iod *iod, unsigned int *port);

/*
 * Take a string in the form [ipv4|ipv6,][hostname,]port and convert
 * it to an addr structure.  If this returns success, the user
 * must free rai with gensio_free_addr().  If protocol is
 * non-zero, allocate for the given protocol only.  The value of
 * protocol is the same as for gensio_scan_network_port().
 */
GENSIO_DLL_PUBLIC
int gensio_os_scan_netaddr(struct gensio_os_funcs *o, const char *str,
			   bool listen, int protocol, struct gensio_addr **rai);

GENSIO_DLL_PUBLIC
int gensio_os_check_socket_open(struct gensio_iod *iod);

GENSIO_DLL_PUBLIC
int gensio_os_set_non_blocking(struct gensio_iod *iod);

GENSIO_DLL_PUBLIC
int gensio_os_socket_open(struct gensio_os_funcs *o,
			  const struct gensio_addr *addr, int protocol,
			  struct gensio_iod **iod);

GENSIO_DLL_PUBLIC
int gensio_os_socket_setup(struct gensio_iod *iod,
			   bool keepalive, bool nodelay,
			   unsigned int opensock_flags,
			   struct gensio_addr *bindaddr);

GENSIO_DLL_PUBLIC
int gensio_os_mcast_add(struct gensio_iod *iod,
			struct gensio_addr *mcast_addrs, int iface,
			bool curr_only);

GENSIO_DLL_PUBLIC
int gensio_os_mcast_del(struct gensio_iod *iod,
			struct gensio_addr *mcast_addrs, int iface,
			bool curr_only);

GENSIO_DLL_PUBLIC
int gensio_os_set_mcast_loop(struct gensio_iod *iod,
			     const struct gensio_addr *addr, bool val);

GENSIO_DLL_PUBLIC
int gensio_os_setsockopt(struct gensio_iod *iod, int level, int optname,
			 const void *optval, int optlen);

GENSIO_DLL_PUBLIC
int gensio_os_getsockopt(struct gensio_iod *iod, int level, int optname,
			 void *optval, int *optlen);

GENSIO_DLL_PUBLIC
int gensio_os_connect(struct gensio_iod *iod, const struct gensio_addr *addr);

GENSIO_DLL_PUBLIC
int gensio_os_get_nodelay(struct gensio_iod *iod, int protocol, int *val);
GENSIO_DLL_PUBLIC
int gensio_os_set_nodelay(struct gensio_iod *iod, int protocol, int val);

GENSIO_DLL_PUBLIC
int gensio_os_getsockname(struct gensio_iod *iod, struct gensio_addr **addr);

GENSIO_DLL_PUBLIC
int gensio_os_get_random(struct gensio_os_funcs *o,
			 void *data, unsigned int len);

/*
 * Open a set of sockets given the addriner list, one per address.
 * Return the actual number of sockets opened in nr_fds.  Set the
 * I/O handler to readhndlr, with the given data.
 *
 * Note that if the function is unable to open an address, it just
 * goes on.  It returns NULL if it is unable to open any addresses.
 * Also, open IPV6 addresses first.  This way, addresses in shared
 * namespaces (like IPV4 and IPV6 on INADDR6_ANY) will work properly
 */
GENSIO_DLL_PUBLIC
int gensio_os_open_socket(struct gensio_os_funcs *o,
			  struct gensio_addr *addr,
			  void (*readhndlr)(struct gensio_iod *, void *),
			  void (*writehndlr)(struct gensio_iod *, void *),
			  void (*fd_handler_cleared)(struct gensio_iod *,
						     void *),
			  int (*call_b4_listen)(struct gensio_iod *, void *),
			  void *data, unsigned int opensock_flags,
			  struct opensocks **socks, unsigned int *nr_fds);

GENSIO_DLL_PUBLIC
int gensio_os_close(struct gensio_iod **iod);

GENSIO_DLL_PUBLIC
int gensio_os_write(struct gensio_iod *iod, const struct gensio_sg *sg,
		    gensiods sglen, gensiods *rcount);

GENSIO_DLL_PUBLIC
int gensio_os_read(struct gensio_iod *iod, void *buf, gensiods buflen,
		   gensiods *rcount);

GENSIO_DLL_PUBLIC
int gensio_os_is_regfile(struct gensio_iod *iod, bool *isfile);

/*
 * Unix only APIs.
 */
GENSIO_DLL_PUBLIC
int gensio_os_setupnewprog(void);

/*
 * Returns a NULL if the fd is ok, a non-NULL error string if not.
 * Uses the default progname ("gensio", or set with
 * gensio_set_progname() if progname is NULL.
 */
GENSIO_DLL_PUBLIC
const char *gensio_os_check_tcpd_ok(struct gensio_iod *iod,
				    const char *progname);

/*
 * SCTP only APIs
 */

/* To avoid having to include netinet/sctp.h here. */
struct sctp_sndrcvinfo;

GENSIO_DLL_PUBLIC
int gensio_os_sctp_recvmsg(struct gensio_iod *iod, void *msg, gensiods len,
			   gensiods *rcount,
			   struct sctp_sndrcvinfo *sinfo, int *msg_flags);

GENSIO_DLL_PUBLIC
int gensio_os_sctp_send(struct gensio_iod *iod, const struct gensio_sg *sg,
			gensiods sglen, gensiods *rcount,
                        const struct sctp_sndrcvinfo *sinfo, uint32_t flags);

GENSIO_DLL_PUBLIC
int gensio_os_sctp_connectx(struct gensio_iod *iod, struct gensio_addr *addrs);

GENSIO_DLL_PUBLIC
int gensio_os_sctp_getpaddrs(struct gensio_iod *iod, struct gensio_addr **addr);

GENSIO_DLL_PUBLIC
int gensio_os_sctp_getladdrs(struct gensio_iod *iod, struct gensio_addr **addr);

GENSIO_DLL_PUBLIC
int gensio_os_sctp_getraddr(struct gensio_iod *iod,
			    void *addr, gensiods *addrlen);

GENSIO_DLL_PUBLIC
int gensio_os_sctp_open_socket(struct gensio_os_funcs *o,
			       struct gensio_addr *addr,
			       void (*readhndlr)(struct gensio_iod *, void *),
			       void (*writehndlr)(struct gensio_iod *, void *),
			       void (*fd_handler_cleared)(struct gensio_iod *,
							  void *),
			       int (*setup_socket)(struct gensio_iod *iod,
						   void *data),
			       void *data, unsigned int opensock_flags,
			       struct opensocks **socks, unsigned int *nr_fds);

#endif /* GENSIO_OSOPS_H */
