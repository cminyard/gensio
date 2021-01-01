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

/* Flags for opensock_flags. */
#define GENSIO_OPENSOCK_REUSEADDR	(1 << 0)

/* For recv and send */
#define GENSIO_MSG_OOB 1

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
int gensio_os_set_non_blocking(struct gensio_iod *iod);

GENSIO_DLL_PUBLIC
int gensio_os_get_random(struct gensio_os_funcs *o,
			 void *data, unsigned int len);

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

GENSIO_DLL_PUBLIC
int gensio_os_open_listen_sockets(struct gensio_os_funcs *o,
		      struct gensio_addr *addr,
		      void (*readhndlr)(struct gensio_iod *, void *),
		      void (*writehndlr)(struct gensio_iod *, void *),
		      void (*fd_handler_cleared)(struct gensio_iod *, void *),
		      int (*call_b4_listen)(struct gensio_iod *, void *),
		      void *data, unsigned int opensock_flags,
		      struct gensio_opensocks **rfds, unsigned int *rnr_fds);

#endif /* GENSIO_OSOPS_H */
