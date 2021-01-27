/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_OSOPS_H
#define GENSIO_OSOPS_H

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_os_funcs.h>

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

/*
 * Call o->open_listen_sockets() then set the I/O handlers with the
 * given data.
 */
GENSIO_DLL_PUBLIC
int gensio_os_open_listen_sockets(struct gensio_os_funcs *o,
		      struct gensio_addr *addr,
		      void (*readhndlr)(struct gensio_iod *, void *),
		      void (*writehndlr)(struct gensio_iod *, void *),
		      void (*fd_handler_cleared)(struct gensio_iod *, void *),
		      int (*call_b4_listen)(struct gensio_iod *, void *),
		      void *data, unsigned int opensock_flags,
		      struct gensio_opensocks **rfds, unsigned int *rnr_fds);

/*
 * Set the generic OS functions for the OS handler to the default ones
 * for this platform.
 */
GENSIO_DLL_PUBLIC
void gensio_osops_set_os_funcs(struct gensio_os_funcs *o);

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

#ifndef _WIN32

struct gensio_unix_termios;

GENSIO_DLL_PUBLIC
int gensio_unix_setup_termios(struct gensio_os_funcs *o, int fd,
			      struct gensio_unix_termios **t);

GENSIO_DLL_PUBLIC
void gensio_unix_cleanup_termios(struct gensio_os_funcs *o,
				 struct gensio_unix_termios **t, int fd);

GENSIO_DLL_PUBLIC
int gensio_unix_termios_control(struct gensio_os_funcs *o, int op, bool get,
				intptr_t val,
				struct gensio_unix_termios **t, int fd);

GENSIO_DLL_PUBLIC
void gensio_unix_do_flush(struct gensio_os_funcs *o, int fd, int whichbuf);

GENSIO_DLL_PUBLIC
int gensio_unix_get_bufcount(struct gensio_os_funcs *o,
			     int fd, int whichbuf, gensiods *rcount);

#endif

#endif /* GENSIO_OSOPS_H */
