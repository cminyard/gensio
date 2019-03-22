/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#ifndef GENSIO_OSOPS_H
#define GENSIO_OSOPS_H

#include <sys/types.h> /* For pid_t */

/* To avoid having to include netinet/sctp.h here. */
struct sctp_sndrcvinfo;

#include <gensio/gensio.h>

int gensio_os_write(struct gensio_os_funcs *o,
		    int fd, const struct gensio_sg *sg, gensiods sglen,
		    gensiods *rcount);

int gensio_os_read(struct gensio_os_funcs *o,
		   int fd, void *buf, gensiods buflen, gensiods *rcount);

int gensio_os_recv(struct gensio_os_funcs *o,
		   int fd, void *buf, gensiods buflen, gensiods *rcount,
		   int flags);

int gensio_os_send(struct gensio_os_funcs *o,
		   int fd, const struct gensio_sg *sg, gensiods sglen,
		   gensiods *rcount, int flags);

int gensio_os_sendto(struct gensio_os_funcs *o,
		     int fd, const struct gensio_sg *sg, gensiods sglen,
		     gensiods *rcount, int flags,
		     const struct sockaddr *raddr,socklen_t raddrlen);

int gensio_os_recvfrom(struct gensio_os_funcs *o,
		       int fd, void *buf, gensiods buflen, gensiods *rcount,
		       int flags, struct sockaddr *raddr, socklen_t *raddrlen);

int gensio_os_accept(struct gensio_os_funcs *o,
		     int fd, struct sockaddr *addr, socklen_t *addrlen,
		     int *newsock);

int gensio_os_sctp_recvmsg(struct gensio_os_funcs *o,
			   int fd, void *msg, gensiods len, gensiods *rcount,
			   struct sctp_sndrcvinfo *sinfo, int *msg_flags);

int gensio_os_sctp_send(struct gensio_os_funcs *o,
			int fd, const struct gensio_sg *sg, gensiods sglen,
			gensiods *rcount,
                        const struct sctp_sndrcvinfo *sinfo, uint32_t flags);

int gensio_setupnewprog(void);

int gensio_setup_child_on_pty(struct gensio_os_funcs *o,
			      char *const argv[], const char **env,
			      int *rptym, pid_t *rpid);

int gensio_get_random(struct gensio_os_funcs *o,
		      void *data, unsigned int len);

struct opensocks
{
    int fd;
    int family;
};

/*
 * Open a set of sockets given the addrinfo list, one per address.
 * Return the actual number of sockets opened in nr_fds.  Set the
 * I/O handler to readhndlr, with the given data.
 *
 * Note that if the function is unable to open an address, it just
 * goes on.  It returns NULL if it is unable to open any addresses.
 * Also, open IPV6 addresses first.  This way, addresses in shared
 * namespaces (like IPV4 and IPV6 on INADDR6_ANY) will work properly
 */
int gensio_open_socket(struct gensio_os_funcs *o,
		       struct addrinfo *ai,
		       void (*readhndlr)(int, void *),
		       void (*writehndlr)(int, void *),
		       void (*fd_handler_cleared)(int, void *),
		       void *data,
		       struct opensocks **socks, unsigned int *nr_fds);

/*
 * Setup a receiving socket given the socket() parameters.  If do_listen
 * is true, call listen on the socket.  This sets nonblocking, reuse,
 * does a bind, etc.
 */
int gensio_setup_listen_socket(struct gensio_os_funcs *o, bool do_listen,
			       int family, int socktype, int protocol,
			       int flags,
			       struct sockaddr *addr, socklen_t addrlen,
			       void (*readhndlr)(int, void *),
			       void (*writehndlr)(int, void *), void *data,
			       void (*fd_handler_cleared)(int, void *),
			       int (*call_b4_listen)(int, void *),
			       int *rfd);

/* Returns a NULL if the fd is ok, a non-NULL error string if not */
const char *gensio_check_tcpd_ok(int new_fd);

#endif /* GENSIO_OSOPS_H */
