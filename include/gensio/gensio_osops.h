/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_OSOPS_H
#define GENSIO_OSOPS_H

/* To avoid having to include netinet/sctp.h here. */
struct sctp_sndrcvinfo;

#include <gensio/gensio.h>

/* For the open_socket calls */
struct opensocks
{
    int fd;
    int family;
    unsigned int port;
    int flags;
};

int gensio_os_write(struct gensio_os_funcs *o,
		    int fd, const struct gensio_sg *sg, gensiods sglen,
		    gensiods *rcount);

int gensio_os_read(struct gensio_os_funcs *o,
		   int fd, void *buf, gensiods buflen, gensiods *rcount);

/* For recv and send */
#define GENSIO_MSG_OOB 1

int gensio_os_recv(struct gensio_os_funcs *o,
		   int fd, void *buf, gensiods buflen, gensiods *rcount,
		   int flags);

int gensio_os_send(struct gensio_os_funcs *o,
		   int fd, const struct gensio_sg *sg, gensiods sglen,
		   gensiods *rcount, int flags);

int gensio_os_sendto(struct gensio_os_funcs *o,
		     int fd, const struct gensio_sg *sg, gensiods sglen,
		     gensiods *rcount, int flags,
		     const struct gensio_addr *addr);

int gensio_os_recvfrom(struct gensio_os_funcs *o,
		       int fd, void *buf, gensiods buflen, gensiods *rcount,
		       int flags, struct gensio_addr **addr);

int gensio_os_accept(struct gensio_os_funcs *o, int fd,
		     struct gensio_addr **addr, int *newsock);

int gensio_os_sctp_recvmsg(struct gensio_os_funcs *o,
			   int fd, void *msg, gensiods len, gensiods *rcount,
			   struct sctp_sndrcvinfo *sinfo, int *msg_flags);

int gensio_os_sctp_send(struct gensio_os_funcs *o,
			int fd, const struct gensio_sg *sg, gensiods sglen,
			gensiods *rcount,
                        const struct sctp_sndrcvinfo *sinfo, uint32_t flags);

int gensio_os_sctp_connectx(struct gensio_os_funcs *o,
			    int fd, struct gensio_addr *addrs);

int gensio_os_sctp_getpaddrs(struct gensio_os_funcs *o, int fd,
			     struct gensio_addr **addr);

int gensio_os_sctp_getladdrs(struct gensio_os_funcs *o, int fd,
			     struct gensio_addr **addr);

int gensio_os_sctp_getraddr(struct gensio_os_funcs *o, int fd,
			    void *addr, gensiods *addrlen);

int gensio_os_sctp_open_socket(struct gensio_os_funcs *o,
			       struct gensio_addr *addr,
			       void (*readhndlr)(int, void *),
			       void (*writehndlr)(int, void *),
			       void (*fd_handler_cleared)(int, void *),
			       int (*setup_socket)(int fd, void *data),
			       void *data,
			       struct opensocks **socks, unsigned int *nr_fds);


int gensio_os_close(struct gensio_os_funcs *o, int fd);

int gensio_os_check_socket_open(struct gensio_os_funcs *o, int fd);

int gensio_os_set_non_blocking(struct gensio_os_funcs *o, int fd);

int gensio_os_socket_open(struct gensio_os_funcs *o,
			  struct gensio_addr *addr, int protocol,
			  int *fd);

int gensio_os_socket_setup(struct gensio_os_funcs *o, int fd,
			   int protocol, bool keepalive, bool nodelay,
			   struct gensio_addr *bindaddr);

int gensio_os_connect(struct gensio_os_funcs *o,
		      int fd, struct gensio_addr *addr);

int gensio_os_get_nodelay(struct gensio_os_funcs *o, int fd, int protocol,
			  int *val);
int gensio_os_set_nodelay(struct gensio_os_funcs *o, int fd, int protocol,
			  int val);

int gensio_os_getsockname(struct gensio_os_funcs *o, int fd,
			  struct gensio_addr **addr);

int gensio_os_setupnewprog(void);

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
int gensio_os_open_socket(struct gensio_os_funcs *o,
			  struct gensio_addr *addr,
			  void (*readhndlr)(int, void *),
			  void (*writehndlr)(int, void *),
			  void (*fd_handler_cleared)(int, void *),
			  void *data,
			  struct opensocks **socks, unsigned int *nr_fds);

/* Returns a NULL if the fd is ok, a non-NULL error string if not */
const char *gensio_os_check_tcpd_ok(int new_fd);

#endif /* GENSIO_OSOPS_H */
