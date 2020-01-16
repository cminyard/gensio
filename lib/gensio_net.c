/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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

/* This code handles TCP and Unix network I/O. */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_osops.h>

struct net_data {
    struct gensio_os_funcs *o;

    struct gensio_ll *ll;

    struct sockaddr_storage remote;	/* The socket address of who
					   is connected to this port. */
    struct sockaddr *raddr;		/* Points to remote, for convenience. */
    socklen_t raddrlen;

    struct addrinfo *ai;
    struct addrinfo *lai; /* Local address, NULL if not set. */
    struct addrinfo *curr_ai;

    bool nodelay;

    bool istcp;

    int last_err;
};

static int net_check_open(void *handler_data, int fd)
{
    struct net_data *tdata = handler_data;
    int optval = 0, err;
    socklen_t len = sizeof(optval);

    err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &len);
    if (err) {
	tdata->last_err = gensio_os_err_to_err(tdata->o, errno);
	return tdata->last_err;
    }
    optval = gensio_os_err_to_err(tdata->o, optval);
    tdata->last_err = optval;
    if (!optval) {
	struct addrinfo *ai = tdata->curr_ai;

	memcpy(tdata->raddr, ai->ai_addr, ai->ai_addrlen);
	tdata->raddrlen = ai->ai_addrlen;
    }
    return optval;
}

static int
net_socket_setup(struct net_data *tdata, int fd)
{
    int optval = 1;

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
	return errno;

    if (tdata->istcp && setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		   (void *)&optval, sizeof(optval)) == -1)
	return errno;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		   (void *)&optval, sizeof(optval)) == -1)
	return errno;

    if (tdata->istcp && tdata->nodelay) {
	int val = 1;

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) == -1)
	    return errno;
    }

    if (tdata->lai) {
	if (bind(fd, tdata->lai->ai_addr, tdata->lai->ai_addrlen) == -1)
	    return errno;
    }

    return 0;
}

static int
net_try_open(struct net_data *tdata, int *fd)
{
    int new_fd, err = EBUSY;
    struct addrinfo *ai = tdata->curr_ai;

    new_fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (new_fd == -1) {
	err = errno;
	goto out;
    }

    err = net_socket_setup(tdata, new_fd);
    if (err)
	goto out;

 retry:
    err = connect(new_fd, ai->ai_addr, ai->ai_addrlen);
    if (err == -1) {
	err = errno;
	if (err == EINPROGRESS) {
	    tdata->curr_ai = ai;
	    *fd = new_fd;
	    goto out_return;
	}
    } else {
	err = 0;
    }

    if (err) {
	ai = ai->ai_next;
	if (ai)
	    goto retry;
    } else {
	memcpy(tdata->raddr, ai->ai_addr, ai->ai_addrlen);
	tdata->raddrlen = ai->ai_addrlen;
    }
 out:
    if (err) {
	if (new_fd != -1)
	    close(new_fd);
    } else {
	*fd = new_fd;
    }

 out_return:
    return gensio_os_err_to_err(tdata->o, err);
}

static int
net_retry_open(void *handler_data, int *fd)
{
    struct net_data *tdata = handler_data;

    if (tdata->curr_ai)
	tdata->curr_ai = tdata->curr_ai->ai_next;
    if (!tdata->curr_ai)
	return tdata->last_err;
    return net_try_open(tdata, fd);
}

static int
net_sub_open(void *handler_data, int *fd)
{
    struct net_data *tdata = handler_data;

    tdata->curr_ai = tdata->ai;
    return net_try_open(tdata, fd);
}

static int
net_raddr_to_str(void *handler_data, gensiods *epos,
		 char *buf, gensiods buflen)
{
    struct net_data *tdata = handler_data;
    socklen_t addrlen = tdata->raddrlen;

    return gensio_sockaddr_to_str(tdata->raddr, &addrlen, buf, epos, buflen);
}

static int
net_get_raddr(void *handler_data, void *addr, gensiods *addrlen)
{
    struct net_data *tdata = handler_data;

    if (*addrlen > tdata->raddrlen)
	*addrlen = tdata->raddrlen;

    memcpy(addr, tdata->raddr, *addrlen);
    return 0;
}

static void
net_free(void *handler_data)
{
    struct net_data *tdata = handler_data;

    if (tdata->ai)
	gensio_free_addrinfo(tdata->o, tdata->ai);
    if (tdata->lai)
	gensio_free_addrinfo(tdata->o, tdata->lai);
    tdata->o->free(tdata->o, tdata);
}

static int
net_control(void *handler_data, int fd, bool get, unsigned int option,
	    char *data, gensiods *datalen)
{
    struct net_data *tdata = handler_data;
    int rv, val;

    switch (option) {
    case GENSIO_CONTROL_NODELAY:
	if (!tdata->istcp)
	    return GE_NOTSUP;
	if (get) {
	    if (fd != -1) {
		socklen_t vallen = sizeof(val);

		rv = getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, &vallen);
		if (rv == -1)
		    return errno;
	    } else {
		val = tdata->nodelay;
	    }
	    *datalen = snprintf(data, *datalen, "%d", val);
	} else {
	    val = strtoul(data, NULL, 0);
	    tdata->nodelay = val;
	    if (fd != -1) {
		rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
		if (rv == -1)
		    return errno;
	    }
	}
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
net_oob_read(int fd, void *data, gensiods count, gensiods *rcount,
	     const char **auxdata, void *cb_data)
{
    struct net_data *tdata = cb_data;
    int rv;

    rv = gensio_os_recv(tdata->o, fd, data, count, rcount, MSG_OOB);
    if (rv)
	*rcount = 0;
    return 0;
}

static void
net_except_ready(void *handler_data, int fd)
{
    struct net_data *tdata = handler_data;
    static const char *argv[3] = { "oob", "oobtcp", NULL };

    gensio_fd_ll_handle_incoming(tdata->ll, net_oob_read, argv, tdata);
}

static int
net_write(void *handler_data, int fd, gensiods *rcount,
	  const struct gensio_sg *sg, gensiods sglen,
	  const char *const *auxdata)
{
    struct net_data *tdata = handler_data;
    int flags = 0;

    if (auxdata) {
	int i;

	for (i = 0; auxdata[i]; i++) {
	    if (strcasecmp(auxdata[i], "oob") == 0)
		flags |= MSG_OOB;
	    else if (strcasecmp(auxdata[i], "oobtcp") == 0)
		flags |= MSG_OOB;
	    else
		return GE_INVAL;
	}
    }

    return gensio_os_send(tdata->o, fd, sg, sglen, rcount, flags);
}

static const struct gensio_fd_ll_ops net_fd_ll_ops = {
    .sub_open = net_sub_open,
    .check_open = net_check_open,
    .retry_open = net_retry_open,
    .raddr_to_str = net_raddr_to_str,
    .get_raddr = net_get_raddr,
    .free = net_free,
    .control = net_control,
    .except_ready = net_except_ready,
    .write = net_write
};

int
net_gensio_alloc(struct addrinfo *iai, const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data, const char *type,
		 struct gensio **new_gensio)
{
    struct net_data *tdata = NULL;
    struct addrinfo *ai, *lai = NULL;
    struct gensio *io;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    bool nodelay = false;
    unsigned int i;
    int ival;
    int err;
    bool istcp = strcmp(type, "tcp") == 0;

    err = gensio_get_default(o, type, "nodelay", false,
			     GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    nodelay = ival;

    err = gensio_get_defaultaddr(o, type, "laddr", false,
				 IPPROTO_TCP, true, false, &lai);
    if (err && err != GE_NOTSUP) {
	gensio_log(o, GENSIO_LOG_ERR, "Invalid default %d laddr: %s",
		   type, gensio_err_to_str(err));
	return err;
    }

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (istcp && gensio_check_keyaddrs(o, args[i], "laddr", IPPROTO_TCP,
					   true, false, &ai) > 0) {
	    if (lai)
		gensio_free_addrinfo(o, lai);
	    lai = ai;
	    continue;
	}
	if (istcp && gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;
	return GE_INVAL;
    }

    for (ai = iai; ai; ai = ai->ai_next) {
	if (ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
	    if (lai)
		gensio_free_addrinfo(o, lai);
	    return GE_TOOBIG;
	}
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata)
	goto out_nomem;

    tdata->istcp = istcp;

    ai = gensio_dup_addrinfo(o, iai);
    if (!ai)
	goto out_nomem;

    tdata->o = o;
    tdata->raddr = (struct sockaddr *) &tdata->remote;
    tdata->nodelay = nodelay;

    tdata->ll = fd_gensio_ll_alloc(o, -1, &net_fd_ll_ops, tdata, max_read_size,
				   false);
    if (!tdata->ll)
	goto out_nomem;

    io = base_gensio_alloc(o, tdata->ll, NULL, NULL, type, cb, user_data);
    if (!io)
	goto out_nomem;

    /* Assign these last so gensio_ll_free() won't free it on err. */
    tdata->ai = ai;
    tdata->lai = lai;

    gensio_set_is_reliable(io, true);

    *new_gensio = io;
    return 0;

 out_nomem:
    if (lai)
	gensio_free_addrinfo(o, lai);
    if (ai)
	gensio_free_addrinfo(o, ai);
    if (tdata) {
	if (tdata->ll)
	    gensio_ll_free(tdata->ll);
	else
	    /* gensio_ll_free() frees it otherwise. */
	    o->free(o, tdata);
    }
    return GE_NOMEM;
}

int
tcp_gensio_alloc(struct addrinfo *iai, const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
    return net_gensio_alloc(iai, args, o, cb, user_data, "tcp", new_gensio);
}

int
str_to_tcp_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    struct addrinfo *ai;
    int err;

    err = gensio_scan_netaddr(o, str, false, SOCK_STREAM, IPPROTO_TCP, &ai);
    if (err)
	return err;

    err = tcp_gensio_alloc(ai, args, o, cb, user_data, new_gensio);
    gensio_free_addrinfo(o, ai);

    return err;
}

int
unix_gensio_alloc(struct addrinfo *iai, const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
    return net_gensio_alloc(iai, args, o, cb, user_data, "unix", new_gensio);
}

int
str_to_unix_gensio(const char *str, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    struct addrinfo *ai;
    int err;

    err = gensio_scan_unixaddr(o, str, &ai, NULL, NULL);
    if (err)
	return err;

    err = unix_gensio_alloc(ai, args, o, cb, user_data, new_gensio);
    gensio_free_addrinfo(o, ai);

    return err;
}

struct netna_data;

struct netna_data {
    struct gensio_accepter *acc;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_runner *cb_en_done_runner;

    gensiods max_read_size;
    bool nodelay;

    gensio_acc_done shutdown_done;
    gensio_acc_done cb_en_done;

    struct addrinfo    *ai;		/* The address list for the portname. */
    struct opensocks   *acceptfds;	/* The file descriptor used to
					   accept connections on the
					   NET port. */
    unsigned int   nr_acceptfds;
    unsigned int   nr_accept_close_waiting;

    bool istcp;

    /* Remove the socket file if it exists. */
    bool delsock;
};

static const struct gensio_fd_ll_ops net_server_fd_ll_ops = {
    .raddr_to_str = net_raddr_to_str,
    .get_raddr = net_get_raddr,
    .free = net_free,
    .control = net_control,
    .except_ready = net_except_ready,
    .write = net_write
};

static void
netna_fd_cleared(int fd, void *cbdata)
{
    struct netna_data *nadata = cbdata;
    unsigned int num_left;

    close(fd);

    nadata->o->lock(nadata->lock);
    assert(nadata->nr_accept_close_waiting > 0);
    num_left = --nadata->nr_accept_close_waiting;
    if (num_left == 0) {
	if (nadata->acceptfds)
	    nadata->o->free(nadata->o, nadata->acceptfds);
	nadata->acceptfds = NULL;
    }
    nadata->o->unlock(nadata->lock);

    if (num_left == 0)
	nadata->shutdown_done(nadata->acc, NULL);
}

static void
netna_set_fd_enables(struct netna_data *nadata, bool enable)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->set_read_handler(nadata->o, nadata->acceptfds[i].fd, enable);
}

static void
netna_finish_server_open(struct gensio *net, int err, void *cb_data)
{
    struct netna_data *nadata = cb_data;

    base_gensio_server_open_done(nadata->acc, net, err);
}

static void
netna_readhandler(int fd, void *cbdata)
{
    struct netna_data *nadata = cbdata;
    int new_fd = -1;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct net_data *tdata = NULL;
    struct gensio *io;
    int err;

    err = base_gensio_accepter_new_child_start(nadata->acc);
    if (err)
	return;

    err = gensio_os_accept(nadata->o,
			   fd, (struct sockaddr *) &addr, &addrlen, &new_fd);
    if (err) {
	if (err != GE_NODATA)
	    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
			   "Error accepting net gensio: %s",
			   gensio_err_to_str(err));
	goto out_err;
    }

    if (nadata->istcp) {
	if (gensio_check_tcpd_ok(new_fd)) {
	    gensio_acc_log(nadata->acc, GENSIO_LOG_INFO,
			   "Error accepting net gensio: tcpd check failed");
	    err = GE_INVAL;
	    goto out_err;
	}
    }

    tdata = nadata->o->zalloc(nadata->o, sizeof(*tdata));
    if (!tdata) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_INFO,
		       "Error accepting net gensio: out of memory");
	err = GE_NOMEM;
	goto out_err;
    }

    tdata->o = nadata->o;
    tdata->raddr = (struct sockaddr *) &tdata->remote;
    memcpy(tdata->raddr, &addr, addrlen);
    tdata->raddrlen = addrlen;
    
    err = net_socket_setup(tdata, new_fd);
    if (err) {
	err = gensio_os_err_to_err(tdata->o, err);
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Error setting up net port: %s", gensio_err_to_str(err));
	goto out_err;
    }

    tdata->ll = fd_gensio_ll_alloc(nadata->o, new_fd, &net_server_fd_ll_ops,
				   tdata, nadata->max_read_size, false);
    if (!tdata->ll) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Out of memory allocating net ll");
	err = GE_NOMEM;
	goto out_err;
    }

    io = base_gensio_server_alloc(nadata->o, tdata->ll, NULL, NULL,
				  nadata->istcp ? "tcp" : "unix",
				  netna_finish_server_open, nadata);
    if (!io) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Out of memory allocating net base");
	err = GE_NOMEM;
	goto out_err;
    }
    gensio_set_is_reliable(io, true);
    err = base_gensio_server_start(io);
    if (err)
	goto out_err;
    base_gensio_accepter_new_child_end(nadata->acc, io, 0);
    return;

 out_err:
    base_gensio_accepter_new_child_end(nadata->acc, io, err);
    if (new_fd != -1)
	close(new_fd);
    if (tdata) {
	if (tdata->ll)
	    gensio_ll_free(tdata->ll);
	else
	    /* gensio_ll_free() frees it otherwise. */
	    net_free(tdata);
    }
}

static int
netna_startup(struct gensio_accepter *accepter, struct netna_data *nadata)
{
    int rv;

    if (!nadata->istcp && nadata->delsock) {
	struct sockaddr_un *sun;

	/* Remove the socket if it already exists. */
	sun = (struct sockaddr_un *) nadata->ai->ai_addr;
	unlink(sun->sun_path);
    }

    rv = gensio_open_socket(nadata->o, nadata->ai,
			    netna_readhandler, NULL, netna_fd_cleared, nadata,
			    &nadata->acceptfds, &nadata->nr_acceptfds);
    if (!rv)
	netna_set_fd_enables(nadata, true);
    return rv;
}

static int
netna_shutdown(struct gensio_accepter *accepter,
	       struct netna_data *nadata,
	       gensio_acc_done shutdown_done)
{
    unsigned int i;

    nadata->shutdown_done = shutdown_done;
    nadata->nr_accept_close_waiting = nadata->nr_acceptfds;
    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->clear_fd_handlers(nadata->o, nadata->acceptfds[i].fd);

    if (!nadata->istcp) {
	/* Remove the socket. */
	struct sockaddr_un *sun;

	sun = (struct sockaddr_un *) nadata->ai->ai_addr;
	unlink(sun->sun_path);
    }

    return 0;
}

static void
netna_cb_en_done(struct gensio_runner *runner, void *cb_data)
{
    struct netna_data *nadata = cb_data;

    nadata->cb_en_done(nadata->acc, NULL);
}

static int
netna_set_accept_callback_enable(struct gensio_accepter *accepter,
				 struct netna_data *nadata,
				 bool enabled,
				 gensio_acc_done done)
{
    unsigned int i;

    nadata->cb_en_done = done;
    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->set_read_handler(nadata->o, nadata->acceptfds[i].fd,
				    enabled);

    if (done)
	nadata->o->run(nadata->cb_en_done_runner);
    return 0;
}

static void
netna_free(struct gensio_accepter *accepter, struct netna_data *nadata)
{
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->cb_en_done_runner)
	nadata->o->free_runner(nadata->cb_en_done_runner);
    if (nadata->ai)
	gensio_free_addrinfo(nadata->o, nadata->ai);
    nadata->o->free(nadata->o, nadata);
}

static int
netna_str_to_gensio(struct gensio_accepter *accepter,
		    struct netna_data *nadata, const char *addr,
		    gensio_event cb, void *user_data, struct gensio **new_io)
{
    int err;
    const char *args[4] = { NULL, NULL, NULL, NULL };
    char buf[100];
    unsigned int i;
    gensiods max_read_size = nadata->max_read_size;
    const char **iargs;
    struct addrinfo *ai;
    const char *laddr = NULL, *dummy;
    bool is_port_set;
    int socktype, protocol = 0;
    bool nodelay = false;

    if (nadata->istcp)
	err = gensio_scan_network_port(nadata->o, addr, false, &ai, &socktype,
				       &protocol, &is_port_set, NULL, &iargs);
    else
	err = gensio_scan_unixaddr(nadata->o, addr, &ai, NULL, &iargs);
    if (err)
	return err;

    err = EINVAL;
    if (nadata->istcp && (protocol != IPPROTO_TCP || !is_port_set))
	goto out_err;

    for (i = 0; iargs && iargs[i]; i++) {
	if (gensio_check_keyds(iargs[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (nadata->istcp &&
		gensio_check_keyvalue(iargs[i], "laddr", &dummy) > 0) {
	    laddr = iargs[i];
	    continue;
	}
	if (nadata->istcp &&
		gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;
	goto out_err;
    }

    i = 0;
    if (max_read_size != GENSIO_DEFAULT_BUF_SIZE) {
	snprintf(buf, sizeof(buf), "readbuf=%lu",
		 (unsigned long) nadata->max_read_size);
	args[i++] = buf;
    }

    if (laddr)
	args[i++] = laddr;

    if (nodelay)
	args[i++] = "nodelay";

    err = net_gensio_alloc(ai, args, nadata->o, cb, user_data,
			   nadata->istcp ? "tcp" : "unix", new_io);

 out_err:
    if (iargs)
	gensio_argv_free(nadata->o, iargs);
    gensio_free_addrinfo(nadata->o, ai);

    return err;
}

static int
netna_control_laddr(struct netna_data *nadata, bool get,
		    char *data, gensiods *datalen)
{
    unsigned int i;
    struct sockaddr_storage sa;
    gensiods pos = 0;
    int rv;
    socklen_t len = sizeof(sa);

    if (!get)
	return GE_NOTSUP;

    if (nadata->nr_acceptfds == 0)
	return GE_NOTREADY;

    i = strtoul(data, NULL, 0);
    if (i >= nadata->nr_acceptfds)
	return GE_NOTFOUND;

    rv = getsockname(nadata->acceptfds[i].fd, (struct sockaddr *) &sa, &len);
    if (rv)
	return gensio_os_err_to_err(nadata->o, errno);

    rv = gensio_sockaddr_to_str((struct sockaddr *) &sa, &len, data,
				&pos, *datalen);
    if (rv)
	return rv;

    *datalen = pos;
    return 0;
}

static int
netna_control_lport(struct netna_data *nadata, bool get,
		    char *data, gensiods *datalen)
{
    unsigned int i;

    if (!get)
	return GE_NOTSUP;

    if (!nadata->istcp)
	return GE_NOTSUP;

    if (nadata->nr_acceptfds == 0)
	return GE_NOTREADY;

    i = strtoul(data, NULL, 0);
    if (i >= nadata->nr_acceptfds)
	return GE_NOTFOUND;

    *datalen = snprintf(data, *datalen, "%d", nadata->acceptfds[i].port);
    return 0;
}

static int
netna_control(struct gensio_accepter *accepter, struct netna_data *nadata,
	      bool get, unsigned int option, char *data, gensiods *datalen)
{
    switch (option) {
    case GENSIO_ACC_CONTROL_LADDR:
	return netna_control_laddr(nadata, get, data, datalen);

    case GENSIO_ACC_CONTROL_LPORT:
	return netna_control_lport(nadata, get, data, datalen);

    default:
	return GE_NOTSUP;
    }
}

static void
netna_disable(struct gensio_accepter *accepter, struct netna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->clear_fd_handlers_norpt(nadata->o,
					   nadata->acceptfds[i].fd);
    for (i = 0; i < nadata->nr_acceptfds; i++)
	close(nadata->acceptfds[i].fd);
}

static int
netna_base_acc_op(struct gensio_accepter *acc, int op,
		  void *acc_op_data, void *done, int val1,
		  void *data, void *data2, void *ret)
{
    switch(op) {
    case GENSIO_BASE_ACC_STARTUP:
	return netna_startup(acc, acc_op_data);

    case GENSIO_BASE_ACC_SHUTDOWN:
	return netna_shutdown(acc, acc_op_data, done);

    case GENSIO_BASE_ACC_SET_CB_ENABLE:
	return netna_set_accept_callback_enable(acc, acc_op_data, val1, done);

    case GENSIO_BASE_ACC_FREE:
	netna_free(acc, acc_op_data);
	return 0;

    case GENSIO_BASE_ACC_CONTROL:
	return netna_control(acc, acc_op_data,
			      val1, *((unsigned int *) done), data, ret);

    case GENSIO_BASE_ACC_STR_TO_GENSIO:
	return netna_str_to_gensio(acc, acc_op_data, (const char *) data,
				    (gensio_event) done, data2, ret);

    case GENSIO_BASE_ACC_DISABLE:
	netna_disable(acc, acc_op_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
net_gensio_accepter_alloc(struct addrinfo *iai,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_accepter_event cb, void *user_data,
			  const char *type,
			  struct gensio_accepter **accepter)
{
    struct netna_data *nadata;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    bool nodelay = false;
    bool istcp = strcmp(type, "tcp") == 0;
    bool delsock = false;
    unsigned int i;
    int err, ival;

    err = gensio_get_default(o, type, "delsock", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    delsock = ival;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (istcp && gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;
	if (!istcp &&
		gensio_check_keybool(args[i], "delsock", &delsock) > 0)
	    continue;
	return GE_INVAL;
    }

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;
    nadata->o = o;

    err = GE_NOMEM;
    nadata->ai = gensio_dup_addrinfo(o, iai);
    if (!nadata->ai)
	goto out_err;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_err;

    nadata->cb_en_done_runner = o->alloc_runner(o, netna_cb_en_done, nadata);
    if (!nadata->cb_en_done_runner)
	goto out_err;

    nadata->istcp = istcp;
    nadata->delsock = delsock;

    err = base_gensio_accepter_alloc(NULL, netna_base_acc_op, nadata,
				    o, type, cb, user_data, accepter);
    if (err)
	goto out_err;

    nadata->acc = *accepter;
    gensio_acc_set_is_reliable(nadata->acc, true);
    nadata->max_read_size = max_read_size;
    nadata->nodelay = nodelay;

    return 0;

 out_err:
    netna_free(NULL, nadata);
    return err;
}

int
tcp_gensio_accepter_alloc(struct addrinfo *iai,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_accepter_event cb, void *user_data,
			  struct gensio_accepter **accepter)
{
    return net_gensio_accepter_alloc(iai, args, o, cb, user_data, "tcp",
				     accepter);
}

int
str_to_tcp_gensio_accepter(const char *str, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb,
			   void *user_data,
			   struct gensio_accepter **acc)
{
    int err;
    struct addrinfo *ai;

    err = gensio_scan_netaddr(o, str, true, SOCK_STREAM, IPPROTO_TCP, &ai);
    if (err)
	return err;

    err = tcp_gensio_accepter_alloc(ai, args, o, cb, user_data, acc);
    gensio_free_addrinfo(o, ai);

    return err;
}

int
unix_gensio_accepter_alloc(struct addrinfo *iai,
			   const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
    return net_gensio_accepter_alloc(iai, args, o, cb, user_data, "unix",
				     accepter);
}

int
str_to_unix_gensio_accepter(const char *str, const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb,
			    void *user_data,
			    struct gensio_accepter **acc)
{
    int err;
    struct addrinfo *ai;

    err = gensio_scan_unixaddr(o, str, &ai, NULL, NULL);
    if (err)
	return err;

    err = unix_gensio_accepter_alloc(ai, args, o, cb, user_data, acc);
    gensio_free_addrinfo(o, ai);

    return err;
}
