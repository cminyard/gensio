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

/* This code handles TCP network I/O. */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

struct tcp_data {
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

    int last_err;
};

static int tcp_check_open(void *handler_data, int fd)
{
    struct tcp_data *tdata = handler_data;
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
tcp_socket_setup(struct tcp_data *tdata, int fd)
{
    int optval = 1;

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
	return errno;

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		   (void *)&optval, sizeof(optval)) == -1)
	return errno;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		   (void *)&optval, sizeof(optval)) == -1)
	return errno;

    if (tdata->nodelay) {
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
tcp_try_open(struct tcp_data *tdata, int *fd)
{
    int new_fd, err = EBUSY;
    struct addrinfo *ai = tdata->curr_ai;

    new_fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (new_fd == -1) {
	err = errno;
	goto out;
    }

    err = tcp_socket_setup(tdata, new_fd);
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
tcp_retry_open(void *handler_data, int *fd)
{
    struct tcp_data *tdata = handler_data;

    if (tdata->curr_ai)
	tdata->curr_ai = tdata->curr_ai->ai_next;
    if (!tdata->curr_ai)
	return tdata->last_err;
    return tcp_try_open(tdata, fd);
}

static int
tcp_sub_open(void *handler_data, int *fd)
{
    struct tcp_data *tdata = handler_data;

    tdata->curr_ai = tdata->ai;
    return tcp_try_open(tdata, fd);
}

static int
tcp_raddr_to_str(void *handler_data, gensiods *epos,
		 char *buf, gensiods buflen)
{
    struct tcp_data *tdata = handler_data;
    socklen_t addrlen = tdata->raddrlen;

    return gensio_sockaddr_to_str(tdata->raddr, &addrlen, buf, epos, buflen);
}

static int
tcp_get_raddr(void *handler_data, void *addr, gensiods *addrlen)
{
    struct tcp_data *tdata = handler_data;

    if (*addrlen > tdata->raddrlen)
	*addrlen = tdata->raddrlen;

    memcpy(addr, tdata->raddr, *addrlen);
    return 0;
}

static void
tcp_free(void *handler_data)
{
    struct tcp_data *tdata = handler_data;

    if (tdata->ai)
	gensio_free_addrinfo(tdata->o, tdata->ai);
    if (tdata->lai)
	gensio_free_addrinfo(tdata->o, tdata->lai);
    tdata->o->free(tdata->o, tdata);
}

static int
tcp_control(void *handler_data, int fd, bool get, unsigned int option,
	    char *data, gensiods *datalen)
{
    struct tcp_data *tdata = handler_data;
    int rv, val;

    switch (option) {
    case GENSIO_CONTROL_NODELAY:
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
tcp_oob_read(int fd, void *data, gensiods count, gensiods *rcount,
	     const char **auxdata, void *cb_data)
{
    struct tcp_data *tdata = cb_data;

    return gensio_os_recv(tdata->o, fd, data, count, rcount, MSG_OOB);
}

static void
tcp_except_ready(void *handler_data, int fd)
{
    struct tcp_data *tdata = handler_data;
    static const char *argv[2] = { "oob", NULL };

    gensio_fd_ll_handle_incoming(tdata->ll, tcp_oob_read, argv, tdata);
}

static int
tcp_write(void *handler_data, int fd, gensiods *rcount,
	  const struct gensio_sg *sg, gensiods sglen,
	  const char *const *auxdata)
{
    struct tcp_data *tdata = handler_data;
    int err = 0;
    int flags = 0;

    if (auxdata) {
	int i;

	for (i = 0; !err && auxdata[i]; i++) {
	    if (strcasecmp(auxdata[i], "oob") == 0) {
		flags |= MSG_OOB;
	    } else {
		err = EINVAL;
	    }
	}

	if (err)
	    return err;
    }

    return gensio_os_send(tdata->o, fd, sg, sglen, rcount, flags);
}

static const struct gensio_fd_ll_ops tcp_fd_ll_ops = {
    .sub_open = tcp_sub_open,
    .check_open = tcp_check_open,
    .retry_open = tcp_retry_open,
    .raddr_to_str = tcp_raddr_to_str,
    .get_raddr = tcp_get_raddr,
    .free = tcp_free,
    .control = tcp_control,
    .except_ready = tcp_except_ready,
    .write = tcp_write
};

int
tcp_gensio_alloc(struct addrinfo *iai, const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
    struct tcp_data *tdata = NULL;
    struct addrinfo *ai, *lai = NULL;
    struct gensio *io;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    bool nodelay = false;
    unsigned int i;
    int ival;
    int err;

    err = gensio_get_default(o, "tcp", "nodelay", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (!err)
	nodelay = ival;

    err = gensio_get_defaultaddr(o, "tcp", "laddr", false,
				 IPPROTO_TCP, true, false, &lai);
    if (err != GE_NOTSUP)
	gensio_log(o, GENSIO_LOG_ERR, "Invalid default tcp laddr, ignoring: %s",
		   gensio_err_to_str(err));

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyaddrs(o, args[i], "laddr", IPPROTO_TCP,
				  true, false, &lai) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;
	return EINVAL;
    }

    for (ai = iai; ai; ai = ai->ai_next) {
	if (ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
	    if (lai)
		gensio_free_addrinfo(o, lai);
	    return E2BIG;
	}
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata) {
	if (lai)
	    gensio_free_addrinfo(o, lai);
	return ENOMEM;
    }

    ai = gensio_dup_addrinfo(o, iai);
    if (!ai) {
	if (lai)
	    gensio_free_addrinfo(o, lai);
	o->free(o, tdata);
	return ENOMEM;
    }

    tdata->o = o;
    tdata->ai = ai;
    tdata->lai = lai;
    tdata->raddr = (struct sockaddr *) &tdata->remote;
    tdata->nodelay = nodelay;

    tdata->ll = fd_gensio_ll_alloc(o, -1, &tcp_fd_ll_ops, tdata, max_read_size,
				   false);
    if (!tdata->ll) {
	if (lai)
	    gensio_free_addrinfo(o, lai);
	gensio_free_addrinfo(o, ai);
	o->free(o, tdata);
	return ENOMEM;
    }

    io = base_gensio_alloc(o, tdata->ll, NULL, NULL, "tcp", cb, user_data);
    if (!io) {
	gensio_ll_free(tdata->ll);
	if (lai)
	    gensio_free_addrinfo(o, lai);
	gensio_free_addrinfo(o, ai);
	o->free(o, tdata);
	return ENOMEM;
    }
    gensio_set_is_reliable(io, true);

    *new_gensio = io;
    return 0;
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

struct tcpna_data;

struct tcpna_waiters {
    struct gensio_os_funcs *o;
    struct tcpna_data *nadata;
    gensio_acc_done done;
    void *done_data;
    struct gensio_runner *runner;
    struct tcpna_waiters *next;
};

struct tcpna_data {
    struct gensio_accepter *acc;

    struct gensio_os_funcs *o;

    gensiods max_read_size;
    bool nodelay;

    struct gensio_lock *lock;

    bool setup;			/* Network sockets are allocated. */
    bool enabled;		/* Accepts are being handled. */
    bool in_shutdown;		/* Currently being shut down. */
    bool in_accept_cb;		/* Currently in a callback. */
    struct tcpna_waiters *acc_disable_waiters;

    unsigned int refcount;

    gensio_acc_done shutdown_done;
    void *shutdown_data;

    struct addrinfo    *ai;		/* The address list for the portname. */
    struct opensocks   *acceptfds;	/* The file descriptor used to
					   accept connections on the
					   TCP port. */
    unsigned int   nr_acceptfds;
    unsigned int   nr_accept_close_waiting;
};

static void
write_nofail(int fd, const char *data, size_t count)
{
    ssize_t written;

    while ((written = write(fd, data, count)) > 0) {
	data += written;
	count -= written;
    }
}

static void
tcpna_finish_free(struct tcpna_data *nadata)
{
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->ai)
	gensio_free_addrinfo(nadata->o, nadata->ai);
    if (nadata->acceptfds)
	nadata->o->free(nadata->o, nadata->acceptfds);
    if (nadata->acc)
	gensio_acc_data_free(nadata->acc);
    nadata->o->free(nadata->o, nadata);
}

static void
tcpna_lock(struct tcpna_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
tcpna_unlock(struct tcpna_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void
tcpna_ref(struct tcpna_data *nadata)
{
    nadata->refcount++;
}

static void
tcpna_deref_and_unlock(struct tcpna_data *nadata)
{
    unsigned int count;

    assert(nadata->refcount > 0);
    count = --nadata->refcount;
    tcpna_unlock(nadata);
    if (count == 0)
	tcpna_finish_free(nadata);
}

static const struct gensio_fd_ll_ops tcp_server_fd_ll_ops = {
    .raddr_to_str = tcp_raddr_to_str,
    .get_raddr = tcp_get_raddr,
    .free = tcp_free,
    .control = tcp_control,
    .except_ready = tcp_except_ready,
    .write = tcp_write
};

static void
tcpna_server_open_done(struct gensio *io, int err, void *open_data)
{
    struct tcpna_data *nadata = open_data;
    struct tcpna_waiters *waiters, *next;

    tcpna_lock(nadata);
    gensio_acc_remove_pending_gensio(nadata->acc, io);
    tcpna_unlock(nadata);
    if (err) {
	gensio_free(io);
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Error setting up TCP server gensio: %s",
		       gensio_err_to_str(err));
    } else {
	gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_NEW_CONNECTION, io);
    }

    tcpna_lock(nadata);
    nadata->in_accept_cb = false;
    waiters = nadata->acc_disable_waiters;
    nadata->acc_disable_waiters = NULL;
    tcpna_unlock(nadata);
    while (waiters) {
	next = waiters->next;
	waiters->done(nadata->acc, waiters->done_data);
	nadata->o->free(nadata->o, waiters);
	waiters = next;
    }
    tcpna_lock(nadata);
    tcpna_deref_and_unlock(nadata);
}

static void
tcpna_readhandler(int fd, void *cbdata)
{
    struct tcpna_data *nadata = cbdata;
    int new_fd;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct tcp_data *tdata = NULL;
    struct gensio *io;
    const char *errstr;
    int err;

    tcpna_lock(nadata);
    if (!nadata->enabled)
	goto out_unlock; /* We can race, just ignore this if so. */

    err = gensio_os_accept(nadata->o,
			   fd, (struct sockaddr *) &addr, &addrlen, &new_fd);
    if (err) {
	if (err != EAGAIN)
	    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
			   "Error accepting TCP gensio: %s",
			   gensio_err_to_str(err));
	goto out_unlock;
    }

    errstr = gensio_check_tcpd_ok(new_fd);
    if (errstr) {
	write_nofail(new_fd, errstr, strlen(errstr));
	close(new_fd);
	goto out_unlock;
    }

    tdata = nadata->o->zalloc(nadata->o, sizeof(*tdata));
    if (!tdata) {
	errstr = "Out of memory\r\n";
	write_nofail(new_fd, errstr, strlen(errstr));
	close(new_fd);
	goto out_unlock;
    }

    tdata->o = nadata->o;
    tdata->raddr = (struct sockaddr *) &tdata->remote;
    memcpy(tdata->raddr, &addr, addrlen);
    tdata->raddrlen = addrlen;
    
    err = tcp_socket_setup(tdata, new_fd);
    if (err) {
	err = gensio_os_err_to_err(tdata->o, err);
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Error setting up tcp port: %s", gensio_err_to_str(err));
	close(new_fd);
	tcp_free(tdata);
	goto out_unlock;
    }

    tdata->ll = fd_gensio_ll_alloc(nadata->o, new_fd, &tcp_server_fd_ll_ops,
				   tdata, nadata->max_read_size, false);
    if (!tdata->ll) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Out of memory allocating tcp ll");
	close(new_fd);
	tcp_free(tdata);
	goto out_unlock;
    }

    io = base_gensio_server_alloc(nadata->o, tdata->ll, NULL, NULL, "tcp",
				  tcpna_server_open_done, nadata);
    if (!io) {
	tcpna_unlock(nadata);
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Out of memory allocating tcp base");
	gensio_ll_free(tdata->ll);
	close(new_fd);
	tcp_free(tdata);
	return;
    }
    tcpna_ref(nadata);
    gensio_set_is_reliable(io, true);
    gensio_acc_add_pending_gensio(nadata->acc, io);
    nadata->in_accept_cb = true;
 out_unlock:
    tcpna_unlock(nadata);
}

static void
tcpna_fd_cleared(int fd, void *cbdata)
{
    struct tcpna_data *nadata = cbdata;
    struct gensio_accepter *accepter = nadata->acc;
    unsigned int num_left;

    close(fd);

    tcpna_lock(nadata);
    num_left = --nadata->nr_accept_close_waiting;
    if (num_left == 0) {
	nadata->in_shutdown = false;
	if (nadata->acceptfds)
	    nadata->o->free(nadata->o, nadata->acceptfds);
	nadata->acceptfds = NULL;
    }
    tcpna_unlock(nadata);

    if (num_left == 0) {
	if (nadata->shutdown_done)
	    nadata->shutdown_done(accepter, nadata->shutdown_data);
	tcpna_lock(nadata);
	tcpna_deref_and_unlock(nadata);
    }
}

static void
tcpna_set_fd_enables(struct tcpna_data *nadata, bool enable)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->set_read_handler(nadata->o, nadata->acceptfds[i].fd, enable);
}

static int
tcpna_startup(struct gensio_accepter *accepter)
{
    struct tcpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    tcpna_lock(nadata);
    if (nadata->in_shutdown || nadata->setup) {
	rv = GE_INUSE;
	goto out_unlock;
    }

    rv = gensio_open_socket(nadata->o, nadata->ai,
			    tcpna_readhandler, NULL, tcpna_fd_cleared, nadata,
			    &nadata->acceptfds, &nadata->nr_acceptfds);
    if (!rv) {
	nadata->setup = true;
	tcpna_set_fd_enables(nadata, true);
	nadata->enabled = true;
	nadata->shutdown_done = NULL;
	tcpna_ref(nadata);
    }

 out_unlock:
    tcpna_unlock(nadata);
    return rv;
}

static void
i_tcpna_shutdown(struct tcpna_data *nadata,
		 gensio_acc_done shutdown_done, void *shutdown_data)
{
    unsigned int i;

    nadata->in_shutdown = true;
    nadata->shutdown_done = shutdown_done;
    nadata->shutdown_data = shutdown_data;
    nadata->nr_accept_close_waiting = nadata->nr_acceptfds;
    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->clear_fd_handlers(nadata->o, nadata->acceptfds[i].fd);
    nadata->setup = false;
    nadata->enabled = false;
}

static int
tcpna_shutdown(struct gensio_accepter *accepter,
	       gensio_acc_done shutdown_done, void *shutdown_data)
{
    struct tcpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    tcpna_lock(nadata);
    if (nadata->setup)
	i_tcpna_shutdown(nadata, shutdown_done, shutdown_data);
    else
	rv = GE_INUSE;
    tcpna_unlock(nadata);

    return rv;
}

static void
waiter_runner_cb(struct gensio_runner *runner, void *cb_data)
{
    struct tcpna_waiters *w = cb_data;

    w->done(w->nadata->acc, w->done_data);
    w->o->free_runner(w->runner);

    tcpna_lock(w->nadata);
    tcpna_deref_and_unlock(w->nadata);

    w->o->free(w->o, w);
}

static int
tcpna_set_accept_callback_enable(struct gensio_accepter *accepter, bool enabled,
				 gensio_acc_done done, void *done_data)
{
    struct tcpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    tcpna_lock(nadata);
    if (nadata->enabled != enabled) {
	tcpna_set_fd_enables(nadata, enabled);
	nadata->enabled = enabled;
    }
    if (done) {
	struct gensio_os_funcs *o = nadata->o;
	struct tcpna_waiters *w = o->zalloc(o, sizeof(*w));

	if (!w)
	    rv = GE_NOMEM;
	else {
	    w->o = o;
	    w->done = done;
	    w->done_data = done_data;
	    if (nadata->in_accept_cb) {
		w->next = nadata->acc_disable_waiters;
		nadata->acc_disable_waiters = w;
	    } else {
		w->nadata = nadata;
		w->runner = o->alloc_runner(o, waiter_runner_cb, w);
		if (!w->runner) {
		    o->free(o, w);
		    rv = GE_NOMEM;
		} else {
		    tcpna_ref(nadata);
		    o->run(w->runner);
		}
	    }
	}
    }
    tcpna_unlock(nadata);
    return rv;
}

static void
tcpna_free(struct gensio_accepter *accepter)
{
    struct tcpna_data *nadata = gensio_acc_get_gensio_data(accepter);

    tcpna_lock(nadata);
    if (nadata->setup)
	i_tcpna_shutdown(nadata, NULL, NULL);
    tcpna_deref_and_unlock(nadata);
}

static void
tcpna_disable(struct gensio_accepter *accepter)
{
    struct tcpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    unsigned int i;

    tcpna_lock(nadata);
    if (nadata->setup) {
	nadata->in_shutdown = false;
	nadata->shutdown_done = NULL;
	for (i = 0; i < nadata->nr_acceptfds; i++)
	    nadata->o->clear_fd_handlers_norpt(nadata->o,
					       nadata->acceptfds[i].fd);
	for (i = 0; i < nadata->nr_acceptfds; i++)
	    close(nadata->acceptfds[i].fd);
	nadata->setup = false;
	nadata->enabled = false;
	tcpna_deref_and_unlock(nadata);
    } else {
	tcpna_unlock(nadata);
    }
}

int
tcpna_str_to_gensio(struct gensio_accepter *accepter, const char *addr,
		    gensio_event cb, void *user_data,
		    struct gensio **new_net)
{
    struct tcpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int err;
    const char *args[4] = { NULL, NULL, NULL, NULL };
    char buf[100];
    unsigned int i;
    gensiods max_read_size = nadata->max_read_size;
    const char **iargs;
    struct addrinfo *ai;
    const char *laddr = NULL, *dummy;
    bool is_port_set;
    int socktype, protocol;
    bool nodelay = false;

    err = gensio_scan_network_port(nadata->o, addr, false, &ai, &socktype,
				   &protocol, &is_port_set, NULL, &iargs);
    if (err)
	return err;

    err = EINVAL;
    if (protocol != IPPROTO_TCP || !is_port_set)
	goto out_err;

    for (i = 0; iargs && iargs[i]; i++) {
	if (gensio_check_keyds(iargs[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyvalue(iargs[i], "laddr", &dummy) > 0) {
	    laddr = iargs[i];
	    continue;
	}
	if (gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
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

    err = tcp_gensio_alloc(ai, args, nadata->o, cb, user_data, new_net);

 out_err:
    if (iargs)
	gensio_argv_free(nadata->o, iargs);
    gensio_free_addrinfo(nadata->o, ai);

    return err;
}

static int
gensio_acc_tcp_func(struct gensio_accepter *acc, int func, int val,
		    const char *addr, void *done, void *data, const void *data2,
		    void *ret)
{
    switch (func) {
    case GENSIO_ACC_FUNC_STARTUP:
	return tcpna_startup(acc);

    case GENSIO_ACC_FUNC_SHUTDOWN:
	return tcpna_shutdown(acc, done, data);

    case GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK:
	return tcpna_set_accept_callback_enable(acc, val, done, data);

    case GENSIO_ACC_FUNC_FREE:
	tcpna_free(acc);
	return 0;

    case GENSIO_ACC_FUNC_STR_TO_GENSIO:
	return tcpna_str_to_gensio(acc, addr, done, data, ret);

    case GENSIO_ACC_FUNC_DISABLE:
	tcpna_disable(acc);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

int
tcp_gensio_accepter_alloc(struct addrinfo *iai,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_accepter_event cb, void *user_data,
			  struct gensio_accepter **accepter)
{
    struct tcpna_data *nadata;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    bool nodelay = false;
    unsigned int i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;
	return EINVAL;
    }

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return ENOMEM;
    nadata->o = o;

    nadata->ai = gensio_dup_addrinfo(o, iai);
    if (!nadata->ai)
	goto out_nomem;
    tcpna_ref(nadata);

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    nadata->acc = gensio_acc_data_alloc(o, cb, user_data, gensio_acc_tcp_func,
					NULL, "tcp", nadata);
    if (!nadata->acc)
	goto out_nomem;
    gensio_acc_set_is_reliable(nadata->acc, true);

    nadata->max_read_size = max_read_size;
    nadata->nodelay = nodelay;

    *accepter = nadata->acc;
    return 0;

 out_nomem:
    tcpna_finish_free(nadata);
    return ENOMEM;
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
