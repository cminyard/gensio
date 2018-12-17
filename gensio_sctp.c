/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* This code handles SCTP network I/O. */

#include <gensio/gensio.h>

#ifdef HAVE_LIBSCTP

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>

struct sctp_data {
    struct gensio_os_funcs *o;

    int fd;

    int family;
    struct addrinfo *ai;
};

static int sctp_check_open(void *handler_data, int fd)
{
    int optval = 0, err;
    socklen_t len = sizeof(optval);

    err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &len);
    if (err)
	return errno;
    return optval;
}

static int
sctp_socket_setup(struct sctp_data *tdata, int fd)
{
    int optval = 1;

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
	return errno;

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		   (void *)&optval, sizeof(optval)) == -1)
	return errno;

    return 0;
}

static int
sctp_addrinfo_to_sockaddr(struct gensio_os_funcs *o, struct addrinfo *iai,
			  struct sockaddr **addrs, unsigned int *naddrs)
{
    struct addrinfo *ai = iai;
    unsigned int size = 0;
    unsigned int count = 0;
    struct sockaddr *a;
    unsigned char *d;

    for (ai = iai; ai; ai = ai->ai_next)
	size += ai->ai_addrlen;
    if (size == 0)
	return EINVAL;

    a = o->zalloc(0, size);
    d = (unsigned char *) a;
    for (ai = iai; ai; ai = ai->ai_next) {
	memcpy(d, ai->ai_addr, ai->ai_addrlen);
	count++;
	d += ai->ai_addrlen;
    }
    *addrs = a;
    *naddrs = count;
    return 0;
}

static int
sctp_try_open(struct sctp_data *tdata, int *fd)
{
    int new_fd, err = EBUSY;
    struct sockaddr *addrs = NULL;
    unsigned int naddrs;

    err = sctp_addrinfo_to_sockaddr(tdata->o, tdata->ai, &addrs, &naddrs);
    if (err)
	return err;

    new_fd = socket(tdata->family, SOCK_STREAM, IPPROTO_SCTP);
    if (new_fd == -1) {
	err = errno;
	goto out;
    }

    err = sctp_socket_setup(tdata, new_fd);
    if (err)
	goto out;

    err = sctp_connectx(new_fd, addrs, naddrs, NULL);
    if (err == -1) {
	err = errno;
	if (err == EINPROGRESS) {
	    *fd = new_fd;
	    goto out_return;
	}
    } else {
	err = 0;
    }

 out:
    if (err) {
	if (new_fd != -1)
	    close(new_fd);
    } else {
	*fd = new_fd;
    }

 out_return:
    tdata->o->free(tdata->o, addrs);
    return err;
}

static int
sctp_sub_open(void *handler_data,
	      int (**check_open)(void *handler_data, int fd),
	      int (**retry_open)(void *handler_data, int *fd),
	      int *fd)
{
    struct sctp_data *tdata = handler_data;

    *check_open = sctp_check_open;
    return sctp_try_open(tdata, fd);
}

static int
sctp_raddr_to_str(void *handler_data, unsigned int *epos,
		  char *buf, unsigned int buflen)
{
    struct sctp_data *tdata = handler_data;
    struct sockaddr *addrs;
    unsigned char *d;
    unsigned int i, count, pos = 0;
    int rv;

    rv = sctp_getpaddrs(tdata->fd, 0, &addrs);
    if (rv < 0)
	return errno;
    if (rv == 0)
	return ENOENT;

    if (epos)
	pos = *epos;

    count = rv;
    d = (unsigned char *) addrs;
    for (i = 0; i < count; i++) {
	socklen_t addrlen = 0;

	if (i > 0) {
	    /* Add the comma between the addresses. */
	    if (pos < buflen && buflen - pos > 1)
		buf[pos] = ',';
	    pos++;
	}

	rv = gensio_sockaddr_to_str((struct sockaddr *) d, &addrlen,
				    buf, &pos, buflen);
	if (rv)
	    goto out;
	d += addrlen;
    }

 out:
    sctp_freepaddrs(addrs);
    if (!rv && epos)
	*epos = pos;
    return rv;
}

static int
sctp_get_raddr(void *handler_data, void *addr, unsigned int *addrlen)
{
    struct sctp_data *tdata = handler_data;
    struct sockaddr *addrs, *a;
    unsigned char *d;
    unsigned int i, size, count;
    int rv;

    rv = sctp_getpaddrs(tdata->fd, 0, &addrs);
    if (rv < 0)
	return errno;
    if (rv == 0)
	return ENOENT;

    count = rv;
    rv = 0;
    d = (unsigned char *) addrs;
    for (i = 0; i < count; i++) {
	a = (struct sockaddr *) d;
	if (a->sa_family == AF_INET) {
	    d += sizeof(struct sockaddr_in);
	} else if (a->sa_family == AF_INET6) {
	    d += sizeof(struct sockaddr_in6);
	} else {
	    rv = EINVAL;
	    goto out;
	}
    }
    size = d - ((unsigned char *) addrs);

    if (size > *addrlen)
	memcpy(addr, addrs, *addrlen);
    else
	memcpy(addr, addrs, size);
    *addrlen = size;

 out:
    sctp_freepaddrs(addrs);
    return rv;
}

static void
sctp_free(void *handler_data)
{
    struct sctp_data *tdata = handler_data;

    if (tdata->ai)
	gensio_free_addrinfo(tdata->o, tdata->ai);
    tdata->o->free(tdata->o, tdata);
}

static int
sctp_control(void *handler_data, int fd, unsigned int option, void *auxdata)
{
    int rv;

    switch (option) {
    case GENSIO_CONTROL_NODELAY:
	rv = setsockopt(fd, SOL_SCTP, SCTP_NODELAY, auxdata, sizeof(int));
	if (rv == -1)
	    return errno;
	return 0;

    default:
	return ENOTSUP;
    }
}

static const struct gensio_fd_ll_ops sctp_fd_ll_ops = {
    .sub_open = sctp_sub_open,
    .raddr_to_str = sctp_raddr_to_str,
    .get_raddr = sctp_get_raddr,
    .free = sctp_free,
    .control = sctp_control
};

int
sctp_gensio_alloc(struct addrinfo *iai, char *args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    struct sctp_data *tdata = NULL;
    struct addrinfo *ai;
    struct gensio_ll *ll;
    struct gensio *io;
    unsigned int max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    int i, family = AF_INET;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    for (ai = iai; ai; ai = ai->ai_next) {
	if (ai->ai_addrlen > sizeof(struct sockaddr_storage))
	    return E2BIG;
	if (ai->ai_addr->sa_family == AF_INET6)
	    family = AF_INET6;
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata)
	return ENOMEM;

    ai = gensio_dup_addrinfo(o, iai);
    if (!ai) {
	o->free(o, tdata);
	return ENOMEM;
    }

    tdata->o = o;
    tdata->family = family;
    tdata->ai = ai;

    ll = fd_gensio_ll_alloc(o, -1, &sctp_fd_ll_ops, tdata, max_read_size);
    if (!ll) {
	gensio_free_addrinfo(o, ai);
	o->free(o, tdata);
	return ENOMEM;
    }

    io = base_gensio_alloc(o, ll, NULL, "sctp", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_free_addrinfo(o, ai);
	o->free(o, tdata);
	return ENOMEM;
    }
    gensio_set_is_reliable(io, true);
    gensio_set_is_packet(io, true);

    *new_gensio = io;
    return 0;
}

int
str_to_sctp_gensio(const char *str, char *args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    struct addrinfo *ai;
    int err;

    err = gensio_scan_netaddr(o, str, false, SOCK_STREAM, IPPROTO_SCTP, &ai);
    if (err)
	return err;

    err = sctp_gensio_alloc(ai, args, o, cb, user_data, new_gensio);
    gensio_free_addrinfo(o, ai);

    return err;
}

struct sctpna_acceptfds {
    int fd;
    int port;
    int family;
    int flags;
};

struct sctpna_data {
    struct gensio_accepter *acc;

    struct gensio_os_funcs *o;

    unsigned int max_read_size;

    struct gensio_lock *lock;

    bool setup;			/* Network sockets are allocated. */
    bool enabled;		/* Accepts are being handled. */
    bool in_shutdown;		/* Currently being shut down. */

    unsigned int refcount;

    gensio_acc_done shutdown_done;
    void *shutdown_data;

    struct sctpna_acceptfds *fds;
    unsigned int nfds;

    struct addrinfo *ai;

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
sctpna_finish_free(struct sctpna_data *nadata)
{
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->ai)
	gensio_free_addrinfo(nadata->o, nadata->ai);
    if (nadata->acc)
	gensio_acc_data_free(nadata->acc);
    nadata->o->free(nadata->o, nadata);
}

static void
sctpna_lock(struct sctpna_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
sctpna_unlock(struct sctpna_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void
sctpna_ref(struct sctpna_data *nadata)
{
    nadata->refcount++;
}

static void
sctpna_deref_and_unlock(struct sctpna_data *nadata)
{
    unsigned int count;

    assert(nadata->refcount > 0);
    count = --nadata->refcount;
    sctpna_unlock(nadata);
    if (count == 0)
	sctpna_finish_free(nadata);
}

static const struct gensio_fd_ll_ops sctp_server_fd_ll_ops = {
    .raddr_to_str = sctp_raddr_to_str,
    .get_raddr = sctp_get_raddr,
    .free = sctp_free,
    .control = sctp_control
};

static void
sctpna_readhandler(int fd, void *cbdata)
{
    struct sctpna_data *nadata = cbdata;
    int new_fd;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct sctp_data *tdata = NULL;
    struct gensio_ll *ll;
    struct gensio *io;
    const char *errstr;
    int err;

    new_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
    if (new_fd == -1) {
	if (errno != EAGAIN && errno != EWOULDBLOCK)
	    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
			   "Could not accept: %s", strerror(errno));
	return;
    }

    tdata = nadata->o->zalloc(nadata->o, sizeof(*tdata));
    if (!tdata) {
	errstr = "Out of memory\r\n";
	write_nofail(new_fd, errstr, strlen(errstr));
	close(new_fd);
	return;
    }

    tdata->o = nadata->o;

    err = sctp_socket_setup(tdata, new_fd);
    if (err) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Error setting up sctp port: %s", strerror(err));
	close(new_fd);
	sctp_free(tdata);
	return;
    }

    ll = fd_gensio_ll_alloc(nadata->o, new_fd, &sctp_server_fd_ll_ops, tdata,
			    nadata->max_read_size);
    if (!ll) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Out of memory allocating sctp ll");
	close(new_fd);
	sctp_free(tdata);
	return;
    }

    io = base_gensio_server_alloc(nadata->o, ll, NULL, "sctp", NULL, NULL);
    if (!io) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Out of memory allocating sctp base");
	gensio_ll_free(ll);
	close(new_fd);
	sctp_free(tdata);
	return;
    }
    gensio_set_is_reliable(io, true);

    gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_NEW_CONNECTION, io);
}

static void
sctpna_fd_cleared(int fd, void *cbdata)
{
    struct sctpna_data *nadata = cbdata;
    struct gensio_accepter *accepter = nadata->acc;
    unsigned int num_left;

    close(fd);

    sctpna_lock(nadata);
    num_left = --nadata->nr_accept_close_waiting;
    sctpna_unlock(nadata);

    if (num_left == 0) {
	if (nadata->shutdown_done)
	    nadata->shutdown_done(accepter, nadata->shutdown_data);
	sctpna_lock(nadata);
	nadata->in_shutdown = false;
	sctpna_deref_and_unlock(nadata);
    }
}

static void
sctpna_set_fd_enables(struct sctpna_data *nadata, bool enable)
{
    struct gensio_os_funcs *o = nadata->o;
    unsigned int i;

    for (i = 0; i < nadata->nfds; i++)
	o->set_read_handler(o, nadata->fds[i].fd, enable);
}

static void
sctpna_shutdown_fds(struct sctpna_data *nadata)
{
    struct gensio_os_funcs *o = nadata->o;
    unsigned int i;

    if (!nadata->fds)
	return;

    for (i = 0; i < nadata->nfds; i++)
	close(nadata->fds[i].fd);
    nadata->nfds = 0;
    o->free(o, nadata->fds);
    nadata->fds = NULL;
}

static int
sctpna_startup(struct gensio_accepter *accepter)
{
    struct sctpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    struct gensio_os_funcs *o = nadata->o;
    struct addrinfo *ai;
    unsigned int i;
    int family = AF_INET6;
    int rv = 0;

    sctpna_lock(nadata);
    if (nadata->in_shutdown || nadata->setup) {
	rv = EBUSY;
	goto out_unlock;
    }

 retry:
    for (ai = nadata->ai; ai; ai = ai->ai_next) {
	struct sctpna_acceptfds *fds = nadata->fds;
	int port = gensio_sockaddr_get_port(ai->ai_addr);

	if (port == -1) {
	    rv = EINVAL;
	    goto out_err;
	}
	if (family != ai->ai_family)
	    continue;

	for (i = 0; i < nadata->nfds; i++) {
	    if (port == fds[i].port &&
		((fds[i].flags & AI_V4MAPPED) || fds[i].family == family)) {
		rv = sctp_bindx(fds[i].fd, ai->ai_addr, 1, SCTP_BINDX_ADD_ADDR);
		if (rv) {
		    rv = errno;
		    goto out_err;
		}
		break;
	    }
	}
	if (i < nadata->nfds)
	    continue; /* Port matched, already did bind. */

	/* Increate the fds array and open a new socket. */
	fds = o->zalloc(o, sizeof(*fds) * (i + 1));
	if (!fds) {
	    rv = ENOMEM;
	    goto out_err;
	}
	memcpy(fds, nadata->fds, sizeof(*fds) * i);

	rv = gensio_setup_listen_socket(o, true, ai->ai_family,
					SOCK_STREAM, IPPROTO_SCTP, ai->ai_flags,
					ai->ai_addr, ai->ai_addrlen,
					sctpna_readhandler, NULL, nadata,
					sctpna_fd_cleared,
					&fds[i].fd);
	if (rv)
	    goto out_err;
	fds[i].port = port;
	fds[i].family = ai->ai_family;
	fds[i].flags = ai->ai_flags;
	o->free(o, nadata->fds);
	nadata->fds = fds;
	nadata->nfds++;
    }
    if (family == AF_INET6) {
	family = AF_INET;
	goto retry;
    }

    if (nadata->nfds == 0) {
	rv = EINVAL;
	goto out_unlock;
    }

    nadata->setup = true;
    sctpna_set_fd_enables(nadata, true);
    nadata->enabled = true;
    nadata->shutdown_done = NULL;
    sctpna_ref(nadata);

 out_unlock:
    sctpna_unlock(nadata);
    return rv;

 out_err:
    sctpna_shutdown_fds(nadata);
    goto out_unlock;
}

static void
_sctpna_shutdown(struct sctpna_data *nadata,
		 gensio_acc_done shutdown_done, void *shutdown_data)
{
    unsigned int i;

    nadata->in_shutdown = true;
    nadata->shutdown_done = shutdown_done;
    nadata->shutdown_data = shutdown_data;
    nadata->nr_accept_close_waiting = nadata->nr_acceptfds;
    for (i = 0; i < nadata->nfds; i++)
	nadata->o->clear_fd_handlers(nadata->o, nadata->fds[i].fd);
    nadata->setup = false;
    nadata->enabled = false;
}

static int
sctpna_shutdown(struct gensio_accepter *accepter,
		gensio_acc_done shutdown_done, void *shutdown_data)
{
    struct sctpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    sctpna_lock(nadata);
    if (nadata->setup)
	_sctpna_shutdown(nadata, shutdown_done, shutdown_data);
    else
	rv = EBUSY;
    sctpna_unlock(nadata);

    return rv;
}

static void
sctpna_set_accept_callback_enable(struct gensio_accepter *accepter, bool enabled)
{
    struct sctpna_data *nadata = gensio_acc_get_gensio_data(accepter);

    sctpna_lock(nadata);
    if (nadata->enabled != enabled) {
	sctpna_set_fd_enables(nadata, enabled);
	nadata->enabled = enabled;
    }
    sctpna_unlock(nadata);
}

static void
sctpna_free(struct gensio_accepter *accepter)
{
    struct sctpna_data *nadata = gensio_acc_get_gensio_data(accepter);

    sctpna_lock(nadata);
    if (nadata->setup)
	_sctpna_shutdown(nadata, NULL, NULL);
    sctpna_deref_and_unlock(nadata);
}

int
sctpna_connect(struct gensio_accepter *accepter, void *addr,
	       gensio_done_err connect_done, void *cb_data,
	       struct gensio **new_net)
{
    struct sctpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    struct gensio *net;
    int err;
    char *args[2] = { NULL, NULL };
    char buf[100];

    if (nadata->max_read_size != GENSIO_DEFAULT_BUF_SIZE) {
	snprintf(buf, 100, "readbuf=%d", nadata->max_read_size);
	args[0] = buf;
    }
    err = sctp_gensio_alloc(addr, args, nadata->o, NULL, NULL, &net);
    if (err)
	return err;
    err = gensio_open(net, connect_done, cb_data);
    if (!err)
	*new_net = net;
    return err;
}

static int
gensio_acc_sctp_func(struct gensio_accepter *acc, int func, int val,
		     void *addr, void *done, void *data,
		     void *ret)
{
    switch (func) {
    case GENSIO_ACC_FUNC_STARTUP:
	return sctpna_startup(acc);

    case GENSIO_ACC_FUNC_SHUTDOWN:
	return sctpna_shutdown(acc, done, data);

    case GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK:
	sctpna_set_accept_callback_enable(acc, val);
	return 0;

    case GENSIO_ACC_FUNC_FREE:
	sctpna_free(acc);
	return 0;

    case GENSIO_ACC_FUNC_CONNECT:
	return sctpna_connect(acc, addr, done, data, ret);

    default:
	return ENOTSUP;
    }
}

int
sctp_gensio_accepter_alloc(struct addrinfo *iai, char *args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
    struct sctpna_data *nadata;
    unsigned int max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    int i;

    for (i = 0; args[i]; i++) {
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return ENOMEM;
    nadata->o = o;
    sctpna_ref(nadata);

    nadata->ai = gensio_dup_addrinfo(o, iai);
    if (!nadata->ai)
	goto out_nomem;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    nadata->acc = gensio_acc_data_alloc(o, cb, user_data, gensio_acc_sctp_func,
					NULL, "sctp", nadata);
    if (!nadata->acc)
	goto out_nomem;
    gensio_acc_set_is_reliable(nadata->acc, true);
    gensio_acc_set_is_packet(nadata->acc, true);

    nadata->max_read_size = max_read_size;

    *accepter = nadata->acc;
    return 0;

 out_nomem:
    sctpna_finish_free(nadata);
    return ENOMEM;
}

int
str_to_sctp_gensio_accepter(const char *str, char *args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb,
			    void *user_data,
			    struct gensio_accepter **acc)
{
    int err;
    struct addrinfo *ai;

    err = gensio_scan_netaddr(o, str, true, SOCK_STREAM, IPPROTO_SCTP, &ai);
    if (err)
	return err;

    err = sctp_gensio_accepter_alloc(ai, args, o, cb, user_data, acc);
    gensio_free_addrinfo(o, ai);

    return err;
}

#else

int
sctp_gensio_alloc(struct addrinfo *iai, char *args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return ENOTSUP;
}

int
str_to_sctp_gensio(const char *str, char *args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return ENOTSUP;
}

int
sctp_gensio_accepter_alloc(struct addrinfo *iai, char *args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
    return ENOTSUP;
}

int
str_to_sctp_gensio_accepter(const char *str, char *args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb,
			    void *user_data,
			    struct gensio_accepter **acc)
{
    return ENOTSUP;
}
#endif
