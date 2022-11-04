/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code handles TCP and Unix network I/O. */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if HAVE_UNIX
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <unistd.h>
#endif

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_osops.h>

#include "gensio_net.h"

struct net_data {
    struct gensio_os_funcs *o;

    struct gensio_ll *ll;

    struct gensio_addr *ai; /* Iterater points to the remote. */
    struct gensio_addr *lai; /* Local address, NULL if not set. */

    bool nodelay;

    bool istcp;

    int last_err;

    bool do_oob;
    int oob_char;
};

static int net_check_open(void *handler_data, struct gensio_iod *iod)
{
    struct net_data *tdata = handler_data;

    tdata->last_err = tdata->o->sock_control(iod, GENSIO_SOCKCTL_CHECK_OPEN,
					     NULL, NULL);
    return tdata->last_err;
}

static int
net_try_open(struct net_data *tdata, struct gensio_iod **iod)
{
    struct gensio_iod *new_iod = NULL;
    int err = GE_INUSE;
    int protocol = tdata->istcp ? GENSIO_NET_PROTOCOL_TCP
				: GENSIO_NET_PROTOCOL_UNIX;
    unsigned int setup = (GENSIO_SET_OPENSOCK_REUSEADDR |
			  GENSIO_OPENSOCK_REUSEADDR |
			  GENSIO_SET_OPENSOCK_KEEPALIVE |
			  GENSIO_SET_OPENSOCK_NODELAY);

    if (tdata->istcp)
	setup |= GENSIO_OPENSOCK_KEEPALIVE;
    if (tdata->nodelay)
	setup |= GENSIO_OPENSOCK_NODELAY;
 retry:
    err = tdata->o->socket_open(tdata->o, tdata->ai, protocol, &new_iod);
    if (err)
	goto out;

    err = tdata->o->socket_set_setup(new_iod, setup, tdata->lai);
    if (err)
	goto out;

    err = tdata->o->connect(new_iod, tdata->ai);
    if (err == GE_INPROGRESS) {
	*iod = new_iod;
	goto out_return;
    }

    /*
     * The GE_NOMEM check is strange here, but it really has more to
     * do with testing.  connect() is not going to return GE_NOMEM
     * unless it's an error trigger failure, and we really want to
     * fail in that case or we will get a "error triggered but no
     * failure" in the test.
     */
    if (err && err != GE_NOMEM) {
	if (gensio_addr_next(tdata->ai)) {
	    tdata->o->close(&new_iod);
	    goto retry;
	}
    }
 out:
    if (err) {
	if (new_iod)
	    tdata->o->close(&new_iod);
    } else {
	*iod = new_iod;
    }

 out_return:
    return err;
}

static int
net_retry_open(void *handler_data, struct gensio_iod **iod)
{
    struct net_data *tdata = handler_data;

    if (!gensio_addr_next(tdata->ai))
	return tdata->last_err;
    return net_try_open(tdata, iod);
}

static int
net_sub_open(void *handler_data, struct gensio_iod **iod)
{
    struct net_data *tdata = handler_data;

    gensio_addr_rewind(tdata->ai);
    return net_try_open(tdata, iod);
}

static void
net_free(void *handler_data)
{
    struct net_data *tdata = handler_data;

    if (tdata->ai)
	gensio_addr_free(tdata->ai);
    if (tdata->lai)
	gensio_addr_free(tdata->lai);
    tdata->o->free(tdata->o, tdata);
}

static int
net_control(void *handler_data, struct gensio_iod *iod, bool get,
	    unsigned int option, char *data, gensiods *datalen)
{
    struct net_data *tdata = handler_data;
    int rv, val;
    unsigned int i, setup;
    gensiods pos, size;
    struct gensio_addr *addr;

    switch (option) {
    case GENSIO_CONTROL_NODELAY:
	if (!tdata->istcp)
	    return GE_NOTSUP;
	if (get) {
	    if (iod) {
		setup = GENSIO_SET_OPENSOCK_NODELAY;
		rv = tdata->o->socket_get_setup(iod, &setup);
		if (rv)
		    return rv;
		val = !!(setup & GENSIO_OPENSOCK_NODELAY);
	    } else {
		val = tdata->nodelay;
	    }
	    *datalen = snprintf(data, *datalen, "%d", val);
	} else {
	    val = strtoul(data, NULL, 0);
	    if (iod) {
		setup = GENSIO_SET_OPENSOCK_NODELAY;
		if (val)
		    setup |= GENSIO_OPENSOCK_NODELAY;
		rv = tdata->o->socket_set_setup(iod, val, NULL);
		if (rv)
		    return rv;
	    }
	    tdata->nodelay = val;
	}
	return 0;

    case GENSIO_CONTROL_LADDR:
	if (!get)
	    return GE_NOTSUP;

	if (strtoul(data, NULL, 0) > 0)
	    return GE_NOTFOUND;

	rv = tdata->o->sock_control(iod, GENSIO_SOCKCTL_GET_SOCKNAME,
				    &addr, NULL);
	if (rv)
	    return rv;

	pos = 0;
	rv = gensio_addr_to_str(addr, data, &pos, *datalen);
	gensio_addr_free(addr);
	if (rv)
	    return rv;

	*datalen = pos;
	return 0;

    case GENSIO_CONTROL_RADDR:
	if (!get)
	    return GE_NOTSUP;

	if (strtoul(data, NULL, 0) > 0)
	    return GE_NOTFOUND;

	pos = 0;
	rv = gensio_addr_to_str(tdata->ai, data, &pos, *datalen);
	if (rv)
	    return rv;

	*datalen = pos;
	return 0;

    case GENSIO_CONTROL_RADDR_BIN:
	if (!get)
	    return GE_NOTSUP;
	gensio_addr_getaddr(tdata->ai, data, datalen);
	return 0;

    case GENSIO_CONTROL_LPORT:
	if (!get)
	    return GE_NOTSUP;
	size = sizeof(unsigned int);
	rv = tdata->o->sock_control(iod, GENSIO_SOCKCTL_GET_PORT, &i, &size);
	if (rv)
	    return rv;
	*datalen = snprintf(data, *datalen, "%d", i);
	return 0;

    case GENSIO_CONTROL_ENABLE_OOB:
	if (get)
	    *datalen = snprintf(data, *datalen, "%u", tdata->do_oob);
	else
	    tdata->do_oob = !!strtoul(data, NULL, 0);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
net_except_read(struct gensio_iod *iod, void *data, gensiods count,
		gensiods *rcount, const char ***auxdata, void *cb_data)
{
    struct net_data *tdata = cb_data;
    static const char *argv[3] = { "oob", "oobtcp", NULL };

    if (tdata->oob_char >= 0) {
	if (tdata->do_oob) {
	    *auxdata = argv;
	    if (count == 0) {
		*rcount = 0;
		return 0;
	    }
	    *((unsigned char *) data) = tdata->oob_char;
	    tdata->oob_char = -1;
	    *rcount = 1;
	    return 0;
	}
	tdata->oob_char = -1;
    }

    return tdata->o->recv(iod, data, count, rcount, 0);
}

static int
net_except_ready(void *handler_data, struct gensio_iod *iod)
{
    struct net_data *tdata = handler_data;
    unsigned char urgdata;
    gensiods rcount = 0;
    int rv;

    if (!tdata->istcp)
	return GE_NOTSUP;

    rv = tdata->o->recv(iod, &urgdata, 1, &rcount, GENSIO_MSG_OOB);
    if (rv || rcount == 0)
	return GE_NOTSUP;

    tdata->oob_char = urgdata;
    gensio_fd_ll_handle_incoming(tdata->ll, net_except_read, NULL, tdata);
    return 0;
}

static int
net_write(void *handler_data, struct gensio_iod *iod, gensiods *rcount,
	  const struct gensio_sg *sg, gensiods sglen,
	  const char *const *auxdata)
{
    struct net_data *tdata = handler_data;
    int flags = 0;

    if (auxdata) {
	int i;

	for (i = 0; auxdata[i]; i++) {
	    if (strcasecmp(auxdata[i], "oob") == 0)
		flags |= GENSIO_MSG_OOB;
	    else if (strcasecmp(auxdata[i], "oobtcp") == 0)
		flags |= GENSIO_MSG_OOB;
	    else
		return GE_INVAL;
	}
    }

    return tdata->o->send(iod, sg, sglen, rcount, flags);
}

static int
net_check_close(void *handler_data, struct gensio_iod *iod,
		enum gensio_ll_close_state state,
		gensio_time *timeout)
{
    struct net_data *tdata = handler_data;
    int err;

    if (state == GENSIO_LL_CLOSE_STATE_START)
	return 0;

    err = tdata->o->graceful_close(&iod);
    if (err == GE_INPROGRESS && timeout) {
	timeout->secs = 0;
	timeout->nsecs = 1000000;
    }
    return err;
}

static const struct gensio_fd_ll_ops net_fd_ll_ops = {
    .sub_open = net_sub_open,
    .check_open = net_check_open,
    .retry_open = net_retry_open,
    .free = net_free,
    .control = net_control,
    .except_ready = net_except_ready,
    .write = net_write,
    .check_close = net_check_close
};

static int
net_gensio_alloc(const struct gensio_addr *iai, const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data, const char *type,
		 struct gensio **new_gensio)
{
    struct net_data *tdata = NULL;
    struct gensio_addr *laddr = NULL, *laddr2, *addr = NULL;
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
				 GENSIO_NET_PROTOCOL_TCP, true, false, &laddr);
    if (err && err != GE_NOTSUP) {
	gensio_log(o, GENSIO_LOG_ERR, "Invalid default %d laddr: %s",
		   type, gensio_err_to_str(err));
	return err;
    }

    err = gensio_get_default(o, type, "nodelay", false,
			     GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    nodelay = ival;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (istcp && gensio_check_keyaddrs(o, args[i], "laddr",
					   GENSIO_NET_PROTOCOL_TCP,
					   true, false, &laddr2) > 0) {
	    if (laddr)
		gensio_addr_free(laddr);
	    laddr = laddr2;
	    continue;
	}
	if (istcp && gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;

	if (laddr)
	    gensio_addr_free(laddr);
	return GE_INVAL;
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata)
	goto out_nomem;

    tdata->istcp = istcp;
    tdata->oob_char = -1;

    addr = gensio_addr_dup(iai);
    if (!addr)
	goto out_nomem;

    tdata->o = o;
    tdata->nodelay = nodelay;

    tdata->ll = fd_gensio_ll_alloc(o, NULL, &net_fd_ll_ops, tdata,
				   max_read_size, false);
    if (!tdata->ll)
	goto out_nomem;

    io = base_gensio_alloc(o, tdata->ll, NULL, NULL, type, cb, user_data);
    if (!io)
	goto out_nomem;

    /* Assign these last so gensio_ll_free() won't free it on err. */
    tdata->ai = addr;
    tdata->lai = laddr;

    gensio_set_is_reliable(io, true);

    *new_gensio = io;
    return 0;

 out_nomem:
    if (laddr)
	gensio_addr_free(laddr);
    if (addr)
	gensio_addr_free(addr);
    if (tdata) {
	if (tdata->ll)
	    gensio_ll_free(tdata->ll);
	else
	    /* gensio_ll_free() frees it otherwise. */
	    o->free(o, tdata);
    }
    return GE_NOMEM;
}

static int
str_to_net_gensio(const char *str, const char * const args[],
		  int protocol, const char *typestr,
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    struct gensio_addr *addr;
    int err;

    err = gensio_os_scan_netaddr(o, str, false, protocol, &addr);
    if (err)
	return err;

    err = net_gensio_alloc(addr, args, o, cb, user_data, typestr, new_gensio);
    gensio_addr_free(addr);

    return err;
}

static int
tcp_gensio_alloc(const void *gdata, const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
    const struct gensio_addr *iai = gdata;

    return net_gensio_alloc(iai, args, o, cb, user_data, "tcp", new_gensio);
}

static int
str_to_tcp_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return str_to_net_gensio(str, args, GENSIO_NET_PROTOCOL_TCP, "tcp",
			     o, cb, user_data, new_gensio);
}

static int
unix_gensio_alloc(const void *gdata, const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
#if HAVE_UNIX
    const struct gensio_addr *iai = gdata;

    return net_gensio_alloc(iai, args, o, cb, user_data, "unix", new_gensio);
#else
    return GE_NOTSUP;
#endif
}

static int
str_to_unix_gensio(const char *str, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    return str_to_net_gensio(str, args, GENSIO_NET_PROTOCOL_UNIX, "unix",
			     o, cb, user_data, new_gensio);
}

struct netna_data {
    struct gensio_accepter *acc;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_runner *cb_en_done_runner;

    gensiods max_read_size;
    bool nodelay;

    gensio_acc_done shutdown_done;
    gensio_acc_done cb_en_done;

    struct gensio_addr *ai;		/* The address list for the portname. */
    struct gensio_opensocks *acceptfds;	/* The file descriptor used to
					   accept connections on the
					   NET port. */
#if HAVE_UNIX
    mode_t mode;
    bool mode_set;
    char *owner;
    char *group;
#endif

#ifdef HAVE_TCPD_H
    enum gensio_tcpd_options tcpd;
    char *tcpd_progname;
#endif

    unsigned int   nr_acceptfds;
    unsigned int   nr_accept_close_waiting;

    unsigned int opensock_flags;

    bool istcp;
};

static const struct gensio_fd_ll_ops net_server_fd_ll_ops = {
    .free = net_free,
    .control = net_control,
    .except_ready = net_except_ready,
    .write = net_write
};

static void
netna_fd_cleared(struct gensio_iod *iod, void *cbdata)
{
    struct netna_data *nadata = cbdata;
    unsigned int num_left, i;

    for (i = 0; i < nadata->nr_acceptfds; i++) {
	if (iod == nadata->acceptfds[i].iod)
	    break;
    }
    assert(i < nadata->nr_acceptfds);
    nadata->o->close(&nadata->acceptfds[i].iod);

    nadata->o->lock(nadata->lock);
    assert(nadata->nr_accept_close_waiting > 0);
    num_left = --nadata->nr_accept_close_waiting;
    if (num_left == 0) {
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
	nadata->o->set_read_handler(nadata->acceptfds[i].iod, enable);
}

static void
netna_finish_server_open(struct gensio *net, int err, void *cb_data)
{
    struct netna_data *nadata = cb_data;

    base_gensio_server_open_done(nadata->acc, net, err);
}

static void
netna_readhandler(struct gensio_iod *iod, void *cbdata)
{
    struct netna_data *nadata = cbdata;
    struct gensio_iod *new_iod = NULL;
    struct gensio_addr *raddr;
    struct net_data *tdata = NULL;
    struct gensio *io = NULL;
    unsigned int setup = (GENSIO_SET_OPENSOCK_REUSEADDR |
			  GENSIO_OPENSOCK_REUSEADDR |
			  GENSIO_SET_OPENSOCK_KEEPALIVE |
			  GENSIO_SET_OPENSOCK_NODELAY);
    int err;

    err = nadata->o->accept(iod, &raddr, &new_iod);
    if (err) {
	if (err != GE_NODATA)
	    /* FIXME - maybe shut down the socket I/O? */
	    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
			   "Error accepting net gensio: %s",
			   gensio_err_to_str(err));
	return;
    }

    err = base_gensio_accepter_new_child_start(nadata->acc);
    if (err) {
	gensio_addr_free(raddr);
	nadata->o->close(&new_iod);
	return;
    }

#ifdef HAVE_TCPD_H
    if (nadata->istcp && nadata->tcpd != GENSIO_TCPD_OFF) {
	const char *msg = gensio_os_check_tcpd_ok(new_iod,
						  nadata->tcpd_progname);

	if (msg) {
	    if (nadata->tcpd == GENSIO_TCPD_PRINT) {
		struct gensio_sg sg[1] = { { msg, strlen(msg) } };
		nadata->o->send(new_iod, sg, 1, NULL, 0);
	    }
	    gensio_acc_log(nadata->acc, GENSIO_LOG_INFO,
			   "Error accepting net gensio: tcpd check failed");
	    err = GE_INVAL;
	    goto out_err;
	}
    }
#endif

    tdata = nadata->o->zalloc(nadata->o, sizeof(*tdata));
    if (!tdata) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_INFO,
		       "Error accepting net gensio: out of memory");
	err = GE_NOMEM;
	goto out_err;
    }

    tdata->o = nadata->o;
    tdata->oob_char = -1;
    tdata->ai = raddr;
    tdata->istcp = nadata->istcp;
    tdata->nodelay = nadata->nodelay;
    raddr = NULL;

    if (tdata->istcp)
	setup |= GENSIO_OPENSOCK_KEEPALIVE;
    if (tdata->nodelay)
	setup |= GENSIO_OPENSOCK_NODELAY;
    err = tdata->o->socket_set_setup(new_iod, setup, NULL);
    if (err) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Error setting up net port: %s", gensio_err_to_str(err));
	goto out_err;
    }

    tdata->ll = fd_gensio_ll_alloc(nadata->o, new_iod, &net_server_fd_ll_ops,
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
    base_gensio_accepter_new_child_end(nadata->acc, NULL, err);
    if (io) {
	gensio_free(io);
	return;
    }
    if (tdata) {
	if (tdata->ll) {
	    gensio_ll_free(tdata->ll);
	    return;
	}

	/* gensio_ll_free() frees it otherwise. */
	net_free(tdata);
    }
    if (raddr)
	gensio_addr_free(raddr);
    if (new_iod)
	nadata->o->close(&new_iod);
}

#if HAVE_UNIX
#define MAX_UNIX_ADDR_PATH (sizeof(((struct sockaddr_un *) 0)->sun_path) + 1)
static void
get_unix_addr_path(struct gensio_addr *addr, char *path)
{
    struct sockaddr_storage taddr;
    struct sockaddr_un *sun = (struct sockaddr_un *) &taddr;
    gensiods len = sizeof(taddr);

    /* Remove the socket if it already exists. */
    gensio_addr_getaddr(addr, sun, &len);

    /*
     * Make sure the path is nil terminated.  See discussions
     * in the unix(7) man page on Linux for details.
     */
    memcpy(path, sun->sun_path, len - sizeof(sa_family_t));
    path[len - sizeof(sa_family_t)] = '\0';
}
#endif

static void
netna_rm_unix_socket(struct gensio_addr *addr)
{
#if HAVE_UNIX
    char path[MAX_UNIX_ADDR_PATH];

    /* Remove the socket if it already exists. */
    get_unix_addr_path(addr, path);
    unlink(path);
#endif
}

static int
netna_b4_listen(struct gensio_iod *iod, void *data)
{
    struct netna_data *nadata = data;
#if HAVE_UNIX
    char pwbuf[16384];
    uid_t ownerid = -1;
    uid_t groupid = -1;
    int err;
    char unpath[MAX_UNIX_ADDR_PATH];
#endif

    if (nadata->istcp)
	return 0;

#if HAVE_UNIX
    get_unix_addr_path(nadata->ai, unpath);

    /* Set up perms for Unix domain sockets. */
    if (nadata->mode_set) {
	err = chmod(unpath, nadata->mode);
	if (err)
	    goto out_errno;
    }

    if (nadata->owner) {
	struct passwd pwdbuf, *pwd;

	err = getpwnam_r(nadata->owner, &pwdbuf, pwbuf, sizeof(pwbuf), &pwd);
	if (err)
	    goto out_errno;
	if (!pwd) {
	    err = ENOENT;
	    goto out_err;
	}
	ownerid = pwd->pw_uid;
    }

    if (nadata->group) {
	struct group grpbuf, *grp;


	err = getgrnam_r(nadata->group, &grpbuf, pwbuf, sizeof(pwbuf), &grp);
	if (err)
	    goto out_errno;
	if (!grp) {
	    err = ENOENT;
	    goto out_err;
	}
	groupid = grp->gr_gid;
    }

    if (ownerid != -1 || groupid != -1) {
	err = chown(unpath, ownerid, groupid);
	if (err)
	    goto out_errno;
    }
    return 0;

 out_errno:
    err = errno;
 out_err:
    return gensio_os_err_to_err(nadata->o, err);
#else
    return GE_NOTSUP;
#endif
}

static int
netna_startup(struct gensio_accepter *accepter, struct netna_data *nadata)
{
    int rv;

    rv = gensio_os_open_listen_sockets(nadata->o, nadata->ai,
			       netna_readhandler,
			       NULL, netna_fd_cleared, netna_b4_listen, nadata,
			       nadata->opensock_flags,
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
	nadata->o->clear_fd_handlers(nadata->acceptfds[i].iod);

    if (!nadata->istcp)
	/* Remove the socket. */
	netna_rm_unix_socket(nadata->ai);

    return 0;
}

static void
netna_cb_en_done(struct gensio_runner *runner, void *cb_data)
{
    struct netna_data *nadata = cb_data;
    gensio_acc_done done = nadata->cb_en_done;

    nadata->cb_en_done = NULL;
    done(nadata->acc, NULL);
}

static int
netna_set_accept_callback_enable(struct gensio_accepter *accepter,
				 struct netna_data *nadata,
				 bool enabled,
				 gensio_acc_done done)
{
    unsigned int i;

    if (nadata->cb_en_done)
	return GE_INUSE;

    nadata->cb_en_done = done;
    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->set_read_handler(nadata->acceptfds[i].iod, enabled);

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
	gensio_addr_free(nadata->ai);
#if HAVE_UNIX
    if (nadata->owner)
	nadata->o->free(nadata->o, nadata->owner);
    if (nadata->group)
	nadata->o->free(nadata->o, nadata->group);
#endif
#ifdef HAVE_TCPD_H
    if (nadata->tcpd_progname)
	nadata->o->free(nadata->o, nadata->tcpd_progname);
#endif
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
    struct gensio_addr *ai;
    const char *laddr = NULL, *dummy;
    bool is_port_set;
    int protocol = 0;
    bool nodelay = false;

    err = gensio_scan_network_port(nadata->o, addr, false, &ai,
				   &protocol, &is_port_set, NULL, &iargs);
    if (err)
	return err;

    err = GE_INVAL;
    if (nadata->istcp) {
	if (protocol != GENSIO_NET_PROTOCOL_TCP || !is_port_set)
	    goto out_err;
    } else {
	if (protocol != GENSIO_NET_PROTOCOL_UNIX)
	    goto out_err;
    }

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
    gensio_addr_free(ai);

    return err;
}

static int
netna_control_laddr(struct netna_data *nadata, bool get,
		    char *data, gensiods *datalen)
{
    unsigned int i;
    gensiods pos = 0;
    struct gensio_addr *addr;
    int rv;

    if (!get)
	return GE_NOTSUP;

    if (nadata->nr_acceptfds == 0)
	return GE_NOTREADY;

    i = strtoul(data, NULL, 0);
    if (i >= nadata->nr_acceptfds)
	return GE_NOTFOUND;

    rv = nadata->o->sock_control(nadata->acceptfds[i].iod,
				 GENSIO_SOCKCTL_GET_SOCKNAME,
				 &addr, NULL);
    if (rv)
	return rv;

    rv = gensio_addr_to_str(addr, data, &pos, *datalen);
    gensio_addr_free(addr);
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

#ifdef HAVE_TCPD_H
    case GENSIO_ACC_CONTROL_TCPDNAME:
	if (get) {
	    if (!nadata->tcpd_progname)
		return GE_NODATA;
	    *datalen = snprintf(data, *datalen, "%s", nadata->tcpd_progname);
	} else {
	    char *newval = strdup(data);

	    if (!newval)
		return GE_NOMEM;
	    if (nadata->tcpd_progname)
		nadata->o->free(nadata->o, nadata->tcpd_progname);
	    nadata->tcpd_progname = newval;
	}
	return 0;
#endif

    default:
	return GE_NOTSUP;
    }
}

static void
netna_disable(struct gensio_accepter *accepter, struct netna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->clear_fd_handlers_norpt(nadata->acceptfds[i].iod);
    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->close(&nadata->acceptfds[i].iod);
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

#ifdef HAVE_TCPD_H
static struct gensio_enum_val tcpd_enums[] = {
    { "on",	GENSIO_TCPD_ON },
    { "print",	GENSIO_TCPD_PRINT },
    { "off", 	GENSIO_TCPD_OFF },
    { NULL }
};
#endif

static int
net_gensio_accepter_alloc(const struct gensio_addr *iai,
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
    bool reuseaddr = istcp ? true : false;
#if HAVE_UNIX
    unsigned int umode = 6, gmode = 6, omode = 6, mode;
    bool mode_set = false;
    const char *owner = NULL, *group = NULL;
#endif
#ifdef HAVE_TCPD_H
    const char *tcpdname = NULL;
    enum gensio_tcpd_options tcpd = GENSIO_TCPD_ON;
#endif
    unsigned int i;
    int err, ival;

    if (istcp) {
	err = gensio_get_default(o, type, "reuseaddr", false,
				 GENSIO_DEFAULT_BOOL, NULL, &ival);
	if (err)
	    return err;
    } else {
	err = gensio_get_default(o, type, "delsock", false,
				 GENSIO_DEFAULT_BOOL, NULL, &ival);
	if (err)
	    return err;
    }
    reuseaddr = ival;

#ifdef HAVE_TCPD_H
    err = gensio_get_default(o, type, "tcpd", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    tcpd = ival;
#endif

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (istcp && gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;
	if (!istcp &&
		gensio_check_keybool(args[i], "delsock", &reuseaddr) > 0)
	    continue;
	if (istcp &&
		gensio_check_keybool(args[i], "reuseaddr", &reuseaddr) > 0)
	    continue;
#ifdef HAVE_TCPD_H
	if (istcp && gensio_check_keyvalue(args[i], "tcpdname", &tcpdname))
	    continue;
	if (istcp && gensio_check_keyenum(args[i], "tcpd",
					  tcpd_enums, &ival) > 0) {
	    tcpd = ival;
	    continue;
	}
#endif
#if HAVE_UNIX
	if (!istcp && gensio_check_keymode(args[i], "umode", &umode) > 0) {
	    mode_set = true;
	    continue;
	}
	if (!istcp && gensio_check_keymode(args[i], "gmode", &gmode) > 0) {
	    mode_set = true;
	    continue;
	}
	if (!istcp && gensio_check_keymode(args[i], "omode", &omode) > 0) {
	    mode_set = true;
	    continue;
	}
	if (!istcp && gensio_check_keyperm(args[i], "perm", &mode) > 0) {
	    mode_set = true;
	    umode = mode >> 6 & 7;
	    gmode = mode >> 3 & 7;
	    omode = mode & 7;
	    continue;
	}
	if (!istcp && gensio_check_keyvalue(args[i], "owner", &owner))
	    continue;
	if (!istcp && gensio_check_keyvalue(args[i], "group", &group))
	    continue;
#endif
	return GE_INVAL;
    }

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;
    nadata->o = o;

    err = GE_NOMEM;
    if (reuseaddr)
	nadata->opensock_flags |= GENSIO_OPENSOCK_REUSEADDR;
#if HAVE_UNIX
    nadata->mode_set = mode_set;
    nadata->mode = umode << 6 | gmode << 3 | omode;
    if (owner) {
	nadata->owner = gensio_strdup(o, owner);
	if (!nadata->owner)
	    goto out_err;
    }
    if (group) {
	nadata->group = gensio_strdup(o, group);
	if (!nadata->group)
	    goto out_err;
    }
#endif

#ifdef HAVE_TCPD_H
    nadata->tcpd = tcpd;
    if (tcpdname)
	nadata->tcpd_progname = strdup(tcpdname);
#endif

    nadata->ai = gensio_addr_dup(iai);
    if (!nadata->ai)
	goto out_err;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_err;

    nadata->cb_en_done_runner = o->alloc_runner(o, netna_cb_en_done, nadata);
    if (!nadata->cb_en_done_runner)
	goto out_err;

    nadata->istcp = istcp;

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

static int
str_to_net_gensio_accepter(const char *str, const char * const args[],
			   int protocol, const char *typestr,
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb,
			   void *user_data,
			   struct gensio_accepter **acc)
{
    int err;
    struct gensio_addr *ai;

    err = gensio_os_scan_netaddr(o, str, true, protocol, &ai);
    if (err)
	return err;

    err = net_gensio_accepter_alloc(ai, args, o, cb, user_data, typestr, acc);
    gensio_addr_free(ai);

    return err;
}

static int
tcp_gensio_accepter_alloc(const void *gdata,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_accepter_event cb, void *user_data,
			  struct gensio_accepter **accepter)
{
    const struct gensio_addr *iai = gdata;

    return net_gensio_accepter_alloc(iai, args, o, cb, user_data, "tcp",
				     accepter);
}

static int
str_to_tcp_gensio_accepter(const char *str, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb,
			   void *user_data,
			   struct gensio_accepter **acc)
{
    return str_to_net_gensio_accepter(str, args, GENSIO_NET_PROTOCOL_TCP, "tcp",
				      o, cb, user_data, acc);
}

static int
unix_gensio_accepter_alloc(const void *gdata,
			   const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
#if HAVE_UNIX
    const struct gensio_addr *iai = gdata;

    return net_gensio_accepter_alloc(iai, args, o, cb, user_data, "unix",
				     accepter);
#else
    return GE_NOTSUP;
#endif
}

static int
str_to_unix_gensio_accepter(const char *str, const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb,
			    void *user_data,
			    struct gensio_accepter **acc)
{
    return str_to_net_gensio_accepter(str, args, GENSIO_NET_PROTOCOL_UNIX,
				      "unix", o, cb, user_data, acc);
}

int
gensio_init_net(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "tcp", str_to_tcp_gensio, tcp_gensio_alloc);
    if (rv)
	return rv;
    rv = register_gensio_accepter(o, "tcp", str_to_tcp_gensio_accepter,
				  tcp_gensio_accepter_alloc);
    if (rv)
	return rv;
    rv = register_gensio(o, "unix", str_to_unix_gensio, unix_gensio_alloc);
    if (rv)
	return rv;
    rv = register_gensio_accepter(o, "unix", str_to_unix_gensio_accepter,
				  unix_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
