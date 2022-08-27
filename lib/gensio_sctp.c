/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code handles SCTP network I/O. */

#include "config.h"
#include <gensio/gensio_err.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_osops.h>

struct sctp_data {
    struct gensio_os_funcs *o;

    struct gensio_ll *ll;

    struct gensio_iod *iod;

    struct gensio_addr *addr;
    struct gensio_addr *laddr; /* Local address, NULL if not set. */

    struct sctp_initmsg initmsg;
    struct sctp_sack_info sackinfo;

    bool nodelay;
    bool do_oob;
    unsigned int instreams;
    unsigned int ostreams;

    char **strind;

    const char *auxdata[3];
};

static int
sctp_setup(struct sctp_data *tdata)
{
    struct gensio_os_funcs *o = tdata->o;
    struct sctp_status status;
    unsigned int i;
    int err;

    err = o->sctp_get_socket_status(tdata->iod, &status);
    if (err)
	return err;

    tdata->instreams = status.sstat_instrms;
    tdata->ostreams = status.sstat_outstrms;

    tdata->strind = o->zalloc(o, sizeof(char *) * tdata->instreams);
    if (!tdata->strind)
	return GE_NOMEM;

    for (i = 1; i < tdata->instreams; i++) {
	tdata->strind[i] = o->zalloc(o, 17);
	if (!tdata->strind[i])
	    return GE_NOMEM;
	snprintf(tdata->strind[i], 17, "stream=%d", i);
    }

    return 0;
}

static int sctp_check_open(void *handler_data, struct gensio_iod *iod)
{
    struct sctp_data *tdata = handler_data;
    int err;

    err = tdata->o->sock_control(iod, GENSIO_SOCKCTL_CHECK_OPEN, NULL, NULL);
    if (!err)
	err = sctp_setup(tdata);

    return err;
}

static int
sctp_socket_setup(struct sctp_data *tdata, struct gensio_iod *iod)
{
    int err;
    unsigned int setup = (GENSIO_SET_OPENSOCK_REUSEADDR |
			  GENSIO_OPENSOCK_REUSEADDR |
			  GENSIO_SET_OPENSOCK_KEEPALIVE |
			  GENSIO_OPENSOCK_KEEPALIVE |
			  GENSIO_SET_OPENSOCK_NODELAY);

    if (tdata->nodelay)
	setup |= GENSIO_OPENSOCK_NODELAY;
    err = tdata->o->socket_set_setup(iod, setup, tdata->laddr);
    if (err)
	return err;

    return tdata->o->sctp_socket_setup(iod, true, &tdata->initmsg,
				       &tdata->sackinfo);
}

static int
sctp_try_open(struct sctp_data *tdata, struct gensio_iod **iod)
{
    int err = GE_INUSE;

    err = tdata->o->socket_open(tdata->o, tdata->addr,
				GENSIO_NET_PROTOCOL_SCTP, &tdata->iod);
    if (err)
	goto out;

    err = sctp_socket_setup(tdata, tdata->iod);
    if (err)
	goto out;

    err = tdata->o->sctp_connectx(tdata->iod, tdata->addr);
    if (err == GE_INPROGRESS) {
	*iod = tdata->iod;
	goto out_return;
    } else if (err) {
	goto out;
    }

    err = sctp_setup(tdata);

 out:
    if (err) {
	if (tdata->iod)
	    tdata->o->close(&tdata->iod);
    } else {
	*iod = tdata->iod;
    }

 out_return:
    return err;
}

static int
sctp_sub_open(void *handler_data, struct gensio_iod **iod)
{
    struct sctp_data *tdata = handler_data;

    return sctp_try_open(tdata, iod);
}

static void
sctp_free(void *handler_data)
{
    struct sctp_data *tdata = handler_data;

    if (tdata->addr)
	gensio_addr_free(tdata->addr);
    if (tdata->laddr)
	gensio_addr_free(tdata->laddr);
    if (tdata->strind) {
	unsigned int i;

	for (i = 1; i < tdata->instreams; i++) {
	    if (tdata->strind[i])
		tdata->o->free(tdata->o, tdata->strind[i]);
	}
	tdata->o->free(tdata->o, tdata->strind);
    }
    tdata->o->free(tdata->o, tdata);
}

static int
sctp_control(void *handler_data, struct gensio_iod *iod, bool get, unsigned int option,
	     char *data, gensiods *datalen)
{
    struct sctp_data *tdata = handler_data;
    int rv, val;
    unsigned int i, setup;
    gensiods pos, size;
    struct gensio_addr *addr;

    switch (option) {
    case GENSIO_CONTROL_NODELAY:
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

    case GENSIO_CONTROL_STREAMS:
	if (!get)
	    return GE_INVAL;
	*datalen = snprintf(data, *datalen,
			    "instreams=%u,ostreams=%u", tdata->instreams,
			    tdata->ostreams);
	return 0;

    case GENSIO_CONTROL_LADDR:
	if (!get)
	    return GE_NOTSUP;

	i = strtoul(data, NULL, 0);
	if (i > 0)
	    return GE_NOTFOUND;

	rv = tdata->o->sock_control(iod, GENSIO_SOCKCTL_GET_SOCKNAME,
				    &addr, NULL);
	if (rv)
	    return rv;

	pos = 0;
	rv = gensio_addr_to_str_all(addr, data, &pos, *datalen);
	gensio_addr_free(addr);
	if (rv)
	    return rv;

	*datalen = pos;
	return 0;

    case GENSIO_CONTROL_RADDR:
	if (!get)
	    return GE_NOTSUP;

	i = strtoul(data, NULL, 0);
	if (i > 0)
	    return GE_NOTFOUND;

	rv = tdata->o->sock_control(iod, GENSIO_SOCKCTL_GET_PEERNAME,
				    &addr, NULL);
	if (rv)
	    return rv;

	pos = 0;
	rv = gensio_addr_to_str_all(addr, data, &pos, *datalen);
	gensio_addr_free(addr);
	if (rv)
	    return rv;

	*datalen = pos;
	return 0;

    case GENSIO_CONTROL_RADDR_BIN:
	if (!get)
	    return GE_NOTSUP;
	return tdata->o->sock_control(tdata->iod, GENSIO_SOCKCTL_GET_PEERRAW,
				      data, datalen);

    case GENSIO_CONTROL_LPORT:
	size = sizeof(unsigned int);
	rv = tdata->o->sock_control(iod, GENSIO_SOCKCTL_GET_PORT, &i, &size);
	if (rv)
	    return rv;
	*datalen = snprintf(data, *datalen, "%d", i);
	return 0;

    case GENSIO_CONTROL_CONNECT_ADDR_STR:
	if (!get)
	    return GE_INVAL;
	pos = 0;
	rv = gensio_addr_to_str_all(tdata->addr, data, &pos, *datalen);
	if (rv)
	    return rv;
	*datalen = pos;
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
sctp_write(void *handler_data, struct gensio_iod *iod, gensiods *rcount,
	  const struct gensio_sg *sg, gensiods sglen,
	  const char *const *auxdata)
{
    struct sctp_data *tdata = handler_data;
    struct sctp_sndrcvinfo sinfo;
    unsigned int stream = 0, i;

    memset(&sinfo, 0, sizeof(sinfo));

    if (auxdata) {
	for (i = 0; auxdata[i]; i++) {
	    if (gensio_check_keyuint(auxdata[i], "stream", &stream) > 0)
		continue;
	    if (strcasecmp(auxdata[i], "oob") == 0) {
		sinfo.sinfo_flags |= SCTP_UNORDERED;
		continue;
	    }
	    return GE_INVAL;
	}
    }

    sinfo.sinfo_stream = stream;
    return tdata->o->sctp_send(tdata->iod, sg, sglen, rcount, &sinfo, 0);
}

static int
sctp_do_read(struct gensio_iod *iod, void *data, gensiods count, gensiods *rcount,
	     const char ***auxdata, void *cb_data)
{
    struct sctp_data *tdata = cb_data;
    int rv;
    struct sctp_sndrcvinfo sinfo;
    int flags = 0;
    unsigned int stream;
    unsigned int i;

 restart:
    rv = tdata->o->sctp_recvmsg(iod, data, count, rcount, &sinfo, &flags);
    /* If the data length is zero, we won't have any info. */
    if (rv || *rcount == 0)
	return rv;

    stream = sinfo.sinfo_stream;
    /* Shouldn't happen, but just in case. */
    assert(stream < tdata->instreams);

    i = 0;
    if (tdata->strind[stream])
	(*auxdata)[i++] = tdata->strind[stream];

    if (sinfo.sinfo_flags && SCTP_UNORDERED) {
	if (!tdata->do_oob)
	    goto restart;
	(*auxdata)[i++] = "oob";
    }

    (*auxdata)[i] = NULL;

    return rv;
}

static void
sctp_read_ready(void *handler_data, struct gensio_iod *iod)
{
    struct sctp_data *tdata = handler_data;

    gensio_fd_ll_handle_incoming(tdata->ll, sctp_do_read, tdata->auxdata,
				 tdata);
}

static const struct gensio_fd_ll_ops sctp_fd_ll_ops = {
    .sub_open = sctp_sub_open,
    .check_open = sctp_check_open,
    .free = sctp_free,
    .control = sctp_control,
    .write = sctp_write,
    .read_ready = sctp_read_ready
};

static int
sctp_gensio_alloc(const void *gdata, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    const struct gensio_addr *iai = gdata;
    struct sctp_data *tdata = NULL;
    struct gensio *io;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    unsigned int instreams = 1, ostreams = 1;
    unsigned int sack_freq = 1, sack_delay = 10;
    int i, err, ival;
    struct gensio_addr *addr, *laddr = NULL;
    bool nodelay = false;

    err = gensio_get_default(o, "sctp", "nodelay", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    nodelay = ival;

    err = gensio_get_default(o, "sctp", "instreams", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    instreams = ival;

    err = gensio_get_default(o, "sctp", "ostreams", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    ostreams = ival;

    err = gensio_get_default(o, "sctp", "sack_freq", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    sack_freq = ival;

    err = gensio_get_default(o, "sctp", "sack_delay", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    sack_delay = ival;

    err = gensio_get_defaultaddr(o, "sctp", "laddr", false,
				 GENSIO_NET_PROTOCOL_SCTP, true, false, &laddr);
    if (err && err != GE_NOTSUP) {
	gensio_log(o, GENSIO_LOG_ERR, "Invalid default sctp laddr: %s",
		   gensio_err_to_str(err));
	return err;
    }

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyaddrs(o, args[i], "laddr",
				  GENSIO_NET_PROTOCOL_SCTP,
				  true, false, &laddr) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "instreams", &instreams) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "ostreams", &ostreams) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "sack_freq", &sack_freq) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "sack_delay", &sack_delay) > 0)
	    continue;
	err = GE_INVAL;
	goto out_err;
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata) {
	err = GE_NOMEM;
	goto out_err;
    }

    addr = gensio_addr_dup(iai);
    if (!addr)
	goto out_nomem;

    tdata->o = o;
    tdata->addr = addr;
    tdata->laddr = laddr;
    tdata->initmsg.sinit_max_instreams = instreams;
    tdata->initmsg.sinit_num_ostreams = ostreams;
    tdata->sackinfo.sack_freq = sack_freq;
    tdata->sackinfo.sack_delay = sack_delay;
    tdata->nodelay = nodelay;

    tdata->ll = fd_gensio_ll_alloc(o, NULL, &sctp_fd_ll_ops, tdata,
				   max_read_size, false);
    if (!tdata->ll)
	goto out_nomem;

    io = base_gensio_alloc(o, tdata->ll, NULL, NULL, "sctp", cb, user_data);
    if (!io)
	goto out_nomem;

    gensio_set_is_reliable(io, true);
    /*
     * We can't really support packet unless we have working
     * SCTP_EXPLICIT_EOR capability.  I'll need that in something
     * I can test with to add this.
     */
    /* gensio_set_is_packet(io, true); */

    *new_gensio = io;
    return 0;

 out_nomem:
    if (tdata) {
	if (tdata->ll) {
	    gensio_ll_free(tdata->ll);
	} else {
	    if (tdata->addr)
		gensio_addr_free(tdata->addr);
	    o->free(o, tdata);
	}
    }
    err = GE_NOMEM;
 out_err:
    if (laddr)
	gensio_addr_free(laddr);
    return err;
}

static int
str_to_sctp_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    struct gensio_addr *addr;
    int err;

    err = gensio_os_scan_netaddr(o, str, false, GENSIO_NET_PROTOCOL_SCTP,
				 &addr);
    if (err)
	return err;

    err = sctp_gensio_alloc(addr, args, o, cb, user_data, new_gensio);
    gensio_addr_free(addr);

    return err;
}

struct sctpna_data {
    struct gensio_accepter *acc;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_runner *cb_en_done_runner;

    gensiods max_read_size;
    bool nodelay;
    unsigned int opensock_flags;

    gensio_acc_done shutdown_done;
    gensio_acc_done cb_en_done;

    struct gensio_addr *ai;
    struct gensio_opensocks *acceptfds;
    unsigned int nr_acceptfds;

    unsigned int nr_accept_close_waiting;

    struct sctp_initmsg initmsg;
    struct sctp_sack_info sackinfo;
};

static const struct gensio_fd_ll_ops sctp_server_fd_ll_ops = {
    .free = sctp_free,
    .control = sctp_control,
    .write = sctp_write,
    .read_ready = sctp_read_ready
};

static void
sctpna_fd_cleared(struct gensio_iod *iod, void *cbdata)
{
    struct sctpna_data *nadata = cbdata;
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
sctpna_set_fd_enables(struct sctpna_data *nadata, bool enable)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->set_read_handler(nadata->acceptfds[i].iod, enable);
}

static void
sctpna_finish_server_open(struct gensio *net, int err, void *cb_data)
{
    struct sctpna_data *nadata = cb_data;

    base_gensio_server_open_done(nadata->acc, net, err);
}

static void
sctpna_readhandler(struct gensio_iod *iod, void *cbdata)
{
    struct sctpna_data *nadata = cbdata;
    struct gensio_iod *new_iod = NULL;
    struct sctp_data *tdata = NULL;
    struct gensio *io = NULL;
    int err;

    err = nadata->o->accept(iod, NULL, &new_iod);
    if (err) {
	if (err != GE_NODATA)
	    /* FIXME - maybe shut down the socket I/O? */
	    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
			   "Error accepting sctp gensio: %s",
			   gensio_err_to_str(err));
	return;
    }

    err = base_gensio_accepter_new_child_start(nadata->acc);
    if (err) {
	nadata->o->close(&new_iod);
	return;
    }

    tdata = nadata->o->zalloc(nadata->o, sizeof(*tdata));
    if (!tdata) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_INFO,
		       "Error accepting net gensio: out of memory");
	err = GE_NOMEM;
	goto out_err;
    }

    tdata->o = nadata->o;
    tdata->iod = new_iod;
    tdata->nodelay = nadata->nodelay;
    tdata->initmsg = nadata->initmsg;
    tdata->sackinfo = nadata->sackinfo;

    err = sctp_socket_setup(tdata, new_iod);
    if (!err)
	err = sctp_setup(tdata);
    if (err) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Error setting up sctp port: %s",
		       gensio_err_to_str(err));
	goto out_err;
    }

    tdata->ll = fd_gensio_ll_alloc(nadata->o, new_iod, &sctp_server_fd_ll_ops,
				   tdata, nadata->max_read_size, false);
    if (!tdata->ll) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Out of memory allocating net ll");
	err = GE_NOMEM;
	goto out_err;
    }

    io = base_gensio_server_alloc(nadata->o, tdata->ll, NULL, NULL, "sctp",
				  sctpna_finish_server_open, nadata);
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
	sctp_free(tdata);
    }
    if (new_iod)
	nadata->o->close(&new_iod);
}

static int
sctpna_setup_socket(struct gensio_iod *iod, void *data)
{
    struct sctpna_data *nadata = data;

    return iod->f->sctp_socket_setup(iod, false,
				     &nadata->initmsg, &nadata->sackinfo);
}

static int
sctpna_startup(struct gensio_accepter *accepter, struct sctpna_data *nadata)
{
    int rv;

    rv = gensio_os_open_listen_sockets(nadata->o, nadata->ai,
				    sctpna_readhandler, NULL, sctpna_fd_cleared,
				    sctpna_setup_socket, nadata,
				    nadata->opensock_flags,
				    &nadata->acceptfds, &nadata->nr_acceptfds);
    if (!rv)
	sctpna_set_fd_enables(nadata, true);

    return rv;
}

static int
sctpna_shutdown(struct gensio_accepter *accepter,
		struct sctpna_data *nadata,
		gensio_acc_done shutdown_done)
{
    unsigned int i;

    nadata->shutdown_done = shutdown_done;
    nadata->nr_accept_close_waiting = nadata->nr_acceptfds;
    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->clear_fd_handlers(nadata->acceptfds[i].iod);
    return 0;
}

static void
sctpna_cb_en_done(struct gensio_runner *runner, void *cb_data)
{
    struct sctpna_data *nadata = cb_data;
    gensio_acc_done done = nadata->cb_en_done;

    nadata->cb_en_done = NULL;
    done(nadata->acc, NULL);
}

static int
sctpna_set_accept_callback_enable(struct gensio_accepter *accepter,
				  struct sctpna_data *nadata,
				  bool enabled,
				  gensio_acc_done done)
{
    unsigned int i;

    if (nadata->cb_en_done)
	return GE_INUSE;

    nadata->cb_en_done = done;
    for (i = 0; i < nadata->nr_acceptfds; i++)
	sctpna_set_fd_enables(nadata, enabled);

    if (done)
	nadata->o->run(nadata->cb_en_done_runner);
    return 0;
}

static void
sctpna_free(struct gensio_accepter *accepter, struct sctpna_data *nadata)
{
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->cb_en_done_runner)
	nadata->o->free_runner(nadata->cb_en_done_runner);
    if (nadata->ai)
	gensio_addr_free(nadata->ai);
    nadata->o->free(nadata->o, nadata);
}

static int
sctpna_str_to_gensio(struct gensio_accepter *accepter,
		     struct sctpna_data *nadata, const char *addr,
		     gensio_event cb, void *user_data, struct gensio **new_io)
{
    int err;
    const char *args[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    char buf[100], buf2[100], buf3[100], buf4[100], buf5[100];
    gensiods max_read_size = nadata->max_read_size;
    unsigned int instreams = nadata->initmsg.sinit_max_instreams;
    unsigned int ostreams = nadata->initmsg.sinit_num_ostreams;
    unsigned int sack_freq = nadata->sackinfo.sack_freq;
    unsigned int sack_delay = nadata->sackinfo.sack_delay;
    unsigned int i;
    const char **iargs;
    int iargc;
    struct gensio_addr *ai;
    const char *laddr = NULL, *dummy;
    bool is_port_set;
    int protocol = GENSIO_NET_PROTOCOL_SCTP;
    bool nodelay = false;

    err = gensio_scan_network_port(nadata->o, addr, false, &ai,
				   &protocol, &is_port_set, &iargc, &iargs);
    if (err)
	return err;

    err = GE_INVAL;
    if (protocol != GENSIO_NET_PROTOCOL_SCTP || !is_port_set)
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
	if (gensio_check_keyuint(iargs[i], "instreams", &instreams) > 0)
	    continue;
	if (gensio_check_keyuint(iargs[i], "ostreams", &ostreams) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "sack_freq", &sack_freq) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "sack_delay", &sack_delay) > 0)
	    continue;
	goto out_err;
    }

    i = 0;
    if (nadata->max_read_size != GENSIO_DEFAULT_BUF_SIZE) {
	snprintf(buf, 100, "readbuf=%lu", (unsigned long) max_read_size);
	args[i++] = buf;
    }
    if (laddr)
	args[i++] = laddr;
    if (instreams > 1) {
	snprintf(buf2, 100, "instreams=%u", instreams);
	args[i++] = buf2;
    }
    if (ostreams > 1) {
	snprintf(buf3, 100, "ostreams=%u", ostreams);
	args[i++] = buf3;
    }
    snprintf(buf4, 100, "sack_freq=%u", sack_freq);
    args[i++] = buf4;
    snprintf(buf5, 100, "sack_delay=%u", sack_delay);
    args[i++] = buf5;
    if (nodelay)
	args[i++] = "nodelay";

    err = sctp_gensio_alloc(ai, args, nadata->o, cb, user_data, new_io);

 out_err:
    if (iargs)
	gensio_argv_free(nadata->o, iargs);
    gensio_addr_free(ai);

    return err;
}

static int
sctpna_control_laddr(struct sctpna_data *nadata, bool get,
                    char *data, gensiods *datalen)
{
    unsigned int i;
    gensiods pos = 0;
    int rv;
    struct gensio_addr *addrs;

    if (!get)
	return GE_NOTSUP;

    if (nadata->nr_acceptfds == 0)
	return GE_NOTREADY;

    i = strtoul(data, NULL, 0);
    if (i >= nadata->nr_acceptfds)
	return GE_NOTFOUND;

    rv = nadata->o->sock_control(nadata->acceptfds[i].iod,
				 GENSIO_SOCKCTL_GET_SOCKNAME,
				 &addrs, NULL);
    if (rv)
	return rv;

    rv = gensio_addr_to_str_all(addrs, data, &pos, *datalen);

    gensio_addr_free(addrs);

    if (!rv)
	*datalen = pos;
    return rv;
}


static int
sctpna_control_lport(struct sctpna_data *nadata, bool get,
		     char *data, gensiods *datalen)
{
    unsigned int i;

    if (!get)
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
sctpna_control(struct gensio_accepter *accepter, struct sctpna_data *nadata,
	       bool get, unsigned int option, char *data, gensiods *datalen)
{
    switch (option) {
    case GENSIO_ACC_CONTROL_LADDR:
	return sctpna_control_laddr(nadata, get, data, datalen);

    case GENSIO_ACC_CONTROL_LPORT:
	return sctpna_control_lport(nadata, get, data, datalen);

    default:
	return GE_NOTSUP;
    }
}

static void
sctpna_disable(struct gensio_accepter *accepter, struct sctpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->clear_fd_handlers_norpt(nadata->acceptfds[i].iod);
    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->close(&nadata->acceptfds[i].iod);
}

static int
sctpna_base_acc_op(struct gensio_accepter *acc, int op,
		   void *acc_op_data, void *done, int val1,
		   void *data, void *data2, void *ret)
{
    switch(op) {
    case GENSIO_BASE_ACC_STARTUP:
	return sctpna_startup(acc, acc_op_data);

    case GENSIO_BASE_ACC_SHUTDOWN:
	return sctpna_shutdown(acc, acc_op_data, done);

    case GENSIO_BASE_ACC_SET_CB_ENABLE:
	return sctpna_set_accept_callback_enable(acc, acc_op_data, val1, done);

    case GENSIO_BASE_ACC_FREE:
	sctpna_free(acc, acc_op_data);
	return 0;

    case GENSIO_BASE_ACC_CONTROL:
	return sctpna_control(acc, acc_op_data,
			      val1, *((unsigned int *) done), data, ret);

    case GENSIO_BASE_ACC_STR_TO_GENSIO:
	return sctpna_str_to_gensio(acc, acc_op_data, (const char *) data,
				    (gensio_event) done, data2, ret);

    case GENSIO_BASE_ACC_DISABLE:
	sctpna_disable(acc, acc_op_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
sctp_gensio_accepter_alloc(const void *gdata,
			   const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
    const struct gensio_addr *iai = gdata;
    struct sctpna_data *nadata;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    unsigned int instreams = 1, ostreams = 1;
    unsigned int sack_freq = 1, sack_delay = 10;
    bool nodelay = false, reuseaddr = true;
    unsigned int i;
    int err, ival;

    err = gensio_get_default(o, "sctp", "reuseaddr", false,
			     GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    reuseaddr = ival;

    err = gensio_get_default(o, "sctp", "sack_freq", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    sack_freq = ival;

    err = gensio_get_default(o, "sctp", "sack_delay", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    sack_delay = ival;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "instreams", &instreams) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "ostreams", &ostreams) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "sack_freq", &sack_freq) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "sack_delay", &sack_delay) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "reuseaddr", &reuseaddr) > 0)
	    continue;
	return GE_INVAL;
    }

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;
    nadata->o = o;
    nadata->initmsg.sinit_max_instreams = instreams;
    nadata->initmsg.sinit_num_ostreams = ostreams;
    nadata->sackinfo.sack_freq = sack_freq;
    nadata->sackinfo.sack_delay = sack_delay;
    if (reuseaddr)
	nadata->opensock_flags |= GENSIO_OPENSOCK_REUSEADDR;

    err = GE_NOMEM;
    nadata->ai = gensio_addr_dup(iai);
    if (!nadata->ai)
	goto out_err;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_err;

    nadata->cb_en_done_runner = o->alloc_runner(o, sctpna_cb_en_done, nadata);
    if (!nadata->cb_en_done_runner)
	goto out_err;

    err = base_gensio_accepter_alloc(NULL, sctpna_base_acc_op, nadata,
				    o, "sctp", cb, user_data, accepter);
    if (err)
	goto out_err;

    nadata->acc = *accepter;
    gensio_acc_set_is_reliable(nadata->acc, true);
    /* See comment on gensio_set_is_packet() above. */
    /* gensio_acc_set_is_packet(nadata->acc, true); */

    nadata->max_read_size = max_read_size;
    nadata->nodelay = nodelay;

    return 0;

 out_err:
    sctpna_free(NULL, nadata);
    return err;
}

static int
str_to_sctp_gensio_accepter(const char *str, const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb,
			    void *user_data,
			    struct gensio_accepter **acc)
{
    int err;
    struct gensio_addr *ai;

    err = gensio_os_scan_netaddr(o, str, true, GENSIO_NET_PROTOCOL_SCTP, &ai);
    if (err)
	return err;

    err = sctp_gensio_accepter_alloc(ai, args, o, cb, user_data, acc);
    gensio_addr_free(ai);

    return err;
}

int
gensio_init_sctp(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "sctp", str_to_sctp_gensio, sctp_gensio_alloc);
    if (rv)
	return rv;
    rv = register_gensio_accepter(o, "sctp", str_to_sctp_gensio_accepter,
				  sctp_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
