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

/* This code handles SCTP network I/O. */

#include "config.h"
#include <errno.h>
#include <gensio/gensio.h>

#ifdef HAVE_LIBSCTP

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_osops.h>

struct sctp_data {
    struct gensio_os_funcs *o;

    struct gensio_ll *ll;

    int fd;

    int family;
    struct addrinfo *ai;
    struct addrinfo *lai; /* Local address, NULL if not set. */

    struct sctp_initmsg initmsg;

    bool nodelay;
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
    socklen_t stat_size = sizeof(status);
    unsigned int i;

    if (getsockopt(tdata->fd, IPPROTO_SCTP, SCTP_STATUS, &status,
		   &stat_size) == -1)
	return errno;

    tdata->instreams = status.sstat_instrms;
    tdata->ostreams = status.sstat_outstrms;

    tdata->strind = o->zalloc(o, sizeof(char *) * tdata->instreams);
    if (!tdata->strind)
	return ENOMEM;

    for (i = 1; i < tdata->instreams; i++) {
	tdata->strind[i] = o->zalloc(o, 17);
	if (!tdata->strind[i])
	    return ENOMEM;
	snprintf(tdata->strind[i], 17, "stream=%d", i);
    }

    return 0;
}

static int sctp_check_open(void *handler_data, int fd)
{
    struct sctp_data *tdata = handler_data;
    int optval = 0, err;
    socklen_t len = sizeof(optval);

    err = getsockopt(fd, SOL_SOCKET, SO_ERROR, &optval, &len);
    if (err)
	return gensio_os_err_to_err(tdata->o, errno);

    /* We assume any errors here are a remote close. */
    if (optval == 0) {
	err = sctp_setup(tdata);
	if (err)
	    err = GE_REMCLOSE;
    } else {
	err = GE_REMCLOSE;
    }


    return err;
}

static int
sctp_socket_setup(struct sctp_data *tdata, int fd)
{
    int optval = 1;
    struct sctp_event_subscribe event_sub;
    struct addrinfo *ai = tdata->lai;

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
	return errno;

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
		   (void *)&optval, sizeof(optval)) == -1)
	return errno;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		   (void *)&optval, sizeof(optval)) == -1)
	return errno;

    if (setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &tdata->initmsg,
		   sizeof(tdata->initmsg)) == -1)
	return errno;

    if (tdata->nodelay) {
	int val = 1;

	if (setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &val, sizeof(val)) == -1)
	    return errno;
    }

    memset(&event_sub, 0, sizeof(event_sub));
    event_sub.sctp_data_io_event = 1;
    if (setsockopt(fd, IPPROTO_SCTP, SCTP_EVENTS, &event_sub,
		   sizeof(event_sub)) == -1)
	return errno;

    while (ai) {
	if (sctp_bindx(fd, ai->ai_addr, 1, SCTP_BINDX_ADD_ADDR) == -1)
	    return errno;
	ai = ai->ai_next;
    }

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
	return GE_INVAL;

    a = o->zalloc(0, size);
    if (!a)
	return GE_NOMEM;
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
    int err = GE_INUSE;
    struct sockaddr *addrs = NULL;
    unsigned int naddrs;

    err = sctp_addrinfo_to_sockaddr(tdata->o, tdata->ai, &addrs, &naddrs);
    if (err)
	return err;

    tdata->fd = socket(tdata->family, SOCK_STREAM, IPPROTO_SCTP);
    if (tdata->fd == -1) {
	err = errno;
	goto out;
    }

    err = sctp_socket_setup(tdata, tdata->fd);
    if (err)
	goto out;

    err = sctp_connectx(tdata->fd, addrs, naddrs, NULL);
    if (err == -1) {
	err = errno;
	if (err == EINPROGRESS) {
	    *fd = tdata->fd;
	    goto out_return;
	}
    } else {
	err = sctp_setup(tdata);
    }

 out:
    if (err) {
	if (tdata->fd != -1) {
	    close(tdata->fd);
	    tdata->fd = -1;
	}
    } else {
	*fd = tdata->fd;
    }

 out_return:
    tdata->o->free(tdata->o, addrs);
    return gensio_os_err_to_err(tdata->o, err);
}

static int
sctp_sub_open(void *handler_data, int *fd)
{
    struct sctp_data *tdata = handler_data;

    return sctp_try_open(tdata, fd);
}

static int
sctp_addr_to_str(struct sockaddr *addrs, unsigned int count,
		 char *buf, gensiods *pos, gensiods buflen)
{
    unsigned char *d;
    unsigned int i;
    int rv;

    d = (unsigned char *) addrs;
    for (i = 0; i < count; i++) {
	socklen_t addrlen = 0;

	if (i > 0)
	    /* Add the semicolons between the addresses. */
	    gensio_pos_snprintf(buf, buflen, pos, ";");

	rv = gensio_sockaddr_to_str((struct sockaddr *) d, &addrlen,
				    buf, pos, buflen);
	if (rv)
	    return rv;
	d += addrlen;
    }

    return 0;
}

static int
sctp_raddr_to_str(void *handler_data, gensiods *pos,
		  char *buf, gensiods buflen)
{
    struct sctp_data *tdata = handler_data;
    struct sockaddr *addrs;
    int rv;

    rv = sctp_getpaddrs(tdata->fd, 0, &addrs);
    if (rv < 0)
	return gensio_os_err_to_err(tdata->o, errno);
    if (rv == 0)
	return GE_NOTFOUND;

    rv = sctp_addr_to_str(addrs, rv, buf, pos, buflen);

    sctp_freepaddrs(addrs);
    return rv;
}

static int
sctp_get_raddr(void *handler_data, void *addr, gensiods *addrlen)
{
    struct sctp_data *tdata = handler_data;
    struct sockaddr *addrs, *a;
    unsigned char *d;
    unsigned int i;
    gensiods size, count;
    int rv;

    rv = sctp_getpaddrs(tdata->fd, 0, &addrs);
    if (rv < 0)
	return gensio_os_err_to_err(tdata->o, errno);
    if (rv == 0)
	return GE_NOTFOUND;

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
	    rv = GE_INVAL;
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
    if (tdata->lai)
	gensio_free_addrinfo(tdata->o, tdata->lai);
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
sctp_control(void *handler_data, int fd, bool get, unsigned int option,
	     char *data, gensiods *datalen)
{
    struct sctp_data *tdata = handler_data;
    int rv, val;

    switch (option) {
    case GENSIO_CONTROL_NODELAY:
	if (get) {
	    if (fd != -1) {
		socklen_t vallen = sizeof(val);

		rv = getsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &val, &vallen);
		if (rv == -1)
		    return gensio_os_err_to_err(tdata->o, errno);
	    } else {
		val = tdata->nodelay;
	    }
	    *datalen = snprintf(data, *datalen, "%d", val);
	} else {
	    val = strtoul(data, NULL, 0);
	    tdata->nodelay = val;
	    if (fd != -1) {
		rv = setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &val,
				sizeof(val));
		if (rv == -1)
		    return gensio_os_err_to_err(tdata->o, errno);
	    }
	}
	return 0;

    case GENSIO_CONTROL_STREAMS:
	if (!get)
	    return GE_INVAL;
	*datalen = snprintf(data, *datalen,
			    "instreams=%u,ostreams=%u", tdata->instreams,
			    tdata->ostreams);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
sctp_write(void *handler_data, int fd, gensiods *rcount,
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
    return gensio_os_sctp_send(tdata->o,
			       tdata->fd, sg, sglen, rcount, &sinfo, 0);
}

static int
sctp_do_read(int fd, void *data, gensiods count, gensiods *rcount,
	     const char **auxdata, void *cb_data)
{
    struct sctp_data *tdata = cb_data;
    int rv;
    struct sctp_sndrcvinfo sinfo;
    int flags = 0;
    unsigned int stream;
    unsigned int i = 0;

    rv = gensio_os_sctp_recvmsg(tdata->o,
				fd, data, count, rcount, &sinfo, &flags);
    /* If the data length is zero, we won't have any info. */
    if (rv || *rcount == 0)
	return rv;

    stream = sinfo.sinfo_stream;
    /* Shouldn't happen, but just in case. */
    assert(stream < tdata->instreams);

    if (tdata->strind[stream])
	auxdata[i++] = tdata->strind[stream];

    if (sinfo.sinfo_flags && SCTP_UNORDERED)
	auxdata[i++] = "oob";

    auxdata[i] = NULL;

    return rv;
}

static void
sctp_read_ready(void *handler_data, int fd)
{
    struct sctp_data *tdata = handler_data;

    gensio_fd_ll_handle_incoming(tdata->ll, sctp_do_read, tdata->auxdata,
				 tdata);
}

static const struct gensio_fd_ll_ops sctp_fd_ll_ops = {
    .sub_open = sctp_sub_open,
    .check_open = sctp_check_open,
    .raddr_to_str = sctp_raddr_to_str,
    .get_raddr = sctp_get_raddr,
    .free = sctp_free,
    .control = sctp_control,
    .write = sctp_write,
    .read_ready = sctp_read_ready
};

int
sctp_gensio_alloc(struct addrinfo *iai, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    struct sctp_data *tdata = NULL;
    struct addrinfo *ai;
    struct gensio *io;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    unsigned int instreams = 1, ostreams = 1;
    int i, family = AF_INET, err, ival;
    struct addrinfo *lai = NULL;
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

    err = gensio_get_defaultaddr(o, "sctp", "laddr", false,
				 IPPROTO_SCTP, true, false, &lai);
    if (err && err != GE_NOTSUP) {
	gensio_log(o, GENSIO_LOG_ERR, "Invalid default sctp laddr: %s",
		   gensio_err_to_str(err));
	return err;
    }

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyaddrs(o, args[i], "laddr", IPPROTO_SCTP,
				  true, false, &lai) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "instreams", &instreams) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "ostreams", &ostreams) > 0)
	    continue;
	err = GE_INVAL;
	goto out_err;
    }

    for (ai = iai; ai; ai = ai->ai_next) {
	if (ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
	    err = GE_TOOBIG;
	    goto out_err;
	}
	if (ai->ai_addr->sa_family == AF_INET6)
	    family = AF_INET6;
    }

    tdata = o->zalloc(o, sizeof(*tdata));
    if (!tdata) {
	err = GE_NOMEM;
	goto out_err;
    }

    ai = gensio_dup_addrinfo(o, iai);
    if (!ai)
	goto out_nomem;

    tdata->o = o;
    tdata->family = family;
    tdata->ai = ai;
    tdata->lai = lai;
    tdata->initmsg.sinit_max_instreams = instreams;
    tdata->initmsg.sinit_num_ostreams = ostreams;
    tdata->fd = -1;
    tdata->nodelay = nodelay;

    tdata->ll = fd_gensio_ll_alloc(o, -1, &sctp_fd_ll_ops, tdata,
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
	    if (tdata->ai)
		gensio_free_addrinfo(o, tdata->ai);
	    o->free(o, tdata);
	}
    }
    err = GE_NOMEM;
 out_err:
    if (lai)
	gensio_free_addrinfo(o, lai);
    return err;
}

int
str_to_sctp_gensio(const char *str, const char * const args[],
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
    unsigned int port;
    int family;
    int flags;
};

struct sctpna_data {
    struct gensio_accepter *acc;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_runner *cb_en_done_runner;

    gensiods max_read_size;
    bool nodelay;

    gensio_acc_done shutdown_done;
    gensio_acc_done cb_en_done;

    struct addrinfo *ai;
    struct sctpna_acceptfds *acceptfds;
    unsigned int nr_acceptfds;

    unsigned int nr_accept_close_waiting;

    struct sctp_initmsg initmsg;
};

static const struct gensio_fd_ll_ops sctp_server_fd_ll_ops = {
    .raddr_to_str = sctp_raddr_to_str,
    .get_raddr = sctp_get_raddr,
    .free = sctp_free,
    .control = sctp_control,
    .write = sctp_write,
    .read_ready = sctp_read_ready
};

static void
sctpna_fd_cleared(int fd, void *cbdata)
{
    struct sctpna_data *nadata = cbdata;
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
sctpna_set_fd_enables(struct sctpna_data *nadata, bool enable)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_acceptfds; i++)
	nadata->o->set_read_handler(nadata->o, nadata->acceptfds[i].fd, enable);
}

static void
sctpna_finish_server_open(struct gensio *net, int err, void *cb_data)
{
    struct sctpna_data *nadata = cb_data;

    base_gensio_server_open_done(nadata->acc, net, err);
}

static void
sctpna_readhandler(int fd, void *cbdata)
{
    struct sctpna_data *nadata = cbdata;
    int new_fd = -1;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    struct sctp_data *tdata = NULL;
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
			   "Error accepting sctp gensio: %s",
			   gensio_err_to_str(err));
	goto out_err;
    }

    tdata = nadata->o->zalloc(nadata->o, sizeof(*tdata));
    if (!tdata) {
	gensio_acc_log(nadata->acc, GENSIO_LOG_INFO,
		       "Error accepting net gensio: out of memory");
	err = GE_NOMEM;
	goto out_err;
    }

    tdata->o = nadata->o;
    tdata->fd = new_fd;
    tdata->nodelay = nadata->nodelay;

    err = sctp_socket_setup(tdata, new_fd);
    if (!err)
	err = sctp_setup(tdata);
    if (err) {
	err = gensio_os_err_to_err(tdata->o, err);
	gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		       "Error setting up sctp port: %s", strerror(err));
	goto out_err;
    }

    tdata->ll = fd_gensio_ll_alloc(nadata->o, new_fd, &sctp_server_fd_ll_ops,
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
    base_gensio_accepter_new_child_end(nadata->acc, io, err);
    if (new_fd != -1)
	close(new_fd);
    if (tdata) {
	if (tdata->ll)
	    gensio_ll_free(tdata->ll);
	else
	    sctp_free(tdata);
    }
}

static int
sctpna_setup_socket(int fd, void *data)
{
    struct sctpna_data *nadata = data;

    if (setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &nadata->initmsg,
		   sizeof(nadata->initmsg)) == -1)
	return gensio_os_err_to_err(nadata->o, errno);

    return 0;
}

static void
sctpna_shutdown_fds(struct sctpna_data *nadata)
{
    struct gensio_os_funcs *o = nadata->o;
    unsigned int i;

    if (!nadata->acceptfds)
	return;

    for (i = 0; i < nadata->nr_acceptfds; i++)
	close(nadata->acceptfds[i].fd);
    nadata->nr_acceptfds = 0;
    o->free(o, nadata->acceptfds);
    nadata->acceptfds = NULL;
}

static int
sctpna_startup(struct gensio_accepter *accepter, struct sctpna_data *nadata)
{
    struct gensio_os_funcs *o = nadata->o;
    struct addrinfo *ai;
    unsigned int i;
    int family = AF_INET6;
    int rv = 0;
    struct gensio_listen_scan_info scaninfo;

    memset(&scaninfo, 0, sizeof(scaninfo));

 retry:
    for (ai = nadata->ai; ai; ai = ai->ai_next) {
	struct sctpna_acceptfds *fds = nadata->acceptfds;
	unsigned int port;

	if (family != ai->ai_family)
	    continue;

	rv = gensio_sockaddr_get_port(ai->ai_addr, &port);
	if (rv)
	    goto out_err;

	for (i = 0; i < nadata->nr_acceptfds; i++) {
	    if (port == fds[i].port &&
		((fds[i].flags & AI_V4MAPPED) || fds[i].family == family)) {
		if (sctp_bindx(fds[i].fd, ai->ai_addr, 1,
			       SCTP_BINDX_ADD_ADDR)) {
		    rv = gensio_os_err_to_err(o, errno);
		    goto out_err;
		}
		break;
	    }
	}
	if (i < nadata->nr_acceptfds)
	    continue; /* Port matched, already did bind. */

	/* Increment the fds array and open a new socket. */
	fds = o->zalloc(o, sizeof(*fds) * (i + 1));
	if (!fds) {
	    rv = GE_NOMEM;
	    goto out_err;
	}
	if (nadata->acceptfds)
	    memcpy(fds, nadata->acceptfds, sizeof(*fds) * i);

	rv = gensio_setup_listen_socket(o, true, ai->ai_family,
					SOCK_STREAM, IPPROTO_SCTP, ai->ai_flags,
					ai->ai_addr, ai->ai_addrlen,
					sctpna_readhandler, NULL, nadata,
					sctpna_fd_cleared,
					sctpna_setup_socket,
					&fds[i].fd, &fds[i].port, &scaninfo);
	if (rv) {
	    o->free(o, fds);
	    goto out_err;
	}
	fds[i].family = ai->ai_family;
	fds[i].flags = ai->ai_flags;
	if (nadata->acceptfds)
	    o->free(o, nadata->acceptfds);
	nadata->acceptfds = fds;
	nadata->nr_acceptfds++;
    }
    if (family == AF_INET6) {
	family = AF_INET;
	goto retry;
    }

    if (nadata->nr_acceptfds == 0) {
	rv = GE_INVAL;
	goto out;
    }

    sctpna_set_fd_enables(nadata, true);

 out:
    return rv;

 out_err:
    sctpna_shutdown_fds(nadata);

    if (rv == GE_ADDRINUSE && scaninfo.start != 0 &&
		scaninfo.curr != scaninfo.start) {
	/* We need to keep scanning. */
	scaninfo.reqport = 0;
	family = AF_INET6;
	goto retry;
    }
    goto out;
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
	nadata->o->clear_fd_handlers(nadata->o, nadata->acceptfds[i].fd);
    return 0;
}

static void
sctpna_cb_en_done(struct gensio_runner *runner, void *cb_data)
{
    struct sctpna_data *nadata = cb_data;

    nadata->cb_en_done(nadata->acc, NULL);
}

static int
sctpna_set_accept_callback_enable(struct gensio_accepter *accepter,
				  struct sctpna_data *nadata,
				  bool enabled,
				  gensio_acc_done done)
{
    unsigned int i;

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
	gensio_free_addrinfo(nadata->o, nadata->ai);
    nadata->o->free(nadata->o, nadata);
}

static int
sctpna_str_to_gensio(struct gensio_accepter *accepter,
		     struct sctpna_data *nadata, const char *addr,
		     gensio_event cb, void *user_data, struct gensio **new_io)
{
    int err;
    const char *args[6] = { NULL, NULL, NULL, NULL, NULL, NULL };
    char buf[100], buf2[100], buf3[100];
    gensiods max_read_size = nadata->max_read_size;
    unsigned int instreams = nadata->initmsg.sinit_max_instreams;
    unsigned int ostreams = nadata->initmsg.sinit_num_ostreams;
    unsigned int i;
    const char **iargs;
    int iargc;
    struct addrinfo *ai;
    const char *laddr = NULL, *dummy;
    bool is_port_set;
    int socktype, protocol;
    bool nodelay = false;

    err = gensio_scan_network_port(nadata->o, addr, false, &ai, &socktype,
				   &protocol, &is_port_set, &iargc, &iargs);
    if (err)
	return err;

    err = GE_INVAL;
    if (protocol != IPPROTO_SCTP || !is_port_set)
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
    if (nodelay)
	args[i++] = "nodelay";

    err = sctp_gensio_alloc(ai, args, nadata->o, cb, user_data, new_io);

 out_err:
    if (iargs)
	gensio_argv_free(nadata->o, iargs);
    gensio_free_addrinfo(nadata->o, ai);

    return err;
}

static int
sctpna_control_laddr(struct sctpna_data *nadata, bool get,
                    char *data, gensiods *datalen)
{
    unsigned int i;
    gensiods pos = 0;
    int rv;
    struct sockaddr *addrs;

    if (!get)
	return GE_NOTSUP;

    if (nadata->nr_acceptfds == 0)
	return GE_NOTREADY;

    i = strtoul(data, NULL, 0);
    if (i >= nadata->nr_acceptfds)
	return GE_NOTFOUND;

    rv = sctp_getladdrs(nadata->acceptfds[i].fd, 0, &addrs);
    if (rv < 0)
	return gensio_os_err_to_err(nadata->o, errno);
    if (rv == 0)
	return GE_DATAMISSING;

    rv = sctp_addr_to_str(addrs, rv, data, &pos, *datalen);

    sctp_freeladdrs(addrs);
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
	nadata->o->clear_fd_handlers_norpt(nadata->o,
					   nadata->acceptfds[i].fd);
    for (i = 0; i < nadata->nr_acceptfds; i++)
	close(nadata->acceptfds[i].fd);
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

int
sctp_gensio_accepter_alloc(struct addrinfo *iai, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
    struct sctpna_data *nadata;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    unsigned int instreams = 1, ostreams = 1;
    bool nodelay = false;
    unsigned int i;
    int err;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "nodelay", &nodelay) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "instreams", &instreams) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "ostreams", &ostreams) > 0)
	    continue;
	return GE_INVAL;
    }

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;
    nadata->o = o;
    nadata->initmsg.sinit_max_instreams = instreams;
    nadata->initmsg.sinit_num_ostreams = ostreams;

    err = GE_NOMEM;
    nadata->ai = gensio_dup_addrinfo(o, iai);
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

int
str_to_sctp_gensio_accepter(const char *str, const char * const args[],
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
sctp_gensio_alloc(struct addrinfo *iai, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return GE_NOTSUP;
}

int
str_to_sctp_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return GE_NOTSUP;
}

int
sctp_gensio_accepter_alloc(struct addrinfo *iai, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
    return GE_NOTSUP;
}

int
str_to_sctp_gensio_accepter(const char *str, const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb,
			    void *user_data,
			    struct gensio_accepter **acc)
{
    return GE_NOTSUP;
}
#endif
