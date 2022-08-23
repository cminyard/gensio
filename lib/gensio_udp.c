/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code handles UDP network I/O. */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_list.h>

#ifdef ENABLE_INTERNAL_TRACE
#define DEBUG_STATE
#endif

/*
 * Maximum UDP packet size, this avoids partial packet reads.  Probably
 * not a good idea to override this.
 */
#define GENSIO_DEFAULT_UDP_BUF_SIZE	65536

struct udpna_data;

enum udpn_state {
    UDPN_CLOSED = 0,
    UDPN_IN_OPEN,
    UDPN_OPEN,
    UDPN_IN_CLOSE
};

struct udpn_data {
    struct gensio *io;
    struct udpna_data *nadata;

    struct gensio_os_funcs *o;

    /* iod the original request came in on, for sending. */
    struct gensio_iod *myiod;

    bool read_enabled;	/* Read callbacks are enabled. */
    bool write_enabled;	/* Write callbacks are enabled. */
    bool in_read;	/* Currently in a read callback. */
    bool deferred_read;
    bool in_write;	/* Currently in a write callback. */
    bool write_pending; /* Need to redo the write callback. */
    bool in_open_cb;	/* Currently in an open callback. */
    bool in_close_cb;	/* Currently in a close callback. */
    bool extrainfo;	/* Deliver extrainfo to user? */

    enum udpn_state state;
    bool freed;		/* Freed during the close process. */

    gensio_done_err open_done;
    void *open_data;

    gensio_done close_done;
    void *close_data;

    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;	/* NULL if not a client. */

    struct gensio_addr *raddr;		/* Points to remote, for convenience. */

    struct gensio_link link;
};

#define gensio_link_to_ndata(l) \
    gensio_container_of(l, struct udpn_data, link);

struct udpna_data;

#ifdef DEBUG_STATE
struct udp_state_trace {
    enum udpn_state old_state;
    enum udpn_state new_state;
    int line;
    bool readdisable;
};
#define STATE_TRACE_LEN 256
#else
#define i_udp_add_trace(nadata, ndata, new_state, line)
#endif

struct udpna_data {
    struct gensio_accepter *acc;
    struct gensio_list udpns;
    unsigned int udpn_count;
    unsigned int refcount;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    gensiods max_read_size;

    unsigned char *read_data;

    bool readhandler_read_disabled;
    gensiods data_pending_len;
    gensiods data_pos;
    struct udpn_data *pending_data_owner;

    struct gensio_list closed_udpns;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

    bool in_new_connection;

    struct gensio_runner *enable_done_runner;
    gensio_acc_done enable_done;
    void *enable_done_data;

    bool is_dummy; /* Am I a dummy udpna? */

    bool enabled;
    bool closed;
    bool in_shutdown;
    bool disabled;
    bool freed;
    bool finished_free;
    gensio_acc_done shutdown_done;
    void *shutdown_data;

    struct gensio_addr *ai;		/* The address list for the portname. */
    struct gensio_opensocks *fds;	/* The file descriptor used for
					   the UDP ports. */
    unsigned int   nr_fds;
    unsigned int opensock_flags;

    unsigned int extrainfo; /* Is extrainfo enabled or disabled in the iod? */

    bool nocon;		/* Disable connection-oriented handling. */
    struct gensio_addr *curr_recvaddr;	/* Address of current received packet */

    bool in_write;
    unsigned int read_disable_count;
    bool read_disabled;
    unsigned int write_enable_count;

#ifdef DEBUG_STATE
    struct udp_state_trace state_trace[STATE_TRACE_LEN];
    unsigned int state_trace_pos;
#endif
};

static void udpna_do_free(struct udpna_data *nadata);

static void
i_udpna_lock(struct udpna_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
i_udpna_unlock(struct udpna_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void i_udpna_ref(struct udpna_data *nadata)
{
    assert(nadata->refcount > 0);
    nadata->refcount++;
}

static void i_udpna_deref(struct udpna_data *nadata)
{
    assert(nadata->refcount > 1);
    nadata->refcount--;
}

static void i_udpna_lock_and_ref(struct udpna_data *nadata)
{
    i_udpna_lock(nadata);
    i_udpna_ref(nadata);
}

static void i_udpna_deref_and_unlock(struct udpna_data *nadata)
{
    assert(nadata->refcount > 0);
    nadata->refcount--;
    if (nadata->refcount == 0) {
	i_udpna_unlock(nadata);
	udpna_do_free(nadata);
    } else {
	i_udpna_unlock(nadata);
    }
}

#ifdef DEBUG_STATE
static void
i_udp_add_trace(struct udpna_data *nadata, struct udpn_data *ndata,
		enum udpn_state new_state, int line)
{
    if (ndata)
	nadata->state_trace[nadata->state_trace_pos].old_state = ndata->state;
    else
	nadata->state_trace[nadata->state_trace_pos].old_state = 99;
    nadata->state_trace[nadata->state_trace_pos].new_state = new_state;
    nadata->state_trace[nadata->state_trace_pos].line = line;
    nadata->state_trace[nadata->state_trace_pos].readdisable =
	nadata->read_disabled;
    if (nadata->state_trace_pos == STATE_TRACE_LEN - 1)
	nadata->state_trace_pos = 0;
    else
	nadata->state_trace_pos++;
}

#define udpna_lock(nadata) do { \
	i_udpna_lock(nadata);				\
	i_udp_add_trace(nadata, NULL, 1001, __LINE__);	\
    } while(0)

#define udpna_unlock(nadata) do { \
	i_udp_add_trace(nadata, NULL, 1002, __LINE__);	\
	i_udpna_unlock(nadata);				\
    } while(0)

#define udpna_ref(nadata) do { \
	i_udpna_ref(nadata);				\
	i_udp_add_trace(nadata, NULL, 2000 + nadata->refcount, __LINE__); \
    } while(0)

#define udpna_deref(nadata) do { \
	i_udp_add_trace(nadata, NULL, 3000 + nadata->refcount, __LINE__); \
	i_udpna_deref(nadata);				\
    } while(0)

#define udpna_lock_and_ref(nadata) do { \
	i_udpna_lock_and_ref(nadata);			\
	i_udp_add_trace(nadata, NULL, 2000 + nadata->refcount, __LINE__); \
    } while(0)

#define udpna_deref_and_unlock(nadata) do { \
	i_udp_add_trace(nadata, NULL, 3000 + nadata->refcount, __LINE__); \
	i_udpna_deref_and_unlock(nadata);		\
    } while(0)

static void
i_udpn_set_state(struct udpn_data *ndata, enum udpn_state state, int line)
{
    i_udp_add_trace(ndata->nadata, ndata, state, line);
    ndata->state = state;
}

#define udpn_set_state(ndata, state) \
    i_udpn_set_state(ndata, state, __LINE__)

#else

#define udpna_lock i_udpna_lock
#define udpna_unlock i_udpna_unlock
#define udpna_ref i_udpna_ref
#define udpna_deref i_udpna_deref
#define udpna_lock_and_ref i_udpna_lock_and_ref
#define udpna_deref_and_unlock i_udpna_deref_and_unlock

static void
udpn_set_state(struct udpn_data *ndata, enum udpn_state state)
{
    ndata->state = state;
}


#endif

static void udpna_start_deferred_op(struct udpna_data *nadata)
{
    if (!nadata->deferred_op_pending) {
	udpna_ref(nadata);
	nadata->deferred_op_pending = true;
	nadata->o->run(nadata->deferred_op_runner);
    }
}

static void
udpn_remove_from_list(struct gensio_list *list, struct udpn_data *ndata)
{
    gensio_list_rm(list, &ndata->link);
}

static struct udpn_data *
udpn_find(struct gensio_list *list, struct gensio_addr *addr)
{
    struct gensio_link *l;

    gensio_list_for_each(list, l) {
	struct udpn_data *ndata = gensio_link_to_ndata(l);

	if (gensio_addr_equal(ndata->raddr, addr, true, false))
	    return ndata;
    }

    return NULL;
}

static void udpn_add_to_list(struct gensio_list *list, struct udpn_data *ndata)
{
    gensio_list_add_tail(list, &ndata->link);
}

static void
udpna_enable_read(struct udpna_data *nadata)
{
    unsigned int i;

    nadata->read_disabled = false;
    for (i = 0; i < nadata->nr_fds; i++)
	nadata->o->set_read_handler(nadata->fds[i].iod, true);
}

static void
udpna_disable_read(struct udpna_data *nadata)
{
    unsigned int i;

    nadata->read_disabled = true;
    for (i = 0; i < nadata->nr_fds; i++)
	nadata->o->set_read_handler(nadata->fds[i].iod, false);
}

static void udpna_check_read_state(struct udpna_data *nadata)
{
    if (nadata->read_disabled && nadata->read_disable_count == 0)
	udpna_enable_read(nadata);
    else if (!nadata->read_disabled && nadata->read_disable_count > 0)
	udpna_disable_read(nadata);
}

static void
i_udpna_fd_read_enable(struct udpna_data *nadata, int line)
{
    assert(nadata->read_disable_count > 0);
    nadata->read_disable_count--;
    i_udp_add_trace(nadata, NULL, 5100 + nadata->read_disable_count, line);
    udpna_check_read_state(nadata);
}
#define udpna_fd_read_enable(nadata) i_udpna_fd_read_enable(nadata, __LINE__)

static void
i_udpna_fd_read_disable(struct udpna_data *nadata, int line)
{
    nadata->read_disable_count++;
    i_udp_add_trace(nadata, NULL, 5200 + nadata->read_disable_count, line);
    udpna_check_read_state(nadata);
}
#define udpna_fd_read_disable(nadata) i_udpna_fd_read_disable(nadata, __LINE__)

static void
udpna_disable_write(struct udpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_fds; i++)
	nadata->o->set_write_handler(nadata->fds[i].iod, false);
}

static void
udpna_fd_write_disable(struct udpna_data *nadata)
{
    assert(nadata->write_enable_count > 0);
    nadata->write_enable_count--;
    if (nadata->write_enable_count == 0 && !nadata->in_write)
	udpna_disable_write(nadata);
}

static void
udpna_enable_write(struct udpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_fds; i++)
	nadata->o->set_write_handler(nadata->fds[i].iod, true);
}

static void
udpna_fd_write_enable(struct udpna_data *nadata)
{
    if (nadata->write_enable_count == 0 && !nadata->in_write)
	udpna_enable_write(nadata);
    nadata->write_enable_count++;
}

static void
udpna_do_free(struct udpna_data *nadata)
{
    unsigned int i;

    for (i = 0; i < nadata->nr_fds; i++) {
	if (nadata->fds && nadata->fds[i].iod)
	    nadata->o->close(&nadata->fds[i].iod);
    }

    if (nadata->deferred_op_runner)
	nadata->o->free_runner(nadata->deferred_op_runner);
    if (nadata->enable_done_runner)
	nadata->o->free_runner(nadata->enable_done_runner);
    if (nadata->ai)
	gensio_addr_free(nadata->ai);
    if (nadata->fds)
	nadata->o->free(nadata->o, nadata->fds);
    if (nadata->curr_recvaddr)
	gensio_addr_free(nadata->curr_recvaddr);
    if (nadata->read_data)
	nadata->o->free(nadata->o, nadata->read_data);
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->acc)
	gensio_acc_data_free(nadata->acc);
    nadata->o->free(nadata->o, nadata);
}

static void
udpna_fd_cleared(struct gensio_iod *iod, void *cbdata)
{
    struct udpna_data *nadata = cbdata;

    udpna_lock(nadata);
    udpna_deref_and_unlock(nadata);
}

static void
udpna_check_finish_free(struct udpna_data *nadata)
{
    unsigned int i;

    if (!nadata->closed || nadata->in_new_connection || nadata->udpn_count ||
		nadata->in_shutdown || !nadata->freed)
	return;
    if (nadata->finished_free)
	return;

    nadata->finished_free = true;
    udpna_deref(nadata);
    for (i = 0; i < nadata->nr_fds; i++) {
	udpna_ref(nadata);
	nadata->o->clear_fd_handlers(nadata->fds[i].iod);
    }
}

static void
udpn_do_free(struct udpn_data *ndata)
{
    if (ndata->io)
	gensio_data_free(ndata->io);
    if (ndata->deferred_op_runner)
	ndata->o->free_runner(ndata->deferred_op_runner);
    if (ndata->raddr)
	gensio_addr_free(ndata->raddr);
    ndata->o->free(ndata->o, ndata);
}

static void
udpn_finish_free(struct udpn_data *ndata)
{
    struct udpna_data *nadata = ndata->nadata;

    udpn_remove_from_list(&nadata->closed_udpns, ndata);
    assert(nadata->udpn_count > 0);
    nadata->udpn_count--;
    udpn_do_free(ndata);
    udpna_check_finish_free(nadata);
}

static int
udpn_write(struct gensio *io, gensiods *count,
	   const struct gensio_sg *sg, gensiods sglen,
	   const char *const *auxdata)
{
    struct udpn_data *ndata = gensio_get_gensio_data(io);
    struct gensio_addr *addr = NULL;
    unsigned int i;
    bool free_addr = false;
    int err;

    for (i = 0; auxdata && auxdata[i]; i++) {
	if (strncmp(auxdata[i], "addr:", 5) == 0) {
	    if (addr)
		gensio_addr_free(addr);
	    err = gensio_os_scan_netaddr(ndata->o, auxdata[i] + 5, false,
					 GENSIO_NET_PROTOCOL_UDP, &addr);
	    if (err)
		return err;
	    free_addr = true;
	} else {
	    return GE_INVAL;
	}
    }

    if (!addr)
	addr = ndata->raddr;

    err = ndata->o->sendto(ndata->myiod, sg, sglen, count, 0, addr);
    if (free_addr)
	gensio_addr_free(addr);
    return err;
}

static void
udpn_finish_close(struct udpna_data *nadata, struct udpn_data *ndata)
{
    if (ndata->in_read || ndata->in_write || ndata->in_open_cb)
	return;

    udpn_set_state(ndata, UDPN_CLOSED);

    if (ndata->close_done) {
	void (*close_done)(struct gensio *io, void *close_data) =
	    ndata->close_done;
	void *close_data = ndata->close_data;

	ndata->close_done = NULL;
	ndata->in_close_cb = true;
	udpna_unlock(nadata);
	close_done(ndata->io, close_data);
	udpna_lock(nadata);
	ndata->in_close_cb = false;
    }

    if (nadata->pending_data_owner == ndata) {
	nadata->pending_data_owner = NULL;
	nadata->data_pending_len = 0;
    }

    if (ndata->freed && !ndata->deferred_op_pending)
	udpn_finish_free(ndata);
}

static void
udpn_finish_read(struct udpn_data *ndata)
{
    struct udpna_data *nadata = ndata->nadata;
    struct gensio *io = ndata->io;
    gensiods count;
    char raddrdata[200];
    char daddrdata[200];
    char ifidx[20];
    const char *auxmem[4] = { NULL, NULL, NULL, NULL };
    const char *const *auxdata;
    int err;
    gensiods pos;

 retry:
    udpna_unlock(nadata);
    count = nadata->data_pending_len;
    auxdata = NULL;

    auxdata = auxmem;
    auxmem[0] = raddrdata;
    strcpy(raddrdata, "addr:");
    pos = 5;
    err = gensio_addr_to_str(nadata->curr_recvaddr, raddrdata, &pos,
			     sizeof(raddrdata));
    if (err) {
	strcpy(raddrdata, "err:addr:");
	strncpy(raddrdata + 9, gensio_err_to_str(err), sizeof(raddrdata) - 9);
	raddrdata[sizeof(raddrdata) - 1] = '\0';
    }

    if (ndata->extrainfo) {
	/* Get the ifidx */
	if (gensio_addr_next(nadata->curr_recvaddr)) {
	    pos = 0;
	    err = gensio_addr_to_str(nadata->curr_recvaddr, ifidx, &pos,
				     sizeof(ifidx));
	    if (!err)
		auxmem[1] = ifidx;
	}
	/* Get the destination address */
	if (gensio_addr_next(nadata->curr_recvaddr)) {
	    strncpy(daddrdata, "daddr:", sizeof(daddrdata));
	    pos = 6;
	    err = gensio_addr_to_str(nadata->curr_recvaddr, daddrdata, &pos,
				     sizeof(daddrdata));
	    if (!err) {
		/* Chop off the ,0 at the end. */
		pos -= 2;
		if (daddrdata[pos] == ',' && daddrdata[pos + 1] == '0')
		    daddrdata[pos] = '\0';
		auxmem[2] = daddrdata;
	    }
	}
    }

    err = gensio_cb(io, GENSIO_EVENT_READ, 0, nadata->read_data,
		    &count, auxdata);
    udpna_lock(nadata);
    if (err)
	goto out;

    if (ndata->state == UDPN_IN_CLOSE) {
	udpn_finish_close(nadata, ndata);
	goto out;
    }

    if (count < nadata->data_pending_len) {
	/* The user didn't comsume all the data */
	nadata->data_pending_len -= count;
	nadata->data_pos += count;
	if (ndata->state == UDPN_OPEN && ndata->read_enabled)
	    goto retry;
    } else {
	nadata->pending_data_owner = NULL;
	nadata->data_pending_len = 0;
    }
 out:
    ndata->in_read = false;
    udpna_check_read_state(nadata);
}

static void
udpna_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct udpna_data *nadata = cbdata;

    udpna_lock(nadata);
    nadata->deferred_op_pending = false;
    if (nadata->pending_data_owner) {
	struct udpn_data *ndata = nadata->pending_data_owner;
	if (ndata->deferred_read) {
	    ndata->deferred_read = false;
	    if (ndata->read_enabled) {
		udpn_finish_read(ndata);
	    } else {
		/* We started to read, but didn't get to do it. */
		ndata->in_read = false;
	    }
	}
    }

    if (nadata->in_shutdown && !nadata->in_new_connection) {
	struct gensio_accepter *accepter = nadata->acc;

	nadata->in_shutdown = false;
	if (nadata->shutdown_done) {
	    udpna_unlock(nadata);
	    nadata->shutdown_done(accepter, nadata->shutdown_data);
	    udpna_lock(nadata);
	}
	udpna_check_finish_free(nadata);
    }

    if (!nadata->freed || !nadata->closed)
	udpna_check_read_state(nadata);
    udpna_deref_and_unlock(nadata);
}

static void
udpn_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct udpn_data *ndata = cbdata;
    struct udpna_data *nadata = ndata->nadata;

    udpna_lock(nadata);
    ndata->deferred_op_pending = false;
    if (ndata->state == UDPN_IN_OPEN) {
	udpn_set_state(ndata, UDPN_OPEN);
	if (ndata->open_done) {
	    ndata->in_open_cb = true;
	    udpna_unlock(nadata);
	    ndata->open_done(ndata->io, 0, ndata->open_data);
	    udpna_lock(nadata);
	    ndata->in_open_cb = false;
	}
	udpna_check_read_state(nadata);
    }

    if (ndata->state == UDPN_IN_CLOSE)
	udpn_finish_close(nadata, ndata);
    else if (ndata->freed && !ndata->in_close_cb &&
	     !nadata->deferred_op_pending)
	udpn_finish_free(ndata);

    udpna_deref_and_unlock(nadata);
}

static void udpn_start_deferred_op(struct udpn_data *ndata)
{
    if (!ndata->deferred_op_pending) {
	udpna_ref(ndata->nadata);
	ndata->deferred_op_pending = true;
	ndata->o->run(ndata->deferred_op_runner);
    }
}

static int
udpn_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    struct udpn_data *ndata = gensio_get_gensio_data(io);
    struct udpna_data *nadata = ndata->nadata;
    int err = GE_INUSE;

    udpna_lock(nadata);
    if (!gensio_is_client(ndata->io)) {
	err = GE_NOTSUP;
    } else if (ndata->state == UDPN_CLOSED) {
	udpn_remove_from_list(&nadata->closed_udpns, ndata);
	udpn_add_to_list(&nadata->udpns, ndata);
	udpna_fd_read_disable(nadata);
	udpn_set_state(ndata, UDPN_IN_OPEN);
	ndata->open_done = open_done;
	ndata->open_data = open_data;
	udpn_start_deferred_op(ndata);
	err = 0;
    }
    udpna_unlock(nadata);

    return err;
}

static void
udpn_start_close(struct udpn_data *ndata,
		 gensio_done close_done, void *close_data)
{
    struct udpna_data *nadata = ndata->nadata;

    if (nadata->pending_data_owner == ndata) {
	if (ndata->deferred_read) {
	    /*
	     * If there is a read pending on a deferred op, it won't
	     * get called now that this is closed.  So cancel it so
	     * the close will finish
	     */
	    ndata->deferred_read = false;
	    ndata->in_read = false;
	}
	nadata->pending_data_owner = NULL;
	nadata->data_pending_len = 0;
    }
    ndata->close_done = close_done;
    ndata->close_data = close_data;

    if (ndata->read_enabled)
	ndata->read_enabled = false;
    else
	udpna_fd_read_enable(nadata);

    if (ndata->write_enabled) {
	ndata->write_enabled = false;
	udpna_fd_write_disable(nadata);
    }

    udpn_remove_from_list(&nadata->udpns, ndata);
    udpn_add_to_list(&nadata->closed_udpns, ndata);
    udpn_set_state(ndata, UDPN_IN_CLOSE);

    udpn_start_deferred_op(ndata);
}

static bool
udpn_is_closed(struct udpn_data *ndata)
{
    return (ndata->state == UDPN_CLOSED || ndata->state == UDPN_IN_CLOSE);
}

static int
udpn_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    struct udpn_data *ndata = gensio_get_gensio_data(io);
    struct udpna_data *nadata = ndata->nadata;
    int err = GE_INUSE;

    udpna_lock(nadata);
    if (!udpn_is_closed(ndata)) {
	udpn_start_close(ndata, close_done, close_data);
	err = 0;
    }
    udpna_unlock(nadata);

    return err;
}

static void
udpn_free(struct gensio *io)
{
    struct udpn_data *ndata = gensio_get_gensio_data(io);
    struct udpna_data *nadata = ndata->nadata;

    udpna_lock_and_ref(nadata);
    ndata->freed = true;
    if (ndata->state == UDPN_IN_CLOSE)
	ndata->close_done = NULL;
    else if (ndata->state != UDPN_CLOSED)
	udpn_start_close(ndata, NULL, NULL);
    else if (!ndata->in_close_cb && !ndata->deferred_op_pending)
	udpn_finish_free(ndata);
    udpna_deref_and_unlock(nadata);
}

static void
udpn_set_read_callback_enable(struct gensio *io, bool enabled)
{
    struct udpn_data *ndata = gensio_get_gensio_data(io);
    struct udpna_data *nadata = ndata->nadata;
    bool my_data_pending;

    udpna_lock(nadata);
    if (udpn_is_closed(ndata) || ndata->read_enabled == enabled)
	goto out_unlock;

    if (enabled) {
	assert(nadata->read_disable_count > 0);
	nadata->read_disable_count--;
	i_udp_add_trace(nadata, NULL, 5300 + nadata->read_disable_count,
			__LINE__);
    } else {
	nadata->read_disable_count++;
	i_udp_add_trace(nadata, NULL, 5400 + nadata->read_disable_count,
			__LINE__);
    }
    ndata->read_enabled = enabled;
    my_data_pending = (nadata->data_pending_len &&
		       nadata->pending_data_owner == ndata);
    if (ndata->in_read || ndata->state == UDPN_IN_OPEN ||
		(my_data_pending && !enabled)) {
	/* Nothing to do. */
    } else if (enabled && my_data_pending) {
	ndata->in_read = true;
	ndata->deferred_read = true;
	/* Call the read from the selector to avoid lock nesting issues. */
	udpna_start_deferred_op(nadata);
    } else {
	udpna_check_read_state(nadata);
    }
 out_unlock:
    udpna_unlock(nadata);
}

static void
udpn_set_write_callback_enable(struct gensio *io, bool enabled)
{
    struct udpn_data *ndata = gensio_get_gensio_data(io);
    struct udpna_data *nadata = ndata->nadata;

    udpna_lock(nadata);
    if (udpn_is_closed(ndata))
	goto out_unlock;
    if (ndata->write_enabled != enabled) {
	ndata->write_enabled = enabled;
	if (ndata->state == UDPN_IN_OPEN)
	    goto out_unlock;
	if (enabled)
	    udpna_fd_write_enable(ndata->nadata);
	else
	    udpna_fd_write_disable(ndata->nadata);
    }
 out_unlock:
    udpna_unlock(nadata);
}

static void
udpn_disable(struct gensio *io)
{
    struct udpn_data *ndata = gensio_get_gensio_data(io);
    struct udpna_data *nadata = ndata->nadata;

    if (ndata->read_enabled) {
	udpna_fd_read_disable(nadata);
	ndata->read_enabled = false;
    }

    if (ndata->write_enabled) {
	udpna_fd_write_disable(nadata);
	ndata->write_enabled = false;
    }

    ndata->close_done = NULL;
    udpn_remove_from_list(&nadata->udpns, ndata);
    udpn_add_to_list(&nadata->closed_udpns, ndata);
    udpn_set_state(ndata, UDPN_CLOSED);
    nadata->disabled = true;
}

static void
udpn_handle_write_incoming(struct udpna_data *nadata, struct udpn_data *ndata)
{
    struct gensio *io = ndata->io;
    int err;

    if (ndata->in_write) {
	/* Only one write callback at a time. */
	ndata->write_pending = true;
	return;
    }
    ndata->in_write = true;
 retry:
    udpna_unlock(nadata);
    err = gensio_cb(io, GENSIO_EVENT_WRITE_READY, 0, NULL, NULL, NULL);
    udpna_lock(nadata);
    if (err)
	goto out;
    if (ndata->write_pending) {
	/* Another write came in while we were unlocked.  Retry. */
	ndata->write_pending = false;
	if (ndata->write_enabled)
	    goto retry;
    }
 out:
    ndata->in_write = false;

    if (ndata->state == UDPN_IN_CLOSE)
	udpn_finish_close(nadata, ndata);
}

static void
udpna_writehandler(struct gensio_iod *iod, void *cbdata)
{
    struct udpna_data *nadata = cbdata;
    struct gensio_link *l;

    udpna_lock_and_ref(nadata);
    if (nadata->in_write) {
	udpna_disable_write(nadata);
	goto out_unlock;
    }

    gensio_list_for_each(&nadata->udpns, l) {
	struct udpn_data *ndata = gensio_link_to_ndata(l);

	if (ndata->write_enabled) {
	    udpn_handle_write_incoming(nadata, ndata);
	    /*
	     * Only handle one per callback, the above call releases
	     * the lock and can result in the list changing.
	     */
	    break;
	}
    }
    if (nadata->write_enable_count > 0)
	udpna_enable_write(nadata);
 out_unlock:
    udpna_deref_and_unlock(nadata);
}

static int
udpna_control_laddr(struct udpna_data *nadata, bool get,
		    char *data, gensiods *datalen)
{
    unsigned int i;
    struct gensio_addr *addr;
    gensiods pos = 0;
    int rv;

    if (!get)
	return GE_NOTSUP;

    if (!nadata->fds)
	return GE_NOTREADY;

    i = strtoul(data, NULL, 0);
    if (i >= nadata->nr_fds)
	return GE_NOTFOUND;

    rv = nadata->o->sock_control(nadata->fds[i].iod,
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
udpna_control_raddr(struct udpn_data *ndata, bool get,
		    char *data, gensiods *datalen)
{
    unsigned int i;
    gensiods pos = 0;
    int rv;

    if (!get)
	return GE_NOTSUP;

    i = strtoul(data, NULL, 0);
    if (i > 0)
	return GE_NOTFOUND;

    rv = gensio_addr_to_str(ndata->raddr, data, &pos, *datalen);
    if (rv)
	return rv;

    *datalen = pos;
    return 0;
}

static int
udpna_control_lport(struct udpna_data *nadata, bool get,
		    char *data, gensiods *datalen)
{
    int rv;
    unsigned int i;
    gensiods size;

    if (!get)
	return GE_NOTSUP;

    if (!nadata->fds)
	return GE_NOTREADY;

    i = strtoul(data, NULL, 0);
    if (i >= nadata->nr_fds)
	return GE_NOTFOUND;

    size = sizeof(unsigned int);
    rv = nadata->o->sock_control(nadata->fds[i].iod, GENSIO_SOCKCTL_GET_PORT,
				 &i, &size);
    if (rv)
	return rv;
    *datalen = snprintf(data, *datalen, "%d", i);
    return 0;
}

static int
udpn_control(struct gensio *io, bool get, int option,
	     char *data, gensiods *datalen)
{
    struct udpn_data *ndata = gensio_get_gensio_data(io);
    struct udpna_data *nadata = ndata->nadata;
    struct gensio_os_funcs *o = nadata->o;
    int err;

    switch(option) {
    case GENSIO_CONTROL_MAX_WRITE_PACKET:
	if (!get)
	    return GE_NOTSUP;
	/*
	 * This is the maximum size for a normal IPv4 UDP packet (per
	 * wikipedia).  IPv6 jumbo packets can go larger, but this should
	 * be safe to advertise.
	 */
	*datalen = snprintf(data, *datalen, "%d", 65507);
	break;

    case GENSIO_CONTROL_LADDR:
	return udpna_control_laddr(nadata, get, data, datalen);

    case GENSIO_CONTROL_RADDR:
	return udpna_control_raddr(ndata, get, data, datalen);

    case GENSIO_CONTROL_RADDR_BIN:
	if (!get)
	    return GE_NOTSUP;
	gensio_addr_getaddr(ndata->raddr, data, datalen);
	break;

    case GENSIO_CONTROL_LPORT:
	return udpna_control_lport(nadata, get, data, datalen);

    case GENSIO_CONTROL_ADD_MCAST:
    case GENSIO_CONTROL_DEL_MCAST: {
	struct gensio_addr *addr;

	err = gensio_scan_network_addr(nadata->o, data,
				       GENSIO_NET_PROTOCOL_UDP, &addr);
	if (err)
	    return err;
	if (option == GENSIO_CONTROL_ADD_MCAST)
	    err = nadata->o->mcast_add(nadata->fds->iod, addr, 0, false);
	else
	    err = nadata->o->mcast_del(nadata->fds->iod, addr, 0, false);
	gensio_addr_free(addr);
	return err;
    }

    case GENSIO_CONTROL_MCAST_LOOP: {
	bool mcast_loop;
	gensiods size = sizeof(mcast_loop);
	struct gensio_iod *iod = nadata->fds->iod;

	if (get) {
	    err = o->sock_control(iod, GENSIO_SOCKCTL_GET_MCAST_LOOP,
				  &mcast_loop, &size);
	    if (err)
		return err;
	    if (mcast_loop)
		*datalen = snprintf(data, *datalen, "true");
	    else
		*datalen = snprintf(data, *datalen, "false");
	} else {
	    if (strncasecmp(data, "true", *datalen))
		mcast_loop = true;
	    else if (strncasecmp(data, "false", *datalen))
		mcast_loop = false;
	    else
		return GE_INVAL;
	    return o->sock_control(iod, GENSIO_SOCKCTL_SET_MCAST_LOOP,
				   &mcast_loop, &size);
	}
	break;
    }

    case GENSIO_CONTROL_MCAST_TTL: {
	unsigned int ttl;
	gensiods size = sizeof(ttl);
	struct gensio_iod *iod = nadata->fds->iod;

	if (get) {
	    err = o->sock_control(iod, GENSIO_SOCKCTL_SET_MCAST_TTL,
				  &ttl, &size);
	    if (err)
		return err;
	    *datalen = snprintf(data, *datalen, "%u", ttl);
	} else {
	    ttl = strtoul(data, NULL, 0);
	    return o->sock_control(iod, GENSIO_SOCKCTL_SET_MCAST_TTL,
				   &ttl, &size);
	}
	break;
    }

    case GENSIO_CONTROL_EXTRAINFO: {
	int val;
	gensiods size = sizeof(val);
	struct gensio_iod *iod = nadata->fds->iod;

	if (get) {
	    err = o->sock_control(iod, GENSIO_SOCKCTL_GET_EXTRAINFO,
				  &val, &size);
	    if (err)
		return err;
	    *datalen = snprintf(data, *datalen, "%u", val);
	} else {
	    val = !!strtoul(data, NULL, 0);
	    udpna_lock(nadata);
	    if (ndata->extrainfo != val) {
		err = 0;
		if ((val && nadata->extrainfo == 0) ||
			(!val && nadata->extrainfo == 1)) {
		    err = o->sock_control(iod, GENSIO_SOCKCTL_SET_EXTRAINFO,
					  &val, &size);
		    if (err)
			return err;
		    ndata->extrainfo = val;
		    if (val)
			nadata->extrainfo++;
		    else
			nadata->extrainfo--;
		}
	    }
	    udpna_unlock(nadata);
	}
	break;
    }

    default:
	return GE_NOTSUP;
    }
    return 0;
}

static int
gensio_udp_func(struct gensio *io, int func, gensiods *count,
		const void *cbuf, gensiods buflen, void *buf,
		const char *const *auxdata)
{
    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	return udpn_write(io, count, cbuf, buflen, auxdata);

    case GENSIO_FUNC_OPEN:
	return udpn_open(io, (void *) cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return udpn_close(io, (void *) cbuf, buf);

    case GENSIO_FUNC_FREE:
	udpn_free(io);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	udpn_set_read_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	udpn_set_write_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_DISABLE:
	udpn_disable(io);
	return 0;

    case GENSIO_FUNC_CONTROL:
	return udpn_control(io, *((bool *) cbuf), buflen, buf, count);

    default:
	return GE_NOTSUP;
    }
}

static struct udpn_data *
udp_alloc_gensio(struct udpna_data *nadata, struct gensio_iod *iod,
		 const struct gensio_addr *addr,
		 gensio_event cb, void *user_data,
		 struct gensio_list *starting_list)
{
    struct udpn_data *ndata = nadata->o->zalloc(nadata->o, sizeof(*ndata));

    if (!ndata)
	return NULL;

    ndata->o = nadata->o;
    ndata->nadata = nadata;

    ndata->deferred_op_runner = ndata->o->alloc_runner(ndata->o,
						       udpn_deferred_op, ndata);
    if (!ndata->deferred_op_runner) {
	nadata->o->free(nadata->o, ndata);
	return NULL;
    }

    ndata->raddr = gensio_addr_dup(addr);
    if (!ndata->raddr) {
	ndata->o->free_runner(ndata->deferred_op_runner);
	nadata->o->free(nadata->o, ndata);
	return NULL;
    }

    ndata->io = gensio_data_alloc(nadata->o, cb, user_data, gensio_udp_func,
				  NULL, "udp", ndata);
    if (!ndata->io) {
	gensio_addr_free(ndata->raddr);
	ndata->o->free_runner(ndata->deferred_op_runner);
	nadata->o->free(nadata->o, ndata);
	return NULL;
    }
    gensio_set_is_packet(ndata->io, true);

    ndata->myiod = iod;

    /* Stick it on the end of the list. */
    udpn_add_to_list(starting_list, ndata);
    nadata->udpn_count++;

    return ndata;
}

static void
udpna_readhandler(struct gensio_iod *iod, void *cbdata)
{
    struct udpna_data *nadata = cbdata;
    struct udpn_data *ndata;
    gensiods datalen;
    int err;

    udpna_lock_and_ref(nadata);
    if (nadata->data_pending_len) {
	nadata->readhandler_read_disabled = true;
	udpna_fd_read_disable(nadata);
	goto out_unlock;
    }

    err = nadata->o->recvfrom(iod, nadata->read_data, nadata->max_read_size,
			      &datalen, 0, nadata->curr_recvaddr);
    if (err) {
	if (!nadata->is_dummy)
	    /* Don't log on dummy accepters. */
	    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
			   "Could not accept on UDP: %s",
			   gensio_err_to_str(err));
	goto out_unlock;
    }
    if (datalen == 0)
	goto out_unlock;

    nadata->data_pending_len = datalen;
    nadata->data_pos = 0;

    if (nadata->nocon) {
	if (gensio_list_empty(&nadata->udpns)) {
	    ndata = NULL;
	} else {
	    ndata = gensio_link_to_ndata(gensio_list_first(&nadata->udpns));
	}
    } else {
	ndata = udpn_find(&nadata->udpns, nadata->curr_recvaddr);
    }
    if (ndata) {
	/* Data belongs to an existing connection. */
	nadata->pending_data_owner = ndata;
	goto got_ndata;
    }

    if (nadata->closed || !nadata->enabled) {
	nadata->data_pending_len = 0;
	goto out_unlock_enable;
    }

    /* New connection. */
    ndata = udp_alloc_gensio(nadata, iod, nadata->curr_recvaddr,
			     NULL, NULL, &nadata->udpns);
    if (!ndata)
	goto out_nomem;

    udpn_set_state(ndata, UDPN_OPEN);
    nadata->read_disable_count++;
    i_udp_add_trace(nadata, NULL, 5500 + nadata->read_disable_count, __LINE__);

    nadata->pending_data_owner = ndata;
    nadata->in_new_connection = true;
    ndata->in_read = true;
    udpna_unlock(nadata);

    gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_NEW_CONNECTION, ndata->io);

    udpna_lock(nadata);
    ndata->in_read = false;
    while (nadata->enable_done) {
	gensio_acc_done enable_done = nadata->enable_done;
	void *enable_done_data = nadata->enable_done_data;

	nadata->enable_done = NULL;
	udpna_unlock(nadata);
	enable_done(nadata->acc, enable_done_data);
	udpna_lock(nadata);
    }
    nadata->in_new_connection = false;

    if (ndata->state == UDPN_OPEN) {
    got_ndata:
	if (ndata->read_enabled && !ndata->in_read) {
	    ndata->in_read = true;
	    udpn_finish_read(ndata);
	}
    } else {
	nadata->data_pending_len = 0;
    }

    if (ndata->state == UDPN_IN_CLOSE) {
	udpn_finish_close(nadata, ndata);
	goto out_unlock_enable;
    }

    if (nadata->in_shutdown) {
	struct gensio_accepter *accepter = nadata->acc;

	nadata->in_shutdown = false;
	ndata->in_read = true;
	udpna_unlock(nadata);
	if (nadata->shutdown_done)
	    nadata->shutdown_done(accepter, nadata->shutdown_data);
	udpna_lock(nadata);
	ndata->in_read = false;
    }
    udpna_check_finish_free(nadata);
    goto out_unlock_enable;

 out_nomem:
    nadata->data_pending_len = 0;
    gensio_acc_log(nadata->acc, GENSIO_LOG_ERR,
		   "Out of memory allocating for udp port");
 out_unlock_enable:
    if (nadata->readhandler_read_disabled) {
	nadata->readhandler_read_disabled = false;
	udpna_fd_read_enable(nadata);
    }
 out_unlock:
    udpna_deref_and_unlock(nadata);
}

static int
udpna_startup(struct gensio_accepter *accepter)
{
    struct udpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    udpna_lock(nadata);
    if (!nadata->fds) {
	rv = gensio_os_open_listen_sockets(nadata->o, nadata->ai,
				   udpna_readhandler, udpna_writehandler,
				   udpna_fd_cleared, NULL, nadata,
				   nadata->opensock_flags,
				   &nadata->fds, &nadata->nr_fds);
	if (rv)
	    goto out_unlock;
    }

    nadata->enabled = true;
    udpna_enable_read(nadata);
 out_unlock:
    udpna_unlock(nadata);

    return rv;
}

static int
udpna_shutdown(struct gensio_accepter *accepter,
	       gensio_acc_done shutdown_done, void *shutdown_data)
{
    struct udpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    udpna_lock(nadata);
    if (!nadata->in_shutdown && !nadata->closed) {
	nadata->enabled = false;
	nadata->in_shutdown = true;
	nadata->closed = true;
	nadata->shutdown_done = shutdown_done;
	nadata->shutdown_data = shutdown_data;
	if (!nadata->in_new_connection)
	    udpna_start_deferred_op(nadata);
    } else {
	rv = GE_NOTREADY;
    }
    udpna_unlock(nadata);

    return rv;
}

static void
udpna_enable_op(struct gensio_runner *runner, void *cb_data)
{
    struct udpna_data *nadata = cb_data;

    udpna_lock(nadata);
    if (nadata->enable_done) {
	gensio_acc_done done = nadata->enable_done;
	void *done_data = nadata->enable_done_data;

	nadata->enable_done = NULL;
	udpna_unlock(nadata);
	done(nadata->acc, done_data);
	udpna_lock(nadata);
    }
    udpna_deref_and_unlock(nadata);
}

static int
udpna_set_accept_callback_enable(struct gensio_accepter *accepter, bool enabled,
				 gensio_acc_done done, void *done_data)
{
    struct udpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    udpna_lock(nadata);
    if (nadata->enable_done) {
	rv = GE_INUSE;
    } else {
	nadata->enabled = enabled;
	nadata->enable_done = done;
	nadata->enable_done_data = done_data;
	if (!nadata->in_new_connection) {
	    udpna_ref(nadata);
	    nadata->o->run(nadata->enable_done_runner);
	}
    }
    udpna_unlock(nadata);

    return rv;
}

static void
udpna_free(struct gensio_accepter *accepter)
{
    struct udpna_data *nadata = gensio_acc_get_gensio_data(accepter);

    udpna_lock_and_ref(nadata);

    assert(!nadata->freed);
    nadata->enabled = false;
    nadata->closed = true;
    nadata->freed = true;

    if (!nadata->disabled) {
	udpna_check_finish_free(nadata);
    } else {
	if (nadata->udpn_count == 0) {
	    unsigned int i;

	    for (i = 0; i < nadata->nr_fds; i++) {
		if (nadata->fds[i].iod)
		    nadata->o->clear_fd_handlers_norpt(nadata->fds[i].iod);
	    }
	    for (i = 0; i < nadata->nr_fds; i++) {
		if (nadata->fds[i].iod)
		    nadata->o->close(&nadata->fds[i].iod);
	    }
	}
    }
    udpna_deref_and_unlock(nadata);
}

static void
udpna_disable(struct gensio_accepter *accepter)
{
    struct udpna_data *nadata = gensio_acc_get_gensio_data(accepter);

    nadata->enabled = false;
    nadata->in_shutdown = false;
    nadata->shutdown_done = NULL;
    nadata->disabled = true;
}

static int
udpna_str_to_gensio(struct gensio_accepter *accepter, const char *addrstr,
		    gensio_event cb, void *user_data, struct gensio **new_net)
{
    struct udpna_data *nadata = gensio_acc_get_gensio_data(accepter);
    struct udpn_data *ndata = NULL;
    struct gensio_addr *addr = NULL;
    unsigned int fdi;
    int err;
    const char **iargs;
    bool is_port_set;
    int protocol = 0;

    err = gensio_scan_network_port(nadata->o, addrstr, false, &addr,
				   &protocol, &is_port_set, NULL, &iargs);
    if (err)
	return err;

    err = GE_INVAL;
    if (protocol != GENSIO_NET_PROTOCOL_UDP || !is_port_set)
	goto out_err;

    /* Don't accept any args, we can't set the readbuf size here. */
    if (iargs && iargs[0])
	goto out_err;

    /* Use the first address with the same family. */
    for (fdi = 0; fdi < nadata->nr_fds; fdi++) {
	if (gensio_addr_family_supports(addr, nadata->fds[fdi].family,
					nadata->fds[fdi].flags))
	    goto found;
    }

    goto out_err;

 found:

    udpna_lock(nadata);
    ndata = udpn_find(&nadata->udpns, addr);
    if (!ndata)
	ndata = udpn_find(&nadata->closed_udpns, addr);
    if (ndata) {
	udpna_unlock(nadata);
	err = GE_EXISTS;
	goto out_err;
    }

    ndata = udp_alloc_gensio(nadata, nadata->fds[fdi].iod, addr,
			     cb, user_data, &nadata->closed_udpns);
    if (!ndata) {
	udpna_unlock(nadata);
	err = GE_NOMEM;
	goto out_err;
    }

    gensio_set_is_client(ndata->io, true);

    udpn_start_deferred_op(ndata);
    udpna_unlock(nadata);

    *new_net = ndata->io;

    err = 0;

 out_err:
    if (addr)
	gensio_addr_free(addr);
    if (iargs)
	gensio_argv_free(nadata->o, iargs);

    return err;
}

static int
udpna_control(struct gensio_accepter *acc, bool get,
	      unsigned int option, char *data, gensiods *datalen)
{
    struct udpna_data *nadata = gensio_acc_get_gensio_data(acc);

    switch (option) {
    case GENSIO_ACC_CONTROL_LADDR:
	return udpna_control_laddr(nadata, get, data, datalen);

    case GENSIO_ACC_CONTROL_LPORT:
	return udpna_control_lport(nadata, get, data, datalen);

    default:
	return GE_NOTSUP;
    }
}

static int
gensio_acc_udp_func(struct gensio_accepter *acc, int func, int val,
		    const char *addr, void *done, void *data,
		    const void *data2, void *ret)
{
    switch (func) {
    case GENSIO_ACC_FUNC_STARTUP:
	return udpna_startup(acc);

    case GENSIO_ACC_FUNC_SHUTDOWN:
	return udpna_shutdown(acc, done, data);

    case GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK:
	return udpna_set_accept_callback_enable(acc, val, done, data);

    case GENSIO_ACC_FUNC_FREE:
	udpna_free(acc);
	return 0;

    case GENSIO_ACC_FUNC_STR_TO_GENSIO:
	return udpna_str_to_gensio(acc, addr, done, data, ret);

    case GENSIO_ACC_FUNC_DISABLE:
	udpna_disable(acc);
	return 0;

    case GENSIO_ACC_FUNC_CONTROL:
	return udpna_control(acc, (bool) val, *((unsigned int *) done),
			     (char *) data, (gensiods *) ret);

    default:
	return GE_NOTSUP;
    }
}

static int
i_udp_gensio_accepter_alloc(const struct gensio_addr *iai,
			    gensiods max_read_size,
			    bool reuseaddr, struct gensio_os_funcs *o,
			    gensio_accepter_event cb, void *user_data,
			    struct gensio_accepter **accepter)
{
    struct udpna_data *nadata;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;
    nadata->o = o;
    gensio_list_init(&nadata->udpns);
    gensio_list_init(&nadata->closed_udpns);
    nadata->refcount = 1;
    if (reuseaddr)
	nadata->opensock_flags |= GENSIO_OPENSOCK_REUSEADDR;

    if (iai)
	nadata->ai = gensio_addr_dup(iai);
    if (!nadata->ai && iai) /* Allow a null ai if it was passed in. */
	goto out_nomem;

    nadata->read_data = o->zalloc(o, max_read_size);
    if (!nadata->read_data)
	goto out_nomem;

    nadata->deferred_op_runner = o->alloc_runner(o, udpna_deferred_op, nadata);
    if (!nadata->deferred_op_runner)
	goto out_nomem;

    nadata->enable_done_runner = nadata->o->alloc_runner(nadata->o,
							 udpna_enable_op,
							 nadata);
    if (!nadata->enable_done_runner)
	goto out_nomem;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    nadata->curr_recvaddr = o->addr_alloc_recvfrom(o);
    if (!nadata->curr_recvaddr)
	goto out_nomem;

    nadata->acc = gensio_acc_data_alloc(o, cb, user_data, gensio_acc_udp_func,
					NULL, "udp", nadata);
    if (!nadata->acc)
	goto out_nomem;
    gensio_acc_set_is_packet(nadata->acc, true);

    nadata->max_read_size = max_read_size;

    *accepter = nadata->acc;
    return 0;

 out_nomem:
    udpna_do_free(nadata);
    return GE_NOMEM;
}

static int
udp_gensio_accepter_alloc(const void *gdata,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_accepter_event cb, void *user_data,
			  struct gensio_accepter **accepter)
{
    const struct gensio_addr *iai = gdata;
    gensiods max_read_size = GENSIO_DEFAULT_UDP_BUF_SIZE;
    unsigned int i;
    bool reuseaddr = false;
    int err, ival;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return GE_INVAL;
    }
    err = gensio_get_default(o, "udp", "reuseaddr", false,
			     GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    reuseaddr = ival;

    return i_udp_gensio_accepter_alloc(iai, max_read_size, reuseaddr,
				       o, cb, user_data, accepter);
}

static int
str_to_udp_gensio_accepter(const char *str, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb,
			   void *user_data,
			   struct gensio_accepter **acc)
{
    int err;
    struct gensio_addr *ai;

    err = gensio_os_scan_netaddr(o, str, true, GENSIO_NET_PROTOCOL_UDP, &ai);
    if (err)
	return err;

    err = udp_gensio_accepter_alloc(ai, args, o, cb, user_data, acc);
    gensio_addr_free(ai);

    return err;
}

static int
udp_gensio_alloc(const void *gdata, const char * const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
    const struct gensio_addr *addr = gdata;
    struct udpn_data *ndata = NULL;
    struct gensio_accepter *accepter;
    struct udpna_data *nadata = NULL;
    struct gensio_addr *laddr = NULL, *mcast = NULL, *tmpaddr, *tmpaddr2;
    int err, ival;
    struct gensio_iod *new_iod;
    gensiods max_read_size = GENSIO_DEFAULT_UDP_BUF_SIZE, size;
    unsigned int i, setup;
    bool nocon = false, mcast_loop_set = false, mcast_loop = true;
    bool reuseaddr = false;
    unsigned int mttl;

    err = gensio_get_defaultaddr(o, "udp", "laddr", false,
				 GENSIO_NET_PROTOCOL_UDP, true, false, &laddr);
    if (err && err != GE_NOTSUP) {
	gensio_log(o, GENSIO_LOG_ERR, "Invalid default udp laddr: %s",
		   gensio_err_to_str(err));
	return err;
    }
    err = gensio_get_default(o, "udp", "reuseaddr", false,
			     GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    reuseaddr = ival;
    err = gensio_get_default(o, "udp", "mttl", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    mttl = ival;

    err = GE_INVAL;
    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	tmpaddr = NULL;
	if (gensio_check_keyaddrs(o, args[i], "laddr", GENSIO_NET_PROTOCOL_UDP,
				  true, false, &tmpaddr) > 0) {
	    if (laddr)
		gensio_addr_free(laddr);
	    laddr = tmpaddr;
	    continue;
	}
	if (gensio_check_keyaddrs_noport(o, args[i], "mcast",
					 GENSIO_NET_PROTOCOL_UDP,
					 &tmpaddr) > 0) {
	    if (mcast) {
		tmpaddr2 = gensio_addr_cat(mcast, tmpaddr);
		if (!tmpaddr2) {
		    err = GE_NOMEM;
		    goto parm_err;
		}
		gensio_addr_free(mcast);
		gensio_addr_free(tmpaddr);
		mcast = tmpaddr2;
	    } else {
		mcast = tmpaddr;
	    }
	    continue;
	}
	if (gensio_check_keybool(args[i], "nocon", &nocon) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "mttl", &mttl) > 0) {
	    if (mttl < 1 || mttl > 255) {
		err = GE_INVAL;
		goto parm_err;
	    }
	    continue;
	}
	if (gensio_check_keybool(args[i], "mloop", &mcast_loop) > 0) {
	    mcast_loop_set = true;
	    continue;
	}
	if (gensio_check_keybool(args[i], "reuseaddr", &reuseaddr) > 0)
	    continue;
    parm_err:
	if (laddr)
	    gensio_addr_free(laddr);
	if (mcast)
	    gensio_addr_free(mcast);
	return err;
    }

    err = o->socket_open(o, addr, GENSIO_NET_PROTOCOL_UDP, &new_iod);
    if (err) {
	if (laddr)
	    gensio_addr_free(laddr);
	if (mcast)
	    gensio_addr_free(mcast);
	return err;
    }

    setup = GENSIO_SET_OPENSOCK_REUSEADDR;
    if (reuseaddr)
	setup |= GENSIO_OPENSOCK_REUSEADDR;
    err = o->socket_set_setup(new_iod, setup, laddr);
    if (err) {
	o->close(&new_iod);
	if (laddr)
	    gensio_addr_free(laddr);
	if (mcast)
	    gensio_addr_free(mcast);
	return err;
    }

    if (laddr) {
	gensio_addr_free(laddr);
	laddr = NULL;
    }

    if (mcast) {
	err = o->mcast_add(new_iod, mcast, 0, false);
	gensio_addr_free(mcast);
	if (err) {
	    o->close(&new_iod);
	    return err;
	}
	mcast = NULL;
    }

    if (mcast_loop_set) {
	size = sizeof(mcast_loop);
	err = o->sock_control(new_iod, GENSIO_SOCKCTL_SET_MCAST_LOOP,
			      &mcast_loop, &size);
	if (err) {
	    o->close(&new_iod);
	    return err;
	}
    }

    if (mttl > 1) {
	size = sizeof(mttl);
	err = o->sock_control(new_iod, GENSIO_SOCKCTL_SET_MCAST_TTL,
			      &mttl, &size);
	if (err) {
	    o->close(&new_iod);
	    return err;
	}
    }

    /* Allocate a dummy network accepter. */
    err = i_udp_gensio_accepter_alloc(NULL, max_read_size, reuseaddr, o,
				      NULL, NULL, &accepter);
    if (err) {
	o->close(&new_iod);
	return err;
    }
    nadata = gensio_acc_get_gensio_data(accepter);
    nadata->is_dummy = true;
    nadata->nocon = nocon;

    nadata->fds = o->zalloc(o, sizeof(*nadata->fds));
    if (!nadata->fds) {
	o->close(&new_iod);
	udpna_do_free(nadata);
	return GE_NOMEM;
    }
    nadata->fds->family = gensio_addr_get_nettype(addr);
    nadata->fds->iod = new_iod;
    nadata->nr_fds = 1;
    /* fd belongs to udpn now, updn_do_free() will close it. */

    nadata->closed = true; /* Free nadata when ndata is freed. */
    nadata->freed = true;

    ndata = udp_alloc_gensio(nadata, new_iod, addr,
			     cb, user_data, &nadata->closed_udpns);
    if (!ndata) {
	err = GE_NOMEM;
    } else {
	gensio_set_is_client(ndata->io, true);
	nadata->udpn_count = 1;
	err = o->set_fd_handlers(new_iod, nadata,
				 udpna_readhandler, udpna_writehandler, NULL,
				 udpna_fd_cleared);
    }

    if (err) {
	if (ndata)
	    udpn_do_free(ndata);
	udpna_do_free(nadata);
    } else {
	*new_gensio = ndata->io;
    }

    return err;
}

static int
str_to_udp_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    struct gensio_addr *addr;
    int err;

    err = gensio_os_scan_netaddr(o, str, false, GENSIO_NET_PROTOCOL_UDP, &addr);
    if (err)
	return err;

    err = udp_gensio_alloc(addr, args, o, cb, user_data, new_gensio);
    gensio_addr_free(addr);
    return err;
}

int
gensio_init_udp(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "udp", str_to_udp_gensio, udp_gensio_alloc);
    if (rv)
	return rv;
    rv = register_gensio_accepter(o, "udp", str_to_udp_gensio_accepter,
				  udp_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
