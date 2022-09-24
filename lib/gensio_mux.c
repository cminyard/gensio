/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/gensio_list.h>

/*
 * The protocol consists of messages.  The first byte of a message
 * is the message id.  The contents of the message depend on the
 * message id.
 *
 * The protocol is completely symmetric, there is no server or client
 * side.
 *
 * When a side of the protocol comes up, the first thing it does is
 * send an init message.  It then waits for an init message from the
 * other end.  A side will fall back to the minimum protocol version
 * of the two sides.
 *
 * After the init messages are exchanged, the connection is up.  To
 * start a channel, a new channel message is sent.  The other end will
 * respond with a new channel response message.
 *
 * The protocol identifies channel by a 16-bit channel number.  Each
 * end assigns the channel number that the remote end sends for a
 * connection.  So in the new channel message, the channel number sent
 * is the channel id that the remote end will send in data message as
 * the remote channel id.  Same with the new channel response.  The
 * ids for a channel may be different for each side.
 *
 * Flow control is done with bytes and message counts.  Each side
 * sends a total number of outstanding bytes that are allowed.  Acks
 * are done by returning the number of bytes that the user has
 * accepted.  Note that the flags (1 byte) and data size (2 bytes) is
 * considered part of the outstanding bytes for each message, so it
 * can be stored in the buffer with the data.
 */

enum mux_msgs {
    /*
     * The init messages carries just a single-byte version for now.
     * An instance must send a mux init message and wait for a mux
     * init message from the remote end before sending anything else.
     * The size is the header size in 32-bit increments.  If a newer
     * version adds data after the version, older version should
     * ignore it.
     *
     * This is version 1 of the protocol.
     *
     * +----------------+--------+-------+----------------+----------------+
     * |   1   |size(1) |    reserved    |    version     |   reserved     |
     * +----------------+--------+-------+----------------+----------------+
     */
    MUX_INIT		= 1,

    /*
     * The new channel message carries a local channel number, a
     * receive window byte size, a receive window message count, and a
     * service string.  The remote end will create a channel with its
     * own channel number and respond with a new channel response.
     * The service string is not part of the header, and is thus not in
     * the size.
     *
     * +----------------+--------+-------+----------------+----------------+
     * |   2   |size(2) |    reserved    |           channel id            |
     * +----------------+--------+-------+----------------+----------------+
     * |                          byte count window                        |
     * +----------------+----------------+----------------+----------------+
     * |        service string size      |    service string data...       |
     * +----------------+----------------+----------------+----------------+
     * |                       service string data...                      |
     * +----------------+----------------+----------------+----------------+
     */
    MUX_NEW_CHANNEL	= 2,

    /*
     * The new channel response carries a local channel number, a
     * remote channel number (the value send in the new channel
     * message), a receive window byte size, a receive window message
     * count, and an error number.  After this is received/sent with a
     * zero error code, data may be sent on the channel.
     *
     * If the error code is non-zero, it is a gensio error describing
     * why the request was denied.
     *
     * +----------------+----------------+----------------+----------------+
     * |   3   |size(3) |     reserved   |       remote channel id         |
     * +----------------+----------------+----------------+----------------+
     * |                          byte count window                        |
     * +----------------+----------------+----------------+----------------+
     * |           channel id            |           error code            |
     * +----------------+----------------+----------------+----------------+
     */
    MUX_NEW_CHANNEL_RSP	= 3,

    /*
     * The close channel message carries a remote channel number.  if
     * the remote end is not already closing, it will respond with a
     * close message.  It has a close code is a gensio error that has
     * the reason for the close.  Zero means the remote end requested
     * it.
     *
     * +----------------+----------------+----------------+----------------+
     * |   4   |size(2) |    reserved    |      remote channel id          |
     * +----------------+----------------+----------------+----------------+
     * |            close code           |            reserved             |
     * +----------------+----------------+----------------+----------------+
     */
    MUX_CLOSE_CHANNEL	= 4,

    /*
     * Data for a channel.  This carries a remote channel number, a
     * data ack, some flags, and a block of data.  The block of data
     * is "data size" long.  The data size and data are not part of
     * the header.
     *
     * +----------------+----------------+----------------+----------------+
     * |   5   |size(2) |     flags      |      remote channel id          |
     * +----------------+----------------+----------------+----------------+
     * |    Ack count (number of bytes received by user)                   |
     * +----------------+----------------+----------------+----------------+
     * |            data size            |            data....             |
     * +----------------+----------------+----------------+----------------+
     * |                               data...                             |
     * +----------------+----------------+----------------+----------------+
     */
    MUX_DATA		= 5,
};

#define MUX_MAX_MSG_NUM MUX_DATA

static unsigned int mux_msg_hdr_sizes[] = { 0, 1, 2, 3, 2, 2 };

/* External flags for MUX_DATA */
#define MUX_FLAG_END_OF_MESSAGE		(1 << 0)
#define MUX_FLAG_OUT_OF_BOUND		(1 << 1)

#define MUX_MAX_HDR_SIZE	12
#define MUX_MIN_SEND_WINDOW_SIZE	128

#ifdef ENABLE_INTERNAL_TRACE
#define MUX_TRACING
#endif

struct mux_data;

enum mux_inst_state {
    MUX_INST_CLOSED,

    /*
     * Channel has been allocated on a received new channel message
     * it, but channel data has not been fully received.
     */
    MUX_INST_PENDING_OPEN,

    /* open channel called for this instance, response not received.  */
    MUX_INST_IN_OPEN,

    MUX_INST_OPEN,

    /* Channel was closed before the open was complete. */
    MUX_INST_IN_OPEN_CLOSE,

    /* Local end requested a close. */
    MUX_INST_IN_CLOSE,

    /* Remote end requested a close, or the child gensio returned an error. */
    MUX_INST_IN_REM_CLOSE,

    /*
     * Close is sent/received or the child has closed, but there is
     * still a read callback pending or the close result has not
     * been delivered.
     */
    MUX_INST_IN_CLOSE_FINAL,
};

struct mux_inst {
    struct gensio_os_funcs *o;
    struct gensio *io;
    struct mux_data *mux;
    unsigned int refcount;
    unsigned int id;
    unsigned int remote_id;
    enum mux_inst_state state;
    int errcode; /* If an error occurs, it is stored here. */
    bool send_new_channel;
    bool send_close;
    bool is_client;
    bool close_sent;
    bool do_oob;

    /*
     * The service, either the local one or the remote one.
     */
    char *service;
    size_t service_len;

    unsigned char *read_data;
    gensiods read_data_pos;
    gensiods read_data_len;
    gensiods max_read_size;
    bool read_enabled;
    bool in_read_report;
    int in_newchannel;

    /* Number of bytes we need to send an ack for. */
    gensiods received_unacked;

    unsigned char *write_data;
    gensiods write_data_pos;
    gensiods write_data_len;
    gensiods max_write_size;
    bool write_ready_enabled;
    bool in_write_ready;

    /* Number of bytes we have sent that are not acked. */
    gensiods sent_unacked;

    /*
     * Maximum number of bytes the remote end told us we can have
     * outstanding.
     */
    unsigned int send_window_size;

    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

    /* Used for current message being transmitted. */
    unsigned char hdr[MUX_MAX_HDR_SIZE];
    struct gensio_sg sg[3];
    unsigned int sgpos;
    unsigned int sglen;
    gensiods cur_msg_len;

    gensio_done_err open_done;
    void *open_data;

    gensio_done close_done;
    void *close_data;
    bool close_called;
    bool freed;

    /* Link for list of channels waiting write. */
    struct gensio_link wrlink;
    bool wr_ready; /* Also true if chan == muxdata->sending_chan. */

    bool in_wrlist;
    bool in_open_chan;

    struct gensio_link link;
};

static gensiods
chan_next_write_pos(struct mux_inst *chan, unsigned int count)
{
    unsigned rv = chan->write_data_pos + count;

    if (rv >= chan->max_write_size)
	rv -= chan->max_write_size;
    return rv;
}

static void
chan_incr_write_pos(struct mux_inst *chan, unsigned int count)
{
    chan->write_data_pos = chan_next_write_pos(chan, count);
    chan->write_data_len -= count;
}

static void
chan_addwrbuf(struct mux_inst *chan, const unsigned char *data, gensiods len)
{
    gensiods epos = chan->write_data_pos + chan->write_data_len;

    if (epos >= chan->max_write_size)
	epos -= chan->max_write_size;

    if (len + epos > chan->max_write_size) {
	gensiods plen = chan->max_write_size - epos;

	memcpy(chan->write_data + epos, data, plen);
	data += plen;
	len -= plen;
	epos = 0;
	chan->write_data_len += plen;
    }
    memcpy(chan->write_data + epos, data, len);
    chan->write_data_len += len;
}

static gensiods
chan_next_read_pos(struct mux_inst *chan, unsigned int count)
{
    unsigned rv = chan->read_data_pos + count;

    if (rv >= chan->max_read_size)
	rv -= chan->max_read_size;
    return rv;
}

static void
chan_addrdbuf(struct mux_inst *chan, const unsigned char *data, gensiods len)
{
    gensiods epos = chan->read_data_pos + chan->read_data_len;

    if (epos >= chan->max_read_size)
	epos -= chan->max_read_size;

    if (len + epos > chan->max_read_size) {
	gensiods plen = chan->max_read_size - epos;

	memcpy(chan->read_data + epos, data, plen);
	data += plen;
	len -= plen;
	epos = 0;
	chan->read_data_len += plen;
    }
    memcpy(chan->read_data + epos, data, len);
    chan->read_data_len += len;
}

static void
chan_addrdbyte(struct mux_inst *chan, unsigned char data)
{
    chan_addrdbuf(chan, &data, 1);
}

static gensiods
chan_rdbufleft(struct mux_inst *chan)
{
    return chan->max_read_size - chan->read_data_len;
}

struct gensio_mux_config {
    struct gensio_os_funcs *o;
    gensiods max_read_size;
    gensiods max_write_size;
    char *service;
    size_t service_len;
    unsigned int max_channels;
    bool is_client;
};

enum mux_state {
    /*
     * Mux is in allocation.
     */
    MUX_IN_ALLOC,

    /*
     * Mux has been allocated but not opened or all channels are closed.
     */
    MUX_CLOSED,

    /*
     * Mux child open was done, but has not yet finished.
     */
    MUX_WAITING_CHILD_OPEN,

    /*
     * Mux is started, but has not received an init message yet.
     */
    MUX_UNINITIALIZED,

    /*
     * Server only, mux has received init message but has not received
     * a new channel message yet.
     */
    MUX_WAITING_OPEN,

    /*
     * Client only, mux has received init message and sent a new channel
     * message, but has not received the response.
     */
    MUX_IN_OPEN,

    /*
     * Mux is operational.
     */
    MUX_OPEN,

    /*
     * Mux has closed the child gensio but has not received the close_done.
     */
    MUX_IN_CLOSE,
};

#ifdef MUX_TRACING
struct mux_trace_info {
    struct mux_inst *chan;
    enum mux_state state;
    enum mux_state new_state;
    enum mux_inst_state cstate;
    enum mux_inst_state new_cstate;
    int line;
};
#define MUX_TRACE_SIZE 256
#endif

struct mux_data {
    struct gensio *child;
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    unsigned int refcount;

    gensiods max_read_size;
    gensiods max_write_size;

    int exit_err;
    enum mux_state exit_state;

    unsigned int max_channels;

    /* Number of channels that are not closed. */
    unsigned int nr_not_closed;

    bool is_client;

    /*
     * Small piece of data for sending new channel responses.  It's
     * separate in case the channel data could not be allocated.  The
     * protocol only allows one new channel request at a time.
     */
    unsigned char xmit_data[MUX_MAX_HDR_SIZE];
    gensiods xmit_data_pos;
    gensiods xmit_data_len;

    /*
     * This is for calling the gensio_acc_gensio's open done handler
     * when the mux is completely opened in server mode.
     */
    gensio_done_err acc_open_done;
    void *acc_open_data;

    /*
     * Channel I am currently sending data on.
     */
    struct mux_inst *sending_chan;

    enum mux_state state;

    /* If the mux was shutdown due to an error, this is set. */
    bool err_shutdown;

    /* Am I currently receiving header or data? */
    bool in_hdr;

    /* Current working incoming header. */
    unsigned char hdr[MUX_MAX_HDR_SIZE];
    unsigned int hdr_pos;
    unsigned int hdr_size;
    enum mux_msgs msgid;

    /* Working info when receiving the beginning of the data. */
    unsigned int data_pos;
    unsigned int data_size;

    /*
     * Channel I am currently receiving for.
     */
    struct mux_inst *curr_chan;

    /* The last id we chose for a channel. */
    unsigned int last_id;

    /* Mux instances with write pending. */
    struct gensio_list wrchans;

    /* Muxes waiting to open. */
    struct gensio_list openchans;
    unsigned int opencount;

    /*
     * Used when doing an error close and we get a normal close in the
     * mean time.  This will cause the error close to invoke the
     * normal close.
     */
    bool do_normal_close;
    struct mux_inst *do_normal_close_chan;

    /*
     * All the channels in the mux.  The channels are kept in id
     * order.
     */
    struct gensio_list chans;

#ifdef MUX_TRACING
    struct mux_trace_info trace[MUX_TRACE_SIZE];
    unsigned int trace_pos;
#endif
};

static void
i_mux_set_state(struct mux_data *mux, enum mux_state state)
{
    mux->state = state;
}
static void
i_muxc_set_state(struct mux_inst *chan, enum mux_inst_state state)
{
    chan->state = state;
}

#ifdef MUX_TRACING
static void
i_mux_add_trace(struct mux_data *mux, struct mux_inst *chan,
		enum mux_state state,
		enum mux_state new_state,
		enum mux_inst_state cstate,
		enum mux_inst_state new_cstate,
		int line)
{
    unsigned int pos = mux->trace_pos;

    mux->trace[pos].chan = chan;
    mux->trace[pos].state = state;
    mux->trace[pos].new_state = new_state;
    mux->trace[pos].cstate = cstate;
    mux->trace[pos].new_cstate = new_cstate;
    mux->trace[pos].line = line;
    if (pos >= MUX_TRACE_SIZE - 1)
	mux->trace_pos = 0;
    else
	mux->trace_pos = pos + 1;
}
#define mux_add_trace(mux, chan, new_state, new_cstate) \
    i_mux_add_trace(mux, chan, mux->state, new_state, chan->state, \
		    new_cstate, __LINE__)

#define mux_set_state(mux, nstate) do {					\
	i_mux_add_trace(mux, NULL, mux->state, nstate, 99, 99, __LINE__);\
	i_mux_set_state(mux, nstate);					\
    } while(false)

#define muxc_set_state(chan, nstate) do {			\
	i_mux_add_trace(chan->mux, chan, chan->mux->state, 99,	\
			chan->state, nstate, __LINE__);		\
	i_muxc_set_state(chan, nstate);				\
    } while(false)

#else
#define i_mux_add_trace(mux, chan, state, cstate, new_state, new_cstate, line)
#define mux_add_trace(mux, chan, cstate, new_cstate)
#define mux_set_state i_mux_set_state
#define muxc_set_state i_muxc_set_state
#endif

static void chan_sched_deferred_op(struct mux_inst *chan);
static int muxc_gensio_handler(struct gensio *io, int func, gensiods *count,
			       const void *cbuf, gensiods buflen, void *buf,
			       const char *const *auxdata);
static void muxc_add_to_wrlist(struct mux_inst *chan);
static void mux_shutdown_channels(struct mux_data *muxdata, int err);

static void
gmux_log_err(struct mux_data *f, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    gensio_vlog(f->o, GENSIO_LOG_ERR, fmt, ap);
    va_end(ap);
}

static void
muxdata_free(struct mux_data *muxdata)
{
    assert(gensio_list_empty(&muxdata->chans));

    if (muxdata->lock)
	muxdata->o->free_lock(muxdata->lock);
    if (muxdata->child)
	gensio_free(muxdata->child);
    muxdata->o->free(muxdata->o, muxdata);
}

static void
i_mux_lock(struct mux_data *muxdata)
{
    muxdata->o->lock(muxdata->lock);
}

static void
i_mux_unlock(struct mux_data *muxdata)
{
    muxdata->o->unlock(muxdata->lock);
}

#ifdef MUX_TRACING
#define mux_lock(m) do {						\
	i_mux_lock(m);							\
	i_mux_add_trace(m, NULL, m->state, 99, 99, 100, __LINE__);	\
    } while (false)

#define mux_unlock(m) do {						\
	i_mux_add_trace(m, NULL, m->state, 99, 99, 101, __LINE__);	\
	i_mux_unlock(m);						\
    } while (false)
#else
#define mux_lock i_mux_lock
#define mux_unlock i_mux_unlock
#endif

static void i_mux_ref(struct mux_data *mux)
{
    assert(mux->refcount > 0);
    mux->refcount++;
}

static bool i_mux_deref(struct mux_data *mux)
{
    assert(mux->refcount > 0);
    if (--mux->refcount == 0) {
	muxdata_free(mux);
	return true;
    }
    return false;
}

static bool i_mux_deref_and_unlock(struct mux_data *mux)
{
    assert(mux->refcount > 0);
    if (--mux->refcount == 0) {
	i_mux_unlock(mux);
	muxdata_free(mux);
	return true;
    }
    i_mux_unlock(mux);
    return false;
}

#ifdef MUX_TRACING
#define mux_ref(m) do {							\
	i_mux_add_trace(m, NULL, m->state, 99, 104,			\
			m->refcount + 2000, __LINE__);			\
	i_mux_ref(m);							\
    } while (false)

#define mux_deref(m) do {						\
	i_mux_add_trace(m, NULL, m->state, 99, 105,			\
			m->refcount + 2000, __LINE__);			\
	i_mux_deref(m);							\
    } while (false)

#else
#define mux_ref i_mux_ref
#define mux_deref i_mux_deref
#endif

static void
chan_free(struct mux_inst *chan)
{
    struct gensio_os_funcs *o = chan->o;

    if (chan->io)
	gensio_data_free(chan->io);
    if (chan->read_data)
	o->free(o, chan->read_data);
    if (chan->write_data)
	o->free(o, chan->write_data);
    if (chan->service)
	o->free(o, chan->service);
    if (chan->deferred_op_runner)
	o->free_runner(chan->deferred_op_runner);
    o->free(o, chan);
}

static void i_chan_ref(struct mux_inst *chan)
{
    assert(chan->refcount > 0);
    chan->refcount++;
}

static bool i_chan_deref(struct mux_inst *chan)
{
    assert(chan->refcount > 0);
    if (--chan->refcount == 0) {
	struct mux_data *mux = chan->mux;

	gensio_list_rm(&mux->chans, &chan->link);
	chan_free(chan);
	i_mux_deref(mux);
	return true;
    }
    return false;
}

#ifdef MUX_TRACING
#define chan_ref(c) do {						\
	i_mux_add_trace(c->mux, c, c->mux->state, 106,			\
			c->state, c->refcount + 3000, __LINE__);	\
	i_chan_ref(c);							\
    } while (false)

static bool i2_chan_deref(struct mux_inst *chan, int line)
{
    i_mux_add_trace(chan->mux, chan, chan->mux->state, 107,
		    chan->state, chan->refcount + 3000, line);
    return i_chan_deref(chan);
}

#define chan_deref(c) i2_chan_deref(c, __LINE__)
#else
#define chan_ref i_chan_ref
#define chan_deref i_chan_deref
#endif

#ifdef MUX_TRACING
#define mux_lock_and_ref(m) do {					\
	i_mux_lock(m);							\
	i_mux_add_trace(m, NULL, m->state, 99, 102, 2000 + m->refcount,	\
			__LINE__);					\
	i_mux_ref(m);							\
    } while (false)

#define mux_deref_and_unlock(m) do {					\
	i_mux_add_trace(m, NULL, m->state, 99, 103, 2000 + m->refcount, \
			__LINE__);					\
	i_mux_deref_and_unlock(m);					\
    } while (false)

#else
#define mux_lock_and_ref(m) do {					\
	i_mux_lock(m);							\
	i_mux_ref(m);							\
    } while (false)

#define mux_deref_and_unlock(m) i_mux_deref_and_unlock(m)

#endif

static struct mux_inst *
mux_chan0(struct mux_data *muxdata)
{
    return gensio_container_of(gensio_list_first(&muxdata->chans),
			       struct mux_inst, link);
}

static struct mux_inst *
mux_firstchan(struct mux_data *muxdata)
{
    struct gensio_link *l;
    struct mux_inst *chan;

    gensio_list_for_each(&muxdata->chans, l) {
	chan = gensio_container_of(l, struct mux_inst, link);
	if (chan->state != MUX_INST_CLOSED &&
		chan->state != MUX_INST_PENDING_OPEN)
	    return chan;
    }
    abort();
}

static int
mux_firstchan_event(struct mux_data *muxdata, int event, int err,
		    unsigned char *buf, gensiods *buflen,
		    const char * const * auxdata)
{
    int rerr;
    struct mux_inst *chan;

    chan = mux_firstchan(muxdata);
    chan_ref(chan);
    mux_unlock(muxdata);
    rerr = gensio_cb(chan->io, event, err, buf, buflen, auxdata);
    mux_lock(muxdata);
    chan_deref(chan);

    return rerr;
}

static bool
mux_channel_set_closed(struct mux_inst *chan, gensio_done close_done,
		       void *close_data)
{
    struct mux_data *muxdata = chan->mux;
    int err;

    muxc_set_state(chan, MUX_INST_CLOSED);
    assert(muxdata->nr_not_closed > 0);
    muxdata->nr_not_closed--;
    mux_add_trace(muxdata, chan, 150, muxdata->nr_not_closed);
    if (muxdata->nr_not_closed == 0) {
	/* There are no open instances, shut the mux down. */
	if (muxdata->state == MUX_IN_CLOSE) {
	    muxdata->do_normal_close = true;
	    muxdata->do_normal_close_chan = chan;
	    return true;
	}
	mux_set_state(muxdata, MUX_IN_CLOSE);
	err = gensio_close(muxdata->child, close_done, close_data);
	if (!err)
	    return true;
    }
    return false;
}

static void
finish_close(struct mux_inst *chan)
{
    struct mux_data *muxdata = chan->mux;

    if (chan->close_done) {
	gensio_done close_done = chan->close_done;

	chan->close_done = NULL;
	/*
	 * Note that we already have ref-ed the channel when the close
	 * started, no need to ref it again here.
	 */
	mux_unlock(muxdata);
	close_done(chan->io, chan->close_data);
	mux_lock(muxdata);
    }
    chan_deref(chan);
}

static void
i_finish_close_close_done(struct mux_inst *chan, struct mux_data *muxdata)
{
    mux_set_state(muxdata, MUX_CLOSED);
    finish_close(chan);
}

static void
finish_close_close_done(struct gensio *child, void *close_data)
{
    struct mux_inst *chan = close_data;
    struct mux_data *muxdata = chan->mux;

    mux_lock_and_ref(muxdata);
    i_finish_close_close_done(chan, muxdata);
    mux_deref_and_unlock(muxdata);
}

static void
mux_channel_finish_close(struct mux_inst *chan)
{
    if (!mux_channel_set_closed(chan, finish_close_close_done, chan))
	finish_close(chan);
}

static void
mux_send_new_channel_rsp(struct mux_data *muxdata, unsigned int remote_id,
			 unsigned int max_read_size, unsigned int id,
			 int err)
{
    muxdata->xmit_data[0] = (MUX_NEW_CHANNEL_RSP << 4) | 0x3;
    muxdata->xmit_data[1] = 0;
    gensio_u16_to_buf(&muxdata->xmit_data[2], remote_id);
    gensio_u32_to_buf(&muxdata->xmit_data[4], max_read_size);
    gensio_u16_to_buf(&muxdata->xmit_data[8], id);
    gensio_u16_to_buf(&muxdata->xmit_data[10], err);
    muxdata->xmit_data_pos = 0;
    muxdata->xmit_data_len = 12;
    gensio_set_write_callback_enable(muxdata->child, true);
}

static void
mux_send_init(struct mux_data *muxdata)
{
    muxdata->xmit_data[0] = (MUX_INIT << 4) | 0x1;
    muxdata->xmit_data[1] = 0;
    muxdata->xmit_data[2] = 1;
    muxdata->xmit_data[3] = 0;
    muxdata->xmit_data_pos = 0;
    muxdata->xmit_data_len = 4;
}

/*
 * Must be called with an extra refcount held.
 */
static void
chan_check_send_more(struct mux_inst *chan)
{
    int err;

    if (chan->in_write_ready)
	/* Another caller is already handling, just let it retry. */
	return;
    chan->in_write_ready = true;

    /* Need at least 4 bytes to write a message. */
    while (chan->max_write_size - chan->write_data_len >= 4 &&
	   chan->write_ready_enabled && chan->state == MUX_INST_OPEN) {
	chan_ref(chan);
	mux_unlock(chan->mux);
	err = gensio_cb(chan->io, GENSIO_EVENT_WRITE_READY, 0, NULL,
			NULL, NULL);
	mux_lock(chan->mux);
	if (chan_deref(chan))
	    return; /* chan was freed. */
	if (err) {
	    chan->errcode = err;
	    break;
	}
    }
    chan->in_write_ready = false;
}

static bool
full_msg_ready(struct mux_inst *chan, gensiods *rlen)
{
    gensiods len;

    if (chan->read_data_len == 0)
	return false;

    assert(chan->read_data_len >= 3);
    len = chan->read_data[chan_next_read_pos(chan, 1)] << 8;
    len |= chan->read_data[chan_next_read_pos(chan, 2)];
    assert(len > 0);

    if (rlen)
	*rlen = len;

    return len + 3 <= chan->read_data_len;
}

/*
 * Must be called with an extra refcount held.
 */
static void
chan_check_read(struct mux_inst *chan)
{
    struct mux_data *muxdata = chan->mux;
    unsigned char flags;
    gensiods len = 0, olen, rcount, orcount, pos, to_ack;
    const char *flstr[3];
    unsigned int i;
    bool fullmsg;
    int err;

    while (((fullmsg = full_msg_ready(chan, &len)) || chan->errcode) &&
	   chan->read_enabled && !chan->in_read_report) {
	if (chan->errcode && !fullmsg) {
	    /* error is true and a full message is not present. */
	    chan->in_read_report = true;
	    chan->read_enabled = false;
	    mux_unlock(muxdata);
	    err = gensio_cb(chan->io, GENSIO_EVENT_READ, chan->errcode,
			    NULL, NULL, NULL);
	    mux_lock(muxdata);
	    chan->in_read_report = false;
	    if (err)
		break;
	    continue;
	}

	flags = chan->read_data[chan->read_data_pos];
	pos = chan_next_read_pos(chan, 3);
	to_ack = 0;
	olen = 0;

	chan->in_read_report = true;
	i = 0;
	if (flags & MUX_FLAG_OUT_OF_BOUND) {
	    if (!chan->do_oob) {
		rcount = len;
		orcount = rcount;
		goto skip_oob_data;
	    }
	    flstr[i++] = "oob";
	}
	flstr[i] = NULL;
	if (pos + len > chan->max_read_size) {
	    /* Buffer wraps, deliver in two parts. */
	    rcount = chan->max_read_size - pos;
	    orcount = rcount;
	    mux_unlock(muxdata);
	    err = gensio_cb(chan->io, GENSIO_EVENT_READ,
			    0, chan->read_data + pos, &rcount, flstr);
	    mux_lock(muxdata);
	    if (err) {
		chan->errcode = err;
		goto after_read_done;
	    }
	    if (rcount > orcount)
		rcount = orcount;
	skip_oob_data:
	    len -= rcount;
	    to_ack += rcount;
	    olen += rcount;
	    if (rcount < orcount || !chan->read_enabled)
		/* User didn't consume all data. */
		goto after_read_done;
	    pos = 0;
	}
	rcount = len;
	orcount = rcount;
	mux_unlock(muxdata);
	if (flags & MUX_FLAG_END_OF_MESSAGE)
	    flstr[i++] = "eom";
	flstr[i] = NULL;
	err = gensio_cb(chan->io, GENSIO_EVENT_READ,
			0, chan->read_data + pos, &rcount, flstr);
	mux_lock(muxdata);
	if (err) {
	    chan->errcode = err;
	    goto after_read_done;
	}
	if (rcount > orcount)
	    rcount = orcount;
	len -= rcount;
	to_ack += rcount;
	olen += rcount;
    after_read_done:
	chan->in_read_report = false;

	if (len > 0) {
	    /* Partial read, create a new 3-byte header over the data left. */
	    chan->read_data_pos = chan_next_read_pos(chan, olen);
	    chan->read_data_len -= olen;
	    chan->read_data[chan->read_data_pos] = flags;
	    chan->read_data[chan_next_read_pos(chan, 1)] = len >> 8;
	    chan->read_data[chan_next_read_pos(chan, 2)] = len & 0xff;
	} else {
	    chan->read_data_pos = chan_next_read_pos(chan, olen + 3);
	    chan->read_data_len -= olen + 3;
	    to_ack += 3;
	}
	chan->received_unacked += to_ack;
    }
    /*
     * Schedule an ack send if we need it.  The send_close thing may
     * look strange, but we delay finishing the close until all read
     * data is delivered, so if all the data is processed and a close
     * is pending, we send it.
     */
    if (chan->received_unacked ||
		(chan->send_close && chan->read_data_len == 0))
	muxc_add_to_wrlist(chan);
}

static void
chan_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct mux_inst *chan = cbdata;
    struct mux_data *muxdata = chan->mux;

    mux_lock_and_ref(muxdata);
    chan->deferred_op_pending = false;
    chan_check_send_more(chan);
    chan_check_read(chan);

    /*
     * If there is a not full message pending, there is no data to send,
     * we are not currently in a read/write callback, and we are ready to
     * finish the close.
     */
    if (!chan->wr_ready && !chan->in_write_ready &&
		!chan->deferred_op_pending &&
		!chan->in_read_report &&
		chan->state == MUX_INST_IN_CLOSE_FINAL)
	mux_channel_finish_close(chan);
    chan_deref(chan);
    mux_deref_and_unlock(muxdata);
}

static void
chan_sched_deferred_op(struct mux_inst *chan)
{
    if (!chan->deferred_op_pending) {
	chan_ref(chan);
	chan->deferred_op_pending = true;
	chan->o->run(chan->deferred_op_runner);
    }
}

static void
muxc_add_to_wrlist(struct mux_inst *chan)
{
    struct mux_data *muxdata = chan->mux;

    if (!chan->wr_ready && !muxdata->err_shutdown) {
	assert(!chan->in_wrlist);
	gensio_list_add_tail(&muxdata->wrchans, &chan->wrlink);
	chan->wr_ready = true;
	chan->in_wrlist = true;
	if (muxdata->state != MUX_CLOSED)
	    gensio_set_write_callback_enable(muxdata->child, true);
    }
}

static int
muxc_write(struct mux_inst *chan, gensiods *count,
	   const struct gensio_sg *sg, gensiods sglen,
	   const char *const *auxdata)
{
    struct mux_data *muxdata = chan->mux;
    gensiods rcount, i, tot_len = 0;
    unsigned char hdr[3];
    gensiods len;
    bool truncated = false;

    for (i = 0; i < sglen; i++)
	tot_len += sg[i].buflen;
    if (tot_len == 0) {
	*count = 0;
	return 0;
    }
    tot_len += 3; /* Add the header. */

    mux_lock(muxdata);
    if (chan->state != MUX_INST_OPEN) {
	mux_unlock(muxdata);
	return GE_NOTREADY;
    }

    if (chan->errcode) {
	int err = chan->errcode;

	mux_unlock(muxdata);
	return err;
    }

    if (chan->in_newchannel) {
	/*
	 * The user sent from the new channel event.  This is a fairly
	 * complicated scenario, the user may expect a data exchange,
	 * so we can't wait for the return from the new channel event
	 * here.  In this case, we go ahead and finish the channel
	 * response and set in_newchannel to 0 to tell the new channel
	 * event handling what happened.
	 */
	chan->in_newchannel = 0;
	mux_send_new_channel_rsp(muxdata, chan->remote_id,
				 chan->max_read_size,
				 chan->id, 0);
	if (chan->service_len) {
	    /* Ack the service data. */
	    chan->received_unacked = chan->service_len;
	    muxc_add_to_wrlist(chan);
	}
    }

    /*
     * Just return on buffer full.  We need 3 bytes for the header and at
     * least a byte of data.
     */
    if (chan->max_write_size - chan->write_data_len < 4) {
    out_unlock_nosend:
	mux_unlock(muxdata);
	if (count)
	    *count = 0;
	return 0;
    }

    if (tot_len > chan->max_write_size - chan->write_data_len) {
	/* Can only send as much as we have buffer for. */
	tot_len = chan->max_write_size - chan->write_data_len;
	if (tot_len <= 3)
	    goto out_unlock_nosend;
	truncated = true;
    }

    if (tot_len > chan->send_window_size / 2) {
	/* Only allow sends to 1/2 the window size. */
	tot_len = chan->send_window_size / 2;
	if (tot_len <= 3)
	    goto out_unlock_nosend;
	truncated = true;
    }

    /* FIXME - consolidate writes if possible. */

    /* Construct the header and put it in first. */
    hdr[0] = 0; /* flags */
    if (!truncated && gensio_str_in_auxdata(auxdata, "eom"))
	hdr[0] |= MUX_FLAG_END_OF_MESSAGE;
    if (gensio_str_in_auxdata(auxdata, "oob"))
	hdr[0] |= MUX_FLAG_OUT_OF_BOUND;
    gensio_u16_to_buf(hdr + 1, tot_len - 3);
    chan_addwrbuf(chan, hdr, 3);
    tot_len -= 3;

    rcount = 0;
    for (i = 0; i < sglen && tot_len; i++) {
	len = sg[i].buflen;
	if (len > tot_len)
	    len = tot_len;
	chan_addwrbuf(chan, sg[i].buf, len);
	rcount += len;
	tot_len -= len;
    }

    muxc_add_to_wrlist(chan);
    mux_unlock(muxdata);

    if (count)
	*count = rcount;
    return 0;
}

static void
muxc_set_read_callback_enable(struct mux_inst *chan, bool enabled)
{
    mux_lock(chan->mux);
    if (chan->read_enabled != enabled) {
	chan->read_enabled = enabled;
	if (enabled)
	    chan_sched_deferred_op(chan);
    }
    mux_unlock(chan->mux);
}

static void
muxc_set_write_callback_enable(struct mux_inst *chan, bool enabled)
{
    mux_lock(chan->mux);
    if (chan->write_ready_enabled != enabled) {
	chan->write_ready_enabled = enabled;
	if (enabled)
	    chan_sched_deferred_op(chan);
    }
    mux_unlock(chan->mux);
}

static void
chan_send_close(struct mux_inst *chan)
{
    assert(chan->sglen == 0);
    chan->hdr[0] = (MUX_CLOSE_CHANNEL << 4) | 0x2;
    chan->hdr[1] = 0;
    gensio_u16_to_buf(&chan->hdr[2], chan->remote_id);
    if (chan->errcode == GE_REMCLOSE)
	gensio_u16_to_buf(&chan->hdr[4], 0);
    else
	gensio_u16_to_buf(&chan->hdr[4], chan->errcode);
    gensio_u16_to_buf(&chan->hdr[6], 0);
    chan->sg[0].buf = chan->hdr;
    chan->sg[0].buflen = 8;
    chan->sglen = 1;
    chan->cur_msg_len = 0; /* Data isn't in chan->write_data. */
    muxc_add_to_wrlist(chan);
}

static int
muxc_close_nolock(struct mux_inst *chan,
		  gensio_done close_done, void *close_data)
{
    switch (chan->state) {
    case MUX_INST_IN_OPEN:
	/* Handle it once the open response is received. */
	muxc_set_state(chan, MUX_INST_IN_OPEN_CLOSE);
	break;

    case MUX_INST_IN_REM_CLOSE:
	muxc_set_state(chan, MUX_INST_IN_CLOSE_FINAL);
	chan_sched_deferred_op(chan);
	break;

    case MUX_INST_OPEN:
	muxc_set_state(chan, MUX_INST_IN_CLOSE);
	if (chan->in_newchannel) {
	    chan->in_newchannel = 2;
	    muxc_set_state(chan, MUX_INST_IN_CLOSE_FINAL);
	    chan_sched_deferred_op(chan);
	} else {
	    chan->send_close = true;
	    muxc_add_to_wrlist(chan);
	}
	break;

    default:
	return GE_NOTREADY;
    }

    chan_ref(chan);
    chan->close_done = close_done;
    chan->close_data = close_data;

    return 0;
}

static int
muxc_close(struct mux_inst *chan, gensio_done close_done, void *close_data)
{
    struct mux_data *muxdata = chan->mux;
    int err = GE_NOTREADY;

    mux_lock(muxdata);
    if (!chan->close_called) {
	chan->close_called = true;
	err = muxc_close_nolock(chan, close_done, close_data);
    }
    mux_unlock(muxdata);
    return err;
}

static void
muxc_free(struct mux_inst *chan)
{
    struct mux_data *muxdata = chan->mux;

    mux_lock_and_ref(muxdata);
    if (chan->in_newchannel) {
	chan->in_newchannel = 2;
	goto out_deref;
    }

    switch (chan->state) {
    case MUX_INST_IN_REM_CLOSE:
    case MUX_INST_IN_CLOSE:
    case MUX_INST_IN_CLOSE_FINAL:
    case MUX_INST_IN_OPEN_CLOSE:
	chan->close_done = NULL;
	/* deref will cause it to be freed when the close is finished. */
	break;

    case MUX_INST_CLOSED:
	/* deref will cause it to be freed here. */
	break;

    case MUX_INST_OPEN:
    case MUX_INST_IN_OPEN:
	muxc_close_nolock(chan, NULL, NULL);
	assert(chan->refcount > 1);
	break;

    case MUX_INST_PENDING_OPEN:
	/* Shouldn't be possible. */
	abort();
    }
 out_deref:
    chan_deref(chan);
    mux_deref_and_unlock(muxdata);
}

static int
muxc_disable(struct mux_inst *chan)
{
    struct mux_data *muxdata = chan->mux;

    mux_set_state(muxdata, MUX_CLOSED);
    gensio_disable(muxdata->child);
    return 0;
}

static unsigned int
next_chan_id(struct mux_data *muxdata, unsigned int num)
{
    if (num >= muxdata->max_channels - 1)
	return 0;
    else
	return num + 1;
}

static int
mux_new_channel(struct mux_data *muxdata, gensio_event cb, void *user_data,
		bool is_client, struct mux_inst **new_mux)
{
    struct mux_inst *chan;
    unsigned int id;
    struct gensio_os_funcs *o = muxdata->o;
    int err = GE_NOMEM;

    chan = o->zalloc(o, sizeof(*chan));
    if (!chan)
	return GE_NOMEM;

    chan->o = o;

    chan->deferred_op_runner = o->alloc_runner(o, chan_deferred_op, chan);
    if (!chan->deferred_op_runner)
	goto out_free;

    chan->io = gensio_data_alloc(o, cb, user_data, muxc_gensio_handler,
				 muxdata->child,
				 "mux-instance", chan);
    if (!chan->io)
	goto out_free;
    gensio_set_is_packet(chan->io, true);
    gensio_set_is_reliable(chan->io, true);
    if (gensio_is_authenticated(muxdata->child))
	gensio_set_is_authenticated(chan->io, true);
    if (gensio_is_encrypted(muxdata->child))
	gensio_set_is_encrypted(chan->io, true);
    chan->mux = muxdata;
    chan->refcount = 1;
    chan->is_client = is_client;
    chan->max_read_size = muxdata->max_read_size;
    chan->max_write_size = muxdata->max_write_size;
    chan->read_data = o->zalloc(o, chan->max_read_size);
    if (!chan->read_data)
	goto out_free;
    chan->write_data = o->zalloc(o, chan->max_write_size);
    if (!chan->write_data)
	goto out_free;

    /*
     * We maintain the list in number order and rotate through the
     * numbers.  So we start after the last number used and rotate
     * through the entries until we find an empty spot.
     */
    if (gensio_list_empty(&muxdata->chans)) {
	gensio_list_add_tail(&muxdata->chans, &chan->link);
	/* Note that we do not claim a ref here, there is already one. */
    } else {
	struct gensio_link *l, *p = &muxdata->chans.link, *f;
	struct mux_inst *tchan = NULL;

	/* First find the place at or before where the last number starts. */
	id = muxdata->last_id;
	gensio_list_for_each(&muxdata->chans, l) {
	    tchan = gensio_container_of(l, struct mux_inst, link);
	    if (tchan->id > id)
		break;
	    p = l;
	}

	id = next_chan_id(muxdata, id);
	l = gensio_list_next_wrap(&muxdata->chans, p);
	f = l;
	do {
	    tchan = gensio_container_of(l, struct mux_inst, link);
	    if (id != tchan->id)
		goto found;
	    id = next_chan_id(muxdata, id);
	    p = l;
	    l = gensio_list_next_wrap(&muxdata->chans, p);
	} while (f != l);
	tchan = gensio_container_of(l, struct mux_inst, link);
	if (id != tchan->id)
	    goto found;

	err = GE_INUSE;

    out_free:
	/* Didn't find a free number. */
	chan_free(chan);
	return err;

    found:
	chan->id = id;
	muxdata->last_id = id;
	gensio_list_add_next(&muxdata->chans, p, &chan->link);
	mux_ref(muxdata);
    }

    *new_mux = chan;
    return 0;
}

static int
muxc_alloc_channel_data(struct mux_data *muxdata,
			gensio_event cb,
			void *user_data,
			struct gensio_mux_config *data,
			struct gensio **new_io)
{
    struct mux_inst *chan = NULL;
    int err = 0;

    err = mux_new_channel(muxdata, cb, user_data, data->is_client, &chan);
    if (err)
	goto out_err;

    if (data->service) {
	if (data->service_len > chan->max_write_size - 10) {
	    err = GE_TOOBIG;
	    goto out_err;
	}
	chan->service = gensio_strdup(muxdata->o, data->service);
	if (!chan->service) {
	    err = GE_NOMEM;
	    goto out_err;
	}
	chan->service_len = data->service_len;
    }

    muxc_set_state(chan, MUX_INST_CLOSED);

    if (new_io)
	*new_io = chan->io;
    return 0;

 out_err:
    if (chan)
	chan_deref(chan);
    return err;
}

static int
gensio_mux_config(struct gensio_os_funcs *o,
		  const char * const args[],
		  struct gensio_mux_config *data)
{
    unsigned int i;
    int rv = GE_NOMEM;
    const char *str;

    data->o = o;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &data->max_read_size) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "writebuf", &data->max_write_size) > 0)
	    continue;
	if (gensio_check_keyboolv(args[i], "mode", "client", "server",
				  &data->is_client) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "max_channels",
				 &data->max_channels) > 0) {
	    if (data->max_channels > 65536 || data->max_channels < 1) {
		rv = GE_INVAL;
		goto out_err;
	    }
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "service", &str) > 0) {
	    data->service = gensio_strdup(o, str);
	    if (!data->service)
		goto out_err;
	    data->service_len = strlen(data->service);
	    continue;
	}
	rv = GE_INVAL;
	goto out_err;
    }
    return 0;

 out_err:
    return rv;
}

static void
gensio_mux_config_cleanup(struct gensio_mux_config *data)
{
    struct gensio_os_funcs *o;

    if (!data)
	return;

    o = data->o;
    if (data->service)
	o->free(o, data->service);
}

/* If the mode is specified in the default, override is_client. */
static int get_default_mode(struct gensio_os_funcs *o, bool *is_client)
{
    int rv;
    char *str;

    rv = gensio_get_default(o, "mux", "mode", false,
			    GENSIO_DEFAULT_STR, &str, NULL);
    if (rv) {
	gensio_log(o, GENSIO_LOG_ERR,
		   "Failed getting mux mode, ignoring: %s",
		   gensio_err_to_str(rv));
	return rv;
    }
    if (str) {
	if (strcasecmp(str, "client") == 0)
	    *is_client = true;
	else if (strcasecmp(str, "server") == 0)
	    *is_client = false;
	else {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unknown default mux mode (%s), ignoring", str);
	}
	o->free(o, str);
    }

    return 0;
}

static int
muxc_alloc_channel(struct mux_data *muxdata,
		   struct gensio_func_alloc_channel_data *ocdata)
{
    int err;
    struct gensio_mux_config data;

    mux_lock(muxdata);
    if (muxdata->state != MUX_OPEN) {
	err = GE_NOTREADY;
	goto out_unlock;
    }

    memset(&data, 0, sizeof(data));
    data.max_read_size = muxdata->max_read_size;
    data.max_write_size = muxdata->max_write_size;
    data.max_channels = muxdata->max_channels;
    data.is_client = true;
    err = get_default_mode(muxdata->o, &data.is_client);
    if (err)
	return err;

    err = gensio_mux_config(muxdata->o, ocdata->args, &data);
    if (err)
	return err;

    err = muxc_alloc_channel_data(muxdata, ocdata->cb, ocdata->user_data,
				  &data, &ocdata->new_io);
    gensio_mux_config_cleanup(&data);
 out_unlock:
    mux_unlock(muxdata);

    return err;
}

static void
mux_call_open_done(struct mux_data *muxdata, struct mux_inst *chan, int err)
{
    gensio_done_err open_done = chan->open_done;
    void *open_data = chan->open_data;

    chan->open_done = NULL;
    if (open_done) {
	mux_unlock(muxdata);
	open_done(chan->io, err, open_data);
	mux_lock(muxdata);
    }
    chan_deref(chan);
}

static void
mux_child_open_done(struct gensio *child, int err, void *open_data)
{
    struct mux_data *muxdata = open_data;
    struct mux_inst *chan;

    mux_lock_and_ref(muxdata);
    chan = mux_chan0(muxdata);
    if (err) {
	mux_shutdown_channels(muxdata, err);
	muxdata->nr_not_closed = 0;
    } else if (chan->state != MUX_INST_IN_OPEN) {
	/* A close was requested, handle it. */
	muxc_set_state(chan, MUX_INST_CLOSED);
	mux_call_open_done(muxdata, chan, 0);
	mux_channel_finish_close(chan);
    } else {
	mux_set_state(muxdata, MUX_UNINITIALIZED);
	muxc_set_state(chan, MUX_INST_IN_OPEN);
	gensio_set_write_callback_enable(muxdata->child, true);
	gensio_set_read_callback_enable(muxdata->child, true);
    }
    mux_deref_and_unlock(muxdata);
}

static void
muxc_reinit(struct mux_inst *chan)
{
    muxc_set_state(chan, MUX_INST_CLOSED);
    chan->send_close = false;
    chan->close_sent = false;
    chan->read_enabled = false;
    chan->read_data_pos = 0;
    chan->read_data_len = 0;
    chan->in_read_report = false;
    chan->received_unacked = 0;
    chan->write_data_pos = 0;
    chan->write_data_len = 0;
    chan->write_ready_enabled = false;
    chan->in_write_ready = false;
    chan->sent_unacked = 0;
    chan->deferred_op_pending = false;
    chan->cur_msg_len = 0;
    chan->close_done = NULL;
    chan->wr_ready = false;
    chan->close_called = false;
}

static int
muxc_open(struct mux_inst *chan, gensio_done_err open_done, void *open_data,
	  bool do_child)
{
    struct mux_data *muxdata = chan->mux;
    int err = GE_NOTREADY;

    mux_lock(muxdata);
    if (muxdata->state == MUX_CLOSED) {
	muxdata->sending_chan = NULL;
	muxdata->in_hdr = true;
	muxdata->hdr_pos = 0;
	muxdata->hdr_size = 0;
	muxdata->exit_err = 0;
	muxdata->err_shutdown = 0;
	muxdata->do_normal_close = false;
	muxc_reinit(chan);
	if (muxdata->is_client) {
	    if (!chan->in_open_chan) {
		gensio_list_add_tail(&chan->mux->openchans, &chan->wrlink);
		chan->in_open_chan = true;
	    }
	    chan->mux->opencount = 1;
	    chan->send_new_channel = true;
	}
	mux_send_init(muxdata);

	chan->open_done = open_done;
	chan->open_data = open_data;
	muxc_set_state(chan, MUX_INST_IN_OPEN);
	if (do_child) {
	    err = gensio_open(muxdata->child, mux_child_open_done, muxdata);
	    if (!err) {
		muxdata->nr_not_closed = 1;
		mux_set_state(muxdata, MUX_WAITING_CHILD_OPEN);
	    } else {
		muxc_set_state(chan, MUX_INST_CLOSED);
		muxdata->opencount--;
		if (muxdata->is_client && chan->in_open_chan) {
		    gensio_list_rm(&muxdata->openchans, &chan->wrlink);
		    chan->in_open_chan = false;
		}
	    }
	} else {
	    muxdata->nr_not_closed = 1;
	    mux_set_state(muxdata, MUX_UNINITIALIZED);
	    gensio_set_write_callback_enable(muxdata->child, true);
	    gensio_set_read_callback_enable(muxdata->child, true);
	    err = 0;
	}
    } else {
	if (!do_child) {
	    err = GE_INVAL;
	    goto out_unlock;
	}
	if (chan->state != MUX_INST_CLOSED)
	    goto out_unlock;

	muxc_reinit(chan);
	/* Only one open at a time is allowed, queue them otherwise. */
	if (muxdata->opencount == 0 && muxdata->state == MUX_OPEN) {
	    muxc_add_to_wrlist(chan);
	} else {
	    gensio_list_add_tail(&muxdata->openchans, &chan->wrlink);
	    chan->in_open_chan = true;
	}
	muxdata->opencount++;
	muxdata->nr_not_closed++;
	chan->open_done = open_done;
	chan->open_data = open_data;
	chan->send_new_channel = true;
	muxc_set_state(chan, MUX_INST_IN_OPEN);
	err = 0;
    }
    if (!err)
	chan_ref(chan); /* Claim the ref we hold while open. */
 out_unlock:
    mux_unlock(muxdata);
    return err;
}

static int
muxc_control(struct mux_inst *chan, bool get, int op,
	     char *data, gensiods *datalen)
{
    struct mux_data *muxdata = chan->mux;
    int err = 0;

    mux_lock(muxdata);
    switch (op) {
    case GENSIO_CONTROL_SERVICE:
	if (get) {
	    gensiods to_copy;

	    if (!chan->service) {
		err = GE_DATAMISSING;
		goto out;
	    }

	    to_copy = chan->service_len;
	    if (to_copy > *datalen)
		to_copy = *datalen;
	    memcpy(data, chan->service, to_copy);
	    if (*datalen > to_copy)
		data[to_copy] = '\0';
	    *datalen = chan->service_len;
	} else {
	    char *new_service = chan->o->zalloc(chan->o, *datalen);

	    if (!new_service) {
		err = GE_NOMEM;
		goto out;
	    }
	    memcpy(new_service, data, *datalen);
	    if (chan->service)
		chan->o->free(chan->o, chan->service);
	    chan->service = new_service;
	    chan->service_len = *datalen;
	}
	break;

    case GENSIO_CONTROL_ENABLE_OOB:
	if (get)
	    *datalen = snprintf(data, *datalen, "%u", chan->do_oob);
	else
	    chan->do_oob = !!strtoul(data, NULL, 0);
	break;

    default:
	err = GE_NOTSUP;
	break;
    }
 out:
    mux_unlock(muxdata);

    return err;
}

static int
muxc_gensio_handler(struct gensio *io, int func, gensiods *count,
		    const void *cbuf, gensiods buflen, void *buf,
		    const char *const *auxdata)
{
    struct mux_inst *chan = gensio_get_gensio_data(io);

    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	return muxc_write(chan, count, cbuf, buflen, auxdata);

    case GENSIO_FUNC_CLOSE:
	return muxc_close(chan, (void *) cbuf, buf);

    case GENSIO_FUNC_FREE:
	muxc_free(chan);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	muxc_set_read_callback_enable(chan, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	muxc_set_write_callback_enable(chan, buflen);
	return 0;

    case GENSIO_FUNC_DISABLE:
	return muxc_disable(chan);

    case GENSIO_FUNC_ALLOC_CHANNEL:
	return muxc_alloc_channel(chan->mux, buf);

    case GENSIO_FUNC_OPEN:
	return muxc_open(chan, (void *) cbuf, buf, true);

    case GENSIO_FUNC_OPEN_NOCHILD:
	return muxc_open(chan, (void *) cbuf, buf, false);

    case GENSIO_FUNC_CONTROL:
	return muxc_control(chan, *((bool *) cbuf), buflen, buf, count);

    default:
	return GE_NOTSUP;
    }
}

static void
mux_shutdown_channels(struct mux_data *muxdata, int err)
{
    struct gensio_link *l, *l2;
    struct mux_inst *chan;

    muxdata->err_shutdown = true;

    mux_set_state(muxdata, MUX_CLOSED);
    if (muxdata->acc_open_done &&
		(muxdata->exit_state == MUX_WAITING_OPEN ||
		 muxdata->exit_state == MUX_UNINITIALIZED)) {
	gensio_done_err acc_open_done = muxdata->acc_open_done;
	void *acc_open_data = muxdata->acc_open_data;

	chan = mux_chan0(muxdata);
	muxc_set_state(chan, MUX_INST_CLOSED);
	muxdata->acc_open_done = NULL;
	mux_unlock(muxdata);
	acc_open_done(chan->io, err, acc_open_data);
	mux_lock(muxdata);
    }

    gensio_list_for_each_safe(&muxdata->chans, l, l2) {
	chan = gensio_container_of(l, struct mux_inst, link);
	if (chan->in_wrlist) {
	    gensio_list_rm(&muxdata->wrchans, &chan->wrlink);
	    chan->in_wrlist = false;
	}
	chan->wr_ready = false;
	if (chan->in_open_chan) {
	    gensio_list_rm(&muxdata->openchans, &chan->wrlink);
	    chan->in_open_chan = false;
	}

	switch (chan->state) {
	case MUX_INST_IN_CLOSE_FINAL:
	    chan_sched_deferred_op(chan);
	    break;

	case MUX_INST_CLOSED:
	case MUX_INST_IN_REM_CLOSE:
	    break;

	case MUX_INST_PENDING_OPEN:
	    muxc_set_state(chan, MUX_INST_CLOSED);
	    mux_call_open_done(muxdata, chan, err);
	    break;

	case MUX_INST_IN_OPEN:
	    muxc_set_state(chan, MUX_INST_CLOSED);
	    mux_call_open_done(muxdata, chan, err);
	    break;

	case MUX_INST_IN_OPEN_CLOSE:
	    muxc_set_state(chan, MUX_INST_CLOSED);
	    chan_ref(chan); /* Don't let the open call free us. */
	    mux_call_open_done(muxdata, chan, err);
	    finish_close(chan);
	    chan_deref(chan);
	    break;

	case MUX_INST_IN_CLOSE:
	    /* Just close it. */
	    muxc_set_state(chan, MUX_INST_CLOSED);
	    finish_close(chan);
	    break;

	case MUX_INST_OPEN:
	    /* Report the error through the read interface. */
	    chan->errcode = err;
	    muxc_set_state(chan, MUX_INST_IN_REM_CLOSE);
	    chan_sched_deferred_op(chan);
	    break;
	}
    }

    if (gensio_list_empty(&muxdata->chans))
	mux_set_state(muxdata, MUX_CLOSED);
}

static void
chan_setup_send_new_channel(struct mux_inst *chan)
{
    assert(chan->sglen == 0);
    chan->hdr[0] = (MUX_NEW_CHANNEL << 4) | 0x2;
    chan->hdr[1] = 0;
    gensio_u16_to_buf(&chan->hdr[2], chan->id);
    gensio_u32_to_buf(&chan->hdr[4], chan->max_read_size);
    gensio_u16_to_buf(&chan->hdr[8], chan->service_len);
    chan->sg[0].buf = chan->hdr;
    chan->sg[0].buflen = 10;
    chan->sglen = 1;
    if (chan->service_len) {
	chan->sg[1].buf = chan->service;
	chan->sg[1].buflen = chan->service_len;
	chan->sglen++;
	chan->sent_unacked = chan->service_len;
    }
    chan->cur_msg_len = 0; /* Data isn't in chan->write_data. */
}

static bool
chan_setup_send_data(struct mux_inst *chan)
{
    unsigned char flags = 0;
    gensiods pos;
    gensiods window_left = chan->send_window_size - chan->sent_unacked;

    assert(chan->sglen == 0);
    chan->hdr[0] = (MUX_DATA << 4) | 0x2;
    chan->hdr[1] = 0;
    gensio_u16_to_buf(chan->hdr + 2, chan->remote_id);
    gensio_u32_to_buf(chan->hdr + 4, chan->received_unacked);

    chan->sg[0].buf = chan->hdr;
    chan->sg[0].buflen = 8;

    if (chan->write_data_len == 0) {
    check_send_ack:
	if (chan->received_unacked == 0)
	    return false;
	chan->received_unacked = 0;
	/* Just sending an ack. */
	gensio_u16_to_buf(chan->hdr + 8, 0);
	chan->sg[0].buflen = 10;
	chan->sglen = 1;
	return true;
    }
    assert(chan->write_data_len > 3);

    pos = chan_next_write_pos(chan, 1);
    chan->cur_msg_len = chan->write_data[pos] << 8;
    pos = chan_next_write_pos(chan, 2);
    chan->cur_msg_len |= chan->write_data[pos];
    assert(chan->cur_msg_len > 0);
    chan->cur_msg_len += 2;

    /* Make sure to add 1 for the flags */
    if (chan->cur_msg_len + 1 > window_left) {
	chan->cur_msg_len = 0;
	goto check_send_ack;
    }

    chan->received_unacked = 0;

    flags = chan->write_data[chan->write_data_pos];
    chan_incr_write_pos(chan, 1);
    chan->hdr[1] = flags;
    chan->sent_unacked++; /* Flags is stored as delivered data on remote end. */

    if (chan->write_data_pos + chan->cur_msg_len > chan->max_write_size) {
	/* Buffer wraps, need three parts for scatter/gatter. */
	chan->sglen = 3;
	chan->sg[1].buf = chan->write_data + chan->write_data_pos;
	chan->sg[1].buflen = chan->max_write_size - chan->write_data_pos;
	chan->sg[2].buf = chan->write_data;
	chan->sg[2].buflen = chan->cur_msg_len - chan->sg[1].buflen;
    } else {
	chan->sglen = 2;
	chan->sg[1].buf = chan->write_data + chan->write_data_pos;
	chan->sg[1].buflen = chan->cur_msg_len;
    }
    chan->sent_unacked += chan->cur_msg_len;

    return true;
}

static void
mux_on_err_close(struct gensio *child, void *close_data)
{
    struct mux_data *muxdata = close_data;

    mux_lock_and_ref(muxdata);
    if (muxdata->do_normal_close)
	i_finish_close_close_done(muxdata->do_normal_close_chan, muxdata);
    else
	mux_shutdown_channels(muxdata, muxdata->exit_err);
    mux_deref_and_unlock(muxdata); /* Lose the open ref. */
}

static int
mux_child_write_ready(struct mux_data *muxdata)
{
    int err = 0;
    struct mux_inst *chan;
    gensiods rcount;

    mux_lock_and_ref(muxdata);
    if (muxdata->state == MUX_IN_CLOSE || muxdata->state == MUX_CLOSED) {
	gensio_set_read_callback_enable(muxdata->child, false);
	gensio_set_write_callback_enable(muxdata->child, false);
	mux_deref_and_unlock(muxdata);
	return 0;
    }

    /* Finish any pending channel data. */
    if (muxdata->sending_chan) {
	chan = muxdata->sending_chan;
    next_channel:
	assert(chan->sglen > 0 && chan->sgpos < chan->sglen);
	err = gensio_write_sg(muxdata->child, &rcount, chan->sg + chan->sgpos,
			      chan->sglen - chan->sgpos, NULL);
	if (err)
	    goto out_write_err;
	while (rcount > 0 && chan->sgpos < chan->sglen) {
	    if (chan->sg[chan->sgpos].buflen <= rcount) {
		rcount -= chan->sg[chan->sgpos].buflen;
		chan->sgpos++;
		assert(chan->sgpos <= 3);
	    } else {
		chan->sg[chan->sgpos].buflen -= rcount;
		chan->sg[chan->sgpos].buf =
		    ((char *) chan->sg[chan->sgpos].buf) + rcount;
		rcount = 0;
	    }
	}
	if (chan->sgpos >= chan->sglen) {
	    /* Finished sending one message. */
	    chan->write_data_pos = chan_next_write_pos(chan, chan->cur_msg_len);
	    chan->write_data_len -= chan->cur_msg_len;
	    chan->cur_msg_len = 0;
	    chan->sgpos = 0;
	    chan->sglen = 0;
	    muxdata->sending_chan = NULL;
	    if (chan->write_data_len > 0 || chan->send_new_channel ||
			chan->send_close) {
		/* More messages to send, add it to the tail for fairness. */
		gensio_list_add_tail(&muxdata->wrchans, &chan->wrlink);
		chan->in_wrlist = true;
	    } else {
		chan->wr_ready = false;
	    }
	    /*
	     * Maybe the user can write.  Also, if a close is pending,
	     * handle it there, too.
	     */
	    chan_sched_deferred_op(chan);
	} else {
	    /* Couldn't send all the data. */
	    goto out;
	}
    }

    /* Handle data not associated with an existing channel. */
    if (muxdata->xmit_data_len) {
	struct gensio_sg sg[1];

	sg[0].buf = muxdata->xmit_data + muxdata->xmit_data_pos;
	sg[0].buflen = muxdata->xmit_data_len;
	err = gensio_write_sg(muxdata->child, &rcount, sg, 1, NULL);
	if (err)
	    goto out_write_err;
	if (rcount >= muxdata->xmit_data_len) {
	    muxdata->xmit_data_len = 0;
	    muxdata->xmit_data_pos = 0;
	} else {
	    /* Partial write, can't write anything else. */
	    muxdata->xmit_data_len -= rcount;
	    muxdata->xmit_data_pos += rcount;
	    goto out;
	}
    }

    /* Now look for a new channel to send. */
 check_next_channel:
    if (!gensio_list_empty(&muxdata->wrchans)) {
	assert(muxdata->sending_chan == NULL);
	chan = gensio_container_of(gensio_list_first(&muxdata->wrchans),
				   struct mux_inst, wrlink);
	gensio_list_rm(&muxdata->wrchans, &chan->wrlink);
	chan->in_wrlist = false;

	if (chan->send_new_channel) {
	    chan_setup_send_new_channel(chan);
	    chan->send_new_channel = false;
	    muxdata->sending_chan = chan;
	} else if ((chan->write_data_len || chan->received_unacked) &&
		   !chan->close_sent) {
	    /*
	     * Send a data packet, either for data delivery or an ack.
	     * Once we send a close, we cannot send any more data,
	     * thus the check in the if statement above.
	     */
	    if (!chan_setup_send_data(chan)) {
		chan->wr_ready = false;
		goto check_next_channel;
	    }
	    muxdata->sending_chan = chan;
	} else if (chan->send_close &&
		   (chan->read_data_len == 0 ||
		    chan->state == MUX_INST_IN_CLOSE ||
		    chan->state == MUX_INST_IN_CLOSE_FINAL)) {
	    /*
	     * Do the close last so all data is sent.  The state
	     * checks above are there because we want to delay the
	     * send close if we are in MUX_INST_IN_REM_CLOSE to
	     * deliver all the data the remote end sent before
	     * reporting the close, but if our end requested the
	     * close, send it after all local data has been sent.
	     */
	    chan_send_close(chan);
	    chan->send_close = false;
	    chan->close_sent = true;
	    muxdata->sending_chan = chan;
	} else {
	    chan->wr_ready = false;
	    goto check_next_channel;
	}
	goto next_channel;
    }
 out:
    gensio_set_write_callback_enable(muxdata->child,
		muxdata->sending_chan || !gensio_list_empty(&muxdata->wrchans));
    mux_deref_and_unlock(muxdata);
    return 0;

 out_write_err:
    gensio_set_read_callback_enable(muxdata->child, false);
    gensio_set_write_callback_enable(muxdata->child, false);
    muxdata->exit_err = err;
    muxdata->exit_state = muxdata->state;
    mux_set_state(muxdata, MUX_IN_CLOSE);
    err = gensio_close(muxdata->child, mux_on_err_close, muxdata);
    if (err)
	mux_shutdown_channels(muxdata, err);
    mux_deref_and_unlock(muxdata);
    return 0;
}

static struct mux_inst *
mux_get_channel(struct mux_data *muxdata)
{
    struct gensio_link *l;
    unsigned int id = gensio_buf_to_u16(muxdata->hdr + 2);

    gensio_list_for_each(&muxdata->chans, l) {
	struct mux_inst *chan = gensio_container_of(l, struct mux_inst, link);

	if (chan->id == id)
	    return chan;
    }
    return NULL;
}

static bool
mux_find_remote_id(struct mux_data *muxdata, unsigned int id)
{
    struct gensio_link *l;

    gensio_list_for_each(&muxdata->chans, l) {
	struct mux_inst *chan = gensio_container_of(l, struct mux_inst, link);

	if (chan->remote_id == id &&
		chan->state != MUX_INST_PENDING_OPEN &&
		chan->state != MUX_INST_IN_OPEN &&
		chan->state != MUX_INST_IN_OPEN_CLOSE &&
		chan->state != MUX_INST_IN_CLOSE_FINAL)
	    return true;
    }
    return false;
}

static int
mux_child_read(struct mux_data *muxdata, int ierr,
	       unsigned char *buf, gensiods *ibuflen,
	       const char *const *nauxdata)
{
    gensiods processed = 0, used, acked, buflen;
    int err = 0;
    struct mux_inst *chan;
    const char *auxdata[2] = { NULL, NULL };
    const char *proto_err_str = "?";

    mux_lock_and_ref(muxdata);
    if (muxdata->state == MUX_IN_CLOSE || muxdata->state == MUX_CLOSED) {
	gensio_set_read_callback_enable(muxdata->child, false);
	gensio_set_write_callback_enable(muxdata->child, false);
	mux_deref_and_unlock(muxdata);
	return 0;
    }

    if (ierr)
	goto out_err;

    if (gensio_str_in_auxdata(nauxdata, "oob")) {
	/* We can't handle OOB data here. */
	mux_deref_and_unlock(muxdata);
	return 0;
    }

    buflen = *ibuflen;
    while (buflen > 0) {
	if (muxdata->in_hdr) {
	    if (muxdata->hdr_pos == 0) {
		/*
		 * The first byte of the header contains what we need
		 * to process the rest of the header.
		 */
		muxdata->hdr[muxdata->hdr_pos++] = *buf;
		muxdata->hdr_size = (*buf & 0xf) * 4;
		if (muxdata->hdr_size > MUX_MAX_HDR_SIZE) {
		    proto_err_str = "Invalid header size";
		    goto protocol_err;
		}
		muxdata->msgid = *buf >> 4;
		if (muxdata->msgid <= 0 || muxdata->msgid > MUX_MAX_MSG_NUM) {
		    proto_err_str = "msgid out of range";
		    goto protocol_err;
		}
		if (mux_msg_hdr_sizes[muxdata->msgid] > muxdata->hdr_size) {
		    proto_err_str = "Invalid header size";
		    goto protocol_err;
		}
		used = 1;
		goto more_data;
	    }

	    if (buflen + muxdata->hdr_pos < muxdata->hdr_size) {
		/* The header is not completely received, partial copy. */
		memcpy(muxdata->hdr + muxdata->hdr_pos, buf, buflen);
		muxdata->hdr_pos += buflen;
		processed += buflen;
		goto out_unlock;
	    }

	    /* We have the whole header now. */
	    used = muxdata->hdr_size - muxdata->hdr_pos;
	    memcpy(muxdata->hdr + muxdata->hdr_pos, buf, used);
	    muxdata->hdr_pos = 0;

	    if (muxdata->msgid == MUX_INIT) {
		if (muxdata->state != MUX_UNINITIALIZED) {
		    proto_err_str = "Init when already initialized";
		    goto protocol_err;
		}
		if (gensio_list_empty(&muxdata->openchans)) {
		    mux_set_state(muxdata, MUX_WAITING_OPEN);
		    goto more_data;
		} else {
		    chan = NULL;
		    mux_set_state(muxdata, MUX_IN_OPEN);
		    goto next_channel_req_send;
		}
	    }

	    if (muxdata->state == MUX_UNINITIALIZED) {
		proto_err_str = "Not initialized";
		goto protocol_err;
	    }

	    switch (muxdata->msgid) {
	    case MUX_NEW_CHANNEL: {
		unsigned int remote_id = gensio_buf_to_u16(muxdata->hdr + 2);
		bool was_chan0 = false;
		if (muxdata->state == MUX_WAITING_OPEN) {
		    chan = mux_chan0(muxdata);
		    was_chan0 = true;
		} else {
		    int err;

		    if (mux_find_remote_id(muxdata, remote_id)) {
			proto_err_str = "New remote channel for existing one";
			goto protocol_err;
		    }

		    err = mux_new_channel(muxdata, NULL, NULL, false, &chan);
		    if (err)
			chan = NULL;
		    else
			muxdata->nr_not_closed++;
		}
		muxdata->curr_chan = chan;
		if (chan) {
		    muxc_set_state(chan, MUX_INST_PENDING_OPEN);
		    chan->send_window_size =
			gensio_buf_to_u32(muxdata->hdr + 4);
		    if (chan->send_window_size <= MUX_MIN_SEND_WINDOW_SIZE) {
			proto_err_str = "Invalid send window size";
			if (was_chan0)
			    goto protocol_err;
			else
			    goto protocol_err_close_chan;
		    }
		    chan->remote_id = remote_id;
		    muxdata->data_pos = 0;
		    muxdata->in_hdr = false; /* Receive the service data */
		}
		break;
	    }

	    case MUX_NEW_CHANNEL_RSP:
		chan = mux_get_channel(muxdata);
		if (!chan) {
		    proto_err_str = "No channel for channel response";
		    goto protocol_err;
		}
		if (chan->state != MUX_INST_IN_OPEN &&
			chan->state != MUX_INST_IN_OPEN_CLOSE) {
		    proto_err_str = "Invalid channel state on open response";
		    goto protocol_err;
		}
		if (muxdata->state == MUX_IN_OPEN) {
		    mux_set_state(muxdata, MUX_OPEN);
		} else if (muxdata->state != MUX_OPEN &&
			   muxdata->state != MUX_IN_CLOSE) {
		    proto_err_str = "New channel response in bad state";
		    goto protocol_err;
		}
		chan->remote_id = gensio_buf_to_u16(muxdata->hdr + 8);
		chan->send_window_size = gensio_buf_to_u32(muxdata->hdr + 4);
		if (chan->send_window_size <= MUX_MIN_SEND_WINDOW_SIZE) {
		    proto_err_str = "Invalid send window size";
		    goto protocol_err;
		}
		chan->errcode = gensio_buf_to_u16(muxdata->hdr + 10);
		muxdata->sending_chan = NULL;

		assert(muxdata->opencount > 0);
		muxdata->opencount--;

		if (chan->errcode) {
		    enum mux_inst_state old_state = chan->state;

		    muxc_set_state(chan, MUX_INST_CLOSED);
		    mux_call_open_done(muxdata, chan, chan->errcode);
		    if (old_state == MUX_INST_IN_OPEN_CLOSE)
			i_finish_close_close_done(chan, muxdata);
		    chan = NULL;
		} else if (chan->state == MUX_INST_IN_OPEN_CLOSE) {
		    muxc_set_state(chan, MUX_INST_IN_CLOSE);
		    mux_call_open_done(muxdata, chan, GE_LOCALCLOSED);
		    chan->send_close = true;
		    muxc_add_to_wrlist(chan);
		    chan = NULL;
		} else {
		    muxc_set_state(chan, MUX_INST_OPEN);
		}

	    next_channel_req_send:
		/* Start the next channel open, if necessary. */
		if (!gensio_list_empty(&muxdata->openchans)) {
		    struct mux_inst *next_chan =
			gensio_container_of(
				gensio_list_first(&muxdata->openchans),
				struct mux_inst, wrlink);
		    gensio_list_rm(&muxdata->openchans, &next_chan->wrlink);
		    next_chan->in_open_chan = false;
		    muxc_add_to_wrlist(next_chan);
		} else {
		    assert(muxdata->opencount == 0);
		}

		if (chan) {
		    chan_ref(chan);
		    mux_call_open_done(muxdata, chan, chan->errcode);
		    if (chan_deref(chan))
			goto more_data;
		    /* Deliver a read error if read is enabled. */
		    if (chan->read_enabled)
			chan_sched_deferred_op(chan);
		}
		break;

	    case MUX_CLOSE_CHANNEL:
		chan = mux_get_channel(muxdata);
		if (!chan || chan->state == MUX_INST_CLOSED ||
				chan->state == MUX_INST_IN_OPEN ||
				chan->state == MUX_INST_IN_OPEN_CLOSE ||
				chan->state == MUX_INST_IN_CLOSE_FINAL ||
				chan->state == MUX_INST_IN_REM_CLOSE) {
		    proto_err_str = "Invalid channel state on close";
		    goto protocol_err;
		}
		chan->errcode = gensio_buf_to_u16(muxdata->hdr + 4);
		if (chan->state == MUX_INST_IN_CLOSE) {
		    muxc_set_state(chan, MUX_INST_IN_CLOSE_FINAL);
		    /* Do the close as a deferred op. */
		    chan_sched_deferred_op(chan);
		} else {
		    muxc_set_state(chan, MUX_INST_IN_REM_CLOSE);
		    if (chan->errcode == 0)
			chan->errcode = GE_REMCLOSE;
		    chan->send_close = true;
		    muxc_add_to_wrlist(chan);
		    chan_sched_deferred_op(chan);
		}
		/* If we receive a close, don't send any more data. */
		chan->write_data_len = 0;
		break;

	    case MUX_DATA:
		chan = mux_get_channel(muxdata);
		if (!chan) {
		    proto_err_str = "No channel on data";
		    goto protocol_err;
		}
		if (chan->state == MUX_INST_CLOSED ||
			chan->state == MUX_INST_IN_OPEN ||
			chan->state == MUX_INST_IN_OPEN_CLOSE ||
			chan->state == MUX_INST_IN_CLOSE_FINAL ||
			chan->state == MUX_INST_IN_REM_CLOSE) {
		    proto_err_str = "Invalid channel state on data";
		    goto protocol_err;
		}
		acked = gensio_buf_to_u32(muxdata->hdr + 4);
		if (acked > chan->sent_unacked) {
		    proto_err_str = "acked > chan->sent_unacked";
		    goto protocol_err;
		}
		chan->sent_unacked -= acked;
		if (acked > 0 && chan->write_data_len)
		    muxc_add_to_wrlist(chan);
		muxdata->curr_chan = chan;
		muxdata->data_pos = 0;
		muxdata->in_hdr = false; /* Receive the data */
		break;

	    default:
		abort();
	    }

	more_data:
	    processed += used;
	    buf += used;
	    buflen -= used;
	} else {
	    /*
	     * We are receiving data from the remote end, either service
	     * or payload.  The first two bytes is always the data length.
	     */
	    if (muxdata->data_pos == 0) {
		muxdata->data_size = *buf << 8;
		muxdata->data_pos++;
		used = 1;
		goto more_data;
	    }
	    chan = muxdata->curr_chan;
	    if (muxdata->data_pos == 1) {
		muxdata->data_size |= *buf;
		muxdata->data_pos++;
		used = 1;
		switch (muxdata->msgid) {
		case MUX_NEW_CHANNEL:
		    if (!chan)
			/* Channel allocation failed, just abort. */
			break;
		    chan->service_len = muxdata->data_size;
		    if (muxdata->data_size == 0)
			goto new_chan_no_service;
		    chan->service = muxdata->o->zalloc(muxdata->o,
						       muxdata->data_size + 1);
		    if (!chan->service) {
			muxdata->curr_chan = NULL;
			chan_deref(chan);
			/* NULL curr_chan will cause an error to be sent. */
		    }
		    break;

		case MUX_DATA:
		    assert(chan);
		    if (muxdata->data_size == 0)
			goto handle_read_no_data;
		    if (chan_rdbufleft(chan) < muxdata->data_size + 3) {
			proto_err_str = "Too much data from remote end";
			goto protocol_err;
		    }
		    /* Add the message flags first. */
		    chan_addrdbyte(chan, muxdata->hdr[1]);
		    chan_addrdbyte(chan, muxdata->data_size >> 8);
		    chan_addrdbyte(chan, muxdata->data_size & 0xff);
		    break;

		default:
		    abort();
		}
		goto more_data;
	    }

	    /* Receiving message data. */
	    switch (muxdata->msgid) {
	    case MUX_NEW_CHANNEL:
		if (buflen + muxdata->data_pos - 2 < muxdata->data_size) {
		    /* Not enough data for service yet. */
		    if (chan)
			memcpy(chan->service + muxdata->data_pos - 2,
			       buf, buflen);
		    muxdata->data_pos += buflen;
		    processed += buflen;
		    goto out_unlock;
		}
		used = muxdata->data_size + 2 - muxdata->data_pos;
		if (chan) {
		    memcpy(chan->service + muxdata->data_pos - 2, buf, used);
		} else {
		    err = GE_INUSE;
		    if (muxdata->xmit_data_len) {
			/* Only one new channel allowed at a time. */
			proto_err_str = "New channel while in progress";
			goto protocol_err_close_chan;
		    }
		    mux_send_new_channel_rsp(muxdata,
				gensio_buf_to_u16(muxdata->hdr + 2),
				0, 0, err);
		    goto finish_new_chan;
		}
	    new_chan_no_service:
		muxc_set_state(chan, MUX_INST_OPEN);
		if (muxdata->state == MUX_WAITING_OPEN) {
		    /*
		     * This is the first channel, deliver to the
		     * gensio_acc_gensio code as an open.
		     */
		    mux_set_state(muxdata, MUX_OPEN);
		    mux_send_new_channel_rsp(muxdata, chan->remote_id,
					     chan->max_read_size,
					     chan->id, 0);
		    if (muxdata->acc_open_done) {
			mux_unlock(muxdata);
			muxdata->acc_open_done(chan->io, 0,
					       muxdata->acc_open_data);
			mux_lock(muxdata);
		    } else {
			mux_call_open_done(muxdata, chan, 0);
		    }
		} else {
		    if (muxdata->xmit_data_len) {
			proto_err_str = "New channel while in progress";
			goto protocol_err_close_chan;
		    }
		    if (chan->service)
			auxdata[0] = chan->service;
		    else
			auxdata[0] = "";
		    chan->in_newchannel = 1;
		    chan_ref(chan);
		    err = mux_firstchan_event(muxdata, GENSIO_EVENT_NEW_CHANNEL,
					      0, (void *) chan->io, 0, auxdata);
		    if (chan->in_newchannel == 0) {
			/*
			 * The user did a write, so the new channel
			 * response and service data ack are already
			 * done.  If an error is returned, we close
			 * the channel.
			 */
			if (err && chan->state == MUX_INST_OPEN) {
			    chan->errcode = err;
			    muxc_set_state(chan, MUX_INST_IN_CLOSE);
			    chan->send_close = true;
			    muxc_add_to_wrlist(chan);
			}
			goto new_chan_done;
		    }
		    if (!err && chan->in_newchannel == 2)
			err = GE_REMCLOSE;
		    chan->in_newchannel = 0;
		    mux_send_new_channel_rsp(muxdata, chan->remote_id,
					     chan->max_read_size,
					     chan->id, err);
		    if (err) {
			if (chan->state == MUX_INST_OPEN)
			    /*
			     * We might have gone to in_close, let the
			     * close call happen in that case.
			     */
			    muxc_set_state(chan, MUX_INST_CLOSED);
		    } else if (chan->service_len) {
			/* Ack the service data. */
			chan->received_unacked = chan->service_len;
			muxc_add_to_wrlist(chan);
		    }
		new_chan_done:
		    chan_deref(chan);
		}
	    finish_new_chan:
		muxdata->in_hdr = true;
		goto more_data;

	    case MUX_DATA:
		assert(chan);
		if (buflen + muxdata->data_pos < muxdata->data_size + 2) {
		    /* Not all data received yet. */
		    chan_addrdbuf(chan, buf, buflen);
		    muxdata->data_pos += buflen;
		    processed += buflen;
		    goto out_unlock;
		}
		used = muxdata->data_size + 2 - muxdata->data_pos;
		chan_addrdbuf(chan, buf, used);

	    handle_read_no_data:
		chan_ref(chan);
		chan_check_send_more(chan);
		if (muxdata->data_size)
		    chan_check_read(chan);
		chan_deref(chan);
		muxdata->in_hdr = true;
		goto more_data;

	    default:
		abort();
	    }
	}
    }

 out_unlock:
    mux_deref_and_unlock(muxdata);
    *ibuflen = processed;
    return 0;

 protocol_err_close_chan:
    /*
     * A protocol error was reported before the channel was reported
     * to the user.  Just delete the channel, otherwise it will not
     * get cleaned up on the close and the close of the mux will never
     * happen.
     */
    chan_deref(muxdata->curr_chan);
    muxdata->curr_chan = NULL;
 protocol_err:
    gmux_log_err(muxdata, "Protocol error: %s\n", proto_err_str);
    ierr = GE_PROTOERR;
 out_err:
    gensio_set_read_callback_enable(muxdata->child, false);
    gensio_set_write_callback_enable(muxdata->child, false);
    muxdata->exit_state = muxdata->state;
    muxdata->exit_err = ierr;
    mux_set_state(muxdata, MUX_IN_CLOSE);
    err = gensio_close(muxdata->child, mux_on_err_close, muxdata);
    if (err)
	mux_shutdown_channels(muxdata, ierr);
    mux_deref_and_unlock(muxdata);
    return 0;
}

static int
mux_child_cb(struct gensio *io, void *user_data, int event,
	     int err, unsigned char *buf, gensiods *buflen,
	     const char *const *auxdata)
{
    struct mux_data *muxdata = user_data;
    int rv;

    switch (event) {
    case GENSIO_EVENT_READ:
	return mux_child_read(muxdata, err, buf, buflen, auxdata);

    case GENSIO_EVENT_WRITE_READY:
	return mux_child_write_ready(muxdata);

    case GENSIO_EVENT_NEW_CHANNEL:
	return GE_NOTSUP;

    default:
	mux_lock_and_ref(muxdata);
	rv = mux_firstchan_event(muxdata, event, err, buf, buflen, auxdata);
	mux_deref_and_unlock(muxdata);
	return rv;
    }
}

static int
mux_gensio_alloc_data(struct gensio *child, struct gensio_mux_config *data,
		      gensio_event cb, void *user_data,
		      struct mux_data **rmuxdata)
{
    struct gensio_os_funcs *o = data->o;
    struct mux_data *muxdata;
    int rv;

    if (data->max_write_size < MUX_MIN_SEND_WINDOW_SIZE ||
		data->max_read_size < MUX_MIN_SEND_WINDOW_SIZE)
	return GE_INVAL;

    muxdata = o->zalloc(o, sizeof(*muxdata));
    if (!muxdata)
	return GE_NOMEM;

    mux_set_state(muxdata, MUX_IN_ALLOC);
    muxdata->o = o;
    muxdata->refcount = 1;
    muxdata->is_client = data->is_client;
    muxdata->child = child;
    muxdata->in_hdr = true;
    muxdata->max_write_size = data->max_write_size;
    muxdata->max_read_size = data->max_read_size;
    muxdata->max_channels = data->max_channels;
    gensio_list_init(&muxdata->chans);
    gensio_list_init(&muxdata->openchans);
    gensio_list_init(&muxdata->wrchans);
    muxdata->lock = o->alloc_lock(o);
    if (!muxdata->lock)
	goto out_nomem;
    gensio_set_callback(child, mux_child_cb, muxdata);

    /* Set up to send the init message. */
    mux_send_init(muxdata);

    /* Allocate channel 0. */
    rv = muxc_alloc_channel_data(muxdata, cb, user_data, data, NULL);
    if (rv)
	goto out_nomem;

    mux_set_state(muxdata, MUX_CLOSED);
    muxdata->nr_not_closed = 1;
    *rmuxdata = muxdata;
    return 0;

 out_nomem:
    if (!gensio_list_empty(&muxdata->chans))
	chan_deref(gensio_container_of(
				gensio_list_first(&muxdata->chans),
				struct mux_inst, link));
    if (muxdata->lock)
	o->free_lock(muxdata->lock);
    o->free(o, muxdata);
    return GE_NOMEM;
}

static int
mux_gensio_alloc(struct gensio *child, const char *const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **net)
{
    int err;
    struct gensio *io;
    struct gensio_mux_config data;
    struct mux_data *muxdata;
    int ival;

    if (!gensio_is_reliable(child))
	/* Cowardly refusing to run MUX over an unreliable connection. */
	return GE_NOTSUP;

    memset(&data, 0, sizeof(data));
    data.max_read_size = GENSIO_DEFAULT_BUF_SIZE * 16;
    data.max_write_size = GENSIO_DEFAULT_BUF_SIZE * 2;
    data.max_channels = 1000;
    err = gensio_get_default(o, "mux", "max-channels", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    data.max_channels = ival;
    data.is_client = true;
    err = get_default_mode(o, &data.is_client);
    if (err)
	return err;

    err = gensio_mux_config(o, args, &data);
    if (err)
	return err;

    err = mux_gensio_alloc_data(child, &data, cb, user_data, &muxdata);
    gensio_mux_config_cleanup(&data);
    if (err)
	return err;

    io = mux_chan0(muxdata)->io;
    gensio_set_is_packet(io, true);
    gensio_set_is_reliable(io, true);
    if (gensio_is_encrypted(child))
	gensio_set_is_encrypted(io, true);

    *net = io;
    return 0;
}

static int
str_to_mux_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    err = str_to_gensio(str, o, NULL, NULL, &io2);
    if (err)
	return err;

    err = mux_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct muxna_data {
    struct gensio_accepter *acc;
    struct gensio_mux_config data;
    struct gensio_os_funcs *o;
};

static void
muxna_free(struct muxna_data *nadata)
{
    gensio_mux_config_cleanup(&nadata->data);
    nadata->o->free(nadata->o, nadata);
}

static int
muxna_alloc_gensio(struct muxna_data *nadata, const char * const *iargs,
		   struct gensio *child, struct gensio **rio)
{
    return mux_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);
}

static int
muxna_new_child(struct muxna_data *nadata, void **finish_data,
		struct gensio_new_child_io *ncio)
{
    struct mux_data *muxdata;
    struct mux_inst *chan;
    int err;

    err = mux_gensio_alloc_data(ncio->child, &nadata->data,
				NULL, NULL, &muxdata);
    if (!err) {
	mux_lock(muxdata);
	chan = mux_chan0(muxdata);
	ncio->new_io = chan->io;
	mux_set_state(muxdata, MUX_UNINITIALIZED);
	muxdata->acc_open_done = ncio->open_done;
	muxdata->acc_open_data = ncio->open_data;
	mux_unlock(muxdata);
	*finish_data = muxdata;
    }
    return err;
}

static int
muxna_finish_parent(struct mux_data *muxdata)
{
    gensio_set_write_callback_enable(muxdata->child, true);
    gensio_set_read_callback_enable(muxdata->child, true);
    return 0;
}

static int
gensio_gensio_acc_mux_cb(void *acc_data, int op, void *data1, void *data2,
			 void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return muxna_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD_IO:
	return muxna_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	muxna_free(acc_data);
	return 0;

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return muxna_finish_parent(data1);

    default:
	return GE_NOTSUP;
    }
}

static int
mux_gensio_accepter_alloc(struct gensio_accepter *child,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_accepter_event cb, void *user_data,
			  struct gensio_accepter **accepter)
{
    struct muxna_data *nadata;
    int err, ival;

    if (!gensio_acc_is_reliable(child))
	/* Cowardly refusing to run MUX over an unreliable connection. */
	return GE_NOTSUP;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    nadata->data.max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    nadata->data.max_write_size = GENSIO_DEFAULT_BUF_SIZE;
    nadata->data.max_channels = 1000;
    err = gensio_get_default(o, "mux", "max-channels", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err) {
	o->free(o, nadata);
	return err;
    }
    nadata->data.max_channels = ival;
    nadata->data.is_client = false;
    err = get_default_mode(o, &nadata->data.is_client);
    if (err) {
	o->free(o, nadata);
	return err;
    }
    err = gensio_mux_config(o, args, &nadata->data);
    if (err) {
	o->free(o, nadata);
	return err;
    }

    nadata->o = o;

    err = gensio_gensio_accepter_alloc(child, o, "mux", cb, user_data,
				       gensio_gensio_acc_mux_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;
    gensio_acc_set_is_packet(nadata->acc, true);
    gensio_acc_set_is_reliable(nadata->acc, true);
    *accepter = nadata->acc;

    return 0;

 out_err:
    muxna_free(nadata);
    return err;
}

static int
str_to_mux_gensio_accepter(const char *str, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb,
			   void *user_data,
			   struct gensio_accepter **acc)
{
    int err;
    struct gensio_accepter *acc2 = NULL;

    err = str_to_gensio_accepter(str, o, NULL, NULL, &acc2);
    if (!err) {
	err = mux_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_mux(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "mux",
				str_to_mux_gensio, mux_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "mux",
					 str_to_mux_gensio_accepter,
					 mux_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
