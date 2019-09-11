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

#include "config.h"
#include <errno.h>

#include <gensio/gensio_class.h>
#include <gensio/gensio_acc_gensio.h>

#include <string.h>
#include <stdlib.h>
#include <assert.h>

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

#define MUX_MAX_HDR_SIZE	12

#if 1
#include <stdio.h>
#define TRACE_MSG(fmt, ...) printf("%p: " fmt "\r\n", muxdata, ##__VA_ARGS__)
#define TRACE_MSG_CHAN(fmt, ...) \
    printf("%p(%p): " fmt "\r\n", chan->mux, chan, ##__VA_ARGS__)
#define MUX_TRACING 1
#else
#define TRACE_MSG(fmt, ...) do { } while (false)
#define TRACE_MSG_CHAN(fmt, ...) do { } while (false)
#undef MUX_TRACING
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
    bool ack_pending;

    /*
     * The service, either the local one or the remote one.
     */
    char *service;
    unsigned int service_len;

    unsigned char *read_data;
    gensiods read_data_pos;
    gensiods read_data_len;
    gensiods max_read_size;
    bool read_enabled;
    bool in_read_report;

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
    unsigned int service_len;
    unsigned int max_channels;
};

enum mux_state {
    /*
     *  Mux has been allocated but not opened or all channels are closed.
     */
    MUX_CLOSED,

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

struct mux_data {
    struct gensio *child;
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    gensiods max_read_size;
    gensiods max_write_size;

    unsigned int max_channels;

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
     * All the channels in the mux.  The non-closed channels are
     * kept in id order at the begining of this list.  The closed
     * channels are kept at the end in no particular order.
     */
    struct gensio_list chans;
};

#define filter_to_mux(v) ((struct mux_data *) gensio_filter_get_user_data(v))

static void chan_sched_deferred_op(struct mux_inst *chan);
static int muxc_gensio_handler(struct gensio *io, int func, gensiods *count,
			       const void *cbuf, gensiods buflen, void *buf,
			       const char *const *auxdata);
static void muxc_add_to_wrlist(struct mux_inst *chan);

static void
gmux_log_err(struct mux_data *f, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    gensio_vlog(f->o, GENSIO_LOG_ERR, fmt, ap);
    va_end(ap);
}

static void
mux_channel_free(struct mux_inst *chan)
{
    struct gensio_os_funcs *o = chan->o;

    if (chan->read_data)
	o->free(o, chan->read_data);
    if (chan->write_data)
	o->free(o, chan->write_data);
    if (chan->service)
	o->free(o, chan->service);
    if (chan->io)
	gensio_data_free(chan->io);
    if (chan->deferred_op_runner)
	chan->o->free_runner(chan->deferred_op_runner);
    o->free(o, chan);
}

static void
muxdata_free(struct mux_data *muxdata)
{
    struct gensio_link *l;
    struct mux_inst *chan;

    gensio_list_for_each(&muxdata->chans, l) {
	chan = gensio_container_of(l, struct mux_inst, link);
	mux_channel_free(chan);
    }

    if (muxdata->lock)
	muxdata->o->free_lock(muxdata->lock);
    if (muxdata->child)
	gensio_free(muxdata->child);
    muxdata->o->free(muxdata->o, muxdata);
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
	gensio_list_rm(&chan->mux->chans, &chan->link);
	mux_channel_free(chan);
	return true;
    }
    return false;
}

#if 0
#include <stdio.h>
#define chan_ref(c) \
    do { \
	printf("%p(%p): ref at %d (%d)\r\n", c->mux, c, __LINE__, c->refcount); \
	i_chan_ref(c);								\
    } while (false)
static bool
j_chan_deref(struct mux_inst *chan, int lineno)
{
    if (i_chan_deref(chan)) {
	printf("%p(%p): chan free at %d\r\n", chan->mux, chan, lineno);
	return true;
    } else {
	printf("%p(%p): deref at %d (%d)\r\n", chan->mux, chan,
	       lineno, chan->refcount);
	return false;
    }
}
#define chan_deref(c) j_chan_deref(c, __LINE__)
#else
#define chan_ref(c) i_chan_ref(c)
#define chan_deref(c) i_chan_deref(c)
#endif

static void
i_mux_lock(struct mux_data *muxdata)
{
    muxdata->o->lock(muxdata->lock);
}

static bool
i_mux_unlock(struct mux_data *muxdata)
{
    if (gensio_list_empty(&muxdata->chans) &&
		muxdata->state != MUX_UNINITIALIZED &&
		muxdata->state != MUX_WAITING_OPEN) {
	muxdata_free(muxdata);
	return true;
    } else {
	muxdata->o->unlock(muxdata->lock);
	return false;
    }
}

#if 0
#include <stdio.h>
#define mux_lock(m) \
    do { printf("%p: Lock at %d\r\n", m, __LINE__); i_mux_lock(m); } while (false)
#define mux_unlock(m) \
    do {							\
	if (i_mux_unlock(m))					\
	    printf("%p: Mux free at %d\r\n", m, __LINE__);	\
	else							\
	    printf("%p: Unlock at %d\r\n", m, __LINE__);	\
    } while (false)
#else
#define mux_lock(m) i_mux_lock(m)
#define mux_unlock(m) i_mux_unlock(m)
#endif

static struct mux_inst *
mux_chan0(struct mux_data *muxdata)
{
    return gensio_container_of(gensio_list_first(&muxdata->chans),
			       struct mux_inst, link);
}

static int
mux_chan0_event(struct mux_data *muxdata, int event, int err,
		unsigned char *buf, gensiods *buflen,
		const char * const * auxdata)
{
    int rerr;
    struct mux_inst *chan;

    mux_lock(muxdata);
    chan = mux_chan0(muxdata);
    chan_ref(chan);
    mux_unlock(muxdata);
    rerr = gensio_cb(chan->io, event, err, buf, buflen, auxdata);
    mux_lock(muxdata);
    chan_deref(chan);
    mux_unlock(muxdata);

    return rerr;
}

static bool
mux_channel_set_closed(struct mux_inst *chan, gensio_done close_done,
		       void *close_data)
{
    struct mux_data *muxdata = chan->mux;
    int err;

    chan->state = MUX_INST_CLOSED;
    gensio_list_rm(&muxdata->chans, &chan->link);
    gensio_list_add_tail(&muxdata->chans, &chan->link);
    if (mux_chan0(muxdata)->state == MUX_INST_CLOSED) {
	/* There are no open instances, shut the mux down. */
	muxdata->state = MUX_IN_CLOSE;
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
finish_close_close_done(struct gensio *child, void *close_data)
{
    struct mux_inst *chan = close_data;
    struct mux_data *muxdata = chan->mux;

    mux_lock(muxdata);
    finish_close(chan);
    muxdata->state = MUX_CLOSED;
    mux_unlock(muxdata);
}

static void
mux_channel_finish_close(struct mux_inst *chan)
{
    if (!mux_channel_set_closed(chan, finish_close_close_done, chan))
	finish_close(chan);
}

static uint32_t
mux_buf_to_u32(unsigned char *data)
{
    return (data[0] << 24 |
	    data[1] << 16 |
	    data[2] << 8 |
	    data[3]);
}

static void
mux_u32_to_buf(unsigned char *data, uint32_t v)
{
    data[0] = v >> 24;
    data[1] = v >> 16;
    data[2] = v >> 8;
    data[3] = v;
}

static uint16_t
mux_buf_to_u16(unsigned char *data)
{
    return (data[0] << 8 | data[1]);
}

static void
mux_u16_to_buf(unsigned char *data, uint16_t v)
{
    data[0] = v >> 8;
    data[1] = v;
}

static void
mux_send_new_channel_rsp(struct mux_data *muxdata, unsigned int remote_id,
			 unsigned int max_read_size, unsigned int id,
			 int err)
{
    muxdata->xmit_data[0] = (MUX_NEW_CHANNEL_RSP << 4) | 0x3;
    muxdata->xmit_data[1] = 0;
    mux_u16_to_buf(&muxdata->xmit_data[2], remote_id);
    mux_u32_to_buf(&muxdata->xmit_data[4], max_read_size);
    mux_u16_to_buf(&muxdata->xmit_data[8], id);
    mux_u16_to_buf(&muxdata->xmit_data[10], err);
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
    /* Need at least 3 bytes to write a message. */
    while (chan->write_data_len + 3 < chan->max_write_size &&
	   chan->write_ready_enabled && !chan->in_write_ready) {
	chan->in_write_ready = true;
	chan_ref(chan);
	mux_unlock(chan->mux);
	gensio_cb(chan->io, GENSIO_EVENT_WRITE_READY, 0, NULL, NULL, NULL);
	mux_lock(chan->mux);
	if (chan_deref(chan))
	    return;
	chan->in_write_ready = false;
    }
}

/*
 * Must be called with an extra refcount held.
 */
static void
chan_check_read(struct mux_inst *chan)
{
    struct mux_data *muxdata = chan->mux;
    unsigned char flags;
    gensiods len, olen, rcount, orcount, pos;
    static const char *eom[] = { "eom", NULL };

    while ((chan->read_data_len || chan->errcode) &&
	   chan->read_enabled && !chan->in_read_report) {
	if (chan->read_data_len == 0) {
	    /* error is true and no data. */
	    chan->in_read_report = true;
	    chan->read_enabled = false;
	    mux_unlock(muxdata);
	    gensio_cb(chan->io, GENSIO_EVENT_READ, chan->errcode,
		      NULL, NULL, NULL);
	    mux_lock(muxdata);
	    chan->in_read_report = false;
	    continue;
	}

	assert(chan->read_data_len > 3); /* FIXME - should this be protocol err? */

	flags = chan->read_data[chan->read_data_pos];
	len = chan->read_data[chan_next_read_pos(chan, 1)] << 8;
	len |= chan->read_data[chan_next_read_pos(chan, 2)];
	olen = 0;
	assert(len > 0 && len + 3 <= chan->read_data_len);
	pos = chan_next_read_pos(chan, 3);

	chan->in_read_report = true;
	if (len > chan->max_read_size - pos) {
	    /* Buffer wraps, deliver in two parts. */
	    rcount = chan->max_read_size - pos;
	    orcount = rcount;
	    mux_unlock(muxdata);
	    gensio_cb(chan->io, GENSIO_EVENT_READ,
		      0, chan->read_data + pos, &rcount, NULL);
	    mux_lock(muxdata);
	    if (rcount > orcount)
		rcount = orcount;
	    len -= rcount;
	    chan->received_unacked += rcount;
	    olen += rcount;
	    if (rcount < orcount)
		/* User didn't consume all data. */
		goto after_read_done;
	    pos = 0;
	}
	rcount = len;
	orcount = rcount;
	mux_unlock(muxdata);
	gensio_cb(chan->io, GENSIO_EVENT_READ,
		  0, chan->read_data + pos, &rcount,
		  flags & MUX_FLAG_END_OF_MESSAGE ? eom : NULL);
	mux_lock(muxdata);
	if (rcount > orcount)
	    rcount = orcount;
	len -= rcount;
	chan->received_unacked += rcount;
	olen += rcount;
    after_read_done:
	chan->in_read_report = false;

	/* Schedule an ack send if we need it. */
	if (chan->received_unacked) {
	    chan->ack_pending = true;
	    muxc_add_to_wrlist(chan);
	}
	if (len > 0) {
	    /* Partial send, create a new 3-byte header over the data left. */
	    chan->read_data_pos = chan_next_read_pos(chan, olen);
	    chan->read_data_len -= olen;
	    chan->read_data[chan->read_data_pos] = flags;
	    chan->read_data[chan_next_read_pos(chan, 1)] = len >> 8;
	    chan->read_data[chan_next_read_pos(chan, 2)] = len & 0xff;
	} else {
	    chan->read_data_pos = chan_next_read_pos(chan, olen + 3);
	    chan->read_data_len -= olen + 3;
	    chan->received_unacked += 3;
	}
    }
    if (chan->read_data_len == 0 && !chan->wr_ready &&
		chan->state == MUX_INST_IN_CLOSE_FINAL)
	mux_channel_finish_close(chan);
}

static void
chan_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct mux_inst *chan = cbdata;
    struct mux_data *muxdata = chan->mux;

    mux_lock(muxdata);
    chan->deferred_op_pending = false;
    chan_check_send_more(chan);
    chan_check_read(chan);
    chan_deref(chan);
    mux_unlock(muxdata);
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

    if (!chan->wr_ready) {
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

    /*
     * Just return on buffer full.  We need 3 bytes for the header and at
     * least a byte of data.
     */
    if (chan->max_write_size - chan->write_data_len < 4) {
	mux_unlock(muxdata);
	*count = 0;
	return 0;
    }

    if (tot_len > chan->max_write_size - chan->write_data_len) {
	/* Can only send as much as we have buffer for. */
	tot_len = chan->max_write_size - chan->write_data_len;
	truncated = true;
    }

    if (tot_len > chan->send_window_size / 2) {
	/* Only allow sends to 1/2 the window size. */
	tot_len = chan->send_window_size / 2;
	truncated = true;
    }


    /* FIXME - consolidate writes if possible. */

    /* Construct the header and put it in first. */
    if (!truncated && auxdata && auxdata[0] && strcmp(auxdata[0], "eom") == 0)
	hdr[0] = MUX_FLAG_END_OF_MESSAGE;
    else
	hdr[0] = 0; /* flags */
    mux_u16_to_buf(hdr + 1, tot_len - 3);
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

    *count = rcount;
    return 0;
}

static int
muxc_raddr_to_str(struct mux_inst *chan, gensiods *epos,
		  char *buf, gensiods buflen)
{
    return GE_NOTSUP;
}

static int
muxc_remote_id(struct mux_inst *chan, int *id)
{
    return GE_NOTSUP;
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
    chan->hdr[0] = (MUX_CLOSE_CHANNEL << 4) | 0x2;
    chan->hdr[1] = 0;
    mux_u16_to_buf(&chan->hdr[2], chan->remote_id);
    mux_u16_to_buf(&chan->hdr[4], chan->errcode);
    mux_u16_to_buf(&chan->hdr[6], 0);
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
    if (chan->state == MUX_INST_IN_OPEN) {
	/* Handle it once the open response is received. */
	chan->state = MUX_INST_IN_OPEN_CLOSE;
	goto out_state;
    } else if (chan->state == MUX_INST_IN_REM_CLOSE) {
	chan->state = MUX_INST_IN_CLOSE_FINAL;
	chan_sched_deferred_op(chan);
	goto out_state;
    } else if (chan->state != MUX_INST_OPEN) {
	return GE_NOTREADY;
    }

    chan->state = MUX_INST_IN_CLOSE;
    chan->send_close = true;
    muxc_add_to_wrlist(chan);

 out_state:
    chan_ref(chan); /* We will deref when we go to closed. */
    chan->close_done = close_done;
    chan->close_data = close_data;

    return 0;
}

static int
muxc_close(struct mux_inst *chan, gensio_done close_done, void *close_data)
{
    struct mux_data *muxdata = chan->mux;
    int err = 0;

    mux_lock(muxdata);
    err = muxc_close_nolock(chan, close_done, close_data);
    mux_unlock(muxdata);
    return err;
}

static void
muxc_func_ref(struct mux_inst *chan)
{
    struct mux_data *muxdata = chan->mux;

    mux_lock(muxdata);
    chan_ref(chan);
    mux_unlock(muxdata);
}

static void
muxc_free(struct mux_inst *chan)
{
    struct mux_data *muxdata = chan->mux;

    mux_lock(muxdata);
    if (muxdata->state == MUX_CLOSED)
	goto out_deref;

    switch (chan->state) {
    case MUX_INST_IN_CLOSE:
    case MUX_INST_IN_REM_CLOSE:
    case MUX_INST_IN_CLOSE_FINAL:
    case MUX_INST_IN_OPEN_CLOSE:
	chan->open_done = NULL;
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
    mux_unlock(muxdata);
}

static int
muxc_disable(struct mux_inst *chan)
{
    struct mux_data *muxdata = chan->mux;

    muxdata->state = MUX_CLOSED;
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

    chan->deferred_op_runner = o->alloc_runner(o, chan_deferred_op, chan);
    if (!chan->deferred_op_runner)
	goto out_free;

    chan->io = gensio_data_alloc(o, cb, user_data, muxc_gensio_handler, NULL,
				 "mux-instance", chan);
    if (!chan->io)
	goto out_free;
    gensio_set_is_packet(chan->io, true);
    gensio_set_is_reliable(chan->io, true);
    if (gensio_is_authenticated(muxdata->child))
	gensio_set_is_authenticated(chan->io, true);
    if (gensio_is_encrypted(muxdata->child))
	gensio_set_is_encrypted(chan->io, true);
    chan->o = o;
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
    chan->state = MUX_INST_PENDING_OPEN;

    /*
     * We maintain the list in number order and rotate through the
     * numbers.  So we start after the last number used and rotate
     * through the entries until we find an empty spot.
     */
    if (gensio_list_empty(&muxdata->chans)) {
	id = 0; /* This is always the automatic channel. */
	gensio_list_add_tail(&muxdata->chans, &chan->link);
    } else {
	struct gensio_link *l, *p = &muxdata->chans.link, *f;
	struct mux_inst *tchan = NULL;

	/* First find the place at or before where the last number starts. */
	id = muxdata->last_id;
	gensio_list_for_each(&muxdata->chans, l) {
	    tchan = gensio_container_of(l, struct mux_inst, link);
	    if (tchan->id > id || tchan->state == MUX_INST_CLOSED)
		break;
	    p = l;
	}

	id = next_chan_id(muxdata, id);
	l = gensio_list_next_wrap(&muxdata->chans, p);
	if (tchan->state == MUX_INST_CLOSED)
	    l = gensio_list_first(&muxdata->chans);
	f = l;
	do {
	    tchan = gensio_container_of(l, struct mux_inst, link);
	    if (tchan->state == MUX_INST_CLOSED) {
		l = gensio_list_first(&muxdata->chans);
		continue;
	    }
	    if (id != tchan->id)
		goto found;
	    id = next_chan_id(muxdata, id);
	    p = l;
	    l = gensio_list_next_wrap(&muxdata->chans, p);
	} while (f != l);

	err = GE_INUSE;

    out_free:
	/* Didn't find a free number. */
	mux_channel_free(chan);
	return err;

    found:
	tchan = gensio_container_of(p, struct mux_inst, link);
	chan->id = id;
	muxdata->last_id = id;
	gensio_list_add_next(&muxdata->chans, p, &chan->link);
    }

    *new_mux = chan;
    return 0;
}

static int
muxc_open_channel_data(struct mux_data *muxdata,
		       gensio_event cb,
		       void *user_data,
		       gensio_done_err open_done,
		       void *open_data,
		       struct gensio_mux_config *data,
		       bool is_client,
		       struct gensio **new_io)
{
    struct mux_inst *chan = NULL;
    int err = 0;

    mux_lock(muxdata);
    err = mux_new_channel(muxdata, cb, user_data, is_client, &chan);
    if (err)
	goto out;

    if (data->service) {
	if (data->service_len > chan->max_write_size - 10) {
	    err = GE_TOOBIG;
	    goto out;
	}
	chan->service = gensio_strdup(muxdata->o, data->service);
	if (!chan->service) {
	    err = GE_NOMEM;
	    goto out;
	}
	chan->service_len = data->service_len;
    }

    chan->open_done = open_done;
    chan->open_data = open_data;
    chan->state = MUX_INST_IN_OPEN;

    if (is_client) {
	/* Only one open at a time is allowed, queue them otherwise. */
	if (muxdata->opencount == 0 && muxdata->state == MUX_OPEN) {
	    muxc_add_to_wrlist(chan);
	} else {
	    gensio_list_add_tail(&muxdata->openchans, &chan->wrlink);
	    chan->in_open_chan = true;
	}
	muxdata->opencount++;
	chan->send_new_channel = true;
    }
    mux_unlock(muxdata);

    if (new_io)
	*new_io = chan->io;
    return 0;

 out:
    mux_unlock(muxdata);
    if (chan)
	mux_channel_free(chan);
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

static int
muxc_open_channel(struct mux_data *muxdata,
		  struct gensio_func_open_channel_data *ocdata)
{
    int err;
    struct gensio_mux_config data;

    if (muxdata->state != MUX_OPEN)
	return GE_NOTREADY;

    memset(&data, 0, sizeof(data));
    data.max_read_size = muxdata->max_read_size;
    data.max_write_size = muxdata->max_write_size;

    err = gensio_mux_config(muxdata->o, ocdata->args, &data);
    if (err)
	return err;

    err = muxc_open_channel_data(muxdata, ocdata->cb, ocdata->user_data,
				 ocdata->open_done, ocdata->open_data,
				 &data, true, &ocdata->new_io);
    gensio_mux_config_cleanup(&data);
    return err;
}

static void
mux_child_open_done(struct gensio *child, int err, void *open_data)
{
    struct mux_data *muxdata = open_data;
    struct mux_inst *chan = mux_chan0(muxdata);

    mux_lock(muxdata);
    if (err) {
	gensio_done_err fopen_done = chan->open_done;
	void *fopen_data = chan->open_data;

	muxdata->state = MUX_CLOSED;
	mux_unlock(muxdata);
	fopen_done(chan->io, err, fopen_data);
	return;
    }
    chan->state = MUX_INST_IN_OPEN;
    gensio_set_write_callback_enable(muxdata->child, true);
    gensio_set_read_callback_enable(muxdata->child, true);
    mux_unlock(muxdata);
}

static void
muxc_reinit(struct mux_inst *chan)
{
    chan->id = 0;
    chan->remote_id = 0;
    chan->refcount = 1;
    chan->state = MUX_INST_PENDING_OPEN;
    chan->send_close = false;
    chan->ack_pending = false;
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
    if (!chan->in_open_chan) {
	gensio_list_add_tail(&chan->mux->openchans, &chan->wrlink);
	chan->in_open_chan = true;
    }
    chan->mux->opencount = 1;
    chan->send_new_channel = true;
}

static int
muxc_open(struct mux_inst *chan, gensio_done_err open_done, void *open_data)
{
    struct mux_data *muxdata = chan->mux;
    int err = GE_NOTREADY;

    mux_lock(muxdata);
    if (muxdata->state == MUX_CLOSED) {
	if (!muxdata->is_client) {
	    err = GE_NOTSUP;
	    goto out_unlock;
	}

	muxdata->sending_chan = NULL;
	muxdata->in_hdr = true;
	muxdata->hdr_pos = 0;
	muxdata->hdr_size = 0;
	muxdata->last_id = 0;
	muxc_reinit(chan);
	mux_send_init(muxdata);

	gensio_list_rm(&muxdata->chans, &chan->link);
	gensio_list_add_head(&muxdata->chans, &chan->link);
	chan->open_done = open_done;
	chan->open_data = open_data;
	err = gensio_open(muxdata->child, mux_child_open_done, muxdata);
	if (!err) {
	    gensio_set_write_callback_enable(muxdata->child, true);
	    muxdata->opencount++;
	    muxdata->state = MUX_UNINITIALIZED;
	}
    }
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

	    if (!chan->service)
		return GE_DATAMISSING;

	    to_copy = chan->service_len;
	    if (to_copy > *datalen)
		to_copy = *datalen;
	    memcpy(data, chan->service, *datalen);
	    *datalen = chan->service_len;
	} else {
	    char *new_service = chan->o->zalloc(chan->o, *datalen);

	    if (!new_service)
		return GE_NOMEM;
	    memcpy(new_service, data, *datalen);
	    if (chan->service)
		chan->o->free(chan->o, chan->service);
	    chan->service = new_service;
	    chan->service_len = *datalen;
	}
	break;

    default:
	err = GE_NOTSUP;
	break;
    }
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

    case GENSIO_FUNC_RADDR_TO_STR:
	return muxc_raddr_to_str(chan, count, buf, buflen);

    case GENSIO_FUNC_CLOSE:
	return muxc_close(chan, cbuf, buf);

    case GENSIO_FUNC_FREE:
	muxc_free(chan);
	return 0;

    case GENSIO_FUNC_REF:
	muxc_func_ref(chan);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	muxc_set_read_callback_enable(chan, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	muxc_set_write_callback_enable(chan, buflen);
	return 0;

    case GENSIO_FUNC_REMOTE_ID:
	return muxc_remote_id(chan, buf);

    case GENSIO_FUNC_DISABLE:
	return muxc_disable(chan);

    case GENSIO_FUNC_OPEN_CHANNEL:
	return muxc_open_channel(chan->mux, buf);

    case GENSIO_FUNC_OPEN:
	return muxc_open(chan, cbuf, buf);

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

    muxdata->state = MUX_IN_CLOSE;

    if (muxdata->state == MUX_WAITING_OPEN) {
	chan = mux_chan0(muxdata);
	mux_unlock(muxdata);
	muxdata->acc_open_done(chan->io, err, muxdata->acc_open_data);
	mux_lock(muxdata);
    }

    gensio_list_for_each_safe(&muxdata->chans, l, l2) {
	chan = gensio_container_of(l, struct mux_inst, link);
	if (chan->in_wrlist) {
	    gensio_list_rm(&muxdata->wrchans, &chan->wrlink);
	    chan->in_wrlist = false;
	}
	if (chan->in_open_chan) {
	    gensio_list_rm(&muxdata->openchans, &chan->wrlink);
	    muxdata->opencount--;
	    chan->in_open_chan = false;
	}
	if (chan->state == MUX_INST_CLOSED ||
		chan->state == MUX_INST_IN_REM_CLOSE ||
		chan->state == MUX_INST_IN_CLOSE_FINAL)
	    continue;
	if (chan->state == MUX_INST_PENDING_OPEN) {
	    gensio_list_rm(&muxdata->chans, &chan->link);
	    mux_channel_free(chan);
	    continue;
	}
	if (chan->state == MUX_INST_IN_OPEN ||
		chan->state == MUX_INST_IN_OPEN_CLOSE) {
	    chan->state = MUX_INST_IN_CLOSE_FINAL;
	    if (chan->open_done) {
		chan_ref(chan);
		mux_unlock(muxdata);
		chan->open_done(chan->io, err, chan->open_data);
		mux_lock(muxdata);
		chan_deref(chan);
	    }
	    continue;
	}

	/* Report the error through the read interface. */
	chan->errcode = err;
	chan->state = MUX_INST_IN_REM_CLOSE;
	chan_sched_deferred_op(chan);
    }
}

static void
chan_setup_send_new_channel(struct mux_inst *chan)
{
    chan->hdr[0] = (MUX_NEW_CHANNEL << 4) | 0x2;
    chan->hdr[1] = 0;
    mux_u16_to_buf(&chan->hdr[2], chan->id);
    mux_u32_to_buf(&chan->hdr[4], chan->max_read_size);
    mux_u16_to_buf(&chan->hdr[8], chan->service_len);
    chan->sg[0].buf = chan->hdr;
    chan->sg[0].buflen = 10;
    chan->sglen = 1;
    if (chan->service_len) {
	chan->sg[1].buf = chan->service;
	chan->sg[1].buflen = chan->service_len;
	chan->sglen++;
    }
    chan->cur_msg_len = 0; /* Data isn't in chan->write_data. */
}

static bool
chan_setup_send_data(struct mux_inst *chan)
{
    unsigned char flags = 0;
    gensiods pos;
    gensiods window_left = chan->send_window_size - chan->sent_unacked;

    chan->hdr[0] = (MUX_DATA << 4) | 0x2;
    chan->hdr[1] = 0;
    mux_u16_to_buf(chan->hdr + 2, chan->remote_id);
    mux_u32_to_buf(chan->hdr + 4, chan->received_unacked);
    chan->ack_pending = false;

    chan->sg[0].buf = chan->hdr;
    chan->sg[0].buflen = 8;

    if (chan->write_data_len == 0) {
    check_send_ack:
	if (chan->received_unacked == 0)
	    return false;
	chan->received_unacked = 0;
	/* Just sending an ack. */
	mux_u16_to_buf(chan->hdr + 8, 0);
	chan->sg[0].buflen = 10;
	chan->sglen = 1;
	return true;
    }
    chan->received_unacked = 0;

    assert(chan->write_data_len > 3);

    pos = chan_next_write_pos(chan, 1);
    chan->cur_msg_len = chan->write_data[pos] << 8;
    pos = chan_next_write_pos(chan, 2);
    chan->cur_msg_len |= chan->write_data[pos];
    chan->cur_msg_len += 2;

    if (chan->cur_msg_len > window_left)
	goto check_send_ack;

    flags = chan->write_data[chan->write_data_pos];
    chan_incr_write_pos(chan, 1);
    chan->hdr[1] = flags;

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

static int
mux_child_write_ready(struct mux_data *muxdata)
{
    int err = 0;
    struct mux_inst *chan;
    gensiods rcount;

    mux_lock(muxdata);
    /* Finish any pending channel data. */
    if (muxdata->sending_chan) {
	chan = muxdata->sending_chan;
    next_channel:
#ifdef MUX_TRACING
	{
	    int i;
	    TRACE_MSG_CHAN("Sending header:");
	    for (i = 0; i < chan->sg[0].buflen; i += 4)
		TRACE_MSG_CHAN("  %2.2x%2.2x%2.2x%2.2x",
			       ((uint8_t *) (chan->sg[0].buf))[i],
			       ((uint8_t *) (chan->sg[0].buf))[i + 1],
			       ((uint8_t *) (chan->sg[0].buf))[i + 2],
			       ((uint8_t *) (chan->sg[0].buf))[i + 3]);
	}
#endif
	err = gensio_write_sg(muxdata->child, &rcount, chan->sg + chan->sgpos,
			      chan->sglen - chan->sgpos, NULL);
	if (err)
	    goto out_write_err;
	while (rcount > 0) {
	    if (chan->sg[chan->sgpos].buflen <= rcount) {
		rcount -= chan->sg[chan->sgpos].buflen;
		chan->sgpos++;
		assert(chan->sgpos <= 3);
	    } else {
		chan->sg[chan->sgpos].buflen -= rcount;
		chan->sg[chan->sgpos].buf += rcount;
		rcount = 0;
	    }
	}
	if (chan->sgpos >= chan->sglen) {
	    /* Finished sending one message. */
	    chan->write_data_pos = chan_next_write_pos(chan, chan->cur_msg_len);
	    chan->write_data_len -= chan->cur_msg_len;
	    chan->cur_msg_len = 0;
	    muxdata->sending_chan = NULL;
	    if (chan->write_data_len > 0 || chan->send_new_channel ||
			chan->send_close) {
		/* More messages to send, add it to the tail for fairness. */
		gensio_list_add_tail(&muxdata->wrchans, &chan->wrlink);
		chan->in_wrlist = true;
	    } else if (chan->state == MUX_INST_IN_CLOSE_FINAL &&
		       chan->read_data_len == 0) {
		mux_channel_finish_close(chan);
		/* chan could be freed after this point, be careful! */
	    } else {
		chan->wr_ready = false;
		if (chan->state == MUX_INST_IN_CLOSE_FINAL)
		    chan_sched_deferred_op(chan);
	    }
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
	muxdata->xmit_data_len -= rcount;
	if (muxdata->xmit_data_len == 0) {
	    muxdata->xmit_data_pos = 0;
	} else {
	    /* Partial write, can't write anything else. */
	    muxdata->xmit_data_pos += rcount;
	    goto out;
	}
    }

    /* Now look for a new channel to send. */
 check_next_channel:
    if (!gensio_list_empty(&muxdata->wrchans)) {
	chan = gensio_container_of(gensio_list_first(&muxdata->wrchans),
				   struct mux_inst, wrlink);
	gensio_list_rm(&muxdata->wrchans, &chan->wrlink);
	chan->in_wrlist = false;
	chan->sgpos = 0;

	if (chan->send_new_channel) {
	    chan_setup_send_new_channel(chan);
	    chan->send_new_channel = false;
	    muxdata->sending_chan = chan;
	} else if (chan->write_data_len || chan->ack_pending) {
	    if (!chan_setup_send_data(chan)) {
		chan->wr_ready = false;
		goto check_next_channel;
	    }
	    muxdata->sending_chan = chan;
	} else if (chan->send_close) {
	    /* Do the close last so all data is sent. */
	    chan_send_close(chan);
	    chan->send_close = false;
	    muxdata->sending_chan = chan;
	} else {
	    muxdata->sending_chan = NULL;
	    chan->wr_ready = false;
	    goto check_next_channel;
	}
	goto next_channel;
    }
 out:
    gensio_set_write_callback_enable(muxdata->child,
		muxdata->sending_chan || !gensio_list_empty(&muxdata->wrchans));
    mux_unlock(muxdata);
    return 0;

 out_write_err:
    gensio_set_read_callback_enable(muxdata->child, false);
    gensio_set_write_callback_enable(muxdata->child, false);
    mux_shutdown_channels(muxdata, err);
    mux_unlock(muxdata);
    return 0;
}

static void
mux_proto_err_close(struct gensio *child, void *close_data)
{
    struct mux_data *muxdata = close_data;

    mux_lock(muxdata);
    mux_shutdown_channels(muxdata, GE_PROTOERR);
    mux_unlock(muxdata);
}

static struct mux_inst *
mux_get_channel(struct mux_data *muxdata)
{
    struct gensio_link *l;
    unsigned int id = mux_buf_to_u16(muxdata->hdr + 2);

    gensio_list_for_each(&muxdata->chans, l) {
	struct mux_inst *chan = gensio_container_of(l, struct mux_inst, link);

	if (chan->state == MUX_INST_CLOSED)
	    break;
	if (chan->id == id)
	    return chan;
    }
    return NULL;
}

static int
mux_child_read(struct mux_data *muxdata, int ierr,
	       unsigned char *buf, gensiods *ibuflen,
	       const char *const *nauxdata)
{
    gensiods processed = 0, used, acked, buflen = *ibuflen;
    int err = 0;
    struct mux_inst *chan;
    const char *auxdata[2] = { NULL, NULL };
    const char *proto_err_str = "?";

    mux_lock(muxdata);
    if (ierr) {
	gensio_set_read_callback_enable(muxdata->child, false);
	gensio_set_write_callback_enable(muxdata->child, false);
	mux_shutdown_channels(muxdata, ierr);
	mux_unlock(muxdata);
	return 0;
    }

    while (buflen > 0) {
	if (muxdata->in_hdr) {
	    if (muxdata->hdr_pos == 0) {
		/*
		 * The first byte of the header contains what we need
		 * to process the rest of the header.
		 */
		muxdata->hdr[muxdata->hdr_pos++] = *buf;
		muxdata->hdr_size = (*buf & 0xf) * 4;
		muxdata->msgid = *buf >> 4;
		if (muxdata->msgid == 0 || muxdata->msgid > MUX_MAX_MSG_NUM) {
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
		processed += buflen;
		goto out_unlock;
	    }

	    /* We have the whole header now. */
	    used = muxdata->hdr_size - muxdata->hdr_pos;
	    memcpy(muxdata->hdr + muxdata->hdr_pos, buf, used);
	    muxdata->hdr_pos = 0;

#ifdef MUX_TRACING
	    {
		int i;
		TRACE_MSG("New header:");
		for (i = 0; i < muxdata->hdr_size; i += 4)
		    TRACE_MSG("  %2.2x%2.2x%2.2x%2.2x", muxdata->hdr[i],
			      muxdata->hdr[i + 1], muxdata->hdr[i + 2],
			      muxdata->hdr[i + 3]);
	    }
#endif
	    if (muxdata->msgid == MUX_INIT) {
		if (muxdata->state != MUX_UNINITIALIZED) {
		    proto_err_str = "Init when already initialized";
		    goto protocol_err;
		}
		if (gensio_list_empty(&muxdata->openchans)) {
		    muxdata->state = MUX_WAITING_OPEN;
		    goto more_data;
		} else {
		    chan = NULL;
		    muxdata->state = MUX_IN_OPEN;
		    goto next_channel_req_send;
		}
	    }

	    if (muxdata->state == MUX_UNINITIALIZED) {
		proto_err_str = "Not initialized";
		goto protocol_err;
	    }

	    switch (muxdata->msgid) {
	    case MUX_NEW_CHANNEL:
		if (muxdata->state == MUX_WAITING_OPEN)
		    chan = mux_chan0(muxdata);
		else {
		    int err = mux_new_channel(muxdata, NULL, NULL, false, &chan);
		    if (err)
			chan = NULL;
		}
		muxdata->curr_chan = chan;
		if (chan) {
		    chan->send_window_size = mux_buf_to_u32(muxdata->hdr + 4);
		    chan->remote_id = mux_buf_to_u16(muxdata->hdr + 2);
		    muxdata->data_pos = 0;
		    muxdata->in_hdr = false; /* Receive the service data */
		}
		break;

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
		if (muxdata->state == MUX_IN_OPEN)
		    muxdata->state = MUX_OPEN;
		chan->remote_id = mux_buf_to_u16(muxdata->hdr + 8);
		chan->send_window_size = mux_buf_to_u32(muxdata->hdr + 4);
		chan->errcode = mux_buf_to_u16(muxdata->hdr + 10);
		assert(muxdata->opencount > 0);
		muxdata->sending_chan = NULL;

		if (chan->errcode) {
		    chan->state = MUX_INST_IN_CLOSE_FINAL;
		} else if (chan->state == MUX_INST_IN_OPEN_CLOSE) {
		    chan->send_close = true;
		    muxc_add_to_wrlist(chan);
		    chan->state = MUX_INST_IN_CLOSE;
		    chan = NULL;
		} else {
		    chan->state = MUX_INST_OPEN;
		}

	    next_channel_req_send:
		muxdata->opencount--;
		/* Start the next channel open, if necessary. */
		if (!gensio_list_empty(&muxdata->openchans)) {
		    struct mux_inst *next_chan =
			gensio_container_of(
				gensio_list_first(&muxdata->openchans),
				struct mux_inst, wrlink);
		    gensio_list_rm(&muxdata->openchans, &next_chan->wrlink);
		    next_chan->in_open_chan = false;
		    muxc_add_to_wrlist(next_chan);
		}

		if (chan && chan->open_done) {
		    chan_ref(chan);
		    mux_unlock(muxdata);
		    chan->open_done(chan->io, chan->errcode, chan->open_data);
		    mux_lock(muxdata);
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
		chan->errcode = mux_buf_to_u16(muxdata->hdr + 4);
		if (chan->state == MUX_INST_IN_CLOSE) {
		    chan->state = MUX_INST_IN_CLOSE_FINAL;
		    if (chan->read_data_len == 0 && !chan->wr_ready)
			mux_channel_finish_close(chan);
		    /* chan could be freed after this point, be careful. */
		} else {
		    chan->state = MUX_INST_IN_REM_CLOSE;
		    if (chan->errcode == 0)
			chan->errcode = GE_REMCLOSE;
		    chan->send_close = true;
		    muxc_add_to_wrlist(chan);
		    chan_sched_deferred_op(chan);
		}
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
		acked = mux_buf_to_u32(muxdata->hdr + 4);
		if (acked > chan->sent_unacked)
		    chan->sent_unacked = 0; /* FIXME - Should we protocol err? */
		else
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
			gensio_list_rm(&chan->mux->chans, &chan->link);
			mux_channel_free(chan);
			/* NULL curr_chan will cause an error to be sent. */
		    }
		    break;

		case MUX_DATA:
		    if (muxdata->data_size == 0) {
			muxdata->data_pos++;
			used = 1;
			goto handle_read_no_data;
		    }
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
		muxdata->data_pos++;
		used = 1;
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
		    goto new_chan_err;
		}
	    new_chan_no_service:
		chan->state = MUX_INST_OPEN;
		chan_ref(chan);
		if (muxdata->state == MUX_WAITING_OPEN) {
		    /*
		     * This is the first channel, deliver to the
		     * gensio_acc_gensio code as an open.
		     */
		    muxdata->state = MUX_OPEN;
		    chan->state = MUX_INST_OPEN;
		    mux_unlock(muxdata);
		    muxdata->acc_open_done(chan->io, 0, muxdata->acc_open_data);
		    mux_lock(muxdata);
		    mux_send_new_channel_rsp(muxdata, chan->remote_id,
					     chan->max_read_size,
					     chan->id, 0);
		} else {
		    mux_unlock(muxdata);
		    if (chan->service)
			auxdata[0] = chan->service;
		    else
			auxdata[0] = "";
		    err = mux_chan0_event(muxdata, GENSIO_EVENT_NEW_CHANNEL, 0,
					  (void *) chan->io, 0, auxdata);
		    mux_lock(muxdata);
		    if (err) {
		    new_chan_err:
			if (muxdata->xmit_data_len) {
			    /* Only one new channel allowed at a time. */
			    proto_err_str = "New channel while in progress";
			    goto protocol_err;
			}
			mux_send_new_channel_rsp(muxdata,
					     mux_buf_to_u16(muxdata->hdr + 2),
					     0, 0, err);
			if (chan) {
			    gensio_list_rm(&chan->mux->chans, &chan->link);
			    mux_channel_free(chan);
			}
		    } else {
			if (muxdata->xmit_data_len) {
			    proto_err_str = "New channel while in progress";
			    goto protocol_err;
			}
			mux_send_new_channel_rsp(muxdata, chan->remote_id,
						 chan->max_read_size,
						 chan->id, 0);
			if (chan->service_len) {
			    /* Ack the service data. */
			    chan->received_unacked = chan->service_len;
			    chan->ack_pending = true;
			    muxc_add_to_wrlist(chan);
			}
		    }
		}
		muxdata->in_hdr = true;
		chan_deref(chan);
		goto more_data;

	    case MUX_DATA:
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
    mux_unlock(muxdata);
    *ibuflen = processed;
    return 0;

 protocol_err:
    gmux_log_err(muxdata, "Protocol error: %s\n", proto_err_str);
    err = gensio_close(muxdata->child, mux_proto_err_close, muxdata);
    if (err)
	mux_shutdown_channels(muxdata, GE_PROTOERR);
    mux_unlock(muxdata);
    return 0;
}

static int
mux_child_cb(struct gensio *io, void *user_data, int event,
	     int err, unsigned char *buf, gensiods *buflen,
	     const char *const *auxdata)
{
    struct mux_data *muxdata = user_data;

    switch (event) {
    case GENSIO_EVENT_READ:
	return mux_child_read(muxdata, err, buf, buflen, auxdata);

    case GENSIO_EVENT_WRITE_READY:
	return mux_child_write_ready(muxdata);

    case GENSIO_EVENT_NEW_CHANNEL:
	return GE_NOTSUP;

    default:
	return mux_chan0_event(muxdata, event, err, buf, buflen, auxdata);
    }
}

static int
mux_gensio_alloc_data(struct gensio *child, struct gensio_mux_config *data,
		      gensio_event cb, void *user_data, bool is_client,
		      struct mux_data **rmuxdata)
{
    struct gensio_os_funcs *o = data->o;
    struct mux_data *muxdata;
    int rv;

    muxdata = o->zalloc(o, sizeof(*muxdata));
    if (!muxdata)
	return GE_NOMEM;

    muxdata->o = o;
    muxdata->is_client = is_client;
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
    rv = muxc_open_channel_data(muxdata, cb, user_data,
				NULL, NULL, data, is_client, NULL);
    if (rv)
	goto out_nomem;

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

int
mux_gensio_alloc(struct gensio *child, const char *const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **net)
{
    int err;
    struct gensio *io;
    struct gensio_mux_config data;
    struct mux_data *muxdata;

    if (!gensio_is_reliable(child))
	/* Cowardly refusing to run MUX over an unreliable connection. */
	return GE_NOTSUP;

    memset(&data, 0, sizeof(data));
    data.max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    data.max_write_size = GENSIO_DEFAULT_BUF_SIZE;
    data.max_channels = 1000;

    err = gensio_mux_config(o, args, &data);
    if (err)
	return err;

    err = mux_gensio_alloc_data(child, &data, cb, user_data, true, &muxdata);
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

int
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
muxna_free(void *acc_data)
{
    struct muxna_data *nadata = acc_data;

    gensio_mux_config_cleanup(&nadata->data);
    nadata->o->free(nadata->o, nadata);
}

int
muxna_alloc_gensio(void *acc_data, const char * const *iargs,
		   struct gensio *child, struct gensio **rio)
{
    struct muxna_data *nadata = acc_data;

    return mux_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);
}

static int
muxna_new_child(void *acc_data, void **finish_data,
		struct gensio_new_child_io *ncio)
{
    struct muxna_data *nadata = acc_data;
    struct mux_data *muxdata;
    struct mux_inst *chan;
    int err;

    err = mux_gensio_alloc_data(ncio->child, &nadata->data,
				NULL, NULL, false, &muxdata);
    if (!err) {
	mux_lock(muxdata);
	chan = mux_chan0(muxdata);
	ncio->new_io = chan->io;
	muxdata->state = MUX_UNINITIALIZED;
	muxdata->acc_open_done = ncio->open_done;
	muxdata->acc_open_data = ncio->open_data;
	gensio_set_write_callback_enable(muxdata->child, true);
	gensio_set_read_callback_enable(muxdata->child, true);
	mux_unlock(muxdata);
    }
    return err;
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
    default:
	return GE_NOTSUP;
    }
}

int
mux_gensio_accepter_alloc(struct gensio_accepter *child,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_accepter_event cb, void *user_data,
			  struct gensio_accepter **accepter)
{
    struct muxna_data *nadata;
    int err;

    if (!gensio_acc_is_reliable(child))
	/* Cowardly refusing to run MUX over an unreliable connection. */
	return GE_NOTSUP;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    nadata->data.max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    nadata->data.max_write_size = GENSIO_DEFAULT_BUF_SIZE;
    nadata->data.max_channels = 1000;
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

int
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
