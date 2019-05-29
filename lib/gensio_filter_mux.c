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

#include "gensio_filter_mux.h"
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

    /*
     * Shut down a mux connection.  If error code is non-zero, it is
     * a gensio error describing the reason.  If this is received on an
     * open session, it is sent as a reponse.
     *
     * +----------------+--------+-------+----------------+----------------+
     * |   6   |size(1) |    reserved    |            error code           |
     * +----------------+--------+-------+----------------+----------------+
     */
    MUX_SHUTDOWN	= 6
};

#define MUX_MAX_MSG_NUM MUX_DATA

static unsigned int mux_msg_hdr_sizes[] = { 0, 1, 2, 3, 2, 2, 1 };

/* External flags for MUX_DATA */
#define MUX_FLAG_END_OF_MESSAGE		(1 << 0)

#define MUX_MAX_HDR_SIZE	12

struct mux_filter;

enum mux_inst_state {
    MUX_INST_CLOSED,
    MUX_INST_IN_OPEN,
    MUX_INST_OPEN,
    MUX_INST_IN_CLOSE,		/* Local end requested a close. */
    MUX_INST_IN_REM_CLOSE	/* Remote end requested a close. */
};

struct mux_inst {
    struct gensio_os_funcs *o;
    struct gensio *io;
    struct mux_filter *filter;
    unsigned int id;
    unsigned int remote_id;
    enum mux_inst_state state;
    int errcode; /* If an error occurs, it is stored here. */
    bool send_new_channel;
    bool send_close;

    /*
     * The service, either the local one or the remote one.
     */
    char *service;

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

    gensio_event cb;
    void *user_data;

    /* Link for list of channels waiting write. */
    struct gensio_link wrlink;
    bool in_wrlist; /* Also true if chan == mfilter->sending_chan. */

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
chan_incr_read_pos(struct mux_inst *chan, unsigned int count)
{
    chan->read_data_pos = chan_next_read_pos(chan, count);
    chan->read_data_len -= count;
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

struct gensio_mux_filter_data {
    struct gensio_os_funcs *o;
    gensiods max_read_size;
    gensiods max_write_size;
    char *service;
    gensio_event cb;
    void *user_data;
};

struct mux_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;
    bool mux_initialized;
    struct gensio_lock *lock;

    gensiods max_read_size;
    gensiods max_write_size;

    /*
     * Small piece of data for sending new channel responses.  It's
     * separate in case the channel data could not be allocated.  The
     * protocol only allows one new channel request at a time.
     */
    unsigned char xmit_data[MUX_MAX_HDR_SIZE];
    gensiods xmit_data_pos;
    gensiods xmit_data_len;

    /*
     * Channel I am currently sending data on.
     */
    struct mux_inst *sending_chan;

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

    struct mux_inst *curr_chan;

    /* The last id we chose for a channel. */
    unsigned int last_id;

    /* Mux instances with write pending. */
    struct gensio_list wrchans;

    /* Muxes waiting to open. */
    struct gensio_list openchans;
    unsigned int opencount;

    /* All the channels in the system. */
    struct gensio_list chans;
};

#define filter_to_mux(v) ((struct mux_filter *) gensio_filter_get_user_data(v))

static void
gmux_log_info(struct mux_filter *f, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    gensio_vlog(f->o, GENSIO_LOG_INFO, fmt, ap);
    va_end(ap);
}

static void
gmux_log_err(struct mux_filter *f, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    gensio_vlog(f->o, GENSIO_LOG_ERR, fmt, ap);
    va_end(ap);
}

static void chan_ref(struct mux_inst *chan)
{
    assert(chan->refcount > 0);
    chan->refcount++;
}

static bool chan_deref(struct mux_inst *chan)
{
    assert(chan->refcount > 0);
    if (--chan->refcount == 0) {
	mux_channel_free(chan);
	return true;
    }
    return false;
}

static void
mux_lock(struct mux_filter *mfilter)
{
    mfilter->o->lock(mfilter->lock);
}

static void
mux_unlock(struct mux_filter *mfilter)
{
    mfilter->o->unlock(mfilter->lock);
}

static struct mux_inst *
mux_chan0(struct mux_filter *mfilter)
{
    return gensio_container_of(gensio_list_first(&mfilter->chans),
			       struct mux_inst, link);
}

static void
mux_set_callbacks(struct mux_filter *mfilter,
		  gensio_filter_cb cb, void *cb_data)
{
    /* Filter callbacks currently are not used. */
}

static bool
mux_ul_read_pending(struct mux_filter *mfilter)
{
    struct mux_inst *chan0 = mux_chan0(mfilter);

    return chan0->read_data_len || chan0->read_deliver_close;
}

static bool
mux_ll_write_pending(struct mux_filter *mfilter)
{
    bool rv;

    mux_lock(mfilter);
    rv = (mfilter->sending_chan ||
	  !gensio_list_empty(&mfilter->wrchans) ||
	  mfilter->xmit_data_len > 0);
    mux_unlock(mfilter);
    return rv;
}

static bool
mux_ll_read_needed(struct mux_filter *mfilter)
{
    /* Flow control is done per-channel, so we can always read. */
    return true;
}

static uint32_t
mux_buf_to_u32(unsigned char *data)
{
    return (data[0] << 24 ||
	    data[1] << 16 ||
	    data[2] << 8 ||
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
    return (data[0] << 8 || data[1]);
}

static void
mux_u16_to_buf(unsigned char *data, uint16_t v)
{
    data[0] = v >> 8;
    data[1] = v;
}

static void
mux_send_new_channel_rsp(struct mux_filter *mfilter, unsigned int remote_id,
			 unsigned int max_read_size, unsigned int id,
			 int err)
{
    mfilter->xmit_data[0] = (MUX_NEW_CHANNEL_RSP << 4) | 0x3;
    mfilter->xmit_data[1] = 0;
    mux_u16_to_buf(&mfilter->xmit_data[2], remote_id);
    mux_u32_to_buf(&mfilter->xmit_data[4], max_read_size);
    mux_u16_to_buf(&mfilter->xmit_data[8], id);
    mux_u16_to_buf(&mfilter->xmit_data[10], err);
    mfilter->xmit_data_pos = 0;
    mfilter->xmit_data_len = 12;
}

static gensiods
add_buf(struct mux_inst *chan, unsigned char *buf, gensiods len)
{
    gensiods rcount = 0;

    if (len + chan->write_data_pos > chan->max_write_size) {
	gensiods ebuf = chan->max_write_size - chan->write_data_pos;

	memcpy(chan->write_data + chan->write_data_pos, buf, ebuf);
	buf += ebuf;
	len -= ebuf;
	chan->write_data_pos = 0;
	chan->write_data_len += ebuf;
	rcount += ebuf;
    }
    memcpy(chan->write_data + chan->write_data_pos, buf, len);
    chan->write_data_pos += len;
    chan->write_data_len += len;

    return rcount + len;
}

static void
chan_check_send_more(struct mux_inst *chan)
{
    while (chan->write_data_len < chan->max_write_size &&
	   chan->write_ready_enabled && !chan->in_write_ready) {
	chan->in_write_ready = true;
	/* FIXME = make sure to keep chan and chan->filter around. */
	chan_ref(chan);
	mux_unlock(chan->filter);
	chan->cb(chan->io, chan->user_data, GENSIO_EVENT_WRITE_READY,
		 0, NULL, NULL, NULL);
	mux_lock(chan->filter);
	if (chan_deref(chan))
	    return;
	chan->in_write_ready = false;
    }
}

static void
chan_check_read(struct mux_inst *chan)
{
    struct mux_filter *mfilter = chan->filter;
    unsigned char flags;
    gensiods len, olen, rcount, orcount, pos;
    static const char *eom[] = { "eom", NULL };

    while ((chan->read_data_len || chan->read_deliver_close) &&
	   chan->read_enabled && !chan->in_read_report) {
	chan->in_read_report = true;

	if (chan->read_data_len == 0) {
	    /* read_deliver_close is true and no data. */
	    chan_ref(chan);
	    mux_unlock(mfilter);
	    chan->cb(chan->io, chan->user_data, GENSIO_EVENT_READ,
		     chan->errcode, NULL, NULL, NULL);
	    mux_lock(mfilter);
	    if (chan_deref(chan))
		return;
	    chan->in_read_report = false;
	    continue;
	}

	assert(chan->read_data_len > 3);

	flags = chan->read_data[chan->read_data_pos];
	len = chan->read_data[chan_next_read_pos(chan, 1)] << 8;
	len |= chan->read_data[chan_next_read_pos(chan, 2)];
	assert(len + 3 <= chan->read_data_len);
	pos = chan_next_read_pos(chan, 3);

	chan_ref(chan);

	olen = len;
	if (len > chan->max_read_size - pos) {
	    /* Buffer wraps, deliver in two parts. */
	    rcount = chan->max_read_size - pos;
	    orcount = rcount;
	    mux_unlock(mfilter);
	    chan->cb(chan->io, chan->user_data, GENSIO_EVENT_READ,
		     0, chan->read_data + pos, &rcount, NULL);
	    mux_lock(mfilter);
	    if (rcount <= len)
		len -= rcount;
	    else
		len = 0;
	    if (rcount != orcount)
		/* User didn't consume all data. */
		goto after_read_done;
	    pos = 0;
	}
	rcount = len;
	mux_unlock(mfilter);
	chan->cb(chan->io, chan->user_data, GENSIO_EVENT_READ,
		 0, chan->read_data + pos, &rcount,
		 flags & MUX_FLAG_END_OF_MESSAGE ? eom : NULL);
	mux_lock(mfilter);
	if (rcount <= len)
	    len -= rcount;
	else
	    len = 0;
    after_read_done:
	if (len > 0) {
	    /* Partial send, create a new 3-byte header over the data left. */
	    chan_incr_read_pos(chan, olen - len);
	    chan->read_data[chan->read_data_pos] = flags;
	    chan->read_data[chan_next_read_pos(chan, 1)] = len >> 8;
	    chan->read_data[chan_next_read_pos(chan, 2)] = len & 0xff;
	} else {
	    chan_incr_read_pos(chan, olen + 3);
	    if (chan->read_data_len == 0 && !chan->in_wrlist &&
			chan->state == MUX_INST_CLOSED)
		mux_channel_finish_close(chan);
	}
	chan->in_read_report = false;
	if (chan_deref(chan))
	    return;
    }
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
mux_channel_finish(struct mux_inst *chan)
{
    struct mux_filter *mfilter = chan->filter;

    gensio_list_rm(&mfilter->chans, &chan->link);
    chan_deref(chan);
}

static void
mux_channel_finish_close(struct mux_inst *chan, int err)
{
    if (chan->state == MUX_INST_CLOSED) {
	if (chan->close_done) {
	    gensio_done_err close_done = chan->close_done;

	    chan->close_done = NULL;
	    chan_ref(chan);
	    mux_unlock(mfilter);
	    close_done(chan->io, chan->errcode, chan->close_data);
	    mux_lock(mfilter);
	    chan_deref(chan);
	}
	mux_channel_finish(chan);
    } else {
	/* Set up to deliver read error. */
	chan->read_deliver_close = true;
	chan_sched_deferred_op(chan);
    }
}

static void
chan_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct mux_inst *chan = cbdata;
    struct mux_filter *mfilter = chan->filter;

    mux_lock(mfilter);
    chan->deferred_op_pending = false;
    chan_check_send_more(chan);
    chan_check_read(chan);

    chan_deref(chan);
    mux_unlock(mfilter);
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

static int
muxc_write(struct mux_inst *chan, gensiods *count,
	   const struct gensio_sg *sg, gensiods sglen,
	   const char *const *auxdata)
{
    struct mux_filter *mfilter = chan->filter;
    gensiods rcount, i, tot_len = 0;
    unsigned char hdr[3];
    gensiods len;
    const unsigned char *buf;
    bool truncated = false;

    for (i = 0; i < sglen; i++)
	tot_len += sg[i].buflen;
    if (tot_len == 0) {
	*count = 0;
	return 0;
    }
    tot_len += 3; /* Add the header. */

    mux_lock(mfilter);
    if (chan->state != MUX_INST_OPEN) {
	mux_unlock(mfilter);
	return GE_NOTREADY;
    }

    if (chan->errcode) {
	int err = chan->errcode;

	mux_unlock(mfilter);
	return err;
    }

    /*
     * Just return on buffer full.  We need 3 bytes for the header and at
     * least a byte of data.
     */
    if (chan->max_write_size - chan->write_data_len < 4) {
	mux_unlock(mfilter);
	*count = 0;
	return 0;
    }

    if (tot_len > chan->max_write_size - chan->write_data_len) {
	/* Can only send as much as we have buffer for. */
	tot_len = chan->max_write_size - chan->write_data_len;
	truncated = true;
    }

    if (tot_len > chan->send_window_size - chan->sent_unacked) {
	/* Flow-control here, don't allow sends more than the remote window. */
	tot_len = chan->send_window_size - chan->sent_unacked;
	truncated = true;
    }

    /* Construct the header and put it in first. */
    if (!truncated && auxdata && auxdata[0] && strcmp(auxdata[0], "eom") == 0)
	hdr[0] = MUX_FLAG_END_OF_MESSAGE;
    else
	hdr[0] = 0; /* flags */
    mux_u16_to_buf(hdr + 1, tot_len - 3);
    chan_addwrbuf(chan, hdr, 3);

    rcount = 0;
    for (i = 0; i < sglen && tot_len; i++) {
	len = sg[i].buflen;
	if (len > tot_len)
	    len = tot_len;
	chan_addwrbuf(chan, sg[i].buf, len);
	rcount += len;
	tot_len -= len;
    }

    if (!chan->in_wrlist) {
	gensio_list_add_tail(&mfilter->wrchans, &chan->wrlink);
	chan->in_wrlist = true;
    }

    mux_unlock(mfilter);

    *count = rcount - 3; /* Subtract off the header. */
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
    mux_lock(chan->filter);
    if (chan->read_enabled != enabled) {
	chan->read_enabled = enabled;
	if (enabled)
	    chan_sched_deferred_op(chan);
    }
    mux_unlock(chan->filter);
}

static void
muxc_set_write_callback_enable(struct mux_inst *chan, bool enabled)
{
    mux_lock(chan->filter);
    if (chan->write_ready_enabled != enabled) {
	chan->write_ready_enabled = enabled;
	if (enabled)
	    chan_sched_deferred_op(chan);
    }
    mux_unlock(chan->filter);
}

static int
muxc_open(struct mux_inst *chan, gensio_done_err open_done, void *open_data)
{
    return GE_NOTSUP;
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
}

static int
muxc_close(struct mux_inst *chan, gensio_done close_done, void *close_data)
{
    int err = 0;

    mux_lock(chan->filter);
    if (chan->state == MUX_INST_IN_OPEN) {
	/* Handle it once the open response is received. */
	goto out_state_unlock;
    } else if (chan->state == MUX_INST_IN_REM_CLOSE) {
	/* Remote end requested a close, so it's already in progress. */
	chan->state = MUX_INST_CLOSED;
	chan->read_deliver_close = false;
	chan_sched_deferred_op(chan);
	goto out_done_handler_unlock;
    } else if (chan->state != MUX_INST_OPEN) {
	err = GE_NOTREADY;
	goto out_unlock;
    }

    if (!chan->in_wrlist) {
	gensio_list_add_tail(&mfilter->wrchans, &chan->wrlink);
	chan->in_wrlist = true;
    }

 out_state_unlock:
    chan->send_close = true;
    chan->state = MUX_INST_IN_CLOSE;
    chan->errcode = GE_REMCLOSE;
 out_done_handler_unlock:
    chan->close_done = close_done;
    chan->close_data = close_data;
    
 out_unlock:
    mux_unlock(chan->filter);
    return err;
    /* FIXME */
}

static void
muxc_func_ref(struct mux_inst *chan)
{
    /* FIXME */
}

static void
muxc_free(struct mux_inst *chan)
{
    /* FIXME */
}

static int
muxc_disable(struct mux_inst *chan)
{
    /* FIXME */
}

static int
muxc_open_channel(struct mux_inst *chan,
		  struct gensio_func_open_channel_data *d)
{
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

    case GENSIO_FUNC_OPEN:
	return muxc_open(chan, cbuf, buf);

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

    default:
	return GE_NOTSUP;
    }
}

static unsigned int
next_chan_id(unsigned int num)
{
    if (num >= 65535)
	return 1;
    else
	return num + 1;
}

static struct mux_inst *
mux_new_channel(struct mux_filter *mfilter, enum mux_inst_state state)
{
    struct mux_inst *chan;
    unsigned int id;
    struct gensio_os_funcs *o = mfilter->o;

    chan = o->zalloc(o, sizeof(*chan));
    if (!chan)
	return NULL;

    chan->deferred_op_runner = o->alloc_runner(o, chan_deferred_op, chan);
    if (!chan->deferred_op_runner)
	goto out_nomem;

    chan->io = gensio_data_alloc(o, NULL, NULL, muxc_gensio_handler, NULL,
				 "mux-instance", chan);
    if (!chan->io)
	goto out_free;
    chan->o = o;
    chan->refcount = 1;
    chan->max_read_size = mfilter->max_read_size;
    chan->max_write_size = mfilter->max_write_size;
    chan->read_data = o->zalloc(o, chan->max_read_size);
    if (!chan->read_data)
	goto out_free;
    chan->write_data = o->zalloc(o, chan->max_write_size);
    if (!chan->write_data)
	goto out_free;
    chan->state = state;

    /*
     * We maintain the list in number order and rotate through the
     * numbers.  So we start after the last number used and rotate
     * through the entries until we find an empty spot.
     */ 
    if (gensio_list_empty(&mfilter->chans)) {
	id = 0; /* This is always the automatic channel. */
	gensio_list_add_tail(&mfilter->chans, &chan->link);
    } else {
	struct gensio_link *l, *p = &mfilter->chans.link, *f;
	struct mux_inst *tchan = NULL;

	/* First find the place at or before where the last number starts. */
	id = mfilter->last_id;
	gensio_list_for_each(&mfilter->chans, l) {
	    tchan = gensio_container_of(l, struct mux_inst, link);
	    if (tchan->id >= id)
		break;
	    p = l;
	}

	id = next_chan_id(id);
	l = gensio_list_next_wrap(&mfilter->chans, p);
	f = l;
	do {
	    tchan = gensio_container_of(l, struct mux_inst, link);
	    if (id != tchan->id)
		goto found;
	    id = next_chan_id(id);
	    p = l;
	    l = gensio_list_next_wrap(&mfilter->chans, p);
	} while (f != l);

    out_free:
	/* Didn't find a free number. */
	mux_channel_free(chan);
	return NULL;

    found:
	chan->id = id;
	mfilter->last_id = id;
	gensio_list_add_next(&mfilter->chans, p, &chan->link);
    }

    return chan;
}

static struct mux_inst *
mux_get_channel(struct mux_filter *mfilter)
{
    struct gensio_link *l;
    unsigned int id = mux_buf_to_u16(mfilter->hdr + 2);

    gensio_list_for_each(&mfilter->chans, l) {
	struct mux_inst *chan = gensio_container_of(l, struct mux_inst, link);

	if (chan->id == id)
	    return chan;
    }
    return NULL;
}

static int
mux_check_open_done(struct mux_filter *mfilter, struct gensio *io)
{
    if (!mfilter->mux_initialized)
	return GE_INPROGRESS;
    return 0;
}

static int
mux_try_connect(struct mux_filter *mfilter, struct timeval *timeout)
{
    mfilter->xmit_data[0] = (MUX_INIT << 4) | 0x1;
    mfilter->xmit_data[1] = 0;
    mfilter->xmit_data[2] = 1;
    mfilter->xmit_data[3] = 0;
    mfilter->xmit_data_pos = 0;
    mfilter->xmit_data_len = 4;
    if (!mfilter->mux_initialized)
	return GE_INPROGRESS;
    return 0;
}

static int
mux_try_disconnect(struct mux_filter *mfilter, struct timeval *timeout)
{
    int rv = 0;

    mux_lock(mfilter);
    /* FIXME */
    mux_unlock(mfilter);

    return rv;
}

static void
chan_setup_send_new_channel(struct mux_inst *chan)
{
    unsigned int len = strlen(chan->service);

    chan->hdr[0] = (MUX_NEW_CHANNEL << 4) | 0x2;
    chan->hdr[1] = 0;
    mux_u16_to_buf(&chan->hdr[2], chan->id);
    mux_u32_to_buf(&chan->hdr[4], chan->max_read_size);
    mux_u16_to_buf(&chan->hdr[8], len);
    chan->sg[0].buf = chan->hdr;
    chan->sg[0].buflen = 10;
    chan->sg[1].buf = chan->service;
    chan->sg[1].buflen = len;
    chan->sglen = 2;
    chan->cur_msg_len = 0; /* Data isn't in chan->write_data. */
}

static void
chan_setup_send_data(struct mux_inst *chan)
{
    unsigned char flags;
    gensiods pos;

    assert(chan->write_data_len > 3);

    flags = chan->write_data[chan->write_data_pos];
    chan_incr_write_pos(chan, 1);

    chan->cur_msg_len = chan->write_data[chan->write_data_pos] << 8;
    pos = chan_next_write_pos(chan, 1);
    chan->cur_msg_len |= chan->write_data[pos];
    chan->cur_msg_len += 2;

    chan->hdr[0] = (MUX_DATA << 4) | 0x2;
    chan->hdr[1] = flags;
    mux_u16_to_buf(chan->hdr + 2, chan->remote_id);
    mux_u32_to_buf(chan->hdr + 4, chan->received_unacked);
    chan->received_unacked = 0;

    chan->sg[0].buf = chan->hdr;
    chan->sg[0].buflen = 8;
    
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
}

static int
mux_ul_write(struct mux_filter *mfilter,
	     gensio_ul_filter_data_handler handler, void *cb_data,
	     gensiods *ircount,
	     const struct gensio_sg *isg, gensiods isglen,
	     const char *const *auxdata)
{
    int err = 0;
    struct mux_inst *chan;
    gensiods rcount;

    if (isglen) {
	chan = mux_chan0(mfilter);
	err = gensio_write_sg(chan->io, ircount, isg, isglen, auxdata);
	if (err)
	    return err;
    }

    mux_lock(mfilter);
    /* Finish any pending channel data. */
    if (mfilter->sending_chan) {
	chan = mfilter->sending_chan;
    next_channel:
	err = handler(cb_data, &rcount, chan->sg + chan->sgpos, chan->sglen,
		      NULL);
	if (err)
	    goto out;
	chan->sent_unacked += rcount;
	while (chan->sg[chan->sgpos].buflen < rcount) {
	    rcount -= chan->sg[chan->sgpos].buflen;
	    chan->sgpos++;
	    assert(chan->sgpos < 3);
	}
	chan->sg[chan->sgpos].buflen -= rcount;
	chan->sg[chan->sgpos].buf += rcount;
	if (chan->sg[chan->sgpos].buflen == 0) {
	    /* Finished sending one message. */
	    chan->write_data_pos = chan_next_write_pos(chan, chan->cur_msg_len);
	    chan->write_data_len -= chan->cur_msg_len;
	    mfilter->sending_chan = NULL;
	    /* FIXME - add more write list reasons here as they come. */
	    if (chan->write_data_len > 0 || chan->send_new_channel ||
			chan->send_close) {
		/* More messages to send, add it to the tail for fairness. */
		gensio_list_add_tail(&mfilter->wrchans, &chan->wrlink);
	    } else if (chan->state == MUX_INST_CLOSED &&
		       chan->read_data_len == 0) {
		mux_channel_finish_close(chan);
		/* chan could be freed after this point, be careful! */
	    } else {
		chan->in_wrlist = false;
	    }
	} else {
	    /* Couldn't send all the data. */
	    goto out;
	}
    }

    /* Handle data not associated with an existing channel. */
    if (mfilter->xmit_data_len) {
	struct gensio_sg sg[1];

	sg[0].buf = mfilter->xmit_data + mfilter->xmit_data_pos;
	sg[0].buflen = mfilter->xmit_data_len;
	err = handler(cb_data, &rcount, sg, 1, NULL);
	if (err)
	    goto out;
	mfilter->xmit_data_len -= rcount;
	if (mfilter->xmit_data_len == 0) {
	    mfilter->xmit_data_pos = 0;
	} else {
	    /* Partial write, can't write anything else. */
	    mfilter->xmit_data_pos += rcount;
	    goto out;
	}
    }

    /* Now look for a new channel to send. */
 check_next_channel:
    if (!gensio_list_empty(&mfilter->wrchans)) {
	gensiods pos;

	chan = gensio_container_of(gensio_list_first(&mfilter->wrchans),
				   struct mux_inst, link);
	gensio_list_rm(&mfilter->wrchans, &chan->wrlink);
	mfilter->sending_chan = chan;

	/* FIXME - add sending an ack if necessary. */
	if (chan->send_new_channel) {
	    chan_setup_send_new_channel(chan);
	    chan->send_new_channel = false;
	} else if (chan->write_data_len) {
	    chan_setup_send_data(chan);
	} else if (chan->send_close) {
	    /* Do the close last so all data is sent. */
	    chan_send_close(chan);
	    chan->send_close = false;
	} else {
	    mfilter->sending_chan = NULL;
	    chan->in_wrlist = false;
	    goto check_next_channel;
	}
	goto next_channel;
    }
 out:
    mux_unlock(mfilter);
    return err;
}

static int
mux_ll_write(struct mux_filter *mfilter,
	     gensio_ll_filter_data_handler handler, void *cb_data,
	     gensiods *rcount, unsigned char *buf, gensiods buflen,
	     const char *const *nauxdata)
{
    gensiods processed = 0, used, acked;
    int err = 0;
    struct mux_inst *chan;
    const char *auxdata[2] = { NULL, NULL };

    mux_lock(mfilter);
    while (buflen > 0) {
	if (mfilter->in_hdr) {
	    if (mfilter->hdr_pos == 0) {
		/*
		 * The first byte of the header contains what we need
		 * to process the rest of the header.
		 */
		mfilter->hdr[mfilter->hdr_pos++] = *buf;
		mfilter->hdr_size = *buf & 0xf;
		mfilter->msgid = *buf >> 4;
		if (mfilter->msgid == 0 || mfilter->msgid > MUX_MAX_MSG_NUM)
		    goto protocol_err;
		if (mux_msg_hdr_sizes[mfilter->msgid] != mfilter->hdr_size)
		    goto protocol_err;
		used = 1;
		goto more_data;
	    }	    

	    if (buflen + mfilter->hdr_pos < mfilter->hdr_size) {
		/* The header is not completely received, partial copy. */
		memcpy(mfilter->hdr + mfilter->hdr_pos, buf, buflen);
		processed += buflen;
		goto out_unlock;
	    }

	    /* We have the whole header now. */
	    used = mfilter->hdr_size - mfilter->hdr_pos;
	    memcpy(mfilter->hdr + mfilter->hdr_pos, buf, used);
	
	    if (mfilter->msgid == MUX_INIT) {
		if (mfilter->mux_initialized)
		    goto protocol_err;
		mfilter->mux_initialized = true;
		goto more_data;
	    }

	    if (!mfilter->mux_initialized)
		goto protocol_err;

	    switch (mfilter->hdr[0]) {
	    case MUX_INIT:
		break;

	    case MUX_NEW_CHANNEL:
		chan = mux_new_channel(mfilter, MUX_INST_OPEN);
		mfilter->curr_chan = chan;
		if (chan) {
		    chan->send_window_size = mux_buf_to_u32(mfilter->hdr + 4);
		    chan->remote_id = mux_buf_to_u16(mfilter->hdr + 2);
		    mfilter->data_pos = 0;
		    mfilter->in_hdr = false; /* Receive the service data */
		}
		break;

	    case MUX_NEW_CHANNEL_RSP:
		chan = mux_get_channel(mfilter);
		if (!chan)
		    goto protocol_err;
		if (chan != mfilter->sending_chan)
		    goto protocol_err;
		chan->remote_id = mux_buf_to_u16(mfilter->hdr + 8);
		chan->send_window_size = mux_buf_to_u32(mfilter->hdr + 4);
		chan->errcode = mux_buf_to_u16(mfilter->hdr + 10);
		chan->state = MUX_INST_OPEN;
		assert(mfilter->opencount > 0);
		mfilter->opencount--;
		mfilter->sending_chan = NULL;

		/* Start the next channel open, if necessary. */
		if (!gensio_list_empty(&mfilter->openchans)) {
		    struct mux_inst *next_chan =
			gensio_container_of(
				gensio_list_first(&mfilter->openchans),
				struct mux_inst, link);
		    gensio_list_rm(&mfilter->openchans, &next_chan->wrlink);
		    gensio_list_add_tail(&mfilter->wrchans, &next_chan->wrlink);
		}

		if (chan->open_done) {
		    /* FIXME - protections for mfilter below. */
		    mux_unlock(mfilter);
		    chan->open_done(chan->io, chan->errcode, chan->open_data);
		    mux_lock(mfilter);
		}
		break;

	    case MUX_CLOSE_CHANNEL:
		chan = mux_get_channel(mfilter);
		if (!chan || chan->state == MUX_INST_CLOSED ||
				chan->state == MUX_INST_IN_OPEN)
				chan->state == MUX_INST_IN_REM_CLOSE)
		    goto protocol_err;
		chan->errcode = mux_buf_to_u16(mfilter->hdr + 8);
		if (chan->state == MUX_INST_IN_CLOSE) {
		    chan->state = MUX_INST_CLOSED;
		    if (chan->read_data_len == 0 && !chan->in_wrlist)
			mux_channel_finish_close(chan);
		    /* chan could be freed after this point, be careful. */
		} else {
		    chan->state = MUX_INST_IN_REM_CLOSE;
		    chan->send_close = true;
		    if (!chan->in_wrlist) {
			gensio_list_add_tail(&mfilter->wrchans, &chan->wrlink);
			chan->in_wrlist = true;
		    }
		}
		break;
	    }

	    case MUX_DATA:
		chan = mux_get_channel(mfilter);
		if (!chan)
		    goto protocol_err;
		mfilter->curr_chan = chan;
		mfilter->data_pos = 0;
		mfilter->in_hdr = false; /* Receive the data */
		break;

	    case MUX_SHUTDOWN:
		/* FIXME - add handling. */
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
	    if (mfilter->data_pos == 0) {
		mfilter->data_size = *buf << 8;
		mfilter->data_pos++;
		used = 1;
		goto more_data;
	    }
	    chan = mfilter->curr_chan;
	    if (mfilter->data_pos == 1) {
		mfilter->data_size |= *buf;
		switch (mfilter->msgid) {
		case MUX_NEW_CHANNEL:
		    if (!chan)
			/* Channel allocation failed, just abort. */
			break;
		    if (mfilter->data_size == 0)
			goto new_chan_no_service;
		    chan->service = mfilter->o->zalloc(mfilter->o,
						       mfilter->data_size + 1);
		    if (!chan->service) {
			mfilter->curr_chan = NULL;
			mux_channel_free(chan);
			/* NULL curr_chan will cause an error to be sent. */
		    }
		    break;

		case MUX_DATA:
		    if (mfilter->data_size == 0) {
			mfilter->data_pos++;
			used = 1;
			goto handle_read_no_data;
		    }
		    if (chan_rdbufleft(chan) < mfilter->data_size + 3)
			goto protocol_err;
		    /* Add the message flags first. */
		    chan_addrdbyte(chan, mfilter->hdr[1]);
		    chan_addrdbyte(chan, mfilter->data_size >> 8);
		    chan_addrdbyte(chan, mfilter->data_size & 0xff);
		    break;

		default:
		    abort();
		}
		mfilter->data_pos++;
		used = 1;
		goto more_data;
	    }

	    /* Receiving message data. */
	    switch (mfilter->msgid) {
	    case MUX_NEW_CHANNEL:
		if (buflen + mfilter->data_pos - 2 < mfilter->data_size) {
		    /* Not enough data for service yet. */
		    if (chan)
			memcpy(chan->service + mfilter->data_pos - 2,
			       buf, buflen);
		    mfilter->data_pos += buflen;
		    processed += buflen;
		    goto out_unlock;
		}
		used = mfilter->data_size + 2 - mfilter->data_pos;
		if (chan) {
		    memcpy(chan->service + mfilter->data_pos, buf, used);
		} else {
		    err = GE_NOMEM;
		    goto new_chan_err;
		}
	    new_chan_no_service:
		mux_unlock(mfilter);
		if (chan->service)
		    auxdata[0] = chan->service;
		else
		    auxdata[0] = "";
		err = gensio_filter_do_event(mfilter->filter,
					     GENSIO_EVENT_NEW_CHANNEL, 0,
					     (void *) chan->io, 0, auxdata);
		mux_lock(mfilter);
		if (err) {
		new_chan_err:
		    if (mfilter->xmit_data_len)
			/* Only one new channel allowed at a time. */
			goto protocol_err;
		    mux_send_new_channel_rsp(mfilter,
					     mux_buf_to_u16(mfilter->hdr + 2),
					     0, 0, err);
		    if (chan)
			mux_channel_free(chan);
		} else {
		    if (mfilter->xmit_data_len)
			goto protocol_err;
		    mux_send_new_channel_rsp(mfilter, chan->remote_id,
					     chan->read_data_len,
					     chan->id, 0);
		}
		mfilter->in_hdr = true;
		goto more_data;

	    case MUX_DATA:
		if (buflen + mfilter->data_pos - 2 < mfilter->data_size) {
		    /* Not all data received yet. */
		    chan_addrdbuf(chan, buf, buflen);
		    processed += buflen;
		    goto out_unlock;
		}
		used = mfilter->data_size + 2 - mfilter->data_pos;
		chan_addrdbuf(chan, buf, used);

	    handle_read_no_data:
		acked = mux_buf_to_u32(mfilter->hdr + 4);
		if (acked) {
		    if (acked > chan->sent_unacked)
			goto protocol_err;
		    chan->sent_unacked -= acked;
		    chan_check_send_more(chan);
		}
		if (mfilter->data_size)
		    chan_check_read(chan);
		/* chan_check_read() can free chan, be careful. */
		mfilter->in_hdr = true;
		goto more_data;

	    default:
		abort();
	    }
	}
    }

 out_unlock:
    mux_unlock(mfilter);

    if (!err)
	*rcount = processed;
    return err;

 protocol_err:
    /* FIXME */
    return -1;
}

static int
mux_setup(struct mux_filter *mfilter, struct gensio *io)
{
    return 0;
}

static void
mux_cleanup(struct mux_filter *mfilter)
{
    /* FIXME - is this all? */
    mfilter->xmit_data_pos = 0;
    mfilter->xmit_data_len = 0;
    mfilter->hdr_pos = 0;
    mfilter->hdr_size = 0;
}

static void
mfilter_free(struct mux_filter *mfilter)
{
    /* FIXME - free everything. */
    if (mfilter->lock)
	mfilter->o->free_lock(mfilter->lock);
    if (mfilter->filter)
	gensio_filter_free_data(mfilter->filter);
    mfilter->o->free(mfilter->o, mfilter);
}

static void
mux_free(struct mux_filter *mfilter)
{
    /* FIXME - close if necessary. */
    return mfilter_free(mfilter);
}

static int
mux_filter_control(struct mux_filter *mfilter, bool get, int op, char *data,
		   gensiods *datalen)
{
    switch (op) {
    default:
	return GE_NOTSUP;
    }
}

/* Channel 0 comes through the main interface. */
static int mux_chan0_cb(struct gensio *io, void *user_data, int event,
			int err, unsigned char *buf, gensiods *buflen,
			const char *const *auxdata)
{
    struct mux_filter *mfilter = user_data;

    return gensio_filter_do_event(mfilter->filter, event, err,
				  buf, buflen, auxdata);
}

static int
mux_filter_open_channel(struct mux_filter *mfilter,
			const char * const *args,
			gensio_event cb,
			void *user_data,
			gensio_done_err open_done,
			void *open_data,
			enum mux_inst_state state)
{
    struct mux_inst *chan = NULL;
    int err = 0;
    unsigned int len = 0;

    mux_lock(mfilter);
    chan = mux_new_channel(mfilter, state);
    if (!chan) {
	err = GE_NOMEM;
	goto out;
    }

    if (args && args[0]) {
	len = strlen(args[0]);
	if (len > 65536 || len > chan->max_write_size - 10) {
	    err = GE_TOOBIG;
	    goto out;
	}
	if (len) {
	    chan->service = malloc(len);
	    if (!chan->service) {
		err = GE_NOMEM;
		goto out;
	    }
	    memcpy(&chan->service, args[0], len);
	}
    }

    chan->cb = cb;
    chan->user_data = user_data;
    chan->open_done = open_done;
    chan->open_data = open_data;
    chan->send_new_channel = true;

    if (state == MUX_INST_IN_OPEN) {
	/* Only one open at a time is allowed, queue them otherwise. */
	if (mfilter->opencount == 0)
	    gensio_list_add_tail(&mfilter->wrchans, &chan->wrlink);
	else
	    gensio_list_add_tail(&mfilter->openchans, &chan->wrlink);
	mfilter->opencount++;
    }
    return 0;

 out:
    mux_unlock(mfilter);
    if (chan)
	mux_channel_free(chan);
    return err;
}

static int gensio_mux_filter_func(struct gensio_filter *filter, int op,
				  const void *func, void *data,
				  gensiods *count,
				  void *buf, const void *cbuf,
				  gensiods buflen,
				  const char *const *auxdata)
{
    struct mux_filter *mfilter = filter_to_mux(filter);

    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	mux_set_callbacks(mfilter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return mux_ul_read_pending(mfilter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return mux_ll_write_pending(mfilter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return mux_ll_read_needed(mfilter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return mux_check_open_done(mfilter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return mux_try_connect(mfilter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return mux_try_disconnect(mfilter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return mux_ul_write(mfilter, func, data, count, cbuf, buflen, buf);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return mux_ll_write(mfilter, func, data, count, buf, buflen, NULL);

    case GENSIO_FILTER_FUNC_SETUP:
	return mux_setup(mfilter, data);

    case GENSIO_FILTER_FUNC_CLEANUP:
	mux_cleanup(mfilter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	mux_free(mfilter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return mux_filter_control(mfilter, *((bool *) cbuf), buflen, data,
				  count);

    case GENSIO_FILTER_FUNC_OPEN_CHANNEL:
    {
	struct gensio_func_open_channel_data *odata = data;
	return mux_filter_open_channel(mfilter,
				       odata->args, odata->cb, odata->user_data,
				       odata->open_done, odata->open_data,
				       MUX_INST_IN_OPEN);
    }

    case GENSIO_FILTER_FUNC_TIMEOUT:
    default:
	return GE_NOTSUP;
    }
}

int
gensio_mux_filter_config(struct gensio_os_funcs *o,
			 const char * const args[],
			 bool default_is_client,
			 struct gensio_mux_filter_data **rdata)
{
    unsigned int i;
    struct gensio_mux_filter_data *data = o->zalloc(o, sizeof(*data));
    int rv = GE_NOMEM, ival;
    const char *str;
    const char *cstr;

    if (!data)
	return GE_NOMEM;
    data->o = o;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &data->max_read_size) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "writebuf", &data->max_write_size) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "service", &str) > 0) {
	    data->service = gensio_strdup(o, str);
	    if (!data->service)
		goto out_err;
	    continue;
	}
	rv = GE_INVAL;
	goto out_err;
    }

    *rdata = data;

    return 0;
 out_err:
    o->free(o, data);
    return rv;
}

void
gensio_mux_filter_config_free(struct gensio_mux_filter_data *data)
{
    struct gensio_os_funcs *o;

    if (!data)
	return;

    o = data->o;
    if (data->service)
	o->free(o, data->service);
    o->free(o, data);
}

int
gensio_mux_filter_alloc(struct gensio_mux_filter_data *data,
			struct gensio_filter **rfilter)
{
    struct gensio_os_funcs *o = data->o;
    struct gensio_filter *filter;
    struct mux_filter *mfilter;
    int rv;
    const char *args[2];

    mfilter = o->zalloc(o, sizeof(*mfilter));
    if (!mfilter)
	return GE_NOMEM;

    mfilter->max_write_size = data->max_write_size;
    mfilter->max_read_size = data->max_read_size;
    mfilter->lock = o->alloc_lock(o);
    if (!mfilter->lock)
	goto out_nomem;

    /* Allocate channel 0. */
    args[0] = data->service;
    args[1] = NULL;
    rv = mux_filter_open_channel(mfilter, args, mux_chan0_cb, mfilter,
				 NULL, NULL, MUX_INST_OPEN);
    if (rv)
	goto out_nomem;

    mfilter->filter = gensio_filter_alloc_data(o, gensio_mux_filter_func,
					       mfilter);
    if (!mfilter->filter)
	goto out_nomem;

    *rfilter = mfilter->filter;
    return 0;

 out_nomem:
    if (!gensio_list_empty(&mfilter->chans))
	mux_channel_finish(gensio_container_of(
				gensio_list_first(&mfilter->openchans),
				struct mux_inst, link));
    if (mfilter->lock)
	o->free_lock(mfilter->lock);
    o->free(o, mfilter);
    return GE_NOMEM;
}
