/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>

#include "gensio_filter_relpkt.h"
#if 0
#define DEBUG_MSG 1
#define ENABLE_PRBUF 1
#endif
#if 0
#define DROP_NR	8
unsigned int curr_drop;
#endif
#include "utils.h"

enum relpkt_msgs {
    /*
     * Request a connection be established.
     *
     * +----------------+----------------+----------------+
     * |   1   |reserv|A|    version     |  recv window   |
     * +----------------+----------------+----------------+
     * +----------------+----------------+
     * | pktlen msb     |    pktlen lsb  |
     * +----------------+----------------+
     * A - response bit, 1 if a response, 0 if not.
     */
    RELPKT_MSG_INIT = 1,

    /*
     * Send some data.  If there is no data after the header, msg seq
     * is ignore and this is only an ack.
     *
     * +----------------+----------------+----------------+
     * |   2   |reserv|A| next expected  |  msg seq       |
     * +----------------+----------------+----------------+
     * A - eom bit, if 1 end of message, if 0 not.
     */
    RELPKT_MSG_DATA = 2,

    /*
     * Request resending data from starting at the first sequence
     * number up to and including the last sequence number.
     * Data after the header is more resend requests in pairs.
     *
     * +----------------+----------------+----------------+
     * |   3   |reserved|first seq resend|last seq resend |
     * +----------------+----------------+----------------+
     */
    RELPKT_MSG_RESEND = 3,

    /*
     * Request that the connection be closed.
     *
     * +----------------+----------------+----------------+
     * |   4   |reserved|   error msb    |   error lsb    |
     * +----------------+----------------+----------------+
     */
    RELPKT_MSG_CLOSE = 4
};

enum relpkt_state {
    /*
     * relpkt is not operational.
     *
     * init =>
     *   send close
     *
     * open() =>
     *   if (server)
     *     state = RELPKT_WAITING_INIT
     *   else
     *     send init
     *     state = RELPKT_WAITING_INIT_RSP
     *     start timer
     */
    RELPKT_CLOSED = 0,

    /*
     * relpkt is waiting to receive an init message.  For the
     * server.
     *
     * init =>
     *   if (!response)
     *     send init rsp
     *     state = RELPKT_OPEN
     *     start timer
     *
     * data =>
     * data resend =>
     * close =>
     * timeout =>
     *
     * close() =>
     *   state = RELPKT_CLOSED
     */
    RELPKT_WAITING_INIT,

    /*
     * relpkt has sent an init and is waiting a response.  client only.
     *
     * init =>
     *   if (response)
     *     state = RELPKT_OPEN
     *
     * data =>
     * data resend =>
     *
     * close =>
     *    state = RELPKT_CLOSED
     *
     * timeout =>
     *    if (retries >= max_retries)
     *      state = RELPKT_CLOSED
     *      report open fail
     *    else
     *      resend init
     *
     * close() =>
     *   send close
     *   state = RELPKT_CLOSED
     */
    RELPKT_WAITING_INIT_RSP,

    /*
     * init =>
     *   if !response
     *     send init rsp
     *     reschedule any sent data
     *
     * data =>
     *   handle ack
     *   reset autoclose timeout
     *   deliver data to user
     *
     * data resend =>
     *   resend requested packet
     *
     * close =>
     *   state = RELPKT_REMCLOSED
     *   send close
     *
     * timeout =>
     *   if (autoclose timeout exceeded)
     *     send close
     *     state = RELPKT_REMCLOSED
     *
     * close() =>
     *   if (data to send)
     *     state = RELPKT_WAITING_CLOSE_CLEAR
     *   else
     *     send close
     *     state = RELPKT_WAITING_CLOSE_RSP
     */
    RELPKT_OPEN,

    /*
     * A local close has been requested, waiting for the transmit
     * queue to clear.
     *
     * init =>
     *   if !response
     *     send init rsp
     *     reschedule any sent data
     *
     * data =>
     *   handle ack
     *   if last sent packet acked
     *     send close
     *     if close msg received
     *       state = RELPKT_CLOSED
     *     else
     *       state = RELPKT_WAITING_CLOSE_RSP
     *   reset autoclose timeout
     *
     * data resend =>
     *   resend requested packet(s)
     *
     * close =>
     *   state = RELPKT_CLOSED
     *   report close done
     *
     * close() =>
     *
     * timeout =>
     *   if (autoclose timeout exceeded)
     *     send close
     *     state = RELPKT_CLOSED
     *
     */
    RELPKT_WAITING_CLOSE_CLEAR,

    /*
     * We sent a close, waiting for a close response.
     *
     * init =>
     *   send close
     *
     * data =>
     * data resend =>
     * close =>
     *   state = RELPKT_CLOSED
     *   report close done
     *
     * close() =>
     *
     * timeout =>
     *   if (autoclose timeout exceeded)
     *     send close
     *     state = RELPKT_CLOSED
     */
    RELPKT_WAITING_CLOSE_RSP,

    /*
     * The remote side requested a close.
     *
     * init =>
     *   send close
     *
     * data =>
     * data resend =>
     * close =>
     *
     * close() =>
     *   state = REMPKT_CLOSED
     *   report close done
     */
    RELPKT_REMCLOSED
};

struct pkt {
    uint16_t len;

    uint16_t start; /* For partial acceptance by user */

    bool sent; /* If true, packet does not need to be sent. */

    bool ready; /* If true, packet is ready to deliver to the user. */
    bool eom; /* If true, report end of message. */

    unsigned char *data;
};

struct relpkt_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    enum relpkt_state state;

    int err;

    bool server; /* True if server mode. */

    gensiods max_pktsize;
    unsigned int max_pkt; /* Our set value. */

    uint8_t next_expected_seq; /* Next seq we expect from the remote. */
    uint8_t next_deliver_seq; /* Next seq we will deliver to the user. */
    uint8_t deliver_recvpkt; /* Pos in recvpkts of next_deliver_seq. */
    struct pkt *recvpkts;

    /*
     * The other end is supposed to send an ack or data at least once
     * a second, keep track of how long since we've seen one to know
     * if the other end went belly up.
     */
    unsigned int timeouts_since_ack;
    bool send_since_timeout;

    unsigned int max_xmit_pktsize;
    unsigned int max_xmitpkt; /* Set from remote end by init packet. */
    uint8_t next_acked_seq; /* Seq for next packet that is unacked. */
    uint8_t next_send_seq; /* Seq for next packet we will send. */
    uint8_t first_xmitpkt; /* Pos in xmitpkts of where next_ack_seq is. */
    struct pkt *xmitpkts;
    unsigned int nr_waiting_xmitpkt; /* nr in xmitpkt unsent */

    char init_pkt[5];
    bool send_init_pkt;
    unsigned int init_retry_count;

    char close_pkt[3];
    bool send_close_pkt;
    unsigned int close_retry_count;

    char ack_pkt[3];
    bool send_ack_pkt;

    char resend_pkt[51];
    bool send_resend_pkt;
    uint16_t resend_pkt_len;

    uint8_t last_timeout_ack; /* next_acked_seq on the last timeout. */
    unsigned int timeout_ack_count; /* nr timeouts last_timeout_ack same. */
};

#define filter_to_relpkt(v) ((struct relpkt_filter *) \
			     gensio_filter_get_user_data(v))
#define link_to_pkt(v) gensio_container_of(v, struct pkt, link);

static int i_relpkt_filter_timeout(struct relpkt_filter *rfilter);

static void
relpkt_lock(struct relpkt_filter *rfilter)
{
    rfilter->o->lock(rfilter->lock);
}

static void
relpkt_unlock(struct relpkt_filter *rfilter)
{
    rfilter->o->unlock(rfilter->lock);
}

/*
 * Returns true if seq >= first and seq < next, taking into account
 * wrapping.  If first == next, this will always return false.
 */
static bool
seq_inside(uint8_t seq, uint8_t first, uint8_t next)
{
    if (first <= next)
	/* not wrapped */
	return seq >= first && seq < next;
    else
	/* wrapped */
	return seq >= first || seq < next;
}

static uint8_t
recvpkt_pos(struct relpkt_filter *rfilter, uint8_t pos)
{
    return (rfilter->deliver_recvpkt + pos) % rfilter->max_pkt;
}

static uint8_t
xmitpkt_pos(struct relpkt_filter *rfilter, uint8_t pos)
{
    return (rfilter->first_xmitpkt + pos) % rfilter->max_xmitpkt;
}

static void
resend_packets(struct relpkt_filter *rfilter, uint8_t first, uint8_t last)
{
    uint8_t seq;
    unsigned int i, pos;

    for (seq = first, i = first - rfilter->next_acked_seq; seq != last; i++) {
	pos = xmitpkt_pos(rfilter, i);
	if (rfilter->xmitpkts[pos].sent) {
	    rfilter->xmitpkts[pos].sent = false;
	    rfilter->nr_waiting_xmitpkt++;
	}
	seq++;
    }
}

static struct pkt *
first_xmitpkt_to_send(struct relpkt_filter *rfilter)
{
    uint8_t seq = rfilter->next_acked_seq;
    unsigned int i, pos;

    for (i = 0; seq != rfilter->next_send_seq; i++, seq++) {
	pos = xmitpkt_pos(rfilter, i);
	if (!rfilter->xmitpkts[pos].sent)
	    return &(rfilter->xmitpkts[pos]);
    }
    assert(0);
    return NULL;
}

static void
send_init(struct relpkt_filter *rfilter, bool response)
{
    rfilter->init_pkt[0] = (RELPKT_MSG_INIT << 4) | (uint8_t) response;
    rfilter->init_pkt[1] = 0; /* version */
    rfilter->init_pkt[2] = rfilter->max_pkt;
    rfilter->init_pkt[3] = rfilter->max_pktsize >> 8;
    rfilter->init_pkt[4] = rfilter->max_pktsize & 0xff;
    rfilter->send_init_pkt = true;
}

static void
send_close(struct relpkt_filter *rfilter)
{
    rfilter->close_pkt[0] = RELPKT_MSG_CLOSE << 4;
    rfilter->close_pkt[1] = 0;
    rfilter->close_pkt[2] = 0;
    rfilter->send_close_pkt = true;
}

static void
send_ack(struct relpkt_filter *rfilter)
{
    rfilter->ack_pkt[0] = RELPKT_MSG_DATA << 4;
    /* seq will be filled in at send time. */
    rfilter->ack_pkt[2] = 0;
    rfilter->send_ack_pkt = true;
}

static void
request_resend(struct relpkt_filter *rfilter, uint8_t first, uint8_t last)
{
    if (!rfilter->send_resend_pkt) {
	rfilter->resend_pkt_len = 1;
	rfilter->resend_pkt[0] = RELPKT_MSG_RESEND << 4;
	rfilter->send_resend_pkt = true;
    }
    if (rfilter->resend_pkt_len + 1 >= sizeof(rfilter->resend_pkt))
	return; /* No space left, let transmit timeout get it. */
    rfilter->resend_pkt[rfilter->resend_pkt_len++] = first;
    rfilter->resend_pkt[rfilter->resend_pkt_len++] = last;
    rfilter->timeout_ack_count = 0;
}

/* Returns true on a protocol error. */
static bool
handle_ack(struct relpkt_filter *rfilter, uint8_t seq)
{
    unsigned int pos;

    /*
     * The last received message on the other end is in seq, but we
     * keep the next thing that should be acked, thus the +1.
     */
    if (!seq_inside(seq, rfilter->next_acked_seq,
		    rfilter->next_send_seq + 1))
	return true;
    while (rfilter->next_acked_seq != seq) {
	pos = rfilter->first_xmitpkt;
	if (!rfilter->xmitpkts[pos].sent) {
	    /*
	     * Packets wasn't sent yet, but we got an ack.  Could
	     * happen on a retransmit or some other error.  Just act
	     * like it was transmitted.
	     */
	    rfilter->xmitpkts[pos].sent = true;
	    assert(rfilter->nr_waiting_xmitpkt > 0);
	    rfilter->nr_waiting_xmitpkt--;
	}
	rfilter->first_xmitpkt = xmitpkt_pos(rfilter, 1);
	rfilter->next_acked_seq++;
    }
    rfilter->timeouts_since_ack = 0;

    return false;
}

static void
relpkt_filter_start_timer(struct relpkt_filter *rfilter)
{
    gensio_time timeout = { 1, 0 };

    rfilter->filter_cb(rfilter->filter_cb_data,
		       GENSIO_FILTER_CB_START_TIMER, &timeout);
}

static void
relpkt_set_callbacks(struct relpkt_filter *rfilter,
		     gensio_filter_cb cb, void *cb_data)
{
    rfilter->filter_cb = cb;
    rfilter->filter_cb_data = cb_data;
}

static bool
relpkt_ul_read_pending(struct relpkt_filter *rfilter)
{
    struct pkt *p = &(rfilter->recvpkts[rfilter->deliver_recvpkt]);

    return p->ready;
}

static bool
relpkt_ll_write_pending(struct relpkt_filter *rfilter)
{
    return rfilter->nr_waiting_xmitpkt || rfilter->send_init_pkt ||
	rfilter->send_close_pkt || rfilter->send_resend_pkt ||
	rfilter->send_ack_pkt;
}

static bool
relpkt_ul_can_write(struct relpkt_filter *rfilter, bool *rv)
{
    unsigned int nrqueued = rfilter->next_send_seq - rfilter->next_acked_seq;

    *rv = nrqueued < rfilter->max_xmitpkt;
    return 0;
}

static bool
relpkt_ll_write_queued(struct relpkt_filter *rfilter, bool *rv)
{
    unsigned int nrqueued = rfilter->next_send_seq - rfilter->next_acked_seq;

    *rv = nrqueued > 0;
    return 0;
}

static bool
relpkt_ll_read_needed(struct relpkt_filter *rfilter)
{
    /* We can always take data.  Flow control should keep us from overrunning */
    return true;
}

static int
relpkt_check_open_done(struct relpkt_filter *rfilter, struct gensio *io)
{
    gensio_set_is_packet(io, true);
    gensio_set_is_message(io, true);
    gensio_set_is_reliable(io, true);
    return 0;
}

static int
relpkt_try_connect(struct relpkt_filter *rfilter, gensio_time *timeout,
		   bool was_timeout)
{
    int rv = 0;

    relpkt_lock(rfilter);
    switch (rfilter->state) {
    case RELPKT_WAITING_INIT_RSP:
	if (was_timeout) {
	    rfilter->init_retry_count++;
	    if (rfilter->init_retry_count > 5) {
		rv = GE_TIMEDOUT;
	    } else {
		send_init(rfilter, false);
		timeout->secs = 1;
		timeout->nsecs = 0;
		rv = GE_RETRY;
	    }
	} else {
	    rv = GE_INPROGRESS;
	}
	break;

    case RELPKT_CLOSED:
	if (rfilter->server) {
	    rfilter->state = RELPKT_WAITING_INIT;
	    rv = GE_INPROGRESS;
	} else {
	    rfilter->state = RELPKT_WAITING_INIT_RSP;
	    send_init(rfilter, false);
	    timeout->secs = 1;
	    timeout->nsecs = 0;
	    rv = GE_RETRY;
	}
	break;

    case RELPKT_WAITING_INIT:
	rv = GE_INPROGRESS;
	break;

    case RELPKT_REMCLOSED:
	rv = GE_REMCLOSE;
	break;

    case RELPKT_OPEN:
	break;

    case RELPKT_WAITING_CLOSE_CLEAR:
    case RELPKT_WAITING_CLOSE_RSP:
	rv = GE_NOTREADY;
	break;

    default:
	assert(0);
    }
    relpkt_unlock(rfilter);

    return rv;
}

static int
relpkt_try_disconnect(struct relpkt_filter *rfilter, gensio_time *timeout,
		      bool was_timeout)
{
    int rv = 0;

    relpkt_lock(rfilter);
    switch (rfilter->state) {
    case RELPKT_WAITING_INIT:
	break;

    case RELPKT_CLOSED:
    case RELPKT_REMCLOSED:
	if (!rfilter->send_close_pkt)
	    /* Close packet has been sent. */
	    break;
	if (was_timeout) {
	    i_relpkt_filter_timeout(rfilter);
	    timeout->secs = 1;
	    timeout->nsecs = 0;
	    rv = GE_RETRY;
	} else {
	    rv = GE_INPROGRESS;
	}
	break;

    case RELPKT_OPEN:
	if (rfilter->next_acked_seq == rfilter->next_send_seq) {
	    /* Nothing left to send, start the close process. */
	    rfilter->state = RELPKT_WAITING_CLOSE_RSP;
	    send_close(rfilter);
	} else {
	    /* Wait for output to clear. */
	    rfilter->state = RELPKT_WAITING_CLOSE_CLEAR;
	}
	timeout->secs = 1;
	timeout->nsecs = 0;
	rv = GE_RETRY;
	break;

    case RELPKT_WAITING_CLOSE_CLEAR:
	/*
	 * Normal timeouts will no longer happen, make sure to continue
	 * timing here.
	 */
	if (rfilter->err) {
	    rv = rfilter->err;
	} else {
	    if (rfilter->next_acked_seq == rfilter->next_send_seq) {
		rfilter->state = RELPKT_WAITING_CLOSE_RSP;
		send_close(rfilter);
	    }
	    if (was_timeout) {
		i_relpkt_filter_timeout(rfilter);
		timeout->secs = 1;
		timeout->nsecs = 0;
		rv = GE_RETRY;
	    } else {
		rv = GE_INPROGRESS;
	    }
	}
	break;

    case RELPKT_WAITING_CLOSE_RSP:
	if (was_timeout) {
	    rfilter->close_retry_count++;
	    if (rfilter->close_retry_count > 5) {
		rv = GE_TIMEDOUT;
	    } else {
		timeout->secs = 1;
		timeout->nsecs = 0;
		rv = GE_RETRY;
	    }
	} else {
	    rv = GE_INPROGRESS;
	}
	break;

    case RELPKT_WAITING_INIT_RSP: /* Should not happen. */
    default:
	assert(0);
    }
    relpkt_unlock(rfilter);

    return rv;
}

static int
relpkt_ul_write(struct relpkt_filter *rfilter,
		gensio_ul_filter_data_handler handler, void *cb_data,
		gensiods *rcount,
		const struct gensio_sg *sg, gensiods sglen,
		const char *const *auxdata)
{
    struct gensio_sg rsg = { NULL, 0 };
    struct pkt *p = NULL;
    unsigned int nrqueued;
    int err = 0;
    bool *endbool = NULL;
    bool finish_close = false;

    relpkt_lock(rfilter);
    nrqueued = rfilter->next_send_seq - rfilter->next_acked_seq;
    if (sglen == 0 || nrqueued >= rfilter->max_xmitpkt) {
	if (rcount)
	    *rcount = 0;
    } else {
	gensiods i, writelen = 0;
	bool trunc = false;
	unsigned int pos = xmitpkt_pos(rfilter, nrqueued);
	struct pkt *p = &(rfilter->xmitpkts[pos]);

	/* FIXME - if previous packet is not full and not eom, can append */
	p->len = 0;
	for (i = 0; i < sglen; i++) {
	    gensiods inlen = sg[i].buflen;
	    const unsigned char *buf = sg[i].buf;

	    if (inlen + p->len > rfilter->max_xmit_pktsize) {
		inlen = rfilter->max_xmit_pktsize - p->len;
		trunc = true;
	    }
	    memcpy(p->data + p->len + 3, buf, inlen);
	    writelen += inlen;
	    p->len += inlen;
	    if (p->len == rfilter->max_xmit_pktsize)
		break;
	}
	if (rcount)
	    *rcount = writelen;

	if (writelen > 0) {
	    if (!trunc && gensio_str_in_auxdata(auxdata, "eom"))
		p->eom = true;
	    p->data[0] = (RELPKT_MSG_DATA << 4) | (uint8_t) p->eom;
	    /* Ack (byte 1) will be filled in on transmit. */
	    p->data[2] = rfilter->next_send_seq;
	    rfilter->next_send_seq++;
	    p->sent = false;
	    p->len += 3; /* For the header. */
	    rfilter->nr_waiting_xmitpkt++;
	}
    }

    p = NULL;
    if (rfilter->send_init_pkt) {
	rsg.buf = rfilter->init_pkt;
	rsg.buflen = 5;
	endbool = &rfilter->send_init_pkt;
    } else if (rfilter->nr_waiting_xmitpkt) {
	p = first_xmitpkt_to_send(rfilter);
	rsg.buf = p->data;
	rsg.buflen = p->len;
	p->data[1] = rfilter->next_deliver_seq; /* Add the ack */
	rfilter->send_ack_pkt = false;
    } else if (rfilter->send_resend_pkt) {
	rsg.buf = rfilter->resend_pkt;
	rsg.buflen = rfilter->resend_pkt_len;
	endbool = &rfilter->send_resend_pkt;
    } else if (rfilter->send_ack_pkt) {
	rfilter->ack_pkt[1] = rfilter->next_deliver_seq;
	rsg.buf = rfilter->ack_pkt;
	rsg.buflen = 3;
	endbool = &rfilter->send_ack_pkt;
    } else if (rfilter->send_close_pkt) {
	rsg.buf = rfilter->close_pkt;
	rsg.buflen = 3;
	endbool = &rfilter->send_close_pkt;
	if (rfilter->state == RELPKT_REMCLOSED)
	    finish_close = true;
    }

    if (rsg.buflen) {
	gensiods count;

#ifdef DEBUG_MSG
	printf("Writing(%p):", rfilter);
	prbuf(rsg.buf, rsg.buflen);
#endif
#ifdef DROP_NR
	if (p && curr_drop % DROP_NR == 0) {
	    err = 0;
	    count = rsg.buflen;
	} else
#endif
	    err = handler(cb_data, &count, &rsg, 1, NULL);

#ifdef DROP_NR
	if (p)
	    curr_drop++;
#endif
	if (!err) {
	    if (count != 0 && count != rsg.buflen) {
		/*
		 * Is this right?  Lower layer should take whole packets
		 * or nothing.
		 */
		err = GE_TOOBIG;
	    } else if (count != 0) {
		if (p) {
		    p->sent = true;
		    assert(rfilter->nr_waiting_xmitpkt);
		    rfilter->nr_waiting_xmitpkt--;
		    rfilter->send_since_timeout = true;
		} else {
		    if (endbool)
			*endbool = false;
		    if (finish_close) {
			rfilter->err = GE_REMCLOSE;
			err = GE_REMCLOSE;
		    }
		}
	    }
	}
    }
    relpkt_unlock(rfilter);

    return err;
}

static int
relpkt_ll_write(struct relpkt_filter *rfilter,
		gensio_ll_filter_data_handler handler, void *cb_data,
		gensiods *rcount,
		unsigned char *buf, gensiods buflen,
		const char *const *auxdata)
{
    int err = 0;
    static const char *eomaux[2] = { "eom", NULL };
    bool response;
    uint8_t seq, endseq, pos, ppos;
    unsigned int i;
    struct pkt *p;
    const char *proto_err_str = NULL;

#ifdef DEBUG_MSG
    if (buflen) {
	printf("Read(%p):", rfilter);
	prbuf(buf, buflen);
    }
#endif

    relpkt_lock(rfilter);
    if (rfilter->err) {
	err = rfilter->err;
	goto out_unlock;
    }
    if (buflen == 0) {
	if (rcount)
	    *rcount = 0;
	goto deliver_recv;
    }
    if (buflen < 3) {
	proto_err_str = "buflen < 3";
	goto protocol_err;
    }

    if (rcount)
	*rcount = buflen;

    switch (buf[0] >> 4) {
    case RELPKT_MSG_INIT:
	if (buflen < 5) {
	    proto_err_str = "buflen < 5";
	    goto protocol_err;
	}
	response = buf[0] & 1;
	switch (rfilter->state) {
	case RELPKT_CLOSED:
	case RELPKT_WAITING_CLOSE_RSP:
	case RELPKT_REMCLOSED:
	    send_close(rfilter);
	    break;

	case RELPKT_WAITING_INIT:
	    if (!response) {
		rfilter->max_xmitpkt = buf[2];
		if (rfilter->max_xmitpkt == 0) {
		    proto_err_str = "rfilter->max_xmitpkt == 0";
		    goto protocol_err;
		}
		if (rfilter->max_xmitpkt > rfilter->max_pkt)
		    rfilter->max_xmitpkt = rfilter->max_pkt;
		rfilter->max_xmit_pktsize = buf[3] << 8 | buf[4];
		if (rfilter->max_xmit_pktsize > rfilter->max_pktsize)
		    rfilter->max_xmit_pktsize = rfilter->max_pktsize;
		send_init(rfilter, true);
		rfilter->state = RELPKT_OPEN;
		relpkt_filter_start_timer(rfilter);
	    }
	    break;

	case RELPKT_WAITING_INIT_RSP:
	    if (response) {
		rfilter->max_xmitpkt = buf[2];
		if (rfilter->max_xmitpkt > rfilter->max_pkt)
		    rfilter->max_xmitpkt = rfilter->max_pkt;
		rfilter->max_xmit_pktsize = buf[3] << 8 | buf[4];
		if (rfilter->max_xmit_pktsize > rfilter->max_pktsize)
		    rfilter->max_xmit_pktsize = rfilter->max_pktsize;
		rfilter->state = RELPKT_OPEN;
		relpkt_filter_start_timer(rfilter);
	    }
	    break;

	case RELPKT_OPEN:
	case RELPKT_WAITING_CLOSE_CLEAR:
	    if (!response) {
		send_init(rfilter, true);
		resend_packets(rfilter, rfilter->next_acked_seq,
			       rfilter->next_send_seq);
	    }
	    break;

	default:
	    assert(0);
	}
	break;

    case RELPKT_MSG_DATA:
	switch (rfilter->state) {
	case RELPKT_CLOSED:
	case RELPKT_WAITING_INIT:
	case RELPKT_WAITING_INIT_RSP:
	case RELPKT_WAITING_CLOSE_RSP:
	case RELPKT_REMCLOSED:
	    break;

	case RELPKT_OPEN:
	case RELPKT_WAITING_CLOSE_CLEAR:
	    if (buflen > rfilter->max_pktsize + 3) {
		proto_err_str = "buflen > rfilter->max_pktsize + 3";
		goto protocol_err;
	    }
	    if (handle_ack(rfilter, buf[1]))
		goto out_unlock;
	    if (rfilter->state != RELPKT_OPEN) {
		/* Only deliver data in open state */

		if (rfilter->next_acked_seq == rfilter->next_send_seq) {
		    /* No more data, we can close. */
		    rfilter->state = RELPKT_WAITING_CLOSE_RSP;
		    send_close(rfilter);
		}
		break;
	    }
	    if (buflen == 3) /* Just an ack */
		break;
	    seq = buf[2];
	    pos = seq - rfilter->next_deliver_seq;
	    if (seq - rfilter->next_deliver_seq > rfilter->max_pkt)
		break; /* Ignore it */
	    ppos = recvpkt_pos(rfilter, pos);
	    if (seq == rfilter->next_expected_seq) {
		rfilter->next_expected_seq++;
	    } else if (!seq_inside(seq, rfilter->next_deliver_seq,
				  rfilter->next_expected_seq)) {
		request_resend(rfilter, rfilter->next_expected_seq, seq - 1);
		rfilter->next_expected_seq = seq + 1;
	    }
	    p = &(rfilter->recvpkts[ppos]);
	    if (!p->ready) {
		memcpy(p->data, buf + 3, buflen - 3);
		p->len = buflen - 3;
		p->start = 0;
		p->ready = true;
		p->eom = buf[0] & 1;
	    }
	    break;

	default:
	    assert(0);
	}
	break;

    case RELPKT_MSG_RESEND:
	switch (rfilter->state) {
	case RELPKT_CLOSED:
	case RELPKT_WAITING_INIT:
	case RELPKT_WAITING_INIT_RSP:
	case RELPKT_REMCLOSED:
	    break;

	case RELPKT_OPEN:
	case RELPKT_WAITING_CLOSE_CLEAR:
	case RELPKT_WAITING_CLOSE_RSP:
	    buf++;
	    buflen--;
	    if (buflen % 2 != 0) { /* Should be pairs of sequence numbers. */
		proto_err_str = "buflen % 2 != 0";
		goto protocol_err;
	    }
	    for (i = 0; i < buflen; i += 2) {
		seq = buf[i];
		endseq = buf[i + 1];
		if (!seq_inside(seq, rfilter->next_acked_seq,
				rfilter->next_send_seq)) {
		    proto_err_str = "seq_inside A";
		    goto protocol_err;
		}
		if (!seq_inside(endseq, rfilter->next_acked_seq,
				rfilter->next_send_seq)) {
		    proto_err_str = "seq_inside B";
		    goto protocol_err;
		}
		resend_packets(rfilter, seq, endseq + 1);
	    }
	    break;

	default:
	    assert(0);
	}
	break;

    case RELPKT_MSG_CLOSE:
	switch (rfilter->state) {
	case RELPKT_CLOSED:
	case RELPKT_WAITING_INIT:
	case RELPKT_REMCLOSED:
	    break;

	case RELPKT_WAITING_INIT_RSP:
	    rfilter->state = RELPKT_CLOSED;
	    break;

	case RELPKT_OPEN:
	case RELPKT_WAITING_CLOSE_CLEAR:
	    rfilter->state = RELPKT_REMCLOSED;
	    send_close(rfilter);
	    break;

	case RELPKT_WAITING_CLOSE_RSP:
	    rfilter->state = RELPKT_CLOSED;
	    break;

	default:
	    assert(0);
	}
	break;

    default:
	proto_err_str = "pkttype";
	goto protocol_err;
    }

 deliver_recv:
    p = &(rfilter->recvpkts[rfilter->deliver_recvpkt]);
    if (p->ready) {
	gensiods count = 0;

	relpkt_unlock(rfilter);
	err = handler(cb_data, &count, p->data + p->start,
		      p->len - p->start, p->eom ? eomaux : NULL);
	relpkt_lock(rfilter);
	if (!err) {
	    if (count >= p->len - p->start) {
		p->ready = false;
		rfilter->deliver_recvpkt = recvpkt_pos(rfilter, 1);
		rfilter->next_deliver_seq++;
		send_ack(rfilter);
	    } else {
		p->start += count;
	    }
	}
    }
 out_unlock:
    relpkt_unlock(rfilter);
    return err;

 protocol_err:
    gensio_log(rfilter->o, GENSIO_LOG_ERR,
	       "relpkt: protocol error: %s", proto_err_str);
    relpkt_unlock(rfilter);
    return GE_PROTOERR;
}

static int
relpkt_setup(struct relpkt_filter *rfilter)
{
    return 0;
}

static void
relpkt_filter_cleanup(struct relpkt_filter *rfilter)
{
    unsigned int i;

    rfilter->state = RELPKT_CLOSED;
    rfilter->err = 0;
    rfilter->next_expected_seq = 0;
    rfilter->next_deliver_seq = 0;
    rfilter->deliver_recvpkt = 0;
    rfilter->timeouts_since_ack = 0;
    rfilter->next_acked_seq = 0;
    rfilter->next_send_seq = 0;
    rfilter->first_xmitpkt = 0;
    rfilter->nr_waiting_xmitpkt = 0;
    rfilter->send_init_pkt = false;
    rfilter->init_retry_count = 0;
    rfilter->send_close_pkt = false;
    rfilter->close_retry_count = 0;
    rfilter->send_resend_pkt = false;
    rfilter->send_ack_pkt = false;
    for (i = 0; i < rfilter->max_pkt; i++) {
	struct pkt *p = &rfilter->recvpkts[i];

	p->ready = false;
    }
}

static void
relpkt_free(struct relpkt_filter *rfilter)
{
    struct gensio_os_funcs *o = rfilter->o;
    gensiods i;

    if (rfilter->lock)
	o->free_lock(rfilter->lock);
    if (rfilter->recvpkts) {
	for (i = 0; i < rfilter->max_pkt; i++) {
	    if (rfilter->recvpkts[i].data)
		o->free(o, rfilter->recvpkts[i].data);
	}
	o->free(o, rfilter->recvpkts);
    }
    if (rfilter->xmitpkts) {
	/* Yes, the below is max_pkt for xmit.  That's the array size. */
	for (i = 0; i < rfilter->max_pkt; i++) {
	    if (rfilter->xmitpkts[i].data)
		o->free(o, rfilter->xmitpkts[i].data);
	}
	o->free(o, rfilter->xmitpkts);
    }
    if (rfilter->filter)
	gensio_filter_free_data(rfilter->filter);
    rfilter->o->free(rfilter->o, rfilter);
}

static int
i_relpkt_filter_timeout(struct relpkt_filter *rfilter)
{
    rfilter->timeouts_since_ack++;
    if (rfilter->timeouts_since_ack > 5) {
	rfilter->err = GE_TIMEDOUT;
	return GE_TIMEDOUT;
    }

    if (rfilter->send_since_timeout)
	rfilter->send_since_timeout = false;
    else
	send_ack(rfilter);

    if (rfilter->next_acked_seq != rfilter->next_send_seq) {
	if (rfilter->next_acked_seq == rfilter->last_timeout_ack) {
	    rfilter->timeout_ack_count++;
	    if (rfilter->timeout_ack_count > 1) {
		/*
		 * We haven't received an ack for something we sent.
		 * The packet must have been dropped.  Resend.
		 */
		resend_packets(rfilter, rfilter->next_acked_seq,
			       rfilter->next_send_seq);
		rfilter->timeout_ack_count = 0;
	    }
	} else {
	    rfilter->timeout_ack_count = 0;
	    rfilter->last_timeout_ack = rfilter->next_acked_seq;
	}
    }
    relpkt_filter_start_timer(rfilter);
    return 0;
}

static int
relpkt_filter_timeout(struct relpkt_filter *rfilter)
{
    int err;

    relpkt_lock(rfilter);
    err = i_relpkt_filter_timeout(rfilter);
    relpkt_unlock(rfilter);
    return err;
}

static int gensio_relpkt_filter_func(struct gensio_filter *filter, int op,
				     void *func, void *data,
				     gensiods *count,
				     void *buf, const void *cbuf,
				     gensiods buflen,
				     const char *const *auxdata)
{
    struct relpkt_filter *rfilter = filter_to_relpkt(filter);

    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	relpkt_set_callbacks(rfilter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return relpkt_ul_read_pending(rfilter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return relpkt_ll_write_pending(rfilter);

    case GENSIO_FILTER_FUNC_UL_CAN_WRITE:
	return relpkt_ul_can_write(rfilter, data);

    case GENSIO_FILTER_FUNC_LL_WRITE_QUEUED:
	return relpkt_ll_write_queued(rfilter, data);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return relpkt_ll_read_needed(rfilter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return relpkt_check_open_done(rfilter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return relpkt_try_connect(rfilter, data, buflen);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return relpkt_try_disconnect(rfilter, data, buflen);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return relpkt_ul_write(rfilter, func, data, count, cbuf, buflen,
			       auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return relpkt_ll_write(rfilter, func, data, count, buf, buflen,
			       auxdata);

    case GENSIO_FILTER_FUNC_SETUP:
	return relpkt_setup(rfilter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	relpkt_filter_cleanup(rfilter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	relpkt_free(rfilter);
	return 0;

    case GENSIO_FILTER_FUNC_TIMEOUT:
	return relpkt_filter_timeout(rfilter);

    default:
	return GE_NOTSUP;
    }
}

static struct gensio_filter *
gensio_relpkt_filter_raw_alloc(struct gensio_os_funcs *o,
			       gensiods max_pktsize, gensiods max_packets,
			       bool server)
{
    struct relpkt_filter *rfilter;
    gensiods i;

    rfilter = o->zalloc(o, sizeof(*rfilter));
    if (!rfilter)
	return NULL;

    rfilter->o = o;
    rfilter->server = server;

    rfilter->lock = o->alloc_lock(o);
    if (!rfilter->lock)
	goto out_nomem;

    rfilter->max_pkt = max_packets;
    rfilter->max_pktsize = max_pktsize;

    rfilter->recvpkts = o->zalloc(o, sizeof(struct pkt) * max_packets);
    if (!rfilter->recvpkts)
	goto out_nomem;
    for (i = 0; i < max_packets; i++) {
	rfilter->recvpkts[i].data = o->zalloc(o, max_pktsize);
	if (!rfilter->recvpkts[i].data)
	    goto out_nomem;
    }

    rfilter->xmitpkts = o->zalloc(o, sizeof(struct pkt) * max_packets);
    if (!rfilter->xmitpkts)
	goto out_nomem;
    for (i = 0; i < max_packets; i++) {
	rfilter->xmitpkts[i].data = o->zalloc(o, max_pktsize + 3);
	if (!rfilter->xmitpkts[i].data)
	    goto out_nomem;
    }

    rfilter->filter = gensio_filter_alloc_data(o, gensio_relpkt_filter_func,
					       rfilter);
    if (!rfilter->filter)
	goto out_nomem;

    return rfilter->filter;

 out_nomem:
    relpkt_free(rfilter);
    return NULL;
}

int
gensio_relpkt_filter_alloc(struct gensio_os_funcs *o,
			   const char * const args[],
			   bool server, struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    unsigned int i;
    gensiods max_pktsize = 123; /* FIXME - magic number. */
    gensiods max_packets = 16;
    char *str = NULL;
    int rv;

    rv = gensio_get_default(o, "relpkt", "mode", false,
			    GENSIO_DEFAULT_STR, &str, NULL);
    if (rv) {
	gensio_log(o, GENSIO_LOG_ERR,
		   "Failed getting relpkt mode: %s", gensio_err_to_str(rv));
	return rv;
    }
    if (str) {
	if (strcasecmp(str, "client") == 0)
	    server = true;
	else if (strcasecmp(str, "server") == 0)
	    server = false;
	else {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unknown default relpkt mode (%s), ignoring", str);
	}
	o->free(o, str);
    }

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "max_pktsize", &max_pktsize) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "max_packets", &max_packets) > 0)
	    continue;
	if (gensio_check_keyboolv(args[i], "mode", "server", "client",
				  &server) > 0)
	    continue;
	return GE_INVAL;
    }

    filter = gensio_relpkt_filter_raw_alloc(o, max_pktsize, max_packets,
					    server);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}
