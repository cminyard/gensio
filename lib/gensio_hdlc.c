/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2026  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <gensio/gensio_err.h>

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_time.h>
#include <gensio/gensio_ax25_addr.h>

/* Add timestamps to messages. */
#define GENSIO_HDLC_DEBUG_TIME	0x10

/* Dump full received/sent messages. */
#define GENSIO_HDLC_DEBUG_MSG	0x08

/* Dump some state handing information. */
#define GENSIO_HDLC_DEBUG_STATE	0x04

/* Dump raw bit handling information. */
#define GENSIO_HDLC_DEBUG_BIT_HNDL	0x02

/* Dump raw messages */
#define GENSIO_HDLC_DEBUG_RAW_MSG	0x01

/*
 * The filter keeps track of multiple possible incoming messages at a
 * time.  If a bit is read that is uncertain (the difference between
 * mark and space are not significant), it will split off a new
 * working message for each current message, one with each bit
 * possibility.  If a current working message is determined to be
 * invalid or done, it is returned to the pool.  The preamble of flags
 * should clear out all the working messages to make it a clean slate
 * for a starting message.
 */

enum hdlc_state {
    /* Looking for a '0' to start the preamble. */
    HDLC_STATE_PREAMBLE_SEARCH_0,

    /* In the preamble (01111110), found a 0, looking for a '1'. */
    HDLC_STATE_PREAMBLE_FIRST_0,

    /* In the preamble, looking for 6 1's in a row. */
    HDLC_STATE_PREAMBLE_1,

    /* In the preamble, found 0111111, looking for the last 0. */
    HDLC_STATE_PREAMBLE_LAST_0,

    /* Currently in a message. */
    HDLC_STATE_IN_MSG,

    /* Got 6 1's in a row while in msg, looking for a 0. */
    HDLC_STATE_POSTAMBLE_LAST_0
};

/*
 * A working receive buffer.
 */
struct wmsg {
    bool in_use;
    bool new_wmsg; /* Used to handle initial processing correctly. */

    unsigned int uncertainty;

    /* Counts 1's in the preamble and when receiving data. */
    unsigned int num_rcv_1;

    enum hdlc_state state;

    /*
     * Current byte/bit the receiver is assembling.
     */
    unsigned char curr_byte;
    unsigned int curr_bit_pos;

    /* Current message in assembly. */
    unsigned char *read_data;
    gensiods read_data_len;
};

struct wrbuf {
    unsigned char *data;
    gensiods len;
    gensiods outpos;
    gensiods bitlen;
};

struct delivermsg {
    unsigned char *deliver_data;
    gensiods deliver_data_pos;
    gensiods deliver_data_len;
};

struct hdlc_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    int err;

    unsigned int debug;
    bool check_ax25;
    bool do_crc;

    unsigned int tx_preamble_count;
    unsigned int tx_postamble_count;
    unsigned int max_uncertainty;

    /*
     * Data to deliver to the upper layer.  We double buffer and swap
     * buffers when new data is ready.
     */
    gensiods max_read_size;
#define MAX_DELIVER_MSGS 8
    struct delivermsg delivermsgs[MAX_DELIVER_MSGS];
    unsigned int num_delivermsgs;
    unsigned int curr_delivermsg;

    /*
     * Messages we are currently working on assembling.
     */
    struct wmsg *wmsgs;
    unsigned int max_wmsgs;
    bool got_flag;
    unsigned int curr_wmsgs;

#define NR_WRITE_BUFS 2
    gensiods max_write_size;
    struct wrbuf wrbufs[NR_WRITE_BUFS];
    unsigned int curr_wrbuf;
    unsigned int nr_wrbufs;
};

#include "crc.h"

#define filter_to_hdlc(v) ((struct hdlc_filter *)		\
			      gensio_filter_get_user_data(v))

static void
hdlc_lock(struct hdlc_filter *sfilter)
{
    sfilter->o->lock(sfilter->lock);
}

static void
hdlc_unlock(struct hdlc_filter *sfilter)
{
    sfilter->o->unlock(sfilter->lock);
}

static void
hdlc_set_callbacks(struct gensio_filter *filter,
		      gensio_filter_cb cb, void *cb_data)
{
    struct hdlc_filter *sfilter = filter_to_hdlc(filter);

    sfilter->filter_cb = cb;
    sfilter->filter_cb_data = cb_data;
}

static bool
hdlc_ul_read_pending(struct gensio_filter *filter)
{
    struct hdlc_filter *sfilter = filter_to_hdlc(filter);
    bool rv;

    hdlc_lock(sfilter);
    rv = sfilter->num_delivermsgs > 0;
    hdlc_unlock(sfilter);
    return rv;
}

static bool
hdlc_ll_write_pending(struct gensio_filter *filter)
{
    struct hdlc_filter *sfilter = filter_to_hdlc(filter);
    bool rv;

    hdlc_lock(sfilter);
    rv = sfilter->nr_wrbufs > 0;
    hdlc_unlock(sfilter);
    return rv;
}

static bool
hdlc_ll_read_needed(struct gensio_filter *filter)
{
    return false;
}

static int
hdlc_ul_can_write(struct gensio_filter *filter, bool *val)
{
    struct hdlc_filter *sfilter = filter_to_hdlc(filter);

    hdlc_lock(sfilter);
    *val = sfilter->nr_wrbufs < NR_WRITE_BUFS;
    hdlc_unlock(sfilter);

    return 0;
}

static int
hdlc_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static int
decode_ax25_control_field(char *str, size_t strlen,
			  unsigned char *buf, unsigned int buflen)
{
    static char *sname[4] = { "RR", "RNR", "REJ", "SREJ" };
    static char *uname[32] = { [0x0f] = "SABME", [0x07] = "SABM",
	[0x08] = "DISC", [0x03] = "DM", [0x0c] = "UA", [0x11] = "FRMR",
	[0x00] = "UI", [0x17] = "XID", [0x1c] = "TEST" };

    if ((*buf & 1) == 0) {
	/* I frame. */
	snprintf(str, strlen, "I p=%d nr=%d ns=%d",
		 (*buf >> 4) & 1,
		 (*buf >> 5) & 0x7,
		 (*buf >> 1) & 0x7);
    } else if ((*buf & 0x3) == 1) {
	/* S frame */
	snprintf(str, strlen, "%s pf=%d nr=%d",
		 sname[(*buf >> 2) & 0x3],
		 (*buf >> 4) & 1,
		 (*buf >> 5) & 0x7);
    } else {
	/* UI frame. */
	char *n = uname[((*buf >> 2) & 0x3) | ((*buf >> 3) & 0x1c)];
	if (!n)
	    n = "?";
	snprintf(str, strlen, "%s pf=%d", n, (*buf >> 4) & 1);
    }

    return 0;
}

static void
hdlc_ax25_prmsg(struct gensio_os_funcs *o,
		unsigned char *buf, unsigned int buflen)
{
    struct gensio_ax25_addr addr;
    char str[100];
    gensiods pos = 0, pos2 = 0;
    int err;

    if (buflen < 15)
	return;

    err = decode_ax25_addr(o, buf, &pos, buflen, 0, &addr);
    if (err)
	return;
    err = addr.r.funcs->addr_to_str(&addr.r, str, &pos2, sizeof(str));
    if (err)
	return;
    printf(" %s", str);

    printf(" ch=%d", addr.dest.ch);

    if (pos < buflen) {
	err = decode_ax25_control_field(str, sizeof(str),
					buf + pos, buflen - pos);
	if (err)
	    return;
	printf(" %s", str);
    }
}

static void
hdlc_print_msg(struct hdlc_filter *sfilter, char *t, unsigned int msgn,
	       unsigned char *buf, unsigned int buflen,
	       bool pr_msgn)
{
    struct gensio_os_funcs *o = sfilter->o;
    struct gensio_fdump h;

    if (sfilter->debug & GENSIO_HDLC_DEBUG_TIME) {
	gensio_time time;

	o->get_monotonic_time(o, &time);
	printf("%lld:%6.6d: ",
	       (long long) time.secs, (time.nsecs + 500) / 1000);
    }

    if (pr_msgn) {
	printf("%sMSG(%u %u):", t, msgn, buflen);
    } else {
	printf("%sMSG(%u):", t, buflen);
	hdlc_ax25_prmsg(sfilter->o, buf, buflen);
    }
    printf("\n");
    gensio_fdump_init(&h, 1);
    gensio_fdump_buf(stdout, buf, buflen, &h);
    gensio_fdump_buf_finish(stdout, &h);
    fflush(stdout);
}

static int
hdlc_try_connect(struct gensio_filter *filter, gensio_time *timeout,
		 bool was_timeout)
{
    return 0;
}

static int
hdlc_try_disconnect(struct gensio_filter *filter, gensio_time *timeout,
		    bool was_timeout)
{
    return 0;
}

static int
hdlc_handle_send(struct hdlc_filter *sfilter,
		 gensio_ul_filter_data_handler handler, void *cb_data)
{
    int rv;
    gensiods count;
    struct gensio_sg sg;
    char auxbuf[20];
    const char *auxdata[2] = { auxbuf, NULL };
    struct wrbuf *wrbuf;

    wrbuf = &sfilter->wrbufs[sfilter->curr_wrbuf];
    sg.buf = wrbuf->data + wrbuf->outpos;
    sg.buflen = wrbuf->len - wrbuf->outpos;
    snprintf(auxbuf, sizeof(auxbuf), "nbits=%lu", wrbuf->bitlen);
    rv = handler(cb_data, &count, &sg, 1, auxdata);
    if (rv) {
	sfilter->err = rv;
	sfilter->nr_wrbufs = 0;
    } else if (count + wrbuf->outpos >= wrbuf->len) {
	sfilter->curr_wrbuf++;
	if (sfilter->curr_wrbuf >= NR_WRITE_BUFS)
	    sfilter->curr_wrbuf = 0;
	sfilter->nr_wrbufs--;
    } else {
	wrbuf->outpos += count;
	wrbuf->bitlen -= count * 8;
    }
    return rv;
}

static void
hdlc_add_out_bit(unsigned char *outbuf,
		 gensiods *pos, unsigned int *outbitpos,
		 unsigned char bit)
{
    outbuf[*pos] |= bit << *outbitpos;
    (*outbitpos)++;
    if (*outbitpos >= 8) {
	(*pos)++;
	*outbitpos = 0;
	outbuf[*pos] = 0;
    }
}

/*
 * Process a byte with HDLC and add the output to the output buffer.
 * This does the bit stuffing.
 */
static void
hdlc_add_out_byte(unsigned char *outbuf,
		  gensiods *pos, unsigned int *outbitpos,
		  unsigned int *one_count, unsigned char byte)
{
    unsigned int i, bit;

    for (i = 0; i < 8; i++) {
	if (*one_count == 5) {
	    *one_count = 0;
	    /* Stuff a zero. */
	    hdlc_add_out_bit(outbuf, pos, outbitpos, 0);
	}
	bit = byte & 1;
	byte >>= 1;
	if (bit)
	    (*one_count)++;
	else
	    *one_count = 0;
	hdlc_add_out_bit(outbuf, pos, outbitpos, bit);
    }
}

/* Like above, bu non bit stuffing. */
static void
hdlc_add_out_byte_ns(unsigned char *outbuf,
		     gensiods *pos, unsigned int *outbitpos,
		     unsigned char byte)
{
    unsigned int i, bit;

    for (i = 0; i < 8; i++) {
	bit = byte & 1;
	byte >>= 1;
	hdlc_add_out_bit(outbuf, pos, outbitpos, bit);
    }
}

static int
hdlc_ul_write(struct gensio_filter *filter,
	      gensio_ul_filter_data_handler handler, void *cb_data,
	      gensiods *rcount,
	      const struct gensio_sg *sg, gensiods sglen,
	      const char *const *auxdata)
{
    struct hdlc_filter *sfilter = filter_to_hdlc(filter);
    gensiods i, j, len, pos, count = 0;
    unsigned int cbuf, one_count, outbitpos = 0;
    unsigned char *outbuf;
    uint16_t crc = 0xffff;
    int rv = 0;

    hdlc_lock(sfilter);
    if (sfilter->err) {
	rv = sfilter->err;
	goto out;
    }
    if (sfilter->nr_wrbufs >= NR_WRITE_BUFS || sglen == 0)
	goto out_process;

    for (i = 0, count = 0; i < sglen; i++) {
	len = sg[i].buflen;
	if (sfilter->do_crc)
	    crc16_ccitt(sg[i].buf, len, &crc);
	count += len;
    }
    if (count == 0)
	goto out_process;
    if (count > sfilter->max_write_size) {
	rv = GE_TOOBIG;
	goto out;
    }

    len = 0;
    cbuf = (sfilter->curr_wrbuf + sfilter->nr_wrbufs) % NR_WRITE_BUFS;
    outbuf = sfilter->wrbufs[cbuf].data;
    for (pos = 0; pos < sfilter->tx_preamble_count; pos++)
	outbuf[pos] = 0x7e;
    outbuf[pos] = 0;
    one_count = 0;
    for (i = 0; i < sglen; i++) {
	const unsigned char *b = sg[i].buf;

	for (j = 0; j < sg[i].buflen; j++)
	    hdlc_add_out_byte(outbuf, &pos, &outbitpos, &one_count, b[j]);
    }
    if (sfilter->do_crc) {
	crc ^= 0xffff;
	hdlc_add_out_byte(outbuf, &pos, &outbitpos, &one_count, crc & 0xff);
	hdlc_add_out_byte(outbuf, &pos, &outbitpos, &one_count,
			  (crc >> 8) & 0xff);
    }
    for (i = 0; i < sfilter->tx_postamble_count; i++)
	hdlc_add_out_byte_ns(outbuf, &pos, &outbitpos, 0x7e);
    sfilter->wrbufs[cbuf].bitlen = pos * 8 + outbitpos;
    if (outbitpos > 0)
	pos++; /* Bits in the last byte. */
    sfilter->wrbufs[cbuf].len = pos;
    sfilter->wrbufs[cbuf].outpos = 0;

    if (sfilter->debug & GENSIO_HDLC_DEBUG_MSG) {
	hdlc_print_msg(sfilter, "W", 0, sfilter->wrbufs[cbuf].data,
			  sfilter->wrbufs[cbuf].len, false);
    }

    sfilter->nr_wrbufs++;

 out_process:
    rv = hdlc_handle_send(sfilter, handler, cb_data);
 out:
    hdlc_unlock(sfilter);
    if (!rv && rcount)
	*rcount = count;

    return rv;
}

static void
hdlc_deliver_data(struct hdlc_filter *sfilter, struct wmsg *w)
{
    if (sfilter->num_delivermsgs < MAX_DELIVER_MSGS) {
	unsigned char *tmp;
	unsigned int msgn = (sfilter->curr_delivermsg +
			     sfilter->num_delivermsgs) % MAX_DELIVER_MSGS;
	struct delivermsg *d = &sfilter->delivermsgs[msgn];

	tmp = w->read_data;
	w->read_data = d->deliver_data;
	d->deliver_data = tmp;
	d->deliver_data_len = w->read_data_len;
	d->deliver_data_pos = 0;
	sfilter->num_delivermsgs++;
    }
}

static void
hdlc_drop_wmsg(struct hdlc_filter *sfilter,
	       unsigned int msgn, struct wmsg *w, bool at_flag)
{
    if (at_flag && !sfilter->got_flag) {
	/*
	 * If we get a flag, and no other flags have been detected in
	 * this set, then we keep this particular data stream.
	 * Otherwise, if we have an error in the flag before the
	 * beginning of a message, we will split and then retire this
	 * message.
	 */
	sfilter->got_flag = true;
	w->read_data_len = 0;
	w->uncertainty = 0;
    } else if (sfilter->curr_wmsgs == 1) {
	/* Always have one working message. */
	if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
	    printf("WMSG: restart\n");
	w->read_data_len = 0;
	w->uncertainty = 0;
	w->state = HDLC_STATE_PREAMBLE_SEARCH_0;
    } else {
	if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
	    printf("WMSG: retire %u\n", msgn);
	sfilter->curr_wmsgs--;
	w->in_use = false;
    }
}

static void
hdlc_handle_new_byte(struct hdlc_filter *sfilter,
		     unsigned int msgn, struct wmsg *w)
{
    if (sfilter->debug & GENSIO_HDLC_DEBUG_BIT_HNDL)
	printf("BYTE(%d): %2.2x\n", msgn, w->curr_byte);
    if (w->read_data_len >= sfilter->max_read_size) {
	hdlc_drop_wmsg(sfilter, msgn, w, false);
	return;
    }
    w->read_data[w->read_data_len] = w->curr_byte;
    w->curr_byte = 0;
    w->curr_bit_pos = 0;
    w->read_data_len++;
}

static void
hdlc_handle_new_message(struct hdlc_filter *sfilter,
			unsigned int msgn, struct wmsg *w)
{
    uint16_t crc, msgcrc;
    unsigned int i;

    if (w->read_data_len < 3)
	goto bad_msg;

    /*
     * If the bit position is 6, that means there was no extra data
     * bits data left after the last flag.  Also, allow 5 in case the
     * sender didn't stuff the last bit in a message.
     */
    if (w->curr_bit_pos != 6 && w->curr_bit_pos != 5)
	goto bad_msg;

    if (sfilter->do_crc) {
	crc = 0xffff;
	crc16_ccitt(w->read_data, w->read_data_len - 2, &crc);
	crc ^= 0xffff;
	msgcrc = ((w->read_data[w->read_data_len - 1] << 8) |
		  w->read_data[w->read_data_len - 2]);

	if (sfilter->debug & GENSIO_HDLC_DEBUG_RAW_MSG)
	    printf("    CRC %4.4x, MSGCRC %4.4x\n", crc, msgcrc);

	if (crc != msgcrc)
	    goto bad_msg;

	w->read_data_len -= 2;

	if (sfilter->check_ax25) {
	    struct gensio_ax25_addr iaddr;
	    gensiods ipos;
	    int err;

	    if (w->read_data_len < 16)
		goto bad_msg;

	    ipos = 0;
	    err = decode_ax25_addr(sfilter->o, w->read_data, &ipos,
				   w->read_data_len, 0, &iaddr);
	    if (err)
		goto bad_msg;
	}
    }

    if (sfilter->debug & GENSIO_HDLC_DEBUG_MSG) {
	hdlc_print_msg(sfilter, "R", 0, w->read_data, w->read_data_len,
			  false);
    }

    hdlc_deliver_data(sfilter, w);

    /* Cancel all working messages. */
    for (i = 0; i < sfilter->max_wmsgs; i++) {
	sfilter->wmsgs[i].read_data_len = 0;
	sfilter->wmsgs[i].uncertainty = 0;
    }
    return;

 bad_msg:
    hdlc_drop_wmsg(sfilter, msgn, w, true);
}

static void
hdlc_process_bit_w(struct hdlc_filter *sfilter, unsigned int msgn,
		   unsigned char bit, unsigned int uncertainty)
{
    unsigned int prev_num_rcv_1;
    struct wmsg *w = &sfilter->wmsgs[msgn];

    if (!w->in_use)
	return;

    if (uncertainty > sfilter->max_uncertainty && !w->new_wmsg) {
	/*
	 * We aren't sure about this bit, try both possibilities if possible.
	 */
	unsigned int i;
	unsigned int max_uncert = UINT_MAX;
	unsigned int max_uncert_pos = 0;
	unsigned int this_uncert = w->uncertainty + uncertainty;
	unsigned int alt_uncert = w->uncertainty + 100 - uncertainty;

	w->uncertainty = this_uncert;
	for (i = 0; i < sfilter->max_wmsgs; i++) {
	    if (i == msgn)
		continue;
	    if (!sfilter->wmsgs[i].in_use) {
		struct wmsg *w2;

	    add_wmsg_at:
		w2 = &sfilter->wmsgs[i];
		w2->in_use = true;
		w2->uncertainty = alt_uncert;
		w2->num_rcv_1 = w->num_rcv_1;
		w2->state = w->state;
		w2->curr_byte = w->curr_byte;
		w2->curr_bit_pos = w->curr_bit_pos;
		w2->read_data_len = w->read_data_len;
		memcpy(w2->read_data, w->read_data, w->read_data_len);
		if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
		    printf("WMSG: add %u\n", i);
		sfilter->curr_wmsgs++;
		w2->new_wmsg = true;

		if (i < msgn) {
		    /* Process this bit, since we won't get it in the main. */
		    hdlc_process_bit_w(sfilter, i, !bit, uncertainty);
		} else {
		    /*
		     * The bit processing will get this bit later, process
		     * the !bit here.
		     */
		    bit = !bit;
		    w2->uncertainty = this_uncert;
		    w->uncertainty = alt_uncert;
		}
		break;
	    }
	    if (sfilter->wmsgs[i].uncertainty > max_uncert) {
		/* Keep a running track of the largest uncertainty value. */
		max_uncert = sfilter->wmsgs[i].uncertainty;
		max_uncert_pos = i;
	    }
	}
	if (i == sfilter->max_wmsgs && alt_uncert < max_uncert) {
	    /*
	     * If the certainty of the current message is greater than
	     * the certainty of a message in the table, kick out the
	     * lowest certainty message and replace it with this
	     * message.
	     */
	    sfilter->curr_wmsgs--;
	    i = max_uncert_pos;
	    goto add_wmsg_at;
	}
    }
    w->new_wmsg = false;

    prev_num_rcv_1 = w->num_rcv_1;
    if (bit)
	w->num_rcv_1++;
    else
	w->num_rcv_1 = 0;

    switch (w->state) {
    case HDLC_STATE_PREAMBLE_SEARCH_0:
	if (!bit)
	    w->state = HDLC_STATE_PREAMBLE_FIRST_0;
	break;

    case HDLC_STATE_PREAMBLE_FIRST_0:
	if (bit)
	    w->state = HDLC_STATE_PREAMBLE_1;
	break;

    case HDLC_STATE_PREAMBLE_1:
	if (!bit)
	    w->state = HDLC_STATE_PREAMBLE_FIRST_0;
	else if (w->num_rcv_1 == 6)
	    w->state = HDLC_STATE_PREAMBLE_LAST_0;
	break;

    case HDLC_STATE_PREAMBLE_LAST_0:
	if (bit) {
	    w->state = HDLC_STATE_PREAMBLE_SEARCH_0;
	} else {
	    w->state = HDLC_STATE_IN_MSG;
	    w->curr_byte = 0;
	    w->curr_bit_pos = 0;
	}
	break;

    case HDLC_STATE_IN_MSG:
	if (prev_num_rcv_1 == 5) {
	    if (bit)
		w->state = HDLC_STATE_POSTAMBLE_LAST_0;
	    /* Otherwise it's a bit-stuffed zero and we ignore it. */
	    break;
	}

	w->curr_byte |= bit << w->curr_bit_pos;
	if (w->curr_bit_pos == 7)
	    hdlc_handle_new_byte(sfilter, msgn, w);
	else
	    w->curr_bit_pos++;
	break;

    case HDLC_STATE_POSTAMBLE_LAST_0:
	if (!bit) {
	    hdlc_handle_new_message(sfilter, msgn, w);
	    w->state = HDLC_STATE_IN_MSG;
	    w->curr_byte = 0;
	    w->curr_bit_pos = 0;
	} else {
	    hdlc_drop_wmsg(sfilter, msgn, w, false);
	}
	break;

    default:
	assert(0);
    }
}

static void
hdlc_process_bit(struct hdlc_filter *sfilter,
		 unsigned char bit, unsigned int uncertainty)
{
    unsigned int i;

    sfilter->got_flag = false;
    for (i = 0; i < sfilter->max_wmsgs; i++)
	hdlc_process_bit_w(sfilter, i, bit, uncertainty);
}

static int
hdlc_ll_write(struct gensio_filter *filter,
	      gensio_ll_filter_data_handler handler, void *cb_data,
	      gensiods *rcount,
	      unsigned char *buf, gensiods buflen,
	      const char *const *auxdata)
{
    struct hdlc_filter *sfilter = filter_to_hdlc(filter);
    unsigned char *uncertainty, uncert;
    unsigned int i, j;
    int err = 0;

    if (gensio_str_in_auxdata(auxdata, "oob")) {
	/* Ignore oob data. */
	if (rcount)
	    *rcount = buflen;
	return 0;
    }

    uncertainty = gensio_find_auxdata_ptr(auxdata, "uncert=");

    hdlc_lock(sfilter);
    if (sfilter->err) {
	err = sfilter->err;
	goto out_err;
    }
    if (buflen > 0) {
	const char *nbitstr = gensio_find_auxdata(auxdata, "nbits=");
	unsigned int nbits;

	if (nbitstr)
	    nbits = strtoul(nbitstr, NULL, 0);
	else
	    nbits = buflen * 8;

	if (uncertainty) {
	    for (i = 0; i < buflen && nbits > 0; i++) {
		unsigned char byte = buf[i];

		for (j = 0; j < 8 && nbits > 0; j++) {
		    uncert = uncertainty[i * 8 + j];
		    hdlc_process_bit(sfilter, byte & 1, uncert);
		    byte >>= 1;
		    nbits--;
		}
	    }
	} else {
	    for (i = 0; i < buflen && nbits > 0; i++) {
		unsigned char byte = buf[i];

		for (j = 0; j < 8 && nbits > 0; j++) {
		    hdlc_process_bit(sfilter, byte & 1, 0);
		    byte >>= 1;
		    nbits++;
		}
	    }
	}
    }

    if (sfilter->num_delivermsgs > 0) {
	gensiods count;
	unsigned int msgn = sfilter->curr_delivermsg;
	struct delivermsg *d = &sfilter->delivermsgs[msgn];

	hdlc_unlock(sfilter);
	err = handler(cb_data, &count,
		      d->deliver_data + d->deliver_data_pos,
		      d->deliver_data_len - d->deliver_data_pos,
		      auxdata);
	hdlc_lock(sfilter);
	if (!err) {
	    if (count + d->deliver_data_pos >= d->deliver_data_len) {
		d->deliver_data_len = 0;
		sfilter->num_delivermsgs--;
		sfilter->curr_delivermsg++;
	    } else {
		d->deliver_data_pos += count;
	    }
	}
    }
 out_err:
    hdlc_unlock(sfilter);
    if (!err && rcount)
	*rcount = buflen;
    return err;
}

static int
hdlc_setup(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static void
hdlc_cleanup(struct gensio_filter *filter)
{
    struct hdlc_filter *sfilter = filter_to_hdlc(filter);
    unsigned int i;

    sfilter->wmsgs[0].in_use = true;
    sfilter->wmsgs[0].read_data_len = 0;
    sfilter->wmsgs[0].uncertainty = 0;
    sfilter->wmsgs[0].state = HDLC_STATE_PREAMBLE_FIRST_0;
    for (i = 1; i < sfilter->max_wmsgs; i++)
	sfilter->wmsgs[i].in_use = false;
    sfilter->curr_wmsgs = 1;
    sfilter->num_delivermsgs = 0;
    sfilter->nr_wrbufs = 0;
}

static void
hdlc_sfilter_free(struct hdlc_filter *sfilter)
{
    struct gensio_os_funcs *o = sfilter->o;
    unsigned int i;

    if (sfilter->lock)
	o->free_lock(sfilter->lock);
    if (sfilter->wmsgs) {
	for (i = 0; i < sfilter->max_wmsgs; i++) {
	    if (sfilter->wmsgs[i].read_data)
		o->free(o, sfilter->wmsgs[i].read_data);
	}
	o->free(o, sfilter->wmsgs);
    }
    for (i = 0; i < MAX_DELIVER_MSGS; i++) {
	if (sfilter->delivermsgs[i].deliver_data)
	    o->free(o, sfilter->delivermsgs[i].deliver_data);
    }
    for (i = 0; i < NR_WRITE_BUFS; i++) {
	if (sfilter->wrbufs[i].data)
	    o->free(o, sfilter->wrbufs[i].data);
    }
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    o->free(o, sfilter);
}

static void
hdlc_free(struct gensio_filter *filter)
{
    struct hdlc_filter *sfilter = filter_to_hdlc(filter);

    return hdlc_sfilter_free(sfilter);
}

static int
hdlc_filter_control(struct gensio_filter *filter, bool get, int op,
		       char *data, gensiods *datalen)
{
    return GE_NOTSUP;
}

static int gensio_hdlc_filter_func(struct gensio_filter *filter, int op,
				      void *func, void *data,
				      gensiods *count,
				      void *buf, const void *cbuf,
				      gensiods buflen,
				      const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	hdlc_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return hdlc_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return hdlc_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return hdlc_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_UL_CAN_WRITE:
	return hdlc_ul_can_write(filter, data);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return hdlc_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return hdlc_try_connect(filter, data, buflen);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return hdlc_try_disconnect(filter, data, buflen);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return hdlc_ul_write(filter, func, data, count, cbuf, buflen, buf);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return hdlc_ll_write(filter, func, data, count, buf, buflen, NULL);

    case GENSIO_FILTER_FUNC_SETUP:
	return hdlc_setup(filter, data);

    case GENSIO_FILTER_FUNC_CLEANUP:
	hdlc_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	hdlc_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return hdlc_filter_control(filter, *((bool *) cbuf), buflen, data,
				  count);

    default:
	return GE_NOTSUP;
    }
}

struct gensio_hdlc_data {
    gensiods max_read_size;
    gensiods max_write_size;
    unsigned int debug;
    bool check_ax25;
    bool do_crc;
    unsigned int max_uncertainty;
    unsigned int tx_preamble_count;
    unsigned int tx_postamble_count;
    unsigned int max_wmsgs;
};

static struct gensio_filter *
gensio_hdlc_filter_raw_alloc(struct gensio_pparm_info *p,
			     struct gensio_os_funcs *o,
			     struct gensio *child,
			     struct gensio_hdlc_data *data)
{
    struct hdlc_filter *sfilter;
    unsigned int i;

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return NULL;

    sfilter->o = o;
    sfilter->max_write_size = data->max_write_size;
    sfilter->max_read_size = data->max_read_size + 2; /* Extra 2 for the CRC. */
    sfilter->debug = data->debug;
    sfilter->check_ax25 = data->check_ax25;
    sfilter->do_crc = data->do_crc;
    sfilter->tx_preamble_count = data->tx_preamble_count;
    sfilter->tx_postamble_count = data->tx_postamble_count;
    sfilter->max_wmsgs = data->max_wmsgs;
    sfilter->max_uncertainty = data->max_uncertainty;

    sfilter->lock = o->alloc_lock(o);
    if (!sfilter->lock)
	goto out_nomem;

    sfilter->wmsgs = o->zalloc(o, sizeof(struct wmsg) * sfilter->max_wmsgs);
    if (!sfilter->wmsgs)
	goto out_nomem;
    for (i = 0; i < sfilter->max_wmsgs; i++) {
	sfilter->wmsgs[i].read_data = o->zalloc(o, sfilter->max_read_size);
	if (!sfilter->wmsgs[i].read_data)
	    goto out_nomem;
    }
    sfilter->wmsgs[0].in_use = true;
    sfilter->wmsgs[0].state = HDLC_STATE_PREAMBLE_FIRST_0;
    sfilter->curr_wmsgs = 1;

    for (i = 0; i < MAX_DELIVER_MSGS; i++) {
	sfilter->delivermsgs[i].deliver_data =
	    o->zalloc(o, sfilter->max_read_size);
	if (!sfilter->delivermsgs[i].deliver_data)
	    goto out_nomem;
    }

    for (i = 0; i < NR_WRITE_BUFS; i++) {
	gensiods wrsz = sfilter->max_write_size;

	/* Calculate the maximum output size for one input packet. */
	if (sfilter->do_crc)
	    /* Add 2 to allow for the CRC to be added. */
	    wrsz += 2;
	/*
	 * You can have up to wrsz * 8 ones that need to be added to
	 * the data for bit stuffing if everything was ones.  Since
	 * you must add a bit every 5 ones, that's how much longer
	 * the buffer might have to be.
	 */
	wrsz += ((wrsz * 8) / 5 + 7) / 8;
	/*
	 * We index past the end of the data at the end
	 * sometimes. When the output bit falls at the end of the
	 * byte, we go ahead and zero the next byte, even though
	 * it may not be used.  So add one for that.
	 */
	wrsz++;
	
	sfilter->wrbufs[i].data = o->zalloc(o, wrsz);
	if (!sfilter->wrbufs[i].data)
	    goto out_nomem;
    }

    sfilter->filter = gensio_filter_alloc_data(o, gensio_hdlc_filter_func,
					       sfilter);
    if (!sfilter->filter)
	goto out_nomem;

    return sfilter->filter;

 out_nomem:
    hdlc_sfilter_free(sfilter);
    return NULL;
}

static int
gensio_hdlc_filter_alloc(struct gensio_pparm_info *p,
			    struct gensio_os_funcs *o,
			    struct gensio *child,
			    const char * const args[],
			    struct gensio_base_parms *parms,
			    struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    struct gensio_hdlc_data data = {
	.max_read_size = 256,
	.max_write_size = 256,
	.max_wmsgs = 32,
	.max_uncertainty = 20,
	.do_crc = true,
	.tx_preamble_count = 25,
	.tx_postamble_count = 2,
    };
    unsigned int i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_ds(p, args[i], "readbuf", &data.max_read_size) > 0)
	    continue;
	if (gensio_pparm_ds(p, args[i], "writebuf", &data.max_write_size) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "wmsgs", &data.max_wmsgs) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "max-uncertainty",
			      &data.max_uncertainty) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "tx-preamble",
				 &data.tx_preamble_count) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "tx-postamble",
				 &data.tx_postamble_count) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "debug", &data.debug) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "checkax25", &data.check_ax25) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "crc", &data.do_crc) > 0)
	    continue;
	if (gensio_base_parm(parms, p, args[i]) > 0)
	    continue;
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

#define CHECK_VAL(d, cmp, v)						\
    if (data.d cmp v) {							\
	gensio_pparm_log(p, #d " cannot be " #cmp " %d\n", v);		\
	return GE_INVAL;						\
    }

    CHECK_VAL(max_wmsgs, ==, 0);

    filter = gensio_hdlc_filter_raw_alloc(p, o, child, &data);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}

static int
hdlc_gensio_alloc(struct gensio *child, const char *const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    struct gensio_base_parms *parms = NULL;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "hdlc", user_data);

    err = gensio_base_parms_alloc(o, true, "hdlc", &parms);
    if (err)
	goto out_err;

    err = gensio_hdlc_filter_alloc(&p, o, child, args, parms, &filter);
    if (err)
	goto out_err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	goto out_nomem;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "hdlc", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	goto out_nomem;
    }

    err = gensio_base_parms_set(io, &parms);
    if (err) {
	gensio_free(io);
	goto out_err;
    }

    gensio_set_is_packet(io, true);
    gensio_free(child); /* Lose the ref we acquired. */

    *net = io;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
str_to_hdlc_gensio(const char *str, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    /* cb is passed in for parmerr handling, it will be overriden later. */
    err = str_to_gensio(str, o, cb, user_data, &io2);
    if (err)
	return err;

    err = hdlc_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

int
gensio_init_hdlc(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "hdlc",
				str_to_hdlc_gensio, hdlc_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
