/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2022  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <gensio/gensio_class.h>
#include <gensio/gensio_err.h>

#include "gensio_filter_afskmdm.h"

#include <assert.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <stdlib.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_time.h>
#include <gensio/gensio_ax25_addr.h>

/*
 * This filter implements a audio frequency shift keying modem per the
 * GAX25 spec.
 *
 * The filter processes data from the child in convsize frame chunks.
 * This convsize will be in_framerate/data_rate, so 1 convsize frame
 * is a approximately a single bit.  It may not be exact, so there is
 * adjustment logic to keep it close to alignment.  A similar thing is
 * done for transmission with out_framerate.
 *
 * Also, the transmitter and receiver may not be exactly aligned on
 * bit rate.  So it may drift.  There is logic to detect the drift and
 * adjust for it automatically.
 *
 * The transmitter will send a preamble that allows the adjustment
 * logic to lock in with the transmitter.
 *
 * It keeps 2 * convsize frames before the beginning of the current
 * chunk, and it waits until the next chunk to process the last
 * convsize frames of the previous chunk.  This lets the receiver
 * adjust backwards in time a bit if it has to.
 *
 * It is constantly looking for 1200Hz (level 1, a mark) and 2200Hz
 * signals (level 0, a space).  If it finds a 0 in this mode, it just
 * then looks for 6 1's in a row.  Then, if the next bit is 0, it
 * starts receiving data for the message.  This sequence will also
 * terminate amessage.
 *
 * The filter keeps track of multiple possible incoming messages at a
 * time.  If a bit is read that is uncertain (the difference between
 * mark and space are not significant), it will split off a new
 * working message for each current message, one with each bit
 * possibility.  If a current working message is determined to be
 * invalid or done, it is returned to the pool.  The preamble of flags
 * should clear out all the working messages to make it a clean slate
 * for a starting message.
 */

enum afskmdm_state {
    /* Looking for a '0' to start the preamble. */
    AFSKMDM_STATE_PREAMBLE_SEARCH_0,

    /* In the preamble (01111110), found a 0, looking for a '1'. */
    AFSKMDM_STATE_PREAMBLE_FIRST_0,

    /* In the preamble, looking for 6 1's in a row. */
    AFSKMDM_STATE_PREAMBLE_1,

    /* In the preamble, found 0111111, looking for the last 0. */
    AFSKMDM_STATE_PREAMBLE_LAST_0,

    /* Currently in a message. */
    AFSKMDM_STATE_IN_MSG,

    /* Got 6 1's in a row while in msg, looking for a 0. */
    AFSKMDM_STATE_POSTAMBLE_LAST_0
};

/*
 * This is the maximum adjust period we will allow.  If it reaches
 * this value, we assume that the small adjustments can be handled by
 * the convolution code.
 */
#define ADJ_PERIOD 10

/*
 * Give the number of values on each side of the convolution to
 * compute another convolution for.  Having values for 6 different
 * areas around the convolution seems to give the best bang for the
 * buck.
 */
#define CONVEDGE 3
#define CONVMIDDLE (CONVEDGE + 1)
#define CONVEXTRA ((2 * CONVEDGE) + 1)

/*
 * A working receive buffer.
 */
struct wmsg {
    bool in_use;
    bool new_wmsg; /* Used to handle initial processing correctly. */

    float certainty;
    unsigned int num_uncertain;

    /* Counts 1's in the preamble and when receiving data. */
    unsigned int num_rcv_1;

    enum afskmdm_state state;

    /* Level we received last time. */
    unsigned char prev_recv_level;

    /*
     * Current byte/bit the receiver is assembling.
     */
    unsigned char curr_byte;
    unsigned int curr_bit_pos;

    /* Current message in assembly. */
    unsigned char *read_data;
    gensiods read_data_len;
};

struct wmsgset {
    struct wmsg *wmsgs;
    bool got_flag;
    unsigned int curr_wmsgs;
};

struct wrbuf {
    unsigned char *data;
    gensiods len;
};

/*
 * These are the entries in a digraph used to send data.  Each of
 * these has a data item (pointing into a sine array), a size (either
 * convsize or convsize +/- 1 for the alternate size that may be
 * periodically sent).
 *
 * It also has pointers to the next entry to send based upon if the
 * next entry is a mark or space and if the next entry is convsize or
 * convsize +/- 1.
 */
struct xmit_entry {
    float *data;
    unsigned int size; /* in bytes. */
    bool is_mark;

    /*
     * If we just send this, the first two are the next entries to
     * send if the next is a space or a mark.  The second two are
     * space and mark for alternate entries
     */
    struct xmit_entry *next_send[4];

    /* A linked list of all of the entries is kept for cleanup and searching */
    struct xmit_entry *next;
};

struct afskmdm_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    int err;

    bool simplex;
    unsigned int in_nchans;
    unsigned int in_chan;
    unsigned int out_nchans;
    unsigned int out_chans;
    unsigned int in_framesize; /* Size of a (sample * nchans) in bytes. */
    unsigned int out_framesize; /* Size of a (sample * nchans) in bytes. */
    unsigned int in_chunksize; /* Frame count we get from the sound gensio. */
    unsigned int out_chunksize; /* Frame count we send to the sound gensio. */
    bool full_duplex;

    unsigned int nsec_per_frame;

    /*
     * Sending parameters;
     */
    uint64_t tx_preamble_time;
    uint64_t tx_postamble_time;
    uint64_t tx_predelay_time;

    /*
     * Frames in a single convolution.  Note that the convolution may
     * not exactly match up with the period of the data rate.  If that
     * is the case, then we will need to periodically adjust the
     * convolution window to keep it aligned.
     */
    unsigned int in_convsize;
    int in_conv_adj; /* +1, 0, or -1 */
    unsigned int in_conv_period; /* How often to add in_conv_adj. */
    unsigned int in_conv_counter; /* Current receive counter for in_conv_adj. */
    uint64_t in_conv_time; /* Time in nsec for a convsize to be received. */

    /*
     * The number of frames in a transmitted bit.  A similar
     * technique is used for sending, there are two send sizes if
     * out_bit_adj != 0 and conv_period says how often we use the
     * alternate one.
     */
    unsigned int out_bitsize;
    int out_bit_adj;
    unsigned int max_out_bitsize; /* Largest entry we will send. */
    unsigned int out_bit_counter; /* Counter for out_bit_period */
    int out_bit_period; /* How often to do an alternate frame size. */
    uint64_t out_bit_time; /* Time in nsec for a bitsize to be sent. */

    unsigned int debug;
    gensiods framecount;
    gensiods framenr;

    /* Previous level (mark = 1, space = 0) we received. */
    unsigned int prev_recv_level;
    unsigned int prev_best_pos;

    /* Level we sent last time. */
    unsigned char prev_xmit_level;

    /*
     * Data to deliver to the upper layer.  We double buffer and swap
     * buffers when new data is ready.
     */
    gensiods max_read_size;
    unsigned char *deliver_data;
    gensiods deliver_data_pos;
    gensiods deliver_data_len;

    /* IIR filter components. */
    float coefa[2];
    float coefb[3];
    float iirhold[2];

    /* FIR Filter components. */
    float *fir_h;
    unsigned int fir_h_n;
    float *firhold;

    /* Filtered data. */
    unsigned char *filteredbuf;

    /*
     * Convolution tables.  First 2 * in_convsize values is sine, second
     * 2 * in_convsize values is cosine.
     */
    float *hzmark;
    float *hzspace;

/*
 * Use this to tell if we are receiving valid data, mostly to know if
 * we can transmit.  If nr_in_sync is > the given value, we are in
 * sync.  When a single sync is missed, set nr_in_sync to the given
 * value to hurry it being reduced.  We then track how long we have
 * been out of sync.
 */
#define IN_SYNC		16
#define SYNC_RESET	32
    unsigned int nr_in_sync;
    unsigned int nr_out_sync;
    unsigned int start_xmit_delay_count;

    /*
     * Certainty value that we say is a known good bit.
     */
    float min_certainty;

    /*
     * Current position in the input, holds this value between frame
     * processing.  Values from 0 to in_convsize-1 are in the prevread
     * buffer, greater values index into the current received buffer.
     */
    unsigned int curr_in_pos;

    /*
     * 2 * in_convsize frames from end of the previous buffer.
     */
    unsigned char *prevread;
    unsigned int prevread_size;

    /*
     * Messages we are currently working on assembling.
     */
    struct wmsgset *wmsgsets;
    unsigned int wmsg_sets; /* Size of wmsgsets. */
    unsigned int max_wmsgs; /* Size of wmsgs in each wmsgset. */

    /*
     * The number of in_convsize intervals to wait before transmitting.
     */
    unsigned int tx_delay;

    /*
     * The number of bytes left to send in a preamble or postamble.
     */
    unsigned int send_count;

    enum { NOT_SENDING,
	   WAITING_ENDXMIT,
	   WAITING_TRANSMIT, /* We will not transmit here and before. */
	   SENDING_PREAMBLE,
	   SENDING_MSG,
	   SENDING_POSTAMBLE } transmit_state;

    bool starting_output_ready;

#define NR_WRITE_BUFS 2
    gensiods max_write_size;
    struct wrbuf wrbufs[NR_WRITE_BUFS];
    unsigned int curr_wrbuf;
    unsigned int nr_wrbufs;
    unsigned char wrbyte;
    unsigned char wrbyte_bit;
    unsigned int send_countdown;

    /* Count the message 1's transmitted to know when to bit stuff. */
    unsigned int num_xmit_1;
    bool bitstuff;

    /*
     * Just a sine wave at the given frequencies scaled by volume.
     * The transmit entries point into these.
     */
    float *mark_xmit;
    float *space_xmit;
    unsigned int mark_xmit_len;
    unsigned int space_xmit_len;

    /* The entry we just sent. */
    struct xmit_entry *curr_xmit_ent;

    /* All the entries, for cleanup. */
    struct xmit_entry *xmit_ent_list;

    unsigned char *xmit_buf;
    gensiods write_pos;
    gensiods xmit_buf_pos;
    gensiods xmit_buf_len;
    gensiods max_xmit_buf;

    unsigned int num_bytes_sent_this_xmit;

    enum {
	KEY_CLOSED,
	KEY_IN_OPEN,
	KEY_OPEN,
	KEY_IN_CLOSE,
    } key_io_state;
    struct gensio *key_io;
    char *key;
    char *keyon;
    char *keyoff;
    int key_err;
    bool keyed; /* Is the transmitter keyed? */
};

/* See rfc1549 */
static const unsigned short ccitt_table[256] = {
   0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
   0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
   0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
   0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
   0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
   0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
   0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
   0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
   0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
   0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
   0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
   0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
   0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
   0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
   0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
   0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
   0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
   0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
   0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
   0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
   0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
   0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
   0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
   0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
   0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
   0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
   0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
   0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
   0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
   0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
   0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
   0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

static void
crc16_ccitt(const unsigned char *buf, unsigned int len, uint16_t *icrc)
{
	unsigned int i;
	uint16_t crc = *icrc;

	for (i = 0; i < len; i++)
	    crc = (crc >> 8) ^ ccitt_table[(crc ^ buf[i]) & 0xff];

	*icrc = crc;
}

#define filter_to_afskmdm(v) ((struct afskmdm_filter *) \
			      gensio_filter_get_user_data(v))

static void
afskmdm_lock(struct afskmdm_filter *sfilter)
{
    sfilter->o->lock(sfilter->lock);
}

static void
afskmdm_unlock(struct afskmdm_filter *sfilter)
{
    sfilter->o->unlock(sfilter->lock);
}

static void
afskmdm_set_callbacks(struct gensio_filter *filter,
		      gensio_filter_cb cb, void *cb_data)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);

    sfilter->filter_cb = cb;
    sfilter->filter_cb_data = cb_data;
}

static bool
afskmdm_ul_read_pending(struct gensio_filter *filter)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);
    bool rv;

    afskmdm_lock(sfilter);
    rv = sfilter->deliver_data_len > 0;
    afskmdm_unlock(sfilter);
    return rv;
}

static bool
afskmdm_ll_write_pending(struct gensio_filter *filter)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);
    bool rv;

    afskmdm_lock(sfilter);
    rv = sfilter->xmit_buf_len > 0 || sfilter->starting_output_ready;
    afskmdm_unlock(sfilter);
    return rv;
}

static bool
afskmdm_ll_read_needed(struct gensio_filter *filter)
{
    return true;
}

static int
afskmdm_ul_can_write(struct gensio_filter *filter, bool *val)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);

    afskmdm_lock(sfilter);
    *val = sfilter->nr_wrbufs < NR_WRITE_BUFS;
    afskmdm_unlock(sfilter);

    return 0;
}

static int
afskmdm_check_open_done(struct gensio_filter *filter, struct gensio *io)
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
afskmdm_ax25_prmsg(struct gensio_os_funcs *o,
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
afskmdm_print_msg(struct afskmdm_filter *sfilter, unsigned int msgn,
		  unsigned char *buf, unsigned int buflen,
		  bool pr_msgn)
{
    struct gensio_fdump h;

    if (pr_msgn) {
	printf("MSG(%u %u):", msgn, buflen);
    } else {
	printf("MSG(%u):", buflen);
	afskmdm_ax25_prmsg(sfilter->o, buf, buflen);
    }
    printf("\n");
    gensio_fdump_init(&h, 1);
    gensio_fdump_buf(stdout, buf, buflen, &h);
    gensio_fdump_buf_finish(stdout, &h);
    fflush(stdout);
}

static int
key_cb(struct gensio *io, void *user_data, int event, int err,
       unsigned char *buf, gensiods *buflen, const char *const *auxdata)
{
    //struct afskmdm_filter *sfilter = user_data;

    switch(event) {
    case GENSIO_EVENT_READ:
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static void
key_open_done(struct gensio *io, int err, void *open_data)
{
    struct afskmdm_filter *sfilter = open_data;

    if (err)
	sfilter->key_io_state = KEY_CLOSED;
    else
	sfilter->key_io_state = KEY_OPEN;
    sfilter->key_err = err;

    /* Just turn on read and ignore what we get. */
    gensio_set_read_callback_enable(io, true);

    sfilter->filter_cb(sfilter->filter_cb_data, GENSIO_FILTER_CB_OPEN_DONE,
		       NULL);
}

static int
afskmdm_try_connect(struct gensio_filter *filter, gensio_time *timeout,
		    bool was_timeout)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);
    int err = sfilter->key_err;

    if (err) {
	sfilter->key_err = 0;
	return err;
    }

    if (sfilter->key_io &&
	sfilter->key_io_state != KEY_IN_OPEN &&
	sfilter->key_io_state != KEY_OPEN) {

	err = gensio_open(sfilter->key_io, key_open_done, sfilter);
	if (err)
	    return err;
	sfilter->key_io_state = KEY_IN_OPEN;
    }
    if (sfilter->key_io_state == KEY_IN_OPEN) {
	timeout->secs = 0;
	timeout->nsecs = GENSIO_MSECS_TO_NSECS(10);
	return GE_RETRY;
    }
    return 0;
}

static void
key_close_done(struct gensio *io, void *close_data)
{
    struct afskmdm_filter *sfilter = close_data;

    sfilter->key_io_state = KEY_CLOSED;
}

static int
afskmdm_try_disconnect(struct gensio_filter *filter, gensio_time *timeout,
		       bool was_timeout)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);
    int err;

    if (sfilter->key_io_state == KEY_OPEN) {
	if (sfilter->keyed) {
	    gensio_write(sfilter->key_io, NULL,
			 sfilter->keyoff, strlen(sfilter->keyoff), NULL);
	    sfilter->keyed = false;
	}
	err = gensio_close(sfilter->key_io, key_close_done, sfilter);
	if (err)
	    sfilter->key_io_state = KEY_CLOSED;
	else
	    sfilter->key_io_state = KEY_IN_CLOSE;
    }
    if (sfilter->key_io_state == KEY_IN_CLOSE) {
	timeout->secs = 0;
	timeout->nsecs = GENSIO_MSECS_TO_NSECS(10);
	return GE_RETRY;
    }
    if (sfilter->transmit_state != NOT_SENDING)
	return GE_INPROGRESS;
    return 0;
}

static void
afskmdm_start_xmit(struct afskmdm_filter *sfilter)
{
    sfilter->num_bytes_sent_this_xmit = 0;
    sfilter->transmit_state = SENDING_PREAMBLE;
    sfilter->wrbyte = 0x7e;
    sfilter->wrbyte_bit = 0;
    sfilter->send_count = (sfilter->tx_preamble_time /
			   sfilter->out_bit_time / 8);
    sfilter->bitstuff = false;
    sfilter->starting_output_ready = true;
    if (sfilter->key_io) {
	gensio_write(sfilter->key_io, NULL,
		     sfilter->keyon, strlen(sfilter->keyon), NULL);
	sfilter->keyed = true;
    }
}

static void
afskmdm_start_drain_timer(struct afskmdm_filter *sfilter)
{
    unsigned long frames_left = 0;
    struct gensio_filter_cb_control_data cd;
    char buf[20] = "0";
    gensiods buflen = sizeof(buf);
    uint64_t timeoutns;
    gensio_time timeout;

    cd.depth = GENSIO_CONTROL_DEPTH_FIRST;
    cd.get = true;
    cd.option = GENSIO_CONTROL_DRAIN_COUNT;
    cd.data = buf;
    cd.datalen = &buflen;
    sfilter->filter_cb(sfilter->filter_cb_data,
		       GENSIO_FILTER_CB_CONTROL, &cd);
    frames_left = strtoul(buf, NULL, 0);

    /*
     * Set a timer to know when we are done transmitting.
     */
    timeoutns = frames_left * sfilter->nsec_per_frame;
    timeout.secs = timeoutns / GENSIO_NSECS_IN_SEC;
    timeout.nsecs = timeoutns % GENSIO_NSECS_IN_SEC;
    sfilter->filter_cb(sfilter->filter_cb_data,
		       GENSIO_FILTER_CB_START_TIMER,
		       &timeout);
}

static int
afskmdm_timeout_done(struct gensio_filter *filter)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);

    afskmdm_lock(sfilter);
    if (sfilter->nr_wrbufs > 0) {
	sfilter->transmit_state = WAITING_TRANSMIT;
    } else {
	sfilter->transmit_state = NOT_SENDING;
    }
    if (sfilter->keyed) {
	gensio_write(sfilter->key_io, NULL,
		     sfilter->keyoff, strlen(sfilter->keyoff), NULL);
	sfilter->keyed = false;
    }
    afskmdm_unlock(sfilter);

    return 0;
}

static void
afskmdm_check_start_xmit(struct afskmdm_filter *sfilter)
{
    unsigned int randv;

    /* Some primitive randomness.  Could be improved. */
    sfilter->o->get_random(sfilter->o, &randv, sizeof(randv));
    randv %= 10;
    if (sfilter->start_xmit_delay_count + 1 > randv) {
	sfilter->start_xmit_delay_count = 0;
	afskmdm_start_xmit(sfilter);
    } else {
	sfilter->start_xmit_delay_count++;
	if (sfilter->curr_in_pos < sfilter->tx_delay / 10)
	    sfilter->curr_in_pos = 0;
	else
	    sfilter->curr_in_pos -= sfilter->tx_delay / 10;
    }
}

static void
afskmdm_send_buffer(struct afskmdm_filter *sfilter,
		    gensio_ul_filter_data_handler handler, void *cb_data)
{
    int rv;
    gensiods count;
    struct gensio_sg sg;

    sg.buf = (sfilter->xmit_buf +
	      (sfilter->xmit_buf_pos * sfilter->out_framesize));
    sg.buflen = ((sfilter->xmit_buf_len - sfilter->xmit_buf_pos) *
		 sfilter->out_framesize);
    rv = handler(cb_data, &count, &sg, 1, NULL);
    if (rv) {
	sfilter->err = rv;
	sfilter->xmit_buf_len = 0;
	sfilter->xmit_buf_pos = 0;
	sfilter->nr_wrbufs = 0;
    } else {
	if (count >= sg.buflen) {
	    sfilter->xmit_buf_len = 0;
	    sfilter->xmit_buf_pos = 0;
	} else {
	    sfilter->xmit_buf_pos += count / sfilter->out_framesize;
	}
    }
}

static void
afskmdm_add_wrbit(struct afskmdm_filter *sfilter)
{
    unsigned char bit = sfilter->wrbyte & 1;
    unsigned char level = sfilter->prev_xmit_level;
    struct xmit_entry *curr = sfilter->curr_xmit_ent;
    unsigned int send_alt = 0, i, j;
    float *s;

    if (sfilter->out_bit_adj) {
	sfilter->out_bit_counter++;
	if (sfilter->out_bit_counter == sfilter->out_bit_period) {
	    sfilter->out_bit_counter = 0;
	    send_alt = 2;
	}
    }

    if (sfilter->transmit_state == SENDING_MSG) {
	if (sfilter->bitstuff) {
	    sfilter->bitstuff = false;
	    sfilter->num_xmit_1 = 0;
	    bit = 0;
	    goto skip_increment;
	} else if (bit) {
	    sfilter->num_xmit_1++;
	    if (sfilter->num_xmit_1 == 5)
		sfilter->bitstuff = true;
	} else {
	    sfilter->num_xmit_1 = 0;
	}
    }

    sfilter->wrbyte >>= 1;
    sfilter->wrbyte_bit++;

 skip_increment:
    /* If the bit is 0, change the frequency.  1 leaves it the same. */
    if (!bit)
	level = !level;
    sfilter->prev_xmit_level = level;

    curr = curr->next_send[level + send_alt];
    sfilter->curr_xmit_ent = curr;

    s = (float *) sfilter->xmit_buf;
    s += sfilter->xmit_buf_len * sfilter->out_nchans;
    for (i = 0; i < curr->size; i++) {
	for (j = 0; j < sfilter->out_nchans; j++) {
	    if ((1 << j) & sfilter->out_chans)
		*s++ = curr->data[i];
	    else
		*s++ = 0.;
	}
    }
    sfilter->xmit_buf_len += curr->size;
}

static void
afskmdm_handle_send(struct afskmdm_filter *sfilter,
		    gensio_ul_filter_data_handler handler, void *cb_data)
{
    sfilter->starting_output_ready = false;
    if (sfilter->xmit_buf_len > 0) {
	afskmdm_send_buffer(sfilter, handler, cb_data);
	if (sfilter->xmit_buf_len > 0)
	    goto out;
	if (sfilter->transmit_state == WAITING_ENDXMIT)
	    afskmdm_start_drain_timer(sfilter);
    }
    while (sfilter->transmit_state > WAITING_TRANSMIT) {
	if (sfilter->bitstuff || sfilter->wrbyte_bit < 8) {
	    afskmdm_add_wrbit(sfilter);
	    if (sfilter->xmit_buf_len >=
			sfilter->max_xmit_buf - sfilter->max_out_bitsize) {
		afskmdm_send_buffer(sfilter, handler, cb_data);
		if (sfilter->err)
		    goto out;
		if (sfilter->xmit_buf_len > 0)
		    goto out;
	    }
	}

	/* Make sure to send the last bitstuff. */
	if (!sfilter->bitstuff && sfilter->wrbyte_bit >= 8) {
	    sfilter->wrbyte_bit = 0;
	    switch (sfilter->transmit_state) {
	    case NOT_SENDING:
	    case WAITING_TRANSMIT:
	    case WAITING_ENDXMIT:
		goto out; /* Should not happen. */

	    case SENDING_PREAMBLE:
		sfilter->send_count--;
		if (sfilter->send_count > 0) {
		    sfilter->wrbyte = 0x7e;
		} else {
		    unsigned int cbuf = sfilter->curr_wrbuf;

		    sfilter->num_bytes_sent_this_xmit++;
		    sfilter->wrbyte = sfilter->wrbufs[cbuf].data[0];
		    sfilter->write_pos = 1;
		    sfilter->num_xmit_1 = 0;
		    sfilter->transmit_state = SENDING_MSG;
		    /* All messages are at least 3 bytes, no check for done. */
		}
		break;

	    case SENDING_MSG: {
		unsigned int cbuf = sfilter->curr_wrbuf;

		if (sfilter->write_pos >= sfilter->wrbufs[cbuf].len) {
		    sfilter->write_pos = 0;
		    sfilter->curr_wrbuf = (cbuf + 1) % NR_WRITE_BUFS;
		    sfilter->nr_wrbufs--;

		    if (sfilter->nr_wrbufs > 0 &&
				sfilter->num_bytes_sent_this_xmit < 128) {
			/*
			 * We haven't sent too many bytes, and we have
			 * another message.  Just throw in a couple of
			 * flags and start it.
			 */
			sfilter->transmit_state = SENDING_PREAMBLE;
			sfilter->wrbyte = 0x7e;
			sfilter->send_count = 2;
		    } else {
			sfilter->transmit_state = SENDING_POSTAMBLE;
			sfilter->wrbyte = 0x7e;
			sfilter->send_count = (sfilter->tx_postamble_time /
					       sfilter->out_bit_time / 8);
		    }
		} else {
		    unsigned int pos = sfilter->write_pos++;

		    sfilter->num_bytes_sent_this_xmit++;
		    sfilter->wrbyte = sfilter->wrbufs[cbuf].data[pos];
		}
		break;
	    }

	    case SENDING_POSTAMBLE:
		sfilter->send_count--;
		if (sfilter->send_count > 0) {
		    sfilter->wrbyte = 0x7e;
		} else {
		    sfilter->nr_out_sync = 0;
		    sfilter->transmit_state = WAITING_ENDXMIT;
		    if (sfilter->xmit_buf_len == 0)
			/*
			 * No more data to send, start the timer now.
			 */
			afskmdm_start_drain_timer(sfilter);
		    /*
		     * Otherwise, start the timer when all
		     * the data has been sent.
		     */
		    goto out;
		}
		break;
	    }
	}
    }
 out:
    return;
}

static int
afskmdm_ul_write(struct gensio_filter *filter,
		 gensio_ul_filter_data_handler handler, void *cb_data,
		 gensiods *rcount,
		 const struct gensio_sg *sg, gensiods sglen,
		 const char *const *auxdata)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);
    gensiods i, count = 0, len;
    unsigned int cbuf;
    uint16_t crc;
    int rv = 0;

    afskmdm_lock(sfilter);
    if (sfilter->err) {
	rv = sfilter->err;
	goto out;
    }
    if (sfilter->nr_wrbufs >= NR_WRITE_BUFS || sglen == 0)
	goto out_process;

    cbuf = (sfilter->curr_wrbuf + sfilter->nr_wrbufs) % NR_WRITE_BUFS;
    sfilter->wrbufs[cbuf].len = 0;
    for (i = 0; i < sglen; i++) {
	len = sg[i].buflen;
	if (sfilter->wrbufs[cbuf].len + len > sfilter->max_write_size)
	    len = sfilter->max_write_size - sfilter->wrbufs[cbuf].len;
	memcpy(sfilter->wrbufs[cbuf].data + sfilter->wrbufs[cbuf].len,
	       sg[i].buf, len);
	sfilter->wrbufs[cbuf].len += len;
	count += len;
    }
    if (count == 0)
	goto out_process;

    if (sfilter->debug & 8) {
	printf("W");
	afskmdm_print_msg(sfilter, 0, sfilter->wrbufs[cbuf].data,
			  sfilter->wrbufs[cbuf].len, false);
    }

    /* We have two extra bytes on the end for the CRC, no check needed. */
    crc = 0xffff;
    len = sfilter->wrbufs[cbuf].len;
    crc16_ccitt(sfilter->wrbufs[cbuf].data, len, &crc);
    crc ^= 0xffff;
    sfilter->wrbufs[cbuf].data[len++] = crc & 0xff;
    sfilter->wrbufs[cbuf].data[len++] = (crc >> 8) & 0xff;
    sfilter->wrbufs[cbuf].len = len;

    sfilter->nr_wrbufs++;
    if (sfilter->transmit_state != NOT_SENDING)
	goto out_process;
    if (sfilter->full_duplex || sfilter->nr_out_sync >= sfilter->tx_delay) {
	afskmdm_start_xmit(sfilter);
    } else {
	sfilter->transmit_state = WAITING_TRANSMIT;
	goto out;
    }

 out_process:
    afskmdm_handle_send(sfilter, handler, cb_data);
 out:
    afskmdm_unlock(sfilter);
    if (!rv && rcount)
	*rcount = count;

    return rv;
}

#if 0
static float
afskmdm_measure_power(struct afskmdm_filter *sfilter,
		      unsigned int curpos,
		      unsigned char *buf1, unsigned char *buf2)
{
    float *s1 = (float *) buf1 + sfilter->chan;
    float *s2 = (float *) buf2 + sfilter->chan;
    float power = 0, v;
    unsigned int i;

    if (curpos < sfilter->prevread_size)
	s1 += curpos * sfilter->in_nchans;
    else
	s2 += (curpos - sfilter->prevread_size) * sfilter->in_nchans;

    for (i = 0; i < sfilter->in_convsize; i++, curpos++) {
	if (curpos < sfilter->prevread_size) {
	    v = *s1;
	    s1 += sfilter->in_nchans;
	} else {
	    v = *s2;
	    s2 += sfilter->in_nchans;
	}
	power += v * v;
    }
    return power;
}
#endif

/*
 * Do a convolution.
 *
 * convdata is the sin/cosine table to convolve against, the first 2 *
 * in_convsize floats are the sin table, the second 2 * in_convsize floats
 * are the cosine table.
 *
 * The data comes in two chunks, buf1 is 2 * in_convsize frames at the
 * beginning, buf2 is chunksize frames after that.
 *
 * buf is an array of floats.  So we have to cast it.  The data may be
 * interleaved, meaning that frames from multiple channels may be in
 * it.  We only care about one channel.  So we have to multiply by the
 * number of channels and add the channel offset.
 *
 * Each convolution is done on in_convsize frames of data.  The first
 * in_convsize bytes is processed and put into p[0] (power at the given
 * frequency).  If edge > 0, then frames 1-(in_convsize+1) are processed
 * and put into p[1], and so on.  (This is done more efficiently by
 * tracking some values, subtracting off the beginning, and adding on
 * the end).
 *
 * You can think of edge as the number of values on each side of the
 * main signal.
 *
 * Multiple values lets you scan for data or align data.
 *
 * dummyp must be [edge * 4].  p must be [(edge * 2) + 1].
 */
static void
afskmdm_convolve(struct afskmdm_filter *sfilter, float *convdata,
		 unsigned int edge,
		 unsigned int curpos, unsigned char *buf1, unsigned char *buf2,
		 float p[], float dummyp[])
{
    /* There will always be one byte before the data, so the -1 ok. */
    float *s1 = (float *) buf1 + sfilter->in_chan;
    float *s2 = (float *) buf2 + sfilter->in_chan;
    float *csin = convdata;
    float *ccos = convdata + 2 * sfilter->in_convsize;
    float v;
    float psin = 0, pcos = 0;
    unsigned int i, ppos = 0, spos;

    if (curpos < sfilter->prevread_size)
	s1 += curpos * sfilter->in_nchans;
    else
	s2 += (curpos - sfilter->prevread_size) * sfilter->in_nchans;

    for (i = 0; i < sfilter->in_convsize; i++, curpos++) {
	if (curpos < sfilter->prevread_size) {
	    v = *s1;
	    s1 += sfilter->in_nchans;
	} else {
	    v = *s2;
	    s2 += sfilter->in_nchans;
	}
	psin += *csin * v;
	pcos += *ccos * v;
	if (i < edge * 2) {
	    dummyp[i * 2] = *csin * v;
	    dummyp[i * 2 + 1] = *ccos * v;
	}
	csin++;
	ccos++;
    }
    p[ppos++] = psin * psin + pcos * pcos;

    for (spos = 0; i < sfilter->in_convsize + (edge * 2);
	 i++, curpos++, spos++) {

	/* Make sure we don't go past the end of the buffer. */
	assert(curpos <= sfilter->prevread_size ||
	       curpos - sfilter->prevread_size < sfilter->in_chunksize);

	if (curpos < sfilter->prevread_size) {
	    v = *s1;
	    s1 += sfilter->in_nchans;
	} else {
	    v = *s2;
	    s2 += sfilter->in_nchans;
	}
	psin -= dummyp[spos * 2];
	pcos -= dummyp[spos * 2 + 1];
	psin += *csin++ * v;
	pcos += *ccos++ * v;
	p[ppos++] = psin * psin + pcos * pcos;
    }
}

static void
afskmdm_handle_new_byte(struct afskmdm_filter *sfilter, unsigned int msgn,
			struct wmsg *w)
{
    if (sfilter->debug & 2)
	printf("BYTE(%d): %2.2x\n", msgn, w->curr_byte);
    if (w->read_data_len < sfilter->max_read_size)
	w->read_data[w->read_data_len] = w->curr_byte;
    w->curr_byte = 0;
    w->curr_bit_pos = 0;
    w->read_data_len++;
}

static void
afskmdm_drop_wmsg(struct afskmdm_filter *sfilter, unsigned int wset,
		  unsigned int msgn, struct wmsg *w, bool at_flag)
{
    struct wmsgset *ws = &sfilter->wmsgsets[wset];

    if (at_flag && !ws->got_flag) {
	/*
	 * If we get a flag, and no other flags have been detected in
	 * this set, then we keep this particular data stream.
	 * Otherwise, if we have an error in the flag before the
	 * beginning of a message, we will split and then retire this
	 * message.
	 */
	ws->got_flag = true;
	w->read_data_len = 0;
	w->num_uncertain = 0;
	w->certainty = 0.0;
    } else if (ws->curr_wmsgs == 1) {
	/* Always have one working message. */
	if (sfilter->debug & 4)
	    printf("WMSG: restart\n");
	w->read_data_len = 0;
	w->num_uncertain = 0;
	w->certainty = 0.0;
	w->state = AFSKMDM_STATE_PREAMBLE_SEARCH_0;
    } else {
	if (sfilter->debug & 4)
	    printf("WMSG: retire %u\n", msgn);
	ws->curr_wmsgs--;
	w->in_use = false;
    }
}

static void
afskmdm_handle_new_message(struct afskmdm_filter *sfilter, unsigned int pos,
			   unsigned int wset, unsigned int msgn, struct wmsg *w)
{
    uint16_t crc, msgcrc;
    unsigned int i;

    if (w->read_data_len < 3)
	goto bad_msg;

    if (sfilter->debug & 1) {
	afskmdm_print_msg(sfilter, msgn, w->read_data, w->read_data_len, true);
	printf("    bitpos %d  endframe %lu\n", w->curr_bit_pos,
	       sfilter->framenr + pos - sfilter->prevread_size);
    }

    /*
     * If the bit position is 6, that means there was no extra data
     * bits data left after the last flag.  Also, allow 5 in case the
     * sender didn't stuff the last bit in a message.
     */
    if (w->curr_bit_pos != 6 && w->curr_bit_pos != 5)
	goto bad_msg;

    crc = 0xffff;
    crc16_ccitt(w->read_data, w->read_data_len - 2, &crc);
    crc ^= 0xffff;
    msgcrc = ((w->read_data[w->read_data_len - 1] << 8) |
	      w->read_data[w->read_data_len - 2]);

    if (sfilter->debug & 1)
	printf("    CRC %4.4x, MSGCRC %4.4x\n", crc, msgcrc);

    if (crc != msgcrc)
	goto bad_msg;

    w->read_data_len -= 2;

    if (sfilter->debug & 8) {
	printf("R");
	afskmdm_print_msg(sfilter, 0, w->read_data, w->read_data_len, false);
    }

    if (w->read_data_len <= sfilter->max_read_size &&
		sfilter->deliver_data_len == 0) {
	unsigned char *tmp;

	tmp = w->read_data;
	w->read_data = sfilter->deliver_data;
	sfilter->deliver_data = tmp;
	sfilter->deliver_data_len = w->read_data_len;
	sfilter->deliver_data_pos = 0;
    }

    /* Cancel all working messages. */
    for (i = 0; i < sfilter->wmsg_sets; i++) {
	unsigned int j;

	for (j = 0; j < sfilter->max_wmsgs; j++) {
	    sfilter->wmsgsets[i].wmsgs[j].read_data_len = 0;
	    sfilter->wmsgsets[i].wmsgs[j].num_uncertain = 0;
	    sfilter->wmsgsets[i].wmsgs[j].certainty = 0.0;
	}
    }
    return;

 bad_msg:
    afskmdm_drop_wmsg(sfilter, wset, msgn, w, true);
}

static void
afskmdm_process_bit(struct afskmdm_filter *sfilter, unsigned int pos,
		    unsigned int wset, unsigned int msgn,
		    unsigned char level, float certainty,
		    bool *in_sync)
{
    unsigned int prev_num_rcv_1;
    unsigned char bit;
    struct wmsg *w = &sfilter->wmsgsets[wset].wmsgs[msgn];

    if (!w->in_use)
	return;

    if (certainty > 0.0 && certainty < sfilter->min_certainty && !w->new_wmsg) {
	/*
	 * We aren't sure about this bit, try both possibilities if possible.
	 */
	unsigned int i;
	float min_certainty = FLT_MAX;
	unsigned int min_cert_pos = 0;
	float this_certainty = (((w->certainty * w->num_uncertain) + certainty)
				/ (w->num_uncertain + 1));
	float alt_certainty = (((w->certainty * w->num_uncertain) + 1/certainty)
			       / (w->num_uncertain + 1));

	w->certainty = this_certainty;
	w->num_uncertain++;
	for (i = 0; i < sfilter->max_wmsgs; i++) {
	    if (i == msgn)
		continue;
	    if (!sfilter->wmsgsets[wset].wmsgs[i].in_use) {
		struct wmsg *w2;

	    add_wmsg_at:
		w2 = &sfilter->wmsgsets[wset].wmsgs[i];
		w2->in_use = true;
		w2->certainty = alt_certainty;
		w2->num_uncertain = w->num_uncertain;
		w2->num_rcv_1 = w->num_rcv_1;
		w2->prev_recv_level = w->prev_recv_level;
		w2->state = w->state;
		w2->curr_byte = w->curr_byte;
		w2->curr_bit_pos = w->curr_bit_pos;
		w2->read_data_len = w->read_data_len;
		memcpy(w2->read_data, w->read_data, w->read_data_len);
		if (sfilter->debug & 4)
		    printf("WMSG: add %u %u\n", wset, i);
		sfilter->wmsgsets[wset].curr_wmsgs++;
		w2->new_wmsg = true;

		if (i < msgn) {
		    /* Process this bit, since we won't get it in the main. */
		    afskmdm_process_bit(sfilter, pos, wset, i, !level,
					certainty, in_sync);
		} else {
		    /*
		     * The bit processing will get this bit later, process
		     * the !bit here.
		     */
		    level = !level;
		    w2->certainty = this_certainty;
		    w->certainty = alt_certainty;
		}
		break;
	    }
	    if (sfilter->wmsgsets[wset].wmsgs[i].certainty < min_certainty) {
		/* Keep a running track of the smallest certainty value. */
		min_certainty = sfilter->wmsgsets[wset].wmsgs[i].certainty;
		min_cert_pos = i;
	    }
	}
	if (i == sfilter->max_wmsgs && alt_certainty > min_certainty) {
	    /*
	     * If the certainty of the current message is greater than
	     * the certainty of a message in the table, kick out the
	     * lowest certainty message and replace it with this
	     * message.
	     */
	    sfilter->wmsgsets[wset].curr_wmsgs--;
	    i = min_cert_pos;
	    goto add_wmsg_at;
	}
    }
    w->new_wmsg = false;

    /*
     * The bit is 0 if the frequency changed, 1 if the frequency
     * stayed the same.
     */
    bit = level == w->prev_recv_level;
    w->prev_recv_level = level;

    if (sfilter->debug & 2)
	printf("BIT(%u %u %lu): l:%d b:%d %f  (%d)\n", wset, msgn,
	       sfilter->framenr + pos - sfilter->prevread_size,
	       level, bit, certainty, w->state);

    prev_num_rcv_1 = w->num_rcv_1;
    if (bit)
	w->num_rcv_1++;
    else
	w->num_rcv_1 = 0;

    switch (w->state) {
    case AFSKMDM_STATE_PREAMBLE_SEARCH_0:
	if (!bit)
	    w->state = AFSKMDM_STATE_PREAMBLE_FIRST_0;
	*in_sync = false;
	break;

    case AFSKMDM_STATE_PREAMBLE_FIRST_0:
	if (bit)
	    w->state = AFSKMDM_STATE_PREAMBLE_1;
	*in_sync = false;
	break;

    case AFSKMDM_STATE_PREAMBLE_1:
	if (!bit)
	    w->state = AFSKMDM_STATE_PREAMBLE_FIRST_0;
	else if (w->num_rcv_1 == 6)
	    w->state = AFSKMDM_STATE_PREAMBLE_LAST_0;
	*in_sync = false;
	break;

    case AFSKMDM_STATE_PREAMBLE_LAST_0:
	if (bit) {
	    w->state = AFSKMDM_STATE_PREAMBLE_SEARCH_0;
	} else {
	    w->state = AFSKMDM_STATE_IN_MSG;
	    w->curr_byte = 0;
	    w->curr_bit_pos = 0;
	    *in_sync = false;
	}
	break;

    case AFSKMDM_STATE_IN_MSG:
	if (prev_num_rcv_1 == 5) {
	    if (bit)
		w->state = AFSKMDM_STATE_POSTAMBLE_LAST_0;
	    /* Otherwise it's a bit-stuffed zero and we ignore it. */
	    break;
	}

	w->curr_byte |= bit << w->curr_bit_pos;
	if (w->curr_bit_pos == 7)
	    afskmdm_handle_new_byte(sfilter, msgn, w);
	else
	    w->curr_bit_pos++;
	break;

    case AFSKMDM_STATE_POSTAMBLE_LAST_0:
	if (!bit) {
	    afskmdm_handle_new_message(sfilter, pos, wset, msgn, w);
	    w->state = AFSKMDM_STATE_IN_MSG;
	    w->curr_byte = 0;
	    w->curr_bit_pos = 0;
	} else {
	    afskmdm_drop_wmsg(sfilter, wset, msgn, w, false);
	    *in_sync = false;
	}
	break;

    default:
	assert(0);
    }
}

/*
 * We have a set of frames.  Look through them all and choose the one
 * with the most certainty.
 */
static void
process_powers(struct afskmdm_filter *sfilter,
	       float pmark[CONVEXTRA], float pspace[CONVEXTRA],
	       unsigned int *rbest_pos,
	       float *rcertainty, unsigned char *rlevel)
{
    float tcertainty;
    unsigned char tlevel;
    unsigned int i;

    for (i = 0; i < CONVEXTRA; i++) {
	if (pspace[i] > pmark[i]) {
	    tlevel = 0;
	    tcertainty = pspace[i] / pmark[i];
	} else {
	    tlevel = 1;
	    tcertainty = pmark[i] / pspace[i];
	}
	if (isnan(tcertainty) || isinf(tcertainty))
	    tcertainty = 0.0;
	if (tcertainty >= *rcertainty) {
	    *rbest_pos = i;
	    *rlevel = tlevel;
	    *rcertainty = tcertainty;
	}
    }
}

/*
 * Do a convolution at 1200Hz and 2200Hz over the data.  Return
 * whether the power at 1200Hz (bit=0) or 2200Hz (bit=1) is greater.
 * Returns the certainty of the bit, which is the ratio of the two
 * power levels.
 */
static void
afskmdm_check_for_data(struct afskmdm_filter *sfilter, unsigned int *curpos,
		       unsigned char *buf1, unsigned char *buf2, bool *in_sync)
{
    float pmark[CONVEXTRA], pspace[CONVEXTRA];
    float pmark2[CONVEXTRA], pspace2[CONVEXTRA];
    float dummyp[CONVEDGE * 4];
    unsigned char level = sfilter->prev_recv_level;
    unsigned int i, best_pos = 0, wset;
    float certainty = 0.0, m;

    afskmdm_convolve(sfilter, sfilter->hzmark, CONVEDGE, (*curpos) - CONVEDGE,
		     buf1, buf2, pmark, dummyp);
    afskmdm_convolve(sfilter, sfilter->hzspace, CONVEDGE, (*curpos) - CONVEDGE,
		     buf1, buf2, pspace, dummyp);

    process_powers(sfilter, pmark, pspace, &best_pos, &certainty, &level);
    if (sfilter->debug & 2) {
	printf("CONV(%lu %u %lu):\n",
	       sfilter->framecount++, *curpos,
	       sfilter->framenr + *curpos - sfilter->prevread_size);
	for (i = 0; i < CONVEXTRA; i++)
	    printf(" %f", pmark[i]);
	printf("\n %d      ", level);
	for (i = 0; i < CONVEXTRA; i++)
	    printf(" %f", pspace[i]);
	printf("\n");
    }

    if (sfilter->prev_recv_level != level) {
	/*
	 * Check re-align on a 1->0 or 0->1 level transition.  You
	 * can't align on no transition because you have to have a
	 * boundary to check against.
	 */

	if (sfilter->prev_best_pos > CONVMIDDLE)
	    *curpos += 1;
	else if (sfilter->prev_best_pos < CONVMIDDLE)
	    *curpos -= 1;

	if (best_pos > CONVMIDDLE)
	    *curpos += 1;
	else if (best_pos < CONVMIDDLE)
	    *curpos -= 1;
    }
    sfilter->prev_recv_level = level;
    sfilter->prev_best_pos = best_pos;

    sfilter->wmsgsets[0].got_flag = false;
    for (i = 0; i < sfilter->max_wmsgs; i++)
	afskmdm_process_bit(sfilter, *curpos, 0, i, level, certainty, in_sync);

    for (wset = 1, m = 4.0; wset < sfilter->wmsg_sets; wset += 2, m += 4.0) {
	for (i = 0; i < CONVEXTRA; i++)
	    pmark2[i] = pmark[i] * m;
	certainty = 0.0;
	process_powers(sfilter, pmark2, pspace, &best_pos, &certainty, &level);
	sfilter->wmsgsets[wset].got_flag = false;
	for (i = 0; i < sfilter->max_wmsgs; i++)
	    afskmdm_process_bit(sfilter, *curpos, wset, i,
				level, certainty, in_sync);

	for (i = 0; i < CONVEXTRA; i++)
	    pspace2[i] = pspace[i] * m;
	certainty = 0.0;
	process_powers(sfilter, pmark, pspace2, &best_pos, &certainty, &level);
	sfilter->wmsgsets[wset + 1].got_flag = false;
	for (i = 0; i < sfilter->max_wmsgs; i++)
	    afskmdm_process_bit(sfilter, *curpos, wset + 1, i,
				level, certainty, in_sync);
    }
}

/*
 * Implement a basic 2nd-order IIR filter.
 */
static void
afskmdm_iir_filter(float *inbuf, float *outbuf, unsigned int nsamples,
		   unsigned int nchans, unsigned int chan,
		   float coefa[2], float coefb[3], float hold[2])
{
    unsigned int i;
    float tmp;

    for (i = chan; i < nsamples * nchans; i += nchans) {
	tmp = inbuf[i] + coefa[0] * hold[0] + coefa[1] * hold[1];
	outbuf[i] = tmp * coefb[0] + coefb[1] * hold[0] + coefb[2] * hold[1];
	hold[1] = hold[0];
	hold[0] = tmp;
    }
}

/*
 * Calculate 2nd order IIR filter coefficients for a low-pass
 * Butterworth filter.
 *
 * See https://www.staff.ncl.ac.uk/oliver.hinton/eee305/Chapter5.pdf
 * for more explaination.
 */
static void
afskmdm_calc_iir_coefs(float samplerate, float cutoff,
		       float coefa[], float coefb[])
{
    float w1 = 2 * M_PI * cutoff / samplerate;
    float w = tan(w1 / 2); /* omega */
    float denom = w * w + M_SQRT2 * w + 1;

    coefa[0] = - (2 * w * w - 2) / denom;
    coefa[1] = - (1 - M_SQRT2 * w + w * w) / denom;
    coefb[0] = (w * w) / denom;
    coefb[1] = 2 * coefb[0];
    coefb[2] = coefb[0];
}

static float
get_fir_val(unsigned int i, unsigned int holdsize, float *inbuf, float *hold,
	    unsigned int nchans, unsigned int chan)
{
    if (i < holdsize)
	return hold[i];
    i -= holdsize;
    i = (i * nchans) + chan;
    return inbuf[i];
}

/*
 * Process a buffer with a fir filter.  h and n come from
 * afskmdm_calc_fir_coefs(), hold must be of size n * 2.
 */
static void
afskmdm_fir_filter(float *inbuf, float *outbuf, unsigned int nsamples,
		   unsigned int nchans, unsigned int chan,
		   unsigned int n, float *h, float *hold)
{
    unsigned int i, j, k;
    unsigned int holdsize = n * 2;
    float tmp;

    for (i = 0; i < nsamples; i++) {

	/* Get the middle value, it's always multiplied by 1. */
	tmp = get_fir_val(n + i, holdsize, inbuf, hold, nchans, chan);

	/*
	 * The h array is half of a symmetric waveform.  That waveform
	 * is always an odd number of values, but we don't include the
	 * middle value (it's always one, handled above) and h only
	 * holds the left half of the waveform.
	 */
	for (j = 0, k = holdsize; j < n; j++, k--) {
	    tmp += h[j] * (get_fir_val(i + j, holdsize, inbuf, hold,
				       nchans, chan) +
			   get_fir_val(i + k, holdsize, inbuf, hold,
				       nchans, chan));
	}

	outbuf[i * nchans + chan] = tmp;
    }
    for (i = 0; i < holdsize; i++) {
	unsigned int pos = nsamples - holdsize + i;
	hold[i] = inbuf[pos * nchans + chan];
    }
}

/*
 * Calculate FIR filter coefficients for a lowpass filter with the
 * given transition band size, sample rate and cutoff frequency.
 * The total number of coefficients is:
 *
 *   N = (n * 2) + 1
 *
 * but the middle value is always 1 and the coefficients are symmetric
 * about the middle value.  Thus we only really need n values because
 * h[n] would be 1 and h[i] == h[N - i - 1].
 *
 * A hamming filter is applied to the coefficients.
 *
 * Adapted from http://www.labbookpages.co.uk/audio/firWindowing.html
 * and https://www.staff.ncl.ac.uk/oliver.hinton/eee305/Chapter4.pdf
 */
static float *
afskmdm_calc_fir_coefs(struct gensio_os_funcs *o,
		       double samplerate, double cutoff, double transband,
		       unsigned int *rn)
{
    double tba = transband / samplerate;
    double w = 2 * M_PI * cutoff / samplerate;
    unsigned int i;
    /* For a hamming filter, transition band ~ (3.3 / N). */
    unsigned int n = 3.3 / tba / 2;
    double N = n * 2 + 1;
    double dx = (n * 2) / (n * 2 - 1);
    double x = dx;
    float *h;

    h = o->zalloc(o, n * sizeof(float));
    if (!h)
	return NULL;

    for (i = n - 1; ; i--) {
	double tmp;

	/* h(x) = 2 * f * sinc() */
	tmp = sin(w * x) / (M_PI * x);

	/* Hamming window */
	tmp *= .54 - .46 * cos(2 * M_PI * (i + 1) / N);

	h[i] = tmp;

	if (i == 0)
	    break;
	x += dx;
    }
    *rn = n;
    return h;
}

static int
afskmdm_ll_write(struct gensio_filter *filter,
		 gensio_ll_filter_data_handler handler, void *cb_data,
		 gensiods *rcount,
		 unsigned char *buf, gensiods buflen,
		 const char *const *auxdata)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);
    unsigned int pos = sfilter->curr_in_pos;
    int err = 0;

    if (gensio_str_in_auxdata(auxdata, "oob")) {
	/* Ignore oob data. */
	if (rcount)
	    *rcount = buflen;
	return 0;
    }

    afskmdm_lock(sfilter);
    if (sfilter->err) {
	err = sfilter->err;
	goto out_err;
    }
    if (buflen == 0)
	goto try_deliver;

    if (buflen != (gensiods) sfilter->in_chunksize * sfilter->in_framesize)
	return GE_INVAL;

    if (sfilter->filteredbuf) {
	if (sfilter->fir_h) {
	    afskmdm_fir_filter((float *) buf, (float *) sfilter->filteredbuf,
			       sfilter->in_chunksize,
			       sfilter->in_nchans, sfilter->in_chan,
			       sfilter->fir_h_n, sfilter->fir_h,
			       sfilter->firhold);
	} else {
	    afskmdm_iir_filter((float *) buf, (float *) sfilter->filteredbuf,
			       sfilter->in_chunksize,
			       sfilter->in_nchans, sfilter->in_chan,
			       sfilter->coefa, sfilter->coefb,
			       sfilter->iirhold);
	}
	buf = sfilter->filteredbuf;
    }

    if (sfilter->debug & 2)
	printf("Processing frame %lu %d %u\n", sfilter->framenr,
	       sfilter->transmit_state, pos);
    if (sfilter->transmit_state > WAITING_TRANSMIT) {
	sfilter->curr_in_pos = sfilter->prevread_size;
	goto skip_processing;
    }
    while (pos < sfilter->in_chunksize + sfilter->in_convsize - CONVEDGE) {
	bool in_sync = true;

	afskmdm_check_for_data(sfilter, &pos, sfilter->prevread, buf, &in_sync);

	if (in_sync) {
	    sfilter->nr_in_sync++;
	} else {
	    if (sfilter->nr_in_sync > SYNC_RESET)
		sfilter->nr_in_sync = SYNC_RESET;
	    else if (sfilter->nr_in_sync > 0)
		sfilter->nr_in_sync--;
	    if (sfilter->nr_in_sync < IN_SYNC)
		sfilter->nr_out_sync++;
	}
	if (sfilter->nr_in_sync > IN_SYNC) {
	    sfilter->nr_out_sync = 0;
	} else {
	    sfilter->nr_out_sync++;
	    if (!sfilter->full_duplex &&
			sfilter->transmit_state == WAITING_TRANSMIT &&
			sfilter->nr_out_sync >= sfilter->tx_delay) {
		afskmdm_check_start_xmit(sfilter);
		if (sfilter->transmit_state > WAITING_TRANSMIT) {
		    sfilter->curr_in_pos = sfilter->prevread_size;
		    goto skip_processing;
		}
	    }
	}

	if (sfilter->debug & 2)
	    printf("SYNC: %d %u\n", in_sync, sfilter->nr_in_sync);

	sfilter->in_conv_counter++;
	if (sfilter->in_conv_counter >= sfilter->in_conv_period) {
	    pos += sfilter->in_conv_adj;
	    sfilter->in_conv_counter = 0;
	}
	pos += sfilter->in_convsize;
    }
    sfilter->curr_in_pos = pos - sfilter->in_chunksize;
 skip_processing:
    sfilter->framenr += sfilter->in_chunksize;

    memcpy(sfilter->prevread,
	   buf + (sfilter->in_framesize *
		  (sfilter->in_chunksize - sfilter->prevread_size)),
	   (size_t) sfilter->prevread_size * sfilter->in_framesize);

 try_deliver:
    if (sfilter->deliver_data_len > 0) {
	gensiods count = 0;

	afskmdm_unlock(sfilter);
	err = handler(cb_data, &count,
		      sfilter->deliver_data + sfilter->deliver_data_pos,
		      sfilter->deliver_data_len - sfilter->deliver_data_pos,
		      NULL);
	afskmdm_lock(sfilter);
	if (!err) {
	    if (count + sfilter->deliver_data_pos >= sfilter->deliver_data_len)
		sfilter->deliver_data_len = 0;
	    else
		sfilter->deliver_data_pos += count;
	}
    }
 out_err:
    afskmdm_unlock(sfilter);
    if (!err && rcount)
	*rcount = buflen;
    return err;
}

static int
afskmdm_setup(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static void
afskmdm_cleanup(struct gensio_filter *filter)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);
    unsigned int i, j;

    if (sfilter->key_io)
	gensio_close(sfilter->key_io, NULL, NULL);
    sfilter->key_io_state = KEY_CLOSED;
    sfilter->key_err = 0;
    sfilter->prev_xmit_level = -1;
    sfilter->prev_recv_level = 0;
    for (i = 0; i < sfilter->wmsg_sets; i++) {
	sfilter->wmsgsets[i].wmsgs[0].in_use = true;
	sfilter->wmsgsets[i].wmsgs[0].read_data_len = 0;
	sfilter->wmsgsets[i].wmsgs[0].num_uncertain = 0;
	sfilter->wmsgsets[i].wmsgs[0].certainty = 0.0;
	sfilter->wmsgsets[i].wmsgs[0].state = AFSKMDM_STATE_PREAMBLE_FIRST_0;
	for (j = 1; j < sfilter->max_wmsgs; j++)
	    sfilter->wmsgsets[i].wmsgs[j].in_use = false;
	sfilter->wmsgsets[i].curr_wmsgs = 1;
    }
    sfilter->curr_in_pos = sfilter->prevread_size;
    sfilter->deliver_data_len = 0;
    sfilter->xmit_buf_len = 0;
    sfilter->xmit_buf_pos = 0;
    sfilter->nr_wrbufs = 0;
    sfilter->in_conv_counter = 0;
    sfilter->out_bit_counter = 0;
}

static void
afskmdm_sfilter_free(struct afskmdm_filter *sfilter)
{
    struct gensio_os_funcs *o = sfilter->o;
    unsigned int i, j;
    struct xmit_entry *e = sfilter->xmit_ent_list, *n;

    while (e) {
	n = e->next;
	o->free(o, e);
	e = n;
    }
    if (sfilter->mark_xmit)
	o->free(o, sfilter->mark_xmit);
    if (sfilter->space_xmit)
	o->free(o, sfilter->space_xmit);
    if (sfilter->key_io)
	gensio_free(sfilter->key_io);
    if (sfilter->key)
	o->free(o, sfilter->key);
    if (sfilter->keyon)
	o->free(o, sfilter->keyon);
    if (sfilter->keyoff)
	o->free(o, sfilter->keyoff);
    if (sfilter->lock)
	o->free_lock(sfilter->lock);
    if (sfilter->hzmark)
	o->free(o, sfilter->hzmark);
    if (sfilter->hzspace)
	o->free(o, sfilter->hzspace);
    if (sfilter->prevread)
	o->free(o, sfilter->prevread);
    if (sfilter->wmsgsets) {
	for (i = 0; i < sfilter->wmsg_sets; i++) {
	    if (sfilter->wmsgsets[i].wmsgs) {
		for (j = 0; j < sfilter->max_wmsgs; j++) {
		    if (sfilter->wmsgsets[i].wmsgs[j].read_data)
			o->free(o, sfilter->wmsgsets[i].wmsgs[j].read_data);
		}
	    }
	    o->free(o, sfilter->wmsgsets[i].wmsgs);
	}
	o->free(o, sfilter->wmsgsets);
    }
    if (sfilter->deliver_data)
	o->free(o, sfilter->deliver_data);
    if (sfilter->xmit_buf)
	o->free(o, sfilter->xmit_buf);
    for (i = 0; i < NR_WRITE_BUFS; i++) {
	if (sfilter->wrbufs[i].data)
	    o->free(o, sfilter->wrbufs[i].data);
    }
    if (sfilter->filteredbuf)
	o->free(o, sfilter->filteredbuf);
    if (sfilter->fir_h)
	o->free(o, sfilter->fir_h);
    if (sfilter->firhold)
	o->free(o, sfilter->firhold);
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    o->free(o, sfilter);
}

static void
afskmdm_free(struct gensio_filter *filter)
{
    struct afskmdm_filter *sfilter = filter_to_afskmdm(filter);

    return afskmdm_sfilter_free(sfilter);
}

static int
afskmdm_filter_control(struct gensio_filter *filter, bool get, int op,
		       char *data, gensiods *datalen)
{
    return GE_NOTSUP;
}

static int gensio_afskmdm_filter_func(struct gensio_filter *filter, int op,
				      void *func, void *data,
				      gensiods *count,
				      void *buf, const void *cbuf,
				      gensiods buflen,
				      const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	afskmdm_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_TIMEOUT:
	return afskmdm_timeout_done(filter);

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return afskmdm_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return afskmdm_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return afskmdm_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_UL_CAN_WRITE:
	return afskmdm_ul_can_write(filter, data);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return afskmdm_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return afskmdm_try_connect(filter, data, buflen);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return afskmdm_try_disconnect(filter, data, buflen);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return afskmdm_ul_write(filter, func, data, count, cbuf, buflen, buf);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return afskmdm_ll_write(filter, func, data, count, buf, buflen, NULL);

    case GENSIO_FILTER_FUNC_SETUP:
	return afskmdm_setup(filter, data);

    case GENSIO_FILTER_FUNC_CLEANUP:
	afskmdm_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	afskmdm_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return afskmdm_filter_control(filter, *((bool *) cbuf), buflen, data,
				  count);

    default:
	return GE_NOTSUP;
    }
}

static unsigned int
afskmdm_find_wave_pos(float *wave, unsigned int wave_size,
		      float v, bool ascend, unsigned int size)
{
    unsigned int i;

    for (i = 0; i < wave_size - size; i++) {
	if (wave[i] <= wave[i + 1] && wave[i + 1] >= wave[i + 2]) {
	    /* At a peak. */
	    if (v > wave[i + 1])
		break;
	}
	if (wave[i] >= wave[i + 1] && wave[i + 1] <= wave[i + 2]) {
	    /* At a trough */
	    if (v < wave[i + 1])
		break;
	}
	if (ascend) {
	    if (v >= wave[i] && v <= wave[i + 1]) {
		float avg = (wave[i] + wave[i + 1]) / 2;
		if (v > avg)
		    i++;
		break;
	    }
	} else {
	    if (v <= wave[i] && v >= wave[i + 1]) {
		float avg = (wave[i] + wave[i + 1]) / 2;
		if (v < avg)
		    i++;
		break;
	    }
	}
    }
    return i;
}

static int afskmdm_setup_xmit_ent(struct afskmdm_filter *sfilter,
				  struct xmit_entry *e);

static struct xmit_entry *
afskmdm_create_xmit_ent(struct afskmdm_filter *sfilter, bool is_mark,
			unsigned int pos, float *data, unsigned int size)
{
    struct xmit_entry *e;

    e = sfilter->o->zalloc(sfilter->o, sizeof(*e));
    if (!e)
	return NULL;
    e->data = data;
    e->size = size;
    e->is_mark = is_mark;
    e->next = sfilter->xmit_ent_list;
    sfilter->xmit_ent_list = e;

    if (afskmdm_setup_xmit_ent(sfilter, e))
	return NULL;

    return e;
}

static struct xmit_entry *
afskmdm_find_xmit_ent(struct afskmdm_filter *sfilter, bool is_mark,
		      float v, bool ascend, unsigned int size)
{
    struct xmit_entry *e = sfilter->xmit_ent_list;
    float *wave;
    unsigned int wave_size, pos;

    if (is_mark) {
	wave = sfilter->mark_xmit;
	wave_size = sfilter->mark_xmit_len;
    } else {
	wave = sfilter->space_xmit;
	wave_size = sfilter->space_xmit_len;
    }

    pos = afskmdm_find_wave_pos(wave, wave_size, v, ascend, size);
    if (pos >= wave_size - size)
	return NULL;

    for(; e; e = e->next) {
	if (is_mark != e->is_mark)
	    continue;
	if (size != e->size)
	    continue;
	if (wave + pos == e->data)
	    break;
    }
    if (!e)
	e = afskmdm_create_xmit_ent(sfilter, is_mark, pos, wave + pos, size);
    return e;
}

static int
afskmdm_setup_xmit_ent(struct afskmdm_filter *sfilter, struct xmit_entry *e)
{
    /*
     * We index one of the end of e->data, but the array it points to
     * has entries there, and it's the next value we want.
     */
    float v = e->data[e->size];
    bool ascend = v > e->data[e->size - 1];
    struct xmit_entry *ne;
    unsigned int size = sfilter->out_bitsize;

    ne = afskmdm_find_xmit_ent(sfilter, false, v, ascend, size);
    if (!ne)
	return GE_NOMEM;
    e->next_send[0] = ne;

    ne = afskmdm_find_xmit_ent(sfilter, true, v, ascend, size);
    if (!ne)
	return GE_NOMEM;
    e->next_send[1] = ne;

    if (sfilter->out_bit_adj == 0)
	return 0;

    size += sfilter->out_bit_adj;
    ne = afskmdm_find_xmit_ent(sfilter, false, v, ascend, size);
    if (!ne)
	return GE_NOMEM;
    e->next_send[2] = ne;

    ne = afskmdm_find_xmit_ent(sfilter, true, v, ascend, size);
    if (!ne)
	return GE_NOMEM;
    e->next_send[3] = ne;

    return 0;
}

struct gensio_afskmdm_data {
    unsigned int in_nchans;
    unsigned int in_chan;
    unsigned int out_nchans;
    unsigned int out_chans;
    gensiods max_read_size;
    gensiods max_write_size;
    float mark_freq;
    float space_freq;
    unsigned int data_rate;
    unsigned int debug;
    unsigned int in_framerate;
    unsigned int out_framerate;
    unsigned int in_chunksize;
    unsigned int out_chunksize;
    unsigned int max_wmsgs;
    unsigned int wmsg_sets;
    float min_certainty;

    int filt_type;
#define NO_FILT 0
#define IIR_FILT 1
#define FIR_FILT 2
    bool filt_type_set;
    unsigned int lpcutoff;
    unsigned int transition_freq;

    unsigned int tx_preamble_time;
    unsigned int tx_postamble_time;
    unsigned int tx_predelay_time;
    float volume;
    const char *key;
    const char *keyon;
    const char *keyoff;
    bool full_duplex;
};

static int
afskmdm_setup_transmit(struct afskmdm_filter *sfilter,
		       struct gensio_afskmdm_data *data,
		       float fbitsize)
{
    struct gensio_os_funcs *o = sfilter->o;
    unsigned int i;
    struct xmit_entry *e;

    sfilter->mark_xmit_len = data->out_framerate / data->mark_freq * 2 + 1;
    if (sfilter->mark_xmit_len < 2 * sfilter->out_bitsize + 1)
	sfilter->mark_xmit_len = 2 * sfilter->out_bitsize + 1;
    sfilter->mark_xmit = o->zalloc(o, sizeof(float) * sfilter->mark_xmit_len);
    if (!sfilter->mark_xmit)
	return GE_NOMEM;
    for (i = 0; i < sfilter->mark_xmit_len; i++) {
	float v = 2 * M_PI * (data->mark_freq / data->data_rate) * ((float) i);
	sfilter->mark_xmit[i] = sin(v / fbitsize) * data->volume;
    }

    sfilter->space_xmit_len = data->out_framerate / data->space_freq * 2 + 1;
    if (sfilter->space_xmit_len < 2 * sfilter->out_bitsize + 1)
	sfilter->space_xmit_len = 2 * sfilter->out_bitsize + 1;
    sfilter->space_xmit = o->zalloc(o, sizeof(float) * sfilter->space_xmit_len);
    if (!sfilter->space_xmit)
	return GE_NOMEM;
    for (i = 0; i < sfilter->space_xmit_len; i++) {
	float v = 2 * M_PI * (data->space_freq / data->data_rate) * ((float) i);
	sfilter->space_xmit[i] = sin(v / fbitsize) * data->volume;
    }

    /* Set up the first entry, just start with a space at zero phase. */
    e = o->zalloc(o, sizeof(*e));
    if (!e)
	return GE_NOMEM;
    e->data = sfilter->space_xmit;
    e->size = sfilter->out_bitsize;
    e->is_mark = false;
    e->next = NULL;
    sfilter->xmit_ent_list = e;
    sfilter->curr_xmit_ent = e;

    return afskmdm_setup_xmit_ent(sfilter, e);
}

static struct gensio_filter *
gensio_afskmdm_filter_raw_alloc(struct gensio_os_funcs *o,
				struct gensio_afskmdm_data *data)
{
    struct afskmdm_filter *sfilter;
    unsigned int i, j;
    float fconvsize, fbitsize;

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return NULL;

    sfilter->o = o;
    sfilter->in_nchans = data->in_nchans;
    sfilter->out_nchans = data->out_nchans;
    sfilter->in_chan = data->in_chan;
    sfilter->out_chans = data->out_chans;
    sfilter->in_framesize = sizeof(float) * data->in_nchans;
    sfilter->out_framesize = sizeof(float) * data->out_nchans;
    sfilter->max_write_size = data->max_write_size;
    sfilter->max_read_size = data->max_read_size + 2; /* Extra 2 for the CRC. */
    sfilter->debug = data->debug;
    sfilter->prev_xmit_level = -1;
    sfilter->prev_recv_level = 0;
    sfilter->in_chunksize = data->in_chunksize;
    sfilter->out_chunksize = data->out_chunksize;
    sfilter->max_wmsgs = data->max_wmsgs;
    sfilter->wmsg_sets = data->wmsg_sets;
    sfilter->min_certainty = data->min_certainty;
    sfilter->tx_preamble_time = GENSIO_MSECS_TO_NSECS(data->tx_preamble_time);
    sfilter->tx_postamble_time = GENSIO_MSECS_TO_NSECS(data->tx_postamble_time);
    sfilter->tx_predelay_time = GENSIO_MSECS_TO_NSECS(data->tx_predelay_time);
    sfilter->full_duplex = data->full_duplex;
    if (data->key) {
	sfilter->key = gensio_strdup(o, data->key);
	if (!sfilter->key)
	    goto out_nomem;
    }
    if (data->keyon) {
	sfilter->keyon = gensio_strdup(o, data->keyon);
	if (!sfilter->keyon)
	    goto out_nomem;
    }
    if (data->keyoff) {
	sfilter->keyoff = gensio_strdup(o, data->keyoff);
	if (!sfilter->keyoff)
	    goto out_nomem;
    }

    /*
     * Calculate the size of the convolution we will be doing.  We
     * round the size to the nearest integer.  We create the
     * convolution tables with the actual floating point value, and we
     * use that for adjust calculation, so get that here, too.
     */
    sfilter->in_convsize = ((data->in_framerate + data->data_rate / 2)
			    / data->data_rate);
    sfilter->in_conv_time = (GENSIO_SECS_TO_NSECS(sfilter->in_convsize) /
			     data->in_framerate);
    fconvsize = (float) data->in_framerate / data->data_rate;
    if (data->in_framerate % data->data_rate != 0) {
	/*
	 * Calculate how often to adjust for the frame rate not being
	 * evenly divisible by the data rate.  If we rounded convsize
	 * up, then it needs to be adjusted down periodically,
	 * otherwise we adjust up.
	 *
	 * Then take 1 divided by the distance from the ideal value,
	 * and that should give how often we need to adjust.  This may
	 * not be really exact, but for all practical values it works
	 * out well, and the auto-adjusting should keep us in sync as
	 * long as this is close.
	 */
	float err = fconvsize - truncf(fconvsize);

	if (sfilter->in_convsize > data->in_framerate / data->data_rate) {
	    /* We rounded up. */
	    err = 1. - err;
	    sfilter->in_conv_adj = -1;
	} else {
	    sfilter->in_conv_adj = 1;
	}
	sfilter->in_conv_period = (unsigned int) ((1. / err) + 0.5);
    }

    sfilter->out_bitsize = ((data->out_framerate + data->data_rate / 2)
			    / data->data_rate);
    sfilter->out_bit_time = (GENSIO_SECS_TO_NSECS(sfilter->out_bitsize) /
			     data->out_framerate);
    fbitsize = (float) data->out_framerate / data->data_rate;
    sfilter->max_out_bitsize = sfilter->out_bitsize;
    if (data->out_framerate % data->data_rate != 0) {
	/*
	 * Calculate how often to adjust for the frame rate not being
	 * evenly divisible by the data rate.  If we rounded convsize
	 * up, then it needs to be adjusted down periodically,
	 * otherwise we adjust up.
	 *
	 * Then take 1 divided by the distance from the ideal value,
	 * and that should give how often we need to adjust.  This may
	 * not be really exact, but for all practical values it works
	 * out well, and the auto-adjusting should keep us in sync as
	 * long as this is close.
	 */
	float err = fbitsize - truncf(fbitsize);

	if (sfilter->out_bitsize > data->out_framerate / data->data_rate) {
	    /* We rounded up. */
	    err = 1. - err;
	    sfilter->out_bit_adj = -1;
	} else {
	    sfilter->out_bit_adj = 1;
	    sfilter->max_out_bitsize++;
	}
	sfilter->out_bit_period = (unsigned int) ((1. / err) + 0.5);
    }

    /*
     * NOTE - this is in received conv periods, because it's measured
     * in the receive portion.
     */
    sfilter->tx_delay = sfilter->tx_predelay_time / sfilter->in_conv_time;

    sfilter->lock = o->alloc_lock(o);
    if (!sfilter->lock)
	goto out_nomem;

    sfilter->hzmark = o->zalloc(o, sizeof(float) * 4 * sfilter->in_convsize);
    if (!sfilter->hzmark)
	goto out_nomem;
    for (i = 0; i < 2 * sfilter->in_convsize; i++) {
	float v = 2 * M_PI * (data->mark_freq / data->data_rate) * ((float) i);
	sfilter->hzmark[i] = sin(v / fconvsize);
	sfilter->hzmark[i + 2 * sfilter->in_convsize] = cos(v / fconvsize);
    }

    sfilter->hzspace = o->zalloc(o, sizeof(float) * 4 * sfilter->in_convsize);
    if (!sfilter->hzspace)
	goto out_nomem;
    for (i = 0; i < 2 * sfilter->in_convsize; i++) {
	float v = 2 * M_PI * (data->space_freq / data->data_rate) * ((float) i);
	sfilter->hzspace[i] = sin(v / fconvsize);
	sfilter->hzspace[i + 2 * sfilter->in_convsize] = cos(v / fconvsize);
    }

    if (data->lpcutoff && data->filt_type != NO_FILT) {
	if (data->filt_type == IIR_FILT) {
	    afskmdm_calc_iir_coefs(data->in_framerate, data->lpcutoff,
				   sfilter->coefa, sfilter->coefb);
	} else {
	    sfilter->fir_h =
		afskmdm_calc_fir_coefs(o, data->in_framerate, data->lpcutoff,
				       data->transition_freq,
				       &sfilter->fir_h_n);
	    if (!sfilter->fir_h)
		goto out_nomem;
	    sfilter->firhold = o->zalloc(o,
					 2 * sfilter->fir_h_n * sizeof(float));
	    if (!sfilter->firhold)
		goto out_nomem;
	}

	sfilter->filteredbuf = o->zalloc(o,
		(gensiods) sfilter->in_framesize * sfilter->in_chunksize);
	if (!sfilter->filteredbuf)
	    goto out_nomem;
    }

    sfilter->prevread_size = sfilter->in_convsize * 2 + CONVEDGE;
    sfilter->prevread = o->zalloc(o,
		(gensiods) sfilter->in_framesize * sfilter->prevread_size);
    if (!sfilter->prevread)
	goto out_nomem;
    sfilter->curr_in_pos = sfilter->prevread_size;

    sfilter->wmsgsets = o->zalloc(o, (sizeof(struct wmsgset) *
				      sfilter->wmsg_sets));
    for (i = 0; i < sfilter->wmsg_sets; i++) {
	sfilter->wmsgsets[i].wmsgs =
	    o->zalloc(o, sizeof(struct wmsg) * sfilter->max_wmsgs);
	if (!sfilter->wmsgsets[i].wmsgs)
	    goto out_nomem;
	for (j = 0; j < sfilter->max_wmsgs; j++) {
	    sfilter->wmsgsets[i].wmsgs[j].read_data =
		o->zalloc(o, sfilter->max_read_size);
	    if (!sfilter->wmsgsets[i].wmsgs[j].read_data)
		goto out_nomem;
	}
	sfilter->wmsgsets[i].wmsgs[0].in_use = true;
	sfilter->wmsgsets[i].wmsgs[0].state = AFSKMDM_STATE_PREAMBLE_FIRST_0;
	sfilter->wmsgsets[i].curr_wmsgs = 1;
    }

    sfilter->deliver_data = o->zalloc(o, sfilter->max_read_size);
    if (!sfilter->deliver_data)
	goto out_nomem;

    for (i = 0; i < NR_WRITE_BUFS; i++) {
	/* Add 2 to allow for the CRC to be added. */
	sfilter->wrbufs[i].data = o->zalloc(o, sfilter->max_write_size + 2);
	if (!sfilter->wrbufs[i].data)
	    goto out_nomem;
    }

    sfilter->max_xmit_buf = sfilter->out_chunksize;
    sfilter->xmit_buf = o->zalloc(o,
		(gensiods) sfilter->out_chunksize * sfilter->out_framesize);
    if (!sfilter->xmit_buf)
	goto out_nomem;

    sfilter->filter = gensio_filter_alloc_data(o, gensio_afskmdm_filter_func,
					       sfilter);
    if (!sfilter->filter)
	goto out_nomem;

    sfilter->nsec_per_frame = (((float) 1) / (float) data->out_framerate *
			       (float) GENSIO_NSECS_IN_SEC);
    if (afskmdm_setup_transmit(sfilter, data, fbitsize))
	goto out_nomem;

    if (sfilter->key) {
	int err = str_to_gensio(sfilter->key, o, key_cb, sfilter,
				&sfilter->key_io);
	if (err)
	    goto out_nomem;
    }

    return sfilter->filter;

 out_nomem:
    afskmdm_sfilter_free(sfilter);
    return NULL;
}

static int
afskmdm_child_getuint(struct gensio *child, int option, unsigned int *val)
{
    int err;
    char cdata[30];
    gensiods cdata_len;

    cdata_len = sizeof(cdata);
    err = gensio_control(child, GENSIO_CONTROL_DEPTH_FIRST, true, option,
			 cdata, &cdata_len);
    if (err)
	return err;
    *val = strtoul(cdata, NULL, 0);
    return 0;
}

static struct gensio_enum_val filttype_enums[] = {
    { .name = "none", .val = NO_FILT },
    { .name = "iir", .val = IIR_FILT },
    { .name = "fir", .val = FIR_FILT },
    { }
};

int
gensio_afskmdm_filter_alloc(struct gensio_os_funcs *o,
			    struct gensio *child,
			    const char * const args[],
			    struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    struct gensio_afskmdm_data data = {
	.in_nchans = 0,
	.in_chan = 0,
	.out_nchans = 0,
	.out_chans = 1,
	.max_read_size = 256,
	.max_write_size = 256,
	.mark_freq = 1200.,
	.space_freq = 2200.,
	.data_rate = 1200,
	.in_framerate = 0,
	.out_framerate = 0,
	.in_chunksize = 0,
	.out_chunksize = 0,
	.max_wmsgs = 32,
	.wmsg_sets = 3,
	.min_certainty = 3.5,
	.filt_type = IIR_FILT,
	.filt_type_set = false,
	.lpcutoff = 2500,
	.transition_freq = 500,
	.tx_preamble_time = 300,
	.tx_postamble_time = 100,
	.tx_predelay_time = 500,
	.volume = .75,
	.full_duplex = false,
    };
    unsigned int i;
    int err;
    char cdata[30];
    gensiods cdata_len;
    unsigned int chan;
    unsigned int wmsg_extra = 1;

    err = afskmdm_child_getuint(child, GENSIO_CONTROL_IN_BUFSIZE,
				&data.in_chunksize);
    if (err)
	return GE_INCONSISTENT;

    err = afskmdm_child_getuint(child, GENSIO_CONTROL_OUT_BUFSIZE,
				&data.out_chunksize);
    if (err)
	return GE_INCONSISTENT;

    /* Don't care if these fail, we will check later. */
    afskmdm_child_getuint(child, GENSIO_CONTROL_IN_RATE,
			  &data.in_framerate);
    afskmdm_child_getuint(child, GENSIO_CONTROL_OUT_RATE,
			  &data.out_framerate);
    afskmdm_child_getuint(child, GENSIO_CONTROL_IN_NR_CHANS,
			  &data.in_nchans);
    afskmdm_child_getuint(child, GENSIO_CONTROL_OUT_NR_CHANS,
			  &data.out_nchans);

    cdata_len = sizeof(cdata);
    err = gensio_control(child, GENSIO_CONTROL_DEPTH_FIRST, true,
			 GENSIO_CONTROL_IN_FORMAT, cdata, &cdata_len);
    if (err || strcmp(cdata, "float") != 0)
	return GE_INCONSISTENT;

    cdata_len = sizeof(cdata);
    err = gensio_control(child, GENSIO_CONTROL_DEPTH_FIRST, true,
			 GENSIO_CONTROL_OUT_FORMAT, cdata, &cdata_len);
    if (err || strcmp(cdata, "float") != 0)
	return GE_INCONSISTENT;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &data.max_read_size) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "writebuf", &data.max_write_size) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "nchans", &data.in_nchans) > 0) {
	    data.out_nchans = data.in_nchans;
	    continue;
	}
	if (gensio_check_keyuint(args[i], "in_nchans", &data.in_nchans) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "out_nchans", &data.out_nchans) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "chan", &data.in_chan) > 0) {
	    data.out_chans = 1 << data.in_chan;
	    continue;
	}
	if (gensio_check_keyuint(args[i], "in_chan", &data.in_chan) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "out_chans", &data.out_chans) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "out_chan", &chan) > 0) {
	    data.out_chans = 1 << chan;
	    continue;
	}
	if (gensio_check_keyuint(args[i], "samplerate",
				 &data.in_framerate) > 0) {
	    data.out_framerate = data.in_framerate;
	    continue;
	}
	if (gensio_check_keyuint(args[i], "in_samplerate",
				 &data.in_framerate) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "out_samplerate",
				 &data.in_framerate) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "wmsgs", &data.max_wmsgs) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "wmsg-extra", &wmsg_extra) > 0)
	    continue;
	if (gensio_check_keyfloat(args[i], "min-certainty",
				  &data.min_certainty) > 0)
	    continue;
	if (gensio_check_keyenum(args[i], "filttype", filttype_enums,
				 &data.filt_type) > 0) {
	    data.filt_type_set = true;
	    continue;
	}
	if (gensio_check_keyuint(args[i], "lpcutoff", &data.lpcutoff) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "trfreq", &data.transition_freq) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "tx-preamble",
				 &data.tx_preamble_time) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "tx-tail",
				 &data.tx_postamble_time) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "tx-predelay",
				 &data.tx_predelay_time) > 0)
	    continue;
	if (gensio_check_keyfloat(args[i], "volume", &data.volume) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "key", &data.key) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "keyon", &data.keyon) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "keyoff", &data.keyoff) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "full-duplex", &data.full_duplex) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "debug", &data.debug) > 0)
	    continue;
	return GE_INVAL;
    }

    if (data.in_framerate == 0 || data.out_framerate == 0 ||
		data.in_chunksize == 0 || data.out_chunksize == 0 ||
		data.in_nchans == 0 || data.out_nchans == 0 ||
		data.in_chan >= data.in_nchans ||
		data.out_chans >= (1 << data.out_nchans) ||
		data.max_wmsgs == 0)
	return GE_INVAL;

    if (data.key && (!data.keyon || !data.keyoff))
	return GE_INVAL;

    /*
     * For lower sample rates a FIR filter doesn't use as much CPU and
     * is much more effective.  For higher sample rates, the IIR
     * filter uses a lot less CPU and works just as well.
     */
    if (!data.filt_type_set) {
	if (data.in_framerate < 30000)
	    data.filt_type = FIR_FILT;
	else
	    data.filt_type = IIR_FILT;
    }

    data.wmsg_sets = wmsg_extra * 2 + 1;

    filter = gensio_afskmdm_filter_raw_alloc(o, &data);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}
