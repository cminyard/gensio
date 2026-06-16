/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2022  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <gensio/gensio_err.h>

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <complex.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_time.h>
#include <gensio/gensio_ax25_addr.h>

/* Dump parameters. */
#define GENSIO_FSK_DEBUG_DUMP_PARMS	0x40

/* Send filtered output to a file named "t1". */
#define GENSIO_FSK_DEBUG_OUTPUT_FILTERED	0x20

/* Add timestamps to messages. */
#define GENSIO_FSK_DEBUG_TIME	0x10

/* Dump full received/sent messages. */
#define GENSIO_FSK_DEBUG_MSG	0x08

/* Dump some state handing information. */
#define GENSIO_FSK_DEBUG_STATE	0x04

/* Dump raw bit handling information. */
#define GENSIO_FSK_DEBUG_BIT_HNDL	0x02

/* Dump raw messages */
#define GENSIO_FSK_DEBUG_RAW_MSG	0x01

/*
 * This filter implements a frequency shift keying modem.
 *
 * The filter processes data from the child in bitsize frame chunks.
 * This bitsize will be in_framerate/data_rate, so bitsize samples
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
 * The receiver works in a work buffer that is (bitsize + 2 * workedge)
 * samples long.  A DFT bin operation works on bitsize size, but a DFT
 * is calculated multiple times over the whole work buffer starting on
 * successive samples, so you end up with (2 * workedge + 1) power
 * samples.  If workedge is 3 and bitsize is n, you end up with
 * something like:
 *
 *  [0|1|2|3|4|5|6 ........ n-1|n+0|n+1|n+2|n+3|n+4|n+5]
 *   |______power[0]__________|
 *     |________power[1]__________|
 *       |_________power[2]___________|
 *         |_________power[3]_____________|
 *           |__________power[4]______________|
 *             |____________power[5]______________|
 *               |______________power[6]______________|
 *
 * The first 3 samples are the last 3 samples from the previous bit.
 * The current bits is samples 3 to n+2.  The last 3 samples are the
 * first 3 samples of the next bit.  If the bit is exactly aligned, it
 * will be in samples 3 to n+2.  If it is not, and the frequency
 * changes, you can use the different power levels calculated here to
 * see where the power starts dropping off, letting the receiver
 * adjust the alignment of the incoming data.
 *
 * The receiver is constantly looking for a mark (level 1) and a space
 * (level 0).  If it finds a 0 in this mode, it just then looks for 6
 * 1's in a row.  Then, if the next bit is 0, it starts receiving data
 * for the message.  This sequence will also terminate a message.
 *
 * The code keeps track of multiple possible incoming messages at a
 * time.  If a bit is read that is uncertain (the difference between
 * mark and space are not significant), it will split off a new
 * working message for each current message, one with each bit
 * possibility.  If a current working message is determined to be
 * invalid or done, it is returned to the pool.  The preamble of flags
 * should clear out all the working messages to make it a clean slate
 * for a starting message.
 */

enum fsk_state {
    /* Looking for a '0' to start the preamble. */
    FSK_STATE_PREAMBLE_SEARCH_0,

    /* In the preamble (01111110), found a 0, looking for a '1'. */
    FSK_STATE_PREAMBLE_FIRST_0,

    /* In the preamble, looking for 6 1's in a row. */
    FSK_STATE_PREAMBLE_1,

    /* In the preamble, found 0111111, looking for the last 0. */
    FSK_STATE_PREAMBLE_LAST_0,

    /* Currently in a message. */
    FSK_STATE_IN_MSG,

    /* Got 6 1's in a row while in msg, looking for a 0. */
    FSK_STATE_POSTAMBLE_LAST_0
};

/*
 * This is the maximum adjust period we will allow.  If it reaches
 * this value, we assume that the small adjustments can be handled by
 * the standard alignment adjustment.
 */
#define ADJ_PERIOD 10

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

    enum fsk_state state;

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
    unsigned char *raw_uncertainty;
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
 * out_bitsize or out_bitsize +/- 1 for the alternate size that may be
 * periodically sent).
 *
 * It also has pointers to the next entry to send based upon if the
 * next entry is a mark or space and if the next entry is out_bitsize or
 * out_bitsize +/- 1.
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

/* IIR and FIR filter code. */
#include "filters.h"

/* Code for handling the transmitter keying. */
#include "xmitkey.h"

enum fsk_format { FSK_FMT_NONE, FSK_FMT_FLOAT, FSK_FMT_FLOATC };

struct fsk_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    int err;

    bool rx;
    bool tx;

    unsigned int in_nchans;
    unsigned int in_chan;
    unsigned int out_nchans;
    unsigned int out_chans;
    unsigned int in_framesize; /* Size of a (sample * nchans) in bytes. */
    unsigned int out_framesize; /* Size of a (sample * nchans) in bytes. */
    unsigned int in_samplesize; /* Size of a sample in bytes. */
    unsigned int out_samplesize; /* Size of a sample in bytes. */
    unsigned int in_bufsize; /* Frame count we get from the sound gensio. */
    unsigned int out_bufsize; /* Frame count we send to the sound gensio. */
    enum fsk_format in_format;
    enum fsk_format out_format;
    bool full_duplex;

    unsigned int nsec_per_frame;

    /*
     * Sending parameters;
     */
    uint64_t tx_preamble_time;
    uint64_t tx_postamble_time;
    uint64_t tx_predelay_time;

    /*
     * Frames in a single bit.  The DFT calculation is done on this
     * size, and transmit is done using this size.  Note that the bit
     * size may not exactly match up with the period of the data rate.
     * If that is the case, then we will need to periodically adjust
     * the window to keep it aligned.
     */
    unsigned int in_bitsize;
    int in_adj; /* +1, 0, or -1 */
    unsigned int in_adj_period; /* How often to add in_adj. */
    unsigned int in_adj_counter; /* Current receive counter for in_adj. */
    uint64_t in_adj_time; /* Time in nsec for a bitsize to be received. */
    int maxadj; /* Maximum we can adjust the frame for alignment. */

    /*
     * The number of frames in a transmitted bit.  A similar
     * technique is used for sending, there are two send sizes if
     * out_bit_adj != 0 and out_bit_period says how often we use the
     * alternate one.
     */
    unsigned int out_bitsize;
    int out_bit_adj;
    unsigned int max_out_bitsize; /* Largest entry we will send. */
    unsigned int out_bit_counter; /* Counter for out_bit_period */
    unsigned int out_bit_period; /* How often to do an alternate frame size. */
    uint64_t out_bit_time; /* Time in nsec for a bitsize to be sent. */

    unsigned int debug;
    bool check_ax25;
    bool do_crc;
    bool do_raw;
    bool in_do_inv;
    bool out_do_inv;
    bool in_do_diff;
    bool out_do_diff;
    bool do_uncert;
    float certainty_multiplier;
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
    unsigned char *deliver_raw_uncertainty;
    gensiods deliver_data_pos;
    gensiods deliver_data_len;

    /* Low pass filter components, IIR and FIR. */
    struct filterinfo lpfilt;
    /* Filtered data. */
    float *lpfilteredbuf;

    /* High pass filter components, IIR only. */
    struct filterinfo hpfilt;
    /* Filtered data. */
    float *hpfilteredbuf;

    /* Copy data in from the external data to the working buffer. */
    void (*do_frame_in_copy)(float *dest, gensiods destpos,
			     float *src, gensiods srcpos,
			     unsigned int nchans, unsigned int chan,
			     gensiods count);

    /* Function to calculate DFT bins, either real or complex versions. */
    void (*do_dftbin)(struct fsk_filter *sfilter, float *dftbin,
		      float *buf, float *power, float *maxp);

    /*
     * DFT tables.  First 2 * in_bitsize values is sine, second 2 *
     * in_bitsize values is cosine.
     */
#define MAX_HZ_BINS 7
    float *hzbin[MAX_HZ_BINS];
    unsigned int nr_hz_bins;

    /*
     * Storage for power measurements, each workextra samples long.
     */
    float *pmeas[MAX_HZ_BINS];
    float *pmark2;
    float *pspace2;

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
     * Buffer holding data being currently processed.  It is
     * (in_bitsize + (2 * workedge)) bytes long.
     */
    float *workbuf;
    unsigned int worksize;

    /*
     * Current position in the processed data workbuf above, this is
     * the amount of data left over from the previous processing.
     */
    unsigned int work_pos;

    /*
     * Give the number of values on each side of the bit samples for
     * alignment calculation as described at the top of the file.
     */
#define MIN_WORKEDGE 3
    unsigned int workedge; // minimum 3
    unsigned int workmiddle; // (workedge + 1)
    unsigned int workextra; // ((2 * workedge) + 1)

    /*
     * Store the first workedge sin and cos values here to subtract
     * off later.  This is workedge * 4 samples long.
     */
    float *firstv;

    /*
     * Messages we are currently working on assembling.
     */
    struct wmsgset *wmsgsets;
    unsigned int wmsg_sets; /* Size of wmsgsets. */
    unsigned int max_wmsgs; /* Size of wmsgs in each wmsgset. */

    /*
     * The number of in_bitsize intervals to wait before transmitting.
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

    struct keyinfo keyinfo;
};

#include "crc.h"

static void fsk_start_xmit(struct fsk_filter *sfilter);
static void fsk_stop_drain_timer(struct fsk_filter *sfilter);

#define filter_to_fsk(v) ((struct fsk_filter *)		\
			  gensio_filter_get_user_data(v))

static void
fsk_lock(struct fsk_filter *sfilter)
{
    sfilter->o->lock(sfilter->lock);
}

static void
fsk_unlock(struct fsk_filter *sfilter)
{
    sfilter->o->unlock(sfilter->lock);
}

static void
fsk_set_callbacks(struct gensio_filter *filter,
		      gensio_filter_cb cb, void *cb_data)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);

    sfilter->filter_cb = cb;
    sfilter->filter_cb_data = cb_data;
}

static bool
fsk_ul_read_pending(struct gensio_filter *filter)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);
    bool rv;

    fsk_lock(sfilter);
    rv = sfilter->deliver_data_len > 0;
    fsk_unlock(sfilter);
    return rv;
}

static bool
fsk_ll_write_pending(struct gensio_filter *filter)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);
    bool rv;

    fsk_lock(sfilter);
    rv = sfilter->xmit_buf_len > 0 || sfilter->starting_output_ready;
    fsk_unlock(sfilter);
    return rv;
}

static bool
fsk_ll_read_needed(struct gensio_filter *filter)
{
    return true;
}

static int
fsk_ul_can_write(struct gensio_filter *filter, bool *val)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);

    fsk_lock(sfilter);
    *val = sfilter->nr_wrbufs < NR_WRITE_BUFS;
    fsk_unlock(sfilter);

    return 0;
}

static int
fsk_check_open_done(struct gensio_filter *filter, struct gensio *io)
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
fsk_ax25_prmsg(struct gensio_os_funcs *o,
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
fsk_print_msg(struct fsk_filter *sfilter, char *t, unsigned int msgn,
	      unsigned char *buf, unsigned int buflen,
	      bool pr_msgn)
{
    struct gensio_os_funcs *o = sfilter->o;
    struct gensio_fdump h;

    if (sfilter->debug & GENSIO_FSK_DEBUG_TIME) {
	gensio_time time;

	o->get_monotonic_time(o, &time);
	printf("%lld:%6.6d: ",
	       (long long) time.secs, (time.nsecs + 500) / 1000);
    }

    if (pr_msgn) {
	printf("%sMSG(%u %u):", t, msgn, buflen);
    } else {
	printf("%sMSG(%u):", t, buflen);
	fsk_ax25_prmsg(sfilter->o, buf, buflen);
    }
    printf("\n");
    gensio_fdump_init(&h, 1);
    gensio_fdump_buf(stdout, buf, buflen, &h);
    gensio_fdump_buf_finish(stdout, &h);
    fflush(stdout);
}

static void
key_open_finished(void *cb_data)
{
    struct fsk_filter *sfilter = cb_data;

    sfilter->filter_cb(sfilter->filter_cb_data, GENSIO_FILTER_CB_OPEN_DONE,
		       NULL);
}

static void
key_log(void *cb_data, enum gensio_log_levels level, const char *fmt, ...)
{
    struct fsk_filter *sfilter = cb_data;
    va_list va;

    va_start(va, fmt);
    gensio_filter_vlog(sfilter->filter, level, fmt, va);
    va_end(va);
}

static int
fsk_try_connect(struct gensio_filter *filter, gensio_time *timeout,
		bool was_timeout)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);
    int err = sfilter->keyinfo.key_err;

    if (err) {
	sfilter->keyinfo.key_err = 0;
	return err;
    }

    return key_try_open(&sfilter->keyinfo, timeout);
}

static unsigned long get_frames_left(struct fsk_filter *sfilter)
{
    struct gensio_filter_cb_control_data cd;
    char buf[20] = "0";
    gensiods buflen = sizeof(buf);

    cd.depth = GENSIO_CONTROL_DEPTH_FIRST;
    cd.get = true;
    cd.option = GENSIO_CONTROL_DRAIN_COUNT;
    cd.data = buf;
    cd.datalen = &buflen;
    sfilter->filter_cb(sfilter->filter_cb_data,
		       GENSIO_FILTER_CB_CONTROL, &cd);
    return strtoul(buf, NULL, 0);
}

static void
get_drain_timeout(struct fsk_filter *sfilter, gensio_time *timeout)
{
    unsigned long frames_left = get_frames_left(sfilter);
    uint64_t timeoutns;

    timeoutns = (uint64_t) frames_left * sfilter->nsec_per_frame;
    timeout->secs = timeoutns / GENSIO_NSECS_IN_SEC;
    timeout->nsecs = timeoutns % GENSIO_NSECS_IN_SEC;
}

static int
fsk_try_disconnect(struct gensio_filter *filter, gensio_time *timeout,
		   bool was_timeout)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);

    if (sfilter->transmit_state == WAITING_ENDXMIT) {
	if (!was_timeout) {
	    get_drain_timeout(sfilter, timeout);
	    return GE_RETRY;
	}
	if (sfilter->nr_wrbufs > 0) {
	    sfilter->transmit_state = WAITING_TRANSMIT;
	    fsk_start_xmit(sfilter);
	} else {
	    sfilter->transmit_state = NOT_SENDING;
	}
    } else if (sfilter->transmit_state != NOT_SENDING) {
	return GE_INPROGRESS;
    }

    return key_try_close(&sfilter->keyinfo, timeout);
}

static void
fsk_start_xmit(struct fsk_filter *sfilter)
{
    bool was_in_endxmit = sfilter->transmit_state == WAITING_ENDXMIT;

    sfilter->num_bytes_sent_this_xmit = 0;
    if (sfilter->do_raw) {
	sfilter->transmit_state = SENDING_MSG;
	sfilter->wrbyte = sfilter->wrbufs[sfilter->curr_wrbuf].data[0];
	sfilter->write_pos = 1;
    } else {
	sfilter->transmit_state = SENDING_PREAMBLE;
	sfilter->wrbyte = 0x7e;
	sfilter->send_count = (sfilter->tx_preamble_time /
			       sfilter->out_bit_time / 8);
    }
    sfilter->wrbyte_bit = 0;
    sfilter->bitstuff = false;
    sfilter->starting_output_ready = true;
    if (was_in_endxmit) {
	fsk_stop_drain_timer(sfilter);
    } else {
	key_do_keyon(&sfilter->keyinfo);
    }
}

static void
fsk_check_start_xmit(struct fsk_filter *sfilter)
{
    unsigned int randv;

    if (sfilter->do_raw) {
	fsk_start_xmit(sfilter);
	return;
    }

    /* Some primitive randomness.  Could be improved. */
    sfilter->o->get_random(sfilter->o, &randv, sizeof(randv));
    randv %= 10;
    if (sfilter->start_xmit_delay_count + 1 > randv) {
	sfilter->start_xmit_delay_count = 0;
	fsk_start_xmit(sfilter);
    } else {
	sfilter->start_xmit_delay_count++;
    }
}

static void
fsk_start_drain_timer(struct fsk_filter *sfilter)
{
    gensio_time timeout;

    /*
     * Set a timer to know when we are done transmitting.
     */
    get_drain_timeout(sfilter, &timeout);
    sfilter->filter_cb(sfilter->filter_cb_data,
		       GENSIO_FILTER_CB_START_TIMER,
		       &timeout);
}

static void
fsk_stop_drain_timer(struct fsk_filter *sfilter)
{
    sfilter->filter_cb(sfilter->filter_cb_data,
		       GENSIO_FILTER_CB_STOP_TIMER,
		       NULL);
}

static int
fsk_timeout_done(struct gensio_filter *filter)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);

    fsk_lock(sfilter);
    if (sfilter->transmit_state != WAITING_ENDXMIT)
	goto out;
    if (sfilter->nr_wrbufs > 0) {
	sfilter->transmit_state = WAITING_TRANSMIT;
	fsk_check_start_xmit(sfilter);
    } else {
	sfilter->transmit_state = NOT_SENDING;
    }
    key_do_keyoff(&sfilter->keyinfo);
 out:
    fsk_unlock(sfilter);

    return 0;
}

static void
fsk_send_buffer(struct fsk_filter *sfilter,
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
fsk_add_wrbit(struct fsk_filter *sfilter)
{
    unsigned char bit = sfilter->wrbyte & 1;
    unsigned char level = sfilter->prev_xmit_level;
    struct xmit_entry *curr = sfilter->curr_xmit_ent;
    unsigned int send_alt = 0, i, j;

    if (sfilter->out_bit_adj) {
	sfilter->out_bit_counter++;
	if (sfilter->out_bit_counter == sfilter->out_bit_period) {
	    sfilter->out_bit_counter = 0;
	    send_alt = 2;
	}
    }

    if (sfilter->transmit_state == SENDING_MSG && !sfilter->do_raw) {
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
    if (sfilter->out_do_inv)
	bit = !bit;
    if (sfilter->out_do_diff) {
	/* If the bit is 1, change the frequency.  0 leaves it the same. */
	if (bit)
	    level = !level;
    } else {
	level = bit;
    }
    sfilter->prev_xmit_level = level;

    curr = curr->next_send[level + send_alt];
    sfilter->curr_xmit_ent = curr;

    if (sfilter->out_format == FSK_FMT_FLOATC) {
	float complex *s = (float complex *) sfilter->xmit_buf;
	float complex *data = (float complex *) curr->data;

	s += sfilter->xmit_buf_len * sfilter->out_nchans;
	for (i = 0; i < curr->size; i++) {
	    for (j = 0; j < sfilter->out_nchans; j++) {
		if ((1 << j) & sfilter->out_chans)
		    *s++ = data[i];
		else
		    *s++ = 0.;
	    }
	}
    } else {
	float *s = (float *) sfilter->xmit_buf;

	s += sfilter->xmit_buf_len * sfilter->out_nchans;
	for (i = 0; i < curr->size; i++) {
	    for (j = 0; j < sfilter->out_nchans; j++) {
		if ((1 << j) & sfilter->out_chans)
		    *s++ = curr->data[i];
		else
		    *s++ = 0.;
	    }
	}
    }
    sfilter->xmit_buf_len += curr->size;
}

static void
fsk_handle_send(struct fsk_filter *sfilter,
		gensio_ul_filter_data_handler handler, void *cb_data)
{
    sfilter->starting_output_ready = false;
    if (sfilter->xmit_buf_len > 0) {
	fsk_send_buffer(sfilter, handler, cb_data);
	if (sfilter->xmit_buf_len > 0)
	    goto out;
	if (sfilter->transmit_state == WAITING_ENDXMIT)
	    fsk_start_drain_timer(sfilter);
    }
    while (sfilter->transmit_state > WAITING_TRANSMIT) {
	if (sfilter->bitstuff || sfilter->wrbyte_bit < 8) {
	    fsk_add_wrbit(sfilter);
	    if (sfilter->xmit_buf_len >=
			sfilter->max_xmit_buf - sfilter->max_out_bitsize) {
		fsk_send_buffer(sfilter, handler, cb_data);
		if (sfilter->err)
		    goto out;
		if (sfilter->xmit_buf_len > 0)
		    goto out;
	    }
	}

	if (sfilter->do_raw) {
	    unsigned int cbuf = sfilter->curr_wrbuf;

	    if (sfilter->wrbyte_bit < 8)
		continue;

	    sfilter->wrbyte_bit = 0;
	    if (sfilter->write_pos >= sfilter->wrbufs[cbuf].len) {
		sfilter->write_pos = 0;
		sfilter->curr_wrbuf = (cbuf + 1) % NR_WRITE_BUFS;
		sfilter->nr_wrbufs--;
		if (sfilter->nr_wrbufs > 0) {
		    cbuf = sfilter->curr_wrbuf;
		    sfilter->wrbyte = sfilter->wrbufs[cbuf].data[0];
		    sfilter->write_pos = 1;
		    sfilter->transmit_state = SENDING_MSG;
		} else {
		    sfilter->transmit_state = WAITING_ENDXMIT;
		    if (sfilter->xmit_buf_len == 0)
			/*
			 * No more data to send, start the timer now.
			 */
			fsk_start_drain_timer(sfilter);
		}
	    } else {
		unsigned int pos = sfilter->write_pos++;

		sfilter->wrbyte = sfilter->wrbufs[cbuf].data[pos];
	    }
	    continue;
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
			fsk_start_drain_timer(sfilter);
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
fsk_ul_write(struct gensio_filter *filter,
	     gensio_ul_filter_data_handler handler, void *cb_data,
	     gensiods *rcount,
	     const struct gensio_sg *sg, gensiods sglen,
	     const char *const *auxdata)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);
    gensiods i, count = 0, len;
    unsigned int cbuf;
    uint16_t crc;
    int rv = 0;

    if (!sfilter->tx) {
	if (rcount) {
	    for (i = 0; i < sglen; i++)
		count += sg[i].buflen;
	    *rcount = count;
	}
	return 0;
    }

    fsk_lock(sfilter);
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

    if (sfilter->debug & GENSIO_FSK_DEBUG_MSG) {
	fsk_print_msg(sfilter, "W", 0, sfilter->wrbufs[cbuf].data,
		      sfilter->wrbufs[cbuf].len, false);
    }

    if (sfilter->do_crc) {
	/* We have two extra bytes on the end for the CRC, no check needed. */
	crc = 0xffff;
	len = sfilter->wrbufs[cbuf].len;
	crc16_ccitt(sfilter->wrbufs[cbuf].data, len, &crc);
	crc ^= 0xffff;
	sfilter->wrbufs[cbuf].data[len++] = crc & 0xff;
	sfilter->wrbufs[cbuf].data[len++] = (crc >> 8) & 0xff;
	sfilter->wrbufs[cbuf].len = len;
    }

    sfilter->nr_wrbufs++;
    if (sfilter->transmit_state == WAITING_ENDXMIT) {
	fsk_check_start_xmit(sfilter);
	goto out_process;
    }
    if (sfilter->transmit_state != NOT_SENDING)
	goto out_process;
    if (sfilter->full_duplex || sfilter->nr_out_sync >= sfilter->tx_delay ||
		sfilter->do_raw) {
	fsk_start_xmit(sfilter);
    } else {
	sfilter->transmit_state = WAITING_TRANSMIT;
	goto out;
    }

 out_process:
    fsk_handle_send(sfilter, handler, cb_data);
 out:
    /*
     * Make sure to clear the output buffer if there's anything left
     * and we can still write.  Otherwise the base handler won't know
     * we have data left to send.
     */
    if (!rv && sfilter->xmit_buf_len > 0)
	fsk_send_buffer(sfilter, handler, cb_data);
    if (!rv && sfilter->xmit_buf_len == 0)
	/*
	 * No more data to send, start the timer now.
	 */
	fsk_start_drain_timer(sfilter);
    fsk_unlock(sfilter);
    if (!rv && rcount)
	*rcount = count;

    return rv;
}

static void
fsk_deliver_data(struct fsk_filter *sfilter, struct wmsg *w)
{
    if (sfilter->deliver_data_len == 0) {
	unsigned char *tmp, *tmp_uncert;

	tmp = w->read_data;
	tmp_uncert = w->raw_uncertainty;
	w->read_data = sfilter->deliver_data;
	w->raw_uncertainty = sfilter->deliver_raw_uncertainty;
	sfilter->deliver_data = tmp;
	sfilter->deliver_raw_uncertainty = tmp_uncert;
	sfilter->deliver_data_len = w->read_data_len;
	sfilter->deliver_data_pos = 0;
    }
}

static void
fsk_process_raw_bit(struct fsk_filter *sfilter, unsigned int bit,
		    float certainty)
{
    struct wmsg *w = &sfilter->wmsgsets[0].wmsgs[0];

    if (sfilter->in_do_diff)
	bit = sfilter->prev_recv_level != bit;
    bit ^= sfilter->in_do_inv;
    w->curr_byte |= bit << w->curr_bit_pos;
    if (sfilter->do_uncert) {
	/*
	 * Convert the certainty to an uncertainty value ranging from
	 * 0 to 50.  certainty comes in 0-50, invert that to get a
	 * 50-0 integer uncertainty.
	 */
	w->raw_uncertainty[w->read_data_len * 8 + w->curr_bit_pos]
	    = 50.0 - certainty;
    }
    if (w->curr_bit_pos == 7) {
	w->read_data[w->read_data_len] = w->curr_byte;
	w->curr_byte = 0;
	w->curr_bit_pos = 0;
	w->read_data_len++;
	if (w->read_data_len >= sfilter->max_read_size) {
	    fsk_deliver_data(sfilter, w);
	    w->read_data_len = 0;
	}
    } else {
	w->curr_bit_pos++;
    }
}

static void
fsk_drop_wmsg(struct fsk_filter *sfilter, unsigned int wset,
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
	if (sfilter->debug & GENSIO_FSK_DEBUG_STATE)
	    printf("WMSG: restart\n");
	w->read_data_len = 0;
	w->num_uncertain = 0;
	w->certainty = 0.0;
	w->state = FSK_STATE_PREAMBLE_SEARCH_0;
    } else {
	if (sfilter->debug & GENSIO_FSK_DEBUG_STATE)
	    printf("WMSG: retire %u\n", msgn);
	ws->curr_wmsgs--;
	w->in_use = false;
    }
}

static void
fsk_handle_new_byte(struct fsk_filter *sfilter,
		    unsigned int wset, unsigned int msgn,
		    struct wmsg *w)
{
    if (sfilter->debug & GENSIO_FSK_DEBUG_BIT_HNDL)
	printf("BYTE(%d): %2.2x\n", msgn, w->curr_byte);
    if (w->read_data_len >= sfilter->max_read_size) {
	fsk_drop_wmsg(sfilter, wset, msgn, w, false);
	return;
    }
    w->read_data[w->read_data_len] = w->curr_byte;
    w->curr_byte = 0;
    w->curr_bit_pos = 0;
    w->read_data_len++;
}

static void
fsk_handle_new_message(struct fsk_filter *sfilter,
		       unsigned int wset, unsigned int msgn, struct wmsg *w)
{
    uint16_t crc, msgcrc;
    unsigned int i;

    if (w->read_data_len < 3)
	goto bad_msg;

    if (sfilter->debug & GENSIO_FSK_DEBUG_RAW_MSG) {
	fsk_print_msg(sfilter, "", msgn, w->read_data, w->read_data_len, true);
	printf("    bitpos %d\n", w->curr_bit_pos);
    }

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

	if (sfilter->debug & GENSIO_FSK_DEBUG_RAW_MSG)
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

    if (sfilter->debug & GENSIO_FSK_DEBUG_MSG) {
	fsk_print_msg(sfilter, "R", 0, w->read_data, w->read_data_len, false);
    }

    if (sfilter->deliver_data_len == 0)
	fsk_deliver_data(sfilter, w);

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
    fsk_drop_wmsg(sfilter, wset, msgn, w, true);
}

static void
fsk_process_bit(struct fsk_filter *sfilter,
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
		if (sfilter->debug & GENSIO_FSK_DEBUG_STATE)
		    printf("WMSG: add %u %u\n", wset, i);
		sfilter->wmsgsets[wset].curr_wmsgs++;
		w2->new_wmsg = true; /* Don't process this again on this run. */

		if (i < msgn) {
		    /* Process this bit, since we won't get it in the main. */
		    fsk_process_bit(sfilter, wset, i, !level,
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
    if (sfilter->in_do_diff)
	bit = level != w->prev_recv_level;
    else
	bit = level;
    bit ^= sfilter->in_do_inv;
    w->prev_recv_level = level;

    if (sfilter->debug & GENSIO_FSK_DEBUG_BIT_HNDL)
	printf("BIT(%u %u %lu): l:%d b:%d %f  (%d)\n", wset, msgn,
	       sfilter->framenr, level, bit, certainty, w->state);

    prev_num_rcv_1 = w->num_rcv_1;
    if (bit)
	w->num_rcv_1++;
    else
	w->num_rcv_1 = 0;

    switch (w->state) {
    case FSK_STATE_PREAMBLE_SEARCH_0:
	if (!bit)
	    w->state = FSK_STATE_PREAMBLE_FIRST_0;
	*in_sync = false;
	break;

    case FSK_STATE_PREAMBLE_FIRST_0:
	if (bit)
	    w->state = FSK_STATE_PREAMBLE_1;
	*in_sync = false;
	break;

    case FSK_STATE_PREAMBLE_1:
	if (!bit)
	    w->state = FSK_STATE_PREAMBLE_FIRST_0;
	else if (w->num_rcv_1 == 6)
	    w->state = FSK_STATE_PREAMBLE_LAST_0;
	*in_sync = false;
	break;

    case FSK_STATE_PREAMBLE_LAST_0:
	if (bit) {
	    w->state = FSK_STATE_PREAMBLE_SEARCH_0;
	} else {
	    w->state = FSK_STATE_IN_MSG;
	    w->curr_byte = 0;
	    w->curr_bit_pos = 0;
	    *in_sync = false;
	}
	break;

    case FSK_STATE_IN_MSG:
	if (prev_num_rcv_1 == 5) {
	    if (bit)
		w->state = FSK_STATE_POSTAMBLE_LAST_0;
	    /* Otherwise it's a bit-stuffed zero and we ignore it. */
	    break;
	}

	w->curr_byte |= bit << w->curr_bit_pos;
	if (w->curr_bit_pos == 7)
	    fsk_handle_new_byte(sfilter, wset, msgn, w);
	else
	    w->curr_bit_pos++;
	break;

    case FSK_STATE_POSTAMBLE_LAST_0:
	if (!bit) {
	    fsk_handle_new_message(sfilter, wset, msgn, w);
	    w->state = FSK_STATE_IN_MSG;
	    w->curr_byte = 0;
	    w->curr_bit_pos = 0;
	} else {
	    fsk_drop_wmsg(sfilter, wset, msgn, w, false);
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
process_powers(struct fsk_filter *sfilter,
	       float *pmark, float *pspace,
	       unsigned int *rbest_pos,
	       float *rcertainty, unsigned char *rlevel)
{
    float tcertainty;
    unsigned char tlevel;
    unsigned int i;

    for (i = 0; i < sfilter->workextra; i++) {
	if (pspace[i] > pmark[i]) {
	    tlevel = 0;
	    tcertainty = pspace[i] / pmark[i];
	} else {
	    tlevel = 1;
	    tcertainty = pmark[i] / pspace[i];
	}
	if (isnan(tcertainty) || isinf(tcertainty))
	    tcertainty = 10000.;
	if (tcertainty >= *rcertainty) {
	    *rbest_pos = i;
	    *rlevel = tlevel;
	    *rcertainty = tcertainty;
	}
    }
    /*
     * Certainty here will range from 1 to an arbitrarily large
     * number.  However, generally, it will be in the 50-60 range
     * on good input.  Cap it there.  plus start it at 0.
     */
    *rcertainty -= 1.0;
    *rcertainty *= sfilter->certainty_multiplier;
    if (*rcertainty > 50.0) /* Certainty ranges from 0 to 50. */
	*rcertainty = 50.0;
}

/*
 * Do a DFT bin analysis.  You generally do this against a sine and
 * cosine table, this lets you measure the power (and phase) of a
 * signal against the frequency of the sine/cosine.
 *
 * dftbin is the sine/cosine table to do the DFT analysis on a single
 * frequency, the first 2 * in_bitsize floats are the sine table, the
 * second 2 * in_bitsize floats are the cosine table.
 *
 * The input has extra data on both edges, the actually currently
 * aligned signal is in the middle.  We start at the data past the
 * left edges and process that data.  Then we store the data and
 * subtract off each frame from the left edge and add on the next data
 * until we have processed the whole right edge.  This gives is values
 * in the "power" array where the middle value is the currently
 * aligned value, but we have power measurements assuming we move the
 * alignment point left and right.  This lets us measure how well we
 * are aligned on a transition from a mark to a space or back.
 *
 * Each DFT bin is done on in_bitsize frames of data.  The first
 * in_bitsize bytes is processed and put into power[0] (power at the
 * given frequency).  Then we skip the first sample and calculate the
 * power then, then skip two samples, and so on, up to workedge * 2
 * samples.
 *
 * We don't do it that way, though, we use a much more efficient way.
 * To process at sample 1 we subtract off the first values and add on
 * the next values, so it's quite efficient.
 *
 * power must be [(edge * 2) + 1].  The input data size must be
 * [in_bitsize + edge * 2].
 */
static void
float_dftbin(struct fsk_filter *sfilter, float *dftbin,
	     float *buf, float *power, float *maxp)
{
    float *csin = dftbin;
    float *ccos = dftbin + 2 * sfilter->in_bitsize;
    float psin = 0, pcos = 0;
    unsigned int i, ppos = 0, fpos;

    /* Calculate the beginning portion and save off the first values. */
    for (i = 0; i < sfilter->workedge * 2; i++, csin++, ccos++) {
	sfilter->firstv[i * 2] = *csin * buf[i];
	sfilter->firstv[i * 2 + 1] = *ccos * buf[i];
	psin += sfilter->firstv[i * 2];
	pcos += sfilter->firstv[i * 2 + 1];
    }
    /*
     * Calculate the rest of the buffer to the point where we have the
     * first value to save.
     */
    for (; i < sfilter->in_bitsize; i++, csin++, ccos++) {
	psin += *csin * buf[i];
	pcos += *ccos * buf[i];
    }

    /* Save the first value's power. */
    power[ppos] = psin * psin + pcos * pcos;
    *maxp = power[ppos];
    ppos++;

    /*
     * Now go through the rest of the buffer and calculate the power for
     * each succeeding position.
     */
    for (fpos = 0; i < sfilter->worksize; i++, fpos++, ppos++) {
	psin -= sfilter->firstv[fpos * 2];
	pcos -= sfilter->firstv[fpos * 2 + 1];
	psin += *csin++ * buf[i];
	pcos += *ccos++ * buf[i];
	power[ppos] = psin * psin + pcos * pcos;
	if (power[ppos] > *maxp)
	    *maxp = power[ppos];
    }
}

/* Like above, but complex. */
static void
floatc_dftbin(struct fsk_filter *sfilter, float *in_dftbin,
	      float *in_buf, float *power, float *maxp)
{
    float complex *cwave = (float complex *) in_dftbin;
    float complex *buf = (float complex *) in_buf;
    float complex pow = 0;
    float complex *firstv = (float complex *) sfilter->firstv;
    unsigned int i, ppos = 0, fpos;

    /* Calculate the beginning portion and save off the first values. */
    for (i = 0; i < sfilter->workedge * 2; i++, cwave++) {
	firstv[i] = *cwave * buf[i];
	pow += sfilter->firstv[i];
    }
    /*
     * Calculate the rest of the buffer to the point where we have the
     * first value to save.
     */
    for (; i < sfilter->in_bitsize; i++, cwave++) {
	pow += *cwave * buf[i];
    }

    /* Save the first value's power. */
    power[ppos] = cabsf(pow);
    *maxp = power[ppos];
    ppos++;

    /*
     * Now go through the rest of the buffer and calculate the power for
     * each succeeding position.
     */
    for (fpos = 0; i < sfilter->worksize; i++, fpos++, cwave++, ppos++) {
	pow -= firstv[fpos];
	pow += *cwave * buf[i];
	power[ppos] = cabsf(pow);
	if (power[ppos] > *maxp)
	    *maxp = power[ppos];
    }
}

/*
 * Do DFT bin analysis at mark and space the data then call the bit
 * processing with the info extracted from the data.
 */
static int
fsk_check_for_data(struct fsk_filter *sfilter, float *buf, bool *in_sync)
{
    unsigned char level;
    unsigned int i, best_pos = 0, wset;
    float certainty = 0.0, m;
    int adj = 0;
    unsigned int markbin, spacebin;
    float maxp[MAX_HZ_BINS] = {0};

#if 0
    printf("A:\n");
    for (i = 0; i < sfilter->worksize * 2; i += 2) {
	printf("  %u (%f %f)\n", i / 2, buf[i], buf[i+1]);
    }
#endif

    for (i = 0; i < sfilter->nr_hz_bins; i++)
	sfilter->do_dftbin(sfilter, sfilter->hzbin[i], buf, sfilter->pmeas[i],
			   &maxp[i]);
    if (sfilter->nr_hz_bins == 2) {
	spacebin = 0;
	markbin = 1;
    } else {
	unsigned int maxp_p = 0;

	for (i = 1; i < sfilter->nr_hz_bins; i++) {
	    if (maxp[i] > maxp[maxp_p])
		maxp_p = i;
	}
	if (maxp_p < 2) {
	    /* On the lower portion, must be a space. */
	    spacebin = maxp_p;
	    markbin = spacebin + 2;
	} else if (maxp_p + 2 >= sfilter->nr_hz_bins) {
	    /* On the upper portion, must be a mark. */
	    markbin = maxp_p;
	    spacebin = markbin - 2;
	} else {
	    /* In the middle, might be a mark or space. */
	    /* FIXME - how do we calculate this? */
	}
	spacebin = 2;
	markbin = 4;
    }

    process_powers(sfilter, sfilter->pmeas[markbin], sfilter->pmeas[spacebin],
		   &best_pos, &certainty, &level);

    if (sfilter->debug & GENSIO_FSK_DEBUG_BIT_HNDL) {
	printf("WORK(%lu): level: %u (%u)  cert: %f  best_pos: %u (%u)\n",
	       sfilter->framecount++,
	       level, sfilter->prev_recv_level, certainty,
	       best_pos, sfilter->prev_best_pos);
	for (i = 0; i < sfilter->workextra; i++) {
	    if (i == sfilter->workmiddle)
		printf(" (");
	    else
		printf(" ");
	    printf("%f", sfilter->pmeas[markbin][i]);
	    if (i == sfilter->workmiddle)
		printf(")");
	}
	printf("\n");
	for (i = 0; i < sfilter->workextra; i++) {
	    if (i == sfilter->workmiddle)
		printf(" (");
	    else
		printf(" ");
	    printf("%f", sfilter->pmeas[spacebin][i]);
	    if (i == sfilter->workmiddle)
		printf(")");
	}
	printf("\n");
    }

    if (sfilter->prev_recv_level != level) {
	/*
	 * Check re-align on a 1->0 or 0->1 level transition.  You
	 * can't align on no transition because you have to have a
	 * boundary to check against.
	 *
	 * Since we are only checking this boundary, only look at the
	 * previous position if it moves the bar forward, and only look
	 * at the current position if it move the bar backwards.
	 */

	if (sfilter->prev_best_pos > sfilter->workmiddle)
	    adj += ((int) sfilter->prev_best_pos - (int) sfilter->workmiddle) / 2;

	if (best_pos < sfilter->workmiddle)
	    adj += ((int) best_pos - (int) sfilter->workmiddle) / 2;
    }

    sfilter->prev_best_pos = best_pos;
    if (sfilter->do_raw) {
	fsk_process_raw_bit(sfilter, level, certainty);
	sfilter->prev_recv_level = level;
	return adj;
    }

    sfilter->prev_recv_level = level;

    sfilter->wmsgsets[0].got_flag = false;
    for (i = 0; i < sfilter->max_wmsgs; i++)
	fsk_process_bit(sfilter, 0, i, level, certainty, in_sync);

    for (wset = 1, m = 4.0; wset < sfilter->wmsg_sets; wset += 2, m += 4.0) {
	for (i = 0; i < sfilter->workextra; i++)
	    sfilter->pmark2[i] = sfilter->pmeas[markbin][i] * m;
	certainty = 0.0;
	process_powers(sfilter, sfilter->pmark2, sfilter->pmeas[spacebin],
		       &best_pos, &certainty, &level);
	sfilter->wmsgsets[wset].got_flag = false;
	for (i = 0; i < sfilter->max_wmsgs; i++)
	    fsk_process_bit(sfilter, wset, i, level, certainty, in_sync);

	for (i = 0; i < sfilter->workextra; i++)
	    sfilter->pspace2[i] = sfilter->pmeas[spacebin][i] * m;
	certainty = 0.0;
	process_powers(sfilter, sfilter->pmeas[markbin], sfilter->pspace2,
		       &best_pos, &certainty, &level);
	sfilter->wmsgsets[wset + 1].got_flag = false;
	for (i = 0; i < sfilter->max_wmsgs; i++)
	    fsk_process_bit(sfilter, wset + 1, i, level, certainty, in_sync);
    }

    return adj;
}

/*
 * Copy the particular channel we are interested in into the
 * destination buffer.  Incoming data may be channelized (nchans > 1)
 * and we only want one of the channels.
 */
static void
float_frame_in_copy(float *dest, gensiods destpos,
		    float *src, gensiods srcpos,
		    unsigned int nchans, unsigned int chan,
		    gensiods count)
{
    gensiods i;

    dest += destpos;
    src += srcpos * nchans + chan;
    for (i = 0; i < count; i++, dest++, src += nchans)
	*dest = *src;
}

static void
floatc_frame_in_copy(float *in_dest, gensiods destpos,
		     float *in_src, gensiods srcpos,
		     unsigned int nchans, unsigned int chan,
		     gensiods count)
{
    float complex *dest = (float complex *) in_dest;
    float complex *src = (float complex *) in_src;
    gensiods i;

    dest += destpos;
    src += srcpos * nchans + chan;
    for (i = 0; i < count; i++, dest++, src += nchans)
	*dest = *src;
}

static int
fsk_ll_write(struct gensio_filter *filter,
	     gensio_ll_filter_data_handler handler, void *cb_data,
	     gensiods *rcount,
	     unsigned char *inbuf, gensiods inbuflen,
	     const char *const *auxdata)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);
    gensiods pos;
    int err = 0;
    /* Work in float increments to simplify calculations. */
    float *buf = (float *) inbuf;
    gensiods buflen = inbuflen / sfilter->in_samplesize;

    if (!sfilter->rx || gensio_str_in_auxdata(auxdata, "oob")) {
	/* Ignore oob data or if we are only tx. */
	if (rcount)
	    *rcount = inbuflen;
	return 0;
    }

    fsk_lock(sfilter);
    if (sfilter->err) {
	err = sfilter->err;
	goto out_err;
    }
    if (buflen == 0)
	goto try_deliver;

    if (inbuflen != (gensiods) sfilter->in_bufsize * sfilter->in_framesize) {
	err = GE_INVAL;
	goto out_err;
    }

    if (sfilter->hpfilteredbuf) {
	sfilter->hpfilt.do_filter(buf, sfilter->hpfilteredbuf,
				  sfilter->in_bufsize,
				  sfilter->in_nchans, sfilter->in_chan,
				  &sfilter->hpfilt);
	buf = sfilter->hpfilteredbuf;
    }
    if (sfilter->lpfilteredbuf) {
	sfilter->lpfilt.do_filter(buf, sfilter->lpfilteredbuf,
				  sfilter->in_bufsize,
				  sfilter->in_nchans, sfilter->in_chan,
				  &sfilter->lpfilt);
	buf = sfilter->lpfilteredbuf;
    }
    if (sfilter->debug & GENSIO_FSK_DEBUG_OUTPUT_FILTERED) {
	FILE *f = fopen("t1", "a");
	fwrite(buf, sfilter->in_framesize, sfilter->in_bufsize, f);
	fclose(f);
    }

    if (sfilter->debug & GENSIO_FSK_DEBUG_BIT_HNDL)
	printf("Processing frame %lu %d\n", sfilter->framenr,
	       sfilter->transmit_state);
    if (!sfilter->full_duplex && sfilter->transmit_state > WAITING_TRANSMIT) {
	sfilter->work_pos = 0;
	goto skip_processing;
    }

    pos = 0; /* Input buffer position. */
    while (sfilter->worksize - sfilter->work_pos <= buflen - pos) {
	bool in_sync = true;
	int adj;
	unsigned int j;

	/* Copy the data from the incoming buffer into workbuf. */
	sfilter->do_frame_in_copy(sfilter->workbuf, sfilter->work_pos,
				  buf, pos, sfilter->in_nchans, sfilter->in_chan,
				  sfilter->worksize - sfilter->work_pos);
	pos += sfilter->worksize - sfilter->work_pos;
	if (sfilter->debug & GENSIO_FSK_DEBUG_BIT_HNDL)
	    printf("BIT(%lu+%u): ",
		   sfilter->framenr + pos - sfilter->worksize,
		   sfilter->workedge);
	adj = fsk_check_for_data(sfilter, sfilter->workbuf, &in_sync);

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
		fsk_check_start_xmit(sfilter);
		if (!sfilter->full_duplex &&
			sfilter->transmit_state > WAITING_TRANSMIT) {
		    sfilter->work_pos = 0;
		    goto skip_processing;
		}
	    }
	}

	if (sfilter->debug & GENSIO_FSK_DEBUG_BIT_HNDL)
	    printf("SYNC: %d %d %u\n", adj, in_sync, sfilter->nr_in_sync);

	sfilter->in_adj_counter++;
	if (sfilter->in_adj_counter >= sfilter->in_adj_period) {
	    adj += sfilter->in_adj;
	    sfilter->in_adj_counter = 0;
	}

	/*
	 * You cannot adjust more than the edge
	 */
	if (adj > (int) sfilter->maxadj)
	    adj = (int) sfilter->maxadj;
	if (adj < - (int) sfilter->maxadj)
	    adj = - (int) sfilter->maxadj;

	/*
	 * Copy the end of the buffer to the beginning.  In this
	 * buffer the end workedge bytes are the first workedge bytes
	 * of the next  The last workedge bytes of this sample
	 */
	sfilter->work_pos = sfilter->workedge * 2 - adj;
	j = sfilter->worksize - sfilter->work_pos;
	memmove(sfilter->workbuf,
		((char *) sfilter->workbuf) + j * sfilter->in_samplesize,
		sfilter->work_pos * sfilter->in_samplesize);
    }

    /*
     * Copy what is left in the incoming buffer into the work buffer
     * to be processed on the next round.
     */
    sfilter->do_frame_in_copy(sfilter->workbuf, sfilter->work_pos,
			      buf, pos, sfilter->in_nchans, sfilter->in_chan,
			      buflen - pos);
    sfilter->work_pos += buflen - pos;

 skip_processing:
    sfilter->framenr += sfilter->in_bufsize;

 try_deliver:
    if (sfilter->deliver_data_len > 0) {
	gensiods count = 0;
	const char **auxdata = NULL, *ad[2];
	char buf[8 + sizeof(unsigned char *)];

	if (sfilter->do_uncert) {
	    unsigned char *uncert = sfilter->deliver_raw_uncertainty;
	    unsigned int pos;

	    uncert += sfilter->deliver_data_pos * 8;
	    pos = sprintf(buf, "uncert=");
	    memcpy(buf + pos, &uncert, sizeof(uncert));
	    buf[sizeof(buf) - 1] = '\0'; /* Just in case. */
	    ad[0] = buf;
	    ad[1] = NULL;
	    auxdata = ad;
	}

	fsk_unlock(sfilter);
	err = handler(cb_data, &count,
		      sfilter->deliver_data + sfilter->deliver_data_pos,
		      sfilter->deliver_data_len - sfilter->deliver_data_pos,
		      auxdata);
	fsk_lock(sfilter);
	if (!err) {
	    if (count + sfilter->deliver_data_pos >= sfilter->deliver_data_len)
		sfilter->deliver_data_len = 0;
	    else
		sfilter->deliver_data_pos += count;
	}
    }
 out_err:
    fsk_unlock(sfilter);
    if (!err && rcount)
	*rcount = inbuflen;
    return err;
}

static int
fsk_setup(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static void
fsk_cleanup(struct gensio_filter *filter)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);
    unsigned int i, j;

    key_cleanup(&sfilter->keyinfo);
    sfilter->prev_xmit_level = 0;
    sfilter->prev_recv_level = 0;
    if (sfilter->wmsgsets) {
	for (i = 0; i < sfilter->wmsg_sets; i++) {
	    sfilter->wmsgsets[i].wmsgs[0].in_use = true;
	    sfilter->wmsgsets[i].wmsgs[0].read_data_len = 0;
	    sfilter->wmsgsets[i].wmsgs[0].num_uncertain = 0;
	    sfilter->wmsgsets[i].wmsgs[0].certainty = 0.0;
	    sfilter->wmsgsets[i].wmsgs[0].state = FSK_STATE_PREAMBLE_FIRST_0;
	    for (j = 1; j < sfilter->max_wmsgs; j++)
		sfilter->wmsgsets[i].wmsgs[j].in_use = false;
	    sfilter->wmsgsets[i].curr_wmsgs = 1;
	}
    }
    sfilter->work_pos = 0;
    sfilter->deliver_data_len = 0;
    sfilter->xmit_buf_len = 0;
    sfilter->xmit_buf_pos = 0;
    sfilter->nr_wrbufs = 0;
    sfilter->in_adj_counter = 0;
    sfilter->out_bit_counter = 0;
}

static void
fsk_sfilter_free(struct fsk_filter *sfilter)
{
    struct gensio_os_funcs *o = sfilter->o;
    unsigned int i, j;
    struct xmit_entry *e = sfilter->xmit_ent_list, *n;

    key_free(&sfilter->keyinfo, o);
    while (e) {
	n = e->next;
	o->free(o, e);
	e = n;
    }
    if (sfilter->mark_xmit)
	o->free(o, sfilter->mark_xmit);
    if (sfilter->space_xmit)
	o->free(o, sfilter->space_xmit);
    if (sfilter->lock)
	o->free_lock(sfilter->lock);
    for (i = 0; i < sfilter->nr_hz_bins; i++) {
	if (sfilter->hzbin[i])
	    o->free(o, sfilter->hzbin[i]);
    }
    if (sfilter->workbuf)
	o->free(o, sfilter->workbuf);
    if (sfilter->firstv)
	o->free(o, sfilter->firstv);
    for (i = 0; i < sfilter->nr_hz_bins; i++) {
	if (sfilter->pmeas[i])
	    o->free(o, sfilter->pmeas[i]);
    }
    if (sfilter->pmark2)
	o->free(o, sfilter->pmark2);
    if (sfilter->pspace2)
	o->free(o, sfilter->pspace2);
    if (sfilter->wmsgsets) {
	for (i = 0; i < sfilter->wmsg_sets; i++) {
	    if (sfilter->wmsgsets[i].wmsgs) {
		for (j = 0; j < sfilter->max_wmsgs; j++) {
		    if (sfilter->wmsgsets[i].wmsgs[j].read_data)
			o->free(o, sfilter->wmsgsets[i].wmsgs[j].read_data);
		    if (sfilter->wmsgsets[i].wmsgs[j].raw_uncertainty)
			o->free(o, sfilter->wmsgsets[i].wmsgs[j].raw_uncertainty);
		}
	    }
	    o->free(o, sfilter->wmsgsets[i].wmsgs);
	}
	o->free(o, sfilter->wmsgsets);
    }
    if (sfilter->deliver_data)
	o->free(o, sfilter->deliver_data);
    if (sfilter->deliver_raw_uncertainty)
	o->free(o, sfilter->deliver_raw_uncertainty);
    if (sfilter->xmit_buf)
	o->free(o, sfilter->xmit_buf);
    for (i = 0; i < NR_WRITE_BUFS; i++) {
	if (sfilter->wrbufs[i].data)
	    o->free(o, sfilter->wrbufs[i].data);
    }
    if (sfilter->lpfilteredbuf)
	o->free(o, sfilter->lpfilteredbuf);
    if (sfilter->hpfilteredbuf)
	o->free(o, sfilter->hpfilteredbuf);
    filter_cleanup(o, &sfilter->lpfilt);
    filter_cleanup(o, &sfilter->hpfilt);
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    o->free(o, sfilter);
}

static void
fsk_free(struct gensio_filter *filter)
{
    struct fsk_filter *sfilter = filter_to_fsk(filter);

    return fsk_sfilter_free(sfilter);
}

static int
fsk_filter_control(struct gensio_filter *filter, bool get, int op,
		   char *data, gensiods *datalen)
{
    return GE_NOTSUP;
}

static int gensio_fsk_filter_func(struct gensio_filter *filter, int op,
				  void *func, void *data,
				  gensiods *count,
				  void *buf, const void *cbuf,
				  gensiods buflen,
				  const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	fsk_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_TIMEOUT:
	return fsk_timeout_done(filter);

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return fsk_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return fsk_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return fsk_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_UL_CAN_WRITE:
	return fsk_ul_can_write(filter, data);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return fsk_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return fsk_try_connect(filter, data, buflen);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return fsk_try_disconnect(filter, data, buflen);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return fsk_ul_write(filter, func, data, count, cbuf, buflen, buf);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return fsk_ll_write(filter, func, data, count, buf, buflen, NULL);

    case GENSIO_FILTER_FUNC_SETUP:
	return fsk_setup(filter, data);

    case GENSIO_FILTER_FUNC_CLEANUP:
	fsk_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	fsk_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return fsk_filter_control(filter, *((bool *) cbuf), buflen, data,
				  count);

    default:
	return GE_NOTSUP;
    }
}

static unsigned int
fsk_floatc_find_wave_pos(float complex *wave, unsigned int wave_size,
			 float complex v, bool ascend, unsigned int size)
{
    unsigned int i;

    /* Only match against the real part, the complex part should match. */
    for (i = 0; i < wave_size - size; i++) {
	if (creal(wave[i]) <= creal(wave[i + 1])
		&& creal(wave[i + 1]) >= creal(wave[i + 2])) {
	    /* At a peak. */
	    if (creal(v) > creal(wave[i + 1]))
		break;
	}
	if (creal(wave[i]) >= creal(wave[i + 1])
		&& creal(wave[i + 1]) <= creal(wave[i + 2])) {
	    /* At a trough */
	    if (creal(v) < creal(wave[i + 1]))
		break;
	}
	if (ascend) {
	    if (creal(v) >= creal(wave[i]) && creal(v) <= creal(wave[i + 1])) {
		float avg = (creal(wave[i]) + creal(wave[i + 1])) / 2;
		if (creal(v) > avg)
		    i++;
		break;
	    }
	} else {
	    if (creal(v) <= creal(wave[i]) && creal(v) >= creal(wave[i + 1])) {
		float avg = (creal(wave[i]) + creal(wave[i + 1])) / 2;
		if (creal(v) < avg)
		    i++;
		break;
	    }
	}
    }
    return i;
}

static unsigned int
fsk_float_find_wave_pos(float *wave, unsigned int wave_size,
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

static int fsk_setup_xmit_ent(struct fsk_filter *sfilter,
			      struct xmit_entry *e);

static struct xmit_entry *
fsk_create_xmit_ent(struct fsk_filter *sfilter, bool is_mark,
		    float *data, unsigned int size)
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

    if (fsk_setup_xmit_ent(sfilter, e))
	return NULL;

    return e;
}

static struct xmit_entry *
fsk_find_xmit_ent(struct fsk_filter *sfilter, bool is_mark,
		  struct xmit_entry *prev_e, unsigned int size)
{
    struct xmit_entry *e = sfilter->xmit_ent_list;
    unsigned int wave_size, pos;

    if (sfilter->out_format == FSK_FMT_FLOATC) {
	float complex *prev_data = (float complex *) prev_e->data;
	float complex v = prev_data[prev_e->size];
	bool ascend = creal(v) > creal(prev_data[prev_e->size - 1]);
	float complex *wave;

	if (is_mark) {
	    wave = (float complex *) sfilter->mark_xmit;
	    wave_size = sfilter->mark_xmit_len;
	} else {
	    wave = (float complex *) sfilter->space_xmit;
	    wave_size = sfilter->space_xmit_len;
	}

	pos = fsk_floatc_find_wave_pos(wave, wave_size, v, ascend, size);
	if (pos >= wave_size - size)
	    return NULL;

	for(; e; e = e->next) {
	    if (is_mark != e->is_mark)
		continue;
	    if (size != e->size)
		continue;
	    if (wave + pos == (float complex *) e->data)
		break;
	}
	if (!e)
	    e = fsk_create_xmit_ent(sfilter, is_mark,
				    (float *) (wave + pos), size);
    } else {
	float v = prev_e->data[prev_e->size];
	bool ascend = v > prev_e->data[prev_e->size - 1];
	float *wave;

	if (is_mark) {
	    wave = sfilter->mark_xmit;
	    wave_size = sfilter->mark_xmit_len;
	} else {
	    wave = sfilter->space_xmit;
	    wave_size = sfilter->space_xmit_len;
	}

	pos = fsk_float_find_wave_pos(wave, wave_size, v, ascend, size);
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
	    e = fsk_create_xmit_ent(sfilter, is_mark, wave + pos, size);
    }
    return e;
}

static int
fsk_setup_xmit_ent(struct fsk_filter *sfilter, struct xmit_entry *e)
{
    /*
     * We index one of the end of e->data, but the array it points to
     * has entries there, and it's the next value we want.
     */
    struct xmit_entry *ne;
    unsigned int size = sfilter->out_bitsize;

    ne = fsk_find_xmit_ent(sfilter, false, e, size);
    if (!ne)
	return GE_NOMEM;
    e->next_send[0] = ne;

    ne = fsk_find_xmit_ent(sfilter, true, e, size);
    if (!ne)
	return GE_NOMEM;
    e->next_send[1] = ne;

    if (sfilter->out_bit_adj == 0)
	return 0;

    size += sfilter->out_bit_adj;
    ne = fsk_find_xmit_ent(sfilter, false, e, size);
    if (!ne)
	return GE_NOMEM;
    e->next_send[2] = ne;

    ne = fsk_find_xmit_ent(sfilter, true, e, size);
    if (!ne)
	return GE_NOMEM;
    e->next_send[3] = ne;

    return 0;
}

struct gensio_fsk_data {
    const char *outgen;
    unsigned int in_nchans;
    unsigned int in_chan;
    unsigned int out_nchans;
    unsigned int out_chans;
    gensiods max_read_size;
    gensiods max_write_size;
    float in_mark_freq;
    float in_space_freq;
    float out_mark_freq;
    float out_space_freq;
    bool in_do_freqadj;
    bool out_do_freqadj;
    unsigned int in_data_rate;
    unsigned int out_data_rate;
    unsigned int debug;
    bool check_ax25;
    bool do_raw;
    bool do_uncert;
    float certainty_multiplier;
    bool in_do_inv;
    bool out_do_inv;
    bool in_do_diff;
    bool out_do_diff;
    bool do_crc;
    enum fsk_format in_format;
    enum fsk_format out_format;
    bool rx;
    bool tx;
    unsigned int in_framerate;
    unsigned int out_framerate;
    unsigned int in_bufsize;
    unsigned int out_bufsize;
    unsigned int max_wmsgs;
    unsigned int wmsg_sets;
    float min_certainty;

    int filt_type;
#define NO_FILT 0
#define IIR_FILT 1
#define FIR_FILT 2
    bool filt_type_set;
    unsigned int lpcutoff;
    float lpgain;
    unsigned int hpcutoff;
    float hpgain;
    unsigned int transition_freq;
    unsigned int maxadj;

    unsigned int tx_preamble_time;
    unsigned int tx_postamble_time;
    unsigned int tx_predelay_time;
    float volume;
    struct keydata keydata;
    bool full_duplex;
};

static void
floatc_gen_sin(float *inbuf, unsigned int bufsize,
	       double freq_incr, double fin_bitsize,
	       double volume)
{
    float complex *buf = (float complex *) inbuf;
    unsigned int i;

    for (i = 0; i < bufsize; i++) {
	float complex v = I * 2 * M_PI * freq_incr * ((float) i);

	buf[i] = cexpf(v / fin_bitsize) * volume;
    }
}

static void
float_gen_sin(float *buf, unsigned int bufsize,
	      double freq_incr, double fin_bitsize,
	      double volume)
{
    unsigned int i;

    for (i = 0; i < bufsize; i++) {
	float v = 2 * M_PI * freq_incr * ((float) i);

	buf[i] = sin(v / fin_bitsize) * volume;
    }
}

static int
fsk_setup_transmit(struct fsk_filter *sfilter,
		   struct gensio_fsk_data *data,
		   float fbitsize)
{
    struct gensio_os_funcs *o = sfilter->o;
    struct xmit_entry *e;

    sfilter->mark_xmit_len = (data->out_framerate
			      / fabsf(data->out_mark_freq) * 2 + 2);
    if (sfilter->mark_xmit_len < 2 * sfilter->out_bitsize + 1)
	sfilter->mark_xmit_len = 2 * sfilter->out_bitsize + 1;
    sfilter->mark_xmit = o->zalloc(o, (sfilter->out_samplesize
				       * sfilter->mark_xmit_len));
    if (!sfilter->mark_xmit)
	return GE_NOMEM;
    if (sfilter->out_format == FSK_FMT_FLOATC)
	floatc_gen_sin(sfilter->mark_xmit, sfilter->mark_xmit_len,
		       data->out_mark_freq / data->out_data_rate, fbitsize,
		       data->volume);
    else
	float_gen_sin(sfilter->mark_xmit, sfilter->mark_xmit_len,
		      data->out_mark_freq / data->out_data_rate, fbitsize,
		      data->volume);

    sfilter->space_xmit_len = (data->out_framerate
			       / fabs(data->out_space_freq) * 2 + 2);
    if (sfilter->space_xmit_len < 2 * sfilter->out_bitsize + 1)
	sfilter->space_xmit_len = 2 * sfilter->out_bitsize + 1;
    sfilter->space_xmit = o->zalloc(o, (sfilter->out_samplesize
					* sfilter->space_xmit_len));
    if (!sfilter->space_xmit)
	return GE_NOMEM;
    if (sfilter->out_format == FSK_FMT_FLOATC)
	floatc_gen_sin(sfilter->space_xmit, sfilter->space_xmit_len,
		       data->out_space_freq / data->out_data_rate, fbitsize,
		       data->volume);
    else
	float_gen_sin(sfilter->space_xmit, sfilter->space_xmit_len,
		      data->out_space_freq / data->out_data_rate, fbitsize,
		      data->volume);

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

    return fsk_setup_xmit_ent(sfilter, e);
}

static void
floatc_gen_hz(float *inbuf, unsigned int bufsize,
	      double freq, double samplerate)
{
    float complex *buf = (float complex *) inbuf;
    unsigned int i;

    for (i = 0; i < 2 * bufsize; i++)
	buf[i] = cexpf(-I * 2 * M_PI * freq * ((float) i) / samplerate);
}

static void
float_gen_hz(float *buf, unsigned int bufsize,
	     double freq_incr, double fin_bitsize)
{
    unsigned int i;

    for (i = 0; i < 2 * bufsize; i++) {
	float v = 2 * M_PI * freq_incr * ((float) i);

	buf[i] = sin(v / fin_bitsize);
	buf[i + 2 * bufsize] = cos(v / fin_bitsize);
    }
}

static struct gensio_filter *
gensio_fsk_filter_raw_alloc(struct gensio_pparm_info *p,
			    struct gensio_os_funcs *o,
			    struct gensio *out_child,
			    bool is_afsk,
			    struct gensio_fsk_data *data)
{
    struct fsk_filter *sfilter;
    unsigned int i, j;
    float fin_bitsize, fout_bitsize, freq, freq_incr;
    bool err;

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return NULL;

    sfilter->o = o;
    sfilter->rx = data->rx;
    sfilter->tx = data->tx;
    sfilter->in_nchans = data->in_nchans;
    sfilter->out_nchans = data->out_nchans;
    sfilter->in_chan = data->in_chan;
    sfilter->out_chans = data->out_chans;
    sfilter->in_format = data->in_format;
    sfilter->out_format = data->out_format;
    if (sfilter->in_format == FSK_FMT_FLOATC)
	sfilter->in_samplesize = sizeof(float complex);
    else
	sfilter->in_samplesize = sizeof(float);
    sfilter->in_framesize = sfilter->in_samplesize * data->in_nchans;
    if (sfilter->out_format == FSK_FMT_FLOATC)
	sfilter->out_samplesize = sizeof(float complex);
    else
	sfilter->out_samplesize = sizeof(float);
    sfilter->out_framesize = sfilter->out_samplesize * data->out_nchans;
    sfilter->max_write_size = data->max_write_size;
    sfilter->max_read_size = data->max_read_size + 2; /* Extra 2 for the CRC. */
    sfilter->debug = data->debug;
    sfilter->check_ax25 = data->check_ax25;
    sfilter->do_crc = data->do_crc;
    sfilter->do_raw = data->do_raw;
    sfilter->do_uncert = data->do_uncert;
    sfilter->certainty_multiplier = data->certainty_multiplier;
    sfilter->in_do_inv = data->in_do_inv;
    sfilter->out_do_inv = data->out_do_inv;
    sfilter->in_do_diff = data->in_do_diff;
    sfilter->out_do_diff = data->out_do_diff;
    sfilter->prev_xmit_level = 0;
    sfilter->prev_recv_level = 0;
    sfilter->in_bufsize = data->in_bufsize;
    sfilter->out_bufsize = data->out_bufsize;
    sfilter->max_wmsgs = data->max_wmsgs;
    sfilter->wmsg_sets = data->wmsg_sets;
    sfilter->min_certainty = data->min_certainty;
    sfilter->tx_preamble_time = GENSIO_MSECS_TO_NSECS(data->tx_preamble_time);
    sfilter->tx_postamble_time = GENSIO_MSECS_TO_NSECS(data->tx_postamble_time);
    sfilter->tx_predelay_time = GENSIO_MSECS_TO_NSECS(data->tx_predelay_time);
    sfilter->full_duplex = data->full_duplex;
    if (key_setup(&sfilter->keyinfo, &data->keydata, out_child, o, p,
		  key_open_finished, key_log, sfilter))
	goto out_nomem;

    sfilter->lock = o->alloc_lock(o);
    if (!sfilter->lock)
	goto out_nomem;

    if (sfilter->rx) {
	/*
	 * Calculate the size of a bit in samples.  We round the size to
	 * the nearest integer.  We create the DFT tables with the actual
	 * floating point value, and we us that for adjust calculation, so
	 * get that here, too.
	 */
	sfilter->in_bitsize = ((data->in_framerate + data->in_data_rate / 2)
			       / data->in_data_rate);
	if (sfilter->in_bitsize < 2 * MIN_WORKEDGE) {
	    gensio_pparm_log(p, "fsk: "
			     "bit size is %u samples, but must be at least %u",
			     sfilter->in_bitsize, 2 * MIN_WORKEDGE);
	    goto out_nomem;
	}
	sfilter->in_adj_time = (GENSIO_SECS_TO_NSECS(sfilter->in_bitsize) /
				data->in_framerate);
	fin_bitsize = (float) data->in_framerate / data->in_data_rate;
	if (data->in_framerate % data->in_data_rate != 0) {
	    /*
	     * Calculate how often to adjust for the frame rate not being
	     * evenly divisible by the data rate.  If we rounded bitsize
	     * up, then it needs to be adjusted down periodically,
	     * otherwise we adjust up.
	     *
	     * Then take 1 divided by the distance from the ideal value,
	     * and that should give how often we need to adjust.  This may
	     * not be really exact, but for all practical values it works
	     * out well, and the auto-adjusting should keep us in sync as
	     * long as this is close.
	     */
	    float err = fin_bitsize - truncf(fin_bitsize);

	    if (sfilter->in_bitsize > data->in_framerate / data->in_data_rate) {
		/* We rounded up. */
		err = 1. - err;
		sfilter->in_adj = -1;
	    } else {
		sfilter->in_adj = 1;
	    }
	    sfilter->in_adj_period = (unsigned int) ((1. / err) + 0.5);
	}

	if (is_afsk || data->in_data_rate > 12000) {
	    sfilter->nr_hz_bins = 2;
	} else if (data->in_data_rate > 4800) {
	    sfilter->nr_hz_bins = 5;
	} else {
	    sfilter->nr_hz_bins = 7;
	}
	/*
	 * FIXME - Right now we fix this at two until we figure out
	 * how to best handle this.
	 */
	sfilter->nr_hz_bins = 2;

	/*
	 * For complex, we don't have a separate sin and cos part,
	 * it's e^(2 * I * w), so it's the same size real or float.
	 */
	if (sfilter->nr_hz_bins < 5) {
	    /* Really, below 5 is 2, as 3 and 4 are not useful numbers. */
	    freq_incr = data->in_mark_freq - data->in_space_freq;
	    freq = data->in_space_freq;
	} else {
	    freq_incr = 1200;
	    freq = (data->in_space_freq
		    - (sfilter->nr_hz_bins / 2 - 1) * freq_incr);
	}
	for (i = 0; i < sfilter->nr_hz_bins; i++, freq += freq_incr) {
	    sfilter->hzbin[i] = o->zalloc(o, (sizeof(float) * 4
					      * sfilter->in_bitsize));
	    if (!sfilter->hzbin[i])
		goto out_nomem;
	    if (sfilter->in_format == FSK_FMT_FLOATC)
		floatc_gen_hz(sfilter->hzbin[i], sfilter->in_bitsize,
			      freq, data->in_framerate);
	    else
		float_gen_hz(sfilter->hzbin[i], sfilter->in_bitsize,
			     freq / data->in_data_rate,
			     fin_bitsize);
	}

	if (sfilter->in_format == FSK_FMT_FLOATC) {
	    sfilter->do_dftbin = floatc_dftbin;
	    sfilter->do_frame_in_copy = floatc_frame_in_copy;
	} else {
	    sfilter->do_dftbin = float_dftbin;
	    sfilter->do_frame_in_copy = float_frame_in_copy;
	}

	err = 0;
	if (data->lpcutoff && data->filt_type != NO_FILT) {
	    if (data->filt_type == IIR_FILT)
		err = setup_iir_filter(o, &sfilter->lpfilt,
				       sfilter->in_format == FSK_FMT_FLOATC,
				       true, data->in_framerate,
				       data->lpcutoff, data->lpgain);
	    else if (data->filt_type == FIR_FILT) {
		err = setup_fir_filter(o, &sfilter->lpfilt,
				       sfilter->in_format == FSK_FMT_FLOATC,
				       true, data->in_framerate,
				       data->lpcutoff, data->transition_freq,
				       data->lpgain);
		if (!err && sfilter->lpfilt.coefs_n * 2 > sfilter->in_bufsize) {
		    gensio_pparm_log(p, "fsk: "
				     "FIR filter hold size (%u) larger than input buffer (%u), sample rate is likely too high for a FIR filter",
				     sfilter->lpfilt.coefs_n * 2,
				     sfilter->in_bufsize);
		    goto out_nomem;
		}
	    }
	    if (err)
		goto out_nomem;
	}
	if (data->hpcutoff) {
	    err = setup_iir_filter(o, &sfilter->lpfilt,
				   sfilter->in_format == FSK_FMT_FLOATC,
				   false, data->in_framerate,
				   data->hpcutoff, data->hpgain);
	    if (err)
		goto out_nomem;
	}
	if (data->lpcutoff && data->filt_type != NO_FILT) {
	    sfilter->lpfilteredbuf = o->zalloc(o, (sfilter->in_framesize
						   * sfilter->in_bufsize));
	    if (!sfilter->lpfilteredbuf)
		goto out_nomem;
	}
	if (data->hpcutoff && data->filt_type != NO_FILT) {
	    sfilter->hpfilteredbuf = o->zalloc(o, (sfilter->in_framesize
						   * sfilter->in_bufsize));
	    if (!sfilter->hpfilteredbuf)
		goto out_nomem;
	}

	sfilter->workedge = sfilter->in_bitsize / 10;
	if (sfilter->workedge < MIN_WORKEDGE)
	    sfilter->workedge = MIN_WORKEDGE;
	sfilter->workmiddle = sfilter->workedge + 1;
	sfilter->workextra = (2 * sfilter->workedge) + 1;

	sfilter->worksize = sfilter->in_bitsize + 2 * sfilter->workedge;
	sfilter->workbuf = o->zalloc(o, (sfilter->worksize
					 * sfilter->in_samplesize));
	if (!sfilter->workbuf)
	    goto out_nomem;

	if (data->maxadj == 0)
	    sfilter->maxadj = sfilter->workedge / 2 + 1;
	else
	    sfilter->maxadj = data->maxadj;
	if (sfilter->maxadj == 0)
	    sfilter->maxadj = 1;
	if (data->maxadj > sfilter->workedge)
	    data->maxadj = sfilter->workedge;

	/*
	 * Complex version stores e^(I * w), real version stores sin
	 * and cos values, so they are the same size.
	 */
	sfilter->firstv = o->zalloc(o, sfilter->workedge * 4 * sizeof(float));
	if (!sfilter->firstv)
	    goto out_nomem;

	for (i = 0; i < sfilter->nr_hz_bins; i++) {
	    sfilter->pmeas[i] = o->zalloc(o, (sfilter->workextra
					      * sfilter->in_samplesize));
	    if (!sfilter->pmeas[i])
		goto out_nomem;
	}
	sfilter->pmark2 = o->zalloc(o, (sfilter->workextra
					* sfilter->in_samplesize));
	if (!sfilter->pmark2)
	    goto out_nomem;
	sfilter->pspace2 = o->zalloc(o, (sfilter->workextra
					 * sfilter->in_samplesize));
	if (!sfilter->pspace2)
	    goto out_nomem;

	sfilter->wmsgsets = o->zalloc(o, (sizeof(struct wmsgset) *
					  sfilter->wmsg_sets));
	if (!sfilter->wmsgsets)
	    goto out_nomem;
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
		if (sfilter->do_uncert) {
		    sfilter->wmsgsets[i].wmsgs[j].raw_uncertainty =
			o->zalloc(o, sfilter->max_read_size * 8);
		    if (!sfilter->wmsgsets[i].wmsgs[j].raw_uncertainty)
			goto out_nomem;
		}
	    }
	    sfilter->wmsgsets[i].wmsgs[0].in_use = true;
	    sfilter->wmsgsets[i].wmsgs[0].state = FSK_STATE_PREAMBLE_FIRST_0;
	    sfilter->wmsgsets[i].curr_wmsgs = 1;
	}

	sfilter->deliver_data = o->zalloc(o, sfilter->max_read_size);
	if (!sfilter->deliver_data)
	    goto out_nomem;

	sfilter->deliver_raw_uncertainty
	    = o->zalloc(o, sfilter->max_read_size * 8);
	if (!sfilter->deliver_raw_uncertainty)
	    goto out_nomem;

	/*
	 * NOTE - this is in received bitsize periods, because it's measured
	 * in the receive portion.
	 */
	sfilter->tx_delay = sfilter->tx_predelay_time / sfilter->in_adj_time;
    }

    if (sfilter->tx) {
	sfilter->out_bitsize = ((data->out_framerate + data->out_data_rate / 2)
				/ data->out_data_rate);
	sfilter->out_bit_time = (GENSIO_SECS_TO_NSECS(sfilter->out_bitsize) /
				 data->out_framerate);
	fout_bitsize = (float) data->out_framerate / data->out_data_rate;
	sfilter->max_out_bitsize = sfilter->out_bitsize;
	if (data->out_framerate % data->out_data_rate != 0) {
	    /*
	     * Calculate how often to adjust for the frame rate not being
	     * evenly divisible by the data rate.  If we rounded bitsize
	     * up, then it needs to be adjusted down periodically,
	     * otherwise we adjust up.
	     *
	     * Then take 1 divided by the distance from the ideal value,
	     * and that should give how often we need to adjust.  This may
	     * not be really exact, but for all practical values it works
	     * out well, and the auto-adjusting should keep us in sync as
	     * long as this is close.
	     */
	    float err = fout_bitsize - truncf(fout_bitsize);

	    if (sfilter->out_bitsize >
			data->out_framerate / data->out_data_rate) {
		/* We rounded up. */
		err = 1. - err;
		sfilter->out_bit_adj = -1;
	    } else {
		sfilter->out_bit_adj = 1;
		sfilter->max_out_bitsize++;
	    }
	    sfilter->out_bit_period = (unsigned int) ((1. / err) + 0.5);
	}

	for (i = 0; i < NR_WRITE_BUFS; i++) {
	    gensiods wrsz = sfilter->max_write_size;

	    if (sfilter->do_crc)
		/* Add 2 to allow for the CRC to be added. */
		wrsz += 2;
	    sfilter->wrbufs[i].data = o->zalloc(o, wrsz);
	    if (!sfilter->wrbufs[i].data)
		goto out_nomem;
	}

	sfilter->max_xmit_buf = sfilter->out_bufsize;
	sfilter->xmit_buf = o->zalloc(o,
				      ((gensiods) sfilter->out_bufsize
				       *sfilter->out_framesize));
	if (!sfilter->xmit_buf)
	    goto out_nomem;
    }

    sfilter->filter = gensio_filter_alloc_data(o, gensio_fsk_filter_func,
					       sfilter);
    if (!sfilter->filter)
	goto out_nomem;

    sfilter->nsec_per_frame = (((float) 1) / (float) data->out_framerate *
			       (float) GENSIO_NSECS_IN_SEC);
    if (sfilter->tx && fsk_setup_transmit(sfilter, data, fout_bitsize))
	goto out_nomem;

    return sfilter->filter;

 out_nomem:
    fsk_sfilter_free(sfilter);
    return NULL;
}

static int
fsk_child_getuint(struct gensio *child, int option, unsigned int *val)
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

static struct gensio_enum_val fsk_format_enums[] = {
    { .name = "none", .val = FSK_FMT_NONE },
    { .name = "float", .val = FSK_FMT_FLOAT },
    { .name = "floatc", .val = FSK_FMT_FLOATC },
    { }
};

static int
gensio_fsk_filter_alloc(struct gensio_pparm_info *p,
			bool is_afsk,
			struct gensio_os_funcs *o,
			struct gensio *child,
			const char * const args[],
			struct gensio_base_parms *parms,
			struct gensio_filter **rfilter,
			struct gensio **rout_child)
{
    struct gensio_filter *filter;
    struct fsk_filter *sfilter = NULL;
    struct gensio_fsk_data data = {
	.in_nchans = 0,
	.in_chan = 0,
	.out_nchans = 0,
	.out_chans = 1,
	.max_read_size = 256,
	.max_write_size = 256,
	.in_mark_freq = 0,
	.out_mark_freq = 0,
	.in_space_freq = 0,
	.out_space_freq = 0,
	.in_data_rate = 2400,
	.out_data_rate = 2400,
	.in_format = FSK_FMT_NONE,
	.out_format = FSK_FMT_NONE,
	.rx = true,
	.tx = true,
	.in_framerate = 0,
	.out_framerate = 0,
	.in_bufsize = 0,
	.out_bufsize = 0,
	.max_wmsgs = 1,
	.min_certainty = 3.5,
	.filt_type = IIR_FILT,
	.filt_type_set = false,
	.lpcutoff = 0,
	.lpgain = .9,
	.hpcutoff = 0,
	.hpgain = .9,
	.maxadj = 0,
	.transition_freq = 500,
	.tx_preamble_time = 300,
	.tx_postamble_time = 100,
	.tx_predelay_time = 500,
	.volume = .75,
	.full_duplex = false,
	KEYDATA_INIT(.keydata),
	.do_crc = false,
	.in_do_inv = false,
	.out_do_inv = false,
	.in_do_diff = false,
	.out_do_diff = false,
	.do_raw = true,
	.certainty_multiplier = 100.0,
    };
    unsigned int i;
    int err;
    int intval;
    unsigned int uintval;
    char cdata[30];
    gensiods cdata_len;
    unsigned int chan;
    unsigned int wmsg_extra = 0;
    struct gensio *out_child = child;

    if (is_afsk) {
	data.in_data_rate = 1200,
	data.out_data_rate = 1200,
	data.in_mark_freq = 2200.;
	data.out_mark_freq = 2200.;
	data.in_space_freq = 1200.;
	data.out_space_freq = 1200.;
	data.max_wmsgs = 32;
	wmsg_extra = 1;
	data.lpcutoff = 2300;
	data.do_crc = true;
	data.in_do_inv = true;
	data.out_do_inv = true;
	data.in_do_diff = true;
	data.out_do_diff = true;
	data.do_raw = false;
	data.certainty_multiplier = 1.0;
    }

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_value(p, args[i], "outgen", &data.outgen) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "rx", &data.rx) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "tx", &data.tx) > 0)
	    continue;
	if (gensio_pparm_ds(p, args[i], "readbuf", &data.max_read_size) > 0)
	    continue;
	if (gensio_pparm_ds(p, args[i], "writebuf", &data.max_write_size) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "in_bufsize", &data.in_bufsize) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "out_bufsize", &data.out_bufsize) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "bufsize", &uintval) > 0) {
	    data.in_bufsize = uintval;
	    data.out_bufsize = uintval;
	    continue;
	}
	if (gensio_pparm_uint(p, args[i], "nchans", &data.in_nchans) > 0) {
	    data.out_nchans = data.in_nchans;
	    continue;
	}
	if (gensio_pparm_uint(p, args[i], "in_nchans", &data.in_nchans) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "out_nchans", &data.out_nchans) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "chan", &data.in_chan) > 0) {
	    data.out_chans = 1 << data.in_chan;
	    continue;
	}
	if (gensio_pparm_uint(p, args[i], "in_chan", &data.in_chan) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "out_chans", &data.out_chans) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "out_chan", &chan) > 0) {
	    data.out_chans = 1 << chan;
	    continue;
	}
	if (gensio_pparm_enum(p, args[i], "format", fsk_format_enums,
				 &intval) > 0) {
	    data.in_format = intval;
	    data.out_format = intval;
	    continue;
	}
	if (gensio_pparm_enum(p, args[i], "in_format", fsk_format_enums,
			      (int *) &data.in_format) > 0)
	    continue;
	if (gensio_pparm_enum(p, args[i], "out_format", fsk_format_enums,
			      (int *) &data.out_format) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "samplerate",
				 &data.in_framerate) > 0) {
	    data.out_framerate = data.in_framerate;
	    continue;
	}
	if (gensio_pparm_uint(p, args[i], "in_samplerate",
				 &data.in_framerate) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "out_samplerate",
				 &data.in_framerate) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "freqadj",
			      &data.in_do_freqadj) > 0) {
	    data.out_do_freqadj = data.in_do_freqadj;
	    continue;
	}
	if (gensio_pparm_bool(p, args[i], "in_freqadj",
			      &data.in_do_freqadj) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "out_freqadj",
			      &data.out_do_freqadj) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "wmsgs", &data.max_wmsgs) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "wmsg-extra", &wmsg_extra) > 0)
	    continue;
	if (gensio_pparm_float(p, args[i], "min-certainty",
				  &data.min_certainty) > 0)
	    continue;
	if (gensio_pparm_enum(p, args[i], "filttype", filttype_enums,
				 &data.filt_type) > 0) {
	    data.filt_type_set = true;
	    continue;
	}
	if (gensio_pparm_uint(p, args[i], "lpcutoff", &data.lpcutoff) > 0)
	    continue;
	if (gensio_pparm_float(p, args[i], "lpgain", &data.lpgain) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "hpcutoff", &data.hpcutoff) > 0)
	    continue;
	if (gensio_pparm_float(p, args[i], "hpgain", &data.hpgain) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "maxadj", &data.maxadj) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "trfreq", &data.transition_freq) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "tx-preamble",
				 &data.tx_preamble_time) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "tx-tail",
				 &data.tx_postamble_time) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "tx-predelay",
				 &data.tx_predelay_time) > 0)
	    continue;
	if (gensio_pparm_float(p, args[i], "volume", &data.volume) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "bps", &data.in_data_rate) > 0) {
	    data.out_data_rate = data.in_data_rate;
	    continue;
	}
	if (gensio_pparm_uint(p, args[i], "in_bps", &data.in_data_rate) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "out_bps", &data.out_data_rate) > 0)
	    continue;
	if (gensio_pparm_float(p, args[i], "space", &data.in_space_freq) > 0) {
	    data.out_space_freq = data.in_space_freq;
	    continue;
	}
	if (gensio_pparm_float(p, args[i], "in_space", &data.in_space_freq) > 0)
	    continue;
	if (gensio_pparm_float(p, args[i], "out_space",
			       &data.out_space_freq) > 0)
	    continue;
	if (gensio_pparm_float(p, args[i], "mark", &data.in_mark_freq) > 0) {
	    data.out_mark_freq = data.in_mark_freq;
	    continue;
	}
	if (gensio_pparm_float(p, args[i], "in_mark", &data.in_mark_freq) > 0)
	    continue;
	if (gensio_pparm_float(p, args[i], "out_mark", &data.out_mark_freq) > 0)
	    continue;
	if (key_pparm(p, args[i], &data.keydata))
	    continue;
	if (gensio_pparm_bool(p, args[i], "full-duplex", &data.full_duplex) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "debug", &data.debug) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "checkax25", &data.check_ax25) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "crc", &data.do_crc) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "raw", &data.do_raw) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "uncert", &data.do_uncert) > 0)
	    continue;
	if (gensio_pparm_float(p, args[i], "certmult",
			       &data.certainty_multiplier) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "inv", &data.in_do_inv) > 0) {
	    data.out_do_inv = data.in_do_inv;
	    continue;
	}
	if (gensio_pparm_bool(p, args[i], "in_inv", &data.in_do_inv) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "out_inv", &data.out_do_inv) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "diff", &data.in_do_diff) > 0) {
	    data.out_do_diff = data.in_do_diff;
	    continue;
	}
	if (gensio_pparm_bool(p, args[i], "in_diff", &data.in_do_diff) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "out_diff", &data.out_do_diff) > 0)
	    continue;
	if (gensio_base_parm(parms, p, args[i]) > 0)
	    continue;
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

    if (!data.rx && !data.tx) {
	gensio_pparm_slog(p, "RX and/or TX must be enabled\n");
	return GE_INCONSISTENT;
    }
    if (data.tx && !data.rx)
	data.full_duplex = true;

    /* Force things off that don't make sense. */
    if (data.do_raw)
	data.do_crc = false;
    else
	data.do_uncert = false;

    if (data.outgen) {
	err = str_to_gensio(data.outgen, o, NULL, NULL, &out_child);
	if (err) {
	    gensio_pparm_log(p, "cannot allocate outdev '%s': %s\n",
			     data.outgen, gensio_err_to_str(err));
	    return err;
	}
    }

    /* After this point we must free out_child if we allocated it. */
#define MY_STRINGIZE(s) #s
#define CHECK_VAL(d, cmp, v)						\
    if (data.d cmp v) {							\
	gensio_pparm_log(p, #d " cannot be " #cmp " %d\n", v);		\
	goto out_inval;							\
    }

    if (data.rx && data.in_bufsize == 0) {
	err = fsk_child_getuint(child, GENSIO_CONTROL_IN_BUFSIZE,
				&data.in_bufsize);
	if (err) {
	    gensio_pparm_slog(p, "Unable to get input bufsize, is the child a sound card?");
	    goto out_err;
	}
    }
    if (data.rx && data.in_framerate == 0) {
	err = fsk_child_getuint(child, GENSIO_CONTROL_IN_RATE,
				&data.in_framerate);
	if (err) {
	    gensio_pparm_slog(p, "Unable to get input framerate, is the child a sound card?");
	    goto out_err;
	}
    }
    if (data.rx && data.in_nchans == 0) {
	err = fsk_child_getuint(child, GENSIO_CONTROL_IN_NR_CHANS,
				&data.in_nchans);
	if (err) {
	    gensio_pparm_slog(p, "Unable to get input number of channels, is the child a sound card?");
	    goto out_err;
	}
    }

    if (data.tx && data.out_bufsize == 0) {
	err = fsk_child_getuint(out_child, GENSIO_CONTROL_OUT_BUFSIZE,
				&data.out_bufsize);
	if (err) {
	    gensio_pparm_slog(p, "Unable to get output bufsize, is the child a sound card?");
	    goto out_err;
	}
    }
    if (data.tx && data.out_framerate == 0) {
	err = fsk_child_getuint(out_child, GENSIO_CONTROL_OUT_RATE,
				&data.out_framerate);
	if (err) {
	    gensio_pparm_slog(p, "Unable to get output framerate, is the child a sound card?");
	    goto out_err;
	}
    }
    if (data.tx && data.out_nchans == 0) {
	err = fsk_child_getuint(out_child, GENSIO_CONTROL_OUT_NR_CHANS,
				&data.out_nchans);
	if (err) {
	    gensio_pparm_slog(p, "Unable to get output number of channels, is the child a sound card?");
	    goto out_err;
	}
    }

    if (data.rx && data.in_format == FSK_FMT_NONE) {
	cdata_len = sizeof(cdata);
	err = gensio_control(child, GENSIO_CONTROL_DEPTH_FIRST, true,
			     GENSIO_CONTROL_IN_FORMAT, cdata, &cdata_len);
	if (!err) {
	    if (strcmp(cdata, "float") == 0) {
		data.in_format = FSK_FMT_FLOAT;
	    } else if (strcmp(cdata, "floatc") == 0) {
		data.in_format = FSK_FMT_FLOATC;
	    } else {
		gensio_pparm_slog(p, "Child input format is not float or floatc");
		return GE_INCONSISTENT;
	    }
	}
    }

    if (data.tx && data.out_format == FSK_FMT_NONE) {
	cdata_len = sizeof(cdata);
	err = gensio_control(out_child, GENSIO_CONTROL_DEPTH_FIRST, true,
			     GENSIO_CONTROL_OUT_FORMAT, cdata, &cdata_len);
	if (!err) {
	    if (strcmp(cdata, "float") == 0) {
		data.out_format = FSK_FMT_FLOAT;
	    } else if (strcmp(cdata, "floatc") == 0) {
		data.out_format = FSK_FMT_FLOATC;
	    } else {
		gensio_pparm_slog(p, "Child output format is not float or floatc");
		return GE_INCONSISTENT;
	    }
	}
    }

    if (data.rx) {
	CHECK_VAL(in_chan, >=, data.in_nchans);
	CHECK_VAL(max_wmsgs, ==, 0);
    }

    if (data.tx) {
	CHECK_VAL(out_chans, >=, (1U << data.out_nchans));
    }

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

    if (data.in_do_freqadj) {
	if (data.in_mark_freq < 0.1)
	    data.in_mark_freq = data.in_data_rate * 4;
	if (data.in_space_freq < 0.1)
	    data.in_space_freq = data.in_mark_freq - data.in_data_rate / 2;
	if (data.lpcutoff == 0)
	    data.lpcutoff = data.in_mark_freq * 2;
    } else if (data.in_format == FSK_FMT_FLOATC) {
	if (data.in_mark_freq < 0.1)
	    data.in_mark_freq = data.in_data_rate / 4;
	if (data.in_space_freq < 0.1)
	    data.in_space_freq = -data.in_mark_freq;
	if (data.lpcutoff == 0)
	    data.lpcutoff = data.in_mark_freq * 4;
    } else {
	if (data.in_mark_freq < 0.1)
	    data.in_mark_freq = data.in_data_rate;
	if (data.in_space_freq < 0.1)
	    data.in_space_freq = data.in_mark_freq / 2;
	if (data.lpcutoff == 0)
	    data.lpcutoff = data.in_mark_freq * 2;
    }

    if (data.out_do_freqadj) {
	if (data.out_mark_freq < 0.1)
	    data.out_mark_freq = data.out_data_rate * 4;
	if (data.out_space_freq < 0.1)
	    data.out_space_freq = data.out_mark_freq - data.out_data_rate / 2;
	if (data.lpcutoff == 0)
	    data.lpcutoff = data.in_mark_freq * 2;
    } else if (data.out_format == FSK_FMT_FLOATC) {
	if (data.out_mark_freq < 0.1)
	    data.out_mark_freq = data.out_data_rate / 4;
	if (data.out_space_freq < 0.1)
	    data.out_space_freq = -data.out_mark_freq;
    } else {
	if (data.out_mark_freq < 0.1)
	    data.out_mark_freq = data.out_data_rate;
	if (data.out_space_freq < 0.1)
	    data.out_space_freq = data.out_mark_freq / 2;
    }

    data.wmsg_sets = wmsg_extra * 2 + 1;

    filter = gensio_fsk_filter_raw_alloc(p, o, child, is_afsk, &data);
    if (!filter)
	return GE_NOMEM;

    sfilter = filter_to_fsk(filter);
    if (data.in_do_freqadj && sfilter->rx) {
	char adjstr[20];
	gensiods len;

	len = snprintf(adjstr, sizeof(adjstr), "%f",
		       - ((data.in_mark_freq + data.in_space_freq) / 2));
	err = gensio_control(child, GENSIO_CONTROL_DEPTH_FIRST, false,
			    GENSIO_CONTROL_IN_FREQ_ADJ, adjstr, &len);
	if (err) {
	    gensio_pparm_slog(p, "Unable to get set input frequency adjustment, can the child gensio do this?");
	    goto out_err;
	}
    }
    if (data.out_do_freqadj && sfilter->tx) {
	char adjstr[20];
	gensiods len;

	len = snprintf(adjstr, sizeof(adjstr), "%f",
		       - ((data.out_mark_freq + data.out_space_freq) / 2));
	err = gensio_control(out_child, GENSIO_CONTROL_DEPTH_FIRST, false,
			    GENSIO_CONTROL_OUT_FREQ_ADJ, adjstr, &len);
	if (err) {
	    gensio_pparm_slog(p, "Unable to get set output frequency adjustment, can the child gensio do this?");
	    goto out_err;
	}
    }

    if (data.debug & GENSIO_FSK_DEBUG_DUMP_PARMS && data.rx) {
	printf("in_mark = %f\n", data.in_mark_freq);
	printf("in_space = %f\n", data.in_space_freq);
	printf("in_freqadj = %f\n", -((data.in_mark_freq + data.in_space_freq) / 2));

	printf("lpcutoff = %u\n", data.lpcutoff);
	printf("hpcutoff = %u\n", data.hpcutoff);
    }

    if (data.debug & GENSIO_FSK_DEBUG_DUMP_PARMS && data.tx) {
	printf("out_mark = %f\n", data.out_mark_freq);
	printf("out_space = %f\n", data.out_space_freq);
	printf("out_freqadj = %f\n", -((data.out_mark_freq + data.out_space_freq) / 2));
    }

    *rfilter = filter;
    if (out_child != child)
	*rout_child = out_child;
    return 0;
 out_inval:
    err = GE_INVAL;
 out_err:
    if (sfilter)
	fsk_sfilter_free(sfilter);
    if (out_child != child)
	gensio_free(out_child);
    return err;
}

static int
i_fsk_gensio_alloc(struct gensio *child, const char *const args[],
		   bool is_afsk, struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io, *out_child = NULL;
    struct gensio_base_parms *parms = NULL;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "fsk", user_data);

    err = gensio_base_parms_alloc(o, true, "fsk", &parms);
    if (err)
	goto out_err;

    err = gensio_fsk_filter_alloc(&p, is_afsk, o, child, args, parms, &filter,
				  &out_child);
    if (err)
	goto out_err;

    ll = gensio_2gensio_ll_alloc(o, child, out_child);
    if (!ll) {
	gensio_filter_free(filter);
	goto out_nomem;
    }

    /*
     * So gensio_ll_free doesn't free the child if this fails.  It
     * will free out_child, but that's ok.
     */
    gensio_ref(child);
    io = base_gensio_alloc(o, ll, filter, child, "fsk", cb, user_data);
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

    *new_gensio = io;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
i_str_to_fsk_gensio(const char *str, const char * const args[],
		    bool is_afsk, struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    /* cb is passed in for parmerr handling, it will be overridden later. */
    err = str_to_gensio(str, o, cb, user_data, &io2);
    if (err)
	return err;

    err = i_fsk_gensio_alloc(io2, args, is_afsk, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

static int
fsk_gensio_alloc(struct gensio *child, const char *const args[],
		 struct gensio_os_funcs *o,
		 gensio_event cb, void *user_data,
		 struct gensio **new_gensio)
{
    return i_fsk_gensio_alloc(child, args, false, o, cb, user_data, new_gensio);
}

static int
str_to_fsk_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return i_str_to_fsk_gensio(str, args, false, o, cb, user_data, new_gensio);
}

static int
afsk_gensio_alloc(struct gensio *child, const char *const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return i_fsk_gensio_alloc(child, args, true, o, cb, user_data, new_gensio);
}

static int
str_to_afsk_gensio(const char *str, const char * const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **new_gensio)
{
    return i_str_to_fsk_gensio(str, args, true, o, cb, user_data, new_gensio);
}

int
gensio_init_fsk(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "fsk",
				str_to_fsk_gensio, fsk_gensio_alloc);
    if (rv)
	return rv;

    rv = register_filter_gensio(o, "afskmdm",
				str_to_afsk_gensio, afsk_gensio_alloc);
    if (rv) {
	return rv;
    }

    return 0;
}
