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

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_time.h>
#include <gensio/gensio_ax25_addr.h>

#include "convcode.h"

/*
 * Holds data for deliver to the upper or lower layer.
 */
struct delivermsg {
    unsigned char *data;
    gensiods pos;
    gensiods len;
};

struct axfec_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    struct convcode *ce;

    unsigned int debug;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    enum {
	AXFEC_NOT_IN_SYNC,
	AXFEC_IN_PREAMBLE,
	AXFEC_IN_DATA,
	AXFEC_IN_POSTAMBLE,
    } state;

    unsigned int preamble_len;

    /* Maximum bits that can come out of the decoder. */
    unsigned int max_dec_out_bits;

    /* Maximum bits that can come out of the encoder. */
    unsigned int max_enc_bits;

    /* Maximum bits you can put into the decoder. */
    unsigned int max_dec_bits;

    /* The number of decode bits currently in the decoder. */
    unsigned int num_dec_bits;

    /*
     * The following is used to build the 32-bit sync compare and the
     * 16-bit processing data to feed into the interleaver.
     */
    unsigned int out_build_pos;
    uint32_t out_build_data;

    /*
     * While building the sync compare or the 16-bit processing data,
     * this holds the uncertainty data for the bits in the above data.
     */
    unsigned int build_uncert_pos;
    unsigned char build_uncert[32];

    /*
     * This is for taking data out of the interleaver and putting it
     * into the convolutional decoder.
     */
    uint16_t out_to_dec;
    unsigned char dec_uncert[16];
    unsigned int out_to_dec_pos;

    /*
     * Number of flags we have received in the preamble or postamble.
     */
    unsigned int amble_flags;

    /* One count for HDLC read processing. */
    unsigned int one_count;

    int err;

    /* Actual buffer sizes, needed to zero the buffers. */
    unsigned int read_deliver_size;
    unsigned int write_deliver_size;

    /* Data to deliver to the upper layer. */
    gensiods max_read_size;
#define MAX_READ_DELIVER_MSGS 8
    struct delivermsg readmsgs[MAX_READ_DELIVER_MSGS];
    unsigned int num_readmsgs;
    unsigned int curr_readmsg;

    /* Data to deliver to the lower layer. */
    gensiods max_write_size;
#define MAX_WRITE_DELIVER_MSGS 2
    struct delivermsg writemsgs[MAX_WRITE_DELIVER_MSGS];
    unsigned int num_writemsgs;
    unsigned int curr_writemsg;
};

#include "crc.h"

/* Add timestamps to messages. */
#define GENSIO_HDLC_DEBUG_TIME		0x10

/* Dump full received/sent messages. */
#define GENSIO_HDLC_DEBUG_MSG		0x08

/* Dump some state handing information. */
#define GENSIO_HDLC_DEBUG_STATE		0x04

/* Dump raw bit handling information. */
#define GENSIO_HDLC_DEBUG_BIT_HNDL	0x02

/* Dump raw messages */
#define GENSIO_HDLC_DEBUG_RAW_MSG	0x01

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
axfec_ax25_prmsg(struct gensio_os_funcs *o,
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
axfec_print_msg(struct axfec_filter *sfilter, char *t, unsigned int msgn,
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
	axfec_ax25_prmsg(sfilter->o, buf, buflen);
    }
    printf("\n");
    gensio_fdump_init(&h, 1);
    gensio_fdump_buf(stdout, buf, buflen, &h);
    gensio_fdump_buf_finish(stdout, &h);
    fflush(stdout);
}

#define filter_to_axfec(v) ((struct axfec_filter *)		\
			       gensio_filter_get_user_data(v))

static void
axfec_lock(struct axfec_filter *sfilter)
{
    sfilter->o->lock(sfilter->lock);
}

static void
axfec_unlock(struct axfec_filter *sfilter)
{
    sfilter->o->unlock(sfilter->lock);
}

static void
axfec_set_callbacks(struct gensio_filter *filter,
		      gensio_filter_cb cb, void *cb_data)
{
    struct axfec_filter *sfilter = filter_to_axfec(filter);

    sfilter->filter_cb = cb;
    sfilter->filter_cb_data = cb_data;
}

static bool
axfec_ul_read_pending(struct gensio_filter *filter)
{
    struct axfec_filter *sfilter = filter_to_axfec(filter);
    bool rv;

    axfec_lock(sfilter);
    rv = sfilter->num_readmsgs > 0;
    axfec_unlock(sfilter);
    return rv;
}

static bool
axfec_ll_write_pending(struct gensio_filter *filter)
{
    struct axfec_filter *sfilter = filter_to_axfec(filter);
    bool rv;

    axfec_lock(sfilter);
    rv = sfilter->num_writemsgs > 0;
    axfec_unlock(sfilter);
    return rv;
}

static bool
axfec_ll_read_needed(struct gensio_filter *filter)
{
    return false;
}

static int
axfec_ul_can_write(struct gensio_filter *filter, bool *val)
{
    struct axfec_filter *sfilter = filter_to_axfec(filter);

    axfec_lock(sfilter);
    *val = sfilter->num_writemsgs < MAX_WRITE_DELIVER_MSGS;
    axfec_unlock(sfilter);

    return 0;
}

static int
axfec_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static int
axfec_try_connect(struct gensio_filter *filter, gensio_time *timeout,
		     bool was_timeout)
{
    return 0;
}

static int
axfec_try_disconnect(struct gensio_filter *filter, gensio_time *timeout,
			bool was_timeout)
{
    return 0;
}

#define SWAP(type, x, y) do { type tmp = (x); (x) = (y); (y) = tmp; } while (0)

static void
interleave_bits(unsigned char *buf, unsigned char *uncert)
{
    uint16_t interleave = buf[0] | (buf[1] << 8);

    buf[0]= 0;
    buf[1]= 0;
    /*
     * 0  4  8 12  1  5  9 13 - interleave bit
     * 0  1  2  3  4  5  6  7 - output bit
     */
    buf[0] = ((interleave & 0x01) | ((interleave >> 3) & 0x02)
	      | ((interleave >> 6) & 0x04) | ((interleave >> 9) & 0x08)
	      | ((interleave << 3) & 0x10) | (interleave & 0x20)
	      | ((interleave >> 3) & 0x40) | ((interleave >> 6) & 0x80));
    /*
     * 2  6 10 14  3  7 11 15 - interleave bit
     * 0  1  2  3  4  5  6  7 - output bit
     */
    buf[1] = (((interleave >> 2) & 0x01) | ((interleave >> 5) & 0x02)
	      | ((interleave >> 8) & 0x04) | ((interleave >> 11) & 0x08)
	      | ((interleave << 1) & 0x10) | ((interleave >> 2) & 0x20)
	      | ((interleave >> 5) & 0x40) | ((interleave >> 8) & 0x80));

    if (uncert) {
	/*
	 *  0  1  2  3
	 *  4  5  6  7
	 *  8  9 10 11
	 * 12 13 14 15
	 */
	SWAP(unsigned char, uncert[4], uncert[1]);
	SWAP(unsigned char, uncert[8], uncert[2]);
	SWAP(unsigned char, uncert[12], uncert[3]);
	SWAP(unsigned char, uncert[9], uncert[6]);
	SWAP(unsigned char, uncert[13], uncert[7]);
	SWAP(unsigned char, uncert[14], uncert[11]);
    }
}

#if 0
static void
pr_buf(const char *str, unsigned char *buf, unsigned int len)
{
    unsigned int i;

    printf("%s: ", str);
    for (i = 0; i < len; i++) {
	unsigned int bytep = i / 8;
	unsigned int bitp = i % 8;

	printf("%d", (buf[bytep] >> bitp) & 1);
    }
    printf("\n");
}
#endif

static int
axfec_ul_write(struct gensio_filter *filter,
		  gensio_ul_filter_data_handler handler, void *cb_data,
		  gensiods *rcount,
		  const struct gensio_sg *sg, gensiods sglen,
		  const char *const *auxdata)
{
    struct axfec_filter *sfilter = filter_to_axfec(filter);
    gensiods i, count = 0, pos, len;
    unsigned int cbuf, outbitpos;
    unsigned char *outbuf;
    unsigned char byte, crcbytes[2];
    unsigned int numones;
    uint16_t crc = 0xffff;
    int rv = 0;

    axfec_lock(sfilter);
    if (sfilter->err) {
	rv = sfilter->err;
	goto out;
    }
    if (sfilter->num_writemsgs >= MAX_WRITE_DELIVER_MSGS || sglen == 0)
	goto out_process;

    for (i = 0, count = 0; i < sglen; i++) {
	crc16_ccitt(sg[i].buf, sg[i].buflen, &crc);
	count += sg[i].buflen;
    }
    crc ^= 0xffff;
    crcbytes[0] = crc & 0xff;
    crcbytes[1] = (crc >> 8) & 0xff;

    if (count == 0)
	goto out_process;
    if (count > sfilter->max_write_size) {
	rv = GE_TOOBIG;
	goto out;
    }

    cbuf = ((sfilter->curr_writemsg + sfilter->num_writemsgs)
	    % MAX_WRITE_DELIVER_MSGS);
    outbuf = sfilter->writemsgs[cbuf].data;

    if (sfilter->debug & GENSIO_HDLC_DEBUG_MSG) {
	unsigned int tmplen = 0;

	/* Abuse the outbuf to hold the data to print. */
	for (i = 0; i < sglen; i++) {
	    memcpy(outbuf + tmplen, sg[i].buf, sg[i].buflen);
	    tmplen += sg[i].buflen;
	}
	axfec_print_msg(sfilter, "W", 0, outbuf, tmplen, false);
    }

    reinit_convencode(sfilter->ce);
    outbitpos = 0;

    /* convcode requires the buffer to be zero-ed first. */
    memset(outbuf, 0, sfilter->read_deliver_size);

    /*
     * We have to shove in one extra bit at the beginning to make the
     * ax5043 work.
     */
    byte = 0;
    convencode_block_partial(sfilter->ce, &byte, 1, &outbuf, &outbitpos);

    /* Put in the preamble. */
    byte = 0x7e;
    for (i = 0; i < sfilter->preamble_len; i++)
	convencode_block_partial(sfilter->ce, &byte, 8, &outbuf, &outbitpos);

    /*
     * Now go through the bytes, do bit stuffing, and put them into
     * the convolutional encoder.
     */
    numones = 0;
    /* We do the crc at i == sglen. */
    for (i = 0; i < sglen + 1; i++) {
	const unsigned char *buf;
	unsigned int len, j, k;

	if (i == sglen) {
	    buf = crcbytes;
	    len = 2;
	} else {
	    buf = sg[i].buf;
	    len = sg[i].buflen;
	}

	for (j = 0; j < len; j++) {
	    byte = buf[j];
	    for (k = 0; k < 8; k++) {
		if (byte & 1)
		    numones++;
		else
		    numones = 0;
		convencode_block_partial(sfilter->ce, &byte, 1,
					 &outbuf, &outbitpos);
		if (numones == 5) {
		    byte &= 0xfe; /* Stuff in a zero bit. */
		    convencode_block_partial(sfilter->ce, &byte, 1,
					     &outbuf, &outbitpos);
		    numones = 0;
		}
		byte >>= 1;
	    }
	}
    }
    /* Now the postamble. */
    byte = 0x7e;
    convencode_block_partial(sfilter->ce, &byte, 8, &outbuf, &outbitpos);
    convencode_block_final(sfilter->ce, &outbuf, &outbitpos);

    /* Extend out to a multiple of 16 bits. */
    len = outbuf - sfilter->writemsgs[cbuf].data;
    if (outbitpos > 0)
	len++;
    if (len & 1)
	len++; /* Round up to 16 bits. */

    outbuf = sfilter->writemsgs[cbuf].data;

    /* Now flip every other bit and interleave the bits. */
    for (i = 0; i < len; i += 2) {
	outbuf[i] ^= 0x55;
	outbuf[i + 1] ^= 0x55;
	interleave_bits(outbuf + i, NULL);
    }

    sfilter->writemsgs[cbuf].len = len;
    sfilter->writemsgs[cbuf].pos = 0;
    
    sfilter->num_writemsgs++;

 out_process:
    if (sfilter->num_writemsgs > 0) {
	struct gensio_sg sg;

	cbuf = sfilter->curr_writemsg;
	pos = sfilter->writemsgs[cbuf].pos;
	sg.buf = sfilter->writemsgs[cbuf].data + pos;
	sg.buflen = sfilter->writemsgs[cbuf].len - pos;
	rv = handler(cb_data, &len, &sg, 1, NULL);
	if (rv) {
	    sfilter->err = rv;
	    sfilter->num_writemsgs = 0;
	} else if (len < sg.buflen) {
	    sfilter->writemsgs[cbuf].pos += len;
	} else {
	    sfilter->curr_writemsg = (cbuf + 1) % MAX_WRITE_DELIVER_MSGS;
	    sfilter->num_writemsgs--;
	}
    }
 out:
    axfec_unlock(sfilter);
    if (!rv && rcount)
	*rcount = count;

    return rv;
}

/* Reverse the order of the array. */
static void byte_reverse(unsigned char *x, int start, int end)
{
    while (start < end) {
	SWAP(unsigned char, x[start], x[end]);
        start++;
        end--;
    }
}

/* Rotate the array x that is n bytes long left by k elements. */
static void byte_shift(unsigned char *x, unsigned int n, unsigned int k)
{
    byte_reverse(x, 0, n - 1);
    byte_reverse(x, 0, n - k - 1);
    byte_reverse(x, n - k, n - 1);
}

static bool
check_crc(unsigned char *buf, unsigned int len)
{
    uint16_t crc = 0xffff, msgcrc;

    crc16_ccitt(buf, len - 2, &crc);
    crc ^= 0xffff;
    msgcrc = (buf[len - 1] << 8) | buf[len - 2];
    return crc == msgcrc;
}

static bool
unstuff_bits(unsigned char *buf, unsigned int *rbitlen)
{
    unsigned int i, j, one_count = 0, bitlen = *rbitlen;

    for (i = 0, j = 0; i < bitlen; i++) {
	unsigned int inbytepos = i / 8;
	unsigned int inbitpos = i % 8;
	unsigned int outbytepos = j / 8;
	unsigned int outbitpos = j % 8;
	unsigned char bit = (buf[inbytepos] >> inbitpos) & 1;

	if (bit)
	    buf[outbytepos] |= 1 << outbitpos;
	else
	    buf[outbytepos] &= ~(1 << outbitpos);
	j++;
	if (bit) {
	    one_count++;
	    if (one_count >= 5) {
		/*
		 * Skip the next bit.  Previous processing should have
		 * assured that the next bit is a zero.
		 */
		i++;
		one_count = 0;
		if (i == bitlen)
		    /*
		     * Can't have 5 ones at the end, must have a
		     * stuffed bit afterwards.
		     */
		    return false;
	    }
	} else {
	    one_count = 0;
	}
    }
    *rbitlen = j;
    return true;
}

/* 10001010111001101000101011100110, backwards */
#define SYNCWORD 0x67516751

static int
axfec_ll_write(struct gensio_filter *filter,
		  gensio_ll_filter_data_handler handler, void *cb_data,
		  gensiods *rcount,
		  unsigned char *buf, gensiods buflen,
		  const char *const *auxdata)
{
    struct axfec_filter *sfilter = filter_to_axfec(filter);
    unsigned char *uncertainty;
    gensiods count;
    struct delivermsg *d;
    unsigned char bits, tmpbits, bytes[4];
    uint16_t tmpbits16;
    uint32_t bit; /* Needs to be 32 for shifting. */
    unsigned int cbuf, j, k, upos;
    int err = 0;

    if (gensio_str_in_auxdata(auxdata, "oob")) {
	/* Ignore oob data. */
	if (rcount)
	    *rcount = buflen;
	return 0;
    }

    axfec_lock(sfilter);
    if (sfilter->err) {
	err = sfilter->err;
	goto out;
    }

    uncertainty = gensio_find_auxdata_ptr(auxdata, "uncert=");

#if 0
    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
	printf("Processing %lu bytes\n", (unsigned long) buflen);
#endif

    if (sfilter->num_readmsgs >= MAX_READ_DELIVER_MSGS || buflen == 0) {
	j = 0; /* Didn't accept any data. */
	goto out_process;
    }

    j = 0;
    k = 8;
    upos = 0;
 restart:
    if (sfilter->state != AXFEC_NOT_IN_SYNC)
	goto do_synced;

    for (; j < buflen; j++) {
	if (k >= 8) {
	    k = 0;
	    bits = buf[j];
	}
	for (; k < 8; k++, bits >>= 1) {
	    bit = bits & 1;
	    sfilter->out_build_data >>= 1;
	    sfilter->out_build_data |= (bit << 31);
	    if (uncertainty) {
		/*
		 * In sync detection the build_uncert array is
		 * kept as a circular array, we shift it into
		 * location when we detect a possible sync.
		 */
		sfilter->build_uncert[sfilter->build_uncert_pos++]
		    = uncertainty[upos++];
		sfilter->build_uncert_pos %= 32;
	    }
	    if (__builtin_popcount(sfilter->out_build_data ^ SYNCWORD) < 4) {
		unsigned char build_uncert[32];

		if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
		    printf("Got sync\n");
		/*
		 * Maybe in sync!  Shove the data into the
		 * encoder to prime it, then check for a flag.
		 */

		reinit_convdecode(sfilter->ce);

		/* Put into an array. */
		bytes[0] = sfilter->out_build_data & 0xff;
		bytes[1] = (sfilter->out_build_data >> 8) & 0xff;
		bytes[2] = (sfilter->out_build_data >> 16) & 0xff;
		bytes[3] = (sfilter->out_build_data >> 24) & 0xff;
		memcpy(build_uncert, sfilter->build_uncert, 32);

		/*
		 * Next location will be where the uncertainty
		 * for the first bit is, so rotate that around
		 * so we have the zero byte in sync as the zero
		 * location in build_uncert.
		 */
		byte_shift(build_uncert, 32,
			   (sfilter->build_uncert_pos + 1) % 32);

		interleave_bits(bytes, build_uncert);
		interleave_bits(bytes + 2, build_uncert + 16);

		/* Now flip the bits that need it. */
		bytes[0] ^= 0x55;
		bytes[1] ^= 0x55;
		bytes[2] ^= 0x55;
		bytes[3] ^= 0x55;

		/*
		 * Don't put in the first two bits.  Those are
		 * for the extra 0 pushed in at the beginning
		 * of the sequence, and they mess things up.
		 * If we skip it, things line up nicely.
		 */
		bytes[0] >>= 2;

		convdecode_data_u(sfilter->ce, bytes, 6,
				  build_uncert + 2);
		convdecode_data_u(sfilter->ce, bytes + 1, 18,
				  build_uncert + 10);

		/*
		 * With the above processing, if you do a
		 * decode on the data you will get a flag out
		 * of the end on a byte boundary.
		 */
		tmpbits = 0;
		convdecode_last_n_block(sfilter->ce, &tmpbits, 8,
					NULL, NULL);
		if (tmpbits == 0x7e) {
		    /*
		     * Got a flag, we are officially in sync!
		     *
		     * We have dropped two bits and put 24 output bits
		     * into the decoder.  We have 6 bits left, set
		     * that up to be ready to decode.
		     */
		    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
			printf("Got first flag\n");
		    sfilter->amble_flags = 1;
		    sfilter->out_to_dec = bytes[3] >> 2;
		    sfilter->out_to_dec_pos = 6;
		    memcpy(sfilter->dec_uncert,
			   sfilter->build_uncert + 32 - 6,
			   6);

		    sfilter->out_build_data = 0;
		    sfilter->out_build_pos = 0;
		    reinit_convdecode_last_bits(sfilter->ce, 4);
		    sfilter->num_dec_bits = 8;
		    sfilter->state = AXFEC_IN_PREAMBLE;
		    sfilter->one_count = 0;
		    k++;
		    if (k >= 8)
			j++;
		    else
			bits >>= 1;
		    goto do_synced;
		}
	    }
	}
    }
    goto out_process;

 do_synced:
    cbuf = ((sfilter->curr_readmsg + sfilter->num_readmsgs)
	    % MAX_READ_DELIVER_MSGS);
    d = &sfilter->readmsgs[cbuf];
    for (; j < buflen; j++) {
	if (k >= 8) {
	    k = 0;
	    bits = buf[j];
	}
	for (; k < 8; k++, bits >>= 1) {
	    bit = bits & 1;
	    sfilter->out_build_data |= bit << sfilter->out_build_pos;
	    if (uncertainty)
		sfilter->build_uncert[sfilter->out_build_pos]
		    = uncertainty[upos++];
	    if (sfilter->out_build_pos < 15) {
		sfilter->out_build_pos++;
	    } else {
		/*
		 * We have all the bytes to interleave,
		 * interleave, flip bits, and put them into the
		 * decoder.
		 */
		bytes[0] = sfilter->out_build_data & 0xff;
		bytes[1] = (sfilter->out_build_data >> 8) & 0xff;
		interleave_bits(bytes, sfilter->build_uncert);
		bytes[0] ^= 0x55;
		bytes[1] ^= 0x55;

		sfilter->out_build_pos = 0;
		sfilter->out_build_data = 0;

		tmpbits16 = bytes[0] | (bytes[1] << 8);
		sfilter->out_to_dec |= tmpbits16 << sfilter->out_to_dec_pos;
		bytes[2] = sfilter->out_to_dec & 0xff;
		bytes[3] = (sfilter->out_to_dec >> 8) & 0xff;
		memcpy(sfilter->dec_uncert + sfilter->out_to_dec_pos,
		       sfilter->build_uncert,
		       16 - sfilter->out_to_dec_pos);
		convdecode_data_u(sfilter->ce, bytes + 2, 16,
				  sfilter->dec_uncert);

		sfilter->out_to_dec = (tmpbits16
				       >> (16 - sfilter->out_to_dec_pos));
		memcpy(sfilter->dec_uncert,
		       sfilter->build_uncert + 16 - sfilter->out_to_dec_pos,
		       sfilter->out_to_dec_pos);

		if (sfilter->state == AXFEC_IN_PREAMBLE) {
		    /*
		     * We put 16 new bits into the decoder, we will
		     * get one new byte out.  Get it in tmpbits.
		     */
		    tmpbits = 0;
		    convdecode_last_n_block(sfilter->ce, &tmpbits, 8,
					    NULL, NULL);
		    if (tmpbits == 0x7e) {
			/* still getting flags */
			sfilter->amble_flags++;
			if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
			    printf("Preamble flag\n");
			reinit_convdecode_last_bits(sfilter->ce, 4);
			sfilter->num_dec_bits = 8;
		    } else {
			/*
			 * We will see this byte again when we fetch
			 * the last 16 bits below, so no need to
			 * process it here.
			 */
			if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
			    printf("First byte: %2.2x\n", tmpbits);
			if (sfilter->amble_flags < 3) {
			    /*
			     * We want at least three valid flags
			     * before we declare victory.  For two
			     * reasons:
			     *
			     * Testing has shown than the AX5043
			     * terminates the packet with a few flags.
			     * This check keeps the state machine from
			     * synchronizing with the end of the
			     * packet.
			     *
			     * You want to be pretty sure you have a
			     * packet, one flag is not enough.
			     */
			    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
				printf("Not enough preamble flags: %d\n",
				       sfilter->amble_flags);
			    goto bad_packet;
			}
			sfilter->one_count = 0;
			sfilter->state = AXFEC_IN_DATA;
			sfilter->num_dec_bits += 16;
		    }
		} else if (sfilter->state == AXFEC_IN_POSTAMBLE) {
		    /*
		     * A note on AX5043 transmit processing and FEC:
		     *
		     * In FEC mode, the AX5043 appears to *always* put
		     * extra HDLC flags after the complete packet.
		     * This means it will put out the FEC encoded
		     * packet, the CRC, the FEC encoded HDLC flag,
		     * then enough zeros to fill out the interleaver.
		     * It then puts out a few more FEC encoded HDLC
		     * flags.
		     *
		     * This is bad because a receiver will see those
		     * HDLC flags and interpret them as the start of a
		     * new packet and start trying to handle a new
		     * packet.  If a packet came in during this time,
		     * it might be missed.
		     *
		     * It appears there is no way to avoid this on the
		     * AX5043.
		     *
		     *
		     * So a receiver will need to check for and handle
		     * these flags.  I have seen two and three of them
		     * (not sure why it varies, but it seems to depend
		     * on packet alignment).  The receiver will need
		     * to handle this by checking for end HDLC flags
		     * and by making sure at the beginning that you
		     * get at least 4 flags before declaring that you
		     * have a good start of packet.
		     *
		     * This also means that if you do back-to-back
		     * packets, you will need to calculate your own
		     * CRC and stick your own flag between them.  On
		     * the receiver it will be hard to know if this
		     * has been done.  It would need to see that it
		     * did not get a flag and back up and handle the
		     * data, dealing with the FEC coder in the
		     * process.  So we aren't doing back-to-back
		     * packets.
		     */

		    tmpbits = 0;
		    convdecode_last_n_block(sfilter->ce, &tmpbits, 8,
					    NULL, NULL);
		    if (tmpbits == 0x7e) {
			/* Still in the postamble. */
			if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
			    printf("Postamble flag\n");
			sfilter->amble_flags++;
			reinit_convdecode_last_bits(sfilter->ce, 4);
			sfilter->num_dec_bits = 8;
		    } else {
			if (sfilter->num_readmsgs >= MAX_READ_DELIVER_MSGS) {
			    /* No room for a new packet. */
			    sfilter->state = AXFEC_NOT_IN_SYNC;
			    sfilter->out_build_data = 0;
			    sfilter->out_build_pos = 0;
			    goto out_process;
			}

			/* Just start the sync processing over for now. */
			goto bad_packet;
		    }
		} else {
		    bool found_flag = false;
		    unsigned int n;

		    sfilter->num_dec_bits += 16;
		    if (sfilter->num_dec_bits > sfilter->max_dec_bits) {
			/* Too much input data. */
			if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
			    printf("Packet too big\n");
			goto bad_packet;
		    }

		    /* Look for a flag in the last 16 bits. */
		    bytes[0] = 0;
		    bytes[1] = 0;
		    convdecode_last_n_block(sfilter->ce, bytes, 16,
					    NULL, NULL);
		    tmpbits16 = bytes[0] | (bytes[1] << 8);
		    for (n = 0; n < 8; n++, tmpbits16 >>= 1) {
			if (tmpbits16 & 1) {
			    sfilter->one_count++;
			    if (sfilter->one_count >= 6) {
				if (tmpbits16 & 2) {
				    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
					printf("Too many ones in packet\n");
				    goto bad_packet;
				}
				n += 2; /* Account for the last two bits. */
				found_flag = true;
				break;
			    }
			} else {
			    sfilter->one_count = 0;
			}
		    }
		    if (found_flag) {
			unsigned int out_bits, leftover_bits, errors;

			/*
			 * At this point n is the number of bits in
			 * the packet, including the flag.  16 - n
			 * is the number of bits after the flag that
			 * are not part of the packet.
			 */
			if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
			    printf("Got final flag\n");
			/* We have a flag at 16 - n bits from the end. */
			memset(d->data, 0, sfilter->read_deliver_size);
			convdecode_last_n_block(sfilter->ce, d->data,
						sfilter->max_dec_out_bits,
						&out_bits, &errors);
			if (errors && sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
			    printf("Packet had errors: %u\n", errors);
			leftover_bits = 16 - n;
			if (out_bits < leftover_bits + 8) {
			    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
				printf("Decode too small\n");
			    goto bad_packet;
			}
			/* Remove the flag and leftover bits. */
			out_bits -= leftover_bits + 8;
			if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
			    printf("Decode bits: %d\n", out_bits);
			if (!unstuff_bits(d->data, &out_bits)) {
			    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
				printf("Unstuffing error\n");
			    goto bad_packet;
			}
			if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
			    printf("Unstuff bits: %d\n", out_bits);
			if (out_bits % 8 != 0) {
			    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
				printf("Misalignment: %d\n", out_bits);
			    /* Must align on a byte. */
			    goto bad_packet;
			}
			if (out_bits / 8 > sfilter->max_read_size) {
			    /* Too big. */
			    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
				printf("Packet too big\n");
			    goto bad_packet;
			}
			if (out_bits < 16) {
			    /* Have to have at least a CRC. */
			    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
				printf("Packet too small\n");
			    goto bad_packet;
			}
			d->pos = 0;
			d->len = out_bits / 8;
			if (!check_crc(d->data, d->len)) {
			    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
				printf("Packet bad CRC\n");
			    goto bad_packet;
			}
			d->len -= 2;

			if (sfilter->debug & GENSIO_HDLC_DEBUG_MSG) {
			    axfec_print_msg(sfilter, "R", 0, d->data, d->len,
					    false);
			}

			/* Commit the packet. */
			sfilter->num_readmsgs++;

			/* Handle the trailing flags. */
			sfilter->state = AXFEC_IN_POSTAMBLE;
			sfilter->amble_flags = 0;

			/*
			 * The AX5043 sticks enough zeros after the flag
			 * that what's after will be aligned.
			 */
			reinit_convdecode_last_bits(sfilter->ce, 4);

			/*
			 * Number of input bits currently in the
			 * decoder.
			 */
			sfilter->num_dec_bits = 8;
		    }
		}
	    }
	}
    }
    goto out_process;

 bad_packet:
    sfilter->out_build_pos = 0;
    sfilter->out_build_data = 0;
    sfilter->state = AXFEC_NOT_IN_SYNC;
    k++;
    if (k >= 8)
	j++;
    else
	bits >>= 1;
    goto restart;

 out_process:
    buflen = j;
    if (sfilter->num_readmsgs > 0) {
	cbuf = sfilter->curr_readmsg;
	d = &sfilter->readmsgs[cbuf];

	axfec_unlock(sfilter);
	err = handler(cb_data, &count, d->data + d->pos, d->len - d->pos, NULL);
	axfec_lock(sfilter);
	if (!err) {
	    if (count + d->pos >= d->len) {
		d->len = 0;
		sfilter->num_readmsgs--;
		sfilter->curr_readmsg++;
		if (sfilter->curr_readmsg >= MAX_READ_DELIVER_MSGS)
		    sfilter->curr_readmsg = 0;
	    } else {
		d->pos += count;
	    }
	}
    }

 out:
    axfec_unlock(sfilter);

#if 0
    if (sfilter->debug & GENSIO_HDLC_DEBUG_STATE)
	printf("Processed %lu bytes\n", (unsigned long) buflen);
#endif

    if (!err && rcount)
	*rcount = buflen;
    return err;
}

static int
axfec_setup(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static void
axfec_cleanup(struct gensio_filter *filter)
{
    struct axfec_filter *sfilter = filter_to_axfec(filter);

    sfilter->num_readmsgs = 0;
    sfilter->num_writemsgs = 0;
    sfilter->num_dec_bits = 0;
    sfilter->out_build_pos = 0;
    sfilter->out_build_data = 0;
    sfilter->build_uncert_pos = 0;
    sfilter->one_count = 0;
    sfilter->err = 0;
    sfilter->num_readmsgs = 0;
    sfilter->num_writemsgs = 0;
}

static void
axfec_sfilter_free(struct axfec_filter *sfilter)
{
    struct gensio_os_funcs *o = sfilter->o;
    unsigned int i;

    if (sfilter->lock)
	o->free_lock(sfilter->lock);
    for (i = 0; i < MAX_READ_DELIVER_MSGS; i++) {
	if (sfilter->readmsgs[i].data)
	    o->free(o, sfilter->readmsgs[i].data);
    }
    for (i = 0; i < MAX_WRITE_DELIVER_MSGS; i++) {
	if (sfilter->writemsgs[i].data)
	    o->free(o, sfilter->writemsgs[i].data);
    }
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    if (sfilter->ce)
	free_convcode(sfilter->ce);
    o->free(o, sfilter);
}

static void
axfec_free(struct gensio_filter *filter)
{
    struct axfec_filter *sfilter = filter_to_axfec(filter);

    return axfec_sfilter_free(sfilter);
}

static int
axfec_filter_control(struct gensio_filter *filter, bool get, int op,
		       char *data, gensiods *datalen)
{
    return GE_NOTSUP;
}

static int gensio_axfec_filter_func(struct gensio_filter *filter, int op,
				      void *func, void *data,
				      gensiods *count,
				      void *buf, const void *cbuf,
				      gensiods buflen,
				      const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	axfec_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return axfec_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return axfec_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return axfec_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_UL_CAN_WRITE:
	return axfec_ul_can_write(filter, data);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return axfec_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return axfec_try_connect(filter, data, buflen);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return axfec_try_disconnect(filter, data, buflen);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return axfec_ul_write(filter, func, data, count, cbuf, buflen, buf);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return axfec_ll_write(filter, func, data, count, buf, buflen, NULL);

    case GENSIO_FILTER_FUNC_SETUP:
	return axfec_setup(filter, data);

    case GENSIO_FILTER_FUNC_CLEANUP:
	axfec_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	axfec_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return axfec_filter_control(filter, *((bool *) cbuf), buflen, data,
				  count);

    default:
	return GE_NOTSUP;
    }
}

struct gensio_axfec_data {
    gensiods max_read_size;
    gensiods max_write_size;
    unsigned int debug;
    unsigned int preamble_len;
};

static struct gensio_filter *
gensio_axfec_filter_raw_alloc(struct gensio_pparm_info *p,
			      struct gensio_os_funcs *o,
			      struct gensio *child,
			      struct gensio_axfec_data *data)
{
    struct axfec_filter *sfilter;
    unsigned int i;
    convcode_state polys[2] = { 023, 035 };

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return NULL;

    sfilter->o = o;
    sfilter->max_write_size = data->max_write_size;
    sfilter->max_read_size = data->max_read_size;
    sfilter->debug = data->debug;
    sfilter->preamble_len = data->preamble_len;

    /* FIXME - add flag handling to all this. */

    /*
     * You can have up to size * 8 ones that need to be added to the
     * read data for bit stuffing if everything was ones.  Since you
     * must add a bit every 5 ones, that's how much longer the buffer
     * might have to be.
     *
     * Add 2 for the CRC and for the end flag and an extra byte.
     */
    sfilter->max_dec_out_bits = (data->max_read_size + 2 + 2) * 8;
    sfilter->max_dec_out_bits += (sfilter->max_dec_out_bits / 5 + 7) / 8;
    sfilter->max_dec_bits = convcode_encoded_size(sfilter->max_dec_out_bits,
						  2, 5, true, NULL, 0);

    /*
     * Like the above, but for write and add the preamble and
     * postamble and CRC and this is the number of encoded bits, not
     * decoded bits.
     */
    sfilter->max_enc_bits = (sfilter->max_write_size + sfilter->preamble_len
			     + 1 + 2) * 8;
    sfilter->max_enc_bits += (sfilter->max_enc_bits / 5 + 7) / 8;
    sfilter->max_enc_bits = convcode_encoded_size(sfilter->max_enc_bits,
						  2, 5, true, NULL, 0);

    sfilter->ce = alloc_convcode(o, 5, polys, 2,
				 sfilter->max_dec_out_bits,
				 0, true, false, true, NULL, 0);

    /* Convert to necessary number of bytes. */
    sfilter->read_deliver_size = CONVCODE_ROUND_UP_BYTE(sfilter->max_dec_bits);
    sfilter->write_deliver_size = CONVCODE_ROUND_UP_BYTE(sfilter->max_enc_bits);

    sfilter->lock = o->alloc_lock(o);
    if (!sfilter->lock)
	goto out_nomem;

    for (i = 0; i < MAX_READ_DELIVER_MSGS; i++) {
	sfilter->readmsgs[i].data = o->zalloc(o, sfilter->read_deliver_size);
	if (!sfilter->readmsgs[i].data)
	    goto out_nomem;
    }

    for (i = 0; i < MAX_WRITE_DELIVER_MSGS; i++) {
	sfilter->writemsgs[i].data = o->zalloc(o, sfilter->write_deliver_size);
	if (!sfilter->writemsgs[i].data)
	    goto out_nomem;
    }

    sfilter->filter = gensio_filter_alloc_data(o, gensio_axfec_filter_func,
					       sfilter);
    if (!sfilter->filter)
	goto out_nomem;

    return sfilter->filter;

 out_nomem:
    axfec_sfilter_free(sfilter);
    return NULL;
}

static int
gensio_axfec_filter_alloc(struct gensio_pparm_info *p,
			  struct gensio_os_funcs *o,
			  struct gensio *child,
			  const char * const args[],
			  struct gensio_base_parms *parms,
			  struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    struct gensio_axfec_data data = {
	.max_read_size = 256,
	.max_write_size = 256,
	.preamble_len = 10,
    };
    unsigned int i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_ds(p, args[i], "readbuf", &data.max_read_size) > 0)
	    continue;
	if (gensio_pparm_ds(p, args[i], "writebuf", &data.max_write_size) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "debug", &data.debug) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "preamble-len",
			      &data.preamble_len) > 0)
	    continue;
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

    filter = gensio_axfec_filter_raw_alloc(p, o, child, &data);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}

static int
axfec_gensio_alloc(struct gensio *child, const char *const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    struct gensio_base_parms *parms = NULL;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "axfec", user_data);

    err = gensio_base_parms_alloc(o, true, "axfec", &parms);
    if (err)
	goto out_err;

    err = gensio_axfec_filter_alloc(&p, o, child, args, parms, &filter);
    if (err)
	goto out_err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	goto out_nomem;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "axfec", cb, user_data);
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
str_to_axfec_gensio(const char *str, const char * const args[],
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

    err = axfec_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

int
gensio_init_axfec(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "axfec",
				str_to_axfec_gensio, axfec_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
