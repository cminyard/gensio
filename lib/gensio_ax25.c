/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This is an implementation of the AX25 protocol, sort of 2.0 and
 * sort of 2.2, available at http://www.ax25.net.
 *
 * It's not a full 2.2 implementation because parts of the protocol
 * are almost unimplementable.  I don't see how the
 * segmentation/reassembly could possibly work as described.
 *
 * This code does implement the extended sequence numbers (SABME) from
 * that spec.  XID is implemented, but it's stupid.  Really.  The
 * SABME should carry the information needed to negotiate the various
 * parameters.  4 bytes would be plenty.  So this code implements a
 * extra data field to tell the remote end about the max message size
 * and windows, if extended2 is enabled.  If it gets a FRMR back from
 * the remote end, it falls back to SABME.  If not enabled (the
 * default) it will send a normal SABME, In both cases if it gets a
 * FRMR from a normal SABME it will fall back to 3-bit sequence
 * numbers.
 *
 * The extended2 extra data is carried on SABME and UA responses to
 * SABME.  It has the following format:
 *   byte 0 - The maximum receive window.  bit 7 is reserved and should be
 *            zero.  This will be used to enable SREJ.
 *   byte 1 - The upper 8 bits of the maximum message size.
 *   byte 2 - The lower 8 bits of the maximum message size.
 *   byte 3 - Unused flags, should all be zero.
 *
 * This code does not currently send an SREJ.  That's pretty
 * complicated, but could be valuable in some situations.  This may be
 * added in the future.  It will handle a received SREJ.
 *
 * Flow-control enable/disable is not done immediately, it is delayed
 * until an ack is sent.  That way momentary enable/disable operations
 * won't result in a ton of unnecessary traffic.
 *
 * In the 2.2 spec the flow-control handling appears to be broken.  If
 * in own receive busy and that is cleared, it sends an RR command
 * with P=1.  However, the response to that (RR response with F=1) is
 * only properly handled in timer recovery state, and the state
 * machines don't go there in this case.  And if they did, that could
 * result in unnecessary data retransmission in the opposite direction
 * on handling the RR response with F=1.  The way the Linux stack
 * handles this is to send an normal RR response with F=0, that's what
 * this code does, too.  But if that RR gets missed, that could result
 * in a stalemate until t3 goes off, which could be a long time.  The
 * only reasonable solution I could see was to go into timer recovery
 * when this happens and live with the retransmits.
 *
 * It seems wrong that a REJ clears peer receive busy in the spec.
 * Only an RR should do that.  This implementation does not do that.
 *
 * Both REJ and SREJ stop T1 and T3 and do not start a new timer, but
 * there's no way that's right.  My guess is that
 * invoke_retransmission should start T1, so that's what this code
 * does.
 *
 * In the spec, SREJ in connected state starts T3, but it should stop
 * T3.
 *
 * There is nothing in the spec that resets the RC value to zero.
 * That should happen when going from timer recover to connected
 * state.
 *
 * The spec says to never set the P bit on I frames, but that's kind
 * of crazy.  This implementation sets the P bit when sending the
 * packet that closes it's transmit window.
 *
 * When checking the sequence numbers for sending a REJ, the sequence
 * number must be in the current receive window.  Otherwise an message
 * from an old resend can result in in_rej being set, but never having
 * anything to clear it.
 *
 * Don't recalculate t1 on a disconnect.  If the other end is no
 * longer available, it can make the shutdown painfully slow.  Just
 * stuck with the t1 value that we were at when the disconnect
 * starts.
 *
 * There are some layer 3 interactions that this code does differently
 * than the spec.  It will never re-initialize a connection if it lost
 * data.  Any significant protocol error will cause the code to shut
 * down the connection and let the user decide what to do.  If the
 * code gets a SABM[E] before it has transferred any data, it will
 * just pretend the previous SABM[E] didn't occur and use the last
 * one, to help in situations where two systems come up at the same
 * time.
 *
 * When a connection is closed, the code here has a wait drain state
 * that waits for all transmitted data to be acked.  That's pretty
 * important for sane usage.  However, this can result in a delay on
 * close, since it has to wait for the ack from the other end for the
 * last data sent.  To expedite this process, in this case the code
 * goes into timer recovery to get a quick response, which is a bit of
 * an abuse of that state.
 *
 * X.25 is really far too complicated.  You can implement a good
 * protocol with four messages.  There is no need for an RNR, you can
 * just use the windows to do flow control, like TCP does.  There
 * should be a version number in the SABME command to allow backwards
 * compatibility.  The whole timer recovery and P/F bit thing is a
 * mess of complexity.  The command/response bits are silly.  The
 * SABME should have a command/response bit in it instead of relying
 * on a UA to ack it.  Same with DISC.  I could go on.
 */
#include "config.h"
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_base.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_list.h>
#include <gensio/gensio_time.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/gensio_ax25_addr.h>

#ifdef DEBUG_DATA
#define ENABLE_PRBUF 1
#include "utils.h"
#endif

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
	unsigned short crc = *icrc;

	for (i = 0; i < len; i++)
	    crc = (crc >> 8) ^ ccitt_table[(crc ^ buf[i]) & 0xff];

	*icrc = crc;
}

enum x25_cmds {
    X25_SABME = 0x6f,
    X25_SABM = 0x2f,
    X25_DISC = 0x43,
    X25_DM = 0x0f,
    X25_UA = 0x63,
    X25_FRMR = 0x87,
    X25_UI = 0x03,
    X25_XID = 0xaf,
    X25_TEST = 0xe3,

    X25_I = 0x00,

    X25_RR = 0x01,
    X25_RNR = 0x05,
    X25_REJ = 0x09,
    X25_SREJ = 0x0d /* Receive side implemented. */
};

enum ax25_base_state {
    /*
     * All channels are closed, child is closed.
     *
     * free of last chan -> free
     * open chan -> AX25_BASE_IN_LL_OPEN
     */
    AX25_BASE_CLOSED = 50,

    /*
     * We have requested that our child open, but have not received the
     * confirmation yet.
     *
     * child open done (err) -> AX25_BASE_CLOSED, fail close all chans
     * child open done -> AX25_BASE_OPEN, start chan opens
     *     if all chan opens fail ->AX25_BASE_CLOSED
     */
    AX25_BASE_IN_CHILD_OPEN,

    /*
     * The child is open, at least one chan is not closed.
     *
     * last chan closed -> AX25_BASE_IN_CHILD_CLOSE
     * io err -> AX25_BASE_IN_CHILD_IO_ERR_CLOSE
     */
    AX25_BASE_OPEN,

    /*
     * A close has been requested, but there is still base data to send.
     */
    AX25_BASE_CLOSE_WAIT_DRAIN,

    /*
     * All chans closed, waiting for the child to close
     *
     * child close && chans waiting open -> AX25_BASE_IN_CHILD_OPEN
     * child close && no chans waiting open -> AX25_BASE_CLOSED
     */
    AX25_BASE_IN_CHILD_CLOSE,

    /*
     * An I/O error occurred, waiting for the close from the child
     *
     * child close && all chans closed -> AX25_BASE_CLOSED
     */
    AX25_BASE_CHILD_IO_ERR,
};

/*
 * Events:
 *   child_write_ready
 *   child_read
 *   child_open_done
 *   child_close_done
 *   write
 *   open
 *   close
 *   free
 */
enum ax25_chan_state {
    /*
     * gensio is closed, either at initial startup after close is
     * complete.
     *
     * chan open && base not open -> start base open if close &&
     *				      AX25_CHAN_WAITING_OPEN
     * chan open && base open -> start open && AX25_CHAN_IN_OPEN
     */
    AX25_CHAN_CLOSED = 100,

    /*
     * We have requested that our child open, but have not received the
     * confirmation yet.
     *
     * base open success -> start open && AX25_CHAN_IN_OPEN
     * close -> if all chans close start base close &&
     *		start runner && AX25_CHAN_REPORT_CLOSE
     * base open fails -> AX25_CHAN_CLOSED && report open errors
     */
    AX25_CHAN_WAITING_OPEN,

    /*
     * We have started the open process.
     *
     * open done -> AX25_CHAN_OPEN
     * close -> start close && AX25_CHAN_REPORT_OPEN_CLOSE
     * remote close -> report open error && AX25_CHAN_CLOSED
     * io err -> report open error && AX25_CHAN_CLOSED
     */
    AX25_CHAN_IN_OPEN,

    /*
     * gensio is operational
     *
     * close && write data pending -> AX25_CHAN_CLOSE_WAIT_DRAIN
     * close && no write data pending -> AX25_CHAN_IN_CLOSE
     * remote close -> AX25_CHAN_IO_ERR
     * io err -> AX25_CHAN_IO_ERR
     */
    AX25_CHAN_OPEN,

    /*
     * A close has been requested, but we have write data to deliver.
     *
     * All data written -> start close && AX25_CHAN_IN_CLOSE
     * io err -> report close && AX25_CHAN_CLOSED
     * remote close -> AX25_CHAN_IO_ERR
     */
    AX25_CHAN_CLOSE_WAIT_DRAIN,

    /*
     * A close has been requested and all data is delivered.  The
     * filter close has been requested but it has not yet reported
     * closed.
     *
     * close done -> report close && AX25_CHAN_CLOSED
     * io err -> report close && AX25_CHAN_CLOSED
     */
    AX25_CHAN_IN_CLOSE,

    /*
     * A disconnect has been received, we need to transmit the UA
     * and shut down.
     *
     * close -> report close && AX25_CHAN_IN_CLOSE
     * io err -> report close && AX25_CHAN_CLOSED
     * ua sent -> report close && AX25_CHAN_CLOSED
     */
    AX25_CHAN_REM_DISC,

    /*
     * A disconnect has been received and then a close was requested,
     * we need to transmit the UA and close
     *
     * io err -> report close && AX25_CHAN_CLOSED
     * ua sent -> report close && AX25_CHAN_CLOSED
     */
    AX25_CHAN_REM_CLOSE,

    /*
     * We have started the open process and a close was requested.
     *
     * open done -> report open && AX25_CHAN_IN_CLOSE
     * remote close -> report open error && report close && AX25_CHAN_CLOSED
     * io err -> report open error && report close && AX25_CHAN_CLOSED
     */
    AX25_CHAN_REPORT_OPEN_CLOSE,

    /*
     * A close has finished and needs to be reported in the runner.
     *
     * runner -> report close && AX25_CHAN_CLOSED
     * io err ->  report close && AX25_CHAN_CLOSED
     */
    AX25_CHAN_REPORT_CLOSE,

    /*
     * An I/O error happened on AX25_CHAN_OPEN, waiting close call.
     *
     * close -> AX25_CHAN_REPORT_CLOSE
     * another io err should be ignored
     */
    AX25_CHAN_IO_ERR,

    /*
     * The channel has no address and just receives/sends UI frames.
     */
    AX25_CHAN_NOCON_IN_OPEN,
    AX25_CHAN_NOCON,
};
#ifdef ENABLE_INTERNAL_TRACE
#define DEBUG_STATE
#endif

struct ax25_chan;
struct ax25_base;

#ifdef DEBUG_STATE
enum ax25_base_trace_type {
    AX25_TRACE_BASE_STATE,
    AX25_TRACE_CHAN_STATE,
    AX25_TRACE_BASE_LOCK,
    AX25_TRACE_BASE_UNLOCK,
    AX25_TRACE_CHAN_LOCK,
    AX25_TRACE_CHAN_UNLOCK,
    AX25_TRACE_BASE_REF,
    AX25_TRACE_BASE_DEREF,
    AX25_TRACE_CHAN_REF,
    AX25_TRACE_CHAN_DEREF,
    AX25_TRACE_OTHER
};
struct ax25_base_state_trace {
    enum ax25_base_trace_type type;
    union {
	struct {
	    enum ax25_base_state old_state;
	    enum ax25_base_state new_state;
	} ax25_base_state;
	struct {
	    enum ax25_chan_state old_state;
	    enum ax25_chan_state new_state;
	} ax25_chan_state;
	int oinfo;
    } u;
    unsigned int line;
};
#define STATE_TRACE_LEN 256
static void i_ax25_base_add_lock(struct ax25_base *base, int line);
static void i_ax25_base_add_other(struct ax25_base *base,
				  enum ax25_base_trace_type type,
				  int other, int line);
#else
#define i_ax25_base_add_lock(base, line)
#define i_ax25_base_add_unlock(base, line)
#define i_ax25_base_add_other(base, type, other, line)
#define i_ax25_chan_add_lock(chan, line)
#define i_ax25_chan_add_unlock(chan, line)
#endif

/*
 * LOCKING INFORMATION
 *
 * The code has two locks: the base lock and the channel lock.  The
 * base lock protects the base data strutures, primarily the list of
 * channels.  The channel lock is per-channel and protects the channel
 * information.
 *
 * If you hold a channel lock, you may lock the base lock.  They both
 * may be locked independently, but if you have the base locked, you
 * cannot lock a channel lock, because you risk deadlock.  When calls
 * come in from the user, you would claim the channel lock first.  But
 * when something comes from the lower layer, it has to claim the base
 * lock so it can search the channels and find which one to use.  But
 * if it releases the base lock and claims the channel lock, there is
 * a chance the channel can be deleted in this time.
 *
 * This is solved by creating a way that, when the base lock is held,
 * a channel may be set to be non-deletable.  Then the base lock is
 * released and the channel lock is grabbed.  Then the channel checked
 * to make sure it wasn't marked for deletion, it it deletes it if so
 * and goes on to the next operation.  So when the channel delete code
 * finds that it is in this lock state, it will just mark the channel
 * for deletion and not delete it.
 *
 * However, when a message comes in from the remote (the child read),
 * and in a few other circumstances, the code must claim the base lock
 * in order to search the lists and find the channel involved.  It
 * would then need to lock the channel before releasing the base lock
 * to keep the channel from being deleted after the base lock is
 * released.  But you can't lock two locks in different orders in
 * different places.  And if you lock the channel lock after unlocking
 * the base lock, it could be deleted during that window.
 *
 * The base_lock_count and base_lock_delete variables do this.
 * base_lock_count is incremented for every thing that puts a channel
 * into this state.  Then when the channel is checked after the
 * channel lock is grabbed, it checked base_lock_delete to know if it
 * should delete it.  These variables can only be used under the base
 * lock.
 *
 * Unnumbered information (UI), opens, and error adds another twist
 * because they need to be able to process multiple channels.  Each of
 * these has their own link in the channel data, all the channels are
 * collected into a list and marked, the base lock is released, and
 * each channel is handled individually.
 */

struct ax25_base_cmdrsp {
    unsigned char addr[AX25_ADDR_MAX_ENCODED_LEN];
    uint8_t addrlen;
    uint8_t cr;
    uint8_t crlen;
    uint8_t extra_data_size;
    unsigned char extra_data[4];
};
#define AX25_BASE_MAX_CMDRSP 16

struct ax25_conf_data {
    gensiods max_read_size;
    gensiods max_write_size;
    unsigned int readwindow;
    unsigned int writewindow;
    unsigned int srtv;
    unsigned int t2v;
    unsigned int t3v;
    unsigned int max_retries;
    unsigned int extended;
    bool do_crc;
    bool ignore_embedded_ua;
    struct gensio_ax25_subaddr *my_addrs;
    unsigned int num_my_addrs;
    struct gensio_addr *addr;
    unsigned int drop_pos;
};

struct ax25_base {
    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    /* If we came from an accepter. */
    struct gensio_accepter *accepter;

    enum ax25_base_state state;

    bool locked;

    /*
     * When opened as an accepter, this says to take the first channel
     * that's already there and use it for the first connection coming
     * in.
     */
    bool waiting_first_open;

    struct ax25_conf_data conf;

    /* A channel will be in one of the following 3 lists, link element. */
    /* Channels that are in closed, report close, or io error state */
    struct gensio_list chans_closed;
    /* Channels that are waiting open */
    struct gensio_list chans_waiting_open;
    /* Channels in all other states, they can receive messages. */
    struct gensio_list chans;

    /*
     * If a channel has data to write, it will be in this, linksend element.
     */
    struct gensio_list send_list;

    /* A queue of commands/responses to send not associated with a channel. */
    struct ax25_base_cmdrsp cmdrsp[AX25_BASE_MAX_CMDRSP];
    uint8_t cmdrsp_pos;
    uint8_t cmdrsp_len;

    struct gensio *child;

    unsigned int refcount;

    /* Transfer data to the deferred open. */
    int open_err;

    /* Marks that we had an error on the child. */
    int child_err;

#ifdef DEBUG_STATE
    struct ax25_base_state_trace state_trace[STATE_TRACE_LEN];
    unsigned int state_trace_pos;
#endif
};

struct ax25_data {
    unsigned char *data;
    uint16_t len;
    uint16_t pos;
    uint8_t seq;
    uint8_t present;
    uint8_t pid;
};

struct ax25_ui_data {
    struct gensio_link link;
    uint16_t len;
};

#define AX25_CHAN_MAX_CMDRSP_EXTRA	32
struct ax25_chan_cmdrsp {
    uint8_t cr;
    uint8_t pf;
    uint8_t is_cmd;
    uint8_t extra_data_size;
    unsigned char extra_data[AX25_CHAN_MAX_CMDRSP_EXTRA];
};
#define AX25_CHAN_MAX_CMDRSP 8

enum ax25_snd_rcv {
    SENT, RCVD
};
#ifdef DEBUG_STATE
struct ax25_chan_msgtrace {
    gensio_time time;
    enum ax25_snd_rcv type;
    bool is_cmd;
    unsigned char data[2];
    bool in_rej;
    bool peer_rcv_bsy;
    bool own_rcv_bsy;
    uint8_t ack_pending;
    uint8_t orig_cmd;
};
#define AX25_CHAN_NR_MSGTRACE 256
#endif

struct ax25_chan {
    struct gensio_link link;
    struct gensio_os_funcs *o;

    struct ax25_base *base;

    bool locked;
    struct gensio_lock *lock;

    struct gensio *io; /* The gensio for this channel */

    unsigned char encoded_addr[AX25_ADDR_MAX_ENCODED_LEN];
    uint8_t encoded_addr_len;

    /* These are after negotiation. */
    uint8_t readwindow;
    uint8_t writewindow;
    uint16_t max_write_size;
    unsigned int max_retries;

    unsigned int curr_drop;

    /* These are modified under the base lock, see locking info above. */
    unsigned int base_lock_count;
    bool base_lock_delete;
    struct gensio_link base_lock_ui_link;
    struct gensio_link base_lock_open_link;
    struct gensio_link base_lock_err_link;

    /* Report UI frames to the upper layer? */
    unsigned int report_ui;
    bool in_ui;

    int in_newchannel;

    int err;

    /*
     * The read_pos is the current next location to report to the
     * user, read_len is the number of packets in queue.
     * These wrap at readwindow.
     */
    struct ax25_data *read_data;
    uint8_t read_pos;
    uint8_t read_len;
    bool in_read;

    /*
     * write_pos is the next message location the user can write.
     * write_len is the number of items in the queue, including ones
     * already sent but unacked, and ones not sent.  Note that items
     * are not removed from this until they are acked.  send_len is
     * the number of packets left to send, starting at write_pos -
     * send_len.  These wrap at conf.writewindow.
     */
    struct ax25_data *write_data;
    uint8_t write_pos;
    uint8_t write_len;
    uint8_t send_len;
    bool in_write;

    /*
     * This is seq# of the next frame to transmit. It corresponds to
     * write_pos.
     */
    uint8_t vs;

    /*
     * This is the seq# of the next expected frame. It corresponds to
     * read_pos + read_len.
     */
    uint8_t vr;

    /*
     * This is the last frame acknowledged by the remote side. vr - va
     * will fall within read_pos and read_pos + read_len.
     */
    uint8_t va;

    /* A queue of commands/responses to send. */
    struct ax25_chan_cmdrsp cmdrsp[AX25_CHAN_MAX_CMDRSP];
    uint8_t cmdrsp_pos;
    uint8_t cmdrsp_len;

    /* List of unnumbered information packets to send. */
    struct gensio_list uis;

    /* Link for list of things waiting to write. */
    struct gensio_link sendlink;

    enum ax25_chan_state state;

    /*
     * Note that we do not have a layer_3_initiated bool like the
     * standard does.  If there is some protocol error, just shut the
     * connection down.  That's a lot safer than dropping data in some
     * fashion.
     */

    bool got_firstmsg;
    unsigned int extended;
    uint8_t modulo;
    bool peer_rcv_bsy;
    bool own_rcv_bsy;
    bool in_rej;
    uint8_t ack_pending; /* Number of rcv packets that haven't been acked. */
    bool poll_pending; /* Timer recovery state. */

    /*
     * SREJ is not currently implemented on the send side, just the receive.
     * uint8_t srej_count;
     */

    struct ax25_conf_data conf;

    /* Current srt and t1 values, in milliseconds. */
    unsigned int t1v;
    unsigned int srt;

    /* Absolute timeout values, in milliseconds.  zero is diabled. */
    int64_t t1;
    int64_t t2;
    int64_t t3;
    int64_t curr_timeout;

    unsigned int retry_count;

    struct gensio_timer *timer;

    unsigned int refcount;

    bool read_enabled;
    bool xmit_enabled;

    gensio_done_err open_done;
    void *open_data;

    gensio_done close_done;
    void *close_data;

    /*
     * Used to run user callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

#ifdef DEBUG_STATE
    struct ax25_chan_msgtrace msgtrace[AX25_CHAN_NR_MSGTRACE];
    unsigned int msgtrace_pos;
#endif
};

static void
ax25_chan_trace_msg(struct ax25_chan *chan,
		    int type, bool is_cmd, uint8_t orig_cmd,
		    unsigned char *data, unsigned int len)
{
#ifdef DEBUG_STATE
    unsigned int pos = chan->msgtrace_pos++, i;
    struct ax25_chan_msgtrace *t = &(chan->msgtrace[pos]);

    chan->o->get_monotonic_time(chan->o, &t->time);
    t->type = type;
    t->is_cmd = is_cmd;
    if (len > sizeof(t->data))
	len = sizeof(t->data);
    memcpy(t->data, data, len);
    for (i = len; i < sizeof(t->data); i++)
	t->data[i] = 0;
    t->in_rej = chan->in_rej;
    t->peer_rcv_bsy = chan->peer_rcv_bsy;
    t->own_rcv_bsy = chan->own_rcv_bsy;
    t->ack_pending = chan->ack_pending;
    t->orig_cmd = orig_cmd;
    if (chan->msgtrace_pos >= AX25_CHAN_NR_MSGTRACE)
	chan->msgtrace_pos = 0;
#endif
}

static int i_ax25_base_child_close_done(struct ax25_base *base);
static void ax25_base_child_close_done(struct gensio *child, void *open_data);
static void ax25_chan_sched_deferred_op(struct ax25_chan *chan);
static int ax25_base_start_open(struct ax25_base *base);
static void ax25_chan_prestart_connect(struct ax25_chan *chan);
static void ax25_chan_start_connect(struct ax25_chan *chan);
static int ax25_chan_alloc(struct ax25_base *base, const char *const args[],
			   gensio_event cb, void *user_data,
			   enum ax25_chan_state start_state,
			   struct gensio_addr *addr, bool firstchan,
			   struct ax25_chan **rchan);
static void ax25_chan_start_t1(struct ax25_chan *chan);
static void ax25_chan_stop_t1(struct ax25_chan *chan);
static void ax25_chan_start_t2(struct ax25_chan *chan);
static void ax25_chan_stop_t2(struct ax25_chan *chan);
static void ax25_chan_start_t3(struct ax25_chan *chan);
static void ax25_chan_stop_t3(struct ax25_chan *chan);
static void ax25_chan_send_cmd(struct ax25_chan *chan, uint8_t cmd, uint8_t pf);
static void ax25_chan_send_rsp(struct ax25_chan *chan, uint8_t cmd, uint8_t pf);
static void ax25_stop_timer(struct ax25_chan *chan);
static void ax25_chan_reset_data(struct ax25_chan *chan);

/*
 * base locking and refcounting.
 */
static void
i_ax25_base_lock(struct ax25_base *base)
{
    base->o->lock(base->lock);
    base->locked = true;
}
#define ax25_base_lock(base) do { \
	i_ax25_base_lock((base));		\
	i_ax25_base_add_lock(base, __LINE__);	\
    } while(false)

static void
i_ax25_base_unlock(struct ax25_base *base)
{
    base->locked = false;
    base->o->unlock(base->lock);
}
#define ax25_base_unlock(base) do { \
	i_ax25_base_add_unlock(base, __LINE__);	\
	i_ax25_base_unlock((base));		\
    } while(false)

static void
i_ax25_base_ref(struct ax25_base *base, int line)
{
    assert(base->refcount > 0);
    base->refcount++;
    i_ax25_base_add_other(base, AX25_TRACE_BASE_REF, base->refcount, line);
}
#define ax25_base_ref(base) i_ax25_base_ref((base), __LINE__)

static void
i_ax25_base_lock_and_ref(struct ax25_base *base, int line)
{
    i_ax25_base_lock(base);
    i_ax25_base_ref(base, line);
}
#define ax25_base_lock_and_ref(base) i_ax25_base_lock_and_ref((base), __LINE__)

/*
 * This can *only* be called if the refcount is guaranteed not to reach
 * zero.
 */
static void
i_ax25_base_deref(struct ax25_base *base, int line)
{
    assert(base->refcount > 1);
    i_ax25_base_add_other(base, AX25_TRACE_BASE_DEREF, base->refcount, line);
    base->refcount--;
}
#define ax25_base_deref(base) i_ax25_base_deref((base), __LINE__)

static void
ax25_cleanup_conf(struct gensio_os_funcs *o, struct ax25_conf_data *conf)
{
    if (conf->my_addrs)
	o->free(o, conf->my_addrs);
    if (conf->addr)
	gensio_addr_free(conf->addr);
}

static void
ax25_base_finish_free(struct ax25_base *base)
{
    ax25_cleanup_conf(base->o, &base->conf);
    if (base->lock)
	base->o->free_lock(base->lock);
    if (base->child)
	gensio_free(base->child);
    base->o->free(base->o, base);
}

static void
i_ax25_base_deref_and_unlock(struct ax25_base *base, int line)
{
    unsigned int count;

    assert(base->refcount > 0);
    i_ax25_base_add_other(base, AX25_TRACE_BASE_DEREF,
			  base->refcount, line);
    count = --base->refcount;
    i_ax25_base_unlock(base);
    if (count == 0)
	ax25_base_finish_free(base);
}
#define ax25_base_deref_and_unlock(base) i_ax25_base_deref_and_unlock((base), \
							       __LINE__)

/*
 * chan locking and refcounting.
 */
static void
i_ax25_chan_lock(struct ax25_chan *chan)
{
    chan->o->lock(chan->lock);
    chan->locked = true;
}
#define ax25_chan_lock(chan) do { \
	i_ax25_chan_lock((chan));		\
	i_ax25_base_lock((chan)->base);		\
	i_ax25_chan_add_lock(chan, __LINE__);	\
	i_ax25_base_unlock((chan)->base);	\
    } while(false)

static void
i_ax25_chan_unlock(struct ax25_chan *chan)
{
    assert(chan->locked);
    chan->locked = false;
    chan->o->unlock(chan->lock);
}
#define ax25_chan_unlock(chan) do { \
	i_ax25_base_lock((chan)->base);		\
	i_ax25_chan_add_unlock(chan, __LINE__);	\
	i_ax25_base_unlock((chan)->base);	\
	i_ax25_chan_unlock((chan));		\
    } while(false)

static void
ax25_chan_finish_free(struct ax25_chan *chan, bool baselocked)
{
    struct ax25_base *base = chan->base;
    struct gensio_os_funcs *o = chan->o;
    unsigned int i;

    if (chan->io)
	gensio_data_free(chan->io);
    if (chan->read_data) {
	for (i = 0; i < chan->conf.readwindow; i++) {
	    if (chan->read_data[i].data)
		o->free(o, chan->read_data[i].data);
	}
	o->free(o, chan->read_data);
    }
    if (chan->write_data) {
	for (i = 0; i < chan->conf.writewindow; i++) {
	    if (chan->write_data[i].data)
		o->free(o, chan->write_data[i].data);
	}
	o->free(o, chan->write_data);
    }
    if (base) {
	if (!baselocked)
	    ax25_base_lock(base);
	if (gensio_list_link_inlist(&chan->sendlink))
	    gensio_list_rm(&base->send_list, &chan->sendlink);
	gensio_list_rm(&base->chans_closed, &chan->link);
	if (baselocked)
	    ax25_base_deref(base);
	else
	    ax25_base_deref_and_unlock(base);
    }

    ax25_cleanup_conf(o, &chan->conf);
    if (chan->lock)
	o->free_lock(chan->lock);
    if (chan->timer)
	o->free_timer(chan->timer);
    if (chan->deferred_op_runner)
	o->free_runner(chan->deferred_op_runner);
    o->free(o, chan);
}

static void
i_ax25_chan_ref(struct ax25_chan *chan, int line)
{
    assert(chan->locked);
    assert(chan->refcount > 0);
    chan->refcount++;
    i_ax25_base_lock(chan->base);
    i_ax25_base_add_other(chan->base, AX25_TRACE_CHAN_REF,
			  chan->refcount, line);
    i_ax25_base_unlock(chan->base);
}
#define ax25_chan_ref(chan) i_ax25_chan_ref((chan), __LINE__)

static void
i_ax25_chan_lock_and_ref(struct ax25_chan *chan, int line)
{
    i_ax25_chan_lock(chan);
    i_ax25_chan_ref(chan, line);
}
#define ax25_chan_lock_and_ref(chan) i_ax25_chan_lock_and_ref((chan), __LINE__)

/*
 * This can *only* be called if the refcount is guaranteed not to reach
 * zero.
 */
static void
i_ax25_chan_deref(struct ax25_chan *chan, int line)
{
    assert(chan->locked);
    assert(chan->refcount > 1);
    i_ax25_base_lock(chan->base);
    i_ax25_base_add_other(chan->base, AX25_TRACE_CHAN_DEREF,
			  chan->refcount, line);
    i_ax25_base_unlock(chan->base);
    chan->refcount--;
}
#define ax25_chan_deref(chan) i_ax25_chan_deref((chan), __LINE__)

static void
i_ax25_chan_deref_and_unlock(struct ax25_chan *chan, int line)
{
    struct ax25_base *base = chan->base;
    unsigned int count;

    assert(chan->locked);
    assert(chan->refcount > 0);
    i_ax25_base_lock(base);
    i_ax25_base_add_other(base, AX25_TRACE_CHAN_DEREF, chan->refcount, line);
    i_ax25_base_unlock(base);
    count = --chan->refcount;
    if (count == 0) {
	i_ax25_base_lock(base);
	if (chan->base_lock_count > 0) {
	    chan->base_lock_delete = true;
	    i_ax25_base_unlock(base);
	    i_ax25_chan_unlock(chan);
	} else {
	    i_ax25_base_unlock(base);
	    i_ax25_chan_unlock(chan);
	    ax25_chan_finish_free(chan, false);
	}
    } else {
	i_ax25_chan_unlock(chan);
    }
}
#define ax25_chan_deref_and_unlock(chan) i_ax25_chan_deref_and_unlock((chan), __LINE__)

/* Like above, but already holding the base lock */
static void
i_ax25_chan_deref_and_unlockb(struct ax25_chan *chan, int line)
{
    unsigned int count;

    assert(chan->locked && chan->base->locked);
    assert(chan->refcount > 0);
    i_ax25_base_add_other(chan->base, AX25_TRACE_CHAN_DEREF,
			  chan->refcount, line);
    count = --chan->refcount;
    if (count == 0) {
	if (chan->base_lock_count > 0) {
	    chan->base_lock_delete = true;
	    i_ax25_chan_unlock(chan);
	} else {
	    i_ax25_chan_unlock(chan);
	    ax25_chan_finish_free(chan, true);
	}
    } else {
	i_ax25_chan_unlock(chan);
    }
}
#define ax25_chan_deref_and_unlockb(chan) i_ax25_chan_deref_and_unlockb((chan), __LINE__)

#ifdef DEBUG_STATE
static void
i_ax25_base_finish_trace(struct ax25_base *base, enum ax25_base_trace_type type,
			 unsigned int line)
{
    struct ax25_base_state_trace *t;

    assert(base->locked);
    t = &(base->state_trace[base->state_trace_pos]);
    memset(t, 0, sizeof(*t));
    t->type = type;
    t->line = line;
    if (base->state_trace_pos == STATE_TRACE_LEN - 1)
	base->state_trace_pos = 0;
    else
	base->state_trace_pos++;
}

static void
i_ax25_chan_set_state(struct ax25_chan *chan, enum ax25_chan_state new_state,
		      int line)
{
    struct ax25_base *base = chan->base;
    struct ax25_base_state_trace *t;

    assert(chan->locked);
    i_ax25_base_lock(base);
    t = &(base->state_trace[base->state_trace_pos]);
    i_ax25_base_finish_trace(base, AX25_TRACE_CHAN_STATE, line);
    t->u.ax25_chan_state.old_state = chan->state;
    t->u.ax25_chan_state.new_state = new_state;
    i_ax25_base_unlock(base);
    chan->state = new_state;
}
#define ax25_chan_set_state(chan, state) \
    i_ax25_chan_set_state(chan, state, __LINE__)

static void
i_ax25_chan_set_stateb(struct ax25_chan *chan, enum ax25_chan_state new_state,
		       int line)
{
    struct ax25_base *base = chan->base;
    struct ax25_base_state_trace *t;

    assert(chan->locked && base->locked);
    t = &(base->state_trace[base->state_trace_pos]);
    i_ax25_base_finish_trace(base, AX25_TRACE_CHAN_STATE, line);
    t->u.ax25_chan_state.old_state = chan->state;
    t->u.ax25_chan_state.new_state = new_state;
    chan->state = new_state;
}
#define ax25_chan_set_stateb(chan, state) \
    i_ax25_chan_set_stateb(chan, state, __LINE__)

static void
i_ax25_base_set_state(struct ax25_base *base,
		      enum ax25_base_state new_state, int line)
{
    struct ax25_base_state_trace *t;

    assert(base->locked);
    t = &(base->state_trace[base->state_trace_pos]);
    i_ax25_base_finish_trace(base, AX25_TRACE_BASE_STATE, line);
    t->u.ax25_base_state.old_state = base->state;
    t->u.ax25_base_state.new_state = new_state;
    base->state = new_state;
}
#define ax25_base_set_state(base, state) \
    i_ax25_base_set_state(base, state, __LINE__)

static void i_ax25_chan_add_lock(struct ax25_chan *chan, int line)
{
    struct ax25_base *base = chan->base;

    i_ax25_base_finish_trace(base, AX25_TRACE_CHAN_LOCK, line);
}

static void i_ax25_chan_add_unlock(struct ax25_chan *chan, int line)
{
    struct ax25_base *base = chan->base;

    i_ax25_base_finish_trace(base, AX25_TRACE_CHAN_UNLOCK, line);
}

static void i_ax25_base_add_lock(struct ax25_base *base, int line)
{
    i_ax25_base_finish_trace(base, AX25_TRACE_BASE_LOCK, line);
}

static void i_ax25_base_add_unlock(struct ax25_base *base, int line)
{
    i_ax25_base_finish_trace(base, AX25_TRACE_BASE_UNLOCK, line);
}

static void i_ax25_base_add_other(struct ax25_base *base,
				  enum ax25_base_trace_type type,
				  int other, int line)
{
    struct ax25_base_state_trace *t;

    t = &(base->state_trace[base->state_trace_pos]);
    i_ax25_base_finish_trace(base, type, line);
    t->u.oinfo = other + 1000;
}
#define ax25_base_add_other(base, type, other) \
    i_ax25_base_add_other(base, type, other, __LINE__)

#else
static void
ax25_chan_set_state(struct ax25_chan *chan, enum ax25_chan_state state)
{
    chan->state = state;
}
#define ax25_chan_set_stateb(chan, state) \
    ax25_chan_set_state(chan, state)

static void
ax25_base_set_state(struct ax25_base *base, enum ax25_base_state state)
{
    base->state = state;
}
#define ax25_base_add_other(base, type, other, line)
#endif

static uint8_t
sub_seq(uint8_t val1, uint8_t val2, uint8_t window)
{
    if (val2 > val1)
	val1 += window;
    return val1 - val2;
}

static uint8_t
add_seq(uint8_t val, uint8_t amt, uint8_t window)
{
    uint8_t rv = amt + val;

    if (rv >= window)
	rv -= window;
    return rv;
}

/* Return true if start <= val < end, false if not. */
static bool
seq_in_range(uint8_t start, uint8_t end, uint8_t val, uint8_t window)
{
    if (end > start)
	return val >= start && val <= end;
    else
	return val >= start || val <= end;
}

/* Can the upper layer write to me? */
static bool
chan_can_write(struct ax25_chan *chan)
{
    return ((chan->state == AX25_CHAN_OPEN &&
	     chan->write_len < chan->writewindow) ||
	    chan->err || chan->state == AX25_CHAN_NOCON);
}

/* Do I have data to deliver to the upper layer? */
static bool
chan_can_read(struct ax25_chan *chan)
{
    return chan->err || chan->read_len > 0;
}

static void
ax25_chan_report_open(struct ax25_chan *chan)
{
    gensio_done_err open_done = chan->open_done;
    void *open_data = chan->open_data;
    int err = chan->err;

    if (open_done) {
	chan->open_done = NULL;
	ax25_chan_unlock(chan);
	open_done(chan->io, err, open_data);
	ax25_chan_lock(chan);
    }
}

static void
ax25_chan_report_close(struct ax25_chan *chan)
{
    gensio_done close_done = chan->close_done;
    void *close_data = chan->close_data;

    ax25_chan_set_state(chan, AX25_CHAN_CLOSED);
    ax25_stop_timer(chan);
    ax25_chan_reset_data(chan);
    if (close_done) {
	chan->close_done = NULL;
	ax25_chan_unlock(chan);
	close_done(chan->io, close_data);
	ax25_chan_lock(chan);
    }
    /* Lose the ref from when close was called. */
    ax25_chan_deref(chan);
}

static void
ax25_chan_check_close(struct ax25_chan *chan)
{
    if (chan->in_read || chan->in_write || chan->in_ui)
	return;
    ax25_chan_report_close(chan);
}

static void
ax25_base_child_close(struct ax25_base *base)
{
    int err;

    err = gensio_close(base->child, ax25_base_child_close_done, base);
    if (err)
	i_ax25_base_child_close_done(base);
    else
	ax25_base_set_state(base, AX25_BASE_IN_CHILD_CLOSE);
}

static void
ax25_chan_move_to_closed(struct ax25_chan *chan, struct gensio_list *old_list)
{
    struct ax25_base *base = chan->base;

    ax25_stop_timer(chan);
    ax25_base_lock_and_ref(base);
    gensio_list_rm(old_list, &chan->link);
    gensio_list_add_tail(&base->chans_closed, &chan->link);
    if (base->state == AX25_BASE_OPEN) {
	if (gensio_list_empty(&base->chans)) {
	    if (base->cmdrsp_len > 0) {
		ax25_base_set_state(base, AX25_BASE_CLOSE_WAIT_DRAIN);
	    } else {
		ax25_base_child_close(base);
	    }
	}
    }
    ax25_base_deref_and_unlock(base);
}

static void
ax25_chan_do_close(struct ax25_chan *chan, bool report)
{
    struct ax25_base *base = chan->base;

    ax25_chan_move_to_closed(chan, &base->chans);
    if (report) {
	ax25_chan_set_state(chan, AX25_CHAN_REPORT_CLOSE);
	ax25_chan_check_close(chan);
    } else {
	ax25_chan_report_close(chan);
    }
}

static void
ax25_chan_do_err_close(struct ax25_chan *chan, bool do_deferred_op)
{
    struct ax25_base *base = chan->base;

    ax25_chan_move_to_closed(chan, &base->chans);
    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
	ax25_chan_set_state(chan, AX25_CHAN_CLOSED);
	ax25_chan_report_open(chan);
	break;

    case AX25_CHAN_IN_CLOSE:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	ax25_chan_set_state(chan, AX25_CHAN_CLOSED);
	ax25_chan_report_close(chan);
	break;

    case AX25_CHAN_REPORT_OPEN_CLOSE:
	ax25_chan_report_open(chan);
	ax25_chan_set_state(chan, AX25_CHAN_CLOSED);
	ax25_chan_report_close(chan);
	break;

    case AX25_CHAN_REPORT_CLOSE:
	ax25_chan_check_close(chan);
	break;

    default:
	ax25_chan_set_state(chan, AX25_CHAN_IO_ERR);
	if (do_deferred_op)
	    ax25_chan_sched_deferred_op(chan);
    }
}

static void
ax25_chan_send_ack(struct ax25_chan *chan, uint8_t pf, bool is_cmd)
{
    unsigned int i;
    unsigned int pos;

    chan->ack_pending = 0;
    ax25_chan_stop_t2(chan);

    if (!pf && !is_cmd && chan->send_len > 0)
	return; /* Just let an I frame ack it. */
    for (pos = chan->cmdrsp_pos, i = 0; i < chan->cmdrsp_len; i++) {
	struct ax25_chan_cmdrsp *cr= &(chan->cmdrsp[pos]);

	/*
	 * Don't have duplicate RRs in the queue.  If there is already
	 * an RR there, just set the pf bit as necessary.
	 */
	if (cr->cr == X25_RR && cr->is_cmd == is_cmd) {
	    if (pf)
		cr->pf = pf;
	    return;
	}

	pos = (pos + 1) % AX25_CHAN_MAX_CMDRSP;
    }

    /* Note that RRs get converted to RNRs in the send code as needed. */
    if (is_cmd)
	ax25_chan_send_cmd(chan, X25_RR, pf);
    else
	ax25_chan_send_rsp(chan, X25_RR, pf);
}

static void
ax25_chan_deliver_read(struct ax25_chan *chan)
{
    gensiods rcount;
    struct ax25_data *d;
    char pidstr[10];
    const char *auxdata[2] = { pidstr, NULL };
    int err;

    if (chan->in_read)
	goto check_for_busy;
    chan->in_read = true;
    while (chan->read_enabled && chan_can_read(chan)) {
	if (chan->err) {
	    ax25_chan_unlock(chan);
	    chan->read_enabled = false;
	    err = gensio_cb(chan->io, GENSIO_EVENT_READ, chan->err,
			    NULL, NULL, NULL);
	    ax25_chan_lock(chan);
	    if (err)
		break;
	    continue;
	}

	d = &(chan->read_data[chan->read_pos]);
	snprintf(pidstr, sizeof(pidstr), "pid:%d", d->pid);
	ax25_chan_unlock(chan);
	rcount = d->len;
	err = gensio_cb(chan->io, GENSIO_EVENT_READ, 0, d->data + d->pos,
			&rcount, auxdata);
	ax25_chan_lock(chan);
	if (err) {
	    if (!chan->err) {
		chan->err = err;
		ax25_chan_do_err_close(chan, true);
	    }
	    break;
	}
	if (rcount < d->len) {
	    d->len -= rcount;
	    d->pos += rcount;
	} else {
	    chan->read_pos = add_seq(chan->read_pos, 1, chan->conf.readwindow);
	    chan->read_len--;
	    d->present = false;
	}
    }
    chan->in_read = false;
    if (chan->state == AX25_CHAN_REPORT_CLOSE)
	ax25_chan_check_close(chan);
 check_for_busy:
    if (!chan->own_rcv_bsy && chan->read_len > chan->conf.readwindow / 2) {
	chan->own_rcv_bsy = true;
	ax25_chan_send_ack(chan, 0, false);
    } else if (chan->own_rcv_bsy && chan->read_len == 0) {
	chan->own_rcv_bsy = false;
	ax25_chan_send_ack(chan, 1, true);
	chan->poll_pending = true;
	if (!chan->t1) {
	    ax25_chan_stop_t3(chan);
	    ax25_chan_start_t1(chan);
	}
    }
}

static void
ax25_chan_deliver_write_ready(struct ax25_chan *chan)
{
    int err;

    if (chan->in_write)
	return;
    chan->in_write = true;
    while (chan->xmit_enabled && chan_can_write(chan)) {
	ax25_chan_unlock(chan);
	err = gensio_cb(chan->io, GENSIO_EVENT_WRITE_READY, 0, NULL,
			NULL, NULL);
	ax25_chan_lock(chan);
	if (err) {
	    if (!chan->err) {
		chan->err = err;
		ax25_chan_do_err_close(chan, true);
	    }
	    break;
	}
    }
    chan->in_write = false;
    if (chan->state == AX25_CHAN_REPORT_CLOSE)
	ax25_chan_check_close(chan);
}

static void
ax25_chan_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct ax25_chan *chan = cbdata;

    ax25_chan_lock(chan);
    chan->deferred_op_pending = false;

    if (chan->state == AX25_CHAN_NOCON_IN_OPEN) {
	ax25_chan_set_state(chan, AX25_CHAN_NOCON);
	ax25_chan_report_open(chan);
    }
    if (chan->state == AX25_CHAN_REPORT_OPEN_CLOSE) {
	ax25_chan_report_open(chan);
	ax25_chan_set_state(chan, AX25_CHAN_CLOSED);
	ax25_chan_report_close(chan);
    }
    if (chan->state == AX25_CHAN_REPORT_CLOSE)
	ax25_chan_check_close(chan);

    /* Read/write callbacks for delivering data and reporting errors. */
    ax25_chan_deliver_read(chan);

    /* Read/write callbacks for delivering data and reporting errors. */
    ax25_chan_deliver_write_ready(chan);

    ax25_chan_deref_and_unlock(chan); /* Ref from ax25_chan_sched_deferred_op */
}

/* Must be called with the channel lock held. */
static void
ax25_chan_sched_deferred_op(struct ax25_chan *chan)
{
    assert(chan->locked);
    if (!chan->deferred_op_pending) {
	chan->deferred_op_pending = true;
	ax25_chan_ref(chan);
	chan->o->run(chan->deferred_op_runner);
    }
}

/* Must hold the base lock to call this. */
static struct ax25_chan *
ax25_base_lookup_chan_by_addr(struct ax25_base *base, struct gensio_addr *addr)
{
    struct gensio_link *l;

    gensio_list_for_each(&base->chans, l) {
	struct ax25_chan *chan = gensio_container_of(l, struct ax25_chan, link);

	if (chan->conf.addr &&
		gensio_addr_equal(addr, chan->conf.addr, true, false))
	    return chan;
    }
    gensio_list_for_each(&base->chans_waiting_open, l) {
	struct ax25_chan *chan = gensio_container_of(l, struct ax25_chan, link);

	if (chan->conf.addr &&
		gensio_addr_equal(addr, chan->conf.addr, true, false))
	    return chan;
    }
    return NULL;
}

static void
ax25_chan_report_open_err(struct ax25_chan *chan, struct gensio_list *old_list,
			  int err)
{
    gensio_done_err open_done = chan->open_done;
    void *open_data = chan->open_data;

    chan->open_done = NULL;
    ax25_chan_move_to_closed(chan, old_list);
    ax25_chan_set_state(chan, AX25_CHAN_CLOSED);
    if (open_done) {
	ax25_chan_unlock(chan);
	if (open_done)
	    open_done(chan->io, err, open_data);
	ax25_chan_lock(chan);
    }
}

static struct ax25_chan *
ax25_chan_check_base_lock_state(struct ax25_chan *chan,
				struct gensio_list *should_be_in,
				bool incl_disc)
{
    struct ax25_base *base = chan->base;

    ax25_chan_lock(chan);
    ax25_base_lock(base);
    assert(chan->base_lock_count > 0);
    chan->base_lock_count--;
    if (chan->base_lock_delete && chan->base_lock_count == 0) {
	ax25_base_unlock(base);
	ax25_chan_unlock(chan);
	ax25_chan_finish_free(chan, false);
	return NULL;
    }
    if (!gensio_list_link_in_this_list(&chan->link, should_be_in) ||
		(incl_disc && (chan->state == AX25_CHAN_REM_DISC ||
			       chan->state == AX25_CHAN_REM_CLOSE))) {
	/* Channel is not in a state where it should be. */
	ax25_base_unlock(base);
	ax25_chan_unlock(chan);
	return NULL;
    }
    ax25_base_unlock(base);
    ax25_chan_ref(chan);
    return chan;
}

static void
ax25_base_handle_open_done(struct ax25_base *base, int err)
{
    struct gensio_list to_deliver;
    struct gensio_link *l, *l2;

    if (gensio_list_empty(&base->chans_waiting_open)) {
	if (err) {
	    ax25_base_deref(base);
	    ax25_base_set_state(base, AX25_BASE_CLOSED);
	} else {
	    ax25_base_child_close(base);
	}
	return;
    }

 restart:
    gensio_list_init(&to_deliver);
    gensio_list_for_each(&base->chans_waiting_open, l) {
	struct ax25_chan *chan = gensio_container_of(l, struct ax25_chan, link);

	gensio_list_add_tail(&to_deliver, &chan->base_lock_open_link);
	chan->base_lock_count++;
    }

    if (err)
	ax25_base_set_state(base, AX25_BASE_IN_CHILD_CLOSE);
    else
	ax25_base_set_state(base, AX25_BASE_OPEN);
    ax25_base_unlock(base);

    gensio_list_for_each_safe(&to_deliver, l, l2) {
	struct ax25_chan *chan = gensio_container_of(l, struct ax25_chan,
						     base_lock_open_link);

	gensio_list_rm(&to_deliver, l);
	chan = ax25_chan_check_base_lock_state(chan, &base->chans_waiting_open,
					       true);
	if (!chan)
	    continue;

	if (chan->state == AX25_CHAN_WAITING_OPEN) {
	    if (err) {
		ax25_chan_report_open_err(chan, &base->chans_waiting_open, err);
	    } else {
		ax25_base_lock(base);
		gensio_list_rm(&base->chans_waiting_open, &chan->link);
		gensio_list_add_tail(&base->chans, &chan->link);
		ax25_chan_prestart_connect(chan);
		ax25_base_unlock(base);
		ax25_chan_start_connect(chan);
	    }
	}
	ax25_chan_deref_and_unlock(chan);
    }
    ax25_base_lock(base);
    if (err) {
	err = i_ax25_base_child_close_done(base);
	if (err)
	    goto restart;
    } else {
	/* Make sure all channels are not waiting open before enabling read. */
	if (base->state == AX25_BASE_OPEN)
	    gensio_set_read_callback_enable(base->child, true);
    }
}

static int
i_ax25_base_child_close_done(struct ax25_base *base)
{
    int rv = 0;

    ax25_base_set_state(base, AX25_BASE_CLOSED);
    ax25_base_deref(base);
    if (!gensio_list_empty(&base->chans_waiting_open)) {
	rv = ax25_base_start_open(base);
	if (rv)
	    /*
	     * An error return will cause this to call
	     * handle_open_done with an error or restart it, which
	     * will drop the ref count again.
	     */
	    ax25_base_ref(base);
	else
	    ax25_base_set_state(base, AX25_BASE_IN_CHILD_OPEN);
    }

    return rv;
}

static void
ax25_base_child_close_done(struct gensio *child, void *open_data)
{
    struct ax25_base *base = open_data;
    int rv;

    ax25_base_lock_and_ref(base);
    rv = i_ax25_base_child_close_done(base);
    if (rv)
	ax25_base_handle_open_done(base, rv);
    ax25_base_deref_and_unlock(base);
}

static void
ax25_base_child_open_done(struct gensio *child, int err, void *open_data)
{
    struct ax25_base *base = open_data;

    ax25_base_lock_and_ref(base);
    ax25_base_handle_open_done(base, err);
    ax25_base_deref_and_unlock(base);
}

/* Must be called with the base lock held. */
static int
ax25_base_start_open(struct ax25_base *base)
{
    int rv;

    base->child_err = 0;
    rv = gensio_open(base->child, ax25_base_child_open_done, base);
    if (!rv) {
	ax25_base_ref(base);
	ax25_base_set_state(base, AX25_BASE_IN_CHILD_OPEN);
    }
    return rv;
}

static void
ax25_proto_err(struct ax25_base *base, struct ax25_chan *chan,
	       const char *errstr)
{
    if (chan && chan->conf.addr) {
	char addrstr[100] = "<none>", subaddrstr[10] = "<none>";

	if (chan->conf.addr)
	    gensio_addr_to_str(chan->conf.addr, addrstr, NULL, sizeof(addrstr));
	if (chan->conf.my_addrs)
	    ax25_subaddr_to_str(&base->conf.my_addrs[0],
				subaddrstr, NULL, sizeof(subaddrstr), false);
	gensio_log(base->o, GENSIO_LOG_ERR, "%s: AX25 error from %s: %s",
		   subaddrstr, addrstr, errstr);
    } else {
	gensio_log(base->o, GENSIO_LOG_ERR, "AX25 error: %s", errstr);
    }
}

static void
ax25_chan_reset_data(struct ax25_chan *chan)
{
    chan->vs = 0;
    chan->va = 0;
    chan->vr = 0;
    chan->peer_rcv_bsy = false;
    chan->own_rcv_bsy = false;
    chan->read_pos = 0;
    chan->read_len = 0;
    chan->write_pos = 0;
    chan->write_len = 0;
    chan->send_len = 0;
    chan->cmdrsp_pos = 0;
    chan->cmdrsp_len = 0;
    chan->in_rej = false;
    chan->ack_pending = 0;
    chan->poll_pending = false;
    chan->retry_count = 0;
    chan->srt = chan->conf.srtv;
    if (chan->conf.addr) {
	struct gensio_ax25_addr *aaddr = addr_to_ax25(chan->conf.addr);

	/* Increase the timeout based on the number of digipeaters. */
	chan->srt *= (aaddr->nr_extra + 1);
    }
    chan->t1v = chan->srt * 2;
    chan->t1 = 0;
    chan->t2 = 0;
    chan->t3 = 0;
    chan->curr_timeout = 0;
    chan->err = 0;
    chan->got_firstmsg = false;
}

static void
i_ax25_chan_schedule_write(struct ax25_chan *chan)
{
    struct ax25_base *base = chan->base;

    if (base->state == AX25_BASE_OPEN) {
	if (!gensio_list_link_inlist(&chan->sendlink))
	    gensio_list_add_tail(&base->send_list, &chan->sendlink);
	gensio_set_write_callback_enable(base->child, true);
    }
}

static void
ax25_chan_schedule_write(struct ax25_chan *chan)
{
    struct ax25_base *base = chan->base;

    ax25_base_lock(base);
    i_ax25_chan_schedule_write(chan);
    ax25_base_unlock(base);
}

static void
ax25_base_send_rsp(struct ax25_base *base, struct gensio_addr *addr,
		   uint8_t rsp, uint8_t pf,
		   unsigned char *extra, unsigned extra_size)
{
    struct ax25_base_cmdrsp *cr;
    unsigned int pos;

    ax25_base_lock(base);
    if (base->cmdrsp_len < AX25_BASE_MAX_CMDRSP &&
		base->state == AX25_BASE_OPEN) {
	pos = (base->cmdrsp_pos + base->cmdrsp_len) % AX25_BASE_MAX_CMDRSP;
	cr = &(base->cmdrsp[pos]);
	cr->cr = rsp | (pf << 4);
	cr->addrlen = ax25_addr_encode(cr->addr, addr);
	/* Set C/R bits to response. */
	cr->addr[6] &= ~0x80;
	cr->addr[13] |= 0x80;
	cr->extra_data_size = extra_size;
	if (extra)
	    memcpy(cr->extra_data, extra, extra_size);
	base->cmdrsp_len++;
	gensio_set_write_callback_enable(base->child, true);
    }
    ax25_base_unlock(base);
}

static void
ax25_chan_send_cr(struct ax25_chan *chan, uint8_t crv, uint8_t pf, bool is_cmd,
		  unsigned char *extra, uint8_t extra_size)
{
    struct ax25_base *base = chan->base;
    struct ax25_chan_cmdrsp *cr;
    unsigned int pos;

    ax25_base_lock(base);
    if (chan->cmdrsp_len < AX25_CHAN_MAX_CMDRSP) {
	pos = (chan->cmdrsp_pos + chan->cmdrsp_len) % AX25_CHAN_MAX_CMDRSP;
	cr = &(chan->cmdrsp[pos]);
	cr->cr = crv;
	cr->pf = pf;
	cr->is_cmd = is_cmd;
	cr->extra_data_size = extra_size;
	if (extra)
	    memcpy(cr->extra_data, extra, extra_size);
	chan->cmdrsp_len++;
	i_ax25_chan_schedule_write(chan);
    }
    ax25_base_unlock(base);
}

static void
ax25_chan_send_cmd(struct ax25_chan *chan, uint8_t cmd, uint8_t pf)
{
    ax25_chan_send_cr(chan, cmd, pf, true, NULL, 0);
}

static void
ax25_chan_send_rsp(struct ax25_chan *chan, uint8_t rsp, uint8_t pf)
{
    ax25_chan_send_cr(chan, rsp, pf, false, NULL, 0);
}

static void
ax25_chan_send_sabm(struct ax25_chan *chan)
{
    if (chan->extended > 1) {
	unsigned char extra[4];

	extra[0] = chan->conf.readwindow;
	extra[1] = chan->conf.max_read_size & 0xff;
	extra[2] = chan->conf.max_read_size >> 8;
	extra[3] = 0;
	ax25_chan_send_cr(chan, X25_SABME, 1, true, extra, 4);
    } else if (chan->extended)
	ax25_chan_send_cmd(chan, X25_SABME, 1);
    else
	ax25_chan_send_cmd(chan, X25_SABM, 1);
}

static void
ax25_stop_timer(struct ax25_chan *chan)
{
    int rv;

    if (chan->curr_timeout) {
	rv = chan->o->stop_timer(chan->timer);
	if (rv == 0) {
	    /* We stopped it, lose the ref. */
	    ax25_chan_deref(chan);
	    chan->curr_timeout = 0;
	} else {
	    /* It's in the handler, it will do the deref. */
	    assert(rv == GE_TIMEDOUT);
	}
    } else {
	/* Just to be sure. */
	chan->o->stop_timer(chan->timer);
    }
}

static void
ax25_chan_check_new_timeout(struct ax25_chan *chan, int64_t value,
			    gensio_time *nowt)
{
    struct gensio_os_funcs *o = chan->o;
    gensio_time t;
    uint64_t now, then;
    int rv;

    if (chan->state == AX25_CHAN_CLOSED)
	return;

    if (chan->curr_timeout) {
	/* The timer is running or in the handler. */
	if (value >= chan->curr_timeout)
	    return; /* New value is after the current timeout. */
    }
    ax25_stop_timer(chan);
    chan->curr_timeout = value;
    now = gensio_time_to_msecs(nowt);
    then = chan->curr_timeout - now;
    gensio_msecs_to_time(&t, then);
    rv = o->start_timer(chan->timer, &t);
    if (rv) {
	gensio_log(o, GENSIO_LOG_FATAL, "AX25 timer start error: %s",
		   gensio_err_to_str(rv));
	assert(0);
    }
    ax25_chan_ref(chan);
}

/*
 * Given a value in milliseconds, return the absolute time in
 * milliseconds and return the current time in now.
 */
static int64_t
ax25_get_abs_timeout(struct gensio_os_funcs *o, unsigned int val,
		     gensio_time *now)
{
    int64_t v;

    o->get_monotonic_time(o, now);
    v = gensio_time_to_msecs(now);
    v += val;
    return v;
}

/*
 * You most be holding the channel lock to do timer operations.
 */

static void
ax25_chan_start_t1(struct ax25_chan *chan)
{
    gensio_time now;

    assert(chan->locked);
    chan->t1 = ax25_get_abs_timeout(chan->o, chan->t1v, &now);
    ax25_chan_check_new_timeout(chan, chan->t1, &now);
}

static void
ax25_chan_start_t2(struct ax25_chan *chan)
{
    gensio_time now;

    assert(chan->locked);
    chan->t2 = ax25_get_abs_timeout(chan->o, chan->conf.t2v, &now);
    ax25_chan_check_new_timeout(chan, chan->t2, &now);
}

static void
ax25_chan_start_t3(struct ax25_chan *chan)
{
    gensio_time now;

    assert(chan->locked);
    chan->t3 = ax25_get_abs_timeout(chan->o, chan->conf.t3v, &now);
    ax25_chan_check_new_timeout(chan, chan->t3, &now);
}

static void
ax25_chan_stop_t1(struct ax25_chan *chan)
{
    assert(chan->locked);
    chan->t1 = 0;
}

static void
ax25_chan_stop_t2(struct ax25_chan *chan)
{
    assert(chan->locked);
    chan->t2 = 0;
}

static void
ax25_chan_stop_t3(struct ax25_chan *chan)
{
    assert(chan->locked);
    chan->t3 = 0;
}

/*
 * Note that unlike the spec, this must be called *before* t1 is
 * cancelled, since that will set it to zero.
 */
static void
ax25_chan_recalc_t1(struct ax25_chan *chan, bool t1_expiry)
{
    struct gensio_os_funcs *o = chan->o;
    gensio_time now;
    int64_t diff;

    /* Calculate how much time is left on t1. */
    o->get_monotonic_time(o, &now);
    diff = gensio_time_to_msecs(&now);
    diff = chan->t1 - diff;
    if (diff < 0)
	diff = 0;

    if (chan->retry_count == 0) {
	chan->srt = (7 * chan->srt / 8) + (chan->t1v / 8) - (diff / 8);
	chan->t1v = chan->srt * 2;
    } else if (t1_expiry) {
	chan->t1v = (1 << (chan->retry_count + 1)) * chan->srt;
    }
}

static void
ax25_chan_transmit_enquiry(struct ax25_chan *chan)
{
    ax25_chan_send_ack(chan, 1, true);
    ax25_chan_start_t1(chan);
}

static void
ax25_t1_timeout(struct ax25_chan *chan)
{
    struct ax25_base *base = chan->base;

    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
	if (chan->retry_count >= chan->max_retries) {
	    chan->err = GE_TIMEDOUT;
	    ax25_chan_set_state(chan, AX25_CHAN_CLOSED);
	    ax25_chan_move_to_closed(chan, &base->chans);
	    ax25_chan_report_open(chan);
	} else {
	    chan->retry_count++;
	    ax25_chan_send_sabm(chan);
	    ax25_chan_recalc_t1(chan, true);
	    chan->t1 = chan->t1v;
	    ax25_chan_start_t1(chan);
	}
	break;

    case AX25_CHAN_OPEN:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	if (chan->poll_pending) {
	    if (chan->retry_count == chan->max_retries) {
		ax25_proto_err(chan->base, chan, "Connection timed out");
		ax25_chan_send_rsp(chan, X25_DM, 1);
		chan->err = GE_TIMEDOUT;
		ax25_chan_do_err_close(chan, true);
		ax25_chan_stop_t3(chan);
		ax25_chan_stop_t1(chan);
	    } else {
		chan->retry_count++;
		ax25_chan_transmit_enquiry(chan);
	    }
	} else {
	    chan->retry_count = 1;
	    chan->poll_pending = true;
	    ax25_chan_transmit_enquiry(chan);
	}
	break;

    case AX25_CHAN_IN_CLOSE:
	if (chan->retry_count >= chan->max_retries) {
	    chan->err = GE_TIMEDOUT;
	    ax25_chan_do_close(chan, true);
	} else {
	    chan->retry_count++;
	    ax25_chan_send_cmd(chan, X25_DISC, 1);
	    /*
	     * Do not recalculate t1 on a disconnect.  It is possible
	     * the other end isn't listening any more and this will
	     * make the disconnect painfully slow.
	     */
	    chan->t1 = chan->t1v;
	    ax25_chan_start_t1(chan);
	}
	break;

    default:
	/* Just ignore this. */
	break;
    }
}

static void ax25_t2_timeout(struct ax25_chan *chan)
{
    switch (chan->state) {
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
    case AX25_CHAN_OPEN:
	if (chan->ack_pending)
	    ax25_chan_send_ack(chan, 0, false);
	break;

    case AX25_CHAN_IN_OPEN:
    case AX25_CHAN_IN_CLOSE:
    default:
	/* Just ignore this. */
	break;
    }
}

static void ax25_t3_timeout(struct ax25_chan *chan)
{
    switch (chan->state) {
    case AX25_CHAN_OPEN:
	chan->retry_count = 0;
	ax25_chan_transmit_enquiry(chan);
	break;

    case AX25_CHAN_IN_OPEN:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
    case AX25_CHAN_IN_CLOSE:
    default:
	/* Just ignore this. */
	break;
    }
}

static void
ax25_chan_timeout(struct gensio_timer *timer, void *cb_data)
{
    struct ax25_chan *chan = cb_data;
    struct gensio_os_funcs *o = chan->o;
    gensio_time t;
    int64_t now;

    o->get_monotonic_time(o, &t);
    now = gensio_time_to_msecs(&t);

    ax25_chan_lock(chan);
    /* Just in case the timer was started between the timeout and here. */
    ax25_stop_timer(chan);

    if (chan->state == AX25_CHAN_CLOSED)
	goto out_unlock;

    if (chan->t1 && chan->t1 <= now) {
	chan->t1 = 0;
	ax25_t1_timeout(chan);
    }
    if (chan->t2 && chan->t2 <= now) {
	chan->t2 = 0;
	ax25_t2_timeout(chan);
    }
    if (chan->t3 && chan->t3 <= now) {
	chan->t3 = 0;
	ax25_t3_timeout(chan);
    }
    chan->curr_timeout = 0;
    if (chan->t1)
	chan->curr_timeout = chan->t1;
    if (chan->t2 && chan->t2 < chan->curr_timeout)
	chan->curr_timeout = chan->t2;
    if (chan->t3 && chan->t3 < chan->curr_timeout)
	chan->curr_timeout = chan->t3;
    if (chan->curr_timeout) {
	int64_t then = chan->curr_timeout - now;

	/*
	 * Don't use an absolute timer here, the precision isn't really good
	 * enough, especially on some OS handlers.
	 */
	gensio_msecs_to_time(&t, then);
	if (o->start_timer(chan->timer, &t) != 0)
	    assert(0);
	ax25_chan_ref(chan);
    }
 out_unlock:
    ax25_chan_deref_and_unlock(chan);
}

static void
ax25_chan_set_extended(struct ax25_chan *chan, bool extended,
		       unsigned char *data, unsigned int len)
{
    unsigned int max_pkt;

    chan->max_retries = chan->conf.max_retries;
    if (chan->extended >= 2 && extended && len >= 4) {
	chan->extended = 2;
	chan->modulo = 128;
	if (data[0])
	    chan->writewindow = data[0];
	else if (chan->conf.writewindow > 7)
	    chan->writewindow = 7;
	else
	    chan->writewindow = chan->conf.writewindow;
	max_pkt = data[2] << 8 | data[1];
	if (max_pkt < 256)
	    chan->max_write_size = 256;
	else if (max_pkt > chan->conf.max_write_size)
	    chan->max_write_size = chan->conf.max_write_size;
	else
	    chan->max_write_size = max_pkt;
	chan->readwindow = chan->conf.readwindow;
	return;
    }

    chan->extended = extended;
    if (chan->conf.max_write_size > 256)
	chan->max_write_size = 256;
    else
	chan->max_write_size = chan->conf.max_write_size;
    if (chan->extended) {
	chan->modulo = 128;
	if (chan->conf.writewindow > 7)
	    chan->writewindow = 7;
	else
	    chan->writewindow = chan->conf.writewindow;
	if (chan->conf.readwindow > 7)
	    chan->readwindow = 7;
	else
	    chan->readwindow = chan->conf.readwindow;
    } else {
	chan->modulo = 8;
	if (chan->conf.writewindow > 4)
	    chan->writewindow = 4;
	else
	    chan->writewindow = chan->conf.writewindow;
	if (chan->conf.readwindow > 4)
	    chan->readwindow = 4;
	else
	    chan->readwindow = chan->conf.readwindow;
    }
}

/* Must be called with the channel and base lock held. */
static void
ax25_chan_prestart_connect(struct ax25_chan *chan)
{
    ax25_chan_reset_data(chan);
    if (chan->conf.addr)
	ax25_chan_set_stateb(chan, AX25_CHAN_IN_OPEN);
    else
	ax25_chan_set_stateb(chan, AX25_CHAN_NOCON_IN_OPEN);
}

/* Must be called with the channel lock held, but not the base lock. */
static void
ax25_chan_start_connect(struct ax25_chan *chan)
{
    if (chan->conf.addr) {
	ax25_chan_set_extended(chan, chan->conf.extended, NULL, 0);
	ax25_chan_send_sabm(chan);
	ax25_chan_start_t1(chan);
	chan->retry_count = 0;
    } else {
	/* A channel for only doing UI messages. */
	ax25_chan_sched_deferred_op(chan);
    }
}

static bool
ax25_match_subaddr(struct gensio_ax25_subaddr *dest,
		   struct gensio_ax25_subaddr *matches,
		   unsigned int num_matches)
{
    unsigned int i;

    for (i = 0; i < num_matches; i++) {
	if (ax25_subaddr_equal(dest, &(matches[i])))
	    return true;
    }
    return false;
}

static void
ax25_chan_handle_ui(struct ax25_base *base, struct gensio_ax25_addr *addr,
		    unsigned char *data, unsigned int len,
		    uint8_t pf)
{
    struct gensio_list to_deliver;
    struct gensio_link *l, *l2;
    char addrstr[GENSIO_AX25_MAX_ADDR_STR_LEN + 5];
    char pidstr[10];
    const char *auxdata[4] = { "oob", addrstr, pidstr, NULL };
    gensiods rcount;

    if (len == 0)
	return;

    snprintf(pidstr, sizeof(pidstr), "pid:%d", *data);
    data++;
    len--;
    gensio_list_init(&to_deliver);
    ax25_base_lock(base);
    gensio_list_for_each(&base->chans, l) {
	struct ax25_chan *chan = gensio_container_of(l, struct ax25_chan, link);

	if (!chan->report_ui || !chan->read_enabled)
	    continue;
	if (chan->report_ui < 2 &&
		!ax25_match_subaddr(&addr->dest, chan->base->conf.my_addrs,
				    chan->base->conf.num_my_addrs))
	    continue;
	gensio_list_add_tail(&to_deliver, &chan->base_lock_ui_link);
	chan->base_lock_count++;
    }
    ax25_base_unlock(base);
    if (gensio_list_empty(&to_deliver))
	return;

    strcpy(addrstr, "addr:");
    gensio_addr_to_str(&addr->r, addrstr + 5, NULL, sizeof(addrstr) - 5);

    gensio_list_for_each_safe(&to_deliver, l, l2) {
	struct ax25_chan *chan = gensio_container_of(l, struct ax25_chan,
						     base_lock_ui_link);

	gensio_list_rm(&to_deliver, l);
	chan = ax25_chan_check_base_lock_state(chan, &chan->base->chans,
					       true);
	if (!chan || !chan->read_enabled)
	    continue;

	chan->in_ui = true;
	ax25_chan_unlock(chan);

	rcount = len;
	/* Errors from here don't matter, we don't loop. */
	gensio_cb(chan->io, GENSIO_EVENT_READ, 0, data, &rcount, auxdata);

	ax25_chan_lock(chan);
	chan->in_ui = false;
	if (chan->state == AX25_CHAN_REPORT_CLOSE)
	    ax25_chan_check_close(chan);
	ax25_chan_deref_and_unlock(chan);
    }
}

static void
ax25_construct_return_addr(struct gensio_ax25_addr *r,
			   struct gensio_ax25_addr *a)
{
    unsigned int i;

    r->r = a->r;
    r->o = a->o;
    r->tnc_port = a->tnc_port;
    r->nr_extra = a->nr_extra;
    r->dest = a->src;
    r->dest.ch = 0;
    r->src = a->dest;
    r->src.ch = 0;
    /* Reverse the extra for going back to the source. */
    for (i = 0; i < r->nr_extra; i++) {
	r->extra[i] = a->extra[r->nr_extra - i - 1];
	r->extra[i].ch = 0;
    }
}

static struct ax25_chan *
ax25_base_first_chan(struct ax25_base *base)
{
    struct ax25_chan *chan;

    ax25_base_lock(base);
    if (gensio_list_empty(&base->chans))
	chan = NULL;
    else
	chan = gensio_container_of(gensio_list_first(&base->chans),
				   struct ax25_chan, link);
    if (chan)
	chan->base_lock_count++;
    ax25_base_unlock(base);

    return chan;
}

/*
 * Call the event handler for the first registered channel.
 */
static int
ax25_firstchan_event(struct ax25_base *base, int event, int err,
		     unsigned char *buf, gensiods *buflen,
		     const char * const * auxdata)
{
    int rerr;
    struct ax25_chan *chan;

 retry:
    chan = ax25_base_first_chan(base);
    if (!chan)
	return GE_LOCALCLOSED;
    chan = ax25_chan_check_base_lock_state(chan, &base->chans, true);
    if (!chan)
	goto retry;
    ax25_chan_unlock(chan);
    rerr = gensio_cb(chan->io, event, err, buf, buflen, auxdata);
    ax25_chan_lock(chan);
    ax25_chan_deref_and_unlock(chan);

    return rerr;
}

/*
 * In an accepter, before startup the first channel is sitting in the
 * closed channel list.  We need to convert it to an open channel.
 */
static struct ax25_chan *
i_ax25_base_promote_first_chan(struct ax25_base *base)
{
    struct ax25_chan *chan;

    assert(!gensio_list_empty(&base->chans_closed));
    chan = gensio_container_of(gensio_list_first(&base->chans_closed),
			       struct ax25_chan, link);
    gensio_list_rm(&base->chans_closed, &chan->link);
    gensio_list_add_tail(&base->chans, &chan->link);
    /*
     * Don't use set state here, the channel lock is not held, but it
     * doesn't matter.
     */
    chan->state = AX25_CHAN_OPEN;

    return chan;
}

static struct ax25_chan *
ax25_base_promote_first_chan(struct ax25_base *base)
{
    struct ax25_chan *chan;

    ax25_base_lock(base);
    chan = i_ax25_base_promote_first_chan(base);
    ax25_base_unlock(base);

    return chan;
}

static struct ax25_chan *
ax25_chan_handle_sabm(struct ax25_base *base, struct ax25_chan *chan,
		      struct gensio_ax25_addr *addr, uint8_t pf, bool is_cmd,
		      unsigned int extended, unsigned char *data,
		      unsigned int len)
{
    int rv;

    if (!chan) {
	if (extended && !base->conf.extended) {
	    unsigned char extra[3];

	    extra[2] = X25_SABME;
	    extra[1] = is_cmd << 4;
	    extra[0] = 1;
	    ax25_base_send_rsp(base, &addr->r, X25_FRMR, pf, extra, 3);
	    return 0;
	}

	if (base->waiting_first_open) {
	    base->waiting_first_open = false;
	    chan = ax25_base_promote_first_chan(base);
	    chan->conf.addr = gensio_addr_dup(&addr->r);
	    if (!chan->conf.addr) {
		chan->err = GE_NOMEM;
		ax25_base_send_rsp(base, &addr->r, X25_DM, pf, NULL, 0);
		ax25_chan_report_open(chan);
		return NULL;
	    }
	    chan->encoded_addr_len = ax25_addr_encode(chan->encoded_addr,
						      chan->conf.addr);
	    ax25_chan_set_extended(chan, extended, data, len);
	    ax25_chan_lock_and_ref(chan);
	    ax25_chan_report_open(chan);
	} else {
	    rv = ax25_chan_alloc(base, NULL, NULL, NULL, AX25_CHAN_OPEN,
				 &addr->r, false, &chan);
	    if (rv) {
		ax25_base_send_rsp(base, &addr->r, X25_DM, pf, NULL, 0);
		return NULL;
	    }
	    ax25_chan_set_extended(chan, extended, data, len);
	    if (base->accepter) {
		gensio_acc_cb(base->accepter, GENSIO_ACC_EVENT_NEW_CONNECTION,
			      chan->io);
		ax25_chan_lock(chan);
	    } else {
		char addrstr[GENSIO_AX25_MAX_ADDR_STR_LEN + 5];
		const char *auxdata[2] = { addrstr, NULL };

		strcpy(addrstr, "addr:");
		gensio_addr_to_str(&addr->r, addrstr + 5, NULL,
				   sizeof(addrstr) - 5);
		chan->in_newchannel = 1;
		rv = ax25_firstchan_event(base, GENSIO_EVENT_NEW_CHANNEL, 0,
					  (unsigned char *) chan->io,
					  NULL, auxdata);
		ax25_chan_lock(chan);
		if (rv || chan->in_newchannel == 2) {
		    if (chan->in_newchannel != 2) {
			ax25_chan_set_state(chan, AX25_CHAN_CLOSED);
			ax25_chan_move_to_closed(chan, &base->chans);
		    }
		    ax25_chan_deref_and_unlock(chan);
		    ax25_base_send_rsp(base, &addr->r, X25_DM, pf, NULL, 0);
		    chan->in_newchannel = 0;
		    return NULL;
		}
		chan->in_newchannel = 0;
	    }
	    ax25_chan_ref(chan);
	}
	ax25_chan_send_rsp(chan, X25_UA, pf);
	if (chan->extended)
	    ax25_chan_send_cmd(chan, X25_XID, 1);
	/* Increase the timeout for every hop through a digipeater. */
	chan->srt = chan->conf.srtv * (addr->nr_extra + 1);
	chan->t1v = chan->srt * 2;
	ax25_chan_start_t3(chan);
	return chan;
    }

    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
	if (!chan->extended && extended) {
	    unsigned char extra[3];

	    extra[2] = X25_SABME;
	    extra[1] = is_cmd << 4;
	    extra[0] = 1;
	    ax25_chan_send_cr(chan, X25_FRMR, pf, is_cmd, extra, 3);
	} else {
	handle_in_open:
	    ax25_chan_set_extended(chan, extended, data, len);
	    ax25_chan_send_rsp(chan, X25_UA, pf);
	}
	break;

    case AX25_CHAN_OPEN:
	/* If no packets have been received, pretend this is a new sabm. */
	if (!chan->got_firstmsg)
	    goto handle_in_open;
	ax25_proto_err(base, chan, "Data Link Reset");
	ax25_chan_send_rsp(chan, X25_DM, pf);
	chan->err = GE_PROTOERR;
	ax25_chan_do_err_close(chan, true);
	ax25_chan_stop_t3(chan);
	ax25_chan_stop_t1(chan);
	break;

    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	/* Data has been lost, no need for drain wait, just shut down. */
    case AX25_CHAN_IN_CLOSE:
    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	ax25_chan_send_rsp(chan, X25_DM, pf);
	ax25_chan_do_close(chan, true);
	break;

    default:
	assert(0);
    }

    return chan;
}

static void
ax25_chan_handle_disc(struct ax25_base *base, struct ax25_chan *chan,
		      struct gensio_ax25_addr *addr, uint8_t pf, bool is_cmd)
{
    if (!chan) {
	ax25_base_send_rsp(base, &addr->r, X25_DM, pf, NULL, 0);
	return;
    }

    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
	ax25_chan_send_rsp(chan, X25_DM, pf);
	break;

    case AX25_CHAN_CLOSE_WAIT_DRAIN:
    case AX25_CHAN_IN_CLOSE:
	/* Channel will be closed, used the base queue. */
	ax25_base_send_rsp(base, chan->conf.addr, X25_UA, pf, NULL, 0);
	ax25_chan_do_close(chan, true);
	break;

    case AX25_CHAN_OPEN:
	chan->err = GE_REMCLOSE;
	ax25_chan_set_state(chan, AX25_CHAN_REM_DISC);
	ax25_chan_send_rsp(chan, X25_UA, pf);
	ax25_chan_stop_t3(chan);
	ax25_chan_stop_t1(chan);
	break;

    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	ax25_chan_send_rsp(chan, X25_UA, pf);
	break;

    default:
	assert(0);
    }
}

static void
ax25_chan_handle_fallback_response(struct ax25_chan *chan)
{
    /* FIXME - handle subfields. */
    if (chan->extended == 2) {
	chan->extended = 1;
	ax25_chan_send_sabm(chan);
	ax25_chan_start_t1(chan);
    } else if (chan->extended == 1) {
	chan->extended = 0;
	chan->modulo = 8;
	chan->writewindow = 4;
	chan->readwindow = 4;
	ax25_chan_send_sabm(chan);
	ax25_chan_start_t1(chan);
    }
}

static void
ax25_chan_handle_dm(struct ax25_base *base, struct ax25_chan *chan,
		    struct gensio_ax25_addr *addr, uint8_t pf, bool is_cmd)
{
    if (!chan)
	/* Ignore this. */
	return;

    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
	if (chan->extended > 0) {
	    /*
	     * Some broken stacks respond with DM, not FRMR, when they
	     * receive a SABME but don't support it.
	     */
	    ax25_chan_handle_fallback_response(chan);
	} else {
	    if (pf) {
		chan->err = GE_REMCLOSE;
		ax25_chan_do_err_close(chan, false);
		ax25_chan_stop_t1(chan);
		ax25_chan_report_open(chan);
	    }
	}
	break;

    case AX25_CHAN_OPEN:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	chan->err = GE_REMCLOSE;
	ax25_chan_stop_t3(chan);
	ax25_chan_stop_t1(chan);
	if (chan->state == AX25_CHAN_CLOSE_WAIT_DRAIN)
	    ax25_chan_do_close(chan, true);
	else
	    ax25_chan_do_err_close(chan, true);
	break;

    case AX25_CHAN_IN_CLOSE:
    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	if (pf) {
	    chan->err = GE_REMCLOSE;
	    ax25_chan_stop_t1(chan);
	    ax25_chan_do_close(chan, true);
	}
	break;

    default:
	assert(0);
    }
}

static void
ax25_chan_handle_ua(struct ax25_base *base, struct ax25_chan *chan,
		    struct gensio_ax25_addr *addr, uint8_t pf, bool is_cmd,
		    unsigned char *data, unsigned int len)
{
    if (!chan) {
	ax25_proto_err(base, chan, "Unexpected UA when disconnected");
	/* Ignore this. */
	return;
    }

    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
	if (pf) {
	    if (len >= 4)
		ax25_chan_set_extended(chan, true, data, len);
	    ax25_chan_stop_t1(chan);
	    ax25_chan_start_t3(chan);
	    ax25_chan_set_state(chan, AX25_CHAN_OPEN);
	    ax25_chan_report_open(chan);
	} else {
	    ax25_proto_err(base, chan,
		     "UA received without F=1 when SABM or DISC was sent P=1");
	}
	break;

    case AX25_CHAN_OPEN:
	/* If no packets have been received, just ignore this. */
	ax25_proto_err(base, chan, "Unexpected UA when connected");
	if (!chan->conf.ignore_embedded_ua) {
	    ax25_chan_stop_t3(chan);
	    ax25_chan_stop_t2(chan);
	    ax25_chan_stop_t1(chan);
	    ax25_chan_reset_data(chan);
	}
	break;

    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	ax25_chan_send_cmd(chan, X25_DISC, 1);
	ax25_chan_start_t1(chan);
	ax25_chan_stop_t3(chan);
	ax25_chan_set_state(chan, AX25_CHAN_IN_CLOSE);
	break;

    case AX25_CHAN_IN_CLOSE:
	if (pf) {
	    ax25_chan_stop_t1(chan);
	    ax25_chan_do_close(chan, true);
	} else {
	    ax25_proto_err(base, chan,
		     "UA received without F=1 when SABM or DISC was sent P=1");
	}
	break;

    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	break;

    default:
	assert(0);
    }
}

#define AX25_XID_SIZE	29
static void
ax25_chan_format_xid(struct ax25_chan *chan, unsigned char *buf)
{
    unsigned int i = 0;
    uint32_t val;

    /* Note that these are big endian, the rest of AX.25 is little. */

    buf[i++] = 0x82; /* FI Format indicator */
    buf[i++] = 0x80; /* GI Group indicator */
    val = 25; /* Our group size */
    buf[i++] = (val >> 8) & 0xff;
    buf[i++] = val & 0xff;

    buf[i++] = 2; /* PI Classes of Procedures */
    buf[i++] = 2;
    val = 0x2100; /* Only half duplex and balanced mode. */
    buf[i++] = (val >> 8) & 0xff;
    buf[i++] = val & 0xff;

    buf[i++] = 3; /* PI HDLC Optional Functions */
    buf[i++] = 3;
    val = (0x800000 | /* Extended address  */
	   0x020000 | /* REJ */
	   0x040000 | /* SREJ */
	   0x008000 | /* 16 bit FCS */
	   0x002000 | /* TEST cmd */
	   0x000800 | /* Modulo 128 */
	   0x000002); /* synchronous TX */
    buf[i++] = (val >> 16) & 0xff;
    buf[i++] = (val >> 8) & 0xff;
    buf[i++] = val & 0xff;

    buf[i++] = 6; /* PI I Field Length RX */
    buf[i++] = 2;
    val = chan->conf.max_read_size * 8;
    buf[i++] = (val >> 8) & 0xff;
    buf[i++] = val & 0xff;

    buf[i++] = 8; /* PI Window Size RX */
    buf[i++] = 1;
    buf[i++] = chan->conf.readwindow;

    buf[i++] = 9; /* Ack Timeout */
    buf[i++] = 4;
    val = chan->conf.srtv * 2;
    buf[i++] = (val >> 24) & 0xff;
    buf[i++] = (val >> 16) & 0xff;
    buf[i++] = (val >> 8) & 0xff;
    buf[i++] = val & 0xff;

    buf[i++] = 10; /* PI Retries */
    buf[i++] = 1;
    buf[i++] = chan->conf.max_retries;

    assert(i == AX25_XID_SIZE);
}

static void
ax25_chan_handle_xid(struct ax25_base *base, struct ax25_chan *chan,
		     struct gensio_ax25_addr *addr, uint8_t pf, bool is_cmd,
		     unsigned char *buf, unsigned int buflen)
{
    unsigned int i = 0, group_len, len;

    if (!chan || chan->state != AX25_CHAN_OPEN)
	/* Ignore this. */
	return;

    if (buflen < 4)
	return;

    if (buf[i++] != 0x82) /* FI Format indicator */
	return;
    if (buf[i++] != 0x80) /* GI Group indicator */
	return;
    group_len = buf[i++];
    group_len = (group_len << 8) | buf[i++];
    buf += 4;
    buflen -= 4;
    if (buflen < group_len)
	return;

    for (; group_len; group_len -= len, buf += len) {
	unsigned int ind, val, j;

	if (group_len < 2)
	    return;
	i = 0;
	ind = buf[i++];
	len = buf[i++];
	if (len < 1 || len > 4)
	    return;
	if (group_len < len + 2)
	    return;
	for (j = 0, val = 0; j < len; j++)
	    val = (val << 8) | buf[i++];
	len += 2;
	switch(ind) {
	case 2: /* PI Classes of Procedures */
	    /* Ignore this, we only really do half duplex. */
	    break;

	case 3: /* PI HDLC Optional Functions */
	    /* Ignore this, we only send REJ. */
	    break;

	case 6: /* PI I Field Length RX */
	    if (val % 8 != 0) /* This is in bits, needs tobe multiple of 8 */
		break;
	    val /= 8;
	    if (val <= 0)
		break;
	    if (val > chan->conf.max_write_size)
		val = chan->conf.max_write_size;
	    chan->writewindow = val;
	    break;

	case 8: /* PI Window Size RX */
	    if (val <= 0)
		break;
	    if (val > chan->conf.writewindow)
		val = chan->conf.writewindow;
	    chan->writewindow = val;
	    break;

	case 9: /* PI Ack Timer */
	    if (val <= 0)
		break;
	    if (val / 2 > chan->conf.srtv)
		chan->srt = val / 2;
	    break;

	case 10: /* PI Retries */
	    if (val <= 0)
		break;
	    if (val > chan->conf.max_retries)
		chan->max_retries = val;
	    break;
	}
    }
    if (is_cmd)
	ax25_chan_send_rsp(chan, X25_XID, pf);
}

static void
ax25_chan_handle_test(struct ax25_base *base, struct ax25_chan *chan,
		      struct gensio_ax25_addr *addr, uint8_t pf, bool is_cmd,
		      unsigned char *buf, unsigned int buflen)
{
    if (!chan || chan->state != AX25_CHAN_OPEN)
	/* Ignore this. */
	return;

    if (buflen > AX25_CHAN_MAX_CMDRSP_EXTRA)
	buflen = AX25_CHAN_MAX_CMDRSP_EXTRA;

    ax25_chan_send_cr(chan, X25_TEST, pf, false, buf, buflen);
}

static void
ax25_chan_handle_frmr(struct ax25_base *base, struct ax25_chan *chan,
		      struct gensio_ax25_addr *addr, uint8_t pf, bool is_cmd,
		      unsigned char *buf, unsigned int buflen)
{
    if (!chan)
	/* Ignore this. */
	return;

    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
	ax25_chan_handle_fallback_response(chan);
	break;

    case AX25_CHAN_OPEN:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
    case AX25_CHAN_IN_CLOSE:
    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	/* Just ignore these. */
	break;

    default:
	assert(0);
    }
}

static void
ax25_chan_update_va(struct ax25_chan *chan, uint8_t nr)
{
    uint8_t first = sub_seq(chan->vs, chan->write_len, chan->modulo);
    uint8_t diff;

    chan->va = nr;
    diff = sub_seq(nr, first, chan->modulo);
    chan->write_len -= diff;
    if (chan->send_len > chan->write_len)
	/*
	 * If we are re-sending and we get an ack for what we are
	 * resending, just abort the resend for the packets that are
	 * to be acked.
	 */
	chan->send_len = chan->write_len;
    if (chan->xmit_enabled && chan_can_write(chan))
	ax25_chan_sched_deferred_op(chan);
}

static bool
ax25_chan_seq_in_range(struct ax25_chan *chan, uint8_t nr)
{
    uint8_t first = sub_seq(chan->vs, chan->write_len, chan->modulo);

    if (!seq_in_range(first, chan->vs, nr, chan->modulo)) {
	ax25_proto_err(chan->base, chan, "N(r) sequence error");
	return false;
    }
    return true;
}

static int
ax25_chan_handle_data(struct ax25_chan *chan, uint8_t ns, uint8_t pf,
		      unsigned char *data, unsigned int len)
{
    uint8_t pos = add_seq(chan->read_pos, chan->read_len, chan->conf.readwindow);
    struct ax25_data *d;
    uint8_t pid;

    if (chan->own_rcv_bsy) {
	if (pf)
	    ax25_chan_send_ack(chan, pf, 1);
	return 0;
    }
    if (len == 0) {
	/* No PID. */
	ax25_proto_err(chan->base, chan, "I frame too short");
	return GE_PROTOERR;
    }
    pid = *data;
    data++;
    len--;
    if (ns == chan->vr) {
	/* It's what we expect, just deliver it. */
	if (chan->read_len >= chan->conf.readwindow) {
	    /* read window violation. */
	    ax25_proto_err(chan->base, chan, "Read window exceeded");
	    return GE_PROTOERR;
	}

	chan->in_rej = false;
	d = &(chan->read_data[pos]);
	memcpy(d->data, data, len);
	d->pid = pid;
	d->len = len;
	d->pos = 0;
	d->seq = ns;
	d->present = true;
	chan->read_len++;
	ax25_chan_deliver_read(chan);
	chan->vr = add_seq(chan->vr, 1, chan->modulo);

	/* We got some data, handle acks. */
	if (pf) {
	    ax25_chan_send_ack(chan, pf, false);
	} else if (chan->ack_pending > (chan->readwindow / 2)) {
	    /* More than half the window is used, send an ack now. */
	    ax25_chan_send_ack(chan, 0, false);
	} else {
	    if (!chan->ack_pending)
		/* The timer wasn't running, start it. */
		ax25_chan_start_t2(chan);
	    chan->ack_pending++;
	}
    } else {
	uint8_t end = add_seq(chan->vr, chan->readwindow - 1, chan->modulo);

	/*
	 * Only consider sequences in our window for resends, ignore
	 * everything else.
	 */
	if (seq_in_range(chan->vr, end, ns, chan->modulo)) {
	    if (chan->in_rej) {
		if (pf)
		    ax25_chan_send_ack(chan, pf, false);
	    } else {
		chan->in_rej = true;
		ax25_chan_send_rsp(chan, X25_REJ, pf);
		ax25_chan_stop_t2(chan);
		chan->ack_pending = 0;
	    }
	}
    }

    return 0;
}

static void
ax25_chan_check_drain_done(struct ax25_chan *chan)
{
    if (chan->vs == chan->va) {
	/* All data is acked in wait drain state, we can close. */
	ax25_chan_send_cmd(chan, X25_DISC, 1);
	ax25_chan_start_t1(chan);
	ax25_chan_stop_t3(chan);
	ax25_chan_set_state(chan, AX25_CHAN_IN_CLOSE);
    }
}

static void
ax25_chan_check_i_frame_acked(struct ax25_chan *chan, uint8_t nr)
{
    if (chan->peer_rcv_bsy) {
	ax25_chan_update_va(chan, nr);
	ax25_chan_start_t3(chan);
	if (!chan->t1)
	    ax25_chan_start_t1(chan);
    } else {
	if (chan->vs == nr) {
	    ax25_chan_update_va(chan, nr);
	    ax25_chan_recalc_t1(chan, false);
	    ax25_chan_stop_t1(chan);
	    ax25_chan_start_t3(chan);
	} else {
	    if (chan->va != nr) {
		ax25_chan_update_va(chan, nr);
		ax25_chan_start_t1(chan);
	    }
	}
    }
}

static int
ax25_chan_handle_i(struct ax25_base *base, struct ax25_chan *chan,
		   struct gensio_ax25_addr *addr,
		   uint8_t nr, uint8_t ns, uint8_t pf, bool is_cmd,
		   unsigned char *data, unsigned int len)
{
    int rv = 0;

    chan->got_firstmsg = true;
    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	break;

    case AX25_CHAN_IN_CLOSE:
	if (pf)
	    ax25_chan_send_rsp(chan, X25_DM, pf);
	break;

    case AX25_CHAN_OPEN:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	if (!is_cmd) {
	    ax25_proto_err(base, chan, "Received response I frame");
	    return 0;
	}
	if (len > chan->conf.max_read_size + 1) { /* + 1 for PID */
	    ax25_proto_err(base, chan, "Received too large a packet");
	    return GE_PROTOERR;
	}
	if (!ax25_chan_seq_in_range(chan, nr))
	    return GE_PROTOERR;
	ax25_chan_check_i_frame_acked(chan, nr);
	if (chan->state == AX25_CHAN_OPEN) {
	    /* Only handle data in open state, throw away in wait drain. */
	    rv = ax25_chan_handle_data(chan, ns, pf, data, len);
	} else {
	    ax25_chan_check_drain_done(chan);
	}
	break;

    default:
	assert(0);
    }

    return rv;
}

static void
ax25_chan_check_response_needed(struct ax25_chan *chan,
				uint8_t pf, bool is_cmd)
{
    if (is_cmd && pf) {
	ax25_chan_send_ack(chan, pf, false);
    } else if (!is_cmd && pf) {
	if (chan->poll_pending) {
	    chan->poll_pending = false;
	    chan->retry_count = 0;
	} else {
	    ax25_proto_err(chan->base, chan, "F=1 but P=1 not outstanding");
	}
    }
}

static void
ax25_chan_rewind_seq(struct ax25_chan *chan, uint8_t nr, bool selective)
{
    uint8_t diff, i;
    unsigned int pos;

    diff = sub_seq(chan->vs, nr, chan->modulo);
    if (diff > chan->send_len) {
	/* Only back up if we need to back up more. */
	chan->send_len = diff;
	assert(chan->send_len <= chan->write_len);
    }
    pos = sub_seq(chan->write_pos, diff, chan->conf.writewindow);
    for (i = 0; i < diff; i++) {
	chan->write_data[pos].present = true;
	if (selective)
	    /* In selective reject, we only mark the one. */
	    break;
	pos = add_seq(pos, 1, chan->conf.writewindow);
    }
    ax25_chan_schedule_write(chan);
    ax25_chan_start_t1(chan);
}

static int
ax25_chan_handle_recovery_rsp(struct ax25_chan *chan, uint8_t nr,
			      uint8_t pf, bool is_cmd)
{
    if (!is_cmd && pf) {
	ax25_chan_recalc_t1(chan, false);
	ax25_chan_stop_t1(chan);
	if (!ax25_chan_seq_in_range(chan, nr))
	    return GE_PROTOERR;
	ax25_chan_update_va(chan, nr);
	if (chan->vs == chan->va) {
	    chan->poll_pending = false;
	    chan->retry_count = 0;
	    ax25_chan_start_t3(chan);
	} else {
	    ax25_chan_rewind_seq(chan, nr, false);
	}
    } else {
	if (is_cmd && pf)
	    ax25_chan_send_ack(chan, pf, false);
	if (!ax25_chan_seq_in_range(chan, nr))
	    return GE_PROTOERR;
	ax25_chan_update_va(chan, nr);
    }
    return 0;
}

static void
ax25_chan_clr_peer_rcv_bsy(struct ax25_chan *chan)
{
    chan->peer_rcv_bsy = false;
    if (chan->send_len > 0)
	ax25_chan_schedule_write(chan);
}

static int
ax25_chan_handle_rr_rnr(struct ax25_chan *chan, uint8_t nr, uint8_t pf,
			bool is_cmd)
{
    int rv;

    if (chan->poll_pending) {
	rv = ax25_chan_handle_recovery_rsp(chan, nr, pf, is_cmd);
	if (rv)
	    return rv;
    } else {
	ax25_chan_check_response_needed(chan, pf, is_cmd);
	if (!ax25_chan_seq_in_range(chan, nr))
	    return GE_PROTOERR;
	ax25_chan_check_i_frame_acked(chan, nr);
    }
    if (chan->state == AX25_CHAN_CLOSE_WAIT_DRAIN)
	ax25_chan_check_drain_done(chan);
    return 0;
}

static int
ax25_chan_handle_rr(struct ax25_base *base, struct ax25_chan *chan,
		    uint8_t nr, uint8_t pf, bool is_cmd)
{
    int rv = 0;

    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	break;

    case AX25_CHAN_IN_CLOSE:
	if (pf)
	    ax25_chan_send_rsp(chan, X25_DM, pf);
	break;

    case AX25_CHAN_OPEN:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	ax25_chan_clr_peer_rcv_bsy(chan);
	rv = ax25_chan_handle_rr_rnr(chan, nr, pf, is_cmd);
	break;

    default:
	assert(0);
    }

    return rv;
}

static int
ax25_chan_handle_rnr(struct ax25_base *base, struct ax25_chan *chan,
		     uint8_t nr, uint8_t pf, bool is_cmd)
{
    int rv = 0;

    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	break;

    case AX25_CHAN_IN_CLOSE:
	if (pf)
	    ax25_chan_send_rsp(chan, X25_DM, pf);
	break;

    case AX25_CHAN_OPEN:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	chan->peer_rcv_bsy = true;
	rv = ax25_chan_handle_rr_rnr(chan, nr, pf, is_cmd);
	break;

    default:
	assert(0);
    }

    return rv;
}

static int
ax25_chan_handle_rej(struct ax25_base *base, struct ax25_chan *chan,
		     uint8_t nr, uint8_t pf, bool is_cmd)
{
    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	break;

    case AX25_CHAN_IN_CLOSE:
	if (pf)
	    ax25_chan_send_rsp(chan, X25_DM, pf);
	break;

    case AX25_CHAN_OPEN:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	if (chan->poll_pending) {
	    if (!is_cmd && pf) {
		ax25_chan_recalc_t1(chan, false);
		ax25_chan_stop_t1(chan);
	    } else if (is_cmd && pf) {
		ax25_chan_send_ack(chan, pf, false);
	    }
	    if (!ax25_chan_seq_in_range(chan, nr))
		return GE_PROTOERR;
	    chan->va = nr;
	    if (chan->va == chan->vs) {
		if (!is_cmd && pf)
		    ax25_chan_start_t3(chan);
	    } else {
		ax25_chan_rewind_seq(chan, nr, false);
	    }
	} else {
	    ax25_chan_check_response_needed(chan, pf, is_cmd);
	    if (!ax25_chan_seq_in_range(chan, nr))
		return GE_PROTOERR;
	    ax25_chan_recalc_t1(chan, false);
	    ax25_chan_stop_t1(chan);
	    ax25_chan_stop_t3(chan);
	    ax25_chan_rewind_seq(chan, nr, false);
	}
	break;

    default:
	assert(0);
    }

    return 0;
}

static int
ax25_chan_handle_srej(struct ax25_base *base, struct ax25_chan *chan,
		      uint8_t nr, uint8_t pf, bool is_cmd)
{
    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	break;

    case AX25_CHAN_IN_CLOSE:
	if (pf)
	    ax25_chan_send_rsp(chan, X25_DM, pf);
	break;

    case AX25_CHAN_OPEN:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	if (chan->poll_pending) {
	    if (!is_cmd) {
		ax25_chan_recalc_t1(chan, false);
		ax25_chan_stop_t1(chan);
	    }
	    if (!ax25_chan_seq_in_range(chan, nr))
		return GE_PROTOERR;
	    if (pf)
		chan->va = nr;
	    if (chan->va == chan->vs) {
		if (!is_cmd)
		    ax25_chan_start_t3(chan);
	    } else {
		ax25_chan_rewind_seq(chan, nr, true);
	    }
	} else {
	    ax25_chan_check_response_needed(chan, pf, is_cmd);
	    if (!ax25_chan_seq_in_range(chan, nr))
		return GE_PROTOERR;
	    ax25_chan_recalc_t1(chan, false);
	    ax25_chan_stop_t1(chan);
	    ax25_chan_stop_t3(chan);
	    ax25_chan_rewind_seq(chan, nr, true);
	}
	break;

    default:
	assert(0);
    }

    return 0;
}

static void
i_ax25_base_handle_child_err(struct ax25_base *base, int err)
{
    struct gensio_list to_deliver;
    struct gensio_link *l, *l2;

    if (base->child_err)
	return;
    base->child_err = err;

    gensio_set_read_callback_enable(base->child, false);
    gensio_set_write_callback_enable(base->child, false);

    gensio_list_init(&to_deliver);

    ax25_base_set_state(base, AX25_BASE_CHILD_IO_ERR);

    if (base->waiting_first_open) {
	struct ax25_chan *chan = i_ax25_base_promote_first_chan(base);
	/*
	 * Don't use set state here, chan lock isn't held, but it
	 * doesn't matter.
	 */
	chan->state = AX25_CHAN_IN_OPEN;
    }

    gensio_list_for_each(&base->chans, l) {
	struct ax25_chan *chan = gensio_container_of(l, struct ax25_chan, link);

	gensio_list_add_tail(&to_deliver, &chan->base_lock_err_link);
	chan->base_lock_count++;
    }
    ax25_base_unlock(base);

    gensio_list_for_each_safe(&to_deliver, l, l2) {
	struct ax25_chan *chan = gensio_container_of(l, struct ax25_chan,
						     base_lock_err_link);

	gensio_list_rm(&to_deliver, l);
	chan = ax25_chan_check_base_lock_state(chan, &base->chans, false);
	if (!chan)
	    continue;
	chan->err = err;
	ax25_chan_do_err_close(chan, true);
	ax25_chan_deref_and_unlock(chan);
    }
    ax25_base_lock(base);
    ax25_base_child_close(base);
}

static void
ax25_base_handle_child_err(struct ax25_base *base, int err)
{
    ax25_base_lock_and_ref(base);
    i_ax25_base_handle_child_err(base, err);
    ax25_base_deref_and_unlock(base);
}

static int
ax25_child_read(struct ax25_base *base, int ierr,
		unsigned char *buf, gensiods *ibuflen,
		const char *const *auxdata)
{
    uint16_t crc;
    unsigned int port = 0, i;
    gensiods pos = 0, buflen;
    struct gensio_ax25_addr iaddr, addr;
    struct ax25_chan *chan;
    int err = 0;
    uint8_t cmd = 0, pf = 0, nr = 0, ns = 0;
    bool is_cmd;

    if (ierr) {
	ax25_base_handle_child_err(base, ierr);
	return 0;
    }

    buflen = *ibuflen;

    for (i = 0; auxdata && auxdata[i]; i++) {
	if (strncmp(auxdata[i], "tnc:", 4) == 0)
	    port = strtoul(auxdata[i] + 4, NULL, 10);
    }
    /* We will always process the whole buffer, don't modify ibuflen. */

    if (base->conf.do_crc) {
	uint16_t msgcrc;

	if (buflen < 2)
	    return 0;
	msgcrc = (buf[buflen - 1] << 8) | buf[buflen - 2];
	crc = 0xffff;
	crc16_ccitt(buf, buflen - 2, &crc);
	crc ^= 0xffff;
	if (msgcrc != crc)
	    return 0;
	buflen -= 2;
    }

    if (buflen < 14)
	return 0;

    pos = 0;
    err = decode_ax25_addr(base->o, buf, &pos, buflen, port, &iaddr);
    if (err)
	return 0;
    ax25_construct_return_addr(&addr, &iaddr);
    buflen -= pos;

    if (buflen < 1)
	return 0;

    /* If it's an unumbered frame, it's always 1 byte. */
    if ((buf[pos] & 0x3) == 0x3) {
	/* Unnumbered frame. */
	pf = (buf[pos] >> 4) & 1;
	cmd = buf[pos++] & 0xef;
	buflen--;
    }

    /* UI frames are the only thing we let through without a matching dest */
    if (cmd == X25_UI) {
	ax25_chan_handle_ui(base, &iaddr, buf + pos, buflen, pf);
	return 0;
    }

    /* Ignore packets with subaddresses that have not yet been repeated. */
    for (i = 0; i < iaddr.nr_extra; i++) {
	if (!iaddr.extra[i].ch)
	    return 0;
    }

    if (!ax25_match_subaddr(&iaddr.dest, base->conf.my_addrs,
			    base->conf.num_my_addrs))
	return 0;

    /* In both old and new protocol version, dest.ch sets if it's a cmd. */
    is_cmd = iaddr.dest.ch;

    ax25_base_lock(base);
    chan = ax25_base_lookup_chan_by_addr(base, &addr.r);
    if (chan)
	chan->base_lock_count++;
    ax25_base_unlock(base);

    if (chan)
	chan = ax25_chan_check_base_lock_state(chan, &base->chans, true);

    if (!cmd) {
	/* Extract data from I and S frames. */

	if (chan)
	    ax25_chan_trace_msg(chan, RCVD, is_cmd, cmd, buf + pos, buflen);
	else
	    /* These are ignored if a connection isn't established. */
	    goto out_unlock;

	if (chan->extended && buflen < 2)
	    goto out_unlock;

	if (chan->extended) {
	    if ((buf[pos] & 0x1) == 0) {
		/* Information frame. */
		cmd = X25_I;
		ns = (buf[pos] >> 1) & 0x7f;
	    } else {
		/* Supervisory frame. */
		cmd = buf[pos];
	    }
	} else {
	    if ((buf[pos] & 0x1) == 0) {
		cmd = X25_I;
		ns = (buf[pos] >> 1) & 7;
	    } else {
		/* Supervisory frame. */
		cmd = buf[pos] & 0xf;
	    }
	}

	if (chan->extended) {
	    nr = (buf[pos + 1] >> 1) & 0x7f;
	    pf = buf[pos + 1] & 1;
	    pos += 2;
	    buflen -= 2;
	} else {
	    nr = (buf[pos] >> 5) & 7;
	    pf = (buf[pos] >> 4) & 1;
	    pos++;
	    buflen--;
	}
    } else {
	if (chan)
	    ax25_chan_trace_msg(chan, RCVD, is_cmd, cmd,
				buf + pos - 1, buflen + 1);
    }

    switch (cmd) {
    case X25_SABME:
	chan = ax25_chan_handle_sabm(base, chan, &addr, pf, is_cmd, true,
				     buf + pos, buflen);
	break;

    case X25_SABM:
	chan = ax25_chan_handle_sabm(base, chan, &addr, pf, is_cmd, false,
				     buf + pos, buflen);
	break;

    case X25_DISC:
	ax25_chan_handle_disc(base, chan, &addr, pf, is_cmd);
	break;

    case X25_DM:
	ax25_chan_handle_dm(base, chan, &addr, pf, is_cmd);
	break;

    case X25_UA:
	ax25_chan_handle_ua(base, chan, &addr, pf, is_cmd, buf + pos, buflen);
	break;

    case X25_FRMR:
	ax25_chan_handle_frmr(base, chan, &addr, pf, is_cmd, buf + pos, buflen);
	break;

    case X25_XID:
	ax25_chan_handle_xid(base, chan, &addr, pf, is_cmd, buf + pos, buflen);
	break;

    case X25_TEST:
	ax25_chan_handle_test(base, chan, &addr, pf, is_cmd, buf + pos, buflen);
	break;

    case X25_I:
	err = ax25_chan_handle_i(base, chan, &addr,
				 nr, ns, pf, is_cmd, buf + pos, buflen);
	break;

    case X25_RR:
	err = ax25_chan_handle_rr(base, chan, nr, pf, is_cmd);
	break;

    case X25_RNR:
	err = ax25_chan_handle_rnr(base, chan, nr, pf, is_cmd);
	break;

    case X25_REJ:
	err = ax25_chan_handle_rej(base, chan, nr, pf, is_cmd);
	break;

    case X25_SREJ:
	err = ax25_chan_handle_srej(base, chan, nr, pf, is_cmd);
	break;

    default:
	break;
    }

    if (err) {
	chan->err = err;
	ax25_chan_do_err_close(chan, true);
	ax25_chan_stop_t3(chan);
	ax25_chan_stop_t1(chan);
    }

 out_unlock:
    if (chan)
	ax25_chan_deref_and_unlock(chan);

    return 0;
}

static void
crc16_sg(const struct gensio_sg *sg, gensiods sglen, unsigned char *outcrc)
{
    uint16_t crc = 0xffff;
    gensiods i;

    for (i = 0; i < sglen; i++)
	crc16_ccitt(sg[i].buf, sg[i].buflen, &crc);
    crc ^= 0xffff;
    outcrc[0] = crc & 0xff;
    outcrc[1] = (crc >> 8) & 0xff;
}

static bool
ax25_chan_in_writable_state(struct ax25_chan *chan)
{
    switch (chan->state) {
    case AX25_CHAN_IN_OPEN:
    case AX25_CHAN_OPEN:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
    case AX25_CHAN_IN_CLOSE:
    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
	return true;

    default:
	return false;
    }
}

static int
ax25_child_write_ready(struct ax25_base *base)
{
    struct gensio_link *l;
    struct ax25_chan *chan = NULL;
    struct ax25_data *d;
    struct ax25_chan_cmdrsp *ccr;
    struct ax25_base_cmdrsp *bcr;
    struct ax25_ui_data *ui;
    unsigned char crv[3], crc[2], xid[AX25_XID_SIZE];
    struct gensio_sg sg[4];
    gensiods sglen, len, sendcnt;
    int rv;

    ax25_base_lock_and_ref(base);
    gensio_set_write_callback_enable(base->child, false);
    while (!gensio_list_empty(&base->send_list)) {
	l = gensio_list_first(&base->send_list);
	gensio_list_rm(&base->send_list, l);
	chan = gensio_container_of(l, struct ax25_chan, sendlink);
	chan->base_lock_count++;
	ax25_base_unlock(base);

	chan = ax25_chan_check_base_lock_state(chan, &base->chans, false);
	if (!chan)
	    goto skip;

	sglen = 0;
	len = 0;
	if (chan->cmdrsp_len > 0) {
	    ccr = &(chan->cmdrsp[chan->cmdrsp_pos]);
	    /* Set command/response. */
	    if (ccr->is_cmd) {
		chan->encoded_addr[6] |= 0x80;
		chan->encoded_addr[13] &= ~0x80;
	    } else {
		chan->encoded_addr[6] &= ~0x80;
		chan->encoded_addr[13] |= 0x80;
	    }
	    sg[0].buf = chan->encoded_addr;
	    sg[0].buflen = chan->encoded_addr_len;
	    len = sg[0].buflen;
	    sg[1].buf = crv;
	    if ((ccr->cr & 0x3) == 0x1) {
		uint8_t cmd = ccr->cr;

		/*
		 * Wait until the last possible moment to decide to
		 * send an RNR.
		 */
		if (ccr->cr == X25_RR && chan->own_rcv_bsy)
		    cmd = X25_RNR;
		/*
		 * If sending a REJ, there's no point if the rej is
		 * already cleared.
		 */
		else if (ccr->cr == X25_REJ && !chan->in_rej)
		    goto skip_cmdrsp;

		/* Supervisory message, put ack value into it. */
		if (chan->extended) {
		    crv[0] = cmd;
		    crv[1] = (chan->vr << 1) | ccr->pf;
		    sg[1].buflen = 2;
		} else {
		    crv[0] = (chan->vr << 5) | (ccr->pf << 4) | cmd;
		    sg[1].buflen = 1;
		}
	    } else {
		crv[0] = (ccr->pf << 4) | ccr->cr;
		sg[1].buflen = 1;
	    }
	    ax25_chan_trace_msg(chan, SENT, ccr->is_cmd, ccr->cr,
				crv, sg[1].buflen);
	    len += sg[1].buflen;
	    sglen = 2;
	    if (ccr->cr == X25_XID) {
		sg[sglen].buf = xid;
		sg[sglen].buflen = sizeof(xid);
		ax25_chan_format_xid(chan, xid);
		sglen++;
		len += sizeof(xid);
	    } else if (ccr->extra_data_size) {
		sg[sglen].buf = ccr->extra_data;
		sg[sglen].buflen = ccr->extra_data_size;
		sglen++;
		len += ccr->extra_data_size;
	    }
	    if (base->conf.do_crc) {
		crc16_sg(sg, sglen, crc);
		sg[sglen].buf = crc;
		sg[sglen].buflen = 2;
		sglen++;
		len += 2;
	    }
	    rv = gensio_write_sg(base->child, &sendcnt, sg, sglen, NULL);
	    if (rv)
		goto out_err_chan;
	    if (sendcnt == 0)
		goto out_reenable_chan;
	    if (sendcnt != len) {
		rv = GE_IOERR;
		goto out_err_chan;
	    }
	skip_cmdrsp:
	    chan->cmdrsp_pos = (chan->cmdrsp_pos + 1) % AX25_CHAN_MAX_CMDRSP;
	    chan->cmdrsp_len--;
	    if (chan->state == AX25_CHAN_REM_DISC ||
			chan->state == AX25_CHAN_REM_CLOSE) {
		if (chan->state == AX25_CHAN_REM_DISC)
		    ax25_chan_do_err_close(chan, true);
		else if (chan->state == AX25_CHAN_REM_CLOSE)
		    ax25_chan_do_close(chan, true);
	    }
	} else if (!chan->peer_rcv_bsy && chan->send_len > 0) {
	    unsigned int pos = sub_seq(chan->write_pos, chan->send_len,
				       chan->conf.writewindow);
	    unsigned int p = 0;

	    d = &(chan->write_data[pos]);
	    if (!d->present) {
		chan->send_len--;
		goto skip;
	    }
	    /* Set command. */
	    chan->encoded_addr[6] |= 0x80;
	    chan->encoded_addr[13] &= ~0x80;
	    sg[0].buf = chan->encoded_addr;
	    sg[0].buflen = chan->encoded_addr_len;
	    len = sg[0].buflen;
	    sg[1].buf = crv;

	    /*
	     * If our transmit window is closing with this packet, set the
	     * p bit to get an immediate response.
	     */
	    if (sub_seq(chan->vs, chan->va, chan->modulo) >= chan->writewindow)
		p = 1;

	    if (chan->extended) {
		crv[0] = d->seq << 1;
		crv[1] = chan->vr << 1 | p;
		crv[2] = d->pid;
		sg[1].buflen = 3;
		len += 3;
	    } else {
		crv[0] = (chan->vr << 5) | (p << 4) | (d->seq << 1);
		crv[1] = d->pid;
		sg[1].buflen = 2;
		len += 2;
	    }
	    chan->ack_pending = 0; /* Sent an ack. */
	    ax25_chan_stop_t2(chan);
	    ax25_chan_trace_msg(chan, SENT, true, 0, crv, sg[1].buflen);
	    sg[2].buf = d->data;
	    sg[2].buflen = d->len;
	    len += d->len;
	    sglen = 3;
	    if (base->conf.do_crc) {
		crc16_sg(sg, sglen, crc);
		sg[3].buf = crc;
		sg[3].buflen = 2;
		sglen++;
		len += 2;
	    }
	    if (chan->conf.drop_pos && chan->curr_drop == chan->conf.drop_pos) {
		rv = 0;
		chan->curr_drop = 0;
		sendcnt = len;
	    } else {
		rv = gensio_write_sg(base->child, &sendcnt, sg, sglen, NULL);
		chan->curr_drop++;
	    }
	    if (rv)
		goto out_err_chan;
	    if (sendcnt == 0)
		goto out_reenable_chan;
	    d->present = false;
	    if (sendcnt != len) {
		rv = GE_IOERR;
		goto out_err_chan;
	    }
	    chan->send_len--;
	    if (!chan->t1) {
		ax25_chan_stop_t3(chan);
		ax25_chan_start_t1(chan);
	    }
	    if (chan->state == AX25_CHAN_CLOSE_WAIT_DRAIN &&
			chan->send_len == 0) {
		/* We abuse timer recovery to get a quick response. */
		chan->retry_count = 1;
		chan->poll_pending = true;
		ax25_chan_transmit_enquiry(chan);
	    }
	} else if (!gensio_list_empty(&chan->uis)) {
	    unsigned char *buf;

	    l = gensio_list_first(&chan->uis);
	    ui = gensio_container_of(l, struct ax25_ui_data, link);
	    buf = ((unsigned char *) ui) + sizeof(*ui);
	    rv = gensio_write(base->child, &sendcnt, buf, ui->len, NULL);
	    if (rv)
		goto out_err_chan;
	    if (sendcnt == 0)
		goto out_reenable_chan;
	    if (sendcnt != ui->len) {
		rv = GE_IOERR;
		goto out_err_chan;
	    }
	    gensio_list_rm(&chan->uis, l);
	    chan->o->free(chan->o, ui);
	}
    skip:
	ax25_base_lock(base);
	if (chan) {
	    if (!gensio_list_link_inlist(&chan->sendlink) &&
			((!chan->peer_rcv_bsy && chan->send_len > 0) ||
			 chan->cmdrsp_len > 0 || !gensio_list_empty(&chan->uis)))
		gensio_list_add_tail(&base->send_list, &chan->sendlink);
	    ax25_chan_deref_and_unlockb(chan);
	    chan = NULL;
	}
    }

    while (base->cmdrsp_len > 0) {
	bcr = &(base->cmdrsp[base->cmdrsp_pos]);
	sg[0].buf = bcr->addr;
	sg[0].buflen = bcr->addrlen;
	len = sg[0].buflen;
	sg[1].buf = crv;
	crv[0] = bcr->cr;
	sg[1].buflen = 1;
	len += 1;
	sglen = 2;
	if (bcr->extra_data_size) {
	    sg[sglen].buf = bcr->extra_data;
	    sg[sglen].buflen = bcr->extra_data_size;
	    sglen++;
	    len += bcr->extra_data_size;
	}
	if (base->conf.do_crc) {
	    crc16_sg(sg, sglen, crc);
	    sg[sglen].buf = crc;
	    sg[sglen].buflen = 2;
	    sglen++;
	    len += 2;
	}
	rv = gensio_write_sg(base->child, &sendcnt, sg, sglen, NULL);
	if (rv)
	    goto out_err_base;
	if (sendcnt == 0)
	    goto out_reenable_base;
	if (sendcnt != len) {
	    rv = GE_IOERR;
	    goto out_err_base;
	}
	base->cmdrsp_pos = add_seq(base->cmdrsp_pos, 1, AX25_BASE_MAX_CMDRSP);
	base->cmdrsp_len--;
    }
    if (base->state == AX25_BASE_CLOSE_WAIT_DRAIN)
	ax25_base_child_close(base);

    ax25_base_deref_and_unlock(base);
    return 0;
 out_reenable_chan:
    /* A write didn't complete, Reenable so we can know when we can finish. */
    ax25_base_lock(base);
    if (!gensio_list_link_inlist(&chan->sendlink))
	gensio_list_add_head(&base->send_list, &chan->sendlink);
    if (ax25_chan_in_writable_state(chan))
	gensio_set_write_callback_enable(base->child, true);
    ax25_chan_deref_and_unlockb(chan);
    ax25_base_deref_and_unlock(base);
    return 0;
 out_err_chan:
    ax25_base_lock(base);
    ax25_chan_deref_and_unlockb(chan);
    i_ax25_base_handle_child_err(base, rv);
    ax25_base_deref_and_unlock(base);
    return 0;
 out_reenable_base:
    /* A write didn't complete, Reenable so we can know when we can finish. */
    if (base->state == AX25_BASE_OPEN)
	gensio_set_write_callback_enable(base->child, true);
    ax25_base_deref_and_unlock(base);
    return 0;
 out_err_base:
    i_ax25_base_handle_child_err(base, rv);
    ax25_base_deref_and_unlock(base);
    return 0;
}

static int
ax25_child_cb(struct gensio *io, void *user_data, int event,
	      int err, unsigned char *buf, gensiods *buflen,
	      const char *const *auxdata)
{
    struct ax25_base *base = user_data;
    int rv;

    switch (event) {
    case GENSIO_EVENT_READ:
	return ax25_child_read(base, err, buf, buflen, auxdata);

    case GENSIO_EVENT_WRITE_READY:
	return ax25_child_write_ready(base);

    case GENSIO_EVENT_NEW_CHANNEL:
	return GE_NOTSUP;

    default:
	rv = ax25_firstchan_event(base, event, err, buf, buflen, auxdata);
	return rv;
    }
}

static gensiods
ax25_add_crc(unsigned char *buf, gensiods len)
{
    uint16_t crc = 0xffff;

    crc16_ccitt(buf, len, &crc);
    crc ^= 0xffff;
    buf[len++] = crc & 0xff;
    buf[len++] = (crc >> 8) & 0xff;
    return len;
}

static int
ax25_chan_send_ui(struct ax25_chan *chan, struct gensio_addr *addr,
		  gensiods *rcount, uint8_t pid, gensiods datalen,
		  const struct gensio_sg *sg, gensiods sglen)
{
    struct ax25_ui_data *ui;
    unsigned char *buf;
    gensiods len, pos;
    unsigned int i;

    /* + 2 for the UI and PID */
    len = sizeof(*ui) + datalen + ax25_addr_encode_len(addr) + 2;
    if (chan->base->conf.do_crc)
	len += 2;
    ui = chan->o->zalloc(chan->o, len);
    if (!ui)
	return 0;

    buf = ((unsigned char *) ui) + sizeof(*ui);

    pos = ax25_addr_encode(buf, addr);
    buf[pos++] = 0x03; /* UI with P/F clear */
    buf[pos++] = pid; /* UI with P/F clear */
    for (i = 0; i < sglen; i++) {
	memcpy(buf + pos, sg[i].buf, sg[i].buflen);
	pos += sg[i].buflen;
    }
    /* Set the C/R bits to response. */
    buf[6] &= ~0x80;
    buf[13] |= 0x80;

    if (chan->base->conf.do_crc)
	pos = ax25_add_crc(buf, pos);
    ui->len = pos;

    ax25_base_lock(chan->base);
    gensio_list_add_tail(&chan->uis, &ui->link);
    i_ax25_chan_schedule_write(chan);
    ax25_base_unlock(chan->base);

    *rcount = datalen;
    return 0;
}

static int
ax25_chan_write(struct ax25_chan *chan, gensiods *rcount,
		const struct gensio_sg *sg, gensiods sglen,
		const char *const *auxdata)
{
    int rv = 0;
    struct ax25_data *d;
    gensiods len, left, pos;
    unsigned int i;
    uint8_t pid = 0xf0;

    for (len = 0, i = 0; i < sglen; i++)
	len += sg[i].buflen;

    for (i = 0; auxdata && auxdata[i]; i++) {
	if (strncmp(auxdata[i], "pid:", 4) == 0) {
	    pid = strtoul(auxdata[i] + 4, NULL, 0);
	    break;
	}
    }

    if (gensio_str_in_auxdata(auxdata, "oob")) {
	const char *addrstr = NULL;
	struct gensio_addr *addr;

	if (len > chan->conf.max_write_size)
	    len = chan->conf.max_write_size;
	ax25_chan_lock(chan);
	if (chan->state != AX25_CHAN_OPEN && chan->state != AX25_CHAN_NOCON) {
	    rv = GE_NOTREADY;
	    goto out_unlock;
	}
	for (i = 0; auxdata && auxdata[i]; i++) {
	    if (strncmp(auxdata[i], "addr:", 5) == 0) {
		addrstr = auxdata[i] + 5;
		break;
	    }
	}
	if (!addrstr) {
	    rv = GE_INVAL;
	    goto out_unlock;
	}
	rv = gensio_ax25_str_to_addr(chan->o, addrstr, &addr);
	if (rv) {
	    rv = 0;
	    goto out_unlock;
	}
	rv = ax25_chan_send_ui(chan, addr, rcount, pid, len, sg, sglen);
	gensio_addr_free(addr);
	goto out_unlock;
    }

    if (len > chan->max_write_size)
	len = chan->max_write_size;

    ax25_chan_lock(chan);
    if (chan->state != AX25_CHAN_OPEN) {
	if (chan->err)
	    rv = chan->err;
	else
	    rv = GE_NOTREADY;
	goto out_unlock;
    }

    if (chan->write_len >= chan->writewindow) {
	*rcount = 0;
	goto out_unlock;
    }

    d = &(chan->write_data[chan->write_pos]);
    d->pid = pid;
    for (left = len, pos = 0, i = 0; i < sglen; i++) {
	if (sg[i].buflen > left) {
	    memcpy(((char *) d->data) + pos, sg[i].buf, left);
	} else {
	    memcpy(((char *) d->data) + pos, sg[i].buf, sg[i].buflen);
	}
	left -= sg[i].buflen;
	pos += sg[i].buflen;
    }

    *rcount = len;
    d->len = len;
    d->seq = chan->vs;
    d->present = true;
    chan->vs = add_seq(chan->vs, 1, chan->modulo);
    chan->write_pos = add_seq(chan->write_pos, 1, chan->conf.writewindow);
    chan->write_len++;
    chan->send_len++;
    assert(chan->send_len <= chan->conf.writewindow);

    if (!chan->peer_rcv_bsy)
	i_ax25_chan_schedule_write(chan);

 out_unlock:
    ax25_chan_unlock(chan);

    return rv;
}

/* Must be called with the channel and base lock held. */
static int
i_ax25_chan_open(struct ax25_chan *chan,
		 gensio_done_err open_done, void *open_data)
{
    struct ax25_base *base = chan->base;
    int err = 0;

    if (chan->state != AX25_CHAN_CLOSED)
	return GE_INUSE;

    ax25_base_lock(base);
    if (chan->conf.addr && ax25_base_lookup_chan_by_addr(base,
							 chan->conf.addr)) {
	ax25_base_unlock(base);
	/* There's already a non-closed connection with this address. */
	return GE_ADDRINUSE;
    }

    chan->writewindow = chan->conf.writewindow;
    chan->readwindow = chan->conf.readwindow;
    chan->max_write_size = chan->conf.max_write_size;
    chan->max_retries = chan->conf.max_retries;

    chan->err = 0;

    switch (base->state) {
    case AX25_BASE_CHILD_IO_ERR:
    case AX25_BASE_IN_CHILD_CLOSE:
	ax25_chan_set_stateb(chan, AX25_CHAN_WAITING_OPEN);
	gensio_list_rm(&base->chans_closed, &chan->link);
	gensio_list_add_tail(&base->chans_waiting_open, &chan->link);
	break;

    case AX25_BASE_CLOSED:
	err = ax25_base_start_open(base);
	if (err)
	    break;
	/* fallthrough */
    case AX25_BASE_IN_CHILD_OPEN:
	ax25_chan_set_stateb(chan, AX25_CHAN_WAITING_OPEN);
	gensio_list_rm(&base->chans_closed, &chan->link);
	gensio_list_add_tail(&base->chans_waiting_open, &chan->link);
	break;

    case AX25_BASE_OPEN:
	gensio_list_rm(&base->chans_closed, &chan->link);
	gensio_list_add_tail(&base->chans, &chan->link);
	ax25_chan_prestart_connect(chan);
	ax25_base_unlock(base);
	ax25_chan_start_connect(chan);
	ax25_base_lock(base);
	break;

    default:
	assert(0);
    }
    ax25_base_unlock(base);

    if (!err) {
	chan->open_done = open_done;
	chan->open_data = open_data;
    }

    return err;
}

static int
ax25_chan_open(struct ax25_chan *chan,
	       gensio_done_err open_done, void *open_data)
{
    int err;

    if (!open_done)
	return GE_INVAL;

    ax25_chan_lock(chan);
    err = i_ax25_chan_open(chan, open_done, open_data);
    ax25_chan_unlock(chan);

    return err;
}

static int
ax25_chan_open_nochild(struct ax25_chan *chan,
		       gensio_done_err open_done, void *open_data)
{
    struct ax25_base *base = chan->base;
    int err;

    if (!open_done)
	return GE_INVAL;

    ax25_chan_lock(chan);
    if (base->state != AX25_BASE_CLOSED) {
	err = GE_NOTREADY;
    } else {
	base->child_err = 0;
	ax25_base_set_state(base, AX25_BASE_OPEN);
	ax25_base_ref(chan->base);
	err = i_ax25_chan_open(chan, open_done, open_data);
	if (err)
	    ax25_base_set_state(base, AX25_BASE_CLOSED);
	else
	    gensio_set_read_callback_enable(base->child, true);
    }
    ax25_chan_unlock(chan);

    return err;
}

/* Must be called with the channel lock held. */
static int
i_ax25_chan_close(struct ax25_chan *chan,
		  gensio_done close_done, void *close_data)
{
    struct ax25_base *base = chan->base;
    int err = 0;

    switch (chan->state) {
    case AX25_CHAN_CLOSED:
    case AX25_CHAN_IN_CLOSE:
    case AX25_CHAN_REPORT_OPEN_CLOSE:
    case AX25_CHAN_REPORT_CLOSE:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
    case AX25_CHAN_REM_CLOSE:
	err = GE_NOTREADY;
	break;

    case AX25_CHAN_REM_DISC:
	ax25_chan_set_state(chan, AX25_CHAN_REM_CLOSE);
	break;

    case AX25_CHAN_WAITING_OPEN:
	ax25_chan_set_state(chan, AX25_CHAN_REPORT_CLOSE);
	ax25_chan_move_to_closed(chan, &base->chans_waiting_open);
	ax25_chan_sched_deferred_op(chan);
	break;

    case AX25_CHAN_NOCON_IN_OPEN:
    case AX25_CHAN_NOCON:
	ax25_chan_move_to_closed(chan, &base->chans);
	/* Fallthrough */
    case AX25_CHAN_IO_ERR:
	ax25_chan_set_state(chan, AX25_CHAN_REPORT_CLOSE);
	ax25_chan_sched_deferred_op(chan);
	break;

    case AX25_CHAN_IN_OPEN:
    case AX25_CHAN_OPEN:
	if (chan->in_newchannel == 1) {
	    ax25_chan_set_state(chan, AX25_CHAN_CLOSED);
	    ax25_chan_move_to_closed(chan, &base->chans);
	    chan->in_newchannel = 2;
	} else if (chan->in_newchannel == 0) {
	    if (chan->state == AX25_CHAN_IN_OPEN) {
		chan->retry_count = 0;
		chan->err = GE_LOCALCLOSED;
		ax25_chan_send_cmd(chan, X25_DM, 1);
		ax25_chan_set_state(chan, AX25_CHAN_REPORT_OPEN_CLOSE);
		ax25_chan_move_to_closed(chan, &base->chans);
		ax25_chan_sched_deferred_op(chan);
	    } else if (chan->write_len > 0) {
		/* We abuse timer recovery to get a quick response. */
		chan->retry_count = 1;
		chan->poll_pending = true;
		ax25_chan_transmit_enquiry(chan);
		ax25_chan_set_state(chan, AX25_CHAN_CLOSE_WAIT_DRAIN);
	    } else {
		chan->retry_count = 0;
		if (chan->ack_pending)
		    /* Make sure to ack anything pending. */
		    ax25_chan_send_ack(chan, 0, 0);
		ax25_chan_send_cmd(chan, X25_DISC, 1);
		ax25_chan_set_state(chan, AX25_CHAN_IN_CLOSE);
	    }
	    ax25_chan_start_t1(chan);
	    ax25_chan_stop_t3(chan);
	}
	break;

    default:
	assert(0);
    }

    if (!err) {
	ax25_chan_ref(chan);
	chan->close_done = close_done;
	chan->close_data = close_data;
    }

    return err;
}

static int
ax25_chan_close(struct ax25_chan *chan,
		gensio_done close_done, void *close_data)
{
    int err;

    ax25_chan_lock(chan);
    err = i_ax25_chan_close(chan, close_done, close_data);
    ax25_chan_unlock(chan);

    return err;
}

static void
ax25_chan_free(struct ax25_chan *chan)
{
    ax25_chan_lock(chan);
    switch (chan->state) {
    case AX25_CHAN_REPORT_CLOSE:
    case AX25_CHAN_REPORT_OPEN_CLOSE:
	/* Undo the close call and just free it. */
	ax25_chan_deref(chan);
	chan->open_done = NULL;
	chan->close_done = NULL;
	break;

    case AX25_CHAN_IO_ERR:
    case AX25_CHAN_CLOSED:
	/* We can free immediately. */
	break;

    case AX25_CHAN_IN_OPEN:
    case AX25_CHAN_OPEN:
	/* Need to close before we can free */
	i_ax25_chan_close(chan, NULL, NULL);
	break;

    case AX25_CHAN_IN_CLOSE:
    case AX25_CHAN_REM_DISC:
    case AX25_CHAN_REM_CLOSE:
    case AX25_CHAN_CLOSE_WAIT_DRAIN:
	/* In the close process, lose a ref so it will free when done. */
	/* Don't call the done */
	chan->close_done = NULL;
	break;

    default:
	assert(0);
    }
    /* Lose the initial ref so it will be freed when done. */
    ax25_chan_deref_and_unlock(chan);
}

static void
ax25_chan_set_read_callback_enable(struct ax25_chan *chan, bool enabled)
{
    ax25_chan_lock(chan);
    if (chan->read_enabled != enabled) {
	chan->read_enabled = enabled;
	if (enabled && chan_can_read(chan))
	    ax25_chan_sched_deferred_op(chan);
    }
    ax25_chan_unlock(chan);
}

static void
ax25_chan_set_write_callback_enable(struct ax25_chan *chan, bool enabled)
{
    ax25_chan_lock(chan);
    if (chan->xmit_enabled != enabled) {
	chan->xmit_enabled = enabled;
	if (enabled && chan_can_write(chan))
	    ax25_chan_sched_deferred_op(chan);
    }
    ax25_chan_unlock(chan);
}

static int
ax25_alloc_channel(struct ax25_chan *dummy,
		   struct gensio_func_alloc_channel_data *ocdata)
{
    struct ax25_base *base = dummy->base;
    struct ax25_chan *chan;
    int rv;

    rv = ax25_chan_alloc(base, ocdata->args, ocdata->cb, ocdata->user_data,
			 AX25_CHAN_CLOSED, NULL, false, &chan);
    if (rv)
	return rv;

    ocdata->new_io = chan->io;
    return 0;
}

static int
ax25_chan_control(struct ax25_chan *chan, bool get, int option,
		  char *data, gensiods *datalen)
{
    struct ax25_base *base = chan->base;
    int rv = 0;
    gensiods pos;
    unsigned int i;

    switch (option) {
    case GENSIO_CONTROL_ENABLE_OOB:
	if (get)
	    *datalen = snprintf(data, *datalen, "%u", chan->report_ui);
	else
	    chan->report_ui = strtoul(data, NULL, 0);
	break;

    case GENSIO_CONTROL_MAX_WRITE_PACKET:
	if (!get)
	    return GE_NOTSUP;
	*datalen = snprintf(data, *datalen, "%u", chan->max_write_size);
	break;

    case GENSIO_CONTROL_LADDR:
	if (!get)
	    return GE_NOTSUP;
	i = strtoul(data, NULL, 0);
	if (i >= base->conf.num_my_addrs)
	    return GE_NOTFOUND;
	pos = 0;
	rv = ax25_subaddr_to_str(&(base->conf.my_addrs[i]),
				 data, &pos, *datalen, false);
	if (!rv)
	    *datalen = pos;
	break;

    case GENSIO_CONTROL_RADDR:
	if (!get)
	    return GE_NOTSUP;
	i = strtoul(data, NULL, 0);
	if (i > 0 || !chan->conf.addr)
	    return GE_NOTFOUND;
	pos = 0;
	rv = gensio_addr_to_str(chan->conf.addr, data, &pos, *datalen);
	if (!rv)
	    *datalen = pos;
	break;

    case GENSIO_CONTROL_RADDR_BIN:
	if (!get)
	    return GE_NOTSUP;
	i = strtoul(data, NULL, 0);
	if (i > 0 || !chan->conf.addr)
	    return GE_NOTFOUND;
	gensio_addr_getaddr(chan->conf.addr, data, datalen);
	break;

    default:
	rv = GE_NOTSUP;
	break;
    }

    return rv;
}

static int
ax25_chan_func(struct gensio *io, int func, gensiods *count,
	       const void *cbuf, gensiods buflen, void *buf,
	       const char *const *auxdata)
{
    struct ax25_chan *chan = gensio_get_gensio_data(io);
    struct ax25_base *base = chan->base;

    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	return ax25_chan_write(chan, count, cbuf, buflen, auxdata);

    case GENSIO_FUNC_OPEN:
	return ax25_chan_open(chan, (void *) cbuf, buf);

    case GENSIO_FUNC_OPEN_NOCHILD:
	return ax25_chan_open_nochild(chan, (void *) cbuf, buf);

    case GENSIO_FUNC_ALLOC_CHANNEL:
	return ax25_alloc_channel(chan, buf);

    case GENSIO_FUNC_CLOSE:
	return ax25_chan_close(chan, (void *) cbuf, buf);

    case GENSIO_FUNC_FREE:
	ax25_chan_free(chan);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	ax25_chan_set_read_callback_enable(chan, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	ax25_chan_set_write_callback_enable(chan, buflen);
	return 0;

    case GENSIO_FUNC_CONTROL:
	return ax25_chan_control(chan, *((bool *) cbuf), buflen, buf, count);

    case GENSIO_FUNC_DISABLE:
	if (chan->state != AX25_CHAN_CLOSED) {
	    ax25_chan_reset_data(chan);
	    ax25_chan_set_state(chan, AX25_CHAN_CLOSED);
	    if (base->child)
		gensio_disable(base->child);
	}
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
ax25_scan_laddrs(struct gensio_os_funcs *o, const char *str,
		 struct gensio_ax25_subaddr **raddrs, unsigned int *rnum_addrs)
{
    char addrstr[8], *s2;
    unsigned int count = 1, i, len;
    int rv;
    struct gensio_ax25_subaddr *addrs;

    s2 = strchr(str, ';');
    while (s2) {
	s2 = strchr(s2 + 1, ';');
	count++;
    }

    addrs = o->zalloc(o, sizeof(*addrs) * count);
    if (!addrs)
	return GE_NOMEM;
    for (i = 0; i < count; i++) {
	s2 = strchr(str, ';');
	if (s2)
	    len = s2 - str;
	else
	    len = strlen(str);
	memcpy(addrstr, str, len);
	rv = ax25_str_to_subaddr(str, &(addrs[i]), false);
	if (rv) {
	    o->free(o, addrs);
	    return rv;
	}
	if (s2)
	    str = s2 + 1;
    }
    if (*raddrs)
	o->free(o, *raddrs);
    *raddrs = addrs;
    *rnum_addrs = count;
    return 0;
}

static int
ax25_readconf(struct gensio_os_funcs *o, bool firstchan, bool noaddr,
	      struct ax25_conf_data *conf, const char *const args[])
{
    int rv = 0;
    unsigned int i;
    const char *str;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &conf->max_read_size) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "writebuf", &conf->max_write_size) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "readwindow", &conf->readwindow) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "writewindow", &conf->writewindow) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "extended", &conf->extended) > 0) {
	    if (conf->extended > 2)
		goto out_err;
	    continue;
	}
	if (!noaddr &&!conf->addr &&
		gensio_check_keyvalue(args[i], "addr", &str)) {
	    rv = gensio_ax25_str_to_addr(o, str, &conf->addr);
	    if (rv)
		goto out_err;
	    continue;
	}
	if (firstchan & gensio_check_keyvalue(args[i], "laddr", &str)) {
	    rv = ax25_scan_laddrs(o, str, &conf->my_addrs, &conf->num_my_addrs);
	    if (rv)
		goto out_err;
	    continue;
	}
	if (firstchan & gensio_check_keybool(args[i], "crc", &conf->do_crc))
	    continue;
	if (gensio_check_keybool(args[i], "ign_emb_ua",
				 &conf->ignore_embedded_ua))
	    continue;
	if (gensio_check_keyuint(args[i], "srt", &conf->srtv) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "t2", &conf->t2v) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "t3", &conf->t3v) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "retries", &conf->max_retries) > 0)
	    continue;
	/* Undocumented, used for testing. */
	if (gensio_check_keyuint(args[i], "drop", &conf->drop_pos) > 0)
	    continue;
	rv = GE_INVAL;
	goto out_err;
    }

    if (conf->srtv == 0 || conf->t2v == 0 || conf->t3v == 0 ||
		conf->readwindow == 0 || conf->writewindow == 0) {
	rv = GE_INVAL;
	goto out_err;
    }
    if (conf->extended) {
	if (conf->writewindow > 127 || conf->readwindow > 127)
	    rv = GE_INVAL;
    } else {
	if (conf->writewindow > 7 || conf->readwindow > 7)
	    rv = GE_INVAL;
    }

 out_err:
    return rv;
}

static void
ax25_defconf(struct ax25_conf_data *conf)
{
    memset(conf, 0, sizeof(*conf));
    conf->max_read_size = 256;
    conf->max_write_size = 256;
    conf->readwindow = 7;
    conf->writewindow = 7;
    conf->extended = 1;
    conf->ignore_embedded_ua = true;
    conf->srtv = 4000; /* 4 seconds (t1 is 8 seconds). */
    conf->t2v = 2000; /* 2 seconds. */
    conf->t3v = 300000; /* 300 seconds. */
    conf->max_retries = 10;
    conf->drop_pos = 0;
}

static int
ax25_chan_alloc(struct ax25_base *base, const char *const args[],
		gensio_event cb, void *user_data,
		enum ax25_chan_state start_state,
		struct gensio_addr *addr, bool firstchan,
		struct ax25_chan **rchan)
{
    struct gensio_os_funcs *o = base->o;
    struct ax25_chan *chan = NULL;
    unsigned int i;
    struct ax25_conf_data conf = base->conf;
    int rv;

    conf.my_addrs = NULL;
    conf.num_my_addrs = 0;

    if (addr) {
	conf.addr = gensio_addr_dup(addr);
	if (!conf.addr)
	    return GE_NOMEM;
    }

    rv = ax25_readconf(base->o, firstchan, false, &conf, args);
    if (rv)
	goto out_err;

    chan = o->zalloc(o, sizeof(*chan));
    if (!chan)
	goto out_nomem;

    chan->o = o;
    if (conf.addr) {
	chan->encoded_addr_len = ax25_addr_encode(chan->encoded_addr,
						  conf.addr);
	if (conf.num_my_addrs == 0 && firstchan) {
	    /* Pull the local address from addr. */
	    struct gensio_ax25_addr *aaddr = addr_to_ax25(conf.addr);

	    conf.my_addrs = o->zalloc(o, sizeof(*conf.my_addrs));
	    if (!conf.my_addrs)
		goto out_nomem;
	    conf.my_addrs[0] = aaddr->src;
	    conf.num_my_addrs = 1;
	}
    }
    chan->conf = conf;
    conf.addr = NULL; /* So we won't free it later. */
    conf.my_addrs = NULL;
    conf.num_my_addrs = 0;
    chan->refcount = 1;
    gensio_list_init(&chan->uis);

    /* After this point we can use ax25_chan_finish_free to free it. */

    chan->read_data = o->zalloc(o, sizeof(struct ax25_data) * conf.readwindow);
    if (!chan->read_data)
	goto out_nomem;
    for (i = 0; i < conf.readwindow; i++) {
	chan->read_data[i].data = o->zalloc(o, chan->conf.max_read_size);
	if (!chan->read_data[i].data)
	    goto out_nomem;
    }

    chan->write_data = o->zalloc(o, (sizeof(struct ax25_data) *
				     chan->conf.writewindow));
    if (!chan->write_data)
	goto out_nomem;
    for (i = 0; i < chan->conf.writewindow; i++) {
	chan->write_data[i].data = o->zalloc(o, chan->conf.max_write_size);
	if (!chan->write_data[i].data)
	    goto out_nomem;
    }

    chan->lock = o->alloc_lock(o);
    if (!chan->lock)
	goto out_nomem;

    chan->timer = o->alloc_timer(o, ax25_chan_timeout, chan);
    if (!chan->timer)
	goto out_nomem;

    chan->deferred_op_runner = o->alloc_runner(o, ax25_chan_deferred_op, chan);
    if (!chan->deferred_op_runner)
	goto out_nomem;

    chan->io = gensio_data_alloc(o, cb, user_data, ax25_chan_func,
				 base->child, "ax25", chan);
    if (!chan->io)
	goto out_nomem;
    gensio_set_is_client(chan->io, true); /* FIXME */

    gensio_set_is_packet(chan->io, true);
    gensio_set_is_reliable(chan->io, true);
    if (gensio_is_authenticated(base->child))
	gensio_set_is_authenticated(chan->io, true);
    if (gensio_is_encrypted(base->child))
	gensio_set_is_encrypted(chan->io, true);

    ax25_base_lock(base);
    chan->base = base;
    ax25_base_ref(base);
    chan->state = start_state;
    if (start_state == AX25_CHAN_CLOSED)
	/* Should never allocate with report close or io err state. */
	gensio_list_add_tail(&base->chans_closed, &chan->link);
    else
	gensio_list_add_tail(&base->chans, &chan->link);
    ax25_base_unlock(base);

    *rchan = chan;
    return 0;

 out_nomem:
    rv = GE_NOMEM;
 out_err:
    ax25_cleanup_conf(o, &conf);
    if (addr)
	gensio_addr_free(addr);
    if (chan)
	ax25_chan_finish_free(chan, false);
    return rv;
}

static int
ax25_gensio_alloc_base(struct gensio *child, const char *const args[],
		       struct ax25_conf_data *conf,
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct ax25_chan **rchan)
{
    int rv;
    struct ax25_base *base;
    struct ax25_chan *chan;
    struct gensio_ax25_subaddr *my_addrs = NULL;
    unsigned int num_my_addrs = 0;

    base = o->zalloc(o, sizeof(*base));
    if (!base)
	return GE_NOMEM;

    base->o = o;
    base->state = AX25_BASE_CLOSED;
    gensio_list_init(&base->chans);
    gensio_list_init(&base->chans_waiting_open);
    gensio_list_init(&base->chans_closed);
    gensio_list_init(&base->send_list);
    base->refcount = 1;
    base->conf = *conf;
    if (conf->my_addrs) {
	unsigned int size = conf->num_my_addrs * sizeof(*(conf->my_addrs));

	base->conf.my_addrs = NULL;
	base->conf.num_my_addrs = 0;
	my_addrs = o->zalloc(o, size);
	if (!my_addrs)
	    goto out_nomem;
	memcpy(my_addrs, conf->my_addrs, size);
	num_my_addrs = conf->num_my_addrs;
    }

    base->lock = o->alloc_lock(o);
    if (!base->lock)
	goto out_nomem;

    base->child = child;

    rv = ax25_chan_alloc(base, args, cb, user_data, AX25_CHAN_CLOSED,
			 NULL, true, &chan);
    if (rv) {
	base->child = NULL; /* Caller will free this. */
	goto out_err;
    }
    /*
     * chan alloc will increment the refcount, but we want the
     * refcount to match the number of channels here.
     */
    base->refcount--;

    gensio_set_callback(child, ax25_child_cb, base);

    base->conf = chan->conf;
    base->conf.addr = NULL;
    chan->conf.my_addrs = NULL;
    chan->conf.num_my_addrs = 0;

    if (my_addrs) {
	base->conf.my_addrs = my_addrs;
	base->conf.num_my_addrs = num_my_addrs;
	my_addrs = NULL;
    }

    *rchan = chan;
    return 0;

 out_nomem:
    rv = GE_NOMEM;
 out_err:
    if (my_addrs)
	o->free(o, my_addrs);
    ax25_base_finish_free(base);
    return rv;
}

static int
ax25_gensio_alloc(struct gensio *child, const char *const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **net)
{
    struct ax25_conf_data conf;
    struct ax25_chan *chan;
    int err;

    ax25_defconf(&conf);
    err = ax25_gensio_alloc_base(child, args, &conf, o, cb, user_data, &chan);
    if (err)
	return err;
    *net = chan->io;
    return 0;
}

static int
str_to_ax25_gensio(const char *str, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    err = str_to_gensio(str, o, NULL, NULL, &io2);
    if (err)
	return err;

    err = ax25_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct ax25a_data {
    struct gensio_accepter *acc;
    struct ax25_conf_data conf;
    struct gensio_os_funcs *o;
};

static void
ax25a_free(struct ax25a_data *nadata)
{
    ax25_cleanup_conf(nadata->o, &nadata->conf);
    nadata->o->free(nadata->o, nadata);
}

static int
ax25a_alloc_gensio(struct ax25a_data *nadata, const char * const *iargs,
		   struct gensio *child, struct gensio **rio)
{
    return ax25_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);
}

static int
ax25a_new_child(struct ax25a_data *adata, void **finish_data,
		struct gensio_new_child_io *ncio)
{
    struct ax25_chan *chan;
    struct ax25_base *base;
    struct ax25_conf_data conf = adata->conf;
    int err;

    err = ax25_gensio_alloc_base(ncio->child, NULL, &conf,
				 adata->o, NULL, NULL, &chan);
    if (err)
	return err;

    base = chan->base;
    base->accepter = adata->acc;
    ncio->new_io = chan->io;
    base->state = AX25_BASE_OPEN;
    base->refcount++;
    base->waiting_first_open = true;
    chan->open_done = ncio->open_done;
    chan->open_data = ncio->open_data;
    *finish_data = chan;

    return err;
}

static int
ax25a_finish_parent(struct ax25_chan *chan)
{
    gensio_set_read_callback_enable(chan->base->child, true);
    return 0;
}

static int
gensio_gensio_acc_ax25_cb(void *acc_data, int op, void *data1, void *data2,
			  void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return ax25a_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD_IO:
	return ax25a_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	ax25a_free(acc_data);
	return 0;

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return ax25a_finish_parent(data1);

    default:
	return GE_NOTSUP;
    }
}

static int
ax25_gensio_accepter_alloc(struct gensio_accepter *child,
			   const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
    struct ax25a_data *adata;
    int err;

    adata = o->zalloc(o, sizeof(*adata));
    if (!adata)
	return GE_NOMEM;

    adata->o = o;
    ax25_defconf(&adata->conf);
    err = ax25_readconf(o, true, true, &adata->conf, args);
    if (err) {
	ax25_cleanup_conf(o, &adata->conf);
	o->free(o, adata);
	return err;
    }

    err = gensio_gensio_accepter_alloc(child, o, "ax25", cb, user_data,
				       gensio_gensio_acc_ax25_cb, adata,
				       &adata->acc);
    if (err)
	goto out_err;
    gensio_acc_set_is_packet(adata->acc, true);
    gensio_acc_set_is_reliable(adata->acc, true);
    *accepter = adata->acc;

    return 0;

 out_err:
    ax25a_free(adata);
    return err;
}

static int
str_to_ax25_gensio_accepter(const char *str, const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb,
			    void *user_data,
			    struct gensio_accepter **acc)
{
    int err;
    struct gensio_accepter *acc2 = NULL;

    err = str_to_gensio_accepter(str, o, NULL, NULL, &acc2);
    if (!err) {
	err = ax25_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_ax25(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "ax25",
				str_to_ax25_gensio, ax25_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "ax25",
					 str_to_ax25_gensio_accepter,
					 ax25_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
