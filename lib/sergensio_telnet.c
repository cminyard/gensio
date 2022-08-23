/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>

#include <gensio/sergensio_class.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>

#include "utils.h"
#include "telnet.h"
#include "gensio_filter_telnet.h"

#define SERCTL_WAIT_TIME 5

struct stel_req {
    int option;
    int minval;
    int maxval;
    void (*done)(struct sergensio *sio, int err, int val, void *cb_data);
    void (*donesig)(struct sergensio *sio, int err, char *sig,
		    unsigned int sig_len, void *cb_data);
    void *cb_data;
    int time_left;
    struct stel_req *next;
};

struct stel_data {
    struct gensio *io;
    struct sergensio *sio;

    struct gensio_os_funcs *o;

    struct gensio_filter *filter;
    const struct gensio_telnet_filter_rops *rops;
    struct gensio_lock *lock;

    bool allow_2217;
    bool do_2217;
    bool cisco_baud;
    bool reported_modemstate;
    bool is_client;

    struct stel_req *reqs;
};

static struct cisco_baud_rates_s {
    int real_rate;
    int cisco_ios_val;
} cisco_baud_rates[] = {
    { 300, 3 },
    { 600 , 4},
    { 1200, 5 },
    { 2400, 6 },
    { 4800, 7 },
    { 9600, 8 },
    { 19200, 10 },
    { 38400, 12 },
    { 57600, 13 },
    { 115200, 14 },
    { 230400, 15 },
};
#define CISCO_BAUD_RATES_LEN \
    ((sizeof(cisco_baud_rates) / sizeof(struct cisco_baud_rates_s)))

/*
 * Convert a Cisco version RFC2217 baud rate to an integer baud rate.
 * Returns 0 if unsuccessful.
 */
static int
cisco_baud_to_baud(int cisco_val)
{
    unsigned int i;

    for (i = 0; i < CISCO_BAUD_RATES_LEN; i++) {
	if (cisco_val == cisco_baud_rates[i].cisco_ios_val)
	    return cisco_baud_rates[i].real_rate;
    }

    return 0;
}

/*
 * Convert an integer baud rate to a Cisco version RFC2217 baud rate.
 * Returns 0 if unsuccessful.
 */
static int
baud_to_cisco_baud(int val)
{
    unsigned int i;

    for (i = 0; i < CISCO_BAUD_RATES_LEN; i++) {
	if (val == cisco_baud_rates[i].real_rate)
	    return cisco_baud_rates[i].cisco_ios_val;
    }

    return 0;
}

static void
stel_lock(struct stel_data *sdata)
{
    sdata->o->lock(sdata->lock);
}

static void
stel_unlock(struct stel_data *sdata)
{
    sdata->o->unlock(sdata->lock);
}

static int
stel_queue(struct stel_data *sdata, int option,
	   int minval, int maxval,
	   void (*done)(struct sergensio *sio, int err,
			int baud, void *cb_data),
	   void (*donesig)(struct sergensio *sio, int err, char *sig,
			   unsigned int sig_len, void *cb_data),
	   void *cb_data)
{
    struct stel_req *curr, *req;
    gensio_time timeout;

    if (!sdata->do_2217)
	return GE_NOTSUP;

    req = sdata->o->zalloc(sdata->o, sizeof(*req));
    if (!req)
	return GE_NOMEM;

    req->option = option;
    req->done = done;
    req->donesig = donesig;
    req->cb_data = cb_data;
    req->minval = minval;
    if (!maxval)
	maxval = INT_MAX;
    req->maxval = maxval;
    req->time_left = SERCTL_WAIT_TIME;
    req->next = NULL;

    stel_lock(sdata);
    curr = sdata->reqs;
    if (!curr) {
	sdata->reqs = req;
    } else {
	while (curr->next)
	    curr = curr->next;
	curr->next = req;
    }
    stel_unlock(sdata);

    timeout.secs = 1;
    timeout.nsecs = 0;
    sdata->rops->start_timer(sdata->filter, &timeout);
    return 0;
}

static int
stel_baud(struct sergensio *sio, int baud,
	  void (*done)(struct sergensio *sio, int err,
		       int baud, void *cb_data),
	  void *cb_data)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    bool is_client = sergensio_is_client(sio);
    unsigned char buf[6];
    int err;

    if (is_client) {
	err = stel_queue(sdata, 1, 0, 0, done, NULL, cb_data);
	if (err)
	    return err;
	buf[1] = 1;
    } else {
	buf[1] = 101;
    }

    buf[0] = 44;
    if (sdata->cisco_baud) {
	buf[2] = baud_to_cisco_baud(baud);
	sdata->rops->send_option(sdata->filter, buf, 3);
    } else {
	buf[2] = baud >> 24;
	buf[3] = baud >> 16;
	buf[4] = baud >> 8;
	buf[5] = baud;
	sdata->rops->send_option(sdata->filter, buf, 6);
    }
    return 0;
}

static int
stel_queue_and_send(struct sergensio *sio, int option, int val,
		    int xmitbase, int minval, int maxval,
		    void (*done)(struct sergensio *sio, int err, int val,
				 void *cb_data),
		    void *cb_data)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    unsigned char buf[3];
    bool is_client = sergensio_is_client(sio);
    int err;

    if (val < minval || val > maxval)
	return GE_INVAL;

    if (is_client) {
	err = stel_queue(sdata, option, xmitbase, xmitbase + maxval,
			 done, NULL, cb_data);
	if (err)
	    return err;
    } else {
	option += 100;
    }

    buf[0] = 44;
    buf[1] = option;
    buf[2] = val + xmitbase;
    sdata->rops->send_option(sdata->filter, buf, 3);

    return 0;
}

static int
stel_datasize(struct sergensio *sio, int datasize,
	      void (*done)(struct sergensio *sio, int err, int datasize,
			   void *cb_data),
	      void *cb_data)
{
    return stel_queue_and_send(sio, 2, datasize, 0, 0, 8, done, cb_data);
}

static int
stel_parity(struct sergensio *sio, int parity,
	    void (*done)(struct sergensio *sio, int err, int parity,
			 void *cb_data),
	    void *cb_data)
{
    return stel_queue_and_send(sio, 3, parity, 0, 0, 5, done, cb_data);
}

static int
stel_stopbits(struct sergensio *sio, int stopbits,
	      void (*done)(struct sergensio *sio, int err, int stopbits,
			   void *cb_data),
	      void *cb_data)
{
    return stel_queue_and_send(sio, 4, stopbits, 0, 0, 3, done, cb_data);
}

static int
stel_flowcontrol(struct sergensio *sio, int flowcontrol,
		 void (*done)(struct sergensio *sio, int err,
			      int flowcontrol, void *cb_data),
		 void *cb_data)
{
    return stel_queue_and_send(sio, 5, flowcontrol, 0, 0, 3, done, cb_data);
}

static int
stel_iflowcontrol(struct sergensio *sio, int iflowcontrol,
		  void (*done)(struct sergensio *sio, int err,
			       int iflowcontrol, void *cb_data),
		  void *cb_data)
{
    return stel_queue_and_send(sio, 5, iflowcontrol, 13, 0, 6, done, cb_data);
}

static int
stel_sbreak(struct sergensio *sio, int breakv,
	    void (*done)(struct sergensio *sio, int err, int breakv,
			 void *cb_data),
	    void *cb_data)
{
    return stel_queue_and_send(sio, 5, breakv, 4, 0, 2, done, cb_data);
}

static int
stel_dtr(struct sergensio *sio, int dtr,
	 void (*done)(struct sergensio *sio, int err, int dtr,
		      void *cb_data),
	 void *cb_data)
{
    return stel_queue_and_send(sio, 5, dtr, 7, 0, 2, done, cb_data);
}

static int
stel_rts(struct sergensio *sio, int rts,
	 void (*done)(struct sergensio *sio, int err, int rts,
		      void *cb_data),
	 void *cb_data)
{
    return stel_queue_and_send(sio, 5, rts, 10, 0, 2, done, cb_data);
}

static int
stel_signature(struct sergensio *sio, char *sig, unsigned int sig_len,
	       void (*done)(struct sergensio *sio, int err, char *sig,
			    unsigned int sig_len, void *cb_data),
	       void *cb_data)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    unsigned char outopt[MAX_TELNET_CMD_XMIT_BUF];
    bool is_client = sergensio_is_client(sio);

    if (sig_len > (MAX_TELNET_CMD_XMIT_BUF - 2))
	sig_len = MAX_TELNET_CMD_XMIT_BUF - 2;

    if (is_client) {
	int err = stel_queue(sdata, 0, 0, 0, NULL, done, cb_data);
	if (err)
	    return err;

	outopt[0] = 44;
	outopt[1] = 0;
	sdata->rops->send_option(sdata->filter, outopt, 2);
    } else {
	outopt[0] = 44;
	outopt[1] = 100;
	strncpy((char *) outopt + 2, sig, sig_len);

	sdata->rops->send_option(sdata->filter, outopt, sig_len + 2);
    }

    return 0;
}

static int
stel_send(struct sergensio *sio, unsigned int opt, unsigned int val)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    unsigned char buf[3];

    buf[0] = 44;
    buf[1] = opt;
    buf[2] = val;

    if (!sergensio_is_client(sio))
	buf[1] += 100;

    sdata->rops->send_option(sdata->filter, buf, 3);

    return 0;
}

static int
stel_modemstate(struct sergensio *sio, unsigned int val)
{
    unsigned int opt;

    if (sergensio_is_client(sio))
	opt = 11;
    else
	opt = 7;
    return stel_send(sio, opt, val);
}

static int
stel_linestate(struct sergensio *sio, unsigned int val)
{
    unsigned int opt;

    if (sergensio_is_client(sio))
	opt = 10;
    else
	opt = 6;
    return stel_send(sio, opt, val);
}

static int
stel_flowcontrol_state(struct sergensio *sio, bool val)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    unsigned char buf[2];

    buf[0] = 44;

    if (val)
	buf[1] = 8;
    else
	buf[1] = 9;
    if (!sergensio_is_client(sio))
	buf[1] += 100;

    sdata->rops->send_option(sdata->filter, buf, 2);

    return 0;
}

static int
stel_flush(struct sergensio *sio, unsigned int val)
{
    return stel_send(sio, 12, val);
}

static int
stel_send_break(struct sergensio *sio)
{
    struct stel_data *sdata = sergensio_get_gensio_data(sio);
    unsigned char buf[2];

    buf[0] = TN_IAC;
    buf[1] = TN_BREAK;
    sdata->rops->send_cmd(sdata->filter, buf, 2);
    return 0;
}

static int
sergensio_stel_func(struct sergensio *sio, int op, int val, char *buf,
		    void *done, void *cb_data)
{
    switch (op) {
    case SERGENSIO_FUNC_BAUD:
	return stel_baud(sio, val, done, cb_data);

    case SERGENSIO_FUNC_DATASIZE:
	return stel_datasize(sio, val, done, cb_data);

    case SERGENSIO_FUNC_PARITY:
	return stel_parity(sio, val, done, cb_data);

    case SERGENSIO_FUNC_STOPBITS:
	return stel_stopbits(sio, val, done, cb_data);

    case SERGENSIO_FUNC_FLOWCONTROL:
	return stel_flowcontrol(sio, val, done, cb_data);

    case SERGENSIO_FUNC_IFLOWCONTROL:
	return stel_iflowcontrol(sio, val, done, cb_data);

    case SERGENSIO_FUNC_SBREAK:
	return stel_sbreak(sio, val, done, cb_data);

    case SERGENSIO_FUNC_DTR:
	return stel_dtr(sio, val, done, cb_data);

    case SERGENSIO_FUNC_RTS:
	return stel_rts(sio, val, done, cb_data);

    case SERGENSIO_FUNC_MODEMSTATE:
	return stel_modemstate(sio, val);

    case SERGENSIO_FUNC_LINESTATE:
	return stel_linestate(sio, val);

    case SERGENSIO_FUNC_FLOWCONTROL_STATE:
	return stel_flowcontrol_state(sio, val);

    case SERGENSIO_FUNC_FLUSH:
	return stel_flush(sio, val);

    case SERGENSIO_FUNC_SIGNATURE:
	return stel_signature(sio, buf, val, done, cb_data);

    case SERGENSIO_FUNC_SEND_BREAK:
	return stel_send_break(sio);

    default:
	return GE_NOTSUP;
    }
}

static int
stelc_com_port_will_do(void *handler_data, unsigned char cmd)
{
    struct stel_data *sdata = handler_data;

    if (cmd != TN_DO && cmd != TN_DONT)
	/* We only handle these. */
	return 0;

    if (cmd == TN_DONT)
	/* The remote end turned off RFC2217 handling. */
	sdata->do_2217 = false;
    else
	sdata->do_2217 = sdata->allow_2217;

    return sdata->do_2217;
}

static void
stelc_com_port_cmd(void *handler_data, const unsigned char *option,
		   unsigned int len)
{
    struct stel_data *sdata = handler_data;
    int val = 0, cmd;
    struct stel_req *curr, *prev = NULL;
    char *sig = NULL;
    unsigned int sig_len;
    gensiods vlen = sizeof(int);
    struct gensio *io = sdata->io;

    if (len < 2)
	return;
    if (option[1] < 100)
	return;
    cmd = option[1] - 100;

    switch (cmd) {
    case 0:
	sig = (char *) (option + 2);
	sig_len = len - 2;
	break;

    case 1:
	if (len < 3)
	    return;
	if (len < 6) {
	    sdata->cisco_baud = true;
	    val = cisco_baud_to_baud(option[2]);
	} else {
	    val = option[2] << 24;
	    val |= option[3] << 16;
	    val |= option[4] << 8;
	    val |= option[5];
	}
	break;

    case 6:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_LINESTATE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	return;

    case 7:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	return;

    case 8:
	val = 1;
	gensio_cb(io, GENSIO_EVENT_SER_FLOW_STATE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	return;

    case 9:
	val = 0;
	gensio_cb(io, GENSIO_EVENT_SER_FLOW_STATE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	return;

    case 12:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_FLUSH, 0,
		  (unsigned char *) &val, &vlen, NULL);
	return;

    default:
	if (len < 3)
	    return;
	val = option[2];
	break;
    }

    stel_lock(sdata);
    curr = sdata->reqs;
    while (curr && curr->option != cmd &&
			val >= curr->minval && val <= curr->maxval) {
	prev = curr;
	curr = curr->next;
    }
    if (curr) {
	if (prev)
	    prev->next = curr->next;
	else
	    sdata->reqs = curr->next;
    }
    stel_unlock(sdata);

    if (curr) {
	if (sig) {
	    if (curr->donesig)
		curr->donesig(sdata->sio, 0, sig, sig_len, curr->cb_data);
	} else {
	    if (curr->done)
		curr->done(sdata->sio, 0, val - curr->minval, curr->cb_data);
	}
	sdata->o->free(sdata->o, curr);
	return;
    }
}

static void
stelc_timeout(void *handler_data)
{
    struct stel_data *sdata = handler_data;
    gensio_time timeout;
    struct stel_req *req, *curr, *prev = NULL, *to_complete = NULL;

    stel_lock(sdata);
    req = sdata->reqs;
    while (req) {
	if (--req->time_left == 0) {
	    if (!prev)
		sdata->reqs = req->next;
	    else
		prev->next = req->next;
	    req->next = NULL;
	    curr = to_complete;
	    if (!curr) {
		to_complete = req;
	    } else {
		while (curr->next)
		    curr = curr->next;
		curr->next = req;
	    }
	} else {
	    prev = req;
	    req = req->next;
	}
    }

    if (sdata->reqs) {
	timeout.secs = 1;
	timeout.nsecs = 0;
	sdata->rops->start_timer(sdata->filter, &timeout);
    }
    stel_unlock(sdata);

    req = to_complete;
    while (req) {
	if (req->done)
	    req->done(sdata->sio, GE_TIMEDOUT, 0, req->cb_data);
	else if (req->donesig)
	    req->donesig(sdata->sio, GE_TIMEDOUT, NULL, 0, req->cb_data);
	prev = req;
	req = req->next;
	sdata->o->free(sdata->o, prev);
    }
}

static void
stelc_got_sync(void *handler_data)
{
    /* Nothing to do, break handling is only on the server side. */
}

static void
stel_free(void *handler_data)
{
    struct stel_data *sdata = handler_data;

    if (sdata->sio)
	sergensio_data_free(sdata->sio);
    if (sdata->lock)
	sdata->o->free_lock(sdata->lock);
    while (sdata->reqs) {
	struct stel_req *req = sdata->reqs;

	sdata->reqs = req->next;
	sdata->o->free(sdata->o, req);
    }
    sdata->o->free(sdata->o, sdata);
}

struct gensio_telnet_filter_callbacks sergensio_telnet_filter_cbs = {
    .got_sync = stelc_got_sync,
    .com_port_will_do = stelc_com_port_will_do,
    .com_port_cmd = stelc_com_port_cmd,
    .timeout = stelc_timeout,
    .free = stel_free
};

static int
stels_cb_com_port_will_do(void *handler_data, unsigned char cmd)
{
    struct stel_data *sdata = handler_data;

    if (cmd != TN_WILL && cmd != TN_WONT)
	/* We only handle these. */
	return 0;
    stel_lock(sdata);
    if (cmd == TN_WONT)
	/* The remote end turned off RFC2217 handling. */
	sdata->do_2217 = false;
    else
	sdata->do_2217 = sdata->allow_2217;

    if (!sdata->reported_modemstate && sdata->do_2217) {
	struct gensio *io = sdata->io;

	if (gensio_get_cb(io)) {
	    int val = 255;
	    gensiods vlen = sizeof(val);

	    sdata->reported_modemstate = true;
	    gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		      (unsigned char *) &val, &vlen, NULL);
	} else {
	    gensio_time timeout;

	    /* Schedule a modemstate report once the callbacks are set. */
	    timeout.secs = 0;
	    timeout.nsecs = 1000000;
	    sdata->rops->start_timer(sdata->filter, &timeout);
	}
    }
    stel_unlock(sdata);

    return sdata->do_2217;
}

static void
stels_cb_com_port_cmd(void *handler_data, const unsigned char *option,
		      unsigned int len)
{
    struct stel_data *sdata = handler_data;
    int val = 0;
    gensiods vlen = sizeof(int);
    struct gensio *io = sdata->io;

    if (len < 2)
	return;
    if (option[1] >= 100)
	return;

    switch (option[1]) {
    case 0:
	vlen = len - 2;
	gensio_cb(io, GENSIO_EVENT_SER_SIGNATURE, 0,
		  (unsigned char *) (option + 2), &vlen, NULL);
	break;

    case 1:
	if (len < 3)
	    return;
	if (len < 6) {
	    sdata->cisco_baud = true;
	    val = cisco_baud_to_baud(option[2]);
	} else {
	    val = option[2] << 24;
	    val |= option[3] << 16;
	    val |= option[4] << 8;
	    val |= option[5];
	}
	gensio_cb(io, GENSIO_EVENT_SER_BAUD, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 2:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_DATASIZE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 3:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_PARITY, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 4:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_STOPBITS, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 5:
	if (len < 3)
	    return;
	switch(option[2]) {
	case 0: case 1: case 2: case 3:
	    val = option[2];
	    gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		      (unsigned char *) &val, &vlen, NULL);
	    break;
	case 4: case 5: case 6:
	    val = option[2] - 4;
	    gensio_cb(io, GENSIO_EVENT_SER_SBREAK, 0,
		      (unsigned char *) &val, &vlen, NULL);
	    break;
	case 7: case 8: case 9:
	    val = option[2] - 7;
	    gensio_cb(io, GENSIO_EVENT_SER_DTR, 0,
		      (unsigned char *) &val, &vlen, NULL);
	    break;
	case 10: case 11: case 12:
	    val = option[2] - 10;
	    gensio_cb(io, GENSIO_EVENT_SER_RTS, 0,
		      (unsigned char *) &val, &vlen, NULL);
	    break;
	case 13: case 14: case 15: case 16: case 17: case 18: case 19:
	    val = option[2] - 13;
	    gensio_cb(io, GENSIO_EVENT_SER_IFLOWCONTROL, 0,
		      (unsigned char *) &val, &vlen, NULL);
	}
	break;

    case 8:
	val = 1;
	gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 9:
	val = 0;
	gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 10:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_LINESTATE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 11:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 12:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_FLUSH, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    default:
	break;
    }
}

static void
stels_got_cmd(void *handler_data, unsigned char cmd)
{
    struct stel_data *sdata = handler_data;
    struct gensio *io = sdata->io;

    if (cmd == TN_BREAK)
	gensio_cb(io, GENSIO_EVENT_SEND_BREAK, 0, NULL, NULL, NULL);
}

static void
stels_cb_got_sync(void *handler_data)
{
    struct stel_data *sdata = handler_data;
    struct gensio *io = sdata->io;

    gensio_cb(io, GENSIO_EVENT_SER_SYNC, 0, NULL, NULL, NULL);
}

static void
stels_timeout(void *handler_data)
{
    struct stel_data *sdata = handler_data;

    stel_lock(sdata);
    if (!sdata->reported_modemstate && sdata->do_2217) {
	struct gensio *io = sdata->io;
	int val = 255;
	gensiods vlen = sizeof(val);

	if (gensio_get_cb(io)) {
	    sdata->reported_modemstate = true;
	    gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		      (unsigned char *) &val, &vlen, NULL);
	} else {
	    gensio_time timeout;

	    timeout.secs = 0;
	    timeout.nsecs = 1000000;
	    sdata->rops->start_timer(sdata->filter, &timeout);
	}
    }
    stel_unlock(sdata);
}

struct gensio_telnet_filter_callbacks sergensio_telnet_server_filter_cbs = {
    .got_sync = stels_cb_got_sync,
    .got_cmd = stels_got_cmd,
    .com_port_will_do = stels_cb_com_port_will_do,
    .com_port_cmd = stels_cb_com_port_cmd,
    .timeout = stels_timeout,
    .free = stel_free
};

static int
stel_setup(const char * const args[], bool default_is_client,
	   struct gensio_os_funcs *o, struct stel_data **rsdata)
{
    struct stel_data *sdata;
    unsigned int i;
    bool allow_2217 = false;
    bool is_client = default_is_client;
    int err;
    int rv, ival;

    rv = gensio_get_default(o, "telnet", "rfc2217", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    allow_2217 = ival;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keybool(args[i], "rfc2217", &allow_2217) > 0)
	    continue;
	if (gensio_check_keyboolv(args[i], "mode", "client", "server",
				  &is_client) > 0)
	    continue;
	/* Ignore everything else, the filter will handle it. */
    }

    sdata = o->zalloc(o, sizeof(*sdata));
    if (!sdata)
	return GE_NOMEM;

    sdata->o = o;
    sdata->allow_2217 = allow_2217;
    sdata->is_client = is_client;

    sdata->lock = o->alloc_lock(o);
    if (!sdata->lock)
	goto out_nomem;

    err = gensio_telnet_filter_alloc(o, args, true,
				     (is_client ?
				      &sergensio_telnet_filter_cbs :
				      &sergensio_telnet_server_filter_cbs),
				     sdata, &sdata->rops, &sdata->filter);
    if (err)
	goto out_err;

    if (is_client) {
	sdata->reported_modemstate = true;
    }

    *rsdata = sdata;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    /* Freeing the filter frees sdata. */
    if (sdata->filter)
	gensio_filter_free(sdata->filter);
    else
	stel_free(sdata);
    return err;
}

static int
telnet_gensio_alloc(struct gensio *child, const char * const args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **rio)
{
    struct stel_data *sdata;
    struct gensio_ll *ll = NULL;
    struct gensio *io = NULL;
    int err;

    err = stel_setup(args, true, o, &sdata);
    if (err)
	return err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll)
	goto out_nomem;

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, sdata->filter, child, "telnet", cb,
			   user_data);
    if (!io)
	goto out_nomem;

    sdata->io = io;

    if (sdata->allow_2217) {
	err = sergensio_addclass(o, io, sergensio_stel_func, sdata,
				 &sdata->sio);
	if (err)
	    goto out_err;
    }

    gensio_free(child); /* Lose the ref we acquired. */
    gensio_set_is_client(io, sdata->is_client);
    *rio = io;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (io) {
	gensio_free(io);
    } else {
	/* Freeing the filter frees sdata. */
	if (sdata->filter)
	    gensio_filter_free(sdata->filter);
	else
	    stel_free(sdata);
	if (ll)
	    gensio_ll_free(ll);
    }
    return err;
}

static int
str_to_telnet_gensio(const char *str, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    err = str_to_gensio(str, o, NULL, NULL, &io2);
    if (err)
	return err;

    err = telnet_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct stela_data {
    struct sergensio_accepter *sacc;

    gensiods max_read_size;
    gensiods max_write_size;

    struct gensio_os_funcs *o;

    bool allow_2217;
    bool is_client;
};

static void
stela_free(void *acc_data)
{
    struct stela_data *stela = acc_data;

    if (stela->sacc)
	sergensio_acc_data_free(stela->sacc);
    stela->o->free(stela->o, stela);
}

static int
stela_alloc_gensio(void *acc_data, const char * const *iargs,
		   struct gensio *child, struct gensio **rio)
{
    struct stela_data *stela = acc_data;
    struct gensio_os_funcs *o = stela->o;
    const char *args[5] = {NULL, NULL, NULL, NULL, NULL};
    char buf1[50], buf2[50];
    unsigned int i;
    bool allow_2217 = stela->allow_2217;
    gensiods max_write_size = stela->max_write_size;
    gensiods max_read_size = stela->max_read_size;
    bool is_client = stela->is_client;

    for (i = 0; iargs && iargs[i]; i++) {
	if (gensio_check_keybool(iargs[i], "rfc2217", &allow_2217) > 0)
	    continue;
	if (gensio_check_keyds(iargs[i], "writebuf", &max_write_size) > 0)
	    continue;
	if (gensio_check_keyds(iargs[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyboolv(iargs[i], "mode", "client", "server",
				  &is_client) > 0)
	    continue;
	return GE_INVAL;
    }

    i = 0;
    if (allow_2217)
	args[i++] = "rfc2217=true";
    if (max_read_size != GENSIO_DEFAULT_BUF_SIZE) {
	snprintf(buf1, sizeof(buf1), "readbuf=%lu",
		 (unsigned long) max_read_size);
	args[i++] = buf1;
    }
    if (max_write_size != GENSIO_DEFAULT_BUF_SIZE) {
	snprintf(buf2, sizeof(buf2), "writebuf=%lu",
		 (unsigned long) max_write_size);
	args[i++] = buf2;
    }
    if (!is_client)
	args[i++] = "mode=server";

    return telnet_gensio_alloc(child, args, o, NULL, NULL, rio);
}

static int
stela_new_child(void *acc_data, void **finish_data,
		struct gensio_filter **filter, struct gensio *child)
{
    struct stela_data *stela = acc_data;
    struct gensio_os_funcs *o = stela->o;
    struct stel_data *sdata;
    int err;
    char arg1[25], arg2[25], arg3[25], arg4[25];
    const char *args[5] = { arg1, arg2, arg3, arg4, NULL };

    snprintf(arg1, sizeof(arg1), "rfc2217=%d", stela->allow_2217);
    snprintf(arg2, sizeof(arg2), "writebuf=%lu",
	     (unsigned long) stela->max_write_size);
    snprintf(arg3, sizeof(arg3), "readbuf=%lu",
             (unsigned long) stela->max_read_size);
    snprintf(arg4, sizeof(arg4), "mode=%s",
	     stela->is_client ? "client" : "server");

    err = stel_setup(args, false, o, &sdata);
    if (err)
	return err;

    *filter = sdata->filter;
    *finish_data = sdata;

    return 0;
}

static int
stela_finish_parent(void *acc_data, void *finish_data, struct gensio *io,
		    struct gensio *child)
{
    struct stel_data *sdata = finish_data;
    int err;

    sdata->io = io;

    if (sdata->allow_2217) {
	err = sergensio_addclass(sdata->o, io, sergensio_stel_func, sdata,
				 &sdata->sio);
	if (err)
	    return err;
    }

    gensio_set_is_client(io, sdata->is_client);

    return 0;
}

static int
gensio_gensio_acc_telnet_cb(void *acc_data, int op, void *data1, void *data2,
			    void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return stela_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return stela_new_child(acc_data, data1, data2, data3);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return stela_finish_parent(acc_data, data1, data2, data3);

    case GENSIO_GENSIO_ACC_FREE:
	stela_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
sergensio_stela_func(struct sergensio_accepter *sacc,
		     int op, int val, char *buf,
		     void *done, void *cb_data)
{
    return GE_NOTSUP;
}

static int
telnet_gensio_accepter_alloc(struct gensio_accepter *child,
			     const char * const args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb, void *user_data,
			     struct gensio_accepter **raccepter)
{
    struct stela_data *stela;
    int err;
    unsigned int i;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    gensiods max_write_size = GENSIO_DEFAULT_BUF_SIZE;
    bool allow_2217 = false;
    bool is_client = false;
    struct gensio_accepter *accepter = NULL;
    int rv, ival;

    rv = gensio_get_default(o, "telnet", "rfc2217", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    allow_2217 = ival;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keybool(args[i], "rfc2217", &allow_2217) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "writebuf", &max_write_size) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyboolv(args[i], "mode", "client", "server",
				  &is_client) > 0)
	    continue;
	return GE_INVAL;
    }

    stela = o->zalloc(o, sizeof(*stela));
    if (!stela)
	return GE_NOMEM;

    stela->o = o;
    stela->max_write_size = max_write_size;
    stela->max_read_size = max_read_size;
    stela->allow_2217 = allow_2217;
    stela->is_client = is_client;

    err = gensio_gensio_accepter_alloc(child, o, "telnet",
				       cb, user_data,
				       gensio_gensio_acc_telnet_cb, stela,
				       &accepter);
    if (err)
	goto out_err;

    if (allow_2217) {
	err = sergensio_acc_addclass(o, accepter, sergensio_stela_func, stela,
				     &stela->sacc);
	if (err)
	    goto out_err;
    }
    gensio_acc_set_is_reliable(accepter, gensio_acc_is_reliable(child));

    *raccepter = accepter;

    return 0;

 out_err:
    if (accepter)
	gensio_gensio_acc_free_nochild(accepter);
    else
	stela_free(stela);
    return err;
}

static int
str_to_telnet_gensio_accepter(const char *str, const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **acc)
{
    int err;
    struct gensio_accepter *acc2 = NULL;

    err = str_to_gensio_accepter(str, o, NULL, NULL, &acc2);
    if (!err) {
	err = telnet_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_telnet(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "telnet",
				str_to_telnet_gensio, telnet_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "telnet",
					 str_to_telnet_gensio_accepter,
					 telnet_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
