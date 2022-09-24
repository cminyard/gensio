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
#include <ctype.h>
#include <stdbool.h>

#include <gensio/sergensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/gensio_osops.h>

#include "uucplock.h"
#include "utils.h"

static int
speedstr_to_speed(const char *speed, const char **rest)
{
    const char *end = speed;
    unsigned int len;
    int rv;

    while (*end && isdigit(*end))
	end++;
    len = end - speed;
    if (len < 1)
	return -1;

    rv = strtoul(speed, NULL, 10);
    *rest = end;

    return rv;
}

struct penum_val { char *str; int val; };
static struct penum_val parity_enums[] = {
    { "NONE", SERGENSIO_PARITY_NONE },
    { "EVEN", SERGENSIO_PARITY_EVEN },
    { "ODD", SERGENSIO_PARITY_ODD },
    { "MARK", SERGENSIO_PARITY_MARK },
    { "SPACE", SERGENSIO_PARITY_SPACE },
    { NULL }
};

static int
lookup_parity_str(const char *str)
{
    unsigned int i;

    for (i = 0; parity_enums[i].str; i++) {
	if (strcmp(parity_enums[i].str, str) == 0)
	    return parity_enums[i].val;
    }
    return -1;
}

static const char *
parity_to_str(int val)
{
    unsigned int i;

    for (i = 0; parity_enums[i].str; i++) {
	if (parity_enums[i].val == val)
	    return parity_enums[i].str;
    }
    return "?";
}

struct sterm_data;

struct termio_op_q {
    int op;
    int (*xlat)(struct sterm_data *, bool get, int *oval, int val);
    void (*done)(struct sergensio *sio, int err, int val, void *cb_data);
    void *cb_data;
    struct termio_op_q *next;
};

struct sterm_data {
    struct sergensio *sio;
    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_timer *timer;
    bool timer_stopped;

    bool open;

    int drain_time;
    int char_drain_wait;

    int close_timeouts_left;
    int char_timeouts_left;
    int last_close_outq_count;

    char *devname;
    char *parms;

    struct gensio_iod *iod;
    struct gensio_ll *ll;

    /*
     * Unfortunately, at least on Linux, ptys return EIO errors when
     * the remote end closes, instead of something sensible like
     * EPIPE, like all other IPC does.  So we have to have special
     * handling to detect ptys.  We still want to return GE_IOERR
     * on IO errors for real devices.
     */
    bool is_pty;

    bool write_only;		/* No serial settings, no read. */

    bool no_uucp_lock;

    void *default_sercfg;
    int def_baud;
    int def_parity;
    int def_datasize;
    int def_stopbits;
    int def_xonxoff;
    int def_rtscts;
    int def_local;
    int def_hupcl;
    char *rs485;

    bool rts_first; /* Set RTS before DTR? */
    bool rts_set;
    bool rts_val;
    bool dtr_set;
    bool dtr_val;

    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;
    struct termio_op_q *termio_q;
    bool break_set;
    bool disablebreak;
    unsigned int last_modemstate;
    unsigned int modemstate_mask;
    bool handling_modemstate;
    bool sent_first_modemstate;
};

static int
set_serdef_from_speed(struct sterm_data *sdata, int speed, const char *others)
{
    sdata->def_baud = speed;

    if (*others) {
	switch (*others) {
	case 'N': case 'n': sdata->def_parity = SERGENSIO_PARITY_NONE; break;
	case 'E': case 'e': sdata->def_parity = SERGENSIO_PARITY_EVEN; break;
	case 'O': case 'o': sdata->def_parity = SERGENSIO_PARITY_ODD; break;
	case 'M': case 'm': sdata->def_parity = SERGENSIO_PARITY_MARK; break;
	case 'S': case 's': sdata->def_parity = SERGENSIO_PARITY_SPACE; break;
	    break;
	default:
	    return GE_INVAL;
	}
	others++;
    }

    if (*others) {
	switch (*others) {
	case '5': sdata->def_datasize = 5; break;
	case '6': sdata->def_datasize = 6; break;
	case '7': sdata->def_datasize = 7; break;
	case '8': sdata->def_datasize = 8; break;
	default:
	    return GE_INVAL;
	}
	others++;
    }

    if (*others) {
	switch (*others) {
	case '1': sdata->def_stopbits = 1; break;
	case '2': sdata->def_stopbits = 2; break;
	default:
	    return GE_INVAL;
	}
	others++;
    }

    if (*others)
	return GE_INVAL;

    return 0;
}

static void serconf_process(struct sterm_data *sdata);

static void
sterm_lock(struct sterm_data *sdata)
{
    sdata->o->lock(sdata->lock);
}

static void
sterm_unlock(struct sterm_data *sdata)
{
    sdata->o->unlock(sdata->lock);
}

static void
sterm_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct sterm_data *sdata = cbdata;

    sterm_lock(sdata);
 restart:
    serconf_process(sdata);

    if (sdata->termio_q)
	/* Something was added, process it. */
	goto restart;

    sdata->deferred_op_pending = false;
    sterm_unlock(sdata);
}

static void
sterm_start_deferred_op(struct sterm_data *sdata)
{
    if (!sdata->deferred_op_pending) {
	sdata->deferred_op_pending = true;
	sdata->o->run(sdata->deferred_op_runner);
    }
}

static void
serconf_process(struct sterm_data *sdata)
{
    while (sdata->termio_q) {
	struct termio_op_q *qe = sdata->termio_q;
	int val = 0, err;

	sdata->termio_q = qe->next;

	err = sdata->o->iod_control(sdata->iod, qe->op, true, (intptr_t) &val);
	if (!err && qe->xlat)
	    err = qe->xlat(sdata, true, &val, val);
	sterm_unlock(sdata);
	qe->done(sdata->sio, err, val, qe->cb_data);
	sdata->o->free(sdata->o, qe);
	sterm_lock(sdata);
    }
}

static void
serconf_clear_q(struct sterm_data *sdata)
{
    while (sdata->termio_q) {
	struct termio_op_q *qe = sdata->termio_q;

	sdata->termio_q = qe->next;
	sdata->o->free(sdata->o, qe);
    }
}

static int
serconf_set_get(struct sterm_data *sdata, int op, int val,
		int (*xlat)(struct sterm_data *sdata, bool get,
			    int *oval, int val),
		void (*done)(struct sergensio *sio, int err,
			     int val, void *cb_data),
		void *cb_data)
{
    struct termio_op_q *qe = NULL;
    int err = 0;

    if (sdata->write_only)
	return GE_NOTSUP;

    if (done) {
	qe = sdata->o->zalloc(sdata->o, sizeof(*qe));
	if (!qe)
	    return GE_NOMEM;
	qe->xlat = xlat;
	qe->done = done;
	qe->cb_data = cb_data;
	qe->op = op;
	qe->next = NULL;
    }

    sterm_lock(sdata);
    if (!sdata->open) {
	err = GE_NOTREADY;
	goto out_unlock;
    }

    if (val) {
	if (xlat)
	    err = xlat(sdata, false, &val, val);
	if (err)
	    goto out_unlock;
	err = sdata->o->iod_control(sdata->iod, op, false, val);
	if (err)
	    goto out_unlock;
	err = sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_APPLY,
				    false, 0);
	if (err)
	    goto out_unlock;
    }

    if (qe) {
	if (!sdata->termio_q) {
	    sdata->termio_q = qe;
	    sterm_start_deferred_op(sdata);
	} else {
	    struct termio_op_q *curr = sdata->termio_q;

	    while (curr->next)
		curr = curr->next;
	    curr->next = qe;
	}
    }
 out_unlock:
    if (err && qe)
	sdata->o->free(sdata->o, qe);
    sterm_unlock(sdata);
    return err;
}

static int
sterm_baud(struct sergensio *sio, int baud,
	   void (*done)(struct sergensio *sio, int err,
			int baud, void *cb_data),
	   void *cb_data)
{
    return serconf_set_get(sergensio_get_gensio_data(sio),
			   GENSIO_IOD_CONTROL_BAUD, baud,
			   NULL, done, cb_data);
}

static int
sterm_datasize(struct sergensio *sio, int datasize,
	       void (*done)(struct sergensio *sio, int err, int datasize,
			    void *cb_data),
	       void *cb_data)
{
    return serconf_set_get(sergensio_get_gensio_data(sio),
			   GENSIO_IOD_CONTROL_DATASIZE, datasize,
			   NULL, done, cb_data);
}

static int
sterm_parity(struct sergensio *sio, int parity,
	     void (*done)(struct sergensio *sio, int err, int parity,
			  void *cb_data),
	     void *cb_data)
{
    return serconf_set_get(sergensio_get_gensio_data(sio),
			   GENSIO_IOD_CONTROL_PARITY, parity,
			   NULL, done, cb_data);
}

static int
sterm_stopbits(struct sergensio *sio, int stopbits,
	       void (*done)(struct sergensio *sio, int err, int stopbits,
			    void *cb_data),
	       void *cb_data)
{
    return serconf_set_get(sergensio_get_gensio_data(sio),
			   GENSIO_IOD_CONTROL_STOPBITS, stopbits,
			   NULL, done, cb_data);
}

static int
serconf_xlat_flowcontrol(struct sterm_data *sdata, bool get,
			 int *oval, int val)
{
    int err;

    if (get) {
	if (val) {
	    *oval = SERGENSIO_FLOWCONTROL_RTS_CTS;
	} else {
	    err = sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_XONXOFF,
					true, (intptr_t) &val);
	    if (err)
		return err;
	    if (val)
		*oval = SERGENSIO_FLOWCONTROL_XON_XOFF;
	    else
		*oval = SERGENSIO_FLOWCONTROL_NONE;
	}
    } else {
	switch (val) {
	case SERGENSIO_FLOWCONTROL_NONE:
	    err = sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_XONXOFF,
					false, 0);
	    if (err)
		return err;
	    err = sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_IXONXOFF,
					false, 0);
	    if (err)
		return err;
	    *oval = 0;
	    break;

	case SERGENSIO_FLOWCONTROL_XON_XOFF:
	    err = sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_XONXOFF,
					false, 1);
	    if (err)
		return err;
	    err = sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_IXONXOFF,
					false, 1);
	    if (err)
		return err;
	    *oval = 0;
	    break;

	case SERGENSIO_FLOWCONTROL_RTS_CTS:
	    err = sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_XONXOFF,
					false, 0);
	    if (err)
		return err;
	    err = sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_IXONXOFF,
					false, 0);
	    if (err)
		return err;
	    *oval = 1;
	    break;

	default:
	    return GE_INVAL;
	}
    }

    return 0;
}

static int
sterm_flowcontrol(struct sergensio *sio, int flowcontrol,
		  void (*done)(struct sergensio *sio, int err,
			       int flowcontrol, void *cb_data),
		  void *cb_data)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);

    switch (flowcontrol) {
    case SERGENSIO_FLOWCONTROL_NONE:
    case SERGENSIO_FLOWCONTROL_RTS_CTS:
    case SERGENSIO_FLOWCONTROL_XON_XOFF:
	break;

    case 0:
    default:
	/* We only fetch in any other case. */
	flowcontrol = 0;
    }

    return serconf_set_get(sdata, GENSIO_IOD_CONTROL_RTSCTS, flowcontrol,
			   serconf_xlat_flowcontrol, done, cb_data);
}

static int
sterm_iflowcontrol(struct sergensio *sio, int iflowcontrol,
		   void (*done)(struct sergensio *sio, int err,
				int iflowcontrol, void *cb_data),
		   void *cb_data)
{
    /* Input flow control is not independently settable. */
    return serconf_set_get(sergensio_get_gensio_data(sio),
			   GENSIO_IOD_CONTROL_XONXOFF, 0,
			   serconf_xlat_flowcontrol, done, cb_data);
}

static int
sterm_xlat_sbreak(struct sterm_data *sdata, bool get, int *oval, int val)
{
    if (get) {
	if (val)
	    *oval = SERGENSIO_BREAK_ON;
	else
	    *oval = SERGENSIO_BREAK_OFF;
    } else {
	switch (val) {
	case SERGENSIO_BREAK_OFF: *oval = 0; break;
	case SERGENSIO_BREAK_ON: *oval = 1; break;
	default:
	    return GE_INVAL;
	}
    }

    return 0;
}

static int
sterm_sbreak(struct sergensio *sio, int breakv,
	     void (*done)(struct sergensio *sio, int err, int breakv,
			  void *cb_data),
	     void *cb_data)
{
    return serconf_set_get(sergensio_get_gensio_data(sio),
			   GENSIO_IOD_CONTROL_SET_BREAK, breakv,
			   sterm_xlat_sbreak, done, cb_data);
}

static int
serconf_xlat_dtr(struct sterm_data *sdata, bool get, int *oval, int val)
{
    if (get) {
	if (val)
	    *oval = SERGENSIO_DTR_ON;
	else
	    *oval = SERGENSIO_DTR_OFF;
    } else {
	switch (val) {
	case SERGENSIO_DTR_OFF: *oval = 0; break;
	case SERGENSIO_DTR_ON: *oval = 1; break;
	default:
	    return GE_INVAL;
	}
    }

    return 0;
}

static int
sterm_dtr(struct sergensio *sio, int dtr,
	  void (*done)(struct sergensio *sio, int err, int dtr,
		       void *cb_data),
	  void *cb_data)
{
    return serconf_set_get(sergensio_get_gensio_data(sio),
			   GENSIO_IOD_CONTROL_DTR, dtr,
			   serconf_xlat_dtr, done, cb_data);
}

static int
serconf_xlat_rts(struct sterm_data *sdata, bool get, int *oval, int val)
{
    if (get) {
	if (val)
	    *oval = SERGENSIO_RTS_ON;
	else
	    *oval = SERGENSIO_RTS_OFF;
    } else {
	if (val == SERGENSIO_RTS_ON)
	    *oval = 1;
	else if (val == SERGENSIO_RTS_OFF)
	    *oval = 0;
	else
	    return GE_INVAL;
    }

    return 0;
}

static int
sterm_rts(struct sergensio *sio, int rts,
	  void (*done)(struct sergensio *sio, int err, int rts,
		       void *cb_data),
	  void *cb_data)
{
    return serconf_set_get(sergensio_get_gensio_data(sio),
			   GENSIO_IOD_CONTROL_RTS, rts,
			   serconf_xlat_rts, done, cb_data);
}

static void
serialdev_timeout(struct gensio_timer *t, void *cb_data)
{
    struct sterm_data *sdata = cb_data;
    int modemstate = 0, rv;
    bool force_send;

    sterm_lock(sdata);
    if (sdata->handling_modemstate || !sdata->open) {
	sterm_unlock(sdata);
	return;
    }
    sdata->handling_modemstate = true;
    sterm_unlock(sdata);

    rv = sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_MODEMSTATE,
			       true, (intptr_t) &modemstate);
    if (rv)
	goto out_restart;

    sterm_lock(sdata);
    /* Bits for things that changed. */
    modemstate |= (modemstate ^ sdata->last_modemstate) >> 4;
    sdata->last_modemstate = modemstate & sdata->modemstate_mask;
    force_send = !sdata->sent_first_modemstate;
    sdata->sent_first_modemstate = true;
    sterm_unlock(sdata);

    /*
     * The bottom 4 buts of modemstate is the "changed" bits, only
     * report this if someing changed that was in the mask.
     */
    if ((force_send || modemstate & 0xf)) {
	struct gensio *io = sergensio_get_my_gensio(sdata->sio);
	gensiods vlen = sizeof(modemstate);

	gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		  (unsigned char *) &modemstate, &vlen, NULL);
    }

 out_restart:
    if (sdata->modemstate_mask) {
	gensio_time timeout = {1, 0};

	sdata->o->start_timer(sdata->timer, &timeout);
    }

    sterm_lock(sdata);
    sdata->handling_modemstate = false;
    sterm_unlock(sdata);
}

static int
sterm_modemstate(struct sergensio *sio, unsigned int val)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);
    gensio_time timeout = {0, 0};

    sterm_lock(sdata);
    sdata->modemstate_mask = val;
    sdata->sent_first_modemstate = false;
    sterm_unlock(sdata);

    /* Cause an immediate send of the modemstate. */
    sdata->o->stop_timer(sdata->timer);
    sdata->o->start_timer(sdata->timer, &timeout);
    return 0;
}

static int
sterm_flowcontrol_state(struct sergensio *sio, bool val)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);

    return sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_FLOWCTL_STATE,
				 false, val);
}

static int
sterm_flush(struct sergensio *sio, unsigned int val)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);
    struct gensio_os_funcs *o = sdata->o;
    int tval;

    switch(val) {
    case SERGENSIO_FLUSH_RCV_BUFFER:	tval = GENSIO_IN_BUF; break;
    case SERGENSIO_FLUSH_XMIT_BUFFER:	tval = GENSIO_OUT_BUF; break;
    case SERGENSIO_FLUSH_RCV_XMIT_BUFFERS:
	tval = GENSIO_IN_BUF | GENSIO_OUT_BUF;
	break;
    default:
	return GE_INVAL;
    }

    o->flush(sdata->iod, tval);
    return 0;
}

static int
sterm_send_break(struct sergensio *sio)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);

    return sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_SEND_BREAK,
				 false, 0);
}

static int
sergensio_sterm_func(struct sergensio *sio, int op, int val, char *buf,
		     void *done, void *cb_data)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);

    if (sdata->write_only)
	return GE_NOTSUP;

    switch (op) {
    case SERGENSIO_FUNC_BAUD:
	return sterm_baud(sio, val, done, cb_data);

    case SERGENSIO_FUNC_DATASIZE:
	return sterm_datasize(sio, val, done, cb_data);

    case SERGENSIO_FUNC_PARITY:
	return sterm_parity(sio, val, done, cb_data);

    case SERGENSIO_FUNC_STOPBITS:
	return sterm_stopbits(sio, val, done, cb_data);

    case SERGENSIO_FUNC_FLOWCONTROL:
	return sterm_flowcontrol(sio, val, done, cb_data);

    case SERGENSIO_FUNC_IFLOWCONTROL:
	return sterm_iflowcontrol(sio, val, done, cb_data);

    case SERGENSIO_FUNC_SBREAK:
	return sterm_sbreak(sio, val, done, cb_data);

    case SERGENSIO_FUNC_DTR:
	return sterm_dtr(sio, val, done, cb_data);

    case SERGENSIO_FUNC_RTS:
	return sterm_rts(sio, val, done, cb_data);

    case SERGENSIO_FUNC_MODEMSTATE:
	return sterm_modemstate(sio, val);

    case SERGENSIO_FUNC_FLOWCONTROL_STATE:
	return sterm_flowcontrol_state(sio, val);

    case SERGENSIO_FUNC_FLUSH:
	return sterm_flush(sio, val);

    case SERGENSIO_FUNC_SEND_BREAK:
	return sterm_send_break(sio);

    case SERGENSIO_FUNC_SIGNATURE:
    case SERGENSIO_FUNC_LINESTATE:
    default:
	return GE_NOTSUP;
    }
}

static void
sterm_timer_stopped(struct gensio_timer *timer, void *cb_data)
{
    struct sterm_data *sdata = cb_data;

    sdata->timer_stopped = true;
}

static int
sterm_check_close_drain(void *handler_data, struct gensio_iod *iod,
			enum gensio_ll_close_state state,
			gensio_time *next_timeout)
{
    struct sterm_data *sdata = handler_data;
    struct gensio_os_funcs *o = sdata->o;
    int rv, err = 0;
    gensiods count = 0;

    sterm_lock(sdata);
    if (state == GENSIO_LL_CLOSE_STATE_START) {
	sdata->open = false;
	rv = sdata->o->stop_timer_with_done(sdata->timer,
					    sterm_timer_stopped, sdata);
	if (rv)
	    sdata->timer_stopped = true;

	sdata->last_close_outq_count = 0;
    }

    if (state != GENSIO_LL_CLOSE_STATE_DONE)
	goto out_unlock;

    sdata->open = false;
    if (sdata->termio_q)
	goto out_einprogress;

    if (!sdata->timer_stopped)
	goto out_einprogress;

    if (sdata->handling_modemstate)
	goto out_einprogress;

    rv = o->bufcount(sdata->iod, GENSIO_OUT_BUF, &count);
    if (rv || count <= 0)
	goto out_rm_uucp;
    if (sdata->last_close_outq_count == 0)
	/* First time through, set the total time. */
	sdata->close_timeouts_left = sdata->drain_time;
    if (sdata->close_timeouts_left >= 0) {
	if (sdata->close_timeouts_left == 0)
	    goto out_rm_uucp;
	sdata->close_timeouts_left--;
    }

    if (sdata->last_close_outq_count == 0 ||
		count < sdata->last_close_outq_count) {
	/* First time through or some data was written, restart the timer. */
	sdata->last_close_outq_count = count;
	sdata->char_timeouts_left = sdata->char_drain_wait;
    }

    if (sdata->char_timeouts_left >= 0) {
	if (sdata->char_timeouts_left == 0)
	    goto out_rm_uucp;
	sdata->char_timeouts_left--;
    }

 out_einprogress:
    err = GE_INPROGRESS;
    next_timeout->secs = 0;
    next_timeout->nsecs = 10000000;
 out_rm_uucp:
    if (!err) {
	o->flush(sdata->iod, GENSIO_OUT_BUF);
	if (!sdata->no_uucp_lock)
	    uucp_rm_lock(sdata->devname);
	gensio_fd_ll_close_now(sdata->ll);
    }
    if (err != GE_INPROGRESS)
	/* We are really closing, the iod will be destroyed now. */
	sdata->iod = NULL;
 out_unlock:
    sterm_unlock(sdata);
    return err;
}

#ifndef _WIN32
#include <unistd.h>
#endif

static bool
is_a_pty(const char *ttyname)
{
#ifdef _WIN32
    return false;
#else
    char buf[PATH_MAX];

    while (readlink(ttyname, buf, sizeof(buf)) > 0)
	ttyname = buf;

    if (strncmp(ttyname, "/dev/pts/", 9) == 0)
	return true;

    /*
     * According to the Linux man page, BSD slave devices are named:
     *  /dev/tty[p-za-e][0-9a-f]
     * so we have this check for them.
     */
    if (strncmp(ttyname, "/dev/tty", 8) != 0)
	return false;

    return (((ttyname[8] >= 'a' && ttyname[8] <= 'e') ||
	     (ttyname[8] >= 'p' && ttyname[8] <= 'z')) &&
	    ((ttyname[9] >= '0' && ttyname[9] <= '9') ||
	     (ttyname[9] >= 'a' && ttyname[9] <= 'f')));
#endif
}

static int
sterm_sub_open(void *handler_data, struct gensio_iod **riod)
{
    struct sterm_data *sdata = handler_data;
    struct gensio_os_funcs *o = sdata->o;
    int err;
    int options;

    if (!sdata->no_uucp_lock) {
	err = uucp_mk_lock(o, sdata->devname);
	if (err)
	    goto out;
    }

    sdata->timer_stopped = false;
    sdata->iod = NULL; /* If it's a re-open make sure this is clear. */

    options = GENSIO_OPEN_OPTION_WRITEABLE;
    if (!sdata->write_only)
	options |= GENSIO_OPEN_OPTION_READABLE;
    err = o->open_dev(o, sdata->devname, options, &sdata->iod);
    if (err)
	goto out_uucp;

    if (!sdata->write_only) {
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_BAUD, false,
			     sdata->def_baud);
	if (err)
	    goto out_uucp;
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_PARITY, false,
			     sdata->def_parity);
	if (err)
	    goto out_uucp;
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_XONXOFF, false,
			     sdata->def_xonxoff);
	if (err)
	    goto out_uucp;
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_IXONXOFF, false,
			     sdata->def_xonxoff);
	if (err)
	    goto out_uucp;
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_RTSCTS, false,
			     sdata->def_rtscts);
	if (err)
	    goto out_uucp;
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_DATASIZE, false,
			     sdata->def_datasize);
	if (err)
	    goto out_uucp;
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_STOPBITS, false,
			     sdata->def_stopbits);
	if (err)
	    goto out_uucp;
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_LOCAL, false,
			     sdata->def_local);
	if (err)
	    goto out_uucp;
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_HANGUP_ON_DONE,
			     false, sdata->def_hupcl);
	if (err)
	    goto out_uucp;
	if (sdata->rs485) {
	    err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_RS485, false,
				 (intptr_t) sdata->rs485);
	    if (err)
		goto out_uucp;
	}
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_APPLY, false, 0);
	if (err)
	    goto out_uucp;
	if (sdata->rts_set && sdata->rts_first) {
	    err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_RTS, false,
				 sdata->rts_val);
	    if (err)
		goto out_uucp;
	}
	if (sdata->dtr_set) {
	    err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_DTR, false,
				 sdata->dtr_val);
	    if (err)
		goto out_uucp;
	}
	if (sdata->rts_set && !sdata->rts_first) {
	    err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_RTS, false,
				 sdata->rts_val);
	    if (err)
		goto out_uucp;
	}
    }

    if (!sdata->write_only && !sdata->disablebreak) {
	err = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_SET_BREAK,
			     false, sdata->disablebreak);
	if (err)
	    gensio_log(o, GENSIO_LOG_WARNING,
		       "serialdev: "
		       "Setting break failed on %s, "
		       "try adding the nobreak option: %s",
		       sdata->devname, gensio_err_to_str(err));
	/*
	 * Do not fail on an error here.  There are USB and bluetooth devices that fail
	 * this because they don't implement it, but it's impossible to tell beforehand
	 * that they will fail.  This shouldn't be able to fail on a working device, so
	 * just log and allow it.
	 */
    }

    sterm_lock(sdata);
    sdata->open = true;
    sdata->sent_first_modemstate = false;
    sterm_unlock(sdata);

    if (!sdata->write_only)
	sterm_modemstate(sdata->sio, 255);

    *riod = sdata->iod;

    return 0;

 out_uucp:
    if (!sdata->no_uucp_lock)
	uucp_rm_lock(sdata->devname);

    /* pty's for some reason return EIO if the remote end closes. */
    if (sdata->is_pty && err == GE_IOERR)
	err = GE_REMCLOSE;
 out:
    if (sdata->iod) {
	o->close(&sdata->iod);
	sdata->iod = NULL;
    }
    return err;
}

static void
sterm_free(void *handler_data)
{
    struct sterm_data *sdata = handler_data;

    if (sdata->sio)
	sergensio_data_free(sdata->sio);
    serconf_clear_q(sdata);
    if (sdata->rs485)
	sdata->o->free(sdata->o, sdata->rs485);
    if (sdata->lock)
	sdata->o->free_lock(sdata->lock);
    if (sdata->timer)
	sdata->o->free_timer(sdata->timer);
    if (sdata->devname)
	sdata->o->free(sdata->o, sdata->devname);
    if (sdata->deferred_op_runner)
	sdata->o->free_runner(sdata->deferred_op_runner);
    sdata->o->free(sdata->o, sdata);
}

static int
sterm_control_raddr(struct sterm_data *sdata, char *buf, gensiods *datalen)
{
    struct gensio_os_funcs *o = sdata->o;
    int tval, rv;
    gensiods pos = 0, buflen = *datalen;

    gensio_pos_snprintf(buf, buflen, &pos, "%s", sdata->devname);

    if (!sdata->write_only) {
	int baud;
	int stopbits;
	int datasize;
	const char *parity;
	int xonxoff;
	int rtscts;
	int clocal;
	int hangup_when_done;
	char str[4];

	if (!sdata->iod) {
	    baud = sdata->def_baud;
	    stopbits = sdata->def_stopbits;
	    datasize = sdata->def_datasize;
	    parity = parity_to_str(sdata->def_parity);
	    xonxoff = sdata->def_xonxoff;
	    rtscts = sdata->def_rtscts;
	    clocal = sdata->def_local;
	    hangup_when_done = sdata->def_hupcl;
	} else {
	    rv = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_BAUD, true,
				(intptr_t) &baud);
	    if (rv)
		return rv;
	    rv = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_STOPBITS, true,
				(intptr_t) &stopbits);
	    if (rv)
		return rv;
	    rv = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_DATASIZE, true,
				(intptr_t) &datasize);
	    if (rv)
		return rv;
	    rv = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_PARITY, true,
				(intptr_t) &tval);
	    if (rv)
		return rv;
	    parity = parity_to_str(tval);

	    rv = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_XONXOFF, true,
				(intptr_t) &xonxoff);
	    if (rv)
		return rv;
	    rv = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_RTSCTS, true,
				(intptr_t) &rtscts);
	    if (rv)
		return rv;
	    rv = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_LOCAL, true,
				(intptr_t) &clocal);
	    if (rv)
		return rv;
	    rv = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_HANGUP_ON_DONE,
				true, (intptr_t) &hangup_when_done);
	    if (rv)
		return rv;
	}

	str[0] = parity[0];
	str[1] = '0' + datasize;
	str[2] = '0' + stopbits;
	str[3] = '\0';

	gensio_pos_snprintf(buf, buflen, &pos, ",%d%s", baud, str);

	if (xonxoff)
	    gensio_pos_snprintf(buf, buflen, &pos, ",XONXOFF");

	if (rtscts)
	    gensio_pos_snprintf(buf, buflen, &pos, ",RTSCTS");

	if (clocal)
	    gensio_pos_snprintf(buf, buflen, &pos, ",CLOCAL");

	if (hangup_when_done)
	    gensio_pos_snprintf(buf, buflen, &pos, ",HANGUP_WHEN_DONE");

    }
    if (!sdata->write_only && sdata->iod) {
	rv = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_RTS,
			    true, (intptr_t) &tval);
	if (rv)
	    return rv;
	if (tval)
	    gensio_pos_snprintf(buf, buflen, &pos, " RTSHI");
	else
	    gensio_pos_snprintf(buf, buflen, &pos, " RTSLO");

	rv = o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_DTR,
			    true, (intptr_t) &tval);
	if (rv)
	    return rv;
	if (tval)
	    gensio_pos_snprintf(buf, buflen, &pos, " DTRHI");
	else
	    gensio_pos_snprintf(buf, buflen, &pos, " DTRLO");
    } else {
	gensio_pos_snprintf(buf, buflen, &pos, " offline");
    }

    *datalen = pos;
    return 0;
}

static int
sterm_control(void *handler_data, struct gensio_iod *iod,
	      bool get, unsigned int option, char *data, gensiods *datalen)
{
    struct sterm_data *sdata = handler_data;

    switch (option) {
    case GENSIO_CONTROL_SEND_BREAK:
	if (get)
	    break;
	return sdata->o->iod_control(sdata->iod, GENSIO_IOD_CONTROL_SEND_BREAK,
				     false, 0);
	return 0;

    case GENSIO_CONTROL_RADDR:
	if (!get)
	    break;
	if (strtoul(data, NULL, 0) > 0)
	    return GE_NOTFOUND;
	return sterm_control_raddr(sdata, data, datalen);

    case GENSIO_CONTROL_REMOTE_ID:
	if (!get)
	    return GE_NOTSUP;
	*datalen = snprintf(data, *datalen, "%d",
			    sdata->o->iod_get_fd(sdata->iod));
	return 0;

    default:
	break;
    }

    return GE_NOTSUP;
}

static int
sterm_write(void *handler_data, struct gensio_iod *iod, gensiods *rcount,
	    const struct gensio_sg *sg, gensiods sglen,
	    const char *const *auxdata)
{
    struct sterm_data *sdata = handler_data;
    int rv = sdata->o->write(iod, sg, sglen, rcount);

    if (rv && sdata->is_pty && rv == GE_IOERR)
	return GE_REMCLOSE; /* We don't seem to get EPIPE from ptys */
    return rv;
}

static int
sterm_do_read(struct gensio_iod *iod, void *data, gensiods count, gensiods *rcount,
	      const char ***auxdata, void *cb_data)
{
    struct sterm_data *sdata = cb_data;
    int rv = sdata->o->read(iod, data, count, rcount);

    if (rv && sdata->is_pty && rv == GE_IOERR)
	return GE_REMCLOSE; /* We don't seem to get EPIPE from ptys */
    return rv;
}

static void
sterm_read_ready(void *handler_data, struct gensio_iod *iod)
{
    struct sterm_data *sdata = handler_data;

    gensio_fd_ll_handle_incoming(sdata->ll, sterm_do_read, NULL, sdata);
}

static const struct gensio_fd_ll_ops sterm_fd_ll_ops = {
    .sub_open = sterm_sub_open,
    .check_close = sterm_check_close_drain,
    .free = sterm_free,
    .write = sterm_write,
    .read_ready = sterm_read_ready,
    .control = sterm_control
};

static int
handle_speedstr(struct sterm_data *sdata, const char *str)
{
    int val, rv;
    const char *rest = "";

    val = speedstr_to_speed(str, &rest);
    if (val < 10)
	/* Some parameters start a digit, ignore them. */
	return GE_INVAL;
    rv = set_serdef_from_speed(sdata, val, rest);
    if (rv)
	return rv;
    return 0;
}

static int
process_defserial_parm(struct sterm_data *sdata, const char *parm)
{
    int rv = 0, val;
    const char *str;
    bool bval;

    if (gensio_check_keyvalue(parm, "speed", &str) > 0) {
	rv = handle_speedstr(sdata, str);
    } else if (handle_speedstr(sdata, parm) == 0) {
	;
    } else if (gensio_check_keybool(parm, "xonxoff", &bval) > 0) {
	sdata->def_xonxoff = bval;
    } else if (gensio_check_keybool(parm, "rtscts", &bval) > 0) {
	sdata->def_rtscts = bval;
    } else if (gensio_check_keybool(parm, "local", &bval) > 0) {
	sdata->def_local = bval;
    } else if (gensio_check_keybool(parm, "hangup-when-done", &bval) > 0) {
	sdata->def_hupcl = bval;
    } else if (gensio_check_keybool(parm, "dtr", &bval) > 0) {
	sdata->dtr_set = true;
	sdata->dtr_val = bval;
    } else if (gensio_check_keybool(parm, "rts", &bval) > 0) {
	if (!sdata->dtr_set)
	    sdata->rts_first = true;
	sdata->rts_set = true;
	sdata->rts_val = bval;

    /* Everything below is deprecated. */
    } else if (strcasecmp(parm, "1STOPBIT") == 0) {
	sdata->def_stopbits = 1;
    } else if (strcasecmp(parm, "2STOPBITS") == 0) {
	sdata->def_stopbits = 2;
    } else if (strcasecmp(parm, "5DATABITS") == 0) {
	sdata->def_datasize = 5;
    } else if (strcasecmp(parm, "6DATABITS") == 0) {
	sdata->def_datasize = 6;
    } else if (strcasecmp(parm, "7DATABITS") == 0) {
	sdata->def_datasize = 7;
    } else if (strcasecmp(parm, "8DATABITS") == 0) {
	sdata->def_datasize = 8;
    } else if ((val = lookup_parity_str(parm)) != -1) {
	sdata->def_parity = val;
    } else if (strcasecmp(parm, "-XONXOFF") == 0) {
	sdata->def_xonxoff = 0;
    } else if (strcasecmp(parm, "-RTSCTS") == 0) {
	sdata->def_rtscts = 0;
    } else if (strcasecmp(parm, "-LOCAL") == 0) {
	sdata->def_local = 0;
    } else if (strcasecmp(parm, "HANGUP_WHEN_DONE") == 0) {
	sdata->def_hupcl = 1;
    } else if (strcasecmp(parm, "-HANGUP_WHEN_DONE") == 0) {
	sdata->def_hupcl = 0;
    } else {
	rv = GE_INVAL;
    }

    return rv;
}

static int
sergensio_process_parms(struct sterm_data *sdata)
{
    int argc, i;
    const char **argv;
    int err = gensio_str_to_argv(sdata->o, sdata->parms, &argc, &argv,
				 " \f\t\n\r\v,");
    const char *str;

    if (err)
	return err;

    for (i = 0; i < argc; i++) {
	if (gensio_check_keybool(argv[i], "wronly", &sdata->write_only) > 0) {
	    continue;
	} else if (gensio_check_keybool(argv[i], "nobreak",
					&sdata->disablebreak) > 0) {
	    continue;
	} else if (gensio_check_keyvalue(argv[i], "rs485", &str) > 0) {
	    if (sdata->rs485)
		sdata->o->free(sdata->o, sdata->rs485);
	    sdata->rs485 = gensio_strdup(sdata->o, str);
	    if (!sdata->rs485) {
		err = GE_NOMEM;
		break;
	    }
	    continue;

	/* The following is deprecated. */
	} else if (strcasecmp(argv[i], "-NOBREAK") == 0) {
	    sdata->disablebreak = false;
	    continue;
	}
	err = process_defserial_parm(sdata, argv[i]);
	if (err)
	    break;
    }

    gensio_argv_free(sdata->o, argv);
    return err;
}

static int
sergensio_setup_defaults(struct sterm_data *sdata)
{
    struct gensio_os_funcs *o = sdata->o;
    int val, err;
    char *str;

    err = gensio_get_default(o, "serialdev", "speed", false,
			     GENSIO_DEFAULT_STR, &str, NULL);
    if (err) {
	gensio_log(o, GENSIO_LOG_ERR, "Failed getting default serialdev speed:"
		   " %s\n", gensio_err_to_str(err));
	return err;
    }
    if (str) {
	if (handle_speedstr(sdata, str)) {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Default speed settings (%s) are invalid,"
		       " defaulting to 9600N81", str);
	    sdata->def_baud = 9600;
	    sdata->def_parity = SERGENSIO_PARITY_NONE;
	    sdata->def_datasize = 8;
	    sdata->def_stopbits = 1;
	}
	o->free(o, str);
    }

    val = 0;
    err = gensio_get_default(o, "serialdev", "xonxoff", false,
			     GENSIO_DEFAULT_BOOL, NULL, &val);
    if (err)
	return err;
    sdata->def_xonxoff = val;

    val = 0;
    err = gensio_get_default(o, "serialdev", "rtscts", false,
			     GENSIO_DEFAULT_BOOL, NULL, &val);
    if (err)
	return err;
    sdata->def_rtscts = val;

    val = 0;
    err = gensio_get_default(o, "serialdev", "local", false,
			     GENSIO_DEFAULT_BOOL, NULL, &val);
    if (err)
	return err;
    sdata->def_local = val;

    val = 0;
    err = gensio_get_default(o, "serialdev", "hangup_when_done", false,
			     GENSIO_DEFAULT_BOOL, NULL, &val);
    if (err)
	return err;
    sdata->def_hupcl = val;

    err = gensio_get_default(o, "serialdev", "rs485", false, GENSIO_DEFAULT_STR,
			     &str, NULL);
    if (err) {
	gensio_log(o, GENSIO_LOG_ERR, "Failed getting default serialdev rs485:"
		   " %s\n", gensio_err_to_str(err));
	return err;
    }
    sdata->rs485 = str;

    return 0;
}

static int
serialdev_gensio_alloc(const void *gdata, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **rio)
{
    const char *devname = gdata;
    struct sterm_data *sdata = o->zalloc(o, sizeof(*sdata));
    struct gensio *io;
    int err;
    char *comma;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    int i, ival;
    bool nouucplock_set = false, dummy = false;
    const char *s;
    char *end;

    if (!sdata)
	return GE_NOMEM;

    sdata->o = o;

    err = gensio_get_default(o, "sergensio", "nouucplock", false,
			     GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	goto out_err;
    sdata->no_uucp_lock = ival;
    err = gensio_get_default(o, "sergensio", "drain_time", false,
			     GENSIO_DEFAULT_INT, NULL, &sdata->drain_time);
    if (err)
	goto out_err;
    err = gensio_get_default(o, "sergensio", "char_drain_wait", false,
			     GENSIO_DEFAULT_INT, NULL, &sdata->char_drain_wait);
    if (err)
	goto out_err;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "drain_time", &s) > 0) {
	    if (strcmp(s, "off") == 0) {
		sdata->drain_time = -1;
	    } else {
		sdata->drain_time = strtol(s, &end, 0);
		if (*end != '\0')
		    goto out_inval;
	    }
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "char_drain_wait", &s) > 0) {
	    if (strcmp(s, "off") == 0) {
		sdata->char_drain_wait = -1;
	    } else {
		sdata->char_drain_wait = strtol(s, &end, 0);
		if (*end != '\0')
		    goto out_inval;
	    }
	    continue;
	}
	if (gensio_check_keybool(args[i], "nouucplock",
				 &sdata->no_uucp_lock) > 0) {
	    nouucplock_set = true;
	    continue;
	}
	/* custspeed is ignored now */
	if (gensio_check_keybool(args[i], "custspeed", &dummy) > 0)
	    continue;
    out_inval:
	err = GE_INVAL;
	goto out_err;
    }

    sdata->timer = o->alloc_timer(o, serialdev_timeout, sdata);
    if (!sdata->timer)
	goto out_nomem;

    sdata->devname = gensio_strdup(o, devname);
    if (!sdata->devname)
	goto out_nomem;

    sdata->is_pty = is_a_pty(sdata->devname);

    comma = strchr(sdata->devname, ',');
    if (comma)
	*comma++ = '\0';

    if (!nouucplock_set) {
	const char *slash = strrchr(devname, '/');

	/*
	 * If the user didn't force it, don't do uucp locking if the
	 * devname is "tty", as in "/dev/tty".  That does all sorts
	 * of bad things...
	 */
	if (slash)
	    slash++;
	else
	    slash = devname;

	/* Don't do uucp locking on /dev/tty or ptys */
	sdata->no_uucp_lock = strcmp(slash, "tty") == 0 || sdata->is_pty;
    }

    err = sergensio_setup_defaults(sdata);
    if (err)
	goto out_err;

    if (comma) {
	sdata->parms = comma;
	err = sergensio_process_parms(sdata);
	if (err)
	    goto out_err;
    }
    sdata->deferred_op_runner = o->alloc_runner(o, sterm_deferred_op, sdata);
    if (!sdata->deferred_op_runner)
	goto out_nomem;

    sdata->lock = o->alloc_lock(o);
    if (!sdata->lock)
	goto out_nomem;

    sdata->ll = fd_gensio_ll_alloc(o, NULL, &sterm_fd_ll_ops, sdata,
				   max_read_size, sdata->write_only);
    if (!sdata->ll)
	goto out_nomem;

    /*
     * After this point, freeing the ll or io will free sdata through
     * the free callbacks.
     */

    io = base_gensio_alloc(o, sdata->ll, NULL, NULL, "serialdev",
			   cb, user_data);
    if (!io) {
	gensio_ll_free(sdata->ll);
	return GE_NOMEM;
    }

    err = sergensio_addclass(o, io, sergensio_sterm_func, sdata, &sdata->sio);
    if (err) {
	gensio_free(io);
	return err;
    }

    *rio = io;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    sterm_free(sdata);
    return err;
}

static int
str_to_serialdev_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio)
{
    return serialdev_gensio_alloc(str, args, o, cb, user_data, new_gensio);
}

int
gensio_init_serialdev(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "serialdev", str_to_serialdev_gensio,
			 serialdev_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
