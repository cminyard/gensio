/*
 *  ser_ioinfo - A program for connecting gensios.
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  gensio give you permission to combine gensio with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for gensio and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of gensio are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
 */

#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "ser_ioinfo.h"

struct ser_dump_data {
    char *signature;
    int speed;
    char parity;
    int datasize;
    int stopbits;
    unsigned int refcount;
    struct ioinfo *ioinfo;
    struct ser_info *serinfo;
};

struct ser_info {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    const char *signature;
    unsigned int modemstate_mask;
    unsigned int last_modemstate;
    unsigned int linestate_mask;
    unsigned int last_linestate;
};

static void
deref(struct ser_dump_data *ddata)
{
    struct ser_info *serinfo = ddata->serinfo;
    struct ser_info *rserinfo = ioinfo_othersubdata(ddata->ioinfo);
    struct gensio_os_funcs *o = serinfo->o;
    unsigned int refcount;

    gensio_os_funcs_lock(o, serinfo->lock);
    refcount = --ddata->refcount;
    gensio_os_funcs_unlock(o, serinfo->lock);
    if (refcount == 0) {
	const char *cts = rserinfo->last_modemstate & GENSIO_SER_MODEMSTATE_CTS
	    ? " cts" : "";
	const char *dsr = rserinfo->last_modemstate & GENSIO_SER_MODEMSTATE_DSR
	    ? " dsr" : "";
	const char *dcd = rserinfo->last_modemstate & GENSIO_SER_MODEMSTATE_CD
	    ? " dcd" : "";
	const char *ri = rserinfo->last_modemstate & GENSIO_SER_MODEMSTATE_RI
	    ? " ri" : "";
	if (ddata->signature)
	    ioinfo_out(ddata->ioinfo,
		       "Signature: %s\r\n", ddata->signature);
	ioinfo_out(ddata->ioinfo,
		   "Speed: %d%c%d%d%s%s%s%s\r\n", ddata->speed,
		   ddata->parity, ddata->datasize, ddata->stopbits,
		   cts, dsr, dcd, ri);
	if (ddata->signature)
	    gensio_os_funcs_zfree(o, ddata->signature);
	gensio_os_funcs_zfree(o, ddata);
    }
}

static void
speed_done(struct gensio *io, int err, const char *buf, gensiods len,
	   void *cb_data)
{
    struct ser_dump_data *ddata = cb_data;

    if (err) {
	ddata->speed = 0;
    } else {
	ddata->speed = strtoul(buf, NULL, 0);
    }
    deref(ddata);
}

static void
signature_done(struct gensio *io, int err, const char *buf, gensiods len,
	       void *cb_data)
{
    struct ser_dump_data *ddata = cb_data;
    struct gensio_os_funcs *o = ddata->serinfo->o;

    if (buf) {
	if (ddata->signature)
	    gensio_os_funcs_zfree(o, ddata->signature);
	ddata->signature = gensio_os_funcs_zalloc(o, len + 1);
	if (ddata->signature) {
	    memcpy(ddata->signature, buf, len);
	    ddata->signature[len] = '\0';
	}
    }
    deref(ddata);
}

static void
parity_done(struct gensio *io, int err, const char *buf, gensiods len,
	    void *cb_data)
{
    struct ser_dump_data *ddata = cb_data;

    if (err) {
	ddata->parity = '?';
    } else {
	if (strcmp(buf, "none") == 0)
	    ddata->parity = 'N';
	else if (strcmp(buf, "odd") == 0)
	    ddata->parity = 'O';
	else if (strcmp(buf, "even") == 0)
	    ddata->parity = 'E';
	else if (strcmp(buf, "mark") == 0)
	    ddata->parity = 'M';
	else if (strcmp(buf, "space") == 0)
	    ddata->parity = 'S';
	else
	    ddata->parity = '?';
    }
    deref(ddata);
}

static void
datasize_done(struct gensio *io, int err, const char *buf, gensiods len,
	      void *cb_data)
{
    struct ser_dump_data *ddata = cb_data;

    if (err) {
	ddata->datasize = 0;
    } else {
	ddata->datasize = strtoul(buf, NULL, 0);
    }
    deref(ddata);
}

static void
stopbits_done(struct gensio *io, int err, const char *buf, gensiods len,
	      void *cb_data)
{
    struct ser_dump_data *ddata = cb_data;

    if (err) {
	ddata->stopbits = 0;
    } else {
	ddata->stopbits = strtoul(buf, NULL, 0);
    }
    deref(ddata);
}

static void
control_val_set(struct gensio *io, int err, const char *buf, gensiods len,
		void *cb_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    unsigned int op = (intptr_t) cb_data;
    struct gensio *rio;

    rio = ioinfo_otherio(ioinfo);
    if (!rio)
	return;

    if (err) {
	if (op == GENSIO_ACONTROL_SER_SIGNATURE) {
	    /* Supply a dummy one. */
	    buf = "gensiot";
	    len = strlen(buf);
	} else {
	    return;
	}
    }
    gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_SET,
		    op, buf, len, NULL, NULL, NULL);
}

static void
s2n_modemstate(struct gensio *io, unsigned int modemstate)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct ser_info *serinfo = ioinfo_subdata(ioinfo);
    struct ser_info *oserinfo = ioinfo_othersubdata(ioinfo);
    unsigned int val = oserinfo->last_modemstate & modemstate;
    char str[10];
    gensiods len;

    snprintf(str, sizeof(str), "%d", val);
    len = strlen(str);

    serinfo->modemstate_mask = modemstate;
    gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST,
		   GENSIO_CONTROL_SET, GENSIO_CONTROL_SER_MODEMSTATE,
		   str, &len);
}

static void
s2n_linestate(struct gensio *io, unsigned int linestate)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct ser_info *serinfo = ioinfo_subdata(ioinfo);
    struct ser_info *oserinfo = ioinfo_othersubdata(ioinfo);
    unsigned int val = oserinfo->last_linestate & linestate;
    char str[10];
    gensiods len;

    snprintf(str, sizeof(str), "%d", val);
    len = strlen(str);

    serinfo->linestate_mask = linestate;
    gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST,
		   GENSIO_CONTROL_SET, GENSIO_CONTROL_SER_LINESTATE,
		   str, &len);
}

static void
s2n_send_up(struct gensio *io, unsigned int option, const char *str,
	    gensio_control_done done, void *cb_data)
{
    gensio_acontrol(io, GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_SET,
		    option, str, strlen(str), done, cb_data, NULL);
}

static void
s2n_send_up_num(struct gensio *io, unsigned int option, unsigned int num,
		gensio_control_done done, void *cb_data)
{
    char str[10];

    snprintf(str, sizeof(str), "%d", num);
    gensio_acontrol(io, GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_SET,
		    option, str, strlen(str), done, cb_data, NULL);
}

static int
handle_sio_event(struct gensio *io, int event,
		 unsigned char *buf, gensiods *buflen)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gensio *rio = ioinfo_otherio(ioinfo);
    struct ser_info *serinfo = ioinfo_subdata(ioinfo);
    gensiods dummy_len = 1;
    int rv;

    if (gensio_is_client(io)) {
	switch (event) {
	case GENSIO_EVENT_SER_MODEMSTATE:
	    serinfo->last_modemstate = *((unsigned int *) buf);
	    /* If we are client to server, sent it upstream. */
	    if (rio && gensio_is_serial(rio) && !gensio_is_client(rio))
		gensio_control(rio, GENSIO_CONTROL_DEPTH_FIRST,
			       GENSIO_CONTROL_SET,
			       GENSIO_CONTROL_SER_MODEMSTATE,
			       (char *) buf, buflen);
	    return 0;

	case GENSIO_EVENT_SER_LINESTATE:
	    serinfo->last_linestate = *((unsigned int *) buf);
	    /* If we are client to server, sent it upstream. */
	    if (rio && gensio_is_serial(rio) && !gensio_is_client(rio))
		gensio_control(rio, GENSIO_CONTROL_DEPTH_FIRST,
			       GENSIO_CONTROL_SET,
			       GENSIO_CONTROL_SER_LINESTATE,
			       (char *) buf, buflen);
	    return 0;
	}
	return GE_NOTSUP;
    }

    if (!rio)
	return GE_NOTSUP;

    /* Telnet breaks work even if you don't have RFC2217 support. */
    if (event == GENSIO_EVENT_SEND_BREAK) {
	gensio_control(rio, GENSIO_CONTROL_DEPTH_FIRST,
		       GENSIO_CONTROL_SET,
		       GENSIO_CONTROL_SEND_BREAK,
		       (char *) buf, buflen);
	return 0;
    }

    if (!rio || !gensio_is_client(rio) || !gensio_is_serial(rio))
	/* Both ends are servers or the other end isn't serial. */
	return GE_NOTSUP;

    switch (event) {
    case GENSIO_EVENT_SER_MODEMSTATE_MASK:
	s2n_modemstate(rio, *((unsigned int *) buf));
	return 0;

    case GENSIO_EVENT_SER_LINESTATE_MASK:
	s2n_linestate(rio, *((unsigned int *) buf));
	return 0;

    case GENSIO_EVENT_SER_FLOW_STATE:
	gensio_control(rio, GENSIO_CONTROL_DEPTH_FIRST,
		       GENSIO_CONTROL_SET, GENSIO_CONTROL_SER_FLOWCONTROL_STATE,
		       "0", &dummy_len);
	return 0;

    case GENSIO_EVENT_SER_FLUSH:
	gensio_control(rio, GENSIO_CONTROL_DEPTH_FIRST,
		       GENSIO_CONTROL_SET, GENSIO_CONTROL_SER_FLUSH,
		       "0", &dummy_len);
	return 0;

    case GENSIO_EVENT_SER_SIGNATURE:
	rv = gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_SET,
			     GENSIO_ACONTROL_SER_SIGNATURE,
			     "", 0, control_val_set,
			     (void *) (intptr_t) GENSIO_ACONTROL_SER_SIGNATURE,
			     NULL);
	if (rv)
	    /* Supply a dummy value. */
	    gensio_acontrol(io, GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_SET,
			    GENSIO_ACONTROL_SER_SIGNATURE,
			    "gensiot", 7, NULL, NULL, NULL);
	return 0;

    case GENSIO_EVENT_SER_BAUD:
	s2n_send_up_num(rio, GENSIO_ACONTROL_SER_BAUD, *((int *) buf),
			control_val_set,
			(void *) (intptr_t) GENSIO_ACONTROL_SER_BAUD);
	return 0;

    case GENSIO_EVENT_SER_DATASIZE:
	s2n_send_up_num(rio, GENSIO_ACONTROL_SER_DATASIZE, *((int *) buf),
			control_val_set,
			(void *) (intptr_t) GENSIO_ACONTROL_SER_DATASIZE);
	return 0;

    case GENSIO_EVENT_SER_PARITY:
	s2n_send_up(rio, GENSIO_ACONTROL_SER_PARITY,
		    gensio_parity_to_str(*((int *) buf)),
		    control_val_set,
		    (void *) (intptr_t) GENSIO_ACONTROL_SER_PARITY);
	return 0;

    case GENSIO_EVENT_SER_STOPBITS:
	s2n_send_up_num(rio, GENSIO_ACONTROL_SER_STOPBITS, *((int *) buf),
			control_val_set,
			(void *) (intptr_t) GENSIO_ACONTROL_SER_STOPBITS);
	return 0;

    case GENSIO_EVENT_SER_FLOWCONTROL:
	s2n_send_up(rio, GENSIO_ACONTROL_SER_FLOWCONTROL,
		    gensio_flowcontrol_to_str(*((int *) buf)),
		    control_val_set,
		    (void *) (intptr_t) GENSIO_ACONTROL_SER_FLOWCONTROL);
	return 0;

    case GENSIO_EVENT_SER_IFLOWCONTROL:
	s2n_send_up(rio, GENSIO_ACONTROL_SER_IFLOWCONTROL,
		    gensio_flowcontrol_to_str(*((int *) buf)),
		    control_val_set,
		    (void *) (intptr_t) GENSIO_ACONTROL_SER_IFLOWCONTROL);
	return 0;

    case GENSIO_EVENT_SER_SBREAK:
	s2n_send_up(rio, GENSIO_ACONTROL_SER_SBREAK,
		    gensio_onoff_to_str(*((int *) buf)),
		    control_val_set,
		    (void *) (intptr_t) GENSIO_ACONTROL_SER_SBREAK);
	return 0;

    case GENSIO_EVENT_SER_DTR:
	s2n_send_up(rio, GENSIO_ACONTROL_SER_DTR,
		    gensio_onoff_to_str(*((int *) buf)),
		    control_val_set,
		    (void *) (intptr_t) GENSIO_ACONTROL_SER_DTR);
	return 0;

    case GENSIO_EVENT_SER_RTS:
	s2n_send_up(rio, GENSIO_ACONTROL_SER_RTS,
		    gensio_onoff_to_str(*((int *) buf)),
		    control_val_set,
		    (void *) (intptr_t) GENSIO_ACONTROL_SER_RTS);
	return 0;

    case GENSIO_EVENT_SER_SYNC:
	gensio_control(rio, GENSIO_CONTROL_DEPTH_FIRST,
		       GENSIO_CONTROL_SET,
		       GENSIO_CONTROL_SEND_BREAK,
		       (char *) buf, buflen);
	return 0;
    }

    return GE_NOTSUP;
}

static bool
handle_sio_escape(struct ioinfo *ioinfo, char c)
{
    struct ser_info *serinfo = ioinfo_subdata(ioinfo);
    struct gensio *rio = ioinfo_otherio(ioinfo);
    struct gensio_os_funcs *o = serinfo->o;
    struct ser_dump_data *ddata;
    int rv;

    if (!gensio_is_client(rio))
	return false;

    switch (c) {
    case 'd': /* Dump serial data. */
	ddata = gensio_os_funcs_zalloc(o, sizeof(*ddata));
	if (!ddata)
	    return false;
	memset(ddata, 0, sizeof(*ddata));
	ddata->ioinfo = ioinfo;
	ddata->serinfo = serinfo;
	gensio_os_funcs_lock(o, serinfo->lock);
	rv = gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_GET,
			     GENSIO_ACONTROL_SER_SIGNATURE,
			     "0", 0, signature_done, ddata, NULL);
	if (!rv)
	    ddata->refcount++;
	rv = gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_GET,
			     GENSIO_ACONTROL_SER_BAUD,
			     "0", 0, speed_done, ddata, NULL);
	if (!rv)
	    ddata->refcount++;
	rv = gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_GET,
			     GENSIO_ACONTROL_SER_PARITY,
			     "0", 0, parity_done, ddata, NULL);
	if (!rv)
	    ddata->refcount++;
	rv = gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_GET,
			     GENSIO_ACONTROL_SER_DATASIZE,
			     "0", 0, datasize_done, ddata, NULL);
	if (!rv)
	    ddata->refcount++;
	rv = gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			     GENSIO_CONTROL_GET,
			     GENSIO_ACONTROL_SER_STOPBITS,
			     "0", 0, stopbits_done, ddata, NULL);
	if (!rv)
	    ddata->refcount++;
	gensio_os_funcs_unlock(o, serinfo->lock);
	if (ddata->refcount == 0) {
	    gensio_os_funcs_zfree(o, ddata);
	    return false;
	}
	break;
    case 's': /* Set baud rate */
	return true; /* Remain in escape mode. */
    case 'n': /* No parity */
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_PARITY,
			"none", 4, NULL, NULL, NULL);
	break;
    case 'o': /* Odd parity */
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_PARITY,
			"odd", 3, NULL, NULL, NULL);
	break;
    case 'e': /* Even parity */
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_PARITY,
			"even", 4, NULL, NULL, NULL);
	break;
    case '5': /* 5 bit data */
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_DATASIZE,
			"5", 1, NULL, NULL, NULL);
	break;
    case '6': /* 6 bit data */
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_DATASIZE,
			"6", 1, NULL, NULL, NULL);
	break;
    case '7': /* 7 bit data */
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_DATASIZE,
			"7", 1, NULL, NULL, NULL);
	break;
    case '8': /* 8 bit data */
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_DATASIZE,
			"8", 1, NULL, NULL, NULL);
	break;
    case '1': /* 1 stop bit */
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_STOPBITS,
			"1", 1, NULL, NULL, NULL);
	break;
    case '2': /* 2 stop bits */
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_STOPBITS,
			"2", 1, NULL, NULL, NULL);
	break;
    case 'x':
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_FLOWCONTROL,
			"xonxoff", 6, NULL, NULL, NULL);
	break;
    case 'r':
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_FLOWCONTROL,
			"rtscts", 6, NULL, NULL, NULL);
	break;
    case 'f':
	gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_SET,
			GENSIO_ACONTROL_SER_FLOWCONTROL,
			"none", 4, NULL, NULL, NULL);
	break;
    }

    return false;
}

static void
handle_sio_multichar_escape(struct ioinfo *ioinfo, char *escape_data)
{
    struct gensio *rio;

    rio = ioinfo_otherio(ioinfo);
    if (!rio || !gensio_is_client(rio) || !gensio_is_serial(rio))
	return;

    gensio_acontrol(rio, GENSIO_CONTROL_DEPTH_FIRST,
		    GENSIO_CONTROL_GET,
		    GENSIO_ACONTROL_SER_BAUD,
		    escape_data + 1, strlen(escape_data + 1), NULL, NULL, NULL);
}

static struct ioinfo_sub_handlers suh = {
    .handle_event = handle_sio_event,
    .handle_escape = handle_sio_escape,
    .handle_multichar_escape = handle_sio_multichar_escape
};

void *
alloc_ser_ioinfo(struct gensio_os_funcs *o,
		 const char *signature,
		 struct ioinfo_sub_handlers **sh)
{
    struct ser_info *subdata;

    subdata = gensio_os_funcs_zalloc(o, sizeof(*subdata));
    if (subdata) {
	subdata->o = o;
	subdata->lock = gensio_os_funcs_alloc_lock(o);
	if (!subdata->lock) {
	    gensio_os_funcs_zfree(o, subdata);
	    subdata = NULL;
	} else {
	    subdata->signature = signature;
	    *sh = &suh;
	}
    }
    return subdata;
}

void
free_ser_ioinfo(void *i_subdata)
{
    struct ser_info *subdata = i_subdata;

    gensio_os_funcs_free_lock(subdata->o, subdata->lock);
    gensio_os_funcs_zfree(subdata->o, subdata);
}
