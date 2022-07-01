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

#include <gensio/sergensio.h>
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
    struct gensio_os_funcs *o = serinfo->o;
    unsigned int refcount;

    gensio_os_funcs_lock(o, serinfo->lock);
    refcount = --ddata->refcount;
    gensio_os_funcs_unlock(o, serinfo->lock);
    if (refcount == 0) {
	if (ddata->signature)
	    ioinfo_out(ddata->ioinfo,
		       "Signature: %s\r\n"
		       "Speed: %d%c%d%d\r\n", ddata->signature, ddata->speed,
		       ddata->parity, ddata->datasize, ddata->stopbits);
	else
	    ioinfo_out(ddata->ioinfo,
		       "Speed: %d%c%d%d\r\n", ddata->speed,
		       ddata->parity, ddata->datasize, ddata->stopbits);
	if (ddata->signature)
	    gensio_os_funcs_zfree(o, ddata->signature);
	gensio_os_funcs_zfree(o, ddata);
    }
}

static void
speed_done(struct sergensio *sio, int err, unsigned int val, void *cb_data)
{
    struct ser_dump_data *ddata = cb_data;

    ddata->speed = val;
    deref(ddata);
}

static void
signature_done(struct sergensio *sio, int err,
	       const char *sig, unsigned int len,
	       void *cb_data)
{
    struct ser_dump_data *ddata = cb_data;
    struct gensio_os_funcs *o = ddata->serinfo->o;

    if (sig) {
	if (ddata->signature)
	    gensio_os_funcs_zfree(o, ddata->signature);
	ddata->signature = gensio_os_funcs_zalloc(o, len + 1);
	if (ddata->signature) {
	    memcpy(ddata->signature, sig, len);
	    ddata->signature[len] = '\0';
	}
    }
    deref(ddata);
}

static void
parity_done(struct sergensio *sio, int err, unsigned int val, void *cb_data)
{
    struct ser_dump_data *ddata = cb_data;

    switch (val) {
    case SERGENSIO_PARITY_NONE: ddata->parity = 'N'; break;
    case SERGENSIO_PARITY_ODD: ddata->parity = 'O'; break;
    case SERGENSIO_PARITY_EVEN: ddata->parity = 'E'; break;
    case SERGENSIO_PARITY_MARK: ddata->parity = 'M'; break;
    case SERGENSIO_PARITY_SPACE: ddata->parity = 'S'; break;
    default: ddata->parity = '?'; break;
    }
    deref(ddata);
}

static void
datasize_done(struct sergensio *sio, int err, unsigned int val, void *cb_data)
{
    struct ser_dump_data *ddata = cb_data;

    ddata->datasize = val;
    deref(ddata);
}

static void
stopbits_done(struct sergensio *sio, int err, unsigned int val, void *cb_data)
{
    struct ser_dump_data *ddata = cb_data;

    ddata->stopbits = val;
    deref(ddata);
}

enum s2n_ser_ops {
    S2N_BAUD = 0,
    S2N_DATASIZE,
    S2N_PARITY,
    S2N_STOPBITS,
    S2N_FLOWCONTROL,
    S2N_IFLOWCONTROL,
    S2N_BREAK,
    S2N_DTR,
    S2N_RTS
};

static void
sergensio_val_set(struct sergensio *sio, int err,
		  unsigned int val, void *cb_data)
{
    struct ioinfo *ioinfo = sergensio_get_user_data(sio);
    enum s2n_ser_ops op = (intptr_t) cb_data;
    struct sergensio *rsio;

    rsio = gensio_to_sergensio(ioinfo_otherio(ioinfo));
    if (!rsio)
	return;

    switch (op) {
    case S2N_BAUD:
	sergensio_baud(rsio, val, NULL, NULL);
	break;

    case S2N_DATASIZE:
	sergensio_datasize(rsio, val, NULL, NULL);
	break;

    case S2N_PARITY:
	sergensio_parity(rsio, val, NULL, NULL);
	break;

    case S2N_STOPBITS:
	sergensio_stopbits(rsio, val, NULL, NULL);
	break;

    case S2N_FLOWCONTROL:
	sergensio_flowcontrol(rsio, val, NULL, NULL);
	break;

    case S2N_IFLOWCONTROL:
	sergensio_iflowcontrol(rsio, val, NULL, NULL);
	break;

    case S2N_BREAK:
	sergensio_sbreak(rsio, val, NULL, NULL);
	break;

    case S2N_DTR:
	sergensio_dtr(rsio, val, NULL, NULL);
	break;

    case S2N_RTS:
	sergensio_rts(rsio, val, NULL, NULL);
	break;
    }
}

static void
s2n_modemstate(struct gensio *io, struct sergensio *sio,
	       unsigned int modemstate)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct ser_info *serinfo = ioinfo_subdata(ioinfo);
    struct ser_info *oserinfo = ioinfo_othersubdata(ioinfo);

    serinfo->modemstate_mask = modemstate;
    sergensio_modemstate(sio, (oserinfo->last_modemstate &
			       serinfo->modemstate_mask));
}

static void
s2n_linestate(struct gensio *io, struct sergensio *sio,
	      unsigned int linestate)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct ser_info *serinfo = ioinfo_subdata(ioinfo);
    struct ser_info *oserinfo = ioinfo_othersubdata(ioinfo);

    serinfo->linestate_mask = linestate;
    sergensio_linestate(sio, (oserinfo->last_linestate &
			      serinfo->linestate_mask));
}

static int
handle_sio_event(struct gensio *io, int event,
		 unsigned char *buf, gensiods *buflen)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gensio *rio = ioinfo_otherio(ioinfo);
    struct ser_info *serinfo = ioinfo_subdata(ioinfo);
    struct ser_info *rserinfo = ioinfo_othersubdata(ioinfo);
    struct sergensio *sio, *rsio;

    sio = gensio_to_sergensio(io);
    if (!sio)
	return GE_NOTSUP;

    if (event == GENSIO_EVENT_SER_SIGNATURE) {
	sergensio_signature(sio, serinfo->signature,
			    strlen(serinfo->signature), NULL, NULL);
	return 0;
    }

    rsio = gensio_to_sergensio(rio);
    if (!rsio)
	return GE_NOTSUP;

    /* Telnet breaks work even if you don't have RFC2217 support. */
    if (event == GENSIO_EVENT_SEND_BREAK) {
	sergensio_send_break(rsio);
	return 0;
    }

    if (sergensio_is_client(sio)) {
	unsigned int state;

	if (sergensio_is_client(rsio))
	    /* Both ends are clients. */
	    return GE_NOTSUP;

	switch (event) {
	case GENSIO_EVENT_SER_MODEMSTATE:
	    serinfo->last_modemstate = *((unsigned int *) buf);
	    state = serinfo->last_modemstate & rserinfo->modemstate_mask;
	    if (state & 4)
		sergensio_modemstate(rsio, state);
	    return 0;

	case GENSIO_EVENT_SER_LINESTATE:
	    serinfo->last_linestate = *((unsigned int *) buf);
	    state = serinfo->last_linestate & rserinfo->linestate_mask;
	    if (state & 4)
		sergensio_linestate(rsio, state);
	    return 0;
	}
	return GE_NOTSUP;
    }

    if (!sergensio_is_client(rsio))
	/* Both ends are servers. */
	return GE_NOTSUP;

    switch (event) {
    case GENSIO_EVENT_SER_MODEMSTATE:
	s2n_modemstate(rio, rsio, *((unsigned int *) buf));
	return 0;

    case GENSIO_EVENT_SER_LINESTATE:
	s2n_linestate(rio, rsio, *((unsigned int *) buf));
	return 0;

    case GENSIO_EVENT_SER_FLOW_STATE:
	sergensio_flowcontrol_state(rsio, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_FLUSH:
	sergensio_flush(rsio, *((int *) buf));
	return 0;

    case GENSIO_EVENT_SER_BAUD:
	sergensio_baud(rsio, *((int *) buf),
		       sergensio_val_set, (void *) (long) S2N_BAUD);
	return 0;

    case GENSIO_EVENT_SER_DATASIZE:
	sergensio_datasize(rsio, *((int *) buf),
			   sergensio_val_set, (void *) (long) S2N_DATASIZE);
	return 0;

    case GENSIO_EVENT_SER_PARITY:
	sergensio_parity(rsio, *((int *) buf),
			 sergensio_val_set, (void *) (long) S2N_PARITY);
	return 0;

    case GENSIO_EVENT_SER_STOPBITS:
	sergensio_stopbits(rsio, *((int *) buf),
			   sergensio_val_set, (void *) (long) S2N_STOPBITS);
	return 0;

    case GENSIO_EVENT_SER_FLOWCONTROL:
	sergensio_flowcontrol(rsio, *((int *) buf),
			      sergensio_val_set,
			      (void *) (long) S2N_FLOWCONTROL);
	return 0;

    case GENSIO_EVENT_SER_IFLOWCONTROL:
	sergensio_iflowcontrol(rsio, *((int *) buf),
			       sergensio_val_set,
			       (void *) (long) S2N_IFLOWCONTROL);
	return 0;

    case GENSIO_EVENT_SER_SBREAK:
	sergensio_sbreak(rsio, *((int *) buf),
			 sergensio_val_set, (void *) (long) S2N_BREAK);
	return 0;

    case GENSIO_EVENT_SER_DTR:
	sergensio_dtr(rsio, *((int *) buf),
		      sergensio_val_set, (void *) (long) S2N_DTR);
	return 0;

    case GENSIO_EVENT_SER_RTS:
	sergensio_rts(rsio, *((int *) buf),
		      sergensio_val_set, (void *) (long) S2N_RTS);
	return 0;

    case GENSIO_EVENT_SER_SYNC:
	sergensio_send_break(rsio);
	return 0;
    }

    return GE_NOTSUP;
}

static bool
handle_sio_escape(struct ioinfo *ioinfo, char c)
{
    struct ser_info *serinfo = ioinfo_subdata(ioinfo);
    struct gensio_os_funcs *o = serinfo->o;
    struct sergensio *sio;
    struct ser_dump_data *ddata;
    int rv;

    sio = gensio_to_sergensio(ioinfo_otherio(ioinfo));
    if (!sio || !sergensio_is_client(sio))
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
	rv = sergensio_signature(sio, NULL, 0, signature_done, ddata);
	if (!rv)
	    ddata->refcount++;
	rv = sergensio_baud(sio, 0, speed_done, ddata);
	if (!rv)
	    ddata->refcount++;
	rv = sergensio_parity(sio, 0, parity_done, ddata);
	if (!rv)
	    ddata->refcount++;
	rv = sergensio_datasize(sio, 0, datasize_done, ddata);
	if (!rv)
	    ddata->refcount++;
	rv = sergensio_stopbits(sio, 0, stopbits_done, ddata);
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
	sergensio_parity(sio, SERGENSIO_PARITY_NONE, NULL, NULL);
	break;
    case 'o': /* Odd parity */
	sergensio_parity(sio, SERGENSIO_PARITY_ODD, NULL, NULL);
	break;
    case 'e': /* Even parity */
	sergensio_parity(sio, SERGENSIO_PARITY_EVEN, NULL, NULL);
	break;
    case '5': /* 5 bit data */
	sergensio_datasize(sio, 5, NULL, NULL);
	break;
    case '6': /* 6 bit data */
	sergensio_datasize(sio, 6, NULL, NULL);
	break;
    case '7': /* 7 bit data */
	sergensio_datasize(sio, 7, NULL, NULL);
	break;
    case '8': /* 8 bit data */
	sergensio_datasize(sio, 8, NULL, NULL);
	break;
    case '1': /* 1 stop bit */
	sergensio_stopbits(sio, 1, NULL, NULL);
	break;
    case '2': /* 2 stop bits */
	sergensio_stopbits(sio, 2, NULL, NULL);
	break;
    case 'x':
	sergensio_flowcontrol(sio, SERGENSIO_FLOWCONTROL_XON_XOFF, NULL, NULL);
	break;
    case 'r':
	sergensio_flowcontrol(sio, SERGENSIO_FLOWCONTROL_RTS_CTS, NULL, NULL);
	break;
    case 'f':
	sergensio_flowcontrol(sio, SERGENSIO_FLOWCONTROL_NONE, NULL, NULL);
	break;
    }

    return false;
}

static void
handle_sio_multichar_escape(struct ioinfo *ioinfo, char *escape_data)
{
    struct sergensio *sio;
    int speed;
    char *end;

    speed = strtol(escape_data + 1, &end, 0);
    if (*end != '\0')
	return;

    sio = gensio_to_sergensio(ioinfo_otherio(ioinfo));
    if (!sio || !sergensio_is_client(sio))
	return;

    sergensio_baud(sio, speed, NULL, NULL);
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
