/*
 *  ser_ioinfo - A program for connecting gensios.
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <string.h>
#include <stdlib.h>
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
};

struct ser_info {
    const char *signature;
    unsigned int modemstate_mask;
    unsigned int last_modemstate;
    unsigned int linestate_mask;
    unsigned int last_linestate;
};

static void
deref(struct ser_dump_data *ddata)
{
    ddata->refcount--;
    if (ddata->refcount == 0) {
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
	    free(ddata->signature);
	free(ddata);
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

    if (sig) {
	if (ddata->signature)
	    free(ddata->signature);
	ddata->signature = strndup(sig, len);
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
    enum s2n_ser_ops op = (long) cb_data;
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
s2n_modemstate(struct sergensio *sio, unsigned int modemstate)
{
    struct ioinfo *ioinfo = sergensio_get_user_data(sio);
    struct ser_info *serinfo = ioinfo_subdata(ioinfo);
    struct ser_info *oserinfo = ioinfo_othersubdata(ioinfo);

    serinfo->modemstate_mask = modemstate;
    sergensio_modemstate(sio, (oserinfo->last_modemstate &
			       serinfo->modemstate_mask));
}

static void
s2n_linestate(struct sergensio *sio, unsigned int linestate)
{
    struct ioinfo *ioinfo = sergensio_get_user_data(sio);
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
	s2n_modemstate(rsio, *((unsigned int *) buf));
	return 0;

    case GENSIO_EVENT_SER_LINESTATE:
	s2n_linestate(rsio, *((unsigned int *) buf));
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
    struct sergensio *sio;
    struct ser_dump_data *ddata;
    int rv;

    sio = gensio_to_sergensio(ioinfo_otherio(ioinfo));
    if (!sio || !sergensio_is_client(sio))
	return false;

    switch (c) {
    case 'd': /* Dump serial data. */
	ddata = malloc(sizeof(*ddata));
	if (!ddata)
	    return false;
	memset(ddata, 0, sizeof(*ddata));
	ddata->ioinfo = ioinfo;
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
	if (ddata->refcount == 0) {
	    free(ddata);
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

    subdata = malloc(sizeof(*subdata));
    if (subdata) {
	memset(subdata, 0, sizeof(*subdata));
	subdata->signature = signature;
	*sh = &suh;
    }
    return subdata;
}

void
free_ser_ioinfo(void *subdata)
{
    free(subdata);
}
