/*
 *  ioinfo - A program for connecting gensios.
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
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "ioinfo.h"

struct ioinfo {
    struct gensio *io;
    struct ioinfo *otherio;
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    bool ready;

    int escape_char;
    bool in_escape;
    char escape_data[11];
    unsigned int escape_pos;

    gensiods max_write;

    struct ioinfo_sub_handlers *sh;
    void *subdata;

    struct ioinfo_user_handlers *uh;
    void *userdata;

    struct ioinfo_oob *oob_head;
    struct ioinfo_oob *oob_tail;
};

void
ioinfo_out(struct ioinfo *ioinfo, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    ioinfo->uh->out(ioinfo, fmt, ap);
    va_end(ap);
}

void
ioinfo_err(struct ioinfo *ioinfo, char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    ioinfo->uh->err(ioinfo, fmt, ap);
    va_end(ap);
}

struct gensio *
ioinfo_otherio(struct ioinfo *ioinfo)
{
    return ioinfo->otherio->io;
}

struct gensio *
ioinfo_io(struct ioinfo *ioinfo)
{
    return ioinfo->io;
}

void *
ioinfo_subdata(struct ioinfo *ioinfo)
{
    return ioinfo->subdata;
}

void *
ioinfo_othersubdata(struct ioinfo *ioinfo)
{
    return ioinfo->otherio->subdata;
}

void *
ioinfo_userdata(struct ioinfo *ioinfo)
{
    return ioinfo->userdata;
}

struct ioinfo *
ioinfo_otherioinfo(struct ioinfo *ioinfo)
{
    return ioinfo->otherio;
}

void
ioinfo_sendoob(struct ioinfo *ioinfo, struct ioinfo_oob *oobinfo)
{
    struct gensio_os_funcs *o = ioinfo->o;

    gensio_os_funcs_lock(o, ioinfo->lock);
    oobinfo->next = NULL;
    if (ioinfo->oob_tail)
	ioinfo->oob_tail->next = oobinfo;
    else
	ioinfo->oob_head = oobinfo;
    ioinfo->oob_tail = oobinfo;
    gensio_os_funcs_unlock(o, ioinfo->lock);
    if (ioinfo->ready)
	gensio_set_write_callback_enable(ioinfo->io, true);
}

static bool
handle_escapechar(struct ioinfo *ioinfo, char c)
{
    bool rv = false;

    if (ioinfo->escape_pos > 0) {
	/* We are getting a multichar escape from the input. */
	if (c == '\r' || c == '\n') {
	    ioinfo->escape_data[ioinfo->escape_pos++] = '\0';
	    if (ioinfo->escape_pos > 1 && ioinfo->sh)
		ioinfo->sh->handle_multichar_escape(ioinfo,
						    ioinfo->escape_data);
	    ioinfo_out(ioinfo, ">", 1);
	    ioinfo->escape_pos = 0;
	    return false;
	}
	if (c == '\b' || c == 0x7f) {
	    if (ioinfo->escape_pos > 1) {
		ioinfo->escape_pos--;
		ioinfo_out(ioinfo, "\b \b", 3);
	    }
	    return true;
	}

	ioinfo_out(ioinfo, &c, 1);
	if (ioinfo->escape_pos < sizeof(ioinfo->escape_data) - 1)
	    ioinfo->escape_data[ioinfo->escape_pos++] = c;
	return true;
    }

    c = tolower(c);

    if (c == 'q') {
	ioinfo->uh->shutdown(ioinfo, IOINFO_SHUTDOWN_USER_REQ);
	return false;
    }

    if (!ioinfo->otherio->ready)
	return false;

    if (c == 'b') { /* Send a break */
	gensio_control(ioinfo->otherio->io, 0, GENSIO_CONTROL_SET,
		       GENSIO_CONTROL_SEND_BREAK, NULL, NULL);
	return false;
    }

    if (ioinfo->sh) {
	rv = ioinfo->sh->handle_escape(ioinfo, c);
	if (rv) {
	    ioinfo_out(ioinfo, "<", 1);
	    ioinfo->escape_data[0] = c;
	    ioinfo->escape_pos = 1;
	}
    }
    return rv;
}

static int
io_event(struct gensio *io, void *user_data, int event, int err,
	 unsigned char *buf, gensiods *buflen,
	 const char *const *auxdata)
{
    struct ioinfo *ioinfo = user_data;
    struct gensio_os_funcs *o = ioinfo->o;
    struct ioinfo *rioinfo = ioinfo->otherio;
    int rv, escapepos = -1;
    gensiods count = 0;
    static const char *oobaux[2] = { "oob", NULL };

    if (err) {
	gensio_os_funcs_lock(o, ioinfo->lock);
	gensio_set_read_callback_enable(ioinfo->io, false);
	gensio_set_write_callback_enable(ioinfo->io, false);
	ioinfo->ready = false;
	gensio_os_funcs_unlock(o, ioinfo->lock);
	if (err != GE_REMCLOSE) {
	    ioinfo_err(ioinfo, "read error: %s", gensio_err_to_str(err));
	    ioinfo->uh->shutdown(ioinfo, IOINFO_SHUTDOWN_ERR);
	} else {
	    ioinfo->uh->shutdown(ioinfo, IOINFO_SHUTDOWN_REMCLOSE);
	}
	return 0;
    }

    switch(event) {
    case GENSIO_EVENT_READ:
	if (*buflen == 0)
	    return 0;

	if (gensio_str_in_auxdata(auxdata, "oob")) {
	    if (ioinfo->uh->oobdata)
		ioinfo->uh->oobdata(ioinfo, buf, buflen);
	    return 0;
	}

	if (ioinfo->escape_char >= 0) {
	    unsigned int i;

	    if (ioinfo->in_escape) {
		if (ioinfo->escape_pos == 0 && buf[0] == ioinfo->escape_char) {
		    /* double escape means send one escape char. */
		    ioinfo->in_escape = false;
		} else {
		    ioinfo->in_escape = handle_escapechar(ioinfo, buf[0]);
		    *buflen = 1;
		    return 0;
		}
	    } else {
		for (i = 0; i < *buflen; i++) {
		    if (buf[i] == ioinfo->escape_char) {
			escapepos = i;
			*buflen = i;
			break;
		    }
		}
	    }
	}
	gensio_os_funcs_lock(o, rioinfo->lock);
	if (rioinfo->ready) {
	    gensiods wrsize = *buflen;

	    if (rioinfo->max_write && wrsize > rioinfo->max_write)
		wrsize = rioinfo->max_write;

	    rv = gensio_write(rioinfo->io, &count, buf, wrsize, NULL);
	    if (rv) {
		enum ioinfo_shutdown_reason reason = IOINFO_SHUTDOWN_ERR;
		if (rv == GE_REMCLOSE)
		    reason = IOINFO_SHUTDOWN_REMCLOSE;
		else
		    ioinfo_err(rioinfo, "write error(1): %s",
			       gensio_err_to_str(rv));
		if (ioinfo->ready)
		    gensio_set_read_callback_enable(ioinfo->io, false);
		gensio_os_funcs_unlock(o, rioinfo->lock);
		ioinfo->uh->shutdown(ioinfo, reason);
		return 0;
	    }
	} else {
	    /*
	     * The remote end isn't ready, cause the read to be
	     * disabled for now.  The remote gensio coming ready will
	     * enable read again.
	     */
	    if (ioinfo->ready)
		gensio_set_read_callback_enable(ioinfo->io, false);
	    count = 0;
	}
	if (count < *buflen) {
	    *buflen = count;
	    if (ioinfo->ready)
		gensio_set_read_callback_enable(ioinfo->io, false);
	    if (rioinfo->ready)
		gensio_set_write_callback_enable(rioinfo->io, true);
	} else if (escapepos >= 0) {
	    /*
	     * Don't do this if we didn't handle all the characters, get
	     * it the next time characters are handled.
	     */
	    (*buflen)++;
	    ioinfo->in_escape = true;
	    ioinfo->escape_pos = 0;
	}
	gensio_os_funcs_unlock(o, rioinfo->lock);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	gensio_os_funcs_lock(o, ioinfo->lock);
	if (ioinfo->oob_head && ioinfo->ready) {
	    struct ioinfo_oob *oob = ioinfo->oob_head;
	    gensiods count, wrsize = oob->len;

	    if (ioinfo->max_write && wrsize > ioinfo->max_write)
		wrsize = ioinfo->max_write;

	    rv = gensio_write(ioinfo->io, &count, oob->buf, wrsize, oobaux);
	    if (rv) {
		enum ioinfo_shutdown_reason reason = IOINFO_SHUTDOWN_ERR;
		if (rv == GE_REMCLOSE)
		    reason = IOINFO_SHUTDOWN_REMCLOSE;
		else
		    ioinfo_err(rioinfo, "write error(2): %s",
			       gensio_err_to_str(rv));
		gensio_set_write_callback_enable(ioinfo->io, false);
		gensio_set_read_callback_enable(ioinfo->io, false);
		ioinfo->ready = false;
		gensio_os_funcs_unlock(o, ioinfo->lock);
		ioinfo->uh->shutdown(ioinfo, reason);
		return 0;
	    }
	    if (count >= oob->len) {
		if (oob->send_done)
		    oob->send_done(oob->cb_data);
		ioinfo->oob_head = oob->next;
		if (ioinfo->oob_head == NULL)
	    /* No more OOB data. */
		    ioinfo->oob_tail = NULL;
	    } else {
		oob->buf += count;
		oob->len -= count;
	    }
	    gensio_os_funcs_unlock(o, ioinfo->lock);
	    return 0;
	}
	if (ioinfo->ready)
	    gensio_set_write_callback_enable(ioinfo->io, false);
	gensio_os_funcs_unlock(o, ioinfo->lock);

	gensio_os_funcs_lock(o, rioinfo->lock);
	if (rioinfo->ready)
	    gensio_set_read_callback_enable(rioinfo->io, true);
	gensio_os_funcs_unlock(o, rioinfo->lock);
	return 0;

    default:
	break;
    }

    gensio_os_funcs_lock(o, rioinfo->lock);
    if (!rioinfo->ready) {
	gensio_os_funcs_unlock(o, rioinfo->lock);
	return 0;
    }
    gensio_os_funcs_unlock(o, rioinfo->lock);

    rv = GE_NOTSUP;
    if (ioinfo->sh)
	rv = ioinfo->sh->handle_event(io, event, buf, buflen);

    if (rv == GE_NOTSUP && ioinfo->uh->event)
	rv = ioinfo->uh->event(ioinfo, io, event, err, buf, buflen, auxdata);

    return rv;
}

static void
set_max_write(struct ioinfo *ioinfo)
{
    int rv;
    char databuf[20];
    gensiods dbsize = sizeof(databuf);

    rv = gensio_control(ioinfo->io, 0, GENSIO_CONTROL_GET,
			GENSIO_CONTROL_MAX_WRITE_PACKET, databuf, &dbsize);
    if (!rv)
	ioinfo->max_write = strtoul(databuf, NULL, 0);
}

void
ioinfo_set_ready(struct ioinfo *ioinfo, struct gensio *io)
{
    struct ioinfo *rioinfo = ioinfo->otherio;

    gensio_os_funcs_lock(ioinfo->o, ioinfo->lock);
    ioinfo->io = io;
    set_max_write(ioinfo);
    gensio_set_callback(io, io_event, ioinfo);
    gensio_set_read_callback_enable(ioinfo->io, true);
    ioinfo->ready = true;
    gensio_os_funcs_unlock(ioinfo->o, ioinfo->lock);
    gensio_os_funcs_lock(rioinfo->o, rioinfo->lock);
    if (rioinfo->ready)
	gensio_set_read_callback_enable(rioinfo->io, true);
    gensio_os_funcs_unlock(rioinfo->o, rioinfo->lock);
}

void
ioinfo_set_not_ready(struct ioinfo *ioinfo)
{
    gensio_os_funcs_lock(ioinfo->o, ioinfo->lock);
    if (ioinfo->io) {
	gensio_set_read_callback_enable(ioinfo->io, false);
	gensio_set_write_callback_enable(ioinfo->io, false);
    }
    ioinfo->ready = false;
    gensio_os_funcs_unlock(ioinfo->o, ioinfo->lock);
}

void
ioinfo_set_otherioinfo(struct ioinfo *ioinfo, struct ioinfo *otherioinfo)
{
    ioinfo->otherio = otherioinfo;
    otherioinfo->otherio = ioinfo;
}

struct ioinfo *
alloc_ioinfo(struct gensio_os_funcs *o,
	     int escape_char,
	     struct ioinfo_sub_handlers *sh, void *subdata,
	     struct ioinfo_user_handlers *uh, void *userdata)
{
    struct ioinfo *ioinfo;

    ioinfo = gensio_os_funcs_zalloc(o, sizeof(*ioinfo));
    if (ioinfo) {
	memset(ioinfo, 0, sizeof(*ioinfo));
	ioinfo->lock = gensio_os_funcs_alloc_lock(o);
	if (!ioinfo->lock) {
	    gensio_os_funcs_zfree(o, ioinfo);
	    ioinfo = NULL;
	} else {
	    ioinfo->escape_char = escape_char;
	    ioinfo->o = o;
	    ioinfo->sh = sh;
	    ioinfo->subdata = subdata;
	    ioinfo->uh = uh;
	    ioinfo->userdata = userdata;
	}
    }
    return ioinfo;
}

void
free_ioinfo(struct ioinfo *ioinfo)
{
    gensio_os_funcs_free_lock(ioinfo->o, ioinfo->lock);
    gensio_os_funcs_zfree(ioinfo->o, ioinfo);
}
