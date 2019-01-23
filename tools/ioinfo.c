/*
 *  ioinfo - A program for connecting gensios.
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


#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "ioinfo.h"

struct ioinfo {
    struct gensio *io;
    struct ioinfo *otherio;
    struct gensio_os_funcs *o;
    bool ready;

    int escape_char;
    bool in_escape;
    char escape_data[11];
    unsigned int escape_pos;

    struct ioinfo_sub_handlers *sh;
    void *subdata;

    struct ioinfo_user_handlers *uh;
    void *userdata;
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

	ioinfo_out(ioinfo, &c, 1);
	if (ioinfo->escape_pos < sizeof(ioinfo->escape_data) - 1)
	    ioinfo->escape_data[ioinfo->escape_pos++] = c;
	return true;
    }

    c = tolower(c);

    if (c == 'q') {
	ioinfo->uh->shutdown(ioinfo);
	return false;
    }

    if (!ioinfo->otherio->ready)
	return false;

    if (c == 'b') { /* Send a break */
	gensio_control(ioinfo->otherio->io, 0, false,
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
io_event(struct gensio *io, int event, int err,
	 unsigned char *buf, gensiods *buflen,
	 const char *const *auxdata)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct ioinfo *rioinfo = ioinfo->otherio;
    int rv, escapepos = -1;
    gensiods count = 0;

    if (err) {
	if (err != EPIPE) /* EPIPE means the other end closed. */
	    ioinfo_err(ioinfo, "%s", strerror(err));
	ioinfo->uh->shutdown(ioinfo);
	return 0;
    }

    switch(event) {
    case GENSIO_EVENT_READ:
	if (*buflen == 0)
	    return 0;

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
	if (rioinfo->ready) {
	    rv = gensio_write(rioinfo->io, &count, buf, *buflen, NULL);
	    if (rv) {
		gensio_set_read_callback_enable(ioinfo->io, false);
		ioinfo_err(ioinfo, "%s", strerror(rv));
		ioinfo->uh->shutdown(ioinfo);
		return 0;
	    }
	} else {
	    count = *buflen;
	}
	if (count < *buflen) {
	    *buflen = count;
	    gensio_set_read_callback_enable(ioinfo->io, false);
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
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	gensio_set_read_callback_enable(rioinfo->io, true);
	gensio_set_write_callback_enable(ioinfo->io, false);
	return 0;

    default:
	break;
    }

    if (!rioinfo->ready)
	return 0;

    if (ioinfo->sh)
	return ioinfo->sh->handle_event(io, event, buf, buflen);
    return 0;
}

void
ioinfo_set_ready(struct ioinfo *ioinfo, struct gensio *io)
{
    ioinfo->io = io;
    gensio_set_callback(io, io_event, ioinfo);
    gensio_set_read_callback_enable(ioinfo->io, true);
    ioinfo->ready = true;
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

    ioinfo = malloc(sizeof(*ioinfo));
    if (ioinfo) {
	memset(ioinfo, 0, sizeof(*ioinfo));
	ioinfo->escape_char = escape_char;
	ioinfo->o = o;
	ioinfo->sh = sh;
	ioinfo->subdata = subdata;
	ioinfo->uh = uh;
	ioinfo->userdata = userdata;
    }
    return ioinfo;
}

void
free_ioinfo(struct ioinfo *ioinfo)
{
    free(ioinfo);
}
