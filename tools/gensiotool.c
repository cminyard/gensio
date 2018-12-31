/*
 *  gensiot - A program for connecting gensios.
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <gensio/gensio.h>
#include <gensio/sergensio.h>

static int
cmparg(int argc, char *argv[], int *arg, char *sarg, char *larg,
       const char **opt)
{
    char *a = argv[*arg];

    if (strcmp(a, sarg) == 0 || strcmp(a, larg) == 0) {
	if (!opt)
	    return 1;
	(*arg)++;
	if (*arg >= argc) {
	    fprintf(stderr, "No argument given for option %s\n", a);
	    return -1;
	}
	*opt = argv[*arg];
	return 1;
    } else {
	unsigned int len = strlen(larg);

	if (strncmp(a, larg, len) == 0 && a[len] == '=') {
	    *opt = a + len + 1;
	    return 1;
	}
    }

    return 0;
}

static int
strtocc(const char *str, char *rc)
{
    int c;

    if (!*str || str[1] != '\0') {
	fprintf(stderr, "Empty string for ^x\n");
	return -1;
    }
    c = toupper(str[0]);
    if (c < 'A' || c > '_') {
	fprintf(stderr, "Invalid character for ^x\n");
	return -1;
    }
    *rc = c - '@';
    return 0;
}

static int
cmparg_char(int argc, char *argv[], int *arg, char *sarg, char *larg, char *rc)
{
    const char *str;
    char *end;
    int rv = cmparg(argc, argv, arg, sarg, larg, &str);
    long v;

    if (rv <= 0)
	return rv;
    if (!str[0]) {
	fprintf(stderr, "No string given for character\n");
	return -1;
    }
    if (str[0] == '^')
	return strtocc(str + 1, rc);
    v = strtol(str, &end, 0);
    if (*end != '\0') {
	fprintf(stderr, "Invalid string given for character\n");
	return -1;
    }
    *rc = v;
    return 1;
}

struct ginfo {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
};

struct ioinfo {
    const char *ios;
    struct gensio *io;
    struct ioinfo *otherio;
    struct ginfo *g;
    char escape_char;
    bool in_escape;
    char escape_data[11];
    unsigned int escape_pos;
};

struct ser_dump_data
{
    int speed;
    char parity;
    int datasize;
    int stopbits;
    unsigned int refcount;
    struct ioinfo *ioinfo;
};

static void
deref(struct ser_dump_data *ddata)
{
    ddata->refcount--;
    if (ddata->refcount == 0) {
	char buf[100];

	snprintf(buf, sizeof(buf), "\r\nSpeed: %d%c%d%d\r\n", ddata->speed,
		 ddata->parity, ddata->datasize, ddata->stopbits);
	gensio_write(ddata->ioinfo->io, NULL, buf, strlen(buf), NULL);
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

static bool
handle_escapechar(struct ioinfo *ioinfo, char c)
{
    struct sergensio *sio;
    struct ser_dump_data *ddata;
    int rv;

    if (ioinfo->escape_pos > 0) {
	/* We are getting a speed from the input. */
	if (c == '\r' || c == '\n') {
	    int speed;
	    char *end;

	    ioinfo->escape_data[ioinfo->escape_pos++] = '\0';
	    speed = strtol(ioinfo->escape_data + 1, &end, 0);
	    if (ioinfo->escape_pos > 1 && *end == '\0') {
		sio = gensio_to_sergensio(ioinfo->otherio->io);
		sergensio_baud(sio, speed, NULL, NULL);
	    }
	    ioinfo->escape_pos = 0;
	    return false;
	}

	if (ioinfo->escape_pos < sizeof(ioinfo->escape_data) - 1)
	    ioinfo->escape_data[ioinfo->escape_pos++] = c;
	return true;
    }

    c = tolower(c);

    switch (c) {
    case 'q':
	ioinfo->g->o->wake(ioinfo->g->waiter);
	break;
    }

    sio = gensio_to_sergensio(ioinfo->otherio->io);
    if (!sio)
	return false;

    switch (c) {
    case 'd': /* Dump serial data. */
	ddata = malloc(sizeof(*ddata));
	if (!ddata)
	    return false;
	memset(ddata, 0, sizeof(*ddata));
	ddata->ioinfo = ioinfo;
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
    case 'b': /* Send a break */
	sergensio_send_break(sio);
	break;
    case 's': /* Set baud rate */
	ioinfo->escape_data[0] = c;
	ioinfo->escape_pos = 1;
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

static int
io_event(struct gensio *io, int event, int err,
	 unsigned char *buf, unsigned int *buflen,
	 const char *const *auxdata)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    int rv, escapepos = -1;
    unsigned int count = 0;

    if (err) {
	fprintf(stderr, "Error from %s: %s\n", ioinfo->ios, strerror(err));
	ioinfo->g->o->wake(ioinfo->g->waiter);
	return 0;
    }

    switch(event) {
    case GENSIO_EVENT_READ:
	if (*buflen == 0)
	    return 0;

	if (ioinfo->escape_char) {
	    unsigned int i;

	    if (ioinfo->in_escape) {
		if (buf[0] != ioinfo->escape_char || ioinfo->escape_pos > 0) {
		    ioinfo->in_escape = handle_escapechar(ioinfo, buf[0]);
		    *buflen = 1;
		    return 0;
		}
		ioinfo->in_escape = false;
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
	rv = gensio_write(ioinfo->otherio->io, &count, buf, *buflen, NULL);
	if (rv) {
	    fprintf(stderr, "Error writing to %s: %s\n",
		    ioinfo->otherio->ios, strerror(err));
	    ioinfo->g->o->wake(ioinfo->g->waiter);
	    return 0;
	}
	if (count < *buflen) {
	    *buflen = count;
	    gensio_set_read_callback_enable(ioinfo->io, false);
	    gensio_set_write_callback_enable(ioinfo->otherio->io, true);
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
	gensio_set_read_callback_enable(ioinfo->otherio->io, true);
	gensio_set_write_callback_enable(ioinfo->io, false);
	return 0;

    default:
	return ENOTSUP;
    }
}
static void
io_open(struct gensio *io, int err, void *open_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);

    if (err) {
	fprintf(stderr, "Unable to open %s: %s\n", ioinfo->ios, strerror(err));
	ioinfo->g->o->wake(ioinfo->g->waiter);
    } else {
	gensio_set_read_callback_enable(ioinfo->io, true);
    }
}

static void
io_close(struct gensio *io, void *close_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gensio_waiter *closewaiter = close_data;

    ioinfo->g->o->wake(closewaiter);
}

int
main(int argc, char *argv[])
{
    struct ginfo g;
    struct ioinfo ioinfo1;
    struct ioinfo ioinfo2;
    int arg, rv;
    struct gensio_waiter *closewaiter;
    unsigned int closecount = 0;

    memset(&g, 0, sizeof(g));
    memset(&ioinfo1, 0, sizeof(ioinfo1));
    memset(&ioinfo2, 0, sizeof(ioinfo2));

    ioinfo1.escape_char = 0x1c; /* ^\ */
    ioinfo1.ios = "serialdev,/dev/tty";
    ioinfo1.g = &g;
    ioinfo2.g = &g;
    ioinfo1.otherio = &ioinfo2;
    ioinfo2.otherio = &ioinfo1;

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != '-')
	    break;
	if ((rv = cmparg(argc, argv, &arg, "-i", "--input", &ioinfo1.ios)))
	    ;
	else if ((rv = cmparg_char(argc, argv, &arg, "-e", "--escchar",
				   &ioinfo1.escape_char)))
	    ;
	else {
	    fprintf(stderr, "Unknown argument: %s\n", argv[arg]);
	    return 1;
	}
	if (rv < 0)
	    return 1;
    }

    if (arg >= argc) {
	fprintf(stderr, "No gensio string given to connect to\n");
	return 1;
    }
    ioinfo2.ios = argv[arg];

    rv = gensio_default_os_hnd(0, &g.o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n", strerror(rv));
	return 1;
    }

    g.waiter = g.o->alloc_waiter(g.o);
    if (!g.waiter) {
	fprintf(stderr, "Could not allocate OS waiter: %s\n", strerror(rv));
	return 1;
    }

    closewaiter = g.o->alloc_waiter(g.o);
    if (!closewaiter) {
	fprintf(stderr, "Could not allocate close waiter: %s\n", strerror(rv));
	return 1;
    }

    rv = str_to_gensio(ioinfo1.ios, g.o, io_event, &ioinfo1, &ioinfo1.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n",
		ioinfo1.ios, strerror(rv));
	return 1;
    }

    rv = str_to_gensio(ioinfo2.ios, g.o, io_event, &ioinfo2, &ioinfo2.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", ioinfo2.ios, strerror(rv));
	return 1;
    }

    rv = gensio_open(ioinfo1.io, io_open, NULL);
    if (rv) {
	fprintf(stderr, "Could not open %s: %s\n", ioinfo1.ios, strerror(rv));
	return 1;
    }

    rv = gensio_open(ioinfo2.io, io_open, NULL);
    if (rv) {
	fprintf(stderr, "Could not open %s: %s\n", ioinfo2.ios, strerror(rv));
	goto close1;
    }

    g.o->wait(g.waiter, 1, NULL);

    rv = gensio_close(ioinfo2.io, io_close, closewaiter);
    if (rv)
	printf("Unable to close %s: %s\n", ioinfo2.ios, strerror(rv));
    else
	closecount++;

 close1:
    rv = gensio_close(ioinfo1.io, io_close, closewaiter);
    if (rv)
	printf("Unable to close %s: %s\n", ioinfo1.ios, strerror(rv));
    else
	closecount++;

    if (closecount > 0) {
	g.o->wait(closewaiter, closecount, NULL);
    }
    
    return 0;
}
