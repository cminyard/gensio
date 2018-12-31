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
#include <string.h>
#include <errno.h>
#include <gensio/gensio.h>
#include <gensio/waiter.h>

static int cmparg(int argc, char *argv[], int *arg, char *sarg, char *larg,
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
    } else {
	unsigned int len = strlen(larg);

	if (strncmp(a, larg, len) == 0 && a[len] == '=') {
	    *opt = a + len + 1;
	    return 1;
	}
    }

    return 0;
}

struct ginfo {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    char escape_char;
};

struct ioinfo {
    const char *ios;
    struct gensio *io;
    struct ioinfo *otherio;
    struct ginfo *g;
    bool primary;
    bool in_escape;
};

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

	if (ioinfo->primary) {
	    unsigned int i;

	    if (ioinfo->in_escape) {
		if (buf[0] == 'q') {
		    ioinfo->g->o->wake(ioinfo->g->waiter);
		    return 0;
		}
		ioinfo->in_escape = false;
	    }
	    for (i = 0; i < *buflen; i++) {
		if (buf[i] == ioinfo->g->escape_char) {
		    escapepos = i;
		    *buflen = i;
		    break;
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
	    (*buflen)++;
	    ioinfo->in_escape = true;
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

    g.escape_char = 0x1c; /* ^\ */
    ioinfo1.primary = true;
    ioinfo1.ios = "serialdev,/dev/tty";
    ioinfo1.g = &g;
    ioinfo2.g = &g;
    ioinfo1.otherio = &ioinfo2;
    ioinfo2.otherio = &ioinfo1;

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != '-')
	    break;
	if ((rv = cmparg(argc, argv, &arg, "-i", "-input", &ioinfo1.ios)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-e", "-noesc", NULL)))
	    ioinfo1.primary = false;
	else {
	    fprintf(stderr, "Unknown argument: %s\n", argv[arg]);
	    return 1;
	}
	if (rv == -1)
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
