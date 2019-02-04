/*
 *  gensiotool - A program for connecting gensios.
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gensio/gensio.h>

#include "ioinfo.h"
#include "ser_ioinfo.h"
#include "utils.h"

unsigned int debug;

struct gdata {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    struct gensio *user_io;
    struct gensio *io;
    const char *ios;
    bool can_close;
};

static void
gshutdown(struct ioinfo *ioinfo)
{
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    ginfo->o->wake(ginfo->waiter);
}

static void
gerr(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    fprintf(stderr, "Error on %s: \n", ginfo->ios);
    vfprintf(stderr, fmt, ap);
}

static void
gout(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    char str[200];

    vsnprintf(str, sizeof(str), fmt, ap);
    gensio_write(ginfo->user_io, NULL, str, strlen(str), NULL);
}

static struct ioinfo_user_handlers guh = {
    .shutdown = gshutdown,
    .err = gerr,
    .out = gout
};

static void
io_open(struct gensio *io, int err, void *open_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    if (err) {
	ginfo->can_close = false;
	fprintf(stderr, "open error on %s: %s", ginfo->ios, strerror(err));
	gshutdown(ioinfo);
    } else {
	ioinfo_set_ready(ioinfo, io);
    }
}

static void
io_close(struct gensio *io, void *close_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    struct gensio_waiter *closewaiter = close_data;

    ginfo->o->wake(closewaiter);
}

static int
io_acc_event(struct gensio_accepter *accepter, int event, void *data)
{

    struct ioinfo *ioinfo = gensio_acc_get_user_data(accepter);
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return GE_NOTSUP;

    if (ginfo->io) {
	gensio_free(data);
	return 0;
    }

    ginfo->io = data;
    ginfo->can_close = true;
    ioinfo_set_ready(ioinfo, ginfo->io);
    gensio_acc_free(accepter);
    if (debug)
	printf("Connected\r\n");
    return 0;
}

static const char *progname;
static const char *io1_default_tty = "serialdev,/dev/tty";
static const char *io1_default_notty = "stdio(self)";

static void
help(int err)
{
    printf("%s [options] io2\n", progname);
    printf("\nA program to connect gensios together.  This programs has two\n");
    printf("gensios, io1 (default is local terminal) and io2 (must be set).\n");
    printf("\noptions are:\n");
    printf("  -i, --input <gensio) - Set the io1 device, default is\n"
	   "    %s for tty or %s for non-tty stdin\n",
	   io1_default_tty, io1_default_notty);
    printf("  -d, --debug - Enable debug.  Specify more than once to increase\n"
	   "    the debug level\n");
    printf("  -a, --accepter - Accept a connection on io2 instead of"
	   " initiating a connection\n");
    printf("  --signature <sig> - Set the RFC2217 server signature to <sig>\n");
    printf("  -e, --escchar - Set the local terminal escape character.\n"
	   "    Set to 0 to disable the escape character\n"
	   "    Default is ^\\ for tty stdin and disabled for non-tty stdin\n");
    printf("  -h, --help - This help\n");
    exit(err);
}

static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    if (!debug)
	return;
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
}

int
main(int argc, char *argv[])
{
    int arg, rv;
    struct gensio_waiter *closewaiter;
    unsigned int closecount = 0;
    bool io2_do_acc = false;
    struct gensio_accepter *io2_acc;
    bool esc_set = false;
    bool io1_set = false;
    int escape_char = -1;
    const char *signature = "gensiotool";
    const char *deftty = io1_default_notty;
    struct gensio_os_funcs *o;
    struct ioinfo_sub_handlers *sh1 = NULL, *sh2 = NULL;
    void *subdata1 = NULL, *subdata2 = NULL;
    struct ioinfo *ioinfo1, *ioinfo2;
    struct gdata userdata1, userdata2;

    progname = argv[0];

    if (isatty(0)) {
	escape_char = 0x1c; /* ^\ */
	deftty = io1_default_tty;
    }

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != '-')
	    break;
	if (strcmp(argv[arg], "--") == 0) {
	    arg++;
	    break;
	}
	if ((rv = cmparg(argc, argv, &arg, "-i", "--input", &deftty)))
	    io1_set = true;
	else if ((rv = cmparg(argc, argv, &arg, "-a", "--accepter", NULL)))
	    io2_do_acc = true;
	else if ((rv = cmparg_int(argc, argv, &arg, "-e", "--escchar",
				  &escape_char)))
	    esc_set = true;
	else if ((rv = cmparg(argc, argv, &arg, "", "--signature",
			      &signature)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-d", "--debug", NULL))) {
	    debug++;
	    if (debug > 1)
		gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else if ((rv = cmparg(argc, argv, &arg, "-h", "--help", NULL)))
	    help(0);
	else {
	    fprintf(stderr, "Unknown argument: %s\n", argv[arg]);
	    help(1);
	}
	if (rv < 0)
	    return 1;
    }

    if (io1_set && !esc_set)
	escape_char = 0; /* disable */

    if (arg >= argc) {
	fprintf(stderr, "No gensio string given to connect to\n");
	help(1);
    }

    memset(&userdata1, 0, sizeof(userdata1));
    memset(&userdata2, 0, sizeof(userdata2));

    userdata1.ios = deftty;
    userdata2.ios = argv[arg];

    rv = gensio_default_os_hnd(0, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    o->vlog = do_vlog;

    userdata1.o = o;
    userdata2.o = o;

    userdata1.waiter = o->alloc_waiter(o);
    if (!userdata1.waiter) {
	fprintf(stderr, "Could not allocate OS waiter: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    userdata2.waiter = userdata1.waiter;

    closewaiter = o->alloc_waiter(o);
    if (!closewaiter) {
	fprintf(stderr, "Could not allocate close waiter: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    subdata1 = alloc_ser_ioinfo(0, signature, &sh1);
    if (!subdata1) {
	fprintf(stderr, "Could not allocate subdata 1\n");
	return 1;
    }
    subdata2 = alloc_ser_ioinfo(0, signature, &sh2);
    if (!subdata2) {
	fprintf(stderr, "Could not allocate subdata 2\n");
	return 1;
    }

    ioinfo1 = alloc_ioinfo(o, escape_char, sh1, subdata1, &guh, &userdata1);
    if (!ioinfo1) {
	fprintf(stderr, "Could not allocate ioinfo 1\n");
	return 1;
    }

    ioinfo2 = alloc_ioinfo(o, 0, sh2, subdata1, &guh, &userdata2);
    if (!ioinfo2) {
	fprintf(stderr, "Could not allocate ioinfo 2\n");
	return 1;
    }

    ioinfo_set_otherioinfo(ioinfo1, ioinfo2);

    rv = str_to_gensio(userdata1.ios, o, NULL, ioinfo1, &userdata1.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n",
		userdata1.ios, gensio_err_to_str(rv));
	return 1;
    }

    userdata1.user_io = userdata1.io;
    userdata2.user_io = userdata1.io;

    if (io2_do_acc)
	rv = str_to_gensio_accepter(userdata2.ios, o, io_acc_event,
				    ioinfo2, &io2_acc);
    else
	rv = str_to_gensio(userdata2.ios, o, NULL, ioinfo2, &userdata2.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", userdata2.ios,
		gensio_err_to_str(rv));
	return 1;
    }

    userdata1.can_close = true;
    rv = gensio_open(userdata1.io, io_open, NULL);
    if (rv) {
	userdata1.can_close = false;
	fprintf(stderr, "Could not open %s: %s\n", userdata1.ios,
		gensio_err_to_str(rv));
	return 1;
    }

    if (io2_do_acc) {
	rv = gensio_acc_startup(io2_acc);
	if (rv) {
	    fprintf(stderr, "Could not start %s: %s\n", userdata2.ios,
		    gensio_err_to_str(rv));
	    goto close1;
	}
    } else {
	userdata2.can_close = true;
	rv = gensio_open(userdata2.io, io_open, NULL);
	if (rv) {
	    userdata2.can_close = false;
	    fprintf(stderr, "Could not open %s: %s\n", userdata2.ios,
		    gensio_err_to_str(rv));
	    goto close1;
	}
    }

    o->wait(userdata1.waiter, 1, NULL);

    if (userdata2.can_close) {
	rv = gensio_close(userdata2.io, io_close, closewaiter);
	if (rv)
	    printf("Unable to close %s: %s\n", userdata2.ios,
		   gensio_err_to_str(rv));
	else
	    closecount++;
    } else if (!userdata2.io && io2_do_acc) {
	gensio_acc_free(io2_acc);
    }

 close1:
    if (userdata1.can_close) {
	rv = gensio_close(userdata1.io, io_close, closewaiter);
	if (rv)
	    printf("Unable to close %s: %s\n", userdata1.ios,
		   gensio_err_to_str(rv));
	else
	    closecount++;
    }

    if (closecount > 0) {
	o->wait(closewaiter, closecount, NULL);
    }

    gensio_free(userdata1.io);
    if (userdata2.io)
	gensio_free(userdata2.io);

    o->free_waiter(closewaiter);
    o->free_waiter(userdata1.waiter);

    free_ioinfo(ioinfo1);
    free_ioinfo(ioinfo2);
    free_ser_ioinfo(subdata1);
    free_ser_ioinfo(subdata2);

    return 0;
}
