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
#include <gensio/gensio_selector.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ioinfo.h"
#include "ser_ioinfo.h"
#include "utils.h"

unsigned int debug;

#ifdef HAVE_OPENSSL
/*
 * Set a dummy random input file, for reproducable openssl usage for
 * fuzz testing.
 */
#include <openssl/rand.h>

static int dummyrnd_file = -1;

int
dummyrnd_seed(const void *buf, int num)
{
    return 1;
}

int
dummyrnd_bytes(unsigned char *buf, int num)
{
    int rc;
    int count = 0;

    while (num > 0) {
	rc = read(dummyrnd_file, buf, num);
	if (rc < 0) {
	    fprintf(stderr, "Error reading from dummyrnd file: %s\n",
		    strerror(errno));
	    return 0;
	}
	if (rc == 0) {
	    off_t pos = lseek(dummyrnd_file, 0, SEEK_SET);

	    if (pos == -1) {
		fprintf(stderr, "Error seeking dummyrnd file: %s\n",
			strerror(errno));
		return 0;
	    }
	    rc = read(dummyrnd_file, buf, num);
	    if (rc <= 0) {
		fprintf(stderr, "Error reading from dummyrnd file: %s\n",
			strerror(errno));
		return 0;
	    }
	}
	count += rc;
	buf += rc;
	num -= rc;
    }

    return count;
}

void
dummyrnd_cleanup(void)
{
}

int
dummyrnd_add(const void *buf, int num, double randomness)
{
    return 1;
}

int
dummyrnd_pseudorand(unsigned char *buf, int num)
{
    return dummyrnd_bytes(buf, num);
}

int
dummyrnd_status(void)
{
    return 1;
}

struct rand_meth_st dummyrnd = {
    .seed = dummyrnd_seed,
    .bytes = dummyrnd_bytes,
    .cleanup = dummyrnd_cleanup,
    .add = dummyrnd_add,
    .pseudorand = dummyrnd_pseudorand,
    .status = dummyrnd_status,
};
#endif

struct gdata {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    struct gensio *user_io;
    struct gensio *io;
    const char *ios;
    bool can_close;
    int err;
};

static void
gshutdown(struct ioinfo *ioinfo, bool user_req)
{
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    if (!user_req)
	ginfo->err = 1;
    ginfo->o->wake(ginfo->waiter);
}

static void
gerr(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    fprintf(stderr, "Error on %s: ", ginfo->ios);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\r\n");
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
	fprintf(stderr, "open error on %s: %s\n", ginfo->ios,
		gensio_err_to_str(err));
	gshutdown(ioinfo, false);
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
io_acc_event(struct gensio_accepter *accepter, void *user_data,
	     int event, void *data)
{
    struct ioinfo *ioinfo = user_data;
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    struct ioinfo *oioinfo = ioinfo_otherioinfo(ioinfo);
    struct gdata *oginfo = ioinfo_userdata(oioinfo);
    int rv;

    if (event == GENSIO_ACC_EVENT_LOG) {
	struct gensio_loginfo *li = data;

	vfprintf(stderr, li->str, li->args);
	fprintf(stderr, "\n");
	gensio_sel_exit(1);
    }

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

    oginfo->can_close = true;
    rv = gensio_open(oginfo->io, io_open, NULL);
    if (rv) {
	oginfo->can_close = false;
	fprintf(stderr, "Could not open %s: %s\n", oginfo->ios,
		gensio_err_to_str(rv));
	gensio_sel_exit(1);
    }
    return 0;
}

static const char *progname;
static char *io1_default_tty = "serialdev,/dev/tty";
static char *io1_default_notty = "stdio(self)";

static void
help(int err)
{
    printf("%s [options] io2\n", progname);
    printf("\nA program to connect gensios together.  This programs has two\n");
    printf("gensios, io1 (default is local terminal) and io2 (must be set).\n");
    printf("\noptions are:\n");
    printf("  -i, --input <gensio> - Set the io1 device, default is\n"
	   "    %s for tty or %s for non-tty stdin\n",
	   io1_default_tty, io1_default_notty);
    printf("  -d, --debug - Enable debug.  Specify more than once to increase\n"
	   "    the debug level\n");
    printf("  -a, --accepter - Accept a connection on io2 instead of"
	   " initiating a connection\n");
    printf("  -p, --printacc - When the accepter is started, print out all"
	   " the addresses being listened on.\n");
    printf("  -v, --verbose - Print all gensio logs\n");
    printf("  --signature <sig> - Set the RFC2217 server signature to <sig>\n");
    printf("  -e, --escchar - Set the local terminal escape character.\n"
	   "    Set to -1 to disable the escape character\n"
	   "    Default is ^\\ for tty stdin and disabled for non-tty stdin\n");
    printf("  -h, --help - This help\n");
    gensio_sel_exit(err);
}

static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    if (!debug)
	return;
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
    fprintf(stderr, "\n");
}

int
main(int argc, char *argv[])
{
    int arg, rv;
    struct gensio_waiter *closewaiter;
    unsigned int closecount = 0;
    bool io2_do_acc = false, io2_acc_print = false;
    struct gensio_accepter *io2_acc;
    bool esc_set = false;
    bool io1_set = false;
    int escape_char = -1;
    char *signature = "gensiotool";
    char *deftty = io1_default_notty;
    struct gensio_os_funcs *o;
    struct ioinfo_sub_handlers *sh1 = NULL, *sh2 = NULL;
    void *subdata1 = NULL, *subdata2 = NULL;
    struct ioinfo *ioinfo1, *ioinfo2;
    struct gdata userdata1, userdata2;
    char *filename;
    sigset_t sigs;

    /*
     * Make sure that SIGPIPE doesn't kill is if the user is doing
     * something involving a pipe.
     */
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGPIPE);
    sigaddset(&sigs, SIGHUP);
    rv = sigprocmask(SIG_BLOCK, &sigs, NULL);
    if (rv) {
	perror("Could not set up signal mask");
	exit(1);
    }

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
	else if ((rv = cmparg(argc, argv, &arg, "-p", "--printacc", NULL)))
	    io2_acc_print = true;
	else if ((rv = cmparg(argc, argv, &arg, "-v", "--verbose", NULL)))
	    gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
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
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--dummyrand",
			      &filename))) {
#ifdef HAVE_OPENSSL
	    /*
	     * This option is undocumented and only for testing.  Do not
	     * use it!
	     */
	    if (dummyrnd_file != -1)
		close(dummyrnd_file);
	    dummyrnd_file = open(filename, O_RDONLY);
	    if (dummyrnd_file == -1) {
		fprintf(stderr, "Could not open rand file: %s\n",
			strerror(errno));
		goto out_err;
	    }

	    rv = RAND_set_rand_method(&dummyrnd);
	    if (rv != 1) {
		fprintf(stderr, "Error setting random method\n");
		goto out_err;
	    }
#endif
	} else {
	    fprintf(stderr, "Unknown argument: %s\n", argv[arg]);
	    help(1);
	}
	if (rv < 0)
	    goto out_err;
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
	goto out_err;
    }
    o->vlog = do_vlog;

    userdata1.o = o;
    userdata2.o = o;

    userdata1.waiter = o->alloc_waiter(o);
    if (!userdata1.waiter) {
	fprintf(stderr, "Could not allocate OS waiter\n");
	goto out_err;
    }
    userdata2.waiter = userdata1.waiter;

    closewaiter = o->alloc_waiter(o);
    if (!closewaiter) {
	fprintf(stderr, "Could not allocate close waiter\n");
	goto out_err;
    }

    subdata1 = alloc_ser_ioinfo(0, signature, &sh1);
    if (!subdata1) {
	fprintf(stderr, "Could not allocate subdata 1\n");
	goto out_err;
    }
    subdata2 = alloc_ser_ioinfo(0, signature, &sh2);
    if (!subdata2) {
	fprintf(stderr, "Could not allocate subdata 2\n");
	goto out_err;
    }

    ioinfo1 = alloc_ioinfo(o, escape_char, sh1, subdata1, &guh, &userdata1);
    if (!ioinfo1) {
	fprintf(stderr, "Could not allocate ioinfo 1\n");
	goto out_err;
    }

    ioinfo2 = alloc_ioinfo(o, -1, sh2, subdata2, &guh, &userdata2);
    if (!ioinfo2) {
	fprintf(stderr, "Could not allocate ioinfo 2\n");
	goto out_err;
    }

    ioinfo_set_otherioinfo(ioinfo1, ioinfo2);

    rv = str_to_gensio(userdata1.ios, o, NULL, ioinfo1, &userdata1.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n",
		userdata1.ios, gensio_err_to_str(rv));
	goto out_err;
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
	goto out_err;
    }

    if (io2_do_acc) {
	rv = gensio_acc_startup(io2_acc);
	if (rv) {
	    fprintf(stderr, "Could not start %s: %s\n", userdata2.ios,
		    gensio_err_to_str(rv));
	    goto close1;
	}
	if (io2_acc_print) {
	    char str[2048];
	    gensiods size;
	    unsigned int i;

	    for (i = 0; ; i++) {
		snprintf(str, sizeof(str), "%u", i);
		size = sizeof(str);
		rv = gensio_acc_control(io2_acc, GENSIO_CONTROL_DEPTH_FIRST,
					true, GENSIO_ACC_CONTROL_LADDR,
					str, &size);
		if (rv == GE_NOTFOUND)
		    break;
		if (rv)
		    fprintf(stderr,
			    "Unable to fetch accept address %d: %s\n", i,
			    gensio_err_to_str(rv));
		else
		    fprintf(stderr, "Address %d: %s\n", i, str);
	    }
	    fprintf(stderr, "Done\n");
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

	userdata1.can_close = true;
	rv = gensio_open(userdata1.io, io_open, NULL);
	if (rv) {
	    userdata1.can_close = false;
	    fprintf(stderr, "Could not open %s: %s\n", userdata1.ios,
		    gensio_err_to_str(rv));
	    goto out_err;
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

    if (!rv && userdata1.err)
	rv = userdata1.err;
    if (!rv && userdata2.err)
	rv = userdata2.err;

    gensio_sel_exit(!!rv);

 out_err:
    gensio_sel_exit(1);
}
