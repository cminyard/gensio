/*
 *  gensiotool - A program for connecting gensios.
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gensio/gensio.h>
#include <gensio/gensio_list.h>
#include <gensio/gensio_unix.h>
#ifdef HAVE_GLIB
#include <gensio/gensio_glib.h>
#endif
#ifdef HAVE_TCL
#include <gensio/gensio_tcl.h>
#endif

#include "ioinfo.h"
#include "ser_ioinfo.h"
#include "utils.h"

unsigned int debug;

#if HAVE_OPENSSL
/*
 * Set a dummy random input file, for reproducable openssl usage for
 * fuzz testing.
 */
#include <openssl/rand.h>

static FILE *dummyrnd_file;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void
dummyrnd_seed(const void *buf, int num)
{
}
#else
static int
dummyrnd_seed(const void *buf, int num)
{
    return 1;
}
#endif

static int
dummyrnd_bytes(unsigned char *buf, int num)
{
    size_t rc;
    int count = 0;

    while (num > 0) {
	rc = fread(buf, 1, num, dummyrnd_file);
	if (rc == 0) {
	    rewind(dummyrnd_file);

	    rc = fread(buf, 1, num, dummyrnd_file);
	    if (rc == 0) {
		fprintf(stderr, "Error reading from dummyrnd file\n");
		return 0;
	    }
	}
	count += rc;
	buf += rc;
	num -= rc;
    }

    return count;
}

static void
dummyrnd_cleanup(void)
{
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void
dummyrnd_add(const void *buf, int num, double randomness)
{
}
#else
static int
dummyrnd_add(const void *buf, int num, double randomness)
{
    return 1;
}
#endif

static int
dummyrnd_pseudorand(unsigned char *buf, int num)
{
    return dummyrnd_bytes(buf, num);
}

static int
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

struct gtinfo {
    struct gensio_os_funcs *o;
    const char *ios1;
    const char *ios2;
    int escape_char;
    const char *signature;
    bool print_laddr;
    bool print_raddr;

    int err;

    bool server_mode;

    struct gensio_waiter *waiter;

    struct gensio_list io_list;

    struct gensio_accepter *acc;
};

struct gtconn_info {
    struct gensio_link link;
    struct gtinfo *g;
    struct gensio *user_io;
    struct gensio *io;
    const char *ios;
    bool close_done;
};

static void
check_finish(struct ioinfo *ioinfo)
{
    struct ioinfo *oioinfo = ioinfo_otherioinfo(ioinfo);
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);
    struct gtconn_info *ogtconn = ioinfo_userdata(oioinfo);
    void *subdata = ioinfo_subdata(ioinfo);
    void *osubdata = ioinfo_subdata(oioinfo);
    struct gtinfo *g = gtconn->g;
    struct gensio_os_funcs *o = g->o;
    struct gensio *io;

    if (!gtconn->close_done || !ogtconn->close_done)
	return;

    io = ioinfo_io(ioinfo);
    if (io)
	gensio_free(io);
    io = ioinfo_io(oioinfo);
    if (io)
	gensio_free(io);

    gensio_list_rm(&g->io_list, &gtconn->link);
    gensio_list_rm(&g->io_list, &ogtconn->link);

    o->free(o, gtconn);
    o->free(o, ogtconn);

    free_ioinfo(ioinfo);
    free_ioinfo(oioinfo);
    free_ser_ioinfo(subdata);
    free_ser_ioinfo(osubdata);

    if (!g->server_mode)
	g->o->wake(g->waiter);
}

static void
io_closed(struct gensio *io, void *close_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);

    if (ioinfo_io(ioinfo) == NULL)
	gensio_free(io);
    gtconn->close_done = true;
    gtconn->io = NULL;
    check_finish(ioinfo);
}

static void
gshutdown(struct ioinfo *ioinfo, bool user_req)
{
    struct ioinfo *oioinfo = ioinfo_otherioinfo(ioinfo);
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);
    struct gtconn_info *ogtconn = ioinfo_userdata(oioinfo);
    struct gtinfo *g = gtconn->g;
    int err;

    if (gtconn->io) {
	err = gensio_close(gtconn->io, io_closed, NULL);
	if (err)
	    io_closed(gtconn->io, NULL);
	gtconn->io = NULL;
    }
    if (ogtconn->io) {
	err = gensio_close(ogtconn->io, io_closed, NULL);
	if (err)
	    io_closed(ogtconn->io, NULL);
	ogtconn->io = NULL;
    }
    if (!g->err && !user_req)
	g->err = GE_IOERR;
}

static void
gerr(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);

    fprintf(stderr, "Error on %s: ", gtconn->ios);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\r\n");
    fflush(stderr);
}

static void
gout(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);
    char str[200];

    vsnprintf(str, sizeof(str), fmt, ap);
    gensio_write(gtconn->user_io, NULL, str, strlen(str), NULL);
}

static struct ioinfo_user_handlers guh = {
    .shutdown = gshutdown,
    .err = gerr,
    .out = gout
};

static void
print_address_list(const char *header, unsigned int anum, char *alist)
{
    unsigned int i = 0;
    char *semipos;

    do {
	semipos = strchr(alist, ';');
	if (semipos)
	    *semipos = '\0';
	fprintf(stderr, "%s %d(%d): %s\n", header, anum, i, alist);
	if (semipos)
	    alist = semipos + 1;
	i++;
    } while (semipos);
    fflush(stderr);
}

static int
print_local_acc_addr(struct gensio_accepter *acc)
{
    char str[2048];
    gensiods size;
    unsigned int i;
    int rv;

    for (i = 0; ; i++) {
	snprintf(str, sizeof(str), "%u", i);
	size = sizeof(str);
	rv = gensio_acc_control(acc, GENSIO_CONTROL_DEPTH_FIRST,
				true, GENSIO_ACC_CONTROL_LADDR,
				str, &size);
	if (rv == GE_NOTFOUND)
	    break;
	if (rv) {
	    fprintf(stderr,
		    "Unable to fetch accept address %d: %s\n", i,
		    gensio_err_to_str(rv));
	    return rv;
	} else {
	    print_address_list("Address", i, str);
	}
    }
    fprintf(stderr, "Done\n");
    fflush(stderr);
    return 0;
}

static int
print_io_addr(struct gensio *io, bool local)
{
    char str[2048];
    gensiods size;
    int rv;
    unsigned int i;
    char *header = local ? "Local Address" : "Remote Address";

    for (i = 0; ; i++) {
	size = sizeof(str);
	snprintf(str, sizeof(str), "%u", i);
	rv = gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_GET,
			    local ? GENSIO_CONTROL_LADDR : GENSIO_CONTROL_RADDR,
			    str, &size);
	if (rv == GE_NOTFOUND)
	    goto done;
	if (rv) {
	    fprintf(stderr,
		    "Unable to fetch %s address: %s\n",
		    local ? "local" : "remote",
		    gensio_err_to_str(rv));
	    return rv;
	} else {
	    print_address_list(header, i, str);
	}
    }
 done:
    fprintf(stderr, "Done\n");
    fflush(stderr);
    return 0;
}

static void
io_open(struct gensio *io, int err, void *open_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);

    if (err) {
	fprintf(stderr, "open error on %s: %s\n", gtconn->ios,
		gensio_err_to_str(err));
	fflush(stderr);
	io_closed(io, NULL);
	gshutdown(ioinfo, false);
    } else {
	ioinfo_set_ready(ioinfo, io);
    }
}

static void
io_open_paddr(struct gensio *io, int err, void *open_data)
{
    struct gtinfo *g = open_data;
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct ioinfo *oioinfo = ioinfo_otherioinfo(ioinfo);
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);
    struct gtconn_info *ogtconn = ioinfo_userdata(oioinfo);
    int rv;

    if (err) {
	fprintf(stderr, "open error on %s: %s\n", gtconn->ios,
		gensio_err_to_str(err));
	fflush(stderr);
	io_closed(io, NULL);
	gshutdown(ioinfo, false);
    } else {
	if (g->print_laddr)
	    print_io_addr(io, true);
	if (g->print_raddr)
	    print_io_addr(io, false);

	rv = gensio_open(ogtconn->io, io_open, NULL);
	if (rv) {
	    fprintf(stderr, "Could not open %s: %s\n", ogtconn->ios,
		    gensio_err_to_str(rv));
	    fflush(stderr);
	    io_closed(ogtconn->io, NULL);
	    gshutdown(ioinfo, false);
	} else {
	    ioinfo_set_ready(ioinfo, io);
	}
    }
}

static int
add_io(struct gtinfo *g, struct gensio *io, bool open_finished)
{
    struct gensio_os_funcs *o = g->o;
    int err = GE_NOMEM;
    struct ioinfo_sub_handlers *sh1 = NULL, *sh2 = NULL;
    void *subdata1 = NULL, *subdata2 = NULL;
    struct ioinfo *ioinfo1 = NULL, *ioinfo2 = NULL;
    struct gtconn_info *gtconn1 = NULL, *gtconn2 = NULL;

    gtconn1 = o->zalloc(o, sizeof(*gtconn1));
    if (!gtconn1) {
	fprintf(stderr, "Could not allocate gtconn 1\n");
	goto out_err;
    }
    gtconn2 = o->zalloc(o, sizeof(*gtconn2));
    if (!gtconn2) {
	fprintf(stderr, "Could not allocate gtconn 2\n");
	goto out_err;
    }

    gtconn1->g = g;
    gtconn2->g = g;

    subdata1 = alloc_ser_ioinfo(o, g->signature, &sh1);
    if (!subdata1) {
	fprintf(stderr, "Could not allocate subdata 1\n");
	goto out_err;
    }
    subdata2 = alloc_ser_ioinfo(o, g->signature, &sh2);
    if (!subdata2) {
	fprintf(stderr, "Could not allocate subdata 2\n");
	goto out_err;
    }

    ioinfo1 = alloc_ioinfo(o, g->escape_char, sh1, subdata1, &guh, gtconn1);
    if (!ioinfo1) {
	fprintf(stderr, "Could not allocate ioinfo 1\n");
	goto out_err;
    }
    ioinfo2 = alloc_ioinfo(o, -1, sh2, subdata2, &guh, gtconn2);
    if (!ioinfo2) {
	fprintf(stderr, "Could not allocate ioinfo 2\n");
	goto out_err;
    }

    ioinfo_set_otherioinfo(ioinfo1, ioinfo2);

    err = str_to_gensio(g->ios1, o, NULL, ioinfo1, &gtconn1->io);
    if (err) {
	fprintf(stderr, "Could not allocate %s: %s\n",
		g->ios1, gensio_err_to_str(err));
	goto out_err;
    }

    gtconn1->ios = g->ios1;
    gtconn2->ios = g->ios2;
    gtconn1->user_io = gtconn1->io;
    gtconn2->user_io = gtconn1->io;
    gtconn2->io = io;

    if (open_finished)
	ioinfo_set_ready(ioinfo2, gtconn2->io);
    else
	gensio_set_user_data(gtconn2->io, ioinfo2);

    if (g->print_laddr)
	print_io_addr(io, true);
    if (g->print_raddr)
	print_io_addr(io, false);
    if (debug)
	printf("Connected\r\n");

    gensio_list_add_tail(&g->io_list, &gtconn1->link);
    gensio_list_add_tail(&g->io_list, &gtconn2->link);
    return 0;

 out_err:
    if (subdata1)
	free_ser_ioinfo(subdata1);
    if (subdata2)
	free_ser_ioinfo(subdata2);
    if (gtconn1)
	o->free(o, gtconn1);
    if (gtconn2)
	o->free(o, gtconn2);
    if (ioinfo1)
	free_ioinfo(ioinfo1);
    if (ioinfo2)
	free_ioinfo(ioinfo2);
    return err;
}

static int
io_acc_event(struct gensio_accepter *accepter, void *user_data,
	     int event, void *data)
{
    struct gtinfo *g = user_data;
    int err;

    if (event == GENSIO_ACC_EVENT_LOG) {
	struct gensio_loginfo *li = data;

	vfprintf(stderr, li->str, li->args);
	fprintf(stderr, "\n");
	fflush(stderr);

	g->err = 1;
	g->o->wake(g->waiter);
	return 0;
    }

    if (event == GENSIO_ACC_EVENT_NEW_CONNECTION) {
	struct gensio *io = data;
	struct ioinfo *ioinfo;
	struct ioinfo *oioinfo;
	struct gtconn_info *ogtconn;

	if (g->server_mode || gensio_list_empty(&g->io_list)) {
	    err = add_io(g, io, true);
	    if (err) {
		gensio_free(io);
		return 0;
	    }

	    ioinfo = gensio_get_user_data(io);
	    oioinfo = ioinfo_otherioinfo(ioinfo);
	    ogtconn = ioinfo_userdata(oioinfo);

	    err = gensio_open(ogtconn->io, io_open, NULL);
	    if (err) {
		g->err = err;
		fprintf(stderr, "Could not open %s: %s\n", ogtconn->ios,
			gensio_err_to_str(err));
		fflush(stderr);
		io_closed(ogtconn->io, NULL);
		gshutdown(ioinfo, false);
		return 0;
	    }
	} else {
	    gensio_free(data);
	}
	if (!g->server_mode && g->acc) {
	    gensio_acc_free(g->acc);
	    g->acc = NULL;
	}

	return 0;
    }

    return GE_NOTSUP;
}

static const char *progname;
static char *io1_default_tty = "stdio(self,raw)";
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
    printf(" --server - When an accept happens, do not shut down the accepter\n"
	   " and continue to accept connections.  Do not terminate when\n"
	   " all the connections close.\n");
    printf("  -l, --printlocaddr - When the connection opens, print out all"
	   " the local addresses.\n");
    printf("  -r, --printremaddr - When the connection opens, print out all"
	   " the remote addresses.\n");
    printf("  -v, --verbose - Print all gensio logs\n");
    printf("  --signature <sig> - Set the RFC2217 server signature to <sig>\n");
    printf("  -e, --escchar - Set the local terminal escape character.\n"
	   "    Set to -1 to disable the escape character\n"
	   "    Default is ^\\ for tty stdin and disabled for non-tty stdin\n");
    printf("  -h, --help - This help\n");
    gensio_osfunc_exit(err);
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
    fflush(stderr);
}

int
main(int argc, char *argv[])
{
    int arg, rv;
    struct gtinfo g;
    bool io2_do_acc = false, io2_acc_print = false;
    bool esc_set = false;
    bool io1_set = false;
    const char *deftty = io1_default_notty;
    const char *filename;
    bool use_glib = false;
    bool use_tcl = false;
    gensio_time endwait = { 5, 0 };
    struct gensio *io = NULL;
    struct gensio_os_proc_data *proc_data = NULL;

    memset(&g, 0, sizeof(g));
    g.escape_char = -1;
    gensio_list_init(&g.io_list);

    progname = argv[0];

    if (can_do_raw()) {
	g.escape_char = 0x1c; /* ^\ */
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
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--server", NULL)))
	    g.server_mode = true;
	else if ((rv = cmparg(argc, argv, &arg, "-l", "--printlocaddr", NULL)))
	    g.print_laddr = true;
	else if ((rv = cmparg(argc, argv, &arg, "-r", "--printremaddr", NULL)))
	    g.print_raddr = true;
	else if ((rv = cmparg(argc, argv, &arg, "-v", "--verbose", NULL)))
	    gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	else if ((rv = cmparg_int(argc, argv, &arg, "-e", "--escchar",
				  &g.escape_char)))
	    esc_set = true;
	else if ((rv = cmparg(argc, argv, &arg, "", "--glib", NULL)))
	    use_glib = true;
	else if ((rv = cmparg(argc, argv, &arg, "", "--tcl", NULL)))
	    use_tcl = true;
	else if ((rv = cmparg(argc, argv, &arg, "", "--signature",
			      &g.signature)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, "-d", "--debug", NULL))) {
	    debug++;
	    if (debug > 1)
		gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else if ((rv = cmparg(argc, argv, &arg, "-h", "--help", NULL)))
	    help(0);
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--dummyrand",
			      &filename))) {
#if HAVE_OPENSSL
	    /*
	     * This option is undocumented and only for testing.  Do not
	     * use it!
	     */
	    if (dummyrnd_file)
		fclose(dummyrnd_file);
	    dummyrnd_file = fopen(filename, "r");
	    if (!dummyrnd_file) {
		fprintf(stderr, "Could not open rand file\n");
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
	g.escape_char = -1; /* disable */

    if (arg >= argc) {
	fprintf(stderr, "No gensio string given to connect to\n");
	help(1);
    }

    g.ios1 = deftty;
    g.ios2 = argv[arg];

    if (use_glib) {
#ifndef HAVE_GLIB
	fprintf(stderr, "glib specified, but glib OS handler not avaiable.\n");
	exit(1);
#else
	rv = gensio_glib_funcs_alloc(&g.o);
#endif
    } else if (use_tcl) {
#ifndef HAVE_TCL
	fprintf(stderr, "tcl specified, but tcl OS handler not avaiable.\n");
	exit(1);
#else
	rv = gensio_tcl_funcs_alloc(&g.o);
#endif
    } else {
	rv = gensio_default_os_hnd(0, &g.o);
    }
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }
    g.o->vlog = do_vlog;

    g.waiter = g.o->alloc_waiter(g.o);
    if (!g.waiter) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not allocate OS waiter\n");
	goto out_err;
    }

    rv = gensio_os_proc_setup(g.o, &proc_data);
    if (rv) {
	fprintf(stderr, "Error setting up process data: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }

    if (io2_do_acc)
	rv = str_to_gensio_accepter(g.ios2, g.o, io_acc_event, &g, &g.acc);
    else
	rv = str_to_gensio(g.ios2, g.o, NULL, &g, &io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", g.ios2,
		gensio_err_to_str(rv));
	goto out_err;
    }

    if (io2_do_acc) {
	rv = gensio_acc_startup(g.acc);
	if (rv)
	    fprintf(stderr, "Could not start %s: %s\n", g.ios2,
		    gensio_err_to_str(rv));
	else if (io2_acc_print)
	    rv = print_local_acc_addr(g.acc);
	if (rv)
	    goto out_err;
    } else {
	rv = add_io(&g, io, false);
	if (rv) {
	    gensio_free(io);
	    io = NULL;
	    goto out_err;
	}
	rv = gensio_open(io, io_open_paddr, &g);
	if (rv) {
	    struct ioinfo *ioinfo = gensio_get_user_data(io);

	    io_closed(io, NULL);
	    io = NULL;
	    fprintf(stderr, "Could not open %s: %s\n", g.ios2,
		    gensio_err_to_str(rv));
	    gshutdown(ioinfo, false);
	}
	io = NULL;
    }

    g.o->wait(g.waiter, 1, NULL);

 out_err:
    if (io)
	gensio_free(io);
    if (g.acc)
	gensio_acc_free(g.acc);

    if (!rv && g.err)
	rv = g.err;

    /*
     * We wait until there are no gensios left pending.  You can get
     * into situations where there is an incoming gensio accept that
     * fails and does not complete, but it's still not freed and is
     * pending close.  Wait for all gensios to finish freeing to avoid
     * memory errors.
     */
    if (gensio_num_alloced() == 0)
	endwait.secs = 0; /* Just run events until we are out. */
    while (g.o && g.o->service(g.o, &endwait) != GE_TIMEDOUT) {
	if (gensio_num_alloced() == 0) {
	    /* Waiting for no gensios left, then run events til we are out. */
	    endwait.secs = 0;
	    endwait.nsecs = 0;
	}
    }
    if (g.waiter)
	g.o->free_waiter(g.waiter);
    if (proc_data)
	gensio_os_proc_cleanup(proc_data);
    if (g.o) {
	gensio_cleanup_mem(g.o);
	g.o->free_funcs(g.o);
    }
    gensio_osfunc_exit(!!rv);
}
