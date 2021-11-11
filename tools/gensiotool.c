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

#ifdef _WIN32
#define SIGUSR1 0
#else
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <syslog.h>
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
    struct gensio_lock *lock;
#ifndef _WIN32
    bool err_syslog;
    const char *pid_file;
#endif
    const char *ios1;
    const char *ios2;
    int escape_char;
    const char *signature;
    bool print_laddr;
    bool print_raddr;

    int err;

    bool server_mode;
    bool in_shutdown;

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
vreport_err(struct gtinfo *g, const char *fmt, va_list ap)
{
#ifndef _WIN32
    if (g->err_syslog) {
	vsyslog(LOG_ERR, fmt, ap);
	return;
    }
#endif
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    fflush(stdout);
}

static void
report_err(struct gtinfo *g, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vreport_err(g, fmt, ap);
    va_end(ap);
}

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

    gensio_list_rm(&g->io_list, &gtconn->link);
    gensio_list_rm(&g->io_list, &ogtconn->link);

    io = ioinfo_io(ioinfo);
    if (io)
	gensio_free(io);
    io = ioinfo_io(oioinfo);
    if (io)
	gensio_free(io);

    o->free(o, gtconn);
    o->free(o, ogtconn);

    free_ioinfo(ioinfo);
    free_ioinfo(oioinfo);
    free_ser_ioinfo(subdata);
    free_ser_ioinfo(osubdata);

    if (!g->server_mode || (g->in_shutdown && gensio_list_empty(&g->io_list)))
	g->o->wake(g->waiter);
}

static void
i_io_closed(struct gensio *io, void *close_data)
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
io_closed(struct gensio *io, void *close_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);
    struct gtinfo *g = gtconn->g;

    g->o->lock(g->lock);
    i_io_closed(io, close_data);
    g->o->unlock(g->lock);
}

static void
i_gshutdown(struct ioinfo *ioinfo, bool user_req)
{
    struct ioinfo *oioinfo = ioinfo_otherioinfo(ioinfo);
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);
    struct gtconn_info *ogtconn = ioinfo_userdata(oioinfo);
    struct gtinfo *g = gtconn->g;
    int err;

    if (gtconn->io) {
	ioinfo_set_not_ready(ioinfo);
	err = gensio_close(gtconn->io, io_closed, NULL);
	if (err)
	    i_io_closed(gtconn->io, NULL);
	gtconn->io = NULL;
    }
    if (ogtconn->io) {
	/*
	 * Do not set the other end not ready.  It may still fail, and
	 * for oomtest to work it has to get that failure.  So let it
	 * report the error if it happens.
	 */
	err = gensio_close(ogtconn->io, io_closed, NULL);
	if (err)
	    i_io_closed(ogtconn->io, NULL);
	ogtconn->io = NULL;
    }
    if (!g->err && !user_req)
	g->err = GE_IOERR;
}

static void
gshutdown(struct ioinfo *ioinfo, bool user_req)
{
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);
    struct gtinfo *g = gtconn->g;

    g->o->lock(g->lock);
    i_gshutdown(ioinfo, user_req);
    g->o->unlock(g->lock);
}

static void
gerr(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    struct gtconn_info *gtconn = ioinfo_userdata(ioinfo);
    char str[200];

    vsnprintf(str, sizeof(str), fmt, ap);
    report_err(gtconn->g, "Error on %s: %s\r", gtconn->ios, str);
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
    struct gtinfo *g = gtconn->g;

    if (err) {
	if (!g->err)
	    g->err = err;
	report_err(gtconn->g, "open error on %s: %s", gtconn->ios,
		   gensio_err_to_str(err));
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
	if (!g->err)
	    g->err = err;
	report_err(g, "open error on %s: %s", gtconn->ios,
		   gensio_err_to_str(err));
	gshutdown(ioinfo, false);
    } else {
	if (g->print_laddr)
	    print_io_addr(io, true);
	if (g->print_raddr)
	    print_io_addr(io, false);

	rv = gensio_open(ogtconn->io, io_open, NULL);
	if (rv) {
	    report_err(g, "Could not open %s: %s", ogtconn->ios,
		       gensio_err_to_str(rv));
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
	report_err(g, "Could not allocate gtconn 1");
	goto out_err;
    }
    gtconn2 = o->zalloc(o, sizeof(*gtconn2));
    if (!gtconn2) {
	report_err(g, "Could not allocate gtconn 2");
	goto out_err;
    }

    gtconn1->g = g;
    gtconn2->g = g;

    subdata1 = alloc_ser_ioinfo(o, g->signature, &sh1);
    if (!subdata1) {
	report_err(g, "Could not allocate subdata 1");
	goto out_err;
    }
    subdata2 = alloc_ser_ioinfo(o, g->signature, &sh2);
    if (!subdata2) {
	report_err(g, "Could not allocate subdata 2");
	goto out_err;
    }

    ioinfo1 = alloc_ioinfo(o, g->escape_char, sh1, subdata1, &guh, gtconn1);
    if (!ioinfo1) {
	report_err(g, "Could not allocate ioinfo 1");
	goto out_err;
    }
    ioinfo2 = alloc_ioinfo(o, -1, sh2, subdata2, &guh, gtconn2);
    if (!ioinfo2) {
	report_err(g, "Could not allocate ioinfo 2");
	goto out_err;
    }

    ioinfo_set_otherioinfo(ioinfo1, ioinfo2);

    err = str_to_gensio(g->ios1, o, NULL, ioinfo1, &gtconn1->io);
    if (err) {
	report_err(g, "Could not allocate %s: %s",
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
    if (!g->server_mode)
	g->o->wake(g->waiter);
    return err;
}

static void
i_handle_term(struct gtinfo *g)
{
    struct gensio_link *link;
    bool closed_one = false;
    int err;

    g->in_shutdown = true;
    if (g->acc) {
	gensio_acc_free(g->acc);
	g->acc = NULL;
    }
    gensio_list_for_each(&g->io_list, link) {
	struct gtconn_info *gtconn = gensio_container_of(link,
							 struct gtconn_info,
							 link);

	closed_one = true;
	if (gtconn->io) {
	    err = gensio_close(gtconn->io, io_closed, NULL);
	    if (err)
		i_io_closed(gtconn->io, NULL);
	    gtconn->io = NULL;
	}
    }
    if (!closed_one)
	g->o->wake(g->waiter);
}

static void
handle_term(void *info)
{
    struct gtinfo *g = info;

    g->o->lock(g->lock);
    i_handle_term(g);
    g->o->unlock(g->lock);
}

static int
io_acc_event(struct gensio_accepter *accepter, void *user_data,
	     int event, void *data)
{
    struct gtinfo *g = user_data;
    int err;

    if (event == GENSIO_ACC_EVENT_LOG) {
	struct gensio_loginfo *li = data;

	vreport_err(g, li->str, li->args);

	g->err = 1;
	g->o->wake(g->waiter);
	return 0;
    }

    if (event == GENSIO_ACC_EVENT_NEW_CONNECTION) {
	struct gensio *io = data;
	struct ioinfo *ioinfo;
	struct ioinfo *oioinfo;
	struct gtconn_info *ogtconn;

	g->o->lock(g->lock);
	if (g->in_shutdown) {
	    gensio_free(io);
	} else if (g->server_mode || gensio_list_empty(&g->io_list)) {
	    err = add_io(g, io, true);
	    if (err) {
		g->err = err;
		gensio_free(io);
		if (!g->server_mode)
		    i_handle_term(g);
		goto out_unlock;
	    }

	    ioinfo = gensio_get_user_data(io);
	    oioinfo = ioinfo_otherioinfo(ioinfo);
	    ogtconn = ioinfo_userdata(oioinfo);

	    err = gensio_open(ogtconn->io, io_open, NULL);
	    if (err) {
		g->err = err;
		report_err(g, "Could not open %s: %s", ogtconn->ios,
			gensio_err_to_str(err));
		i_gshutdown(ioinfo, false);
		goto out_unlock;
	    }
	} else {
	    gensio_free(data);
	}
	if (!g->server_mode && g->acc) {
	    gensio_acc_free(g->acc);
	    g->acc = NULL;
	}
    out_unlock:
	g->o->unlock(g->lock);

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
    printf("  -n, --extra-threads <n> - Spawn <n> extra threads to handle\n"
	   "    gensio operations.  Useful for scalabiity with --server.\n");
    printf("  --server - When an accept happens, do not shut down the\n"
	   "    accepter and continue to accept connections.  Do not\n"
	   "    terminate when all the connections close.\n");
    printf("  -l, --printlocaddr - When the connection opens, print out all"
	   " the local addresses.\n");
    printf("  -r, --printremaddr - When the connection opens, print out all"
	   " the remote addresses.\n");
    printf("  -v, --verbose - Print all gensio logs\n");
    printf("  --signature <sig> - Set the RFC2217 server signature to <sig>\n");
#ifndef _WIN32
    printf("  -P, --pidfile <file> - Create a pid file.\n");
#endif
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
    char buf[200];

    if (!debug)
	return;
    vsnprintf(buf, sizeof(buf), log, args);

    report_err(f->other_data, "gensio %s log: %s",
	       gensio_log_level_to_str(level), buf);
}

struct gensio_loop_info
{
    struct gensio_os_funcs *o;
    struct gensio_thread *loopth;
    struct gensio_waiter *loopwaiter;
};

static void
gensio_loop(void *info)
{
    struct gensio_loop_info *li = info;

    li->o->wait(li->loopwaiter, 1, NULL);
}

#ifndef _WIN32
static void
make_pidfile(struct gtinfo *g)
{
    FILE *fpidfile;

    if (!g->pid_file)
	return;
    fpidfile = fopen(g->pid_file, "w");
    if (!fpidfile) {
	report_err(g, "Error opening pidfile '%s': %s, pidfile not created",
		   g->pid_file, strerror(errno));
	g->pid_file = NULL;
	return;
    }
    fprintf(fpidfile, "%d\n", getpid());
    fclose(fpidfile);
}
#endif

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
    const char *tmpstr;
    bool use_glib = false;
    bool use_tcl = false;
    gensio_time endwait = { 5, 0 };
    struct gensio *io = NULL;
    struct gensio_os_proc_data *proc_data = NULL;
    unsigned int num_extra_threads = 0, i;
    struct gensio_loop_info *loopinfo = NULL;

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
#ifndef _WIN32
	else if ((rv = cmparg(argc, argv, &arg, "-P", "--pidfile",
			      &g.pid_file)))
	    ;
	else if ((rv = cmparg(argc, argv, &arg, NULL, "--syslog", NULL)))
	    g.err_syslog = true;
#endif
	else if ((rv = cmparg(argc, argv, &arg, "-n", "--extra-threads",
			      &tmpstr)))
	    num_extra_threads = strtol(tmpstr, NULL, 0);
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

#ifndef _WIN32
    if (g.err_syslog)
	openlog(argv[0], 0, LOG_DAEMON);
    make_pidfile(&g);
#endif

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
	if (num_extra_threads > 0)
	    fprintf(stderr, "Number of extra threads is %u, incompatible with"
		    " TCL, forcing to 0\n", num_extra_threads);
	num_extra_threads = 0;
	rv = gensio_tcl_funcs_alloc(&g.o);
#endif
    } else {
	rv = gensio_default_os_hnd(SIGUSR1, &g.o);
    }
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }
    g.o->other_data = &g;
    g.o->vlog = do_vlog;

    g.waiter = g.o->alloc_waiter(g.o);
    if (!g.waiter) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not allocate OS waiter\n");
	goto out_err;
    }

    g.lock = g.o->alloc_lock(g.o);
    if (!g.lock) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not allocate OS lock\n");
	goto out_err;
    }

    rv = gensio_os_proc_setup(g.o, &proc_data);
    if (rv) {
	fprintf(stderr, "Error setting up process data: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = GE_NOMEM;
    if (num_extra_threads > 0) {
	loopinfo = g.o->zalloc(g.o, sizeof(*loopinfo) * num_extra_threads);
	if (!loopinfo)
	    goto out_err;
    }

    for (i = 0; i < num_extra_threads; i++) {
	loopinfo[i].o = g.o;
	loopinfo[i].loopwaiter = g.o->alloc_waiter(g.o);
	if (!loopinfo[i].loopwaiter) {
	    fprintf(stderr, "Could not allocate loop waiter\n");
	    goto out_err;
	}

	rv = gensio_os_new_thread(g.o, gensio_loop, loopinfo + i,
				  &loopinfo[i].loopth);
	if (rv) {
	    fprintf(stderr, "Could not allocate loop thread: %s",
		    gensio_err_to_str(rv));
	    goto out_err;
	}
	rv = GE_NOMEM;
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
	g.o->lock(g.lock);
	rv = add_io(&g, io, false);
	if (rv) {
	    gensio_free(io);
	    io = NULL;
	    g.o->unlock(g.lock);
	    goto out_err;
	}
	rv = gensio_open(io, io_open_paddr, &g);
	if (rv) {
	    struct ioinfo *ioinfo = gensio_get_user_data(io);

	    fprintf(stderr, "Could not open %s: %s\n", g.ios2,
		    gensio_err_to_str(rv));
	    i_gshutdown(ioinfo, false);
	}
	g.o->unlock(g.lock);
	io = NULL;
    }

    rv = gensio_os_proc_register_term_handler(proc_data, handle_term, &g);
    if (rv)
	handle_term(&g);

    g.o->wait(g.waiter, 1, NULL);

 out_err:
    if (io)
	gensio_free(io);
    if (g.lock)
	g.o->lock(g.lock);
    if (g.acc) {
	gensio_acc_free(g.acc);
	g.acc = NULL;
    }
    if (g.lock)
	g.o->unlock(g.lock);

    if (!rv && g.err)
	rv = g.err;

    for (i = 0; loopinfo && i < num_extra_threads; i++) {
	if (loopinfo[i].loopth) {
	    g.o->wake(loopinfo[i].loopwaiter);
	    gensio_os_wait_thread(loopinfo[i].loopth);
	}
	if (loopinfo[i].loopwaiter)
	    g.o->free_waiter(loopinfo[i].loopwaiter);
    }
    if (loopinfo)
	g.o->free(g.o, loopinfo);

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
    if (g.lock)
	g.o->free_lock(g.lock);
    if (proc_data)
	gensio_os_proc_cleanup(proc_data);
    if (g.o) {
	gensio_cleanup_mem(g.o);
	g.o->free_funcs(g.o);
    }

#ifndef _WIN32
    if (g.pid_file)
	unlink(g.pid_file);
    if (g.err_syslog)
	closelog();
#endif

    gensio_osfunc_exit(!!rv);
}
