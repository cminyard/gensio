/*
 *  gmdns - A program for playing with MDNS
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
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
#include <string.h>
#include <stdlib.h>
#include <gensio/gensio.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_mdns.h>
#include <gensio/gensio_selector.h>
#include <gensio/argvutils.h>
#include "utils.h"

static const char *progname;
static int debug;
static bool close_on_done;

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

struct freed_data {
    struct gensio_os_funcs *o;
    struct gensio_waiter *closewaiter;
};

static void mdns_freed(struct gensio_mdns *m, void *userdata)
{
    struct freed_data *f = userdata;

    gensio_os_funcs_wake(f->o, f->closewaiter);
}

static void mdns_watch_freed(struct gensio_mdns_watch *w, void *userdata)
{
    struct freed_data *f = userdata;

    gensio_os_funcs_wake(f->o, f->closewaiter);
}

static const char *
ip_domain_to_str(int ipdomain)
{
    switch(ipdomain) {
    case GENSIO_NETTYPE_UNSPEC:
	return "unspec";
    case GENSIO_NETTYPE_IPV4:
	return "ipv4";
    case GENSIO_NETTYPE_IPV6:
	return "ipv6";
    case GENSIO_NETTYPE_UNIX:
	return "unix";
    default:
	return "invalid";
    }
}

static void
mdns_info_found(struct gensio_mdns_watch *w,
		enum gensio_mdns_data_state state,
		int interface, int ipdomain,
		const char *name, const char *type,
		const char *domain, const char *host,
		const struct gensio_addr *addr,
		const char * const *txt, void *userdata)
{
    char strbuf[250];
    const char * const *s;
    int rv;
    struct freed_data *f = userdata;

    if (state == GENSIO_MDNS_ALL_FOR_NOW) {
	printf("All-for-now:\n");
	if (close_on_done)
	    gensio_os_funcs_wake(f->o, f->closewaiter);
	return;
    }

    printf("%s:\n interface: %d\n iptype: %s\n",
	   state == GENSIO_MDNS_NEW_DATA ? "Found" : "Removed",
	   interface, ip_domain_to_str(ipdomain));
    printf(" name: '%s'\n type: '%s'\n domain: '%s'\n host: '%s'\n",
	   name, type, domain, host);
    rv = gensio_addr_to_str(addr, strbuf, NULL, sizeof(strbuf));
    if (!rv)
	printf(" addr: '%s'\n", strbuf);
    if (txt) {
	printf(" txt:\n");
	for (s = txt; *s; s++)
	    printf("  '%s'\n", *s);
    }
}

static void
term_handler(void *handler_data)
{
    struct freed_data *f = handler_data;

    gensio_os_funcs_wake(f->o, f->closewaiter);
}

static void
help(int err)
{
    printf("%s [options]\n", progname);
    printf("\nA program to do mdns handling.\n");
    printf("\noptions are:\n");
    printf("  -n, --name <str> - The name to search for or service broadcast.\n"
	   "    Required for service.\n");
    printf("  -t, --type <str> - The type to search for or service broadcast.\n"
	   "    Required for service.\n");
    printf("  -m, --domain <str> - The domain to search for or service\n"
	   "    broadcast.  Defaults to 'local'\n");
    printf("  -o, --host <str> - The host to search for or service broadcast.\n"
	   "    Defaults to anything\n");
    printf("  -i, --interface <int>- The net interface to search on or\n"
	   "    service broadcast.  Defaults to all interfaces\n");
    printf("  -y, --nettype <nt> - The net type to search on or service\n"
	   "    broadcast.  Defaults to unspec.  May be ipv4, ipv6, or\n"
	   "    unspec\n");
    printf("  -s, --service - Broadcast the service instead of looking for\n"
	   "    the service\n");
    printf("  -p, --port - Port for the service broadcast\n");
    printf("  -x, --txt <str> - Add the text field to the service broadcast\n");
    printf("  -c, --close-on-done - Shut down after the first scan of data\n");
    printf("  -d, --debug - Increment debug level\n");
    printf("  -h, --help - This help\n");
    gensio_osfunc_exit(err);
}

int
main(int argc, char *argv[])
{
    struct gensio_os_funcs *o = NULL;
    struct gensio_waiter *closewaiter = NULL;
    struct gensio_mdns *mdns = NULL;
    struct gensio_mdns_watch *watch = NULL;
    struct gensio_mdns_service *service = NULL;
    struct freed_data fdata;
    int rv, arg, err;
    const char *name = NULL, *type = NULL, *domain = NULL, *host = NULL;
    int interface = -1, nettype = GENSIO_NETTYPE_UNSPEC, port = -1;
    const char *nettype_str = NULL;
    const char *txtstr = NULL;
    const char **txt = NULL;
    gensiods txtargc = 0, txtargs = 0;
    bool do_service = false;
    struct gensio_os_proc_data *proc_data;

    progname = argv[0];

    rv = gensio_default_os_hnd(0, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_set_vlog(o, do_vlog);

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != '-')
	    break;
	if ((rv = cmparg(argc, argv, &arg, "-n", "--name", &name))) {
	    ;
	} else if ((rv = cmparg(argc, argv, &arg, "-t", "--type", &type))) {
	    ;
	} else if ((rv = cmparg(argc, argv, &arg, "-m", "--domain", &domain))) {
	    ;
	} else if ((rv = cmparg(argc, argv, &arg, "-o", "--host", &host))) {
	    ;
	} else if ((rv = cmparg_int(argc, argv, &arg, "-i", "--interface",
				    &interface))) {
	    ;
	} else if ((rv = cmparg(argc, argv, &arg, "-y", "--nettype",
				&nettype_str))) {
	    if (strcmp(nettype_str, "ipv4") == 0)
		nettype = GENSIO_NETTYPE_IPV4;
	    else if (strcmp(nettype_str, "ipv6") == 0)
		nettype = GENSIO_NETTYPE_IPV6;
	    else if (strcmp(nettype_str, "unspec") == 0)
		nettype = GENSIO_NETTYPE_UNSPEC;
	    else {
		fprintf(stderr, "Invalid nettype: %s\n", nettype_str);
		help(1);
	    }
	} else if ((rv = cmparg(argc, argv, &arg, "-s", "--service", NULL))) {
	    do_service = true;
	} else if ((rv = cmparg_int(argc, argv, &arg, "-p", "--port",
				    &port))) {
	    ;
	} else if ((rv = cmparg(argc, argv, &arg, "-x", "--txt", &txtstr))) {
	    err = gensio_argv_append(o, &txt, txtstr, &txtargs, &txtargc, true);
	    if (err) {
		fprintf(stderr, "Unable to append text argument: %s\n",
			gensio_err_to_str(err));
		exit(1);
	    }
	} else if ((rv = cmparg(argc, argv, &arg, "-c", "--close-on-done",
				NULL))) {
	    close_on_done = true;
	} else if ((rv = cmparg(argc, argv, &arg, "-d", "--debug", NULL))) {
	    debug++;
	    if (debug > 1)
		gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else if ((rv = cmparg(argc, argv, &arg, "-h", "--help", NULL))) {
	    help(0);
	} else {
	    fprintf(stderr, "Unknown argument: %s\n", argv[arg]);
	    help(1);
	}
	if (rv < 0)
	    return 1;
    }

    rv = gensio_os_proc_setup(o, &proc_data);
    if (rv) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	gensio_os_funcs_free(o);
	return 1;
    }

    closewaiter = gensio_os_funcs_alloc_waiter(o);
    if (!closewaiter) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not allocate close waiter\n");
	goto out_err;
    }

    fdata.o = o;
    fdata.closewaiter = closewaiter;

    rv = gensio_os_proc_register_term_handler(proc_data, term_handler, &fdata);
    if (rv) {
	fprintf(stderr, "Can't register term handler: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_alloc_mdns(o, &mdns);
    if (rv) {
	fprintf(stderr, "Could not allocate mdns handler: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }

    if (do_service) {
	if (!name) {
	    fprintf(stderr, "Name must be set for service\n");
	    goto out_err;
	}
	if (!type) {
	    fprintf(stderr, "Type must be set for service\n");
	    goto out_err;
	}
	if (port < 1) {
	    fprintf(stderr, "Port must be set > 1 for service\n");
	    goto out_err;
	}
	/* NULL terminate txt. */
	err = gensio_argv_append(o, &txt, NULL, &txtargs, &txtargc, false);
	if (err) {
	    fprintf(stderr, "Unable to append text argument: %s\n",
			gensio_err_to_str(err));
	    exit(1);
	}
	rv = gensio_mdns_add_service(mdns, interface, nettype,
				     name, type, domain, host,
				     port, txt, &service);
	if (rv) {
	    fprintf(stderr, "Could not allocate mdns service: %s\n",
		    gensio_err_to_str(rv));
	    goto out_err;
	}
    } else {
	rv = gensio_mdns_add_watch(mdns, interface, nettype,
				   name, type, domain, host,
				   mdns_info_found, &fdata, &watch);
	if (rv) {
	    fprintf(stderr, "Could not allocate mdns watcher: %s\n",
		    gensio_err_to_str(rv));
	    goto out_err;
	}
    }

    gensio_os_funcs_wait(o, closewaiter, 1, NULL);

 out_err:
    if (service) {
	rv = gensio_mdns_remove_service(service);
	if (rv)
	    fprintf(stderr, "Could not free mdns service: %s\n",
		    gensio_err_to_str(rv));
    }
    if (watch) {
	rv = gensio_mdns_remove_watch(watch, mdns_watch_freed, &fdata);
	if (rv)
	    fprintf(stderr, "Could not free mdns watch: %s\n",
		    gensio_err_to_str(rv));
	else
	    gensio_os_funcs_wait(o, closewaiter, 1, NULL);
    }

    if (mdns) {
	rv = gensio_free_mdns(mdns, mdns_freed, &fdata);
	if (rv)
	    fprintf(stderr, "Could not free mdns handler: %s\n",
		    gensio_err_to_str(rv));
	else
	    gensio_os_funcs_wait(o, closewaiter, 1, NULL);
    }

    if (txt)
	gensio_argv_free(o, txt);

    if (o && closewaiter)
	gensio_os_funcs_free_waiter(o, closewaiter);
    if (o) {
	gensio_time endwait = { 0, 0 };

	while (gensio_os_funcs_service(o, &endwait) != GE_TIMEDOUT)
	    ;
	gensio_cleanup_mem(o);
	gensio_os_funcs_free(o);
	gensio_os_proc_cleanup(proc_data);
    }
    gensio_osfunc_exit(!!rv);
}
