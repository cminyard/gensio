/*
 *  localport - A library for handling local gensio connections to mux channel
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <gensio/gensio_list.h>
#include "localports.h"
#include "ioinfo.h"
#include "utils.h"

void (*localport_err)(const char *format, va_list ap);

static void
localport_pr(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    localport_err(format, ap);
    va_end(ap);
}

struct local_portinfo {
    char *accepter_str;
    char *service_str;
    char *id_str;

    struct gensio_os_funcs *o;
    struct gensio_accepter *accepter;

    struct local_portinfo *next;
};

static struct local_portinfo *local_ports;
static bool started;
struct gensio *base_io;

struct portcon {
    struct gensio *io1;
    struct gensio *io2;
    bool io2_open;
    char *id_str;

    struct gensio_link link;
};

static struct gensio_list portcons;

static void
pshutdown(struct ioinfo *ioinfo1, bool user_req)
{
    struct portcon *pc = ioinfo_userdata(ioinfo1);
    struct ioinfo *ioinfo2;

    ioinfo2 = ioinfo_otherioinfo(ioinfo1);
    gensio_free(pc->io1);
    gensio_free(pc->io2);
    free_ioinfo(ioinfo1);
    free_ioinfo(ioinfo2);
    gensio_list_rm(&portcons, &pc->link);
    free(pc);
}

static void
perr(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    struct portcon *pc = ioinfo_userdata(ioinfo);
    char *s;

    s = alloc_vsprintf(fmt, ap);

    if (s) {
	localport_pr("Error on %s: %s\n", pc->id_str, s);
	free(s);
    } else {
	localport_pr("Error on %s: \n", pc->id_str);
	localport_err(fmt, ap);
	localport_pr("\n");
    }
}

static void
pout(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    /* There should never be anything to print. */
}

static struct ioinfo_user_handlers puh = {
    .shutdown = pshutdown,
    .err = perr,
    .out = pout
};

static void
popen_done(struct gensio *io, int err, void *open_data)
{
    struct portcon *pc = open_data;
    struct ioinfo *ioinfo1, *ioinfo2;

    ioinfo2 = gensio_get_user_data(io);
    ioinfo1 = ioinfo_otherioinfo(ioinfo2);

    if (err) {
	localport_pr("Mux open failed for %s: %s\n",
		pc->id_str, gensio_err_to_str(err));
	pshutdown(ioinfo1, false);
	return;
    }

    pc->io2_open = true;
    ioinfo_set_ready(ioinfo1, pc->io1);
    ioinfo_set_ready(ioinfo2, pc->io2);
}

static struct portcon *
portcon_setup(struct gensio_os_funcs *o, struct gensio *io, char *id_str,
	      struct ioinfo **ioinfo1, struct ioinfo **ioinfo2)
{
    struct portcon *pc;

    pc = malloc(sizeof(*pc));
    if (!pc) {
	localport_pr(
		"Unable to allocate new connection for %s: Out of memory\n",
		id_str);
	goto out_err;
    }
    memset(pc, 0, sizeof(*pc));
    pc->id_str = id_str;

    *ioinfo1 = alloc_ioinfo(o, -1, NULL, NULL, &puh, pc);
    if (!*ioinfo1) {
	localport_pr("Could not allocate ioinfo 1\n");
	goto out_err;
    }

    *ioinfo2 = alloc_ioinfo(o, -1, NULL, NULL, &puh, pc);
    if (!*ioinfo2) {
	localport_pr("Could not allocate ioinfo 2\n");
	goto out_err;
    }

    ioinfo_set_otherioinfo(*ioinfo1, *ioinfo2);

    pc->io1 = io;
    return pc;

 out_err:
    if (pc)
	free(pc);
    return NULL;
}

static void
local_port_new_con(struct local_portinfo *pi, struct gensio *io)
{
    struct portcon *pc;
    struct ioinfo *ioinfo1 = NULL, *ioinfo2 = NULL;
    gensiods len;
    int err;

    pc = portcon_setup(pi->o, io, pi->id_str, &ioinfo1, &ioinfo2);
    if (!pc)
	goto out_err;

    err = gensio_alloc_channel(base_io, NULL, NULL, ioinfo2, &pc->io2);
    if (err) {
	localport_pr("Unable to alloc local mux channel for %s: %s\n",
		pi->id_str, gensio_err_to_str(err));
	goto out_err;
    }

    len = 1;
    gensio_control(pc->io2, 0, false, GENSIO_CONTROL_ENABLE_OOB, "1", &len);

    len = strlen(pi->service_str);
    err = gensio_control(pc->io2, 0, GENSIO_CONTROL_SET, GENSIO_CONTROL_SERVICE,
			 pi->service_str, &len);
    if (err) {
	localport_pr("Unable to set channel service for %s: %s\n",
		pi->id_str, gensio_err_to_str(err));
	goto out_err;
    }

    err = gensio_open(pc->io2, popen_done, pc);
    if (err) {
	localport_pr("Unable to open local mux channel for %s: %s\n",
		pi->id_str, gensio_err_to_str(err));
	goto out_err;
    }

    gensio_list_add_tail(&portcons, &pc->link);
    return;

 out_err:
    gensio_free(io);
    if (ioinfo1)
	free_ioinfo(ioinfo1);
    if (ioinfo2)
	free_ioinfo(ioinfo2);
    if (pc)
	free(pc);
}

void
remote_port_new_con(struct gensio_os_funcs *o, struct gensio *io,
		    const char *connecter_str, char *id_str)
{
    struct portcon *pc;
    struct ioinfo *ioinfo1 = NULL, *ioinfo2 = NULL;
    int err;

    pc = portcon_setup(o, io, id_str, &ioinfo1, &ioinfo2);
    if (!pc)
	goto out_err;

    err = str_to_gensio(connecter_str, o, NULL, ioinfo2, &pc->io2);
    if (err) {
	localport_pr("Unable to alloc for remote channel for %s: %s\n",
		     id_str, gensio_err_to_str(err));
	goto out_err;
    }

    err = gensio_open(pc->io2, popen_done, pc);
    if (err) {
	localport_pr("Unable to open local mux channel for %s: %s\n",
		     id_str, gensio_err_to_str(err));
	goto out_err;
    }

    gensio_list_add_tail(&portcons, &pc->link);
    return;

 out_err:
    gensio_free(io);
    if (ioinfo1)
	free_ioinfo(ioinfo1);
    if (ioinfo2)
	free_ioinfo(ioinfo2);
    if (pc)
	free(pc);
}

static int
local_port_accept(struct gensio_accepter *accepter,
		  void *user_data, int event, void *data)
{
    switch (event) {
    case GENSIO_ACC_EVENT_NEW_CONNECTION:
	local_port_new_con(user_data, data);
	return 0;

    case GENSIO_ACC_EVENT_LOG: {
	struct gensio_loginfo *li = data;
	struct local_portinfo *pi = user_data;
	const char *level = "unknown";

	switch (li->level) {
	case GENSIO_LOG_FATAL:	level = "fatal"; break;
	case GENSIO_LOG_ERR:	level = "err"; break;
	case GENSIO_LOG_WARNING:level = "warning"; break;
	case GENSIO_LOG_INFO:	level = "info"; break;
	case GENSIO_LOG_DEBUG:	level = "debug"; break;
	}
	localport_pr("Accept log level %s from %s: ", level, pi->id_str);
	localport_pr(li->str, li->args);
	return 0;
    }

    default:
	return GE_NOTSUP;
    }
}

static void
start_local_port(struct local_portinfo *curr)
{
    int err;

    err = str_to_gensio_accepter(curr->accepter_str, curr->o,
				 local_port_accept, curr,
				 &curr->accepter);
    if (err) {
	localport_pr("Unable to open local port %s: %s\n",
		     curr->id_str, gensio_err_to_str(err));
	return;
    }

    err = gensio_acc_startup(curr->accepter);
    if (err) {
	localport_pr("Unable to start local port %s: %s\n",
		     curr->id_str, gensio_err_to_str(err));
	gensio_acc_free(curr->accepter);
	curr->accepter = NULL;
    }
}

void
start_local_ports(struct gensio *user_io)
{
    struct local_portinfo *curr = local_ports;

    base_io = user_io;
    gensio_list_init(&portcons);
    for (; curr; curr = curr->next)
	start_local_port(curr);
    started = true;
}

int
add_local_port(struct gensio_os_funcs *o,
	       const char *gensio_str, const char *service_str,
	       const char *id_str)
{
    struct local_portinfo *np = NULL;
    int err = GE_NOMEM;

    np = malloc(sizeof(*np));
    if (!np) {
	localport_pr("Out of memory allocating port info\n");
	goto out_err;
    }
    memset(np, 0, sizeof(*np));
    np->o = o;

    np->accepter_str = strdup(gensio_str);
    if (!np->accepter_str) {
	localport_pr("Out of memory allocating accept string: %s\n",
		gensio_str);
	goto out_err;
    }

    np->service_str = strdup(service_str);
    if (!np->service_str) {
	localport_pr("Out of memory allocating connecter string: %s\n",
		service_str);
	goto out_err;
    }

    np->id_str = strdup(id_str);
    if (!np->id_str) {
	localport_pr("Out of memory allocating id string: %s\n", id_str);
	goto out_err;
    }
    np->next = local_ports;
    local_ports = np;

    if (started)
	start_local_port(np);

    np = NULL;
    err = 0;

 out_err:
    if (np) {
	if (np->accepter_str)
	    free(np->accepter_str);
	if (np->service_str)
	    free(np->service_str);
	if (np->id_str)
	    free(np->id_str);
	free(np);
    }
    return err;
}
