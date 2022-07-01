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

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <gensio/gensio_list.h>
#include "localports.h"
#include "ioinfo.h"
#include "utils.h"

struct local_portinfo {
    struct local_ports *p;

    char *accepter_str;
    char *service_str;
    char *id_str;

    struct gensio_accepter *accepter;

    struct local_portinfo *next;
};

struct local_ports {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    struct local_portinfo *local_ports;
    bool started;
    struct gensio *base_io;
    struct gensio_list portcons;
    void (*localport_err)(void *cb_data, const char *format, va_list ap);
    void *cb_data;
};

struct portcon {
    struct local_ports *p;

    struct gensio *io1;
    struct gensio *io2;
    bool io2_open;
    char *id_str;

    struct gensio_link link;
};

static void
localport_pr(struct local_ports *p, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    p->localport_err(p->cb_data, format, ap);
    va_end(ap);
}

static void
pshutdown(struct ioinfo *ioinfo1, enum ioinfo_shutdown_reason reason)
{
    struct portcon *pc = ioinfo_userdata(ioinfo1);
    struct local_ports *p = pc->p;
    struct gensio_os_funcs *o = p->o;
    struct ioinfo *ioinfo2;

    ioinfo2 = ioinfo_otherioinfo(ioinfo1);
    gensio_free(pc->io1);
    gensio_free(pc->io2);
    free_ioinfo(ioinfo1);
    free_ioinfo(ioinfo2);
    o->lock(p->lock);
    gensio_list_rm(&p->portcons, &pc->link);
    o->unlock(p->lock);
    p->o->free(p->o, pc);
}

static void
perr(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    struct portcon *pc = ioinfo_userdata(ioinfo);
    struct local_ports *p = pc->p;
    char *s;

    s = gensio_alloc_vsprintf(p->o, fmt, ap);

    if (s) {
	localport_pr(p, "Error on %s: %s\n", pc->id_str, s);
	p->o->free(p->o, s);
    } else {
	localport_pr(p, "Error on %s: \n", pc->id_str);
	p->localport_err(p->cb_data, fmt, ap);
	localport_pr(p, "\n");
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
    struct local_ports *p = pc->p;
    struct ioinfo *ioinfo1, *ioinfo2;

    ioinfo2 = gensio_get_user_data(io);
    ioinfo1 = ioinfo_otherioinfo(ioinfo2);

    if (err) {
	localport_pr(p, "Mux open failed for %s: %s\n",
		     pc->id_str, gensio_err_to_str(err));
	pshutdown(ioinfo1, IOINFO_SHUTDOWN_ERR);
	return;
    }

    pc->io2_open = true;
    ioinfo_set_ready(ioinfo1, pc->io1);
    ioinfo_set_ready(ioinfo2, pc->io2);
}

static struct portcon *
portcon_setup(struct local_ports *p, struct gensio *io, char *id_str,
	      struct ioinfo **rioinfo1, struct ioinfo **rioinfo2)
{
    struct gensio_os_funcs *o = p->o;
    struct portcon *pc;
    struct ioinfo *ioinfo1, *ioinfo2;

    pc = o->zalloc(o, sizeof(*pc));
    if (!pc) {
	localport_pr(p,
		"Unable to allocate new connection for %s: Out of memory\n",
		id_str);
	goto out_err;
    }
    pc->p = p;
    pc->id_str = id_str;

    ioinfo1 = alloc_ioinfo(o, -1, NULL, NULL, &puh, pc);
    if (!ioinfo1) {
	localport_pr(p, "Could not allocate ioinfo 1\n");
	goto out_err;
    }

    ioinfo2 = alloc_ioinfo(o, -1, NULL, NULL, &puh, pc);
    if (!ioinfo2) {
	free_ioinfo(ioinfo1);
	localport_pr(p, "Could not allocate ioinfo 2\n");
	goto out_err;
    }

    ioinfo_set_otherioinfo(ioinfo1, ioinfo2);

    *rioinfo1 = ioinfo1;
    *rioinfo2 = ioinfo2;
    pc->io1 = io;
    return pc;

 out_err:
    if (pc)
	o->free(o, pc);
    return NULL;
}

static void
local_port_new_con(struct local_portinfo *pi, struct gensio *io)
{
    struct local_ports *p = pi->p;
    struct gensio_os_funcs *o = p->o;
    struct portcon *pc;
    struct ioinfo *ioinfo1 = NULL, *ioinfo2 = NULL;
    gensiods len;
    int err;

    pc = portcon_setup(p, io, pi->id_str, &ioinfo1, &ioinfo2);
    if (!pc)
	goto out_err;

    err = gensio_alloc_channel(p->base_io, NULL, NULL, ioinfo2, &pc->io2);
    if (err) {
	localport_pr(p,
		     "Unable to alloc local mux channel for %s: %s\n",
		     pi->id_str, gensio_err_to_str(err));
	goto out_err;
    }

    len = 1;
    gensio_control(pc->io2, 0, false, GENSIO_CONTROL_ENABLE_OOB, "1", &len);

    len = strlen(pi->service_str);
    err = gensio_control(pc->io2, 0, GENSIO_CONTROL_SET, GENSIO_CONTROL_SERVICE,
			 pi->service_str, &len);
    if (err) {
	localport_pr(p, "Unable to set channel service for %s: %s\n",
		     pi->id_str, gensio_err_to_str(err));
	goto out_err;
    }

    err = gensio_open(pc->io2, popen_done, pc);
    if (err) {
	localport_pr(p, "Unable to open local mux channel for %s: %s\n",
		     pi->id_str, gensio_err_to_str(err));
	goto out_err;
    }

    o->lock(p->lock);
    gensio_list_add_tail(&p->portcons, &pc->link);
    o->unlock(p->lock);
    return;

 out_err:
    gensio_free(io);
    if (ioinfo1)
	free_ioinfo(ioinfo1);
    if (ioinfo2)
	free_ioinfo(ioinfo2);
    if (pc)
	o->free(o, pc);
}

void
remote_port_new_con(struct local_ports *p, struct gensio *io,
		    const char *connecter_str, char *id_str)
{
    struct gensio_os_funcs *o = p->o;
    struct portcon *pc;
    struct ioinfo *ioinfo1 = NULL, *ioinfo2 = NULL;
    int err;

    pc = portcon_setup(p, io, id_str, &ioinfo1, &ioinfo2);
    if (!pc)
	goto out_err;

    err = str_to_gensio(connecter_str, o, NULL, ioinfo2, &pc->io2);
    if (err) {
	localport_pr(p, "Unable to alloc for remote channel for %s: %s\n",
		     id_str, gensio_err_to_str(err));
	goto out_err;
    }

    err = gensio_open(pc->io2, popen_done, pc);
    if (err) {
	localport_pr(p, "Unable to open local mux channel for %s: %s\n",
		     id_str, gensio_err_to_str(err));
	goto out_err;
    }

    o->lock(p->lock);
    gensio_list_add_tail(&p->portcons, &pc->link);
    o->unlock(p->lock);
    return;

 out_err:
    gensio_free(io);
    if (ioinfo1)
	free_ioinfo(ioinfo1);
    if (ioinfo2)
	free_ioinfo(ioinfo2);
    if (pc)
	o->free(o, pc);
}

static int
local_port_accept(struct gensio_accepter *accepter,
		  void *user_data, int event, void *data)
{
    struct local_portinfo *pi = user_data;

    switch (event) {
    case GENSIO_ACC_EVENT_NEW_CONNECTION:
	local_port_new_con(pi, data);
	return 0;

    case GENSIO_ACC_EVENT_LOG: {
	struct gensio_loginfo *li = data;
	struct local_ports *p = pi->p;
	const char *level = "unknown";

	switch (li->level) {
	case GENSIO_LOG_FATAL:	level = "fatal"; break;
	case GENSIO_LOG_ERR:	level = "err"; break;
	case GENSIO_LOG_WARNING:level = "warning"; break;
	case GENSIO_LOG_INFO:	level = "info"; break;
	case GENSIO_LOG_DEBUG:	level = "debug"; break;
	}
	localport_pr(p, "Accept log level %s from %s: ", level, pi->id_str);
	localport_pr(p, li->str, li->args);
	return 0;
    }

    default:
	return GE_NOTSUP;
    }
}

static void
start_local_port(struct local_portinfo *pi)
{
    struct local_ports *p = pi->p;
    int err;

    err = str_to_gensio_accepter(pi->accepter_str, p->o,
				 local_port_accept, pi,
				 &pi->accepter);
    if (err) {
	localport_pr(p, "Unable to open local port %s: %s\n",
		     pi->id_str, gensio_err_to_str(err));
	return;
    }

    err = gensio_acc_startup(pi->accepter);
    if (err) {
	localport_pr(p, "Unable to start local port %s: %s\n",
		     pi->id_str, gensio_err_to_str(err));
	gensio_acc_free(pi->accepter);
	pi->accepter = NULL;
    }
}

void
start_local_ports(struct local_ports *p, struct gensio *user_io)
{
    struct gensio_os_funcs *o = p->o;
    struct local_portinfo *curr = p->local_ports;

    o->lock(p->lock);
    p->base_io = user_io;
    for (; curr; curr = curr->next)
	start_local_port(curr);
    p->started = true;
    o->unlock(p->lock);
}

int
add_local_port(struct local_ports *p,
	       const char *gensio_str, const char *service_str,
	       const char *id_str)
{
    struct gensio_os_funcs *o = p->o;
    struct local_portinfo *pi = NULL;
    int err = GE_NOMEM;

    pi = o->zalloc(o, sizeof(*pi));
    if (!pi) {
	localport_pr(p, "Out of memory allocating port info\n");
	goto out_err;
    }
    pi->p = p;

    pi->accepter_str = gensio_strdup(o, gensio_str);
    if (!pi->accepter_str) {
	localport_pr(p, "Out of memory allocating accept string: %s\n",
		gensio_str);
	goto out_err;
    }

    pi->service_str = gensio_strdup(o, service_str);
    if (!pi->service_str) {
	localport_pr(p, "Out of memory allocating connecter string: %s\n",
		service_str);
	goto out_err;
    }

    pi->id_str = gensio_strdup(o, id_str);
    if (!pi->id_str) {
	localport_pr(p, "Out of memory allocating id string: %s\n", id_str);
	goto out_err;
    }

    o->lock(p->lock);
    pi->next = p->local_ports;
    p->local_ports = pi;

    if (p->started)
	start_local_port(pi);
    o->unlock(p->lock);

    pi = NULL;
    err = 0;

 out_err:
    if (pi) {
	if (pi->accepter_str)
	    o->free(o, pi->accepter_str);
	if (pi->service_str)
	    o->free(o, pi->service_str);
	if (pi->id_str)
	    o->free(o, pi->id_str);
	o->free(o, pi);
    }
    return err;
}

void
free_local_ports(struct local_ports *p)
{
    struct gensio_os_funcs *o = p->o;

    o->free_lock(p->lock);
    o->free(o, p);
}

struct local_ports *
alloc_local_ports(struct gensio_os_funcs *o,
		  void (*localport_err)(void *cb_data,
					const char *format,
					va_list ap),
		  void *cb_data)
{
    struct local_ports *p;

    p = o->zalloc(o, sizeof(*p));
    if (!p)
	return NULL;
    p->lock = o->alloc_lock(o);
    if (!p->lock) {
	o->free(o, p);
	return NULL;
    }
    p->o = o;
    p->localport_err = localport_err;
    p->cb_data = cb_data;
    gensio_list_init(&p->portcons);

    return p;
}
