/*
 *  gensio - A library for streaming I/O
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

#ifndef MDNS_H
#define MDNS_H

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio.h>

struct gensio_mdns;
struct gensio_mdns_service;

typedef void (*gensio_mdns_done)(struct gensio_mdns *m, void *userdata);

GENSIO_DLL_PUBLIC
int gensio_alloc_mdns(struct gensio_os_funcs *o, struct gensio_mdns **m);

GENSIO_DLL_PUBLIC
int gensio_free_mdns(struct gensio_mdns *m,
		     gensio_mdns_done done, void *userdata);


GENSIO_DLL_PUBLIC
int gensio_mdns_add_service(struct gensio_mdns *m,
			    int interface, int ipdomain,
			    const char *name, const char *type,
			    const char *domain, const char *host,
			    int port, const char *txt[],
			    struct gensio_mdns_service **rservice);

GENSIO_DLL_PUBLIC
int gensio_mdns_remove_service(struct gensio_mdns_service *s);


struct gensio_mdns_watch;
enum gensio_mdns_data_state { GENSIO_MDNS_NEW_DATA, GENSIO_MDNS_DATA_GONE,
			      GENSIO_MDNS_ALL_FOR_NOW };

typedef void (*gensio_mdns_watch_cb)(struct gensio_mdns_watch *w,
				     enum gensio_mdns_data_state state,
				     int interface, int ipdomain,
				     const char *name, const char *type,
				     const char *domain, const char *host,
				     struct gensio_addr *addr,
				     const char *txt[], void *userdata);

GENSIO_DLL_PUBLIC
int gensio_mdns_add_watch(struct gensio_mdns *m,
			  int interface, int ipdomain,
			  const char *name, const char *type,
			  const char *domain, const char *host,
			  gensio_mdns_watch_cb callback, void *userdata,
			  struct gensio_mdns_watch **rwatch);

typedef void (*gensio_mdns_watch_done)(struct gensio_mdns_watch *w,
				       void *userdata);

GENSIO_DLL_PUBLIC
int gensio_mdns_remove_watch(struct gensio_mdns_watch *w,
			     gensio_mdns_watch_done done, void *userdata);

#endif /* MDNS_H */
