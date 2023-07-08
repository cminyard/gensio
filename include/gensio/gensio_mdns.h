/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef MDNS_H
#define MDNS_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined GENSIO_LINK_STATIC
  #define GENSIOMDNS_DLL_PUBLIC
  #define GENSIOMDNS_DLL_LOCAL
#elif defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_GENSIOMDNS_DLL
    #ifdef __GNUC__
      #define GENSIOMDNS_DLL_PUBLIC __attribute__ ((dllexport))
    #else
      #define GENSIOMDNS_DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define GENSIOMDNS_DLL_PUBLIC __attribute__ ((dllimport))
    #else
      #define GENSIOMDNS_DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
  #define GENSIOMDNS_DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define GENSIOMDNS_DLL_PUBLIC __attribute__ ((visibility ("default")))
    #define GENSIOMDNS_DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define GENSIOMDNS_DLL_PUBLIC
    #define GENSIOMDNS_DLL_LOCAL
  #endif
#endif

#include <gensio/gensio_types.h>
#include <gensio/gensio.h>

struct gensio_mdns;
struct gensio_mdns_service;

typedef void (*gensio_mdns_done)(struct gensio_mdns *m, void *userdata);

GENSIOMDNS_DLL_PUBLIC
int gensio_alloc_mdns(struct gensio_os_funcs *o, struct gensio_mdns **m);

GENSIOMDNS_DLL_PUBLIC
int gensio_free_mdns(struct gensio_mdns *m,
		     gensio_mdns_done done, void *userdata);


GENSIOMDNS_DLL_PUBLIC
int gensio_mdns_add_service(struct gensio_mdns *m,
			    int iface, int ipdomain,
			    const char *name, const char *type,
			    const char *domain, const char *host,
			    int port, const char * const *txt,
			    struct gensio_mdns_service **rservice);

GENSIOMDNS_DLL_PUBLIC
int gensio_mdns_remove_service(struct gensio_mdns_service *s);


struct gensio_mdns_watch;
enum gensio_mdns_data_state { GENSIO_MDNS_NEW_DATA, GENSIO_MDNS_DATA_GONE,
			      GENSIO_MDNS_ALL_FOR_NOW };

typedef void (*gensio_mdns_watch_cb)(struct gensio_mdns_watch *w,
				     enum gensio_mdns_data_state state,
				     int iface, int ipdomain,
				     const char *name, const char *type,
				     const char *domain, const char *host,
				     const struct gensio_addr *addr,
				     const char * const *txt, void *userdata);

GENSIOMDNS_DLL_PUBLIC
int gensio_mdns_add_watch(struct gensio_mdns *m,
			  int iface, int ipdomain,
			  const char *name, const char *type,
			  const char *domain, const char *host,
			  gensio_mdns_watch_cb callback, void *userdata,
			  struct gensio_mdns_watch **rwatch);

typedef void (*gensio_mdns_watch_done)(struct gensio_mdns_watch *w,
				       void *userdata);

GENSIOMDNS_DLL_PUBLIC
int gensio_mdns_remove_watch(struct gensio_mdns_watch *w,
			     gensio_mdns_watch_done done, void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* MDNS_H */
