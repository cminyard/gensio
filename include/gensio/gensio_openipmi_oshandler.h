/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2025  Corey Minyard <minyard@acm.org>
 *
 *  This is an OpenIPMI os handler that you can create from a
 *  gensio_os_funcs.
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_OPENIPMI_OSHANDLER_H
#define GENSIO_OPENIPMI_OSHANDLER_H

#include <OpenIPMI/os_handler.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined GENSIO_LINK_STATIC
  #define GENSIO_OI_OSH_DLL_PUBLIC
  #define GENSIO_OI_OSH_DLL_LOCAL
#elif defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_GENSIO_OI_OSH_DLL
    #ifdef __GNUC__
      #define GENSIO_OI_OSH_DLL_PUBLIC __attribute__ ((dllexport))
    #else
      #define GENSIO_OI_OSH_DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define GENSIO_OI_OSH_DLL_PUBLIC __attribute__ ((dllimport))
    #else
      #define GENSIO_OI_OSH_DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
  #define GENSIO_OI_OSH_DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define GENSIO_OI_OSH_DLL_PUBLIC __attribute__ ((visibility ("default")))
    #define GENSIO_OI_OSH_DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define GENSIO_OI_OSH_DLL_PUBLIC
    #define GENSIO_OI_OSH_DLL_LOCAL
  #endif
#endif

GENSIO_OI_OSH_DLL_PUBLIC
os_handler_t *gensio_openipmi_oshandler_alloc(struct gensio_os_funcs *o);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_OPENIPMI_OSHANDLER_H */
