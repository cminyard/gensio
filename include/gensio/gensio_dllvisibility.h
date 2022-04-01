/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_DLLVISIBILITY
#define GENSIO_DLLVISIBILITY

#if defined GENSIO_LINK_STATIC
  #define GENSIO_DLL_PUBLIC
  #define GENSIO_DLL_LOCAL
#elif defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_GENSIO_DLL
    #ifdef __GNUC__
      #define GENSIO_DLL_PUBLIC __attribute__ ((dllexport))
    #else
      #define GENSIO_DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define GENSIO_DLL_PUBLIC __attribute__ ((dllimport))
    #else
      #define GENSIO_DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
  #define GENSIO_DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define GENSIO_DLL_PUBLIC __attribute__ ((visibility ("default")))
    #define GENSIO_DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define GENSIO_DLL_PUBLIC
    #define GENSIO_DLL_LOCAL
  #endif
#endif

#endif /* GENSIO_DLLVISIBILITY */
