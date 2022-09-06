/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIOOSH_DLLVISIBILITY
#define GENSIOOSH_DLLVISIBILITY

#if defined GENSIO_LINK_STATIC
  #define GENSIOOSH_DLL_PUBLIC
  #define GENSIOOSH_DLL_LOCAL
#elif defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_GENSIOOSH_DLL
    #ifdef __GNUC__
      #define GENSIOOSH_DLL_PUBLIC __attribute__ ((dllexport))
    #else
      #define GENSIOOSH_DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define GENSIOOSH_DLL_PUBLIC __attribute__ ((dllimport))
    #else
      #define GENSIOOSH_DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
  #define GENSIOOSH_DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define GENSIOOSH_DLL_PUBLIC __attribute__ ((visibility ("default")))
    #define GENSIOOSH_DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define GENSIOOSH_DLL_PUBLIC
    #define GENSIOOSH_DLL_LOCAL
  #endif
#endif

#endif /* GENSIOOSH_DLLVISIBILITY */
