/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_DEPRECATED
#define GENSIO_DEPRECATED

#if defined(__GNUC__) && (__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 2))
# define GENSIO_FUNC_DEPRECATED __attribute__ ((deprecated))
# define GENSIO_TYPE_DEPRECATED __attribute__ ((deprecated))
# define GENSIO_VAR_DEPRECATED __attribute__ ((deprecated))
#else
# define GENSIO_FUNC_DEPRECATED
# define GENSIO_TYPE_DEPRECATED
# define GENSIO_VAR_DEPRECATED
#endif

#endif /* GENSIO_DEPRECATED */
