/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Test code to trigger errors at specific counts.  See errtrig.c for details.
 */
#ifndef _GENSIO_ERRTRIG_H
#define _GENSIO_ERRTRIG_H

#include "config.h"

#include <stdlib.h>
#include <stdbool.h>

#ifdef ENABLE_INTERNAL_TRACE
#define ENABLE_ERRTRIG_TEST
#endif

#ifdef ENABLE_ERRTRIG_TEST
bool do_errtrig(void);
void errtrig_exit(int rv);
#else
#define do_errtrig() false
#define errtrig_exit(rv) do {} while(false)
#endif

#endif /* _GENSIO_ERRTRIG_H */
