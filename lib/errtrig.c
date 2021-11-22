/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "errtrig.h"
#ifdef _MSC_VER
#include <intrin.h>
#endif

#include "pthread_handler.h"
#include <assert.h>
/*
 * Some memory allocation and other failure testing.  If the
 * GENSIO_ERRTRIG_TEST environment variable is set to number N, the
 * Nth call to do_errtrig will return true.  The program should call
 * gensio_osfunc_exit (below); it will cause specific values to be
 * returned on an exit failure.
 */

static lock_type errtrig_lock = LOCK_INITIALIZER;
static bool errtrig_initialized;
static bool errtrig_ready;
static bool triggered;
static unsigned int errtrig_count;
static unsigned int errtrig_curr;

static void *trig_caller[4];

bool
do_errtrig(void)
{
    unsigned int curr;
    bool triggerit = false;

    LOCK(&errtrig_lock);
    if (!errtrig_initialized) {
	char *s = getenv("GENSIO_ERRTRIG_TEST");

	errtrig_initialized = true;
	if (s) {
	    errtrig_count = strtoul(s, NULL, 0);
	    errtrig_ready = true;
	}
    }
    if (errtrig_ready) {
	curr = errtrig_curr++;
	if (curr == errtrig_count) {
	    triggered = true;
	    triggerit = true;
#if _MSC_VER
	    trig_caller[0] = _ReturnAddress();
#else
	    trig_caller[0] = __builtin_return_address(0);
#if 0
	    trig_caller[1] = __builtin_return_address(1);
	    trig_caller[2] = __builtin_return_address(2);
	    trig_caller[3] = __builtin_return_address(3);
#endif
#endif
	}
    }
    UNLOCK(&errtrig_lock);
    return triggerit;
}

#include <stdio.h>
void errtrig_exit(int rv)
{
    if (!errtrig_ready)
	exit(rv);

    assert (rv == 1 || rv == 0); /* Only these values are allowed. */

    /*
     * Return an error.  The values mean:
     *
     * 0 - No error occurred and the memory allocation failure didn't happen
     * 1 - An error occurred and the memory allocation failure happenned
     * 2 - No error occurred and the memory allocation failure happenned
     * 3 - An error occurred and the memory allocation failure didn't happen
     */
    if (rv == 0 && triggered)
	rv = 2;
    if (rv == 0 && !triggered)
	rv = 0;
    if (rv == 1 && triggered)
	rv = 1;
    if (rv == 1 && !triggered)
	rv = 3;
    exit(rv);
}
