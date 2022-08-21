/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_TIME_H
#define GENSIO_TIME_H

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Add the given number of nanoseconds to the time.
 */
GENSIO_DLL_PUBLIC
void gensio_time_add_nsecs(gensio_time *t, int64_t v);

GENSIO_DLL_PUBLIC
int64_t gensio_time_to_msecs(gensio_time *t);
GENSIO_DLL_PUBLIC
int64_t gensio_time_to_usecs(gensio_time *t);
GENSIO_DLL_PUBLIC
void gensio_msecs_to_time(gensio_time *t, int64_t v);
GENSIO_DLL_PUBLIC
void gensio_usecs_to_time(gensio_time *t, int64_t v);

/*
 * Return the value of t1 - t2 in nanoseconds.
 */
GENSIO_DLL_PUBLIC
int64_t gensio_time_diff_nsecs(gensio_time *t1, gensio_time *t2);

#define GENSIO_NSECS_IN_SEC 1000000000LL

#define GENSIO_NSECS_TO_USECS(v) (((int64_t) (v) + 500) / 1000)
#define GENSIO_NSECS_TO_MSECS(v) (((int64_t) (v) + 500000) / 1000000)

#define GENSIO_USECS_TO_NSECS(v) ((int64_t) (v) * 1000)
#define GENSIO_MSECS_TO_NSECS(v) ((int64_t) (v) * 1000000)

#define gensio_time_is_zero(v) ((v).secs == 0 && (v).nsecs == 0)

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_TIME_H */
