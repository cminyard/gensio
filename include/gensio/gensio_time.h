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
 * A well-formed time will always have nsecs >= 0.  secs will be
 * < 0 for negative times and >= 0 for positive time (or zero).
 */

/*
 * Convert a string in the standard definition (as defined in
 * gensio.5) to a time value.  mod sets the default time scale ('s'
 * for seconds, 'm' for milliseconds, etc.)  Set it to zero to have
 * no default.
 */
GENSIO_DLL_PUBLIC
int gensio_str_to_time(const char *str, gensio_time *time, char mod);

/*
 * Add time v to time t1.
 */
GENSIO_DLL_PUBLIC
void gensio_time_add(gensio_time *t, gensio_time *v);

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
int64_t gensio_time_to_nsecs(gensio_time *t);
GENSIO_DLL_PUBLIC
void gensio_msecs_to_time(gensio_time *t, int64_t v);
GENSIO_DLL_PUBLIC
void gensio_usecs_to_time(gensio_time *t, int64_t v);
GENSIO_DLL_PUBLIC
void gensio_nsecs_to_time(gensio_time *t, int64_t v);

/*
 * Return the value of t1 - t2 in nanoseconds.
 */
GENSIO_DLL_PUBLIC
int64_t gensio_time_diff_nsecs(gensio_time *t1, gensio_time *t2);

/*
 * Return -1 if t1 < t2, 0 if t1 == t2, or 1 if t1 > t2.
 */
GENSIO_DLL_PUBLIC
int gensio_time_cmp(gensio_time *t1, gensio_time *t2);

#define GENSIO_MSECS_IN_SEC 1000LL
#define GENSIO_USECS_IN_SEC 1000000LL
#define GENSIO_NSECS_IN_SEC 1000000000LL

/*
 * Convert time to a less granular value, rounding as necessary.
 * Then conversions from nanoseconds to different values.
 */
#define GENSIO_TIME_CONV_DOWN(v,d) (((int64_t) (v) + (d / 2)) / d)
#define GENSIO_NSECS_TO_MSECS(v) GENSIO_TIME_CONV_DOWN(v, GENSIO_MSECS_IN_SEC)
#define GENSIO_NSECS_TO_USECS(v) GENSIO_TIME_CONV_DOWN(v, GENSIO_USECS_IN_SEC)
#define GENSIO_NSECS_TO_SECS(v) GENSIO_TIME_CONV_DOWN(v, GENSIO_NSECS_IN_SEC)

/*
 * Convert time to a more granular value.
 * Then conversions to nanoseconds to different values.
 */
#define GENSIO_TIME_CONV_UP(v,m) ((int64_t) (v) * m)
#define GENSIO_MSECS_TO_NSECS(v) GENSIO_TIME_CONV_UP(v, 1000000LL)
#define GENSIO_USECS_TO_NSECS(v) GENSIO_TIME_CONV_UP(v, 1000LL)
#define GENSIO_SECS_TO_NSECS(v) GENSIO_TIME_CONV_UP(v, GENSIO_NSECS_IN_SEC)

#define gensio_time_is_zero(v) ((v).secs == 0 && (v).nsecs == 0)
#define gensio_time_gt_zero(v) ((v).secs > 0 || ((v).secs == 0 && (v).nsecs > 0))
#define gensio_time_ge_zero(v) ((v).secs >= 0)
#define gensio_time_lt_zero(v) ((v).secs < 0)
#define gensio_time_le_zero(v) ((v).secs < 0 || gensio_time_is_zero(v))

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_TIME_H */
