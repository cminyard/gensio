/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2024  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_REFCOUNT_H
#define GENSIO_REFCOUNT_H

/*
 * A basic refcount type using atomics.
 */

#include <assert.h>
#include <gensio/gensio_atomics.h>

typedef struct {
    gensio_atomic_uint count;
} gensio_refcount;

#define gensio_refcount_set(a, v)	gensio_atomic_set(&(a)->count, v)
#define gensio_refcount_get(a)		gensio_atomic_get(&(a)->count)

/*
 * Set up the refcount.
 */
static inline int gensio_refcount_init(struct gensio_os_funcs *o,
				       gensio_refcount *a, unsigned int val)
{
    return gensio_atomic_init(o, &a->count, val);
}

/*
 * Increment the refcount.  The refcount must be non-zero.
 */
static inline void gensio_refcount_inc(gensio_refcount *a)
{
    unsigned int gensio_refcount_old;

    gensio_atomic_inc_if_nz(&a->count, &gensio_refcount_old);
    assert(gensio_refcount_old != 0);
}

/*
 * Decrement the refcount.  The refcount must be non-zero.  The new
 * value of the refcount is returned.
 */
static inline unsigned int gensio_refcount_dec(gensio_refcount *a)
{
    unsigned int gensio_refcount_old;

    gensio_atomic_dec_if_nz(&a->count, &gensio_refcount_old);
    assert(gensio_refcount_old != 0);
    return gensio_refcount_old - 1;
}

/*
 * If the refcount is non-zero, decrement it.  Otherwise no operation
 * is done.  If the value was decremented, return true, otherwise
 * return false.
 */
static inline bool gensio_refcount_dec_if_nz(gensio_refcount *a)
{
    unsigned int gensio_refcount_old;

    return gensio_atomic_dec_if_nz(&a->count, &gensio_refcount_old);
}

/*
 * Increment the refcount if the refcount is non-zero.  If the refcount
 * was zero, return false, otherwise return true.
 */
static inline bool gensio_refcount_inc_if_nz(gensio_refcount *a)
{
    unsigned int gensio_refcount_old;

    return gensio_atomic_inc_if_nz(&a->count, &gensio_refcount_old);
}

/*
 * Nothing to do for now.
 */
static inline void gensio_refcount_cleanup(gensio_refcount *a)
{
    gensio_atomic_cleanup(&a->count);
}

#endif
