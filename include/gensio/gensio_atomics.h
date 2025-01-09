/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2024  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Basic atomic operations, not really filled out, really here for
 * the refcount code, but may be filled out someday.
 */

#ifndef GENSIO_ATOMICS_H
#define GENSIO_ATOMICS_H

#include <stdbool.h>
#include <gensio/gensio_os_funcs_public.h>

#ifndef __STDC_VERSION__
#define GENSIO_HAS_STDC_ATOMICS 0
#elif __STDC_VERSION__ < 201112L || __STDC_NO_ATOMICS__ == 1
#define GENSIO_HAS_STDC_ATOMICS 0
#else
#define GENSIO_HAS_STDC_ATOMICS 1
#endif

#if GENSIO_HAS_STDC_ATOMICS
#define GENSIO_HAS_GCC_ATOMICS 0
#else
#ifdef __ATOMIC_SEQ_CST
#define GENSIO_HAS_GCC_ATOMICS 1
#else
#define GENSIO_HAS_GCC_ATOMICS 0
#endif
#endif

#if GENSIO_HAS_STDC_ATOMICS
#include <stdatomic.h>

#define gensio_atomic_lockless(a)	atomic_is_lock_free(a)

typedef atomic_uint gensio_atomic_uint;

enum gensio_memory_order {
    gensio_mo_relaxed = memory_order_relaxed,
    gensio_mo_consume = memory_order_consume,
    gensio_mo_acquire = memory_order_acquire,
    gensio_mo_release = memory_order_release,
    gensio_mo_acq_rel = memory_order_acq_rel,
    gensio_mo_seq_cst = memory_order_seq_cst,
};

#define gensio_atomic_init(o, a, v)	(atomic_store(a, v), 0)
#define gensio_atomic_cleanup(a)	do {} while(0)
#define gensio_atomic_set(a, v)		atomic_store(a, v)
#define gensio_atomic_set_mo(a, v, mo)	atomic_store_explicit(a, v, mo)
#define gensio_atomic_get(a)		atomic_load(a)
#define gensio_atomic_get_mo(a, mo)	atomic_load_explicit(a, mo)

#define gensio_atomic_cas(a, old, new) \
    atomic_compare_exchange_strong(a, old, new)
#define gensio_atomic_cas_mo(a, old, new, succ_mo, fail_mo) \
    atomic_compare_exchange_strong_explicit(a, old, new, succ_mo, fail_mo)

#define gensio_atomic_add(a, v)		atomic_fetch_add(a, v)
#define gensio_atomic_add_mo(a, v, mo)	atomic_fetch_add_explicit(a, v, mo)

#define gensio_atomic_sub(a, v)		atomic_fetch_sub(a, v)
#define gensio_atomic_sub_mo(a, v, mo)	atomic_fetch_sub_explicit(a, v, mo)

#elif GENSIO_HAS_GCC_ATOMICS

#define gensio_atomic_lockless(a)	__atomic_is_lock_free(sizeof(*a), a)

typedef unsigned int gensio_atomic_uint;

enum gensio_memory_order {
    gensio_mo_relaxed = __ATOMIC_RELAXED,
    gensio_mo_consume = __ATOMIC_CONSUME,
    gensio_mo_acquire = __ATOMIC_ACQUIRE,
    gensio_mo_release = __ATOMIC_RELEASE,
    gensio_mo_acq_rel = __ATOMIC_ACQ_REL,
    gensio_mo_seq_cst = __ATOMIC_SEQ_CST,
};

#define gensio_atomic_init(o, a, v)	(__atomic_store_n(a, v, __ATOMIC_SEQ_CST), 0)
#define gensio_atomic_cleanup(a)	do {} while(0)
#define gensio_atomic_set(a, v)		__atomic_store_n(a, v, __ATOMIC_SEQ_CST)
#define gensio_atomic_set_mo(a, v, mo)	__atomic_store_n(a, v, mo)
#define gensio_atomic_get(a)		__atomic_load_n(a, __ATOMIC_SEQ_CST)
#define gensio_atomic_get_mo(a, mo)	__atomic_load_n(a, mo)

#define gensio_atomic_cas(a, old, new) \
    __atomic_compare_exchange_n(a, old, new, false,			\
				__ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define gensio_atomic_cas_mo(a, old, new, succ_mo, fail_mo) \
    __atomic_compare_exchange_n(a, old, new, false, succ_mo, fail_mo)

#define gensio_atomic_add(a, v)	      __atomic_fetch_add(a, v, __ATOMIC_SEQ_CST)
#define gensio_atomic_add_mo(a, v, mo)	__atomic_fetch_add(a, v, mo)

#define gensio_atomic_sub(a, v)	      __atomic_fetch_sub(a, v, __ATOMIC_SEQ_CST)
#define gensio_atomic_sub_mo(a, v, mo)	__atomic_fetch_sub(a, v, mo)

#else

/* Atomics not available, create one using locks. */
#define gensio_atomic_lockless(a)	false

typedef struct {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    unsigned int val;
} gensio_atomic_uint;

enum gensio_memory_order {
    gensio_mo_relaxed = 1,
    gensio_mo_consume = 2,
    gensio_mo_acquire = 3,
    gensio_mo_release = 4,
    gensio_mo_acq_rel = 5,
    gensio_mo_seq_cst = 6
};

#define gensio_atomic_init(o, a, v)	\
    ({							\
	int rv = GE_NOMEM;				\
	(a)->lock = gensio_os_funcs_alloc_lock(o);	\
	if ((a)->lock) {				\
	    rv = 0;					\
	    (a)->o = o;					\
	    (a)->val = v;				\
	};						\
	rv;						\
    })
#define gensio_atomic_cleanup(a)	\
    do {						\
	if ((a)->lock)					\
	    gensio_os_funcs_free_lock((a)->o, (a)->lock);\
    } while(0)

#define gensio_atomic_set(a, v)				\
    do {						\
	gensio_os_funcs_lock((a)->o, (a)->lock);	\
	(a)->val = v;					\
	gensio_os_funcs_unlock((a)->o, (a)->lock);	\
    } while(0)
#define gensio_atomic_set_mo(a, v, mo)	gensio_atomic_set(a, v)

#define gensio_atomic_get(a)				\
    ({							\
	long rv;					\
	gensio_os_funcs_lock((a)->o, (a)->lock);	\
	rv = (a)->val;					\
	gensio_os_funcs_unlock((a)->o, (a)->lock);	\
	rv;						\
    })
#define gensio_atomic_get_mo(a, mo)	gensio_atomic_get(a)

#define gensio_atomic_cas(a, expected, desired) \
    ({							\
	bool rv;					\
	gensio_os_funcs_lock((a)->o, (a)->lock);	\
	if (*(expected) == (a)->val) {			\
	    (a)->val = desired;				\
	    rv = true;					\
	} else {					\
	    rv = false;					\
	}						\
	gensio_os_funcs_unlock((a)->o, (a)->lock);	\
	rv;						\
    })
#define gensio_atomic_cas_mo(a, expected, desired, succ_mo, fail_mo) \
    gensio_atomic_cas(a, expected, desired)

#define gensio_atomic_add(a, v)		\
    ({							\
	long rv;					\
	gensio_os_funcs_lock((a)->o, (a)->lock);	\
	rv = (a)->val;					\
	(a)->val += v;					\
	gensio_os_funcs_unlock((a)->o, (a)->lock);	\
	rv;						\
    })
#define gensio_atomic_add_mo(a, v, mo)	gensio_atomic_add(a, v)

#define gensio_atomic_sub(a, v)		\
    ({							\
	long rv;					\
	gensio_os_funcs_lock((a)->o, (a)->lock);	\
	rv = (a)->val;					\
	(a)->val -= v;					\
	gensio_os_funcs_unlock((a)->o, (a)->lock);	\
	rv;						\
    })
#define gensio_atomic_sub_mo(a, v, mo)	gensio_atomic_sub(a, v)

#endif

/*
 * If *a is zero, return.  Otherwise, atomically replace *a with *a + v,
 * or *a - v.  The previous value of *a is always returned in *old;
 */
#define gensio_atomic_add_if_nz(a, old, v) \
    do {								\
	*old = gensio_atomic_get(a);					\
	if (*old == 0)							\
	    break;							\
	if (gensio_atomic_cas(a, old, *old + v))			\
	    break;							\
    } while(1)

#define gensio_atomic_add_if_nz_mo(a, old, v, mo) \
    do {								\
	*old = gensio_atomic_get_mo(a, mo);				\
	if (*old == 0)							\
	    break;							\
	if (gensio_atomic_cas_mo(a, old, *old + v, mo, mo))		\
	    break;							\
    } while(1)
#define gensio_atomic_sub_if_nz(a, old, v) \
    do {								\
	*old = gensio_atomic_get(a);					\
	if (*old == 0)							\
	    break;							\
	if (gensio_atomic_cas(a, old, *old - v))			\
	    break;							\
    } while(1)

#define gensio_atomic_sub_if_nz_mo(a, old, v, mo) \
    do {								\
	*old = gensio_atomic_get_mo(a, mo);				\
	if (*old == 0)							\
	    break;							\
	if (gensio_atomic_cas_mo(a, old, *old - v, mo, mo))		\
	    break;							\
    } while(1)

#define gensio_atomic_inc_if_nz(a, old) \
    gensio_atomic_add_if_nz(a, old, 1)
#define gensio_atomic_inc_if_nz_mo(a, old, mo)	\
    gensio_atomic_add_if_nz(a, old, 1, mo)
#define gensio_atomic_dec_if_nz(a, old) \
    gensio_atomic_sub_if_nz(a, old, 1)
#define gensio_atomic_dec_if_nz_mo(a, old, mo)	\
    gensio_atomic_sub_if_nz(a, old, 1, mo)

#endif
