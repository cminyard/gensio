/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This allows a lot of pthread calls to be dummied out if pthreads is
 * disabled.
 */
#ifdef _WIN32
#include <windows.h>
#define lock_type SRWLOCK
#define LOCK_INIT(l) InitializeSRWLock(l)
#define LOCK_DESTROY(l) do {} while(0)
#define LOCK(l) AcquireSRWLockExclusive(l)
#define UNLOCK(l) ReleaseSRWLockExclusive(l)
#define LOCK_INITIALIZER SRWLOCK_INIT
#define lock_thread_type DWORD
#define LOCK_GET_THREAD_ID GetCurrentThreadId()
#define LOCK_THREAD_ID_EQUAL(a,b) ((a) == (b))
#elif defined(USE_PTHREADS)
#include <pthread.h>
#define lock_type pthread_mutex_t
#define LOCK_INIT(l) pthread_mutex_init(l, NULL)
#define LOCK_DESTROY(l) pthread_mutex_destroy(l)
#define LOCK(l) pthread_mutex_lock(l)
#define UNLOCK(l) pthread_mutex_unlock(l)
#define LOCK_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define lock_thread_type pthread_t
#define LOCK_GET_THREAD_ID pthread_self()
#define LOCK_THREAD_ID_EQUAL(a,b) pthread_equal(a,b)
#else
#include <assert.h>
#define lock_type int
#define LOCK_INIT(l) do { *l = 0; } while(0)
#define LOCK_DESTROY(l) do { assert(*l == 0); } while(0)
#define LOCK(l) do { assert(*l == 0); *l = 1; } while(0)
#define UNLOCK(l) do { assert(*l == 1); *l = 0; } while(0)
#define LOCK_INITIALIZER 0
#define lock_thread_type int
#define LOCK_GET_THREAD_ID 0
#define LOCK_THREAD_ID_EQUAL(a,b) ((a) == (b))
#endif
