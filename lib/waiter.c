/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>
#include <gensio/waiter.h>

#ifdef USE_PTHREADS

#include <pthread.h>
#include <signal.h>
#include <stdbool.h>

struct wait_data {
    pthread_t tid;
    int wake_sig;
    struct wait_data *prev;
    struct wait_data *next;
};

struct waiter_s {
    struct selector_s *sel;
    int wake_sig;
    unsigned int count;
    pthread_mutex_t lock;
    struct wait_data wts;
};

waiter_t *
alloc_waiter(struct selector_s *sel, int wake_sig)
{
    waiter_t *waiter;

    waiter = malloc(sizeof(waiter_t));
    if (waiter) {
	memset(waiter, 0, sizeof(*waiter));
	waiter->wake_sig = wake_sig;
	waiter->sel = sel;
	pthread_mutex_init(&waiter->lock, NULL);
	waiter->wts.next = &waiter->wts;
	waiter->wts.prev = &waiter->wts;
    }
    return waiter;
}

void
free_waiter(waiter_t *waiter)
{
    assert(waiter);
    assert(waiter->wts.next == waiter->wts.prev);
    pthread_mutex_destroy(&waiter->lock);
    free(waiter);
}

static void
wake_thread_send_sig(long thread_id, void *cb_data)
{
    struct wait_data *w = cb_data;

    pthread_kill(w->tid, w->wake_sig);
}

static int
i_wait_for_waiter_timeout(waiter_t *waiter, unsigned int count,
			  struct timeval *timeout, bool intr,
			  sigset_t *sigmask)
{
    struct wait_data w;
    int err = 0;

    w.tid = pthread_self();
    w.wake_sig = waiter->wake_sig;
    w.next = NULL;
    w.prev = NULL;

    pthread_mutex_lock(&waiter->lock);
    waiter->wts.next->prev = &w;
    w.next = waiter->wts.next;
    waiter->wts.next = &w;
    w.prev = &waiter->wts;

    while (waiter->count < count) {
	pthread_mutex_unlock(&waiter->lock);
	if (intr)
	    err = sel_select_intr_sigmask(waiter->sel, wake_thread_send_sig,
					  w.tid, &w, timeout, sigmask);
	else
	    err = sel_select(waiter->sel, wake_thread_send_sig, w.tid, &w,
			     timeout);
	if (err < 0)
	    err = errno;
	else if (err == 0)
	    err = ETIMEDOUT;
	else
	    err = 0;
	/* lock may affect errno, delay it until here. */
	pthread_mutex_lock(&waiter->lock);
	if (err)
	    break;
    }
    if (!err)
	waiter->count -= count;
    w.next->prev = w.prev;
    w.prev->next = w.next;
    pthread_mutex_unlock(&waiter->lock);

    return err;
}

void
wake_waiter(waiter_t *waiter)
{
    struct wait_data *w;

    pthread_mutex_lock(&waiter->lock);
    waiter->count++;
    w = waiter->wts.next;
    while (w != &waiter->wts) {
	pthread_kill(w->tid, w->wake_sig);
	w = w->next;
    }
    pthread_mutex_unlock(&waiter->lock);
}

#else /* USE_PTHREADS */

struct waiter_s {
    unsigned int count;
    struct selector_s *sel;
};

waiter_t *
alloc_waiter(struct selector_s *sel, int wake_sig)
{
    waiter_t *waiter;

    waiter = malloc(sizeof(waiter_t));
    if (waiter)
	memset(waiter, 0, sizeof(*waiter));
    waiter->sel = sel;
    return waiter;
}

void
free_waiter(waiter_t *waiter)
{
    assert(waiter);
    free(waiter);
}

static int
i_wait_for_waiter_timeout(waiter_t *waiter, unsigned int count,
			  struct timeval *timeout, bool intr, sigset_t *sigmask)
{
    int err = 0;

    while (waiter->count < count) {
	if (intr)
	    err = sel_select_intr_sigmask(waiter->sel, 0, 0, NULL, timeout,
					  sigmask);
	else
	    err = sel_select(waiter->sel, 0, 0, NULL, timeout);
	if (err < 0) {
	    err = errno;
	    break;
	} else if (err == 0) {
	    err = ETIMEDOUT;
	    break;
	}
	err = 0;
    }
    if (!err)
	waiter->count -= count;
    return err;
}

void
wake_waiter(waiter_t *waiter)
{
    waiter->count++;
}

#endif /* USE_PTHREADS */

int
wait_for_waiter_timeout(waiter_t *waiter, unsigned int count,
			struct timeval *timeout)
{
    return i_wait_for_waiter_timeout(waiter, count, timeout, false, NULL);
}

void
wait_for_waiter(waiter_t *waiter, unsigned int count)
{
    wait_for_waiter_timeout(waiter, count, NULL);
}

int
wait_for_waiter_timeout_intr(waiter_t *waiter, unsigned int count,
			     struct timeval *timeout)
{
    return i_wait_for_waiter_timeout(waiter, count, timeout, true, NULL);
}

int
wait_for_waiter_intr(waiter_t *waiter, unsigned int count)
{
    return wait_for_waiter_timeout_intr(waiter, count, NULL);
}

int
wait_for_waiter_timeout_intr_sigmask(waiter_t *waiter, unsigned int count,
				     struct timeval *timeout, sigset_t *sigmask)
{
    return i_wait_for_waiter_timeout(waiter, count, timeout, true, sigmask);
}
