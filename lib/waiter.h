/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* Utils for waiting and handling a select loop. */

#ifndef WAITER_H
#define WAITER_H

#include <gensio/selector.h>

typedef struct waiter_s waiter_t;

waiter_t *alloc_waiter(struct selector_s *sel, int wake_sig);

void free_waiter(waiter_t *waiter);

int wait_for_waiter_timeout(waiter_t *waiter, unsigned int count,
			    struct timeval *timeout);

void wait_for_waiter(waiter_t *waiter, unsigned int count);

int wait_for_waiter_timeout_intr(waiter_t *waiter, unsigned int count,
				 struct timeval *timeout);

int wait_for_waiter_intr(waiter_t *waiter, unsigned int count);

int wait_for_waiter_timeout_intr_sigmask(waiter_t *waiter, unsigned int count,
					 struct timeval *timeout,
					 sigset_t *sigmask);

void wake_waiter(waiter_t *waiter);

#endif /* WAITER_H */
