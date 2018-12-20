/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.  These licenses are available
 *  in the root directory of this package named COPYING.LIB and
 *  COPYING.BSD, respectively.
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

void wake_waiter(waiter_t *waiter);

#endif /* WAITER_H */
