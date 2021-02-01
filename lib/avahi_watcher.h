/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef AVAHI_WATCHER_H
#define AVAHI_WATCHER_H

#include <avahi-common/watch.h>
#include <gensio/gensio_os_funcs.h>

/*
 * You must call these before/after doing any Avahi calls.  Avahi is
 * single-threaded.
 */
void gensio_avahi_lock(AvahiPoll *ap);
void gensio_avahi_unlock(AvahiPoll *ap);

/* Allocate an Avahi poll structure.  You only need one of these. */
struct AvahiPoll *alloc_gensio_avahi_poll(struct gensio_os_funcs *o);

typedef void (*gensio_avahi_done)(AvahiPoll *ap, void *userdata);

void gensio_avahi_poll_disable(AvahiPoll *ap);

void gensio_avahi_poll_free(AvahiPoll *ap,
			    gensio_avahi_done done, void *userdata);

#endif /* AVAHI_WATCHER_H */
