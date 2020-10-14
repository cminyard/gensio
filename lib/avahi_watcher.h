/*
 *  gensio - A library for streaming I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  gensio give you permission to combine gensio with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for gensio and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of gensio are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
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

void gensio_avahi_poll_free(AvahiPoll *ap,
			    gensio_avahi_done done, void *userdata);

#endif /* AVAHI_WATCHER_H */
