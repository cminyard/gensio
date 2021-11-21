/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_TYPES_H
#define GENSIO_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct gensio;
struct gensio_accepter;

struct sergensio;
struct sergensio_accepter;

struct gensio_os_funcs;
struct gensio_iod;
struct gensio_addr;
struct gensio_opensocks;

struct gensio_lock;
struct gensio_timer;
struct gensio_runner;
struct gensio_waiter;

/*
 * Used by wait functions and general handling for process setup and
 * cleanup.
 */
struct gensio_os_proc_data;

/*
 * Basic thread handling.  You can use the standard OS functions to do
 * this, too, this is here for genericity.  It may not cover all your
 * needs.
 */
struct gensio_thread;

typedef unsigned long gensiods; /* Data size */

typedef int (*gensio_event)(struct gensio *io, void *user_data,
			    int event, int err,
			    unsigned char *buf, gensiods *buflen,
			    const char *const *auxdata);

typedef int (*gensio_accepter_event)(struct gensio_accepter *accepter,
				     void *user_data, int event, void *data);

/*
 * Callbacks for functions that don't give an error (close);
 */
typedef void (*gensio_done)(struct gensio *io, void *open_data);

/*
 * Callbacks for functions that give an error (open);
 */
typedef void (*gensio_done_err)(struct gensio *io, int err, void *open_data);

/*
 * Callbacks for functions that don't give an error (shutdown);
 */
typedef void (*gensio_acc_done)(struct gensio_accepter *acc, void *cb_data);

enum gensio_log_levels {
    GENSIO_LOG_FATAL,
    GENSIO_LOG_ERR,
    GENSIO_LOG_WARNING,
    GENSIO_LOG_INFO,
    GENSIO_LOG_DEBUG
};
#define GENSIO_LOG_MASK_ALL (1 << GENSIO_LOG_FATAL | 1 << GENSIO_LOG_ERR | \
	1 << GENSIO_LOG_WARNING | 1 << GENSIO_LOG_INFO | 1 << GENSIO_LOG_DEBUG)

typedef struct gensio_time {
    int64_t secs;
    int32_t nsecs;
} gensio_time;

/* Purposefully exactly the same as iovev (see writev(2)) */
struct gensio_sg {
    const void *buf;
    gensiods buflen;
};

#define gensio_container_of(ptr, type, member)		\
    ((type *)(((char *) ptr) - offsetof(type, member)))

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_TYPES_H */
