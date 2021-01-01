/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_TYPES_H
#define GENSIO_TYPES_H

#include <stddef.h>
#include <stdint.h>

struct gensio;

struct gensio_addr;

typedef unsigned long gensiods; /* Data size */

enum gensio_log_levels {
    GENSIO_LOG_FATAL,
    GENSIO_LOG_ERR,
    GENSIO_LOG_WARNING,
    GENSIO_LOG_INFO,
    GENSIO_LOG_DEBUG
};

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

#endif /* GENSIO_TYPES_H */
