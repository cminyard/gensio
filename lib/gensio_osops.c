/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#define _DEFAULT_SOURCE /* Get getgrouplist(), setgroups() */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int taddrlen;
#define EINTR WSAEINTR
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EAGAIN WSAEWOULDBLOCK
#define EADDRINUSE WSAEADDRINUSE
#else
#include <arpa/inet.h>
#include <netinet/tcp.h>
typedef socklen_t taddrlen;
#endif
#if HAVE_UNIX
#include <sys/un.h>
#endif

#include <gensio/gensio_osops.h>
#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/argvutils.h>

#include "errtrig.h"

static const char *progname = "gensio";

bool gensio_set_progname(const char *iprogname)
{
    progname = iprogname;
    return true;
}

struct gensio_iod {
    struct gensio_os_funcs *f;
    int fd;
    enum gensio_iod_type type;
    bool handlers_set;
    void *cb_data;
    void (*read_handler)(struct gensio_iod *iod, void *cb_data);
    void (*write_handler)(struct gensio_iod *iod, void *cb_data);
    void (*except_handler)(struct gensio_iod *iod, void *cb_data);
    void (*cleared_handler)(struct gensio_iod *iod, void *cb_data);
};

#ifdef _WIN32
#include "gensio_osops_win.h"
#else
#include "gensio_osops_unix.h"
#endif
#include "gensio_osops_addrinfo.h"
#include "gensio_osops_socket.h"
