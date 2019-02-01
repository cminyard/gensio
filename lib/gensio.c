/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include "config.h"
#include <errno.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <limits.h>
#include <stdio.h>

#include <arpa/inet.h>
#ifdef HAVE_LIBSCTP
#include <netinet/sctp.h>
#endif

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>

#include "utils.h"

static unsigned int gensio_log_mask =
    (1 << GENSIO_LOG_FATAL) | (1 << GENSIO_LOG_ERR);

struct gensio_classobj {
    const char *name;
    void *classdata;
    struct gensio_classobj *next;
};

static int
gen_addclass(struct gensio_os_funcs *o,
	     struct gensio_classobj **classes,
	     const char *name, void *classdata)
{
    struct gensio_classobj *c;

    c = o->zalloc(o, sizeof(*c));
    if (!c)
	return ENOMEM;
    c->name = name;
    c->classdata = classdata;
    c->next = *classes;
    *classes = c;
    return 0;
}

static void *
gen_getclass(struct gensio_classobj *classes, const char *name)
{
    struct gensio_classobj *c;

    for (c = classes; c; c = c->next) {
	if (strcmp(c->name, name) == 0)
	    return c->classdata;
    }
    return NULL;
}

struct gensio {
    struct gensio_os_funcs *o;
    void *user_data;
    gensio_event cb;

    struct gensio_classobj *classes;

    gensio_func func;
    void *gensio_data;

    const char *typename;

    struct gensio *child;

    bool is_client;
    bool is_packet;
    bool is_reliable;
    bool is_authenticated;
    bool is_encrypted;

    struct gensio_link pending_link;
};

struct gensio *
gensio_data_alloc(struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  gensio_func func, struct gensio *child,
		  const char *typename, void *gensio_data)
{
    struct gensio *io = o->zalloc(o, sizeof(*io));

    if (!io)
	return NULL;

    io->o = o;
    io->cb = cb;
    io->user_data = user_data;
    io->func = func;
    io->typename = typename;
    io->gensio_data = gensio_data;
    io->child = child;

    return io;
}

void
gensio_data_free(struct gensio *io)
{
    while (io->classes) {
	struct gensio_classobj *c = io->classes;

	io->classes = c->next;
	io->o->free(io->o, c);
    }
    io->o->free(io->o, io);
}

void *
gensio_get_gensio_data(struct gensio *io)
{
    return io->gensio_data;
}

gensio_event
gensio_get_cb(struct gensio *io)
{
    return io->cb;
}

void gensio_set_cb(struct gensio *io, gensio_event cb, void *user_data)
{
    io->cb = cb;
    io->user_data = user_data;
}

int
gensio_cb(struct gensio *io, int event, int err,
	  unsigned char *buf, gensiods *buflen, const char *const *auxdata)
{
    return io->cb(io, event, err, buf, buflen, auxdata);
}

int
gensio_addclass(struct gensio *io, const char *name, void *classdata)
{
    return gen_addclass(io->o, &io->classes, name, classdata);
}

void *
gensio_getclass(struct gensio *io, const char *name)
{
    return gen_getclass(io->classes, name);
}

struct gensio_accepter {
    struct gensio_os_funcs *o;

    void *user_data;
    gensio_accepter_event cb;

    struct gensio_classobj *classes;

    const struct gensio_accepter_functions *funcs;
    gensio_acc_func func;
    void *gensio_acc_data;

    const char *typename;

    struct gensio_accepter *child;

    bool is_packet;
    bool is_reliable;

    struct gensio_list pending_ios;
};

struct gensio_accepter *
gensio_acc_data_alloc(struct gensio_os_funcs *o,
		      gensio_accepter_event cb, void *user_data,
		      gensio_acc_func func, struct gensio_accepter *child,
		      const char *typename, void *gensio_acc_data)
{
    struct gensio_accepter *acc = o->zalloc(o, sizeof(*acc));

    if (!acc)
	return NULL;

    acc->o = o;
    acc->cb = cb;
    acc->user_data = user_data;
    acc->func = func;
    acc->typename = typename;
    acc->child = child;
    acc->gensio_acc_data = gensio_acc_data;
    gensio_list_init(&acc->pending_ios);

    return acc;
}

void
gensio_acc_data_free(struct gensio_accepter *acc)
{
    while (acc->classes) {
	struct gensio_classobj *c = acc->classes;

	acc->classes = c->next;
	acc->o->free(acc->o, c);
    }
    acc->o->free(acc->o, acc);
}

void *
gensio_acc_get_gensio_data(struct gensio_accepter *acc)
{
    return acc->gensio_acc_data;
}

int
gensio_acc_cb(struct gensio_accepter *acc, int event, void *data)
{
    return acc->cb(acc, event, data);
}

int
gensio_acc_addclass(struct gensio_accepter *acc,
		    const char *name, void *classdata)
{
    return gen_addclass(acc->o, &acc->classes, name, classdata);
}

void *
gensio_acc_getclass(struct gensio_accepter *acc, const char *name)
{
    return gen_getclass(acc->classes, name);
}

const char *
gensio_acc_get_type(struct gensio_accepter *acc, unsigned int depth)
{
    struct gensio_accepter *c = acc;

    while (depth > 0) {
	if (!c->child)
	    return NULL;
	depth--;
	c = c->child;
    }
    return c->typename;
}

void
gensio_acc_add_pending_gensio(struct gensio_accepter *acc,
			      struct gensio *io)
{
    gensio_list_add_tail(&acc->pending_ios, &io->pending_link);
}

void
gensio_acc_remove_pending_gensio(struct gensio_accepter *acc,
				 struct gensio *io)
{
    gensio_list_rm(&acc->pending_ios, &io->pending_link);
}

int
gensio_scan_args(const char **rstr, int *argc, const char ***args)
{
    const char *str = *rstr;
    int err = 0;

    if (*str == '(') {
	err = str_to_argv_lengths_endchar(str + 1, argc, args, NULL,
					  " \f\n\r\t\v,", ")", &str);
	if (!err && (!str || (*str != ',' && *str)))
	    err = EINVAL; /* Not a ',' or end of string after */
	else
	    str++;
    } else {
	if (*str)
	    str += 1; /* skip the comma */
	err = str_to_argv_lengths("", argc, args, NULL, ")");
    }

    if (!err)
	*rstr = str;

    return err;
}

static int
strisallzero(const char *str)
{
    if (*str == '\0')
	return 0;

    while (*str == '0')
	str++;
    return *str == '\0';
}

static int
scan_ips(struct gensio_os_funcs *o, const char *str, bool listen, int ifamily,
	 int socktype, int protocol, bool *is_port_set, struct addrinfo **rai)
{
    char *strtok_data, *strtok_buffer;
    struct addrinfo hints, *ai = NULL, *ai2 = NULL, *ai3, *ai4;
    char *ip;
    char *port;
    int portnum;
    bool first = true, portset = false;
    int rv = 0;
    int bflags = AI_ADDRCONFIG;

    if (listen)
	bflags |= AI_PASSIVE;

    strtok_buffer = gensio_strdup(o, str);
    if (!strtok_buffer)
	return ENOMEM;

    ip = strtok_r(strtok_buffer, ",", &strtok_data);
    while (ip) {
	int family = ifamily, rflags = 0;

	if (strcmp(ip, "ipv4") == 0) {
	    family = AF_INET;
	    ip = strtok_r(NULL, ",", &strtok_data);
	} else if (strcmp(ip, "ipv6") == 0) {
	    family = AF_INET6;
	    ip = strtok_r(NULL, ",", &strtok_data);
	} else if (strcmp(ip, "ipv6n4") == 0) {
	    family = AF_INET6;
	    rflags |= AI_V4MAPPED;
	    ip = strtok_r(NULL, ",", &strtok_data);
	}

	if (ip == NULL) {
	    rv = EINVAL;
	    goto out_err;
	}

	port = strtok_r(NULL, ",", &strtok_data);
	if (port == NULL) {
	    port = ip;
	    ip = NULL;
	}

	if (ip && *ip == '\0')
	    ip = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = bflags | rflags;
	hints.ai_family = family;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;
	if (getaddrinfo(ip, port, &hints, &ai)) {
	    rv = EINVAL;
	    goto out_err;
	}

	/*
	 * If a port was/was not set, this must be consistent for all
	 * addresses.
	 */
	portnum = gensio_sockaddr_get_port(ai->ai_addr);
	if (portnum == -1) {
	    /* Not AF_INET or AF_INET6. */
	    rv = EINVAL;
	    goto out_err;
	}
	if (first) {
	    portset = portnum != 0;
	} else {
	    if ((portnum != 0) != portset) {
		/* One port was set and the other wasn't. */
		rv = ENXIO;
		goto out_err;
	    }
	}

	ai3 = gensio_dup_addrinfo(o, ai);
	if (!ai3) {
	    rv = ENOMEM;
	    goto out_err;
	}

	for (ai4 = ai3; ai4; ai4 = ai4->ai_next)
	    ai4->ai_flags = rflags;

	if (ai2)
	    ai2 = gensio_cat_addrinfo(o, ai2, ai3);
	else
	    ai2 = ai3;
	ip = strtok_r(NULL, ",", &strtok_data);
	first = false;
    }

    if (!ai2) {
	rv = ENOENT;
	goto out_err;
    }

    if (is_port_set)
	*is_port_set = portset;

    *rai = ai2;

 out_err:
    if (ai)
	freeaddrinfo(ai);
    o->free(o, strtok_buffer);
    if (rv && ai2)
	gensio_free_addrinfo(o, ai2);

    return rv;
}

int
gensio_scan_network_port(struct gensio_os_funcs *o, const char *str,
			 bool listen, struct addrinfo **rai,
			 int *socktype, int *protocol,
			 bool *is_port_set,
			 int *rargc, const char ***rargs)
{
    int err = 0, family = AF_UNSPEC, argc = 0;
    const char **args = NULL;
    bool doskip = true;

    if (strncmp(str, "ipv4,", 5) == 0) {
	family = AF_INET;
	str += 5;
    } else if (strncmp(str, "ipv6,", 5) == 0) {
	family = AF_INET6;
	str += 5;
    }

    if (strncmp(str, "tcp,", 4) == 0 ||
		(rargs && strncmp(str, "tcp(", 4) == 0)) {
	str += 3;
	*socktype = SOCK_STREAM;
	*protocol = IPPROTO_TCP;
    } else if (strncmp(str, "udp,", 4) == 0 ||
	       (rargs && strncmp(str, "udp(", 4) == 0)) {
	str += 3;
	*socktype = SOCK_DGRAM;
	*protocol = IPPROTO_UDP;
    } else if (strncmp(str, "sctp,", 5) == 0 ||
	       (rargs && strncmp(str, "sctp(", 5) == 0)) {
	str += 4;
	*socktype = SOCK_SEQPACKET;
	*protocol = IPPROTO_SCTP;
    } else {
	doskip = false;
	*socktype = SOCK_STREAM;
	*protocol = IPPROTO_TCP;
    }

    if (doskip) {
	if (*str == '(') {
	    if (!rargs)
		return EINVAL;
	    err = gensio_scan_args(&str, &argc, &args);
	    if (err)
		return err;
	} else {
	    str++; /* Skip the ',' */
	}
    }

    err = scan_ips(o, str, listen, family, *socktype, *protocol,
		   is_port_set, rai);
    if (err) {
	if (args)
	    str_to_argv_free(argc, args);
	return err;
    }

    if (rargc)
	*rargc = argc;
    if (rargs)
	*rargs = args;

    return 0;
}

int
gensio_scan_netaddr(struct gensio_os_funcs *o, const char *str, bool listen,
		    int socktype, int protocol, struct addrinfo **rai)
{
    int family = AF_UNSPEC;

    if (strncmp(str, "ipv4,", 5) == 0) {
	family = AF_INET;
	str += 5;
    } else if (strncmp(str, "ipv6,", 5) == 0) {
	family = AF_INET6;
	str += 5;
    }

    return scan_ips(o, str, listen, family, socktype, protocol, NULL, rai);
}

bool
gensio_sockaddr_equal(const struct sockaddr *a1, socklen_t l1,
		      const struct sockaddr *a2, socklen_t l2,
		      bool compare_ports)
{
    if (l1 != l2)
	return false;
    if (a1->sa_family != a2->sa_family)
	return false;
    switch (a1->sa_family) {
    case AF_INET:
	{
	    struct sockaddr_in *s1 = (struct sockaddr_in *) a1;
	    struct sockaddr_in *s2 = (struct sockaddr_in *) a2;
	    if (compare_ports && s1->sin_port != s2->sin_port)
		return false;
	    if (s1->sin_addr.s_addr != s2->sin_addr.s_addr)
		return false;
	}
	break;

    case AF_INET6:
	{
	    struct sockaddr_in6 *s1 = (struct sockaddr_in6 *) a1;
	    struct sockaddr_in6 *s2 = (struct sockaddr_in6 *) a2;
	    if (compare_ports && s1->sin6_port != s2->sin6_port)
		return false;
	    if (memcmp(s1->sin6_addr.s6_addr, s2->sin6_addr.s6_addr,
		       sizeof(s1->sin6_addr.s6_addr)) != 0)
		return false;
	}
	break;

    default:
	/* Unknown family. */
	return false;
    }

    return true;
}

int
gensio_sockaddr_get_port(const struct sockaddr *s)
{
    switch (s->sa_family) {
    case AF_INET:
	return ntohs(((struct sockaddr_in *) s)->sin_port);

    case AF_INET6:
	return ntohs(((struct sockaddr_in6 *) s)->sin6_port);
    }
    return -1;
}

void
gensio_set_callback(struct gensio *io, gensio_event cb, void *user_data)
{
    io->cb = cb;
    io->user_data = user_data;
}

void *
gensio_get_user_data(struct gensio *io)
{
    return io->user_data;
}

void
gensio_set_user_data(struct gensio *io, void *user_data)
{
    io->user_data = user_data;
}

int
gensio_write(struct gensio *io, gensiods *count,
	     const void *buf, gensiods buflen,
	     const char *const *auxdata)
{
    if (buflen == 0) {
	*count = 0;
	return 0;
    }
    return io->func(io, GENSIO_FUNC_WRITE, count, buf, buflen, NULL, auxdata);
}

int
gensio_raddr_to_str(struct gensio *io, gensiods *pos,
		    char *buf, gensiods buflen)
{
    return io->func(io, GENSIO_FUNC_RADDR_TO_STR, pos, NULL, buflen, buf, NULL);
}

int
gensio_get_raddr(struct gensio *io, void *addr, gensiods *addrlen)
{
    return io->func(io, GENSIO_FUNC_GET_RADDR, addrlen, NULL, 0, addr, NULL);
}

int
gensio_remote_id(struct gensio *io, int *id)
{
    return io->func(io, GENSIO_FUNC_REMOTE_ID, NULL, NULL, 0, id, NULL);
}

int
gensio_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    return io->func(io, GENSIO_FUNC_OPEN, NULL, open_done, 0, open_data, NULL);
}

struct gensio_open_s_data {
    struct gensio_os_funcs *o;
    int err;
    struct gensio_waiter *waiter;
};

static void
gensio_open_s_done(struct gensio *io, int err, void *cb_data)
{
    struct gensio_open_s_data *data = cb_data;

    data->err = err;
    data->o->wake(data->waiter);
}

int
gensio_open_s(struct gensio *io)
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_open_s_data data;
    int err;

    data.o = o;
    data.err = 0;
    data.waiter = o->alloc_waiter(o);
    if (!data.waiter)
	return ENOMEM;
    err = gensio_open(io, gensio_open_s_done, &data);
    if (!err) {
	o->wait(data.waiter, 1, NULL);
	err = data.err;
    }
    o->free_waiter(data.waiter);
    return err;
}

int
gensio_open_channel(struct gensio *io, const char * const args[],
		    gensio_event cb, void *user_data,
		    gensio_done_err open_done, void *open_data,
		    struct gensio **new_io)
{
    int rv;
    struct gensio_func_open_channel_data d;

    d.args = args;
    d.cb = cb;
    d.user_data = user_data;
    d.open_done = open_done;
    d.open_data = open_data;
    rv = io->func(io, GENSIO_FUNC_OPEN_CHANNEL, NULL, NULL, 0, &d, NULL);
    if (!rv)
	*new_io = d.new_io;

    return rv;
}

int
gensio_open_channel_s(struct gensio *io, const char * const args[],
		      gensio_event cb, void *user_data,
		      struct gensio **new_io)
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_open_s_data data;
    int err;

    data.o = o;
    data.err = 0;
    data.waiter = o->alloc_waiter(o);
    if (!data.waiter)
	return ENOMEM;
    err = gensio_open_channel(io, args, cb, user_data,
			      gensio_open_s_done, &data, new_io);
    if (!err) {
	o->wait(data.waiter, 1, NULL);
	err = data.err;
    }
    o->free_waiter(data.waiter);
    return err;
}

int
gensio_control(struct gensio *io, int depth, bool get,
	       unsigned int option, char *data, gensiods *datalen)
{
    struct gensio *c = io;

    if (depth == GENSIO_CONTROL_DEPTH_ALL) {
	if (get)
	    return EINVAL;
	while (c) {
	    int rv = c->func(c, GENSIO_FUNC_CONTROL, datalen, &get, option,
			     data, NULL);

	    if (rv && rv != ENOTSUP)
		return rv;
	    c = c->child;
	}
	return 0;
    }

    if (depth == GENSIO_CONTROL_DEPTH_FIRST) {
	while (c) {
	    int rv = c->func(c, GENSIO_FUNC_CONTROL, datalen, &get, option,
			     data, NULL);

	    if (rv != ENOTSUP)
		return rv;
	    c = c->child;
	}
	return ENOTSUP;
    }

    if (depth < 0)
	return EINVAL;

    while (depth > 0) {
	if (!c->child)
	    return ENOENT;
	depth--;
	c = c->child;
    }

    return c->func(c, GENSIO_FUNC_CONTROL, datalen, &get, option, data, NULL);
}

const char *
gensio_get_type(struct gensio *io, unsigned int depth)
{
    struct gensio *c = io;

    while (depth > 0) {
	if (!c->child)
	    return NULL;
	depth--;
	c = c->child;
    }
    return c->typename;
}

int
gensio_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    return io->func(io, GENSIO_FUNC_CLOSE, NULL, close_done, 0, close_data,
		    NULL);
}

struct gensio_close_s_data {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
};

static void
gensio_close_s_done(struct gensio *io, void *cb_data)
{
    struct gensio_close_s_data *data = cb_data;

    data->o->wake(data->waiter);
}

int
gensio_close_s(struct gensio *io)
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_close_s_data data;
    int err;

    data.o = o;
    data.waiter = o->alloc_waiter(o);
    if (!data.waiter)
	return ENOMEM;
    err = gensio_close(io, gensio_close_s_done, &data);
    if (!err)
	o->wait(data.waiter, 1, NULL);
    o->free_waiter(data.waiter);
    return err;
}

void
gensio_disable(struct gensio *io)
{
    struct gensio *c = io;

    while (c) {
	io->func(c, GENSIO_FUNC_DISABLE, NULL, NULL, 0, NULL, NULL);
	c = c->child;
    }
}

void
gensio_free(struct gensio *io)
{
    io->func(io, GENSIO_FUNC_FREE, NULL, NULL, 0, NULL, NULL);
}

void
gensio_set_read_callback_enable(struct gensio *io, bool enabled)
{
    io->func(io, GENSIO_FUNC_SET_READ_CALLBACK, NULL, NULL, enabled, NULL,
	     NULL);
}

void
gensio_set_write_callback_enable(struct gensio *io, bool enabled)
{
    io->func(io, GENSIO_FUNC_SET_WRITE_CALLBACK, NULL, NULL, enabled, NULL,
	     NULL);
}

void
gensio_ref(struct gensio *io)
{
    io->func(io, GENSIO_FUNC_REF, NULL, NULL, 0, NULL, NULL);
}

bool
gensio_is_client(struct gensio *io)
{
    return io->is_client;
}

bool
gensio_is_reliable(struct gensio *io)
{
    return io->is_reliable;
}

bool
gensio_is_packet(struct gensio *io)
{
    return io->is_packet;
}

bool
gensio_is_authenticated(struct gensio *io)
{
    return io->is_authenticated;
}

bool
gensio_is_encrypted(struct gensio *io)
{
    return io->is_encrypted;
}

void
gensio_set_is_client(struct gensio *io, bool is_client)
{
    io->is_client = is_client;
}

void
gensio_set_is_reliable(struct gensio *io, bool is_reliable)
{
    io->is_reliable = is_reliable;
}

void
gensio_set_is_packet(struct gensio *io, bool is_packet)
{
    io->is_packet = is_packet;
}

void
gensio_set_is_authenticated(struct gensio *io, bool is_authenticated)
{
    io->is_authenticated = is_authenticated;
}

void
gensio_set_is_encrypted(struct gensio *io, bool is_encrypted)
{
    io->is_encrypted = is_encrypted;
}

void *
gensio_acc_get_user_data(struct gensio_accepter *accepter)
{
    return accepter->user_data;
}

void
gensio_acc_set_user_data(struct gensio_accepter *accepter,
			 void *user_data)
{
    accepter->user_data = user_data;
}

void
gensio_acc_set_callback(struct gensio_accepter *accepter,
			gensio_accepter_event cb,
			void *user_data)
{
    accepter->cb = cb;
    accepter->user_data = user_data;
}

int
gensio_acc_startup(struct gensio_accepter *accepter)
{
    return accepter->func(accepter, GENSIO_ACC_FUNC_STARTUP, 0,
			  NULL, NULL, NULL, NULL, NULL);
}

int
gensio_acc_shutdown(struct gensio_accepter *accepter,
		    gensio_acc_done shutdown_done, void *shutdown_data)
{
    return accepter->func(accepter, GENSIO_ACC_FUNC_SHUTDOWN, 0,
			  0, shutdown_done, shutdown_data, NULL, NULL);
}

static void
gensio_acc_shutdown_s_done(struct gensio_accepter *acc, void *cb_data)
{
    struct gensio_close_s_data *data = cb_data;

    data->o->wake(data->waiter);
}

int
gensio_acc_shutdown_s(struct gensio_accepter *acc)
{
    struct gensio_os_funcs *o = acc->o;
    struct gensio_close_s_data data;
    int err;

    data.o = o;
    data.waiter = o->alloc_waiter(o);
    if (!data.waiter)
	return ENOMEM;
    err = gensio_acc_shutdown(acc, gensio_acc_shutdown_s_done, &data);
    if (!err)
	o->wait(data.waiter, 1, NULL);
    o->free_waiter(data.waiter);
    return err;
}

void
gensio_acc_disable(struct gensio_accepter *acc)
{
    struct gensio_accepter *c = acc;

    while (c) {
	struct gensio_link *l, *l2;

	gensio_list_for_each_safe(&acc->pending_ios, l, l2) {
	    struct gensio *io = gensio_container_of(l, struct gensio,
						    pending_link);
	    gensio_acc_remove_pending_gensio(acc, io);
	    gensio_disable(io);
	    gensio_free(io);
	}
	c->func(c, GENSIO_ACC_FUNC_DISABLE, 0, NULL, NULL, NULL, NULL, NULL);
	c = c->child;
    }
}

int
gensio_acc_control(struct gensio_accepter *acc, int depth, bool get,
		   unsigned int option, char *data, gensiods *datalen)
{
    struct gensio_accepter *c = acc;

    if (depth == GENSIO_CONTROL_DEPTH_ALL) {
	if (get)
	    return EINVAL;
	while (c) {
	    int rv = c->func(c, GENSIO_ACC_FUNC_CONTROL, get, NULL, NULL,
			     data, NULL, datalen);

	    if (rv && rv != ENOTSUP)
		return rv;
	    c = c->child;
	}
	return 0;
    }

    if (depth == GENSIO_CONTROL_DEPTH_FIRST) {
	while (c) {
	    int rv = c->func(c, GENSIO_ACC_FUNC_CONTROL, get, NULL, NULL,
			     data, NULL, datalen);

	    if (rv != ENOTSUP)
		return rv;
	    c = c->child;
	}
	return ENOTSUP;
    }

    if (depth < 0)
	return EINVAL;

    while (depth > 0) {
	if (!c->child)
	    return ENOENT;
	depth--;
	c = c->child;
    }

    return c->func(c, GENSIO_ACC_FUNC_CONTROL, get, NULL, NULL,
		   data, NULL, datalen);
}

void
gensio_acc_set_accept_callback_enable(struct gensio_accepter *accepter,
				      bool enabled)
{
    accepter->func(accepter, GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK, enabled,
		   NULL, NULL, NULL, NULL, NULL);
}

void
gensio_acc_free(struct gensio_accepter *accepter)
{
    accepter->func(accepter, GENSIO_ACC_FUNC_FREE, 0, NULL, NULL, NULL, NULL,
		   NULL);
}

int
gensio_acc_str_to_gensio(struct gensio_accepter *accepter, const char *addr,
			 gensio_event cb, void *user_data,
			 struct gensio **new_io)
{
    return accepter->func(accepter, GENSIO_ACC_FUNC_STR_TO_GENSIO, 0,
			  addr, cb, user_data, NULL, new_io);
}

/* FIXME - this is a cheap hack and needs to be fixed. */
bool
gensio_acc_exit_on_close(struct gensio_accepter *accepter)
{
    return strcmp(accepter->typename, "stdio") == 0;
}

bool
gensio_acc_is_reliable(struct gensio_accepter *accepter)
{
    return accepter->is_reliable;
}

bool
gensio_acc_is_packet(struct gensio_accepter *accepter)
{
    return accepter->is_packet;
}

void
gensio_acc_set_is_reliable(struct gensio_accepter *accepter, bool is_reliable)
{
     accepter->is_reliable = is_reliable;
}

void
gensio_acc_set_is_packet(struct gensio_accepter *accepter, bool is_packet)
{
    accepter->is_packet = is_packet;
}

struct registered_gensio_accepter {
    const char *name;
    str_to_gensio_acc_handler handler;
    struct registered_gensio_accepter *next;
};

struct registered_gensio_accepter *reg_gensio_accs;
struct gensio_lock *reg_gensio_acc_lock;


struct gensio_once gensio_acc_str_initialized;

static void
add_default_gensio_accepters(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    reg_gensio_acc_lock = o->alloc_lock(o);
    register_gensio_accepter(o, "tcp", str_to_tcp_gensio_accepter);
    register_gensio_accepter(o, "udp", str_to_udp_gensio_accepter);
    register_gensio_accepter(o, "sctp", str_to_sctp_gensio_accepter);
    register_gensio_accepter(o, "stdio", str_to_stdio_gensio_accepter);
    register_gensio_accepter(o, "ssl", str_to_ssl_gensio_accepter);
    register_gensio_accepter(o, "certauth", str_to_certauth_gensio_accepter);
    register_gensio_accepter(o, "telnet", str_to_telnet_gensio_accepter);
}

int
register_gensio_accepter(struct gensio_os_funcs *o,
			 const char *name, str_to_gensio_acc_handler handler)
{
    struct registered_gensio_accepter *n;

    o->call_once(o, &gensio_acc_str_initialized,
		 add_default_gensio_accepters, o);

    n = o->zalloc(o, sizeof(*n));
    if (!n)
	return ENOMEM;

    n->name = name;
    n->handler = handler;
    o->lock(reg_gensio_acc_lock);
    n->next = reg_gensio_accs;
    reg_gensio_accs = n;
    o->unlock(reg_gensio_acc_lock);
    return 0;
}

int str_to_gensio_accepter(const char *str,
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
    int err;
    struct addrinfo *ai = NULL;
    bool is_port_set;
    int socktype, protocol;
    int argc;
    const char **args = NULL;
    struct registered_gensio_accepter *r;
    unsigned int len;

    o->call_once(o, &gensio_acc_str_initialized,
		 add_default_gensio_accepters, o);

    while (isspace(*str))
	str++;
    for (r = reg_gensio_accs; r; r = r->next) {
	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != ',' && str[len] != '(' && str[len]))
	    continue;

	str += len;
	err = gensio_scan_args(&str, &argc, &args);
	if (!err)
	    err = r->handler(str, args, o, cb, user_data, accepter);
	if (args)
	    str_to_argv_free(argc, args);
	return err;
    }

    if (strisallzero(str)) {
	err = stdio_gensio_accepter_alloc(NULL, o, cb, user_data,
					  accepter);
    } else {
	err = gensio_scan_network_port(o, str, true, &ai, &socktype, &protocol,
				       &is_port_set, &argc, &args);
	if (!err) {
	    if (!is_port_set) {
		err = EINVAL;
	    } else if (protocol == IPPROTO_UDP) {
		err = udp_gensio_accepter_alloc(ai, args, o, cb,
						user_data, accepter);
	    } else if (protocol == IPPROTO_TCP) {
		err = tcp_gensio_accepter_alloc(ai, args, o, cb,
						user_data, accepter);
	    } else if (protocol == IPPROTO_SCTP) {
		err = sctp_gensio_accepter_alloc(ai, args, o, cb,
						 user_data, accepter);
	    } else {
		err = EINVAL;
	    }

	    gensio_free_addrinfo(o, ai);
	}
    }

    if (args)
	str_to_argv_free(argc, args);

    return err;
}

struct registered_gensio {
    const char *name;
    str_to_gensio_handler handler;
    struct registered_gensio *next;
};

struct registered_gensio *reg_gensios;
struct gensio_lock *reg_gensio_lock;


struct gensio_once gensio_str_initialized;

static void
add_default_gensios(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    reg_gensio_lock = o->alloc_lock(o);
    register_gensio(o, "tcp", str_to_tcp_gensio);
    register_gensio(o, "udp", str_to_udp_gensio);
    register_gensio(o, "sctp", str_to_sctp_gensio);
    register_gensio(o, "stdio", str_to_stdio_gensio);
    register_gensio(o, "pty", str_to_pty_gensio);
    register_gensio(o, "ssl", str_to_ssl_gensio);
    register_gensio(o, "certauth", str_to_certauth_gensio);
    register_gensio(o, "telnet", str_to_telnet_gensio);
    register_gensio(o, "serialdev", str_to_serialdev_gensio);
#ifdef HAVE_OPENIPMI
    register_gensio(o, "ipmisol", str_to_ipmisol_gensio);
#endif
}

int
register_gensio(struct gensio_os_funcs *o,
		const char *name, str_to_gensio_handler handler)
{
    struct registered_gensio *n;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);

    n = o->zalloc(o, sizeof(*n));
    if (!n)
	return ENOMEM;

    n->name = name;
    n->handler = handler;
    o->lock(reg_gensio_lock);
    n->next = reg_gensios;
    reg_gensios = n;
    o->unlock(reg_gensio_lock);
    return 0;
}

int
str_to_gensio(const char *str,
	      struct gensio_os_funcs *o,
	      gensio_event cb, void *user_data,
	      struct gensio **gensio)
{
    int err = 0;
    struct addrinfo *ai = NULL;
    bool is_port_set;
    int socktype, protocol;
    int argc;
    const char **args = NULL;
    struct registered_gensio *r;
    unsigned int len;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);

    while (isspace(*str))
	str++;
    for (r = reg_gensios; r; r = r->next) {
	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != ',' && str[len] != '(' && str[len]))
	    continue;

	str += len;
	err = gensio_scan_args(&str, &argc, &args);
	if (!err)
	    err = r->handler(str, args, o, cb, user_data, gensio);
	if (args)
	    str_to_argv_free(argc, args);
	return err;
    }

    if (*str == '/') {
	err = str_to_serialdev_gensio(str, NULL, o, cb, user_data,
				      gensio);
	goto out;
    }

    err = gensio_scan_network_port(o, str, false, &ai, &socktype, &protocol,
				   &is_port_set, &argc, &args);
    if (!err) {
	if (!is_port_set) {
	    err = EINVAL;
	} else if (protocol == IPPROTO_UDP) {
	    err = udp_gensio_alloc(ai, args, o, cb, user_data, gensio);
	} else if (protocol == IPPROTO_TCP) {
	    err = tcp_gensio_alloc(ai, args, o, cb, user_data, gensio);
	} else if (protocol == IPPROTO_SCTP) {
	    err = sctp_gensio_alloc(ai, args, o, cb, user_data, gensio);
	} else {
	    err = EINVAL;
	}

	gensio_free_addrinfo(o, ai);
    }

 out:
    if (args)
	str_to_argv_free(argc, args);

    return err;
}

struct addrinfo *
gensio_dup_addrinfo(struct gensio_os_funcs *o, struct addrinfo *iai)
{
    struct addrinfo *ai = NULL, *aic, *aip = NULL;

    while (iai) {
	aic = o->zalloc(o, sizeof(*aic));
	if (!aic)
	    goto out_nomem;
	memcpy(aic, iai, sizeof(*aic));
	aic->ai_next = NULL;
	aic->ai_addr = o->zalloc(o, iai->ai_addrlen);
	if (!aic->ai_addr) {
	    o->free(o, aic);
	    goto out_nomem;
	}
	memcpy(aic->ai_addr, iai->ai_addr, iai->ai_addrlen);
	if (iai->ai_canonname) {
	    aic->ai_canonname = gensio_strdup(o, iai->ai_canonname);
	    if (!aic->ai_canonname) {
		o->free(o, aic->ai_addr);
		o->free(o, aic);
		goto out_nomem;
	    }
	}
	if (aip) {
	    aip->ai_next = aic;
	    aip = aic;
	} else {
	    ai = aic;
	    aip = aic;
	}
	iai = iai->ai_next;
    }

    return ai;

 out_nomem:
    gensio_free_addrinfo(o, ai);
    return NULL;
}

struct addrinfo *gensio_cat_addrinfo(struct gensio_os_funcs *o,
				     struct addrinfo *ai1,
				     struct addrinfo *ai2)
{
    struct addrinfo *rai = ai1;

    while (ai1->ai_next)
	ai1 = ai1->ai_next;
    ai1->ai_next = ai2;

    return rai;
}

void
gensio_free_addrinfo(struct gensio_os_funcs *o, struct addrinfo *ai)
{
    while (ai) {
	struct addrinfo *aic = ai;

	ai = ai->ai_next;
	o->free(o, aic->ai_addr);
	if (aic->ai_canonname)
	    o->free(o, aic->ai_canonname);
	o->free(o, aic);
    }
}

char *
gensio_strdup(struct gensio_os_funcs *o, const char *str)
{
    char *s;

    if (!str)
	return NULL;

    s = o->zalloc(o, strlen(str) + 1);
    if (!s)
	return NULL;
    strcpy(s, str);
    return s;
}

int
gensio_sockaddr_to_str(const struct sockaddr *addr, socklen_t *addrlen,
		       char *buf, gensiods *epos, gensiods buflen)
{
    gensiods pos = 0;
    gensiods left;

    if (epos)
	pos = *epos;

    if (pos >= buflen)
	left = 0;
    else
	left = buflen - pos;

    if (addr->sa_family == AF_INET) {
	struct sockaddr_in *a4 = (struct sockaddr_in *) addr;
	char ibuf[INET_ADDRSTRLEN];

	if (addrlen && *addrlen && *addrlen != sizeof(struct sockaddr_in))
	    goto out_err;
	pos += snprintf(buf + pos, left, "%s,%d",
			inet_ntop(AF_INET, &a4->sin_addr, ibuf, sizeof(ibuf)),
			ntohs(a4->sin_port));
	if (addrlen)
	    *addrlen = sizeof(struct sockaddr_in);
    } else if (addr->sa_family == AF_INET6) {
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) addr;
	char ibuf[INET6_ADDRSTRLEN];

	if (addrlen && *addrlen && *addrlen != sizeof(struct sockaddr_in6))
	    goto out_err;
	pos += snprintf(buf + pos, left, "%s,%d",
			inet_ntop(AF_INET6, &a6->sin6_addr, ibuf, sizeof(ibuf)),
			ntohs(a6->sin6_port));
	if (addrlen)
	    *addrlen = sizeof(struct sockaddr_in6);
    } else {
    out_err:
	if (left)
	    buf[pos] = '\0';
	return EINVAL;
    }

    if (epos)
	*epos = pos;

    return 0;
}

int
gensio_check_keyvalue(const char *str, const char *key, const char **value)
{
    unsigned int keylen = strlen(key);

    if (strncmp(str, key, keylen) != 0)
	return 0;
    if (str[keylen] != '=')
	return 0;
    *value = str + keylen + 1;
    return 1;
}

int
gensio_check_keyds(const char *str, const char *key, gensiods *rvalue)
{
    const char *sval;
    char *end;
    int rv = gensio_check_keyvalue(str, key, &sval);
    gensiods value;

    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    value = strtoul(sval, &end, 0);
    if (*end != '\0')
	return -1;

    *rvalue = value;
    return 1;
}

int
gensio_check_keyuint(const char *str, const char *key, unsigned int *rvalue)
{
    const char *sval;
    char *end;
    int rv = gensio_check_keyvalue(str, key, &sval);
    unsigned long value;

    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    value = strtoul(sval, &end, 0);
    if (*end != '\0')
	return -1;

    if (value > UINT_MAX)
	return -1;

    *rvalue = value;
    return 1;
}

int
gensio_check_keybool(const char *str, const char *key, bool *rvalue)
{
    const char *sval;
    int rv;

    if (strcmp(str, key) == 0) {
	*rvalue = true;
	return 1;
    }

    rv = gensio_check_keyvalue(str, key, &sval);
    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    if (strcmp(sval, "true") == 0 || strcmp(sval, "1") == 0)
	*rvalue = true;
    else if (strcmp(sval, "false") == 0 || strcmp(sval, "0") == 0)
	*rvalue = false;
    else
	return -1;

    return 1;
}

int
gensio_check_keyboolv(const char *str, const char *key, const char *trueval,
		      const char *falseval, bool *rvalue)
{
    const char *sval;
    int rv;

    rv = gensio_check_keyvalue(str, key, &sval);
    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    if (strcmp(sval, trueval) == 0)
	*rvalue = true;
    else if (strcmp(sval, falseval) == 0)
	*rvalue = false;
    else
	return -1;

    return 1;
}

int
gensio_check_keyaddrs(struct gensio_os_funcs *o,
		      const char *str, const char *key, int iprotocol,
		      bool listen, bool require_port, struct addrinfo **rai)
{
    const char *sval;
    int rv;
    struct addrinfo *ai;
    int socktype, protocol;
    bool is_port_set;

    rv = gensio_check_keyvalue(str, key, &sval);
    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    rv = gensio_scan_network_port(o, sval, listen, &ai, &socktype,
				  &protocol, &is_port_set, NULL, NULL);
    if (rv)
	return -1;

    if (require_port && !is_port_set)
	return -1;
    if (protocol != iprotocol)
	return -1;

    *rai = ai;

    return 1;
}

void
gensio_set_log_mask(unsigned int mask)
{
    gensio_log_mask = mask;
}

unsigned int
gensio_get_log_mask(void)
{
    return gensio_log_mask;
}

void
gensio_vlog(struct gensio_os_funcs *o, enum gensio_log_levels level,
	    const char *str, va_list args)
{
    if (!(gensio_log_mask & (1 << level)))
	return;

    o->vlog(o, level, str, args);
}

void
gensio_log(struct gensio_os_funcs *o, enum gensio_log_levels level,
	   const char *str, ...)
{
    va_list args;

    va_start(args, str);
    gensio_vlog(o, level, str, args);
    va_end(args);
}

void
gensio_acc_vlog(struct gensio_accepter *acc, enum gensio_log_levels level,
		char *str, va_list args)
{
    struct gensio_loginfo info;

    if (!(gensio_log_mask & (1 << level)))
	return;

    info.level = level;
    info.str = str;
    va_copy(info.args, args);
    acc->cb(acc, GENSIO_ACC_EVENT_LOG, &info);
    va_end(info.args);
}

void
gensio_acc_log(struct gensio_accepter *acc, enum gensio_log_levels level,
	       char *str, ...)
{
    va_list args;

    va_start(args, str);
    gensio_acc_vlog(acc, level, str, args);
    va_end(args);
}

static struct gensio_once gensio_default_initialized;

static struct gensio_lock *deflock;

union gensio_def_val {
	char *strval;
	int intval;
};

struct gensio_class_def {
    const char *class;
    union gensio_def_val val;
    struct gensio_class_def *next;
};

struct gensio_def_entry {
    const char *name;
    enum gensio_default_type type;
    int min;
    int max;
    union gensio_def_val val;
    bool val_set;
    union gensio_def_val def;
    const struct gensio_enum_val *enums;
    struct gensio_class_def *classvals;
    struct gensio_def_entry *next;
};

static struct gensio_enum_val gensio_parity_enums[] = {
    { "NONE", 'N' },
    { "EVEN", 'E' },
    { "ODD", 'O' },
    { "none", 'N' },
    { "even", 'E' },
    { "odd", 'O' },
    { "MARK", 'M' },
    { "SPACE", 'S' },
    { "mark", 'M' },
    { "space", 'S' },
    { NULL }
};

#ifdef HAVE_OPENIPMI
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_sol.h>
struct gensio_enum_val shared_serial_alert_enums[] = {
    { "fail",		ipmi_sol_serial_alerts_fail },
    { "deferred", 	ipmi_sol_serial_alerts_deferred },
    { "succeed", 	ipmi_sol_serial_alerts_succeed },
    { NULL }
};
#endif

struct gensio_def_entry builtin_defaults[] = {
    /* serialdev */
    { "stopbits",	GENSIO_DEFAULT_INT,	.min = 1, .max = 2,
						.def.intval = 1},
    { "databits",	GENSIO_DEFAULT_INT,	.min = 5, .max = 8,
						.def.intval = 8 },
    { "parity",		GENSIO_DEFAULT_ENUM,	.enums = gensio_parity_enums,
						.def.intval = 'N' },
    { "xonxoff",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "rtscts",		GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "local",		GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "hangup_when_done", GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    /* serialdev and SOL */
    { "speed",		GENSIO_DEFAULT_INT,	.min = 1, .max = INT_MAX,
						.def.intval = 9600 },
    { "nobreak",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
#ifdef HAVE_OPENIPMI
    /* SOL only */
    { "authenticated",	GENSIO_DEFAULT_BOOL,	.def.intval = 1 },
    { "encrypted",	GENSIO_DEFAULT_BOOL,	.def.intval = 1 },
    { "ack-timeout",	GENSIO_DEFAULT_INT,	.min = 1, .max = INT_MAX,
						.def.intval = 1000000 },
    { "ack-retries",	GENSIO_DEFAULT_INT,	.min = 1, .max = INT_MAX,
						.def.intval = 10 },
    { "shared-serial-alert", GENSIO_DEFAULT_ENUM,
				.enums = shared_serial_alert_enums,
				.def.intval = ipmi_sol_serial_alerts_fail },
    { "deassert_CTS_DCD_DSR_on_connect", GENSIO_DEFAULT_BOOL, .def.intval = 0 },
#endif
    /* For telnet */
    { "rfc2217",	GENSIO_DEFAULT_BOOL,	.def.intval = false },
    /* For SSL or other key authentication. */
    { "CA",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "cert",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "key",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "clientauth",	GENSIO_DEFAULT_BOOL,	.def.intval = false },
    /* General authentication flags. */
    { "allow-authfail",	GENSIO_DEFAULT_BOOL,	.def.intval = false },
    { "username",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "password",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "service",	GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "use-child-auth",	GENSIO_DEFAULT_BOOL,	.def.intval = false, },
    {}
};

static struct gensio_def_entry *defaults;

static void
gensio_default_init(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    deflock = o->alloc_lock(o);
    if (!deflock)
	gensio_log(o, GENSIO_LOG_FATAL,
		   "Unable to allocate gensio default lock");
}

static void
gensio_reset_default(struct gensio_os_funcs *o, struct gensio_def_entry *d)
{
    struct gensio_class_def *n, *c = d->classvals;

    for (; c; c = n) {
	n = c->next;
	if (c->val.strval)
	    o->free(o, c->val.strval);
	o->free(o, c);
    }
    d->classvals = NULL;

    if (d->val.strval) {
	o->free(o, d->val.strval);
	d->val.strval = NULL;
    }
    d->val_set = false;
}

void
gensio_reset_defaults(struct gensio_os_funcs *o)
{
    struct gensio_def_entry *d;
    unsigned int i;

    o->call_once(o, &gensio_default_initialized, gensio_default_init, o);

    o->lock(deflock);
    for (i = 0; builtin_defaults[i].name; i++)
	gensio_reset_default(o, &builtin_defaults[i]);
    for (d = defaults; d; d = d->next)
	gensio_reset_default(o, d);
    o->unlock(deflock);
}

static struct gensio_def_entry *
gensio_lookup_default(const char *name)
{
    struct gensio_def_entry *d;
    unsigned int i;

    for (i = 0; builtin_defaults[i].name; i++) {
	if (strcmp(builtin_defaults[i].name, name) == 0)
	    return &builtin_defaults[i];
    }
    for (d = defaults; d; d = d->next) {
	if (strcmp(d->name, name) == 0)
	    return d;
    }
    return NULL;
}

static struct gensio_class_def *
gensio_lookup_default_class(struct gensio_def_entry *d, const char *class)
{
    struct gensio_class_def *c = d->classvals;

    for (; c; c = c->next) {
	if (strcmp(c->class, class) == 0)
	    return c;
    }
    return NULL;
}

int
gensio_add_default(struct gensio_os_funcs *o,
		   const char *name,
		   enum gensio_default_type type,
		   const char *strval, int intval,
		   int minval, int maxval,
		   const struct gensio_enum_val *enums)
{
    int err = 0;
    struct gensio_def_entry *d;

    o->call_once(o, &gensio_default_initialized, gensio_default_init, o);

    o->lock(deflock);
    d = gensio_lookup_default(name);
    if (d) {
	err = EEXIST;
	goto out_unlock;
    }

    d = o->zalloc(o, sizeof(*d));
    if (!d) {
	err = ENOMEM;
	goto out_unlock;
    }

    d->type = type;
    d->name = name;
    d->min = minval;
    d->max = maxval;
    d->enums = enums;
    d->def.intval = intval;
    if (strval) {
	d->def.strval = strdup(strval);
	if (!d->def.strval) {
	    o->free(0, d);
	    err = ENOMEM;
	    goto out_unlock;
	}
    }

    d->next = defaults;
    defaults = d;

 out_unlock:
    o->unlock(deflock);
    return err;
}

int
gensio_set_default(struct gensio_os_funcs *o,
		   const char *class, const char *name,
		   const char *strval, int intval)
{
    int err = 0;
    struct gensio_def_entry *d;
    char *new_strval = NULL, *end;
    unsigned int i;

    o->call_once(o, &gensio_default_initialized, gensio_default_init, o);

    o->lock(deflock);
    d = gensio_lookup_default(name);
    if (!d) {
	err = ENOENT;
	goto out_unlock;
    }

    switch (d->type) {
    case GENSIO_DEFAULT_ENUM:
	for (i = 0; d->enums[i].name; i++) {
	    if (strcmp(d->enums[i].name, strval) == 0)
		break;
	}
	if (!d->enums[i].name) {
	    err = EINVAL;
	    goto out_unlock;
	}
	intval = d->enums[i].val;
	break;

    case GENSIO_DEFAULT_BOOL:
	intval = strtoul(strval, &end, 10);
	if (end == strval || *end)
	    intval = !!intval;
	else if (strcmp(strval, "true") == 0 ||
		 strcmp(strval, "TRUE") == 0)
	    intval = 1;
	else if (strcmp(strval, "false") == 0 ||
		 strcmp(strval, "FALSE") == 0)
	    intval = 0;
	else {
	    err = EINVAL;
	    goto out_unlock;
	}
	break;

    case GENSIO_DEFAULT_INT:
	if (strval) {
	    intval = strtoul(strval, &end, 10);
	    if (end == strval || *end) {
		err = EINVAL;
		goto out_unlock;
	    }
	    if (intval < d->min || intval > d->max) {
		err = ERANGE;
		goto out_unlock;
	    }
	}
	break;

    case GENSIO_DEFAULT_STR:
	new_strval = gensio_strdup(o, strval);
	if (!new_strval) {
	    err = ENOMEM;
	    goto out_unlock;
	}
	break;

    default:
	err = EINVAL;
	goto out_unlock;
    }

    if (class) {
	struct gensio_class_def *c = gensio_lookup_default_class(d, class);

	if (!c) {
	    c = o->zalloc(o, sizeof(*c));
	    if (!c) {
		err = ENOMEM;
		goto out_unlock;
	    }
	    c->class = class;
	    if (c->val.strval)
		o->free(o, c->val.strval);
	    c->val.strval = new_strval;
	    new_strval = NULL;
	    c->val.intval = intval;
	    c->next = d->classvals;
	    d->classvals = c;
	}
    } else {
	if (d->val.strval)
	    o->free(o, d->val.strval);
	d->val.strval = new_strval;
	new_strval = NULL;
	d->val.intval = intval;
	d->val_set = true;
    }

 out_unlock:
    if (new_strval)
	o->free(o, new_strval);
    o->unlock(deflock);
    return err;
}

int
gensio_get_default(struct gensio_os_funcs *o,
		   const char *class, const char *name, bool classonly,
		   enum gensio_default_type type,
		   const char **strval, int *intval)
{
    struct gensio_def_entry *d;
    struct gensio_class_def *c = NULL;
    union gensio_def_val *val;
    int err = 0;

    o->call_once(o, &gensio_default_initialized, gensio_default_init, o);

    o->lock(deflock);
    d = gensio_lookup_default(name);
    if (!d) {
	err = ENOENT;
	goto out_unlock;
    }

    if (d->type != type &&
	    !(d->type == GENSIO_DEFAULT_ENUM && type == GENSIO_DEFAULT_INT) &&
	    !(d->type == GENSIO_DEFAULT_BOOL && type == GENSIO_DEFAULT_INT)) {
	err = EINVAL;
	goto out_unlock;
    }

    if (class)
	c = gensio_lookup_default_class(d, class);

    if (c)
	val = &c->val;
    else if (d->val_set)
	val = &d->val;
    else
	val = &d->def;

    switch (type) {
    case GENSIO_DEFAULT_BOOL:
    case GENSIO_DEFAULT_ENUM:
    case GENSIO_DEFAULT_INT:
	*intval = val->intval;
	break;

    case GENSIO_DEFAULT_STR:
	*strval = val->strval;
	break;

    default:
	abort(); /* Shouldn't happen. */
    }

 out_unlock:
    o->unlock(deflock);

    return err;
}

void
gensio_list_rm(struct gensio_list *list, struct gensio_link *link)
{
    link->next->prev = link->prev;
    link->prev->next = link->next;
}

void
gensio_list_add_tail(struct gensio_list *list, struct gensio_link *link)
{
    link->prev = list->link.prev;
    link->next = &list->link;
    list->link.prev->next = link;
    list->link.prev = link;
}

void
gensio_list_init(struct gensio_list *list)
{
    list->link.next = &list->link;
    list->link.prev = &list->link;
}

bool
gensio_list_empty(struct gensio_list *list)
{
    return list->link.next == &list->link;
}

const char *
gensio_log_level_to_str(enum gensio_log_levels level)
{
    switch (level) {
    case GENSIO_LOG_FATAL: return "fatal"; break;
    case GENSIO_LOG_ERR: return "err"; break;
    case GENSIO_LOG_WARNING: return "warning"; break;
    case GENSIO_LOG_INFO: return "info"; break;
    case GENSIO_LOG_DEBUG: return "debug"; break;
    default: return "invalid";
    }
}
