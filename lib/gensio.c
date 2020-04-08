/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_builtins.h>
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
	return GE_NOMEM;
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

struct gensio_nocbwait {
    bool queued;
    struct gensio_waiter *waiter;
    struct gensio_link link;
};

struct gensio_sync_io;

struct gensio {
    struct gensio_os_funcs *o;
    void *user_data;
    gensio_event cb;
    unsigned int cb_count;
    struct gensio_list waiters;
    struct gensio_lock *lock;

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
    bool is_message;

    struct gensio_sync_io *sync_io;

    struct gensio_link link;
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

    io->lock = o->alloc_lock(o);
    if (!io->lock) {
	o->free(o, io);
	return NULL;
    }
    gensio_list_init(&io->waiters);
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
    assert(gensio_list_empty(&io->waiters));

    while (io->classes) {
	struct gensio_classobj *c = io->classes;

	io->classes = c->next;
	io->o->free(io->o, c);
    }
    io->o->free_lock(io->lock);
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
    struct gensio_os_funcs *o = io->o;
    int rv;

    if (!io->cb)
	return GE_NOTSUP;
    o->lock(io->lock);
    io->cb_count++;
    o->unlock(io->lock);
    rv = io->cb(io, io->user_data, event, err, buf, buflen, auxdata);
    o->lock(io->lock);
    assert(io->cb_count > 0);
    io->cb_count--;
    if (io->cb_count == 0) {
	struct gensio_link *l, *l2;

	gensio_list_for_each_safe(&io->waiters, l, l2) {
	    struct gensio_nocbwait *w = gensio_container_of(l,
							struct gensio_nocbwait,
							link);

	    gensio_list_rm(&io->waiters, l);
	    w->queued = false;
	    o->wake(w->waiter);
	}
    }
    o->unlock(io->lock);

    return rv;
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
    struct gensio_lock *lock;

    struct gensio_classobj *classes;

    const struct gensio_accepter_functions *funcs;
    gensio_acc_func func;
    void *gensio_acc_data;

    const char *typename;

    struct gensio_accepter *child;

    bool is_packet;
    bool is_reliable;
    bool is_message;
    bool sync;
    bool enabled;

    struct gensio_list pending_ios;

    struct gensio_list waiting_ios;
    struct gensio_list waiting_accepts;
};

struct gensio_waiting_accept {
    bool queued;
    struct gensio_waiter *waiter;
    struct gensio_link link;
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

    acc->lock = o->alloc_lock(o);
    if (!acc->lock) {
	o->free(o, acc);
	return NULL;
    }
    acc->o = o;
    acc->cb = cb;
    acc->user_data = user_data;
    acc->func = func;
    acc->typename = typename;
    acc->child = child;
    acc->gensio_acc_data = gensio_acc_data;
    gensio_list_init(&acc->pending_ios);
    gensio_list_init(&acc->waiting_ios);
    gensio_list_init(&acc->waiting_accepts);

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
    if (acc->lock)
	acc->o->free_lock(acc->lock);
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
    if (event == GENSIO_ACC_EVENT_NEW_CONNECTION && acc->sync) {
	struct gensio *io = data;

	acc->o->lock(acc->lock);
	if (!acc->enabled) {
	    gensio_free(io);
	} else {
	    gensio_list_add_tail(&acc->waiting_ios, &io->link);
	    if (!gensio_list_empty(&acc->waiting_accepts)) {
		struct gensio_link *l =
		    gensio_list_first(&acc->waiting_accepts);
		struct gensio_waiting_accept *wa =
		    gensio_container_of(l,
					struct gensio_waiting_accept,
					link);

		wa->queued = false;
		gensio_list_rm(&acc->waiting_accepts, &wa->link);
		acc->o->wake(wa->waiter);
	    }
	}
	acc->o->unlock(acc->lock);
	return 0;
    }
    if (!acc->cb)
	return GE_NOTSUP;
    return acc->cb(acc, acc->user_data, event, data);
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
    gensio_list_add_tail(&acc->pending_ios, &io->link);
}

void
gensio_acc_remove_pending_gensio(struct gensio_accepter *acc,
				 struct gensio *io)
{
    gensio_list_rm(&acc->pending_ios, &io->link);
}

int
gensio_scan_args(struct gensio_os_funcs *o,
		 const char **rstr, int *argc, const char ***args)
{
    const char *str = *rstr;
    int err = 0;

    if (*str == '(') {
	err = gensio_str_to_argv_endchar(o, str + 1, argc, args,
					 " \f\n\r\t\v,", ")", &str);
	if (!err) {
	    if (*str != ')') {
		err = GE_INVAL; /* Didn't end in ')'. */
	    } else {
		str++;
		if (*str != ',' && *str)
		    err = GE_INVAL; /* Not a ',' or end of string after */
		else
		    str++;
	    }
	}
    } else {
	if (*str)
	    str += 1; /* skip the comma */
	err = gensio_str_to_argv(o, "", argc, args, ")");
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
    struct gensio_sg sg;

    if (buflen == 0) {
	*count = 0;
	return 0;
    }
    sg.buf = buf;
    sg.buflen = buflen;
    return io->func(io, GENSIO_FUNC_WRITE_SG, count, &sg, 1, NULL, auxdata);
}

int
gensio_write_sg(struct gensio *io, gensiods *count,
		const struct gensio_sg *sg, gensiods sglen,
		const char *const *auxdata)
{
    if (sglen == 0) {
	*count = 0;
	return 0;
    }
    return io->func(io, GENSIO_FUNC_WRITE_SG, count, sg, sglen, NULL, auxdata);
}

int
gensio_raddr_to_str(struct gensio *io, gensiods *pos,
		    char *buf, gensiods buflen)
{
    struct gensio *c = io;
    gensiods dummypos = 0;

    if (!pos)
	pos = &dummypos;

    while (c) {
	int rv = c->func(c, GENSIO_FUNC_RADDR_TO_STR, pos, NULL, buflen,
			 buf, NULL);
	if (rv != GE_NOTSUP)
	    return rv;
	c = c->child;
    }
    return GE_NOTSUP;
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

int
gensio_open_nochild(struct gensio *io, gensio_done_err open_done,
		    void *open_data)
{
    return io->func(io, GENSIO_FUNC_OPEN_NOCHILD, NULL, open_done, 0,
		    open_data, NULL);
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

static int
i_gensio_open_s(struct gensio *io,
		int (*func)(struct gensio *io, gensio_done_err open_done,
			    void *open_data))
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_open_s_data data;
    int err;

    data.o = o;
    data.err = 0;
    data.waiter = o->alloc_waiter(o);
    if (!data.waiter)
	return GE_NOMEM;
    err = func(io, gensio_open_s_done, &data);
    if (!err) {
	o->wait(data.waiter, 1, NULL);
	err = data.err;
    }
    o->free_waiter(data.waiter);
    return err;
}

int
gensio_open_s(struct gensio *io)
{
    return i_gensio_open_s(io, gensio_open);
}

int
gensio_open_nochild_s(struct gensio *io)
{
    return i_gensio_open_s(io, gensio_open_nochild);
}

int
gensio_alloc_channel(struct gensio *io, const char * const args[],
		     gensio_event cb, void *user_data,
		     struct gensio **new_io)
{
    int rv;
    struct gensio_func_alloc_channel_data d;

    d.args = args;
    d.cb = cb;
    d.user_data = user_data;
    rv = io->func(io, GENSIO_FUNC_ALLOC_CHANNEL, NULL, NULL, 0, &d, NULL);
    if (!rv)
	*new_io = d.new_io;

    return rv;
}

int
gensio_control(struct gensio *io, int depth, bool get,
	       unsigned int option, char *data, gensiods *datalen)
{
    struct gensio *c = io;

    if (depth == GENSIO_CONTROL_DEPTH_ALL) {
	if (get)
	    return GE_INVAL;
	while (c) {
	    int rv = c->func(c, GENSIO_FUNC_CONTROL, datalen, &get, option,
			     data, NULL);

	    if (rv && rv != GE_NOTSUP)
		return rv;
	    c = c->child;
	}
	return 0;
    }

    if (depth == GENSIO_CONTROL_DEPTH_FIRST) {
	while (c) {
	    int rv = c->func(c, GENSIO_FUNC_CONTROL, datalen, &get, option,
			     data, NULL);

	    if (rv != GE_NOTSUP)
		return rv;
	    c = c->child;
	}
	return GE_NOTSUP;
    }

    if (depth < 0)
	return GE_INVAL;

    while (depth > 0) {
	if (!c->child)
	    return GE_NOTFOUND;
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

struct gensio *
gensio_get_child(struct gensio *io, unsigned int depth)
{
    struct gensio *c = io;

    while (depth > 0) {
	if (!c->child)
	    return NULL;
	depth--;
	c = c->child;
    }
    return c;
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
	return GE_NOMEM;
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
gensio_is_message(struct gensio *io)
{
    return io->is_message;
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
gensio_set_is_message(struct gensio *io, bool is_message)
{
    io->is_message = is_message;
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
    accepter->enabled = true;
    return accepter->func(accepter, GENSIO_ACC_FUNC_STARTUP, 0,
			  NULL, NULL, NULL, NULL, NULL);
}

int
gensio_acc_shutdown(struct gensio_accepter *accepter,
		    gensio_acc_done shutdown_done, void *shutdown_data)
{
    struct gensio_link *l, *l2;

    accepter->o->lock(accepter->lock);
    accepter->enabled = false;
    accepter->sync = false;
    gensio_list_for_each_safe(&accepter->waiting_accepts, l, l2) {
	struct gensio_waiting_accept *wa =
	    gensio_container_of(l,
				struct gensio_waiting_accept,
				link);

	wa->queued = false;
	gensio_list_rm(&accepter->waiting_accepts, &wa->link);
	accepter->o->wake(wa->waiter);
    }
    gensio_list_for_each_safe(&accepter->waiting_ios, l, l2) {
	struct gensio *io = gensio_container_of(l, struct gensio, link);

	gensio_list_rm(&accepter->waiting_ios, &io->link);
	gensio_free(io);
    }
    accepter->o->unlock(accepter->lock);
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
	return GE_NOMEM;
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

    acc->enabled = false;
    while (c) {
	struct gensio_link *l, *l2;

	gensio_list_for_each_safe(&acc->pending_ios, l, l2) {
	    struct gensio *io = gensio_container_of(l, struct gensio, link);

	    gensio_acc_remove_pending_gensio(acc, io);
	    gensio_disable(io);
	    gensio_free(io);
	}
	gensio_list_for_each_safe(&acc->waiting_ios, l, l2) {
	    struct gensio *io = gensio_container_of(l, struct gensio, link);

	    gensio_list_rm(&acc->waiting_ios, &io->link);
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
	    return GE_INVAL;
	while (c) {
	    int rv = c->func(c, GENSIO_ACC_FUNC_CONTROL, get, NULL, &option,
			     data, NULL, datalen);

	    if (rv && rv != GE_NOTSUP)
		return rv;
	    c = c->child;
	}
	return 0;
    }

    if (depth == GENSIO_CONTROL_DEPTH_FIRST) {
	while (c) {
	    int rv = c->func(c, GENSIO_ACC_FUNC_CONTROL, get, NULL, &option,
			     data, NULL, datalen);

	    if (rv != GE_NOTSUP)
		return rv;
	    c = c->child;
	}
	return GE_NOTSUP;
    }

    if (depth < 0)
	return GE_INVAL;

    while (depth > 0) {
	if (!c->child)
	    return GE_NOTFOUND;
	depth--;
	c = c->child;
    }

    return c->func(c, GENSIO_ACC_FUNC_CONTROL, get, NULL, &option,
		   data, NULL, datalen);
}

void
gensio_acc_set_accept_callback_enable(struct gensio_accepter *accepter,
				      bool enabled)
{
    accepter->func(accepter, GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK, enabled,
		   NULL, NULL, NULL, NULL, NULL);
}

int
gensio_acc_set_accept_callback_enable_cb(struct gensio_accepter *accepter,
					 bool enabled,
					 gensio_acc_done done,
					 void *done_data)
{
    return accepter->func(accepter, GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK,
			  enabled, NULL, done, done_data, NULL, NULL);
}

struct acc_cb_enable_data {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
};

static void
acc_cb_enable_done(struct gensio_accepter *acc, void *done_data)
{
    struct acc_cb_enable_data *data = done_data;

    data->o->wake(data->waiter);
}

int
gensio_acc_set_accept_callback_enable_s(struct gensio_accepter *accepter,
					bool enabled)
{
    struct acc_cb_enable_data data;
    int err;

    data.o = accepter->o;
    data.waiter = data.o->alloc_waiter(data.o);
    if (!data.waiter)
	return GE_NOMEM;
    err = gensio_acc_set_accept_callback_enable_cb(accepter, enabled,
						   acc_cb_enable_done, &data);
    if (err) {
	data.o->free_waiter(data.waiter);
	return err;
    }
    data.o->wait(data.waiter, 1, NULL);
    data.o->free_waiter(data.waiter);

    return 0;
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

bool
gensio_acc_is_message(struct gensio_accepter *accepter)
{
    return accepter->is_message;
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

void
gensio_acc_set_is_message(struct gensio_accepter *accepter, bool is_message)
{
    accepter->is_message = is_message;
}

struct registered_gensio_accepter {
    const char *name;
    str_to_gensio_acc_handler handler;
    str_to_gensio_acc_child_handler chandler;
    struct registered_gensio_accepter *next;
};

static struct registered_gensio_accepter *reg_gensio_accs;
static struct gensio_lock *reg_gensio_acc_lock;


static struct gensio_once gensio_acc_str_initialized;
static int reg_gensio_acc_rv;

#define REG_GENSIO_ACC(o, str, acc) \
    do {								\
	reg_gensio_acc_rv = register_gensio_accepter(o, str, acc);	\
	if (reg_gensio_acc_rv)						\
	    return;							\
    } while(0)
#define REG_FILT_GENSIO_ACC(o, str, acc, aloc) \
    do {								\
	reg_gensio_acc_rv = register_filter_gensio_accepter(o, str, acc, aloc);\
	if (reg_gensio_acc_rv)						\
	    return;							\
    } while(0)

static void
add_default_gensio_accepters(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    reg_gensio_acc_lock = o->alloc_lock(o);
    if (!reg_gensio_acc_lock) {
	reg_gensio_acc_rv = GE_NOMEM;
	return;
    }
    REG_GENSIO_ACC(o, "tcp", str_to_tcp_gensio_accepter);
    REG_GENSIO_ACC(o, "udp", str_to_udp_gensio_accepter);
    REG_GENSIO_ACC(o, "sctp", str_to_sctp_gensio_accepter);
#if HAVE_STDIO
    REG_GENSIO_ACC(o, "stdio", str_to_stdio_gensio_accepter);
#endif
#if HAVE_UNIX
    REG_GENSIO_ACC(o, "unix", str_to_unix_gensio_accepter);
#endif
    REG_FILT_GENSIO_ACC(o, "ssl", str_to_ssl_gensio_accepter,
			ssl_gensio_accepter_alloc);
    REG_FILT_GENSIO_ACC(o, "mux", str_to_mux_gensio_accepter,
			mux_gensio_accepter_alloc);
    REG_FILT_GENSIO_ACC(o, "certauth",
			str_to_certauth_gensio_accepter,
			certauth_gensio_accepter_alloc);
    REG_FILT_GENSIO_ACC(o, "telnet", str_to_telnet_gensio_accepter,
			telnet_gensio_accepter_alloc);
    REG_GENSIO_ACC(o, "dummy", str_to_dummy_gensio_accepter);
    REG_FILT_GENSIO_ACC(o, "msgdelim", str_to_msgdelim_gensio_accepter,
			msgdelim_gensio_accepter_alloc);
    REG_FILT_GENSIO_ACC(o, "relpkt", str_to_relpkt_gensio_accepter,
			relpkt_gensio_accepter_alloc);
    REG_FILT_GENSIO_ACC(o, "trace", str_to_trace_gensio_accepter,
			trace_gensio_accepter_alloc);
}

int
register_filter_gensio_accepter(struct gensio_os_funcs *o,
				const char *name,
				str_to_gensio_acc_handler handler,
				str_to_gensio_acc_child_handler chandler)
{
    struct registered_gensio_accepter *n;

    o->call_once(o, &gensio_acc_str_initialized,
		 add_default_gensio_accepters, o);
    if (reg_gensio_acc_rv)
	return reg_gensio_acc_rv;

    n = o->zalloc(o, sizeof(*n));
    if (!n)
	return GE_NOMEM;

    n->name = name;
    n->handler = handler;
    n->chandler = chandler;
    o->lock(reg_gensio_acc_lock);
    n->next = reg_gensio_accs;
    reg_gensio_accs = n;
    o->unlock(reg_gensio_acc_lock);
    return 0;
}

int
register_gensio_accepter(struct gensio_os_funcs *o,
			 const char *name,
			 str_to_gensio_acc_handler handler)
{
    return register_filter_gensio_accepter(o, name, handler, NULL);
}

int
str_to_gensio_accepter(const char *str,
		       struct gensio_os_funcs *o,
		       gensio_accepter_event cb, void *user_data,
		       struct gensio_accepter **accepter)
{
    int err;
    struct gensio_addr *ai = NULL;
    int protocol = 0;
    const char **args = NULL;
    struct registered_gensio_accepter *r;
    size_t len;

    o->call_once(o, &gensio_acc_str_initialized,
		 add_default_gensio_accepters, o);
    if (reg_gensio_acc_rv)
	return reg_gensio_acc_rv;

    while (isspace(*str))
	str++;
    for (r = reg_gensio_accs; r; r = r->next) {
	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != ',' && str[len] != '(' && str[len]))
	    continue;

	str += len;
	err = gensio_scan_args(o, &str, NULL, &args);
	if (!err)
	    err = r->handler(str, args, o, cb, user_data, accepter);
	if (args)
	    gensio_argv_free(o, args);
	return err;
    }

    if (strisallzero(str)) {
#if HAVE_STDIO
	err = stdio_gensio_accepter_alloc(NULL, o, cb, user_data,
					  accepter);
#else
	err = GE_NOTSUP;
#endif
    } else {
	err = gensio_scan_network_port(o, str, true, &ai, &protocol,
				       NULL, NULL, &args);
	if (!err) {
	    if (protocol == GENSIO_NET_PROTOCOL_UDP) {
		err = udp_gensio_accepter_alloc(ai, args, o, cb,
						user_data, accepter);
	    } else if (protocol == GENSIO_NET_PROTOCOL_TCP) {
		err = tcp_gensio_accepter_alloc(ai, args, o, cb,
						user_data, accepter);
	    } else if (protocol == GENSIO_NET_PROTOCOL_SCTP) {
		err = sctp_gensio_accepter_alloc(ai, args, o, cb,
						 user_data, accepter);
	    } else {
		err = GE_INVAL;
	    }

	    gensio_addr_free(ai);
	}
    }

    if (args)
	gensio_argv_free(o, args);

    return err;
}

int
str_to_gensio_accepter_child(struct gensio_accepter *child,
			     const char *str,
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb, void *user_data,
			     struct gensio_accepter **accepter)
{
    int err = GE_INVAL;
    struct registered_gensio_accepter *r;
    size_t len;

    o->call_once(o, &gensio_acc_str_initialized,
		 add_default_gensio_accepters, o);
    if (reg_gensio_acc_rv)
	return reg_gensio_acc_rv;

    while (isspace(*str))
	str++;
    for (r = reg_gensio_accs; r; r = r->next) {
	const char **args = NULL;

	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != ',' && str[len] != '(' && str[len]))
	    continue;

	str += len;
	err = gensio_scan_args(o, &str, NULL, &args);
	if (!err)
	    err = r->chandler(child, args, o, cb, user_data, accepter);
	if (args)
	    gensio_argv_free(o, args);
	return err;
    }

    return err;
}

struct registered_gensio {
    const char *name;
    str_to_gensio_handler handler;
    str_to_gensio_child_handler chandler;
    struct registered_gensio *next;
};

static struct registered_gensio *reg_gensios;
static struct gensio_lock *reg_gensio_lock;


static struct gensio_once gensio_str_initialized;
static int reg_gensio_rv;

#define REG_GENSIO(o, str, con) \
    do {								\
	reg_gensio_rv = register_gensio(o, str, con);			\
	if (reg_gensio_rv)						\
	    return;							\
    } while(0)

#define REG_FILT_GENSIO(o, str, con, aloc)				\
    do {								\
	reg_gensio_rv = register_filter_gensio(o, str, con, aloc);	\
	if (reg_gensio_rv)						\
	    return;							\
    } while(0)

static void
add_default_gensios(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    reg_gensio_lock = o->alloc_lock(o);
    if (!reg_gensio_lock) {
	reg_gensio_rv = GE_NOMEM;
	return;
    }
    REG_GENSIO(o, "tcp", str_to_tcp_gensio);
    REG_GENSIO(o, "udp", str_to_udp_gensio);
    REG_GENSIO(o, "sctp", str_to_sctp_gensio);
#if HAVE_UNIX
    REG_GENSIO(o, "unix", str_to_unix_gensio);
#endif
#if HAVE_STDIO
    REG_GENSIO(o, "stdio", str_to_stdio_gensio);
#endif
#if HAVE_PTY
    REG_GENSIO(o, "pty", str_to_pty_gensio);
#endif
    REG_FILT_GENSIO(o, "ssl", str_to_ssl_gensio, ssl_gensio_alloc);
    REG_FILT_GENSIO(o, "mux", str_to_mux_gensio, mux_gensio_alloc);
    REG_FILT_GENSIO(o, "certauth", str_to_certauth_gensio,
		    certauth_gensio_alloc);
    REG_FILT_GENSIO(o, "telnet", str_to_telnet_gensio, telnet_gensio_alloc);
#if HAVE_SERIALDEV
    REG_GENSIO(o, "serialdev", str_to_serialdev_gensio);
#endif
    REG_GENSIO(o, "echo", str_to_echo_gensio);
    REG_GENSIO(o, "file", str_to_file_gensio);
    REG_GENSIO(o, "ipmisol", str_to_ipmisol_gensio);
    REG_FILT_GENSIO(o, "msgdelim", str_to_msgdelim_gensio,
		    msgdelim_gensio_alloc);
    REG_FILT_GENSIO(o, "relpkt", str_to_relpkt_gensio,
		    relpkt_gensio_alloc);
    REG_FILT_GENSIO(o, "trace", str_to_trace_gensio,
		    trace_gensio_alloc);
}

int
register_filter_gensio(struct gensio_os_funcs *o,
		       const char *name, str_to_gensio_handler handler,
		       str_to_gensio_child_handler chandler)
{
    struct registered_gensio *n;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);
    if (reg_gensio_rv)
	return reg_gensio_rv;

    n = o->zalloc(o, sizeof(*n));
    if (!n)
	return GE_NOMEM;

    n->name = name;
    n->handler = handler;
    n->chandler = chandler;
    o->lock(reg_gensio_lock);
    n->next = reg_gensios;
    reg_gensios = n;
    o->unlock(reg_gensio_lock);
    return 0;
}

int
register_gensio(struct gensio_os_funcs *o,
		const char *name, str_to_gensio_handler handler)
{
    return register_filter_gensio(o, name, handler, NULL);
}

int
str_to_gensio(const char *str,
	      struct gensio_os_funcs *o,
	      gensio_event cb, void *user_data,
	      struct gensio **gensio)
{
    int err = 0;
    struct gensio_addr *ai = NULL;
    bool is_port_set;
    int protocol = 0;
    const char **args = NULL;
    struct registered_gensio *r;
    size_t len;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);
    if (reg_gensio_rv)
	return reg_gensio_rv;

    while (isspace(*str))
	str++;
    for (r = reg_gensios; r; r = r->next) {
	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != ',' && str[len] != '(' && str[len]))
	    continue;

	str += len;
	err = gensio_scan_args(o, &str, NULL, &args);
	if (!err)
	    err = r->handler(str, args, o, cb, user_data, gensio);
	if (args)
	    gensio_argv_free(o, args);
	return err;
    }

#if HAVE_SERIALDEV
    if (*str == '/') {
	err = str_to_serialdev_gensio(str, NULL, o, cb, user_data,
				      gensio);
	goto out;
    }
#endif

    err = gensio_scan_network_port(o, str, false, &ai, &protocol,
				   &is_port_set, NULL, &args);
    if (!err) {
	if (!is_port_set) {
	    err = GE_INVAL;
	} else if (protocol == GENSIO_NET_PROTOCOL_UDP) {
	    err = udp_gensio_alloc(ai, args, o, cb, user_data, gensio);
	} else if (protocol == GENSIO_NET_PROTOCOL_TCP) {
	    err = tcp_gensio_alloc(ai, args, o, cb, user_data, gensio);
	} else if (protocol == GENSIO_NET_PROTOCOL_SCTP) {
	    err = sctp_gensio_alloc(ai, args, o, cb, user_data, gensio);
	} else {
	    err = GE_INVAL;
	}

	gensio_addr_free(ai);
    }

 out:
    if (args)
	gensio_argv_free(o, args);

    return err;
}

int
str_to_gensio_child(struct gensio *child,
		    const char *str,
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **gensio)
{
    int err = 0;
    const char **args = NULL;
    struct registered_gensio *r;
    size_t len;

    while (isspace(*str))
	str++;
    for (r = reg_gensios; r; r = r->next) {
	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != '(' && str[len]))
	    continue;

	if (!r->chandler)
	    return GE_INVAL;

	str += len;
	err = gensio_scan_args(o, &str, NULL, &args);
	if (!err)
	    err = r->chandler(child, args, o, cb, user_data, gensio);
	if (args)
	    gensio_argv_free(o, args);
	return err;
    }

    return GE_INVAL;
}

int
gensio_check_keyvalue(const char *str, const char *key, const char **value)
{
    size_t keylen = strlen(key);

    if (strncasecmp(str, key, keylen) != 0)
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

    if (strcasecmp(str, key) == 0) {
	*rvalue = true;
	return 1;
    }

    rv = gensio_check_keyvalue(str, key, &sval);
    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    if (strcmp(sval, "true") == 0 || strcmp(sval, "1") == 0 ||
		strcmp(sval, "yes") == 0 || strcmp(sval, "on") == 0)
	*rvalue = true;
    else if (strcmp(sval, "false") == 0 || strcmp(sval, "0") == 0 ||
		strcmp(sval, "no") == 0 || strcmp(sval, "off") == 0)
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
gensio_check_keyenum(const char *str, const char *key,
		     struct gensio_enum_val *enums, int *rval)
{
    const char *sval;
    int rv;
    unsigned int i;

    rv = gensio_check_keyvalue(str, key, &sval);
    if (!rv)
	return 0;

    for (i = 0; enums[i].name; i++) {
	if (strcasecmp(sval, enums[i].name) == 0) {
	    *rval = enums[i].val;
	    return 1;
	}
    }

    return -1;
}

int
gensio_check_keyaddrs(struct gensio_os_funcs *o,
		      const char *str, const char *key, int iprotocol,
		      bool listen, bool require_port,
		      struct gensio_addr **rai)
{
    const char *sval;
    int rv;
    struct gensio_addr *ai;
    int protocol = iprotocol;
    bool is_port_set;

    rv = gensio_check_keyvalue(str, key, &sval);
    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    rv = gensio_scan_network_port(o, sval, listen, &ai,
				  &protocol, &is_port_set, NULL, NULL);
    if (rv)
	return -1;

    if ((require_port && !is_port_set) || protocol != iprotocol) {
	gensio_addr_free(ai);
	return -1;
    }

    if (*rai)
	gensio_addr_free(*rai);

    *rai = ai;

    return 1;
}

int
gensio_check_keyaddrs_noport(struct gensio_os_funcs *o,
			     const char *str, const char *key, int protocol,
			     struct gensio_addr **rai)
{
    const char *sval;
    int rv;
    struct gensio_addr *ai;

    rv = gensio_check_keyvalue(str, key, &sval);
    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    rv = gensio_scan_network_addr(o, sval, protocol, &ai);
    if (rv)
	return -1;

    if (*rai)
	gensio_addr_free(*rai);

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
    acc->cb(acc, acc->user_data, GENSIO_ACC_EVENT_LOG, &info);
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

struct gensio_def_val {
    char *strval;
    int intval; /* data length, not including terminating \0, when data */
};

struct gensio_class_def {
    char *class;
    struct gensio_def_val val;
    struct gensio_class_def *next;
};

struct gensio_def_entry {
    char *name;
    enum gensio_default_type type;
    int min;
    int max;
    struct gensio_def_val val;
    bool val_set;
    struct gensio_def_val def;
    const struct gensio_enum_val *enums;
    struct gensio_class_def *classvals;
    struct gensio_def_entry *next;
};

#if HAVE_OPENIPMI
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
    /* Defaults for TCP, UDP, and SCTP. */
    { "nodelay",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "laddr",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    /* sctp */
    { "instreams",	GENSIO_DEFAULT_INT,	.min = 1, .max = INT_MAX,
						.def.intval = 1 },
    { "ostreams",	GENSIO_DEFAULT_INT,	.min = 1, .max = INT_MAX,
						.def.intval = 1 },
    /* serialdev */
    { "xonxoff",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "rtscts",		GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "local",		GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "hangup_when_done", GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "custspeed",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "rs485",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    /* serialdev and SOL */
    { "speed",		GENSIO_DEFAULT_STR,	.def.strval = "9600N81" },
    { "nobreak",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
#if HAVE_OPENIPMI
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
    { "deassert-CTS-DCD-DSR-on-connect", GENSIO_DEFAULT_BOOL, .def.intval = 0 },
#endif
    /* For client/server protocols. */
    { "mode",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
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
    { "use-child-auth",	GENSIO_DEFAULT_BOOL,	.def.intval = false },
    { "enable-password",GENSIO_DEFAULT_BOOL,	.def.intval = false },
    /* For mux */
    { "max-channels",	GENSIO_DEFAULT_INT,	.min = 1, .max = INT_MAX,
						.def.intval = 1000 },
    /* For unix (accepter only) */
    { "delsock",	GENSIO_DEFAULT_BOOL,	.def.intval = false },
    { NULL }
};

static struct gensio_def_entry *defaults;
static int gensio_def_init_rv;

static void
gensio_default_init(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    deflock = o->alloc_lock(o);
    if (!deflock)
	gensio_def_init_rv = GE_NOMEM;
}

void
gensio_cleanup_mem(struct gensio_os_funcs *o)
{
    struct registered_gensio_accepter *n, *n2;
    struct registered_gensio *g, *g2;

    if (deflock)
	o->free_lock(deflock);
    deflock = NULL;

    if (reg_gensio_acc_lock)
	o->free_lock(reg_gensio_acc_lock);
    reg_gensio_acc_lock = NULL;

    n = reg_gensio_accs;
    while (n) {
	n2 = n->next;
	o->free(o, n);
	n = n2;
    }
    reg_gensio_accs = NULL;

    if (reg_gensio_lock)
	o->free_lock(reg_gensio_lock);
    reg_gensio_lock = NULL;

    g = reg_gensios;
    while (g) {
	g2 = g->next;
	o->free(o, g);
	g = g2;
    }
    reg_gensios = NULL;
}

static void
gensio_reset_default(struct gensio_os_funcs *o, struct gensio_def_entry *d)
{
    struct gensio_class_def *n, *c = d->classvals;

    for (; c; c = n) {
	n = c->next;
	o->free(o, c->class);
	if (d->type == GENSIO_DEFAULT_STR && c->val.strval)
	    o->free(o, c->val.strval);
	o->free(o, c);
    }
    d->classvals = NULL;

    if (d->type == GENSIO_DEFAULT_STR && d->val.strval) {
	o->free(o, d->val.strval);
	d->val.strval = NULL;
    }
    d->val_set = false;
}

int
gensio_reset_defaults(struct gensio_os_funcs *o)
{
    struct gensio_def_entry *d;
    unsigned int i;

    o->call_once(o, &gensio_default_initialized, gensio_default_init, o);
    if (gensio_def_init_rv)
	return gensio_def_init_rv;

    o->lock(deflock);
    for (i = 0; builtin_defaults[i].name; i++)
	gensio_reset_default(o, &builtin_defaults[i]);
    for (d = defaults; d; d = d->next)
	gensio_reset_default(o, d);
    o->unlock(deflock);
    return 0;
}

static struct gensio_def_entry *
gensio_lookup_default(const char *name, struct gensio_def_entry **prev,
		      bool *isdefault)
{
    struct gensio_def_entry *d, *p = NULL;
    unsigned int i;

    for (i = 0; builtin_defaults[i].name; i++) {
	if (strcmp(builtin_defaults[i].name, name) == 0) {
	    if (prev)
		*prev = NULL;
	    if (isdefault)
		*isdefault = true;
	    return &builtin_defaults[i];
	}
    }
    for (d = defaults; d; d = d->next) {
	if (strcmp(d->name, name) == 0) {
	    if (prev)
		*prev = p;
	    if (isdefault)
		*isdefault = false;
	    return d;
	}
	p = d;
    }
    return NULL;
}

static struct gensio_class_def *
gensio_lookup_default_class(struct gensio_def_entry *d, const char *class,
			    struct gensio_class_def **prev)
{
    struct gensio_class_def *c = d->classvals;
    struct gensio_class_def *p = NULL;

    for (; c; c = c->next) {
	if (strcmp(c->class, class) == 0) {
	    if (prev)
		*prev = p;
	    return c;
	}
	p = c;
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
    if (gensio_def_init_rv)
	return gensio_def_init_rv;

    o->lock(deflock);
    d = gensio_lookup_default(name, NULL, NULL);
    if (d) {
	err = GE_EXISTS;
	goto out_unlock;
    }

    d = o->zalloc(o, sizeof(*d));
    if (!d) {
	err = GE_NOMEM;
	goto out_unlock;
    }

    d->name = gensio_strdup(o, name);
    if (!d->name) {
	o->free(o, d);
	err = GE_NOMEM;
	goto out_unlock;
    }
    d->type = type;
    d->min = minval;
    d->max = maxval;
    d->enums = enums;
    d->def.intval = intval;
    if (strval) {
	if (type == GENSIO_DEFAULT_DATA) {
	    d->def.strval = o->zalloc(o, intval + 1);
	    if (d->def.strval) {
		memcpy(d->def.strval, strval, intval);
		d->def.strval[intval] = '\0';
	    }
	} else {
	    d->def.strval = gensio_strdup(o, strval);
	}
	if (!d->def.strval) {
	    o->free(o, d->name);
	    o->free(o, d);
	    err = GE_NOMEM;
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
    if (gensio_def_init_rv)
	return gensio_def_init_rv;

    o->lock(deflock);
    d = gensio_lookup_default(name, NULL, NULL);
    if (!d) {
	err = GE_NOTFOUND;
	goto out_unlock;
    }

    switch (d->type) {
    case GENSIO_DEFAULT_ENUM:
	if (!strval) {
	    err = GE_INVAL;
	    goto out_unlock;
	}
	for (i = 0; d->enums[i].name; i++) {
	    if (strcmp(d->enums[i].name, strval) == 0)
		break;
	}
	if (!d->enums[i].name) {
	    err = GE_INVAL;
	    goto out_unlock;
	}
	intval = d->enums[i].val;
	break;

    case GENSIO_DEFAULT_BOOL:
	if (strval) {
	    if (strcmp(strval, "true") == 0 ||
			strcmp(strval, "TRUE") == 0) {
		intval = 1;
	    } else if (strcmp(strval, "false") == 0 ||
		       strcmp(strval, "FALSE") == 0) {
		intval = 0;
	    } else {
		intval = strtoul(strval, &end, 10);
		if (end == strval || *end) {
		    err = GE_INVAL;
		    goto out_unlock;
		}
	    }
	} else {
	    intval = !!intval;
	}
	break;

    case GENSIO_DEFAULT_INT:
	if (strval) {
	    intval = strtoul(strval, &end, 10);
	    if (end == strval || *end) {
		err = GE_INVAL;
		goto out_unlock;
	    }
	    if (intval < d->min || intval > d->max) {
		err = GE_OUTOFRANGE;
		goto out_unlock;
	    }
	}
	break;

    case GENSIO_DEFAULT_STR:
	if (strval) {
	    new_strval = gensio_strdup(o, strval);
	    if (!new_strval) {
		err = GE_NOMEM;
		goto out_unlock;
	    }
	}
	break;

    case GENSIO_DEFAULT_DATA:
	if (intval < 0) {
	    err = GE_INVAL;
	    goto out_unlock;
	}
	new_strval = o->zalloc(o, intval + 1);
	if (!new_strval) {
	    err = GE_NOMEM;
	    goto out_unlock;
	}
	memcpy(new_strval, strval, intval);
	new_strval[intval] = '\0';
	break;

    default:
	err = GE_INVAL;
	goto out_unlock;
    }

    if (class) {
	struct gensio_class_def *c = gensio_lookup_default_class(d, class,
								 NULL);

	if (!c) {
	    c = o->zalloc(o, sizeof(*c));
	    if (!c) {
		err = GE_NOMEM;
		goto out_unlock;
	    }
	    c->class = gensio_strdup(o, class);
	    if (!c->class) {
		o->free(o, c);
		err = GE_NOMEM;
		goto out_unlock;
	    }
	    c->next = d->classvals;
	    d->classvals = c;
	}
	c->val.intval = intval;
	if (d->type == GENSIO_DEFAULT_STR || d->type == GENSIO_DEFAULT_DATA) {
	    if (c->val.strval)
		o->free(o, c->val.strval);
	    c->val.strval = new_strval;
	    new_strval = NULL;
	}
    } else {
	d->val.intval = intval;
	if (d->type == GENSIO_DEFAULT_STR || d->type == GENSIO_DEFAULT_DATA) {
	    if (d->val.strval)
		o->free(o, d->val.strval);
	    d->val.strval = new_strval;
	    new_strval = NULL;
	}
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
		   char **strval, int *intval)
{
    struct gensio_def_entry *d;
    struct gensio_class_def *c = NULL;
    struct gensio_def_val *val;
    int err = 0;
    char *str;

    o->call_once(o, &gensio_default_initialized, gensio_default_init, o);
    if (gensio_def_init_rv)
	return gensio_def_init_rv;

    o->lock(deflock);
    d = gensio_lookup_default(name, NULL, NULL);
    if (!d) {
	err = GE_NOTFOUND;
	goto out_unlock;
    }

    if (d->type != type &&
	    !(d->type == GENSIO_DEFAULT_ENUM && type == GENSIO_DEFAULT_INT) &&
	    !(d->type == GENSIO_DEFAULT_BOOL && type == GENSIO_DEFAULT_INT)) {
	err = GE_INVAL;
	goto out_unlock;
    }

    if (class)
	c = gensio_lookup_default_class(d, class, NULL);

    if (c)
	val = &c->val;
    else if (classonly) {
	err = GE_NOTFOUND;
	goto out_unlock;
    } else if (d->val_set)
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
	if (val->strval) {
	    str = gensio_strdup(o, val->strval);
	    if (!str) {
		err = GE_NOMEM;
		goto out_unlock;
	    }
	    *strval = str;
	} else {
	    *strval = NULL;
	}
	break;

    case GENSIO_DEFAULT_DATA:
	if (val->strval) {
	    str = o->zalloc(o, val->intval);
	    if (!str) {
		err = GE_NOMEM;
		goto out_unlock;
	    }
	    memcpy(str, val->strval, val->intval + 1); /* copy terminating \0 */
	    *strval = str;
	    *intval = val->intval;
	} else {
	    *strval = NULL;
	    *intval = 0;
	}
	break;

    default:
	abort(); /* Shouldn't happen. */
    }

 out_unlock:
    o->unlock(deflock);

    return err;
}

int
gensio_del_default(struct gensio_os_funcs *o,
		   const char *class, const char *name, bool delclasses)
{
    struct gensio_def_entry *d, *prev;
    struct gensio_class_def *c = NULL, *prevc;
    bool isdefault;
    int err = 0;

    o->call_once(o, &gensio_default_initialized, gensio_default_init, o);
    if (gensio_def_init_rv)
	return gensio_def_init_rv;

    o->lock(deflock);
    d = gensio_lookup_default(name, &prev, &isdefault);
    if (!d) {
	err = GE_NOTFOUND;
	goto out_unlock;
    }

    if (class) {
	c = gensio_lookup_default_class(d, class, &prevc);
	if (!c) {
	    err = GE_NOTFOUND;
	    goto out_unlock;
	}
	if (prevc)
	    prevc->next = c->next;
	else
	    d->classvals = c->next;
	
	if (c->val.strval)
	    o->free(o, c->val.strval);
	o->free(o, c->class);
	o->free(o, c);
	goto out_unlock;
    }

    if (isdefault) {
	err = GE_NOTSUP;
	goto out_unlock;
    }

    if (d->classvals && !delclasses) {
	err = GE_INUSE;
	goto out_unlock;
    }

    if (prev)
	prev->next = d->next;
    else
	defaults = d->next;

    while (d->classvals) {
	c = d->classvals;
	d->classvals = c->next;
	if (c->val.strval)
	    o->free(o, c->val.strval);
	o->free(o, c->class);
	o->free(o, c);
    }

    if (d->val.strval)
	o->free(o, d->val.strval);
    o->free(o, d->name);
    o->free(o, d);

 out_unlock:
    o->unlock(deflock);

    return err;
}

int
gensio_get_defaultaddr(struct gensio_os_funcs *o,
		       const char *class, const char *name, bool classonly,
		       int iprotocol, bool listen, bool require_port,
		       struct gensio_addr **rai)
{
    int err;
    int protocol = iprotocol;
    struct gensio_addr *ai;
    bool is_port_set;
    char *str;

    err = gensio_get_default(o, class, name, classonly, GENSIO_DEFAULT_STR,
			     &str, NULL);
    if (err)
	return err;

    if (!str)
	return GE_NOTSUP;

    err = gensio_scan_network_port(o, str, listen, &ai,
				   &protocol, &is_port_set, NULL, NULL);
    o->free(o, str);
    if (err)
	return err;

    if ((require_port && !is_port_set) || protocol != iprotocol) {
	gensio_addr_free(ai);
	return GE_INCONSISTENT;
    }

    if (*rai)
	gensio_addr_free(*rai);

    *rai = ai;

    return 1;
}

void
gensio_list_rm(struct gensio_list *list, struct gensio_link *link)
{
    assert(link->list == list);
    link->next->prev = link->prev;
    link->prev->next = link->next;
    link->next = NULL;
    link->prev = NULL;
    link->list = NULL;
}

void
gensio_list_add_head(struct gensio_list *list, struct gensio_link *link)
{
    assert(link->list == NULL && link->next == NULL && link->prev == NULL);
    link->next = list->link.next;
    link->prev = &list->link;
    list->link.next->prev = link;
    list->link.next = link;
    link->list = list;
}

void
gensio_list_add_tail(struct gensio_list *list, struct gensio_link *link)
{
    assert(link->list == NULL && link->next == NULL && link->prev == NULL);
    link->prev = list->link.prev;
    link->next = &list->link;
    list->link.prev->next = link;
    list->link.prev = link;
    link->list = list;
}

void
gensio_list_add_next(struct gensio_list *list, struct gensio_link *curr,
		     struct gensio_link *link)
{
    assert(link->list == NULL && link->next == NULL && link->prev == NULL);
    link->next = curr->next;
    link->prev = curr;
    curr->next->prev = link;
    curr->next = link;
    link->list = list;
}

void
gensio_list_add_prev(struct gensio_list *list, struct gensio_link *curr,
		     struct gensio_link *link)
{
    assert(link->list == NULL && link->next == NULL && link->prev == NULL);
    link->prev = curr->prev;
    link->next = curr;
    curr->prev->next = link;
    curr->prev = link;
    link->list = list;
}

void
gensio_list_init(struct gensio_list *list)
{
    list->link.next = &list->link;
    list->link.prev = &list->link;
    list->link.list = list;
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

static int
gensio_wait_no_cb(struct gensio *io, struct gensio_waiter *waiter,
		  gensio_time *timeout)
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_nocbwait wait;
    int rv = 0;

    wait.waiter = waiter;
    o->lock(io->lock);
    if (io->cb_count != 0) {
	wait.queued = true;
	gensio_list_add_tail(&io->waiters, &wait.link);
	o->unlock(io->lock);
	rv = o->wait(waiter, 1, timeout);
	o->lock(io->lock);
	if (wait.queued) {
	    rv = GE_TIMEDOUT;
	    gensio_list_rm(&io->waiters, &wait.link);
	}
    }
    o->unlock(io->lock);
    return rv;
}

struct gensio_sync_op {
    bool queued;
    unsigned char *buf;
    gensiods len;
    int err;
    struct gensio_waiter *waiter;
    struct gensio_link link;
};

struct gensio_sync_io {
    gensio_event old_cb;

    struct gensio_list readops;
    struct gensio_list writeops;
    int err;

    struct gensio_lock *lock;
    struct gensio_waiter *close_waiter;
};

static void
gensio_sync_flush_waiters(struct gensio_sync_io *sync_io,
			  struct gensio_os_funcs *o)
{
    struct gensio_link *l, *l2;

    gensio_list_for_each_safe(&sync_io->readops, l, l2) {
	struct gensio_sync_op *op = gensio_container_of(l,
							struct gensio_sync_op,
							link);

	op->err = sync_io->err;
	op->queued = false;
	o->wake(op->waiter);
	gensio_list_rm(&sync_io->readops, l);
    }

    gensio_list_for_each_safe(&sync_io->writeops, l, l2) {
	struct gensio_sync_op *op = gensio_container_of(l,
							struct gensio_sync_op,
							link);

	op->err = sync_io->err;
	op->queued = false;
	o->wake(op->waiter);
	gensio_list_rm(&sync_io->writeops, l);
    }
}

static int
gensio_syncio_event(struct gensio *io, void *user_data,
		    int event, int err,
		    unsigned char *buf, gensiods *buflen,
		    const char *const *auxdata)
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_sync_io *sync_io = io->sync_io;
    gensiods done_len;

    switch (event) {
    case GENSIO_EVENT_READ:
	o->lock(sync_io->lock);
	if (err) {
	    if (!sync_io->err)
		sync_io->err = err;
	    gensio_sync_flush_waiters(sync_io, o);
	    goto read_unlock;
	}
	if (gensio_list_empty(&sync_io->readops)) {
	    *buflen = 0;
	    gensio_set_read_callback_enable(io, false);
	    goto read_unlock;
	}
	done_len = *buflen;
	while (*buflen && !gensio_list_empty(&sync_io->readops)) {
	    struct gensio_link *l = gensio_list_first(&sync_io->readops);
	    struct gensio_sync_op *op = gensio_container_of(l,
							struct gensio_sync_op,
							link);
	    gensiods len = done_len;

	    if (len > op->len)
		len = op->len;
	    memcpy(op->buf, buf, len);
	    op->len = len;
	    gensio_list_rm(&sync_io->readops, l);
	    op->queued = false;
	    o->wake(op->waiter);
	    done_len -= len;
	}
	*buflen -= done_len;
	if (done_len > 0)
	    gensio_set_read_callback_enable(io, false);
    read_unlock:
	o->unlock(sync_io->lock);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	o->lock(sync_io->lock);
	if (gensio_list_empty(&sync_io->writeops)) {
	    gensio_set_write_callback_enable(io, false);
	    goto write_unlock;
	}
	while (!gensio_list_empty(&sync_io->writeops)) {
	    struct gensio_link *l = gensio_list_first(&sync_io->writeops);
	    struct gensio_sync_op *op = gensio_container_of(l,
							struct gensio_sync_op,
							link);
	    gensiods len = 0;

	    err = gensio_write(io, &len, op->buf, op->len, NULL);
	    if (err) {
		if (!sync_io->err)
		    sync_io->err = err;
		gensio_sync_flush_waiters(sync_io, o);
	    } else {
		op->buf += len;
		op->len -= len;
		if (op->len == 0) {
		    gensio_list_rm(&sync_io->writeops, l);
		    op->queued = false;
		    o->wake(op->waiter);
		} else {
		    break;
		}
	    }
	}
	if (gensio_list_empty(&sync_io->writeops))
	    gensio_set_write_callback_enable(io, false);
    write_unlock:
	o->unlock(sync_io->lock);
	return 0;

    default:
	if (sync_io->old_cb)
	    return sync_io->old_cb(io, io->user_data,
				   event, err, buf, buflen, auxdata);
	return GE_NOTSUP;
    }
}

int
gensio_set_sync(struct gensio *io)
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_sync_io *sync_io = o->zalloc(o, sizeof(*sync_io));

    if (!sync_io)
	return GE_NOMEM;

    sync_io->lock = o->alloc_lock(o);
    if (!sync_io->lock) {
	o->free(o, sync_io);
	return GE_NOMEM;
    }

    sync_io->close_waiter = o->alloc_waiter(o);
    if (!sync_io->close_waiter) {
	o->free_lock(sync_io->lock);
	o->free(o, sync_io);
	return GE_NOMEM;
    }

    gensio_list_init(&sync_io->readops);
    gensio_list_init(&sync_io->writeops);

    gensio_set_read_callback_enable(io, false);
    gensio_set_write_callback_enable(io, false);
    gensio_wait_no_cb(io, sync_io->close_waiter, NULL);

    io->sync_io = sync_io;
    sync_io->old_cb = io->cb;
    io->cb = gensio_syncio_event;
    return 0;
}

int
gensio_clear_sync(struct gensio *io)
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_sync_io *sync_io = io->sync_io;

    if (!sync_io)
	return GE_NOTREADY;

    gensio_set_read_callback_enable(io, false);
    gensio_set_write_callback_enable(io, false);
    gensio_wait_no_cb(io, sync_io->close_waiter, NULL);

    io->cb = sync_io->old_cb;

    o->free_waiter(sync_io->close_waiter);
    o->free_lock(sync_io->lock);
    o->free(o, sync_io);
    io->sync_io = NULL;

    return 0;
}

static int
i_gensio_read_s(struct gensio *io, gensiods *count, void *data, gensiods datalen,
		gensio_time *timeout, bool return_on_intr)
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_sync_io *sync_io = io->sync_io;
    struct gensio_sync_op op;
    int rv = 0;

    if (!sync_io)
	return GE_NOTREADY;

    if (datalen == 0) {
	if (count)
	    *count = 0;
	return 0;
    }

    op.queued = true;
    op.buf = data;
    op.len = datalen;
    op.err = 0;
    op.waiter = o->alloc_waiter(o);
    if (!op.waiter)
	return GE_NOMEM;
    o->lock(sync_io->lock);
    if (sync_io->err) {
	rv = sync_io->err;
	goto out_unlock;
    }
    gensio_set_read_callback_enable(io, true);
    memset(&op.link, 0, sizeof(op.link));
    gensio_list_add_tail(&sync_io->readops, &op.link);

    o->unlock(sync_io->lock);
 retry:
    rv = o->wait_intr(op.waiter, 1, timeout);
    if (!return_on_intr && rv == GE_INTERRUPTED)
	goto retry;
    if (rv == GE_TIMEDOUT)
	rv = 0;
    o->lock(sync_io->lock);
    if (op.err) {
	rv = op.err;
    } else if (op.queued) {
	if (count)
	    *count = 0;
	gensio_list_rm(&sync_io->readops, &op.link);
    } else if (count) {
	*count = op.len;
    }
    if (gensio_list_empty(&sync_io->readops))
	gensio_set_read_callback_enable(io, false);
 out_unlock:
    o->unlock(sync_io->lock);
    o->free_waiter(op.waiter);

    return rv;
}

int
gensio_read_s(struct gensio *io, gensiods *count, void *data, gensiods datalen,
	      gensio_time *timeout)
{
    return i_gensio_read_s(io, count, data, datalen, timeout, false);
}

int
gensio_read_s_intr(struct gensio *io, gensiods *count, void *data,
		   gensiods datalen, gensio_time *timeout)
{
    return i_gensio_read_s(io, count, data, datalen, timeout, true);
}

static int
i_gensio_write_s(struct gensio *io, gensiods *count,
		 const void *data, gensiods datalen,
		 gensio_time *timeout, bool return_on_intr)
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_sync_io *sync_io = io->sync_io;
    struct gensio_sync_op op;
    int rv = 0;
    gensiods origlen;

    if (!sync_io)
	return GE_NOTREADY;

    if (datalen == 0) {
	if (count)
	    *count = 0;
	return 0;
    }

    origlen = datalen;
    op.queued = true;
    op.buf = (void *) data;
    op.len = datalen;
    op.err = 0;
    op.waiter = o->alloc_waiter(o);
    if (!op.waiter)
	return GE_NOMEM;
    o->lock(sync_io->lock);
    if (sync_io->err) {
	rv = sync_io->err;
	goto out_unlock;
    }
    gensio_set_write_callback_enable(io, true);
    memset(&op.link, 0, sizeof(op.link));
    gensio_list_add_tail(&sync_io->writeops, &op.link);

    o->unlock(sync_io->lock);
 retry:
    rv = o->wait_intr(op.waiter, 1, timeout);
    if (!return_on_intr && rv == GE_INTERRUPTED)
	goto retry;
    if (rv == GE_TIMEDOUT)
	rv = 0;
    o->lock(sync_io->lock);
    if (op.queued)
	gensio_list_rm(&sync_io->writeops, &op.link);
    if (op.err)
	rv = op.err;
    else if (count)
	*count = origlen - op.len;
    if (gensio_list_empty(&sync_io->writeops))
	gensio_set_write_callback_enable(io, false);
 out_unlock:
    o->unlock(sync_io->lock);
    o->free_waiter(op.waiter);

    return rv;
}

int
gensio_write_s(struct gensio *io, gensiods *count,
	       const void *data, gensiods datalen,
	       gensio_time *timeout)
{
    return i_gensio_write_s(io, count, data, datalen, timeout, false);
}

int
gensio_write_s_intr(struct gensio *io, gensiods *count,
		    const void *data, gensiods datalen,
		    gensio_time *timeout)
{
    return i_gensio_write_s(io, count, data, datalen, timeout, true);
}

int
gensio_acc_set_sync(struct gensio_accepter *acc)
{
    if (acc->enabled)
	return GE_NOTREADY;
    acc->sync = true;
    return 0;
}

static int
i_gensio_acc_accept_s(struct gensio_accepter *acc, gensio_time *timeout,
		      struct gensio **new_io, bool return_on_intr)
{
    struct gensio_os_funcs *o = acc->o;
    struct gensio_waiting_accept wa;
    struct gensio_link *l;
    int rv;

    memset(&wa, 0, sizeof(wa));
    wa.waiter = o->alloc_waiter(o);
    if (!wa.waiter)
	return GE_NOMEM;

    wa.queued = true;
    o->lock(acc->lock);
    if (!gensio_list_empty(&acc->waiting_ios))
	goto got_one;
    gensio_list_add_tail(&acc->waiting_accepts, &wa.link);
    o->unlock(acc->lock);
 retry:
    rv = o->wait_intr(wa.waiter, 1, timeout);
    if (!return_on_intr && rv == GE_INTERRUPTED)
	goto retry;
    if (rv == GE_TIMEDOUT)
	rv = 0;
    o->lock(acc->lock);
    if (wa.queued) {
	rv = GE_TIMEDOUT;
	gensio_list_rm(&acc->waiting_accepts, &wa.link);
    } else if (gensio_list_empty(&acc->waiting_ios)) {
	rv = GE_LOCALCLOSED;
    } else {
    got_one:
	rv = 0;
	l = gensio_list_first(&acc->waiting_ios);
	gensio_list_rm(&acc->waiting_ios, l);
	*new_io = gensio_container_of(l, struct gensio, link);
    }
    o->unlock(acc->lock);

    o->free_waiter(wa.waiter);

    return rv;
}

int
gensio_acc_accept_s(struct gensio_accepter *acc, gensio_time *timeout,
		    struct gensio **new_io)
{
    return i_gensio_acc_accept_s(acc, timeout, new_io, false);
}

int
gensio_acc_accept_s_intr(struct gensio_accepter *acc, gensio_time *timeout,
			 struct gensio **new_io)
{
    return i_gensio_acc_accept_s(acc, timeout, new_io, true);
}

bool
gensio_str_in_auxdata(const char *const *auxdata, const char *str)
{
    unsigned int i;

    if (!auxdata)
	return false;
    for (i = 0; auxdata[i]; i++) {
	if (strcmp(auxdata[i], str) == 0)
	    return true;
    }
    return false;
}

uint32_t
gensio_buf_to_u32(unsigned char *data)
{
    return (data[0] << 24 |
	    data[1] << 16 |
	    data[2] << 8 |
	    data[3]);
}

void
gensio_u32_to_buf(unsigned char *data, uint32_t v)
{
    data[0] = v >> 24;
    data[1] = v >> 16;
    data[2] = v >> 8;
    data[3] = v;
}

uint16_t
gensio_buf_to_u16(unsigned char *data)
{
    return (data[0] << 8 | data[1]);
}

void
gensio_u16_to_buf(unsigned char *data, uint16_t v)
{
    data[0] = v >> 8;
    data[1] = v;
}

int
gensio_pos_snprintf(char *buf, gensiods len, gensiods *pos, char *format, ...)
{
    va_list ap;
    int rv;
    gensiods size = len;

    if (*pos > len) {
	/*
	 * If we are past the end of buffer, go to the end and don't
	 * output anything, just get the return from vsnprintf().
	 */
	size = 0;
	buf += len;
    } else {
	size = len - *pos;
	buf += *pos;
    }

    va_start(ap, format);
    rv = vsnprintf(buf, size, format, ap);
    va_end(ap);
    *pos += rv;
    return rv;
}

int
gensio_quote_str(char *buf, gensiods len, gensiods *pos, const char *arg)
{
    int olen = 0;

    olen = gensio_pos_snprintf(buf, len, pos, "\"");
    while (*arg) {
	if (*arg == '"')
	    olen += gensio_pos_snprintf(buf, len, pos, "\\\"");
	else if (*arg == '\\')
	    olen += gensio_pos_snprintf(buf, len, pos, "\\\\");
	else
	    olen += gensio_pos_snprintf(buf, len, pos, "%c", *arg);
	arg++;
    }
    olen += gensio_pos_snprintf(buf, len, pos, "\"");

    if (*pos < len)
	buf[*pos] = '\0';

    return olen;
}

int
gensio_argv_snprintf(char *buf, gensiods len, gensiods *pos, const char **argv)
{
    int olen = 0;
    bool first = true;

    while (argv && *argv) {
	if (!first) {
	    olen += gensio_pos_snprintf(buf, len, pos, " ");
	} else {
	    first = false;
	}

	olen += gensio_quote_str(buf, len, pos, *argv);
	argv++;
    }

    if (*pos < len)
	buf[*pos] = '\0';

    return olen;
}

char *
gensio_alloc_vsprintf(struct gensio_os_funcs *o, const char *fmt, va_list va)
{
    va_list va2;
    size_t len;
    char c[1], *str;

    va_copy(va2, va);
    len = vsnprintf(c, 0, fmt, va) + 1;
    str = o->zalloc(o, len);
    if (str)
	vsnprintf(str, len, fmt, va2);
    va_end(va2);

    return str;
}

char *
gensio_alloc_sprintf(struct gensio_os_funcs *o, const char *fmt, ...)
{
    va_list va;
    char *s;

    va_start(va, fmt);
    s = gensio_alloc_vsprintf(o, fmt, va);
    va_end(va);

    return s;
}

static const char *gensio_errs[] = {
    /*   0 */    "No error",
    /*   1 */    "Out of memory",
    /*   2 */    "Operation not supported",
    /*   3 */    "Invalid data to parameter",
    /*   4 */    "Value or file not found",
    /*   5 */    "Value already exists",
    /*   6 */    "Value out of range",
    /*   7 */    "Parameters inconsistent in call",
    /*   8 */    "No data was available for the function",
    /*   9 */	 "OS error, see logs",
    /*  10 */    "Object was already in use",
    /*  11 */    "Operation is in progress",
    /*  12 */    "Object was not ready for operation",
    /*  13 */    "Value was too large for data",
    /*  14 */    "Operation timed out",
    /*  15 */    "Retry operation later",
    /*  16 */    "Invalid error number 1",
    /*  17 */    "Unable to find the given key",
    /*  18 */    "Key was revoked",
    /*  19 */    "Key was expired",
    /*  20 */    "Key is not valid",
    /*  21 */    "Certificate not provided",
    /*  22 */    "Certificate is not valid",
    /*  23 */    "Protocol error",
    /*  24 */    "Communication error",
    /*  25 */    "Internal I/O error",
    /*  26 */    "Remote end closed connection",
    /*  27 */    "Host could not be reached",
    /*  28 */    "Connection refused",
    /*  29 */    "Data was missing",
    /*  30 */    "Unable to find given certificate",
    /*  31 */    "Authentication tokens rejected",
    /*  32 */    "Address already in use",
    /*  33 */    "Operation was interrupted by a signal",
    /*  34 */    "Operation on shutdown fd",
    /*  35 */    "Local end closed connection",
    /*  36 */    "Permission denied"
};
const unsigned int errno_len = sizeof(gensio_errs) / sizeof(char *);

const char *
gensio_err_to_str(int err)
{
    if (err < 0 || err >= errno_len)
	return "Unknown error";
    return gensio_errs[err];
}
