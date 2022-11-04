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
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_addr.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_list.h>
#include <gensio/gensio_time.h>
#include <gensio/gensio_osops.h>

#include "gensio_net.h"

static void check_flush_sync_io(struct gensio *io);

struct gensio_classobj {
    const char *name;
    void *classdata;
    struct gensio_classops *ops;
    struct gensio_classobj *next;
};

static int
gen_addclass(struct gensio_os_funcs *o, struct gensio_classobj **classes,
	     const char *name, struct gensio_classops *ops, void *classdata)
{
    struct gensio_classobj *c;

    c = o->zalloc(o, sizeof(*c));
    if (!c)
	return GE_NOMEM;
    c->name = name;
    c->ops = ops;
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

struct gensio {
    struct gensio_os_funcs *o;
    void *user_data;
    gensio_event cb;
    unsigned int cb_count;
    struct gensio_list waiters;
    unsigned int refcount;
    struct gensio_lock *lock;

    struct gensio_classobj *classes;

    gensio_func func;
    void *gensio_data;

    struct gensio_frdata *frdata;

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

static struct gensio_os_funcs *o_base;
static struct gensio_once gensio_base_initialized;
static struct gensio_lock *gensio_base_lock;
static int gensio_base_init_rv;
static gensiods num_alloced_gensios;

gensiods
gensio_num_alloced(void)
{
    gensiods rv;

    if (!o_base)
	return 0;

    o_base->lock(gensio_base_lock);
    rv = num_alloced_gensios;
    o_base->unlock(gensio_base_lock);
    return rv;
}

static void
gensio_base_init(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    gensio_base_lock = o->alloc_lock(o);
    if (!gensio_base_lock)
	gensio_base_init_rv = GE_NOMEM;
    else
	o_base = o;
}

struct gensio *
gensio_data_alloc(struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  gensio_func func, struct gensio *child,
		  const char *typename, void *gensio_data)
{
    struct gensio *io;

    o->call_once(o, &gensio_base_initialized, gensio_base_init, o);
    if (gensio_base_init_rv)
	return NULL;

    io = o->zalloc(o, sizeof(*io));
    if (!io)
	return NULL;
    io->refcount = 1;

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

    if (child) {
	struct gensio_classobj *c = child->classes;

	while (c) {
	    if (c->ops && c->ops->propagate_to_parent) {
		int rv = c->ops->propagate_to_parent(io, child, c->classdata);
		if (rv) {
		    gensio_data_free(io);
		    return NULL;
		}
	    }
	    c = c->next;
	}
    }

    o_base->lock(gensio_base_lock);
    num_alloced_gensios++;
    o_base->unlock(gensio_base_lock);

    return io;
}

void
gensio_data_free(struct gensio *io)
{
    assert(gensio_list_empty(&io->waiters));

    gensio_clear_sync(io);

    if (io->frdata && io->frdata->freed)
	io->frdata->freed(io, io->frdata);

    while (io->classes) {
	struct gensio_classobj *c = io->classes;

	if (c->ops && c->ops->cleanup)
	    c->ops->cleanup(io, c->classdata);
	io->classes = c->next;
	io->o->free(io->o, c);
    }
    io->o->free_lock(io->lock);
    io->o->free(io->o, io);

    o_base->lock(gensio_base_lock);
    num_alloced_gensios--;
    o_base->unlock(gensio_base_lock);
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
gensio_addclass(struct gensio *io, const char *name, int classops_ver,
		struct gensio_classops *ops, void *classdata)
{
    return gen_addclass(io->o, &io->classes, name, ops, classdata);
}

void *
gensio_getclass(struct gensio *io, const char *name)
{
    struct gensio *c = io;
    void *rv = NULL;

    while (c) {
	rv = gen_getclass(c->classes, name);
	if (rv)
	    return rv;
	c = c->child;
    }

    return rv;
}

struct gensio_acc_classobj {
    const char *name;
    void *classdata;
    struct gensio_acc_classops *ops;
    struct gensio_acc_classobj *next;
};

static int
gen_acc_addclass(struct gensio_os_funcs *o,
		 struct gensio_acc_classobj **classes,
		 const char *name, struct gensio_acc_classops *ops,
		 void *classdata)
{
    struct gensio_acc_classobj *c;

    c = o->zalloc(o, sizeof(*c));
    if (!c)
	return GE_NOMEM;
    c->name = name;
    c->ops = ops;
    c->classdata = classdata;
    c->next = *classes;
    *classes = c;
    return 0;
}

static void *
gen_acc_getclass(struct gensio_acc_classobj *classes, const char *name)
{
    struct gensio_acc_classobj *c;

    for (c = classes; c; c = c->next) {
	if (strcmp(c->name, name) == 0)
	    return c->classdata;
    }
    return NULL;
}

struct gensio_accepter {
    struct gensio_os_funcs *o;

    void *user_data;
    gensio_accepter_event cb;
    struct gensio_lock *lock;

    struct gensio_acc_classobj *classes;

    const struct gensio_accepter_functions *funcs;
    gensio_acc_func func;
    void *gensio_acc_data;

    struct gensio_acc_frdata *frdata;

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

    if (child) {
	struct gensio_acc_classobj *c = child->classes;

	while (c) {
	    if (c->ops && c->ops->propagate_to_parent) {
		int rv = c->ops->propagate_to_parent(acc, child, c->classdata);
		if (rv) {
		    gensio_acc_data_free(acc);
		    return NULL;
		}
	    }
	    c = c->next;
	}
    }

    return acc;
}

void
gensio_acc_data_free(struct gensio_accepter *acc)
{
    if (acc->frdata && acc->frdata->freed)
	acc->frdata->freed(acc, acc->frdata);

    while (acc->classes) {
	struct gensio_acc_classobj *c = acc->classes;

	if (c->ops && c->ops->cleanup)
	    c->ops->cleanup(acc, c->classdata);
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
		    const char *name, int classops_ver,
		    struct gensio_acc_classops *ops,
		    void *classdata)
{
    return gen_acc_addclass(acc->o, &acc->classes, name, ops, classdata);
}

void *
gensio_acc_getclass(struct gensio_accepter *acc, const char *name)
{
    return gen_acc_getclass(acc->classes, name);
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

void
gensio_acc_set_frdata(struct gensio_accepter *acc,
		      struct gensio_acc_frdata *frdata)
{
    acc->frdata = frdata;
}

struct gensio_acc_frdata *
gensio_acc_get_frdata(struct gensio_accepter *acc)
{
    return acc->frdata;
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
gensio_call_func(struct gensio *io, int func, gensiods *count,
		 const void *cbuf, gensiods buflen, void *buf,
		 const char *const *auxdata)
{
    return io->func(io, func, count, cbuf, buflen, buf, auxdata);
}

int
gensio_write(struct gensio *io, gensiods *count,
	     const void *buf, gensiods buflen,
	     const char *const *auxdata)
{
    struct gensio_sg sg;

    if (buflen == 0) {
	if (count)
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
	if (count)
	    *count = 0;
	return 0;
    }
    return io->func(io, GENSIO_FUNC_WRITE_SG, count, sg, sglen, NULL, auxdata);
}

int
gensio_raddr_to_str(struct gensio *io, gensiods *pos,
		    char *buf, gensiods buflen)
{
    gensiods dummypos = 0, curlen;
    char *data;
    int rv;

    if (!pos)
	pos = &dummypos;

    if (buflen > *pos) {
	curlen = buflen - *pos;
	data = buf + *pos;
    } else {
	curlen = 0;
	data = buf;
    }
    rv = gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_GET,
			GENSIO_CONTROL_RADDR, data, &curlen);
    if (!rv)
	*pos += curlen;
    return rv;
}

int
gensio_get_raddr(struct gensio *io, void *addr, gensiods *addrlen)
{
    return gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_GET,
			  GENSIO_CONTROL_RADDR_BIN, addr, addrlen);
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
	return GE_NOTFOUND;
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
    int rv;

    rv = io->func(io, GENSIO_FUNC_CLOSE, NULL, close_done, 0, close_data,
		  NULL);
    if (!rv)
	check_flush_sync_io(io);
    return rv;
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
	c->func(c, GENSIO_FUNC_DISABLE, NULL, NULL, 0, NULL, NULL);
	c = c->child;
    }
}

void
gensio_free(struct gensio *io)
{
    struct gensio_os_funcs *o = io->o;
    unsigned int count;

    o->lock(io->lock);
    count = --io->refcount;
    o->unlock(io->lock);
    if (count == 0) {
	check_flush_sync_io(io);
	io->func(io, GENSIO_FUNC_FREE, NULL, NULL, 0, NULL, NULL);
    }
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
    struct gensio_os_funcs *o = io->o;

    o->lock(io->lock);
    io->refcount++;
    o->unlock(io->lock);
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

void
gensio_set_frdata(struct gensio *io, struct gensio_frdata *frdata)
{
    io->frdata = frdata;
}

struct gensio_frdata *
gensio_get_frdata(struct gensio *io)
{
    return io->frdata;
}

void
gensio_set_attr_from_child(struct gensio *io, struct gensio *child)
{
    gensio_set_is_reliable(io, gensio_is_reliable(child));
    gensio_set_is_packet(io, gensio_is_packet(child));
    gensio_set_is_authenticated(io, gensio_is_authenticated(child));
    gensio_set_is_encrypted(io, gensio_is_encrypted(child));
    gensio_set_is_message(io, gensio_is_message(child));
}

struct gensio_accepter *
gensio_acc_get_child(struct gensio_accepter *acc, unsigned int depth)
{
    struct gensio_accepter *c = acc;

    while (depth > 0) {
	if (!c->child)
	    return NULL;
	depth--;
	c = c->child;
    }
    return c;
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
    gensio_terminal_acc_alloch terminal_alloc;
    gensio_filter_acc_alloch filter_alloc;
    struct registered_gensio_accepter *next;
};

static struct gensio_os_funcs *reg_o;

static struct registered_gensio *reg_gensios;
static struct gensio_lock *reg_gensio_lock;

static struct registered_gensio_accepter *reg_gensio_accs;
static struct gensio_lock *reg_gensio_acc_lock;

static struct gensio_class_cleanup *cleanups;
static struct gensio_lock *cleanups_lock;

static struct gensio_once gensio_str_initialized;
static int reg_gensio_rv;

#define INIT_GENSIO(name)				\
    int gensio_init_##name(struct gensio_os_funcs *o);
#include "builtin_gensios.h"
#undef INIT_GENSIO

static void
add_default_gensios(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    reg_o = o;

    reg_gensio_lock = o->alloc_lock(o);
    if (!reg_gensio_lock) {
	reg_gensio_rv = GE_NOMEM;
	return;
    }
    reg_gensio_acc_lock = o->alloc_lock(o);
    if (!reg_gensio_acc_lock) {
	reg_gensio_rv = GE_NOMEM;
	return;
    }
    cleanups_lock = o->alloc_lock(o);
    if (!cleanups_lock) {
	reg_gensio_rv = GE_NOMEM;
	return;
    }

#define INIT_GENSIO(name)				\
    do {						\
	reg_gensio_rv = gensio_init_##name(o);		\
	if (reg_gensio_rv)				\
	    return;					\
    } while(0)
#include "builtin_gensios.h"
#undef INIT_GENSIO
}

int
register_base_gensio_accepter(struct gensio_os_funcs *o,
			      const char *name,
			      str_to_gensio_acc_handler handler,
			      gensio_terminal_acc_alloch terminal_alloc,
			      gensio_filter_acc_alloch filter_alloc)
{
    struct registered_gensio_accepter *n;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);
    if (reg_gensio_rv)
	return reg_gensio_rv;

    n = o->zalloc(o, sizeof(*n));
    if (!n)
	return GE_NOMEM;

    n->name = name;
    n->handler = handler;
    n->terminal_alloc = terminal_alloc;
    n->filter_alloc = filter_alloc;
    o->lock(reg_gensio_acc_lock);
    n->next = reg_gensio_accs;
    reg_gensio_accs = n;
    o->unlock(reg_gensio_acc_lock);
    return 0;
}

int
register_filter_gensio_accepter(struct gensio_os_funcs *o,
				const char *name,
				str_to_gensio_acc_handler handler,
				gensio_filter_acc_alloch alloc)
{
    return register_base_gensio_accepter(o, name, handler, NULL, alloc);
}

int
register_gensio_accepter(struct gensio_os_funcs *o,
			 const char *name,
			 str_to_gensio_acc_handler handler,
			 gensio_terminal_acc_alloch alloc)
{
    return register_base_gensio_accepter(o, name, handler, alloc, NULL);
}

static bool
gensio_loadlib(struct gensio_os_funcs *o, const char *str)
{
    const char *end = str;
    unsigned int len;
    char name[50];

    while (*end && *end != '(' && *end != ',')
	end++;
    len = end - str;
    if (len >= sizeof(name))
	return false;
    memcpy(name, str, len);
    name[len] = '\0';
    if (strcmp(name, "tcp") == 0 || strcmp(name, "unix") == 0)
	strcpy(name, "net");

    return gensio_os_loadlib(o, name);
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
    bool retried = false;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);
    if (reg_gensio_rv)
	return reg_gensio_rv;

    while (isspace(*str))
	str++;
 retry:
    for (r = reg_gensio_accs; r; r = r->next) {
	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != ',' && str[len] != '(' && str[len]))
	    continue;

	str += len;
	err = gensio_scan_args(o, &str, NULL, &args);
	if (!err) {
	    while (isspace(*str))
		str++;
	    err = r->handler(str, args, o, cb, user_data, accepter);
	}
	if (args)
	    gensio_argv_free(o, args);
	return err;
    }
    if (!retried && gensio_loadlib(o, str)) {
	retried = true;
	goto retry;
    }

    if (strisallzero(str)) {
	err = gensio_terminal_acc_alloc("stdio", NULL, NULL, o, cb, user_data,
					accepter);
    } else {
	err = gensio_scan_network_port(o, str, true, &ai, &protocol,
				       NULL, NULL, &args);
	if (!err) {
	    if (protocol == GENSIO_NET_PROTOCOL_UDP) {
		err = gensio_terminal_acc_alloc("udp", ai, args, o, cb,
						user_data, accepter);
	    } else if (protocol == GENSIO_NET_PROTOCOL_TCP) {
		err = gensio_terminal_acc_alloc("tcp", ai, args, o, cb,
						user_data, accepter);
	    } else if (protocol == GENSIO_NET_PROTOCOL_SCTP) {
		err = gensio_terminal_acc_alloc("sctp", ai, args, o, cb,
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
gensio_terminal_acc_alloc(const char *gensiotype, const void *gdata,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_accepter_event cb, void *user_data,
			  struct gensio_accepter **accepter)
{
    struct registered_gensio_accepter *r;
    bool retried = false;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);
    if (reg_gensio_rv)
	return reg_gensio_rv;

 retry:
    for (r = reg_gensio_accs; r; r = r->next) {
	if (strcmp(r->name, gensiotype) != 0)
	    continue;

	if (!r->terminal_alloc)
	    break;

	return r->terminal_alloc(gdata, args, o, cb, user_data, accepter);
    }
    if (!retried && gensio_loadlib(o, gensiotype)) {
	retried = true;
	goto retry;
    }
    return GE_NOTSUP;
}

int
gensio_filter_acc_alloc(const char *gensiotype,
			struct gensio_accepter *child,
			const char * const args[],
			struct gensio_os_funcs *o,
			gensio_accepter_event cb, void *user_data,
			struct gensio_accepter **accepter)
{
    struct registered_gensio_accepter *r;
    bool retried = false;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);
    if (reg_gensio_rv)
	return reg_gensio_rv;

 retry:
    for (r = reg_gensio_accs; r; r = r->next) {
	if (strcmp(r->name, gensiotype) != 0)
	    continue;

	if (!r->filter_alloc)
	    break;

	return r->filter_alloc(child, args, o, cb, user_data, accepter);
    }
    if (!retried && gensio_loadlib(o, gensiotype)) {
	retried = true;
	goto retry;
    }
    return GE_NOTSUP;
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
    bool retried = false;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);
    if (reg_gensio_rv)
	return reg_gensio_rv;

    while (isspace(*str))
	str++;
 retry:
    for (r = reg_gensio_accs; r; r = r->next) {
	const char **args = NULL;

	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != ',' && str[len] != '(' && str[len]))
	    continue;

	str += len;
	err = gensio_scan_args(o, &str, NULL, &args);
	if (!err)
	    err = r->filter_alloc(child, args, o, cb, user_data, accepter);
	if (args)
	    gensio_argv_free(o, args);
	return err;
    }
    if (!retried && gensio_loadlib(o, str)) {
	retried = true;
	goto retry;
    }

    return err;
}

struct registered_gensio {
    const char *name;
    str_to_gensio_handler handler;
    gensio_terminal_alloch terminal_alloc;
    gensio_filter_alloch filter_alloc;
    struct registered_gensio *next;
};

static int
register_base_gensio(struct gensio_os_funcs *o,
		     const char *name,
		     str_to_gensio_handler handler,
		     gensio_terminal_alloch terminal_alloc,
		     gensio_filter_alloch filter_alloc)
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
    n->terminal_alloc = terminal_alloc;
    n->filter_alloc = filter_alloc;
    o->lock(reg_gensio_lock);
    n->next = reg_gensios;
    reg_gensios = n;
    o->unlock(reg_gensio_lock);
    return 0;
}

int
register_filter_gensio(struct gensio_os_funcs *o,
		       const char *name,
		       str_to_gensio_handler handler,
		       gensio_filter_alloch alloc)
{
    return register_base_gensio(o, name, handler, NULL, alloc);
}

int
register_gensio(struct gensio_os_funcs *o,
		const char *name, str_to_gensio_handler handler,
		gensio_terminal_alloch alloc)
{
    return register_base_gensio(o, name, handler, alloc, NULL);
}

static bool
is_serialdev_default_gensio(const char *str)
{
#if _WIN32
    return strncmp(str, "COM", 3) == 0;
#else
    return *str == '/';
#endif
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
    bool retried = false;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);
    if (reg_gensio_rv)
	return reg_gensio_rv;

    while (isspace(*str))
	str++;
 retry:
    for (r = reg_gensios; r; r = r->next) {
	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != ',' && str[len] != '(' && str[len]))
	    continue;

	str += len;
	err = gensio_scan_args(o, &str, NULL, &args);
	if (!err) {
	    while (isspace(*str))
		str++;
	    err = r->handler(str, args, o, cb, user_data, gensio);
	}
	if (args)
	    gensio_argv_free(o, args);
	return err;
    }
    if (!retried && gensio_loadlib(o, str)) {
	retried = true;
	goto retry;
    }

    if (is_serialdev_default_gensio(str)) {
	char *nstr = gensio_alloc_sprintf(o, "serialdev,%s", str);

	if (!nstr)
	    return GE_NOMEM;
	
	err = str_to_gensio(nstr, o, cb, user_data, gensio);
	o->free(o, nstr);
	goto out;
    }

    err = gensio_scan_network_port(o, str, false, &ai, &protocol,
				   &is_port_set, NULL, &args);
    if (!err) {
	if (!is_port_set) {
	    err = GE_INVAL;
	} else if (protocol == GENSIO_NET_PROTOCOL_UDP) {
	    err = gensio_terminal_alloc("udp", ai, args, o, cb, user_data,
					gensio);
	} else if (protocol == GENSIO_NET_PROTOCOL_TCP) {
	    err = gensio_terminal_alloc("tcp", ai, args, o, cb, user_data,
					gensio);
	} else if (protocol == GENSIO_NET_PROTOCOL_SCTP) {
	    err = gensio_terminal_alloc("sctp", ai, args, o, cb, user_data,
					gensio);
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
gensio_terminal_alloc(const char *gensiotype, const void *gdata,
		      const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio)
{
    struct registered_gensio *r;
    bool retried = false;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);
    if (reg_gensio_rv)
	return reg_gensio_rv;

 retry:
    for (r = reg_gensios; r; r = r->next) {
	if (strcmp(r->name, gensiotype) != 0)
	    continue;

	if (!r->terminal_alloc)
	    break;
	return r->terminal_alloc(gdata, args, o, cb, user_data, new_gensio);
    }
    if (!retried && gensio_loadlib(o, gensiotype)) {
	retried = true;
	goto retry;
    }
    return GE_NOTSUP;
}

int
gensio_filter_alloc(const char *gensiotype,
		    struct gensio *child,
		    const char * const args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **new_gensio)
{
    struct registered_gensio *r;
    bool retried = false;

    o->call_once(o, &gensio_str_initialized, add_default_gensios, o);
    if (reg_gensio_rv)
	return reg_gensio_rv;

 retry:
    for (r = reg_gensios; r; r = r->next) {
	if (strcmp(r->name, gensiotype) != 0)
	    continue;

	if (!r->filter_alloc)
	    break;
	return r->filter_alloc(child, args, o, cb, user_data, new_gensio);
    }
    if (!retried && gensio_loadlib(o, gensiotype)) {
	retried = true;
	goto retry;
    }
    return GE_NOTSUP;
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
    bool retried = false;

    while (isspace(*str))
	str++;
 retry:
    for (r = reg_gensios; r; r = r->next) {
	len = strlen(r->name);
	if (strncmp(r->name, str, len) != 0 ||
			(str[len] != '(' && str[len]))
	    continue;

	if (!r->filter_alloc)
	    return GE_INVAL;

	str += len;
	err = gensio_scan_args(o, &str, NULL, &args);
	if (!err)
	    err = r->filter_alloc(child, args, o, cb, user_data, gensio);
	if (args)
	    gensio_argv_free(o, args);
	return err;
    }
    if (!retried && gensio_loadlib(o, str)) {
	retried = true;
	goto retry;
    }

    return GE_NOTSUP;
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
gensio_check_keyint(const char *str, const char *key, int *rvalue)
{
    const char *sval;
    char *end;
    int rv = gensio_check_keyvalue(str, key, &sval);
    long value;

    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    value = strtol(sval, &end, 0);
    if (*end != '\0')
	return -1;

    if (value > INT_MAX)
	return -1;
    if (value < INT_MIN)
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

int
gensio_check_keymode(const char *str, const char *key, unsigned int *rmode)
{
    const char *sval;
    int rv = gensio_check_keyvalue(str, key, &sval);
    unsigned int mode;

    if (!rv)
	return 0;

    if (*sval >= '0' && *sval <= '7') {
	if (sval[1])
	    return -1;
	*rmode = *sval - '0';
	return 1;
    }

    mode = 0;
    while (*sval) {
	if (*sval == 'r')
	    mode |= 4;
	else if (*sval == 'w')
	    mode |= 2;
	else if (*sval == 'x')
	    mode |= 1;
	else
	    return -1;
	sval++;
    }
    *rmode = mode;
    return 1;
}

int
gensio_check_keyperm(const char *str, const char *key, unsigned int *rmode)
{
    const char *sval;
    char *end;
    int rv = gensio_check_keyvalue(str, key, &sval);
    unsigned int mode;

    if (!rv)
	return 0;

    mode = strtoul(sval, &end, 8);
    if (end == sval || *end != '\0')
	return -1;

    *rmode = mode;
    return 1;
}

int
gensio_check_keytime(const char *str, const char *key, char mod,
		     gensio_time *rgt)
{
    const char *sval;
    char *end;
    int rv = gensio_check_keyvalue(str, key, &sval);
    gensio_time gt = { 0, 0 };
    int64_t v;
    int64_t nsecs = 0; /* Use this to avoid overflows. */

    if (!rv)
	return 0;

    while (true) {
	v = strtoul(sval, &end, 0);
	if (end == sval)
	    return -1;
	if (*end) {
	    mod = *end;
	    end++;
	}
	switch (mod) {
	case 'D': gt.secs += v * 24 * 3600; break;
	case 'H': gt.secs += v * 3600; break;
	case 'M': gt.secs += v * 60; break;
	case 's': gt.secs += v; break;
	case 'm': nsecs += GENSIO_MSECS_TO_NSECS(v); goto done;
	case 'u': nsecs += GENSIO_USECS_TO_NSECS(v); goto done;
	case 'n': nsecs += v; goto done;
	default:
	    return -1;
	}
	if (nsecs >= 10 * GENSIO_NSECS_IN_SEC) {
	    gt.secs += nsecs / GENSIO_NSECS_IN_SEC;
	    nsecs = nsecs % GENSIO_NSECS_IN_SEC;
	} else {
	    /* Avoid the division on small numbers. */
	    while (nsecs >= GENSIO_NSECS_IN_SEC) {
		nsecs -= GENSIO_NSECS_IN_SEC;
		gt.secs += 1;
	    }
	}
	if (!*end)
	    break;
	mod = 0;
	sval = end;
    }
 done:
    gt.nsecs = nsecs;
    if (*end)
	return -1;

    *rgt = gt;
    return 1;
}

int
gensio_check_keyfloat(const char *str, const char *key, float *rvalue)
{
    const char *sval;
    char *end;
    int rv = gensio_check_keyvalue(str, key, &sval);
    float value;

    if (!rv)
	return 0;

    if (!*sval)
	return -1;

    value = strtof(sval, &end);
    if (*end != '\0')
	return -1;

    *rvalue = value;
    return 1;
}

void
gensio_acc_vlog(struct gensio_accepter *acc, enum gensio_log_levels level,
		char *str, va_list args)
{
    struct gensio_loginfo info;

    if (!(gensio_get_log_mask() & (1 << level)))
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

#ifdef HAVE_TCPD_H
static struct gensio_enum_val tcpd_enums[] = {
    { "on",	GENSIO_TCPD_ON },
    { "print",	GENSIO_TCPD_PRINT },
    { "off", 	GENSIO_TCPD_OFF },
    { NULL }
};
#endif

struct gensio_def_entry builtin_defaults[] = {
    /* Defaults for TCP, UDP, and SCTP. */
    { "nodelay",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "laddr",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    /* TCP only */
#ifdef HAVE_TCPD_H
    { "tcpd",		GENSIO_DEFAULT_ENUM,	.enums = tcpd_enums,
						.def.intval = GENSIO_TCPD_ON },
#endif
    /* UDP only */
    { "mttl",		GENSIO_DEFAULT_INT,	.min = 1, .max = 255,
						.def.intval = 1 },
    /* SCTP only */
    { "instreams",	GENSIO_DEFAULT_INT,	.min = 1, .max = INT_MAX,
						.def.intval = 1 },
    { "ostreams",	GENSIO_DEFAULT_INT,	.min = 1, .max = INT_MAX,
						.def.intval = 1 },
    { "sack_freq",	GENSIO_DEFAULT_INT,	.min = 0, .max = INT_MAX,
						.def.intval = 1 },
    { "sack_delay",	GENSIO_DEFAULT_INT,	.min = 0, .max = INT_MAX,
						.def.intval = 10 },
    /* TCP and SCTP, UDP get added in init as false. */
    { "reuseaddr",	GENSIO_DEFAULT_BOOL,	.def.intval = 1 },
    /* serialdev */
    { "xonxoff",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "rtscts",		GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "local",		GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "hangup_when_done", GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "custspeed",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "rs485",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "nouucplock",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { "drain_time",	GENSIO_DEFAULT_INT,	.min = -1, .max = INT_MAX,
						.def.intval = -1, },
    { "char_drain_wait",GENSIO_DEFAULT_INT,	.min = -1, .max = INT_MAX,
						.def.intval = 50, },
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

    /* For mdns */
    { "name",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "type",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "domain",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "host",		GENSIO_DEFAULT_STR,	.def.strval = NULL },
    { "interface",	GENSIO_DEFAULT_INT,	.min = -1, .max = INT_MAX,
						.def.intval = -1 },
    { "nettype",	GENSIO_DEFAULT_STR,	.def.strval = "unspec" },
    { "nostack",	GENSIO_DEFAULT_BOOL,	.def.intval = 0 },
    { NULL }
};

static struct gensio_def_entry *defaults;
static int gensio_def_init_rv;
static int l_gensio_set_default(struct gensio_os_funcs *o,
				const char *class, const char *name,
				const char *strval, int intval);
static void l_gensio_reset_defaults(struct gensio_os_funcs *o);

static void
gensio_default_init(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    deflock = o->alloc_lock(o);
    if (!deflock)
	gensio_def_init_rv = GE_NOMEM;
    else
	/* Default reuseaddr to false for UDP. */
	gensio_def_init_rv = l_gensio_set_default(o, "udp", "reuseaddr",
						  NULL, 0);
}

void
gensio_register_class_cleanup(struct gensio_class_cleanup *cleanup)
{
    reg_o->lock(cleanups_lock);
    if (!cleanup->ginfo) {
	cleanup->ginfo = (void *) 1; /* Just mark it as in use. */
	cleanup->next = cleanups;
	cleanups = cleanup;
    }
    reg_o->unlock(cleanups_lock);
}

void
gensio_cleanup_mem(struct gensio_os_funcs *o)
{
    struct registered_gensio_accepter *n, *n2;
    struct registered_gensio *g, *g2;
    struct gensio_class_cleanup *cl = cleanups;

    if (gensio_base_lock)
	o->free_lock(gensio_base_lock);
    gensio_base_lock = NULL;

    l_gensio_reset_defaults(o);

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

    memset(&gensio_default_initialized, 0, sizeof(gensio_default_initialized));
    memset(&gensio_base_initialized, 0, sizeof(gensio_base_initialized));
    cleanups = NULL;
    while (cl) {
	cl->ginfo = NULL;
	cl->cleanup();
	cl = cl->next;
    }

    if (cleanups_lock)
	o->free_lock(cleanups_lock);
    cleanups_lock = NULL;

    reg_o = NULL;
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

static void
l_gensio_reset_defaults(struct gensio_os_funcs *o)
{
    struct gensio_def_entry *d;
    unsigned int i;

    if (deflock) {
	o->lock(deflock);
	for (i = 0; builtin_defaults[i].name; i++)
	    gensio_reset_default(o, &builtin_defaults[i]);
	for (d = defaults; d; d = d->next)
	    gensio_reset_default(o, d);
	o->unlock(deflock);
    }
}

int
gensio_reset_defaults(struct gensio_os_funcs *o)
{
    o->call_once(o, &gensio_default_initialized, gensio_default_init, o);
    if (gensio_def_init_rv)
	return gensio_def_init_rv;

    l_gensio_reset_defaults(o);
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

static int
l_gensio_set_default(struct gensio_os_funcs *o,
		     const char *class, const char *name,
		     const char *strval, int intval)
{
    int err = 0;
    struct gensio_def_entry *d;
    char *new_strval = NULL, *end;
    unsigned int i;

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
gensio_set_default(struct gensio_os_funcs *o,
		   const char *class, const char *name,
		   const char *strval, int intval)
{
    o->call_once(o, &gensio_default_initialized, gensio_default_init, o);
    if (gensio_def_init_rv)
	return gensio_def_init_rv;

    return l_gensio_set_default(o, class, name, strval, intval);
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
	    memcpy(str, val->strval, (size_t) val->intval + 1); /* copy emding \0 */
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

static int
gensio_wait_no_cb(struct gensio *io, struct gensio_waiter *waiter,
		  gensio_time *timeout)
{
    struct gensio_os_funcs *o = io->o;
    struct gensio_nocbwait wait;
    int rv = 0;

    memset(&wait, 0, sizeof(wait));
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

static void
check_flush_sync_io(struct gensio *io)
{
    struct gensio_sync_io *sync_io = io->sync_io;
    struct gensio_os_funcs *o = io->o;

    if (sync_io) {
	o->lock(sync_io->lock);
	if (!sync_io->err)
	    sync_io->err = GE_LOCALCLOSED;
	gensio_sync_flush_waiters(sync_io, io->o);
	o->unlock(sync_io->lock);
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
	    gensio_set_read_callback_enable(io, false);
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
    int rv = 0;

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
    } else if (!rv) {
    got_one:
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

void
gensio_fdump_init(struct gensio_fdump *h, unsigned int indent)
{
    h->column = 0;
    h->pos = 0;
    h->indent = indent;
}

void
gensio_fdump_buf(FILE *f, const unsigned char *buf, gensiods len,
		 struct gensio_fdump *h)
{
    gensiods i, j;

    for (i = 0; i < len; i++) {
	if (h->column == 0)
	    fprintf(f, "%*s%4.4x:", h->indent, "", h->pos);
	fprintf(f, " %2.2x", buf[i]);
	h->data[h->column++] = buf[i];
	h->pos++;
	if (h->column == 16) {
	    fputs("  ", f);
	    for (j = 0; j < 16; j++) {
		if (isprint(h->data[j]))
		    fputc(h->data[j], f);
		else
		    fputc('.', f);
	    }
	    fputc('\n', f);
	    h->column = 0;
	}
    }
}

void
gensio_fdump_buf_finish(FILE *f, struct gensio_fdump *h)
{
    gensiods i;

    if (h->column == 0)
	return;
    for (i = h->column; i < 16; i++)
	fputs("   ", f);
    fputs("  ", f);
    for (i = 0; i < h->column; i++) {
	if (isprint(h->data[i]))
	    fputc(h->data[i], f);
	else
	    fputc('.', f);
    }
    fputc('\n', f);
}

void
gensio_time_add_nsecs(gensio_time *t, int64_t v)
{
    t->secs += v / GENSIO_NSECS_IN_SEC;
    t->nsecs += v % GENSIO_NSECS_IN_SEC;
    while (t->nsecs > GENSIO_NSECS_IN_SEC) {
	t->secs++;
	t->nsecs -= GENSIO_NSECS_IN_SEC;
    }
    while (t->nsecs < 0) {
	t->secs--;
	t->nsecs += GENSIO_NSECS_IN_SEC;
    }
}

int64_t
gensio_time_to_msecs(gensio_time *t1)
{
    int64_t v;

    v = t1->secs * 1000;
    v += GENSIO_NSECS_TO_MSECS(t1->nsecs);
    return v;
}

int64_t
gensio_time_to_usecs(gensio_time *t1)
{
    int64_t v;

    v = t1->secs * 1000000;
    v += GENSIO_NSECS_TO_USECS(t1->nsecs);
    return v;
}

void
gensio_msecs_to_time(gensio_time *t1, int64_t v)
{
    t1->secs = v / 1000;
    t1->nsecs = GENSIO_MSECS_TO_NSECS(v % 1000);
}

void
gensio_usecs_to_time(gensio_time *t1, int64_t v)
{
    t1->secs = v / 1000000;
    t1->nsecs = GENSIO_USECS_TO_NSECS(v % 1000000);
}

int64_t
gensio_time_diff_nsecs(gensio_time *t1, gensio_time *t2)
{
    int64_t v;

    v = t1->secs - t2->secs;
    v += (int64_t) t1->nsecs - (int64_t) t2->nsecs;
    return v;
}

/* For lack of a better place to put this. */
bool gensio_uucp_locking_enabled = true;
