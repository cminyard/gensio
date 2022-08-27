/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "gensio_ll_ipmisol.h"
#include <gensio/gensio_err.h>

#include <gensio/gensio_class.h>
#include <gensio/sergensio_class.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_list.h>

#include <gensio/gensio_buffer.h>
#include "utils.h"

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_smi.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_lan.h>

#include <OpenIPMI/ipmi_sol.h>
#include <OpenIPMI/ipmi_debug.h>

struct igensio_info
{
    struct gensio_os_funcs *o;
    os_vlog_t log_handler;
};


static void *
gio_mem_alloc(int size)
{
    return malloc(size);
}

static void
gio_mem_free(void *data)
{
    free(data);
}

struct os_hnd_fd_id_s
{
    struct gensio_os_funcs *o;
    int             fd;
    struct gensio_iod *iod;
    void            *cb_data;
    os_data_ready_t data_ready;
    os_data_ready_t write_ready;
    os_data_ready_t except_ready;
    os_handler_t    *handler;
    os_fd_data_freed_t freed;
};

static void
fd_read_handler(struct gensio_iod *iod, void *data)
{
    os_hnd_fd_id_t *fd_data = (os_hnd_fd_id_t *) data;

    fd_data->data_ready(fd_data->fd, fd_data->cb_data, fd_data);
}

static void
fd_write_handler(struct gensio_iod *iod, void *data)
{
    os_hnd_fd_id_t *fd_data = (os_hnd_fd_id_t *) data;

    fd_data->write_ready(fd_data->fd, fd_data->cb_data, fd_data);
}

static void
fd_except_handler(struct gensio_iod *iod, void *data)
{
    os_hnd_fd_id_t *fd_data = (os_hnd_fd_id_t *) data;

    fd_data->except_ready(fd_data->fd, fd_data->cb_data, fd_data);
}

static void
free_fd_data(struct gensio_iod *iod, void *data)
{
    os_hnd_fd_id_t *fd_data = data;

    fd_data->o->release_iod(fd_data->iod);
    if (fd_data->freed)
        fd_data->freed(fd_data->fd, fd_data->cb_data);
    free(data);
}

static int
gio_add_fd_to_wait_for(os_handler_t       *handler,
		       int                fd,
		       os_data_ready_t    data_ready,
		       void               *cb_data,
		       os_fd_data_freed_t freed,
		       os_hnd_fd_id_t     **id)
{
    os_hnd_fd_id_t *fd_data;
    int rv;
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;


    fd_data = malloc(sizeof(*fd_data));
    if (!fd_data)
	return ENOMEM;
    fd_data->o = o;

    rv = o->add_iod(o, GENSIO_IOD_SOCKET, fd, &fd_data->iod);
    if (rv) {
	free(fd_data);
	return rv;
    }
    fd_data->fd = fd;
    fd_data->cb_data = cb_data;
    fd_data->data_ready = data_ready;
    fd_data->handler = handler;
    fd_data->freed = freed;
    rv = o->set_fd_handlers(fd_data->iod, fd_data,
			    fd_read_handler, fd_write_handler,
			    fd_except_handler, free_fd_data);
    if (rv) {
	o->release_iod(fd_data->iod);
	free(fd_data);
	return rv;
    }
    o->set_write_handler(fd_data->iod, false);
    o->set_except_handler(fd_data->iod, false);
    o->set_read_handler(fd_data->iod, true);

    *id = fd_data;
    return 0;
}

static int
gio_remove_fd_to_wait_for(os_handler_t   *handler,
			  os_hnd_fd_id_t *id)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->set_read_handler(id->iod, false);
    o->clear_fd_handlers(id->iod);
    return 0;
}

struct os_hnd_timer_id_s
{
    void           *cb_data;
    os_timed_out_t timed_out;
    struct gensio_timer *timer;
    bool running;
    os_handler_t *handler;
    struct gensio_lock *lock;
};

static void
timer_handler(struct gensio_timer *t, void *data)
{
    os_hnd_timer_id_t *timer = (os_hnd_timer_id_t *) data;
    os_handler_t *handler = timer->handler;
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;
    void              *cb_data;
    os_timed_out_t    timed_out;

    o->lock(timer->lock);
    timed_out = timer->timed_out;
    cb_data = timer->cb_data;
    timer->running = false;
    o->unlock(timer->lock);
    timed_out(cb_data, timer);
}

static int
gio_alloc_timer(os_handler_t      *handler,
		os_hnd_timer_id_t **rtimer)
{
    os_hnd_timer_id_t *timer;
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    timer = malloc(sizeof(*timer));
    if (!timer)
	return ENOMEM;

    timer->lock = o->alloc_lock(o);
    if (!timer->lock) {
	free(timer);
	return ENOMEM;
    }

    timer->running = false;
    timer->timed_out = NULL;
    timer->handler = handler;

    timer->timer = o->alloc_timer(o, timer_handler, timer);
    if (!timer->timer) {
	o->free_lock(timer->lock);
	free(timer);
	return ENOMEM;
    }

    *rtimer = timer;
    return 0;
}

static int
gio_free_timer(os_handler_t      *handler,
	       os_hnd_timer_id_t *timer)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->free_timer(timer->timer);
    o->free_lock(timer->lock);
    free(timer);
    return 0;
}

static int
gio_start_timer(os_handler_t      *handler,
		os_hnd_timer_id_t *timer,
		struct timeval    *timeout,
		os_timed_out_t    timed_out,
		void              *cb_data)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;
    gensio_time gtime;
    int rv = 0;

    o->lock(timer->lock);
    if (timer->running) {
	rv = EAGAIN;
	goto out_unlock;
    }

    timer->running = true;
    timer->cb_data = cb_data;
    timer->timed_out = timed_out;

    gtime.secs = timeout->tv_sec;
    gtime.nsecs = timeout->tv_usec * 1000;

    rv = o->start_timer(timer->timer, &gtime);
    if (rv)
	timer->running = false;

 out_unlock:
    o->unlock(timer->lock);

    return rv;
}

static int
gio_stop_timer(os_handler_t *handler,
	       os_hnd_timer_id_t *timer)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;
    int rv = 0;

    o->lock(timer->lock);
    if (timer->running) {
	timer->running = 0;
	o->stop_timer(timer->timer);
    } else {
	rv = ETIMEDOUT;
    }
    o->unlock(timer->lock);

    return rv;
}

struct os_hnd_lock_s
{
    struct gensio_lock *lock;
};

static int
gio_create_lock(os_handler_t  *handler,
		os_hnd_lock_t **rlock)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;
    os_hnd_lock_t *lock;

    lock = malloc(sizeof(*lock));
    if (!lock)
	return ENOMEM;

    lock->lock = o->alloc_lock(o);
    if (!lock->lock) {
	free(lock);
	return ENOMEM;
    }

    *rlock = lock;

    return 0;
}

static int
gio_destroy_lock(os_handler_t  *handler,
		 os_hnd_lock_t *lock)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->free_lock(lock->lock);
    free(lock);
    return 0;
}

static int
gio_lock(os_handler_t  *handler,
	 os_hnd_lock_t *lock)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->lock(lock->lock);
    return 0;
}

static int
gio_unlock(os_handler_t  *handler,
	   os_hnd_lock_t *lock)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->unlock(lock->lock);
    return 0;
}

static int
gio_get_random(os_handler_t  *handler,
	       void          *data,
	       unsigned int  len)
{
    struct igensio_info *info = handler->internal_data;

    return info->o->get_random(info->o, data, len);
}

static void
gio_vlog(os_handler_t         *handler,
	 enum ipmi_log_type_e log_type,
	 const char           *format,
	 va_list              ap)
{
    struct igensio_info *info = handler->internal_data;
    os_vlog_t log_handler = info->log_handler;
    enum gensio_log_levels level;

    switch(log_type) {
    case IPMI_LOG_INFO:
    default:
	level = GENSIO_LOG_INFO;
	break;

    case IPMI_LOG_WARNING:
    case IPMI_LOG_ERR_INFO:
	level = GENSIO_LOG_WARNING;
	break;

    case IPMI_LOG_SEVERE:
	level = GENSIO_LOG_ERR;
	break;

    case IPMI_LOG_FATAL:
	level = GENSIO_LOG_FATAL;
	break;

    case IPMI_LOG_DEBUG:
    case IPMI_LOG_DEBUG_START:
    case IPMI_LOG_DEBUG_CONT:
    case IPMI_LOG_DEBUG_END:
	level = GENSIO_LOG_DEBUG;
	break;
    }

    if (log_handler) {
	log_handler(handler, format, log_type, ap);
    } else if (info->o->vlog) {
	gensio_vlog(info->o, level, format, ap);
    } else if (gensio_get_log_mask() & (1 << level)) {
	vprintf(format, ap);
	putc('\n', stdout);
    }
}

static void
gio_log(os_handler_t         *handler,
	enum ipmi_log_type_e log_type,
	const char           *format,
	...)
{
    va_list ap;

    va_start(ap, format);
    gio_vlog(handler, log_type, format, ap);
    va_end(ap);
}

static void
gio_set_log_handler(os_handler_t *handler,
		    os_vlog_t    log_handler)
{
    struct igensio_info *info = handler->internal_data;

    info->log_handler = log_handler;
}

static void
gio_set_fd_handlers(os_handler_t *handler, os_hnd_fd_id_t *id,
		    os_data_ready_t write_ready,
		    os_data_ready_t except_ready)
{
    id->write_ready = write_ready;
    id->except_ready = except_ready;
}

static int
gio_set_fd_enables(os_handler_t *handler, os_hnd_fd_id_t *id,
		   int read, int write, int except)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;

    o->set_read_handler(id->iod, read);
    o->set_write_handler(id->iod, write);
    o->set_except_handler(id->iod, except);
    return 0;
}

static int
gio_get_monotonic_time(os_handler_t *handler, struct timeval *tv)
{
    struct igensio_info *info = handler->internal_data;
    struct gensio_os_funcs *o = info->o;
    gensio_time gtime;

    o->get_monotonic_time(o, &gtime);
    tv->tv_sec = gtime.secs;
    tv->tv_usec = (gtime.nsecs + 500) / 1000;
    return 0;
}

static int
gio_get_real_time(os_handler_t *handler, struct timeval *tv)
{
    gettimeofday(tv, NULL);
    return 0;
}

void ipmi_malloc_init(os_handler_t *oshandler);
void ipmi_malloc_shutdown(void);

static os_handler_t *
gio_alloc(struct gensio_os_funcs *o)
{
    struct igensio_info *info;
    os_handler_t *handler;
    os_handler_t dummyh;

    info = malloc(sizeof(*info));
    if (!info)
	return NULL;
    info->o = o;
    info->log_handler = NULL;

    memset(&dummyh, 0, sizeof(dummyh));
    dummyh.mem_alloc = gio_mem_alloc;
    dummyh.mem_free = gio_mem_free;
    ipmi_malloc_init(&dummyh);

    handler = ipmi_alloc_os_handler();
    if (!handler) {
	free(info);
	return NULL;
    }

    ipmi_malloc_shutdown();

    handler->mem_alloc = gio_mem_alloc;
    handler->mem_free = gio_mem_free;
    handler->add_fd_to_wait_for = gio_add_fd_to_wait_for;
    handler->remove_fd_to_wait_for = gio_remove_fd_to_wait_for;
    handler->alloc_timer = gio_alloc_timer;
    handler->free_timer = gio_free_timer;
    handler->start_timer = gio_start_timer;
    handler->stop_timer = gio_stop_timer;
    handler->create_lock = gio_create_lock;
    handler->destroy_lock = gio_destroy_lock;
    handler->lock = gio_lock;
    handler->unlock = gio_unlock;
    handler->get_random = gio_get_random;
    handler->log = gio_log;
    handler->vlog = gio_vlog;
    handler->set_log_handler = gio_set_log_handler;
    handler->set_fd_handlers = gio_set_fd_handlers;
    handler->set_fd_enables = gio_set_fd_enables;
    handler->get_monotonic_time = gio_get_monotonic_time;
    handler->get_real_time = gio_get_real_time;

    handler->internal_data = info;
    return handler;
};

enum sol_state {
    SOL_CLOSED,
    SOL_IN_OPEN,
    SOL_IN_SOL_OPEN,
    SOL_OPEN,
    SOL_IN_CLOSE
};

struct sol_ll;

struct sol_op_done {
    struct sol_ll *solll;
    bool started;
    bool use_runner;
    sergensio_done cb;
    int done_val;
    int val;
    void *cb_data;
    int (*func)(ipmi_sol_conn_t *, int, ipmi_sol_transmit_complete_cb, void *);
    struct sol_op_done *next;
};

struct sol_ll {
    struct gensio_ll *ll;
    struct gensio_os_funcs *o;
    struct sergensio *sio;

    struct gensio_lock *lock;

    unsigned int refcount;

    /* Callbacks set by gensio_base. */
    gensio_ll_cb cb;
    void *cb_data;

    /* Serial callbacks. */
    gensio_ll_ipmisol_cb ser_cbs;
    void *ser_cbs_data;

    char *devname;

    ipmi_args_t *args;
    ipmi_con_t *ipmi;
    ipmi_sol_conn_t *sol;

    enum sol_state state;

    bool read_enabled;
    bool write_enabled;

    gensio_ll_open_done open_done;
    void *open_data;
    int open_err;

    gensio_ll_close_done close_done;
    void *close_data;

    struct gensio_buffer read_data;
    gensiods max_write_size;

    /*
     * If the connection is closed or goes down from the remote end,
     * this hold the error to return (if non-zero);
     */
    int read_err;

    bool in_read;
    bool in_write;
    gensiods write_outstanding;

    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;

    bool deferred_read;
    bool deferred_write;

    /* The last report from the SOL connection whether it's up or not. */
    int last_any_port_up;

    unsigned int nacks_sent;

    /* SOL parms */
    int speed;
    bool authenticated;
    bool disablebreak;
    bool encrypted;
    unsigned int ack_timeout;
    unsigned int ack_retries;
    bool deassert_CTS_DCD_DSR_on_connect;
    bool shared_serial_alert_behavior;

    /* Pending transmit done handling. */
    bool xmit_dones_pending;
    struct gensio_list xmit_dones;
    struct gensio_lock *xmit_done_lock;
    struct gensio_runner *xmit_done_runner;

    /*
     * We got a flush/break while one was still pending, do these when
     * it finishes.
     */
    int pending_flush;
    int pending_break;

    struct sol_op_done *cts_done;
    struct sol_op_done *dcd_dsr_done;
    struct sol_op_done *ri_done;
};

/* Used to hold information about pending transmits. */
struct sol_tc {
    unsigned int size;
    struct sol_ll *solll;
    int err;
    struct gensio_link link;
};

os_handler_t *gensio_os_handler;

#define ll_to_sol(v) ((struct sol_ll *) gensio_ll_get_user_data(v))

static void
sol_lock(struct sol_ll *solll)
{
    solll->o->lock(solll->lock);
}

static void
sol_unlock(struct sol_ll *solll)
{
    solll->o->unlock(solll->lock);
}

static void
sol_ref(struct sol_ll *solll)
{
    solll->refcount++;
}

static void sol_finish_free(struct sol_ll *solll)
{
    if (solll->sol) {
	ipmi_sol_close(solll->sol);
	ipmi_sol_free(solll->sol);
    }
    if (solll->ipmi)
	solll->ipmi->close_connection(solll->ipmi);
    if (solll->ll)
	gensio_ll_free_data(solll->ll);
    if (solll->lock)
	solll->o->free_lock(solll->lock);
    if (solll->xmit_done_lock)
	solll->o->free_lock(solll->xmit_done_lock);
    if (solll->xmit_done_runner)
	solll->o->free_runner(solll->xmit_done_runner);
    if (solll->read_data.buf)
	solll->o->free(solll->o, solll->read_data.buf);
    if (solll->deferred_op_runner)
	solll->o->free_runner(solll->deferred_op_runner);
    if (solll->ser_cbs)
	solll->ser_cbs(solll->ser_cbs_data, GENSIO_SOL_LL_FREE, NULL);
    if (solll->args)
	ipmi_free_args(solll->args);
    if (solll->devname)
	solll->o->free(solll->o, solll->devname);
    solll->o->free(solll->o, solll);
}

static void
sol_deref_and_unlock(struct sol_ll *solll)
{
    unsigned int count;

    assert(solll->refcount > 0);
    count = --solll->refcount;
    sol_unlock(solll);
    if (count == 0)
	sol_finish_free(solll);
}

static int sol_xlat_ipmi_err(struct gensio_os_funcs *o, int err)
{
    if (IPMI_IS_OS_ERR(err)) {
	return gensio_os_err_to_err(o, IPMI_OS_ERR_VAL(err));
    } else if (IPMI_IS_SOL_ERR(err)) {
	err = IPMI_GET_SOL_ERR(err);
	if (err == IPMI_SOL_DISCONNECTED)
	    err = GE_REMCLOSE;
	else if (err == IPMI_SOL_NOT_AVAILABLE)
	    err = GE_COMMERR;
	else if (err == IPMI_SOL_DEACTIVATED)
	    err = GE_HOSTDOWN;
	else
	    err = GE_COMMERR;
    } else if (IPMI_IS_RMCPP_ERR(err)) {
	err = IPMI_GET_RMCPP_ERR(err);
	if (err == IPMI_RMCPP_INVALID_PAYLOAD_TYPE)
	    err = GE_CONNREFUSE;
	else
	    err = GE_COMMERR;
    } else {
	err = GE_COMMERR;
    }
    return err;
}

static int
sol_do_read_send(void *cb_data, void *buf, unsigned int buflen,
		 unsigned int *written)
{
    struct sol_ll *solll = cb_data;
    gensiods count;

    solll->in_read = true;
    sol_unlock(solll);
    count = solll->cb(solll->cb_data, GENSIO_LL_CB_READ, 0, buf, buflen, NULL);
    sol_lock(solll);
    solll->in_read = false;
    *written = count;
    return 0;
}

static void
check_for_read_delivery(struct sol_ll *solll)
{
    while (solll->read_enabled &&
	   (gensio_buffer_cursize(&solll->read_data) || solll->read_err) &&
	   !solll->in_read) {
	if (solll->read_err) {
	    sol_unlock(solll);
	    solll->cb(solll->cb_data, GENSIO_LL_CB_READ, solll->read_err,
		      NULL, 0, NULL);
	    sol_lock(solll);
	} else {
	    gensio_buffer_write(sol_do_read_send, solll, &solll->read_data);

	    /* Maybe we consumed some data, let the other end send if so. */
	    while (solll->nacks_sent > 0 &&
		   gensio_buffer_left(&solll->read_data) > 128) { /* FIXME - magic */
		if (ipmi_sol_release_nack(solll->sol))
		    break;
		solll->nacks_sent--;
	    }
	}
    }
}

static void
check_for_write_ready(struct sol_ll *solll)
{
    while (!solll->in_write &&
	   solll->write_enabled &&
	   solll->write_outstanding < solll->max_write_size) {
	solll->in_write = true;
	sol_unlock(solll);
	solll->cb(solll->cb_data, GENSIO_LL_CB_WRITE_READY, 0, NULL, 0, NULL);
	sol_lock(solll);
	solll->in_write = false;
    }
}

static void sol_op_done(struct sol_ll *solll, int err,
			struct sol_op_done **op_done);

static void
sol_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct sol_ll *solll = cbdata;

    sol_lock(solll);
    while (solll->deferred_op_pending) {
	solll->deferred_op_pending = false;

	if (solll->cts_done && solll->cts_done->use_runner)
	    sol_op_done(solll, 0, &solll->cts_done);
	if (solll->dcd_dsr_done && solll->dcd_dsr_done->use_runner)
	    sol_op_done(solll, 0, &solll->dcd_dsr_done);
	if (solll->ri_done && solll->ri_done->use_runner)
	    sol_op_done(solll, 0, &solll->ri_done);

	while (solll->deferred_read) {
	    solll->deferred_read = false;
	    check_for_read_delivery(solll);
	}

	while (solll->deferred_write) {
	    solll->deferred_write = false;
	    check_for_write_ready(solll);
	}
    }

    sol_deref_and_unlock(solll);
}

static void
sol_sched_deferred_op(struct sol_ll *solll)
{
    if (!solll->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	sol_ref(solll);
	solll->deferred_op_pending = true;
	solll->o->run(solll->deferred_op_runner);
    }
}

static void
sol_set_callbacks(struct gensio_ll *ll, gensio_ll_cb cb, void *cb_data)
{
    struct sol_ll *solll = ll_to_sol(ll);

    solll->cb = cb;
    solll->cb_data = cb_data;
}

static void connection_closed(ipmi_con_t *ipmi, void *cb_data);

static void
handle_xmit_dones(struct gensio_runner *runner, void *cbdata)
{
    struct sol_ll *solll = cbdata;
    struct gensio_os_funcs *o = solll->o;
    unsigned int deref_count = 0;

    sol_lock(solll);
    o->lock(solll->xmit_done_lock);
    solll->xmit_dones_pending = false;
    while (!gensio_list_empty(&solll->xmit_dones)) {
	struct gensio_link *l = gensio_list_first(&solll->xmit_dones);
	struct sol_tc *tc = gensio_container_of(l, struct sol_tc, link);

	gensio_list_rm(&solll->xmit_dones, l);
	o->unlock(solll->xmit_done_lock);

	if (tc->err && solll->state != SOL_IN_CLOSE) {
	    solll->read_err = tc->err;
	    check_for_read_delivery(solll);
	} else {
	    solll->write_outstanding -= tc->size;
	    if (solll->state == SOL_IN_CLOSE) {
		if (solll->write_outstanding == 0) {
		    tc->err = ipmi_sol_close(solll->sol);
		    if (tc->err)
			tc->err = solll->ipmi->close_connection_done(
					     solll->ipmi,
					     connection_closed,
					     solll);
		    if (tc->err) {
			solll->state = SOL_CLOSED;
			solll->ipmi = NULL;
			if (solll->close_done)
			    solll->close_done(solll->cb_data, solll->open_data);
		    }
		}
	    } else {
		check_for_write_ready(solll);
	    }
	}
	o->free(o, tc);
	deref_count++;

	o->lock(solll->xmit_done_lock);
    }
    o->unlock(solll->xmit_done_lock);

    if (deref_count >= 1) {
	assert(solll->refcount >= deref_count);
	solll->refcount -= deref_count - 1;
	sol_deref_and_unlock(solll);
    } else {
	sol_unlock(solll);
    }
}

static void
transmit_complete(ipmi_sol_conn_t *conn,
		  int             err,
		  void            *cb_data)
{
    struct sol_tc *tc = cb_data;
    struct sol_ll *solll = tc->solll;
    struct gensio_os_funcs *o = solll->o;

    if (err)
	err = sol_xlat_ipmi_err(o, err);
    tc->err = err;

    /*
     * Unfortunately, OpenIPMI isn't quite as nice as gensio, you can
     * get callbacks from user function calls.  So we need to run the
     * transmit complete handling in a runner.
     */
    o->lock(solll->xmit_done_lock);
    gensio_list_add_tail(&solll->xmit_dones, &tc->link);
    if (!solll->xmit_dones_pending) {
	solll->xmit_dones_pending = true;
	o->run(solll->xmit_done_runner);
    }
    o->unlock(solll->xmit_done_lock);
}

static int
sol_write(struct gensio_ll *ll, gensiods *rcount,
	  const struct gensio_sg *sg, gensiods sglen)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int err = 0;
    struct sol_tc *tc;
    gensiods left, i, total_write = 0, pos = 0;
    unsigned char *buf = NULL;

    sol_lock(solll);
    if (solll->state != SOL_OPEN) {
	err = GE_NOTREADY;
	goto out_unlock;
    }

    left = solll->max_write_size - solll->write_outstanding;

    for (i = 0; i < sglen; i++)
	total_write += sg[i].buflen;
    if (total_write > left)
	total_write = left;
    if (total_write == 0) {
	pos = 0;
	goto out_finish;
    }

    buf = solll->o->zalloc(solll->o, total_write);
    if (!buf) {
	err = GE_NOMEM;
	goto out_unlock;
    }
    for (i = 0; i < sglen; i++) {
	if (sg[i].buflen >= total_write - pos) {
	    memcpy(buf + pos, sg[i].buf, total_write - pos);
	    break;
	} else {
	    memcpy(buf + pos, sg[i].buf, sg[i].buflen);
	    pos += sg[i].buflen;
	}
    }

    pos = 0;
    while (pos < total_write) {
	tc = solll->o->zalloc(solll->o, sizeof(*tc));
	if (!tc) {
	    if (pos == 0) {
		/* Nothing transmitted, return an error. */
		err = GE_NOMEM;
		goto out_unlock;
	    }
	    goto out_finish;
	}
	if (total_write - pos > 255)
	    tc->size = 255;
	else
	    tc->size = total_write - pos;
	tc->solll = solll;
	err = ipmi_sol_write(solll->sol, buf + pos, tc->size,
			     transmit_complete, tc);
	if (err) {
	    solll->o->free(solll->o, tc);
	    if (pos == 0 && err != EAGAIN) {
		/*
		 * Nothing transmitted and it's not full buffers,
		 * return an error.
		 */
		err = sol_xlat_ipmi_err(solll->o, err);
		goto out_unlock;
	    }
	    err = 0;
	    goto out_finish;
	} else {
	    solll->write_outstanding += tc->size;
	    sol_ref(solll);
	    pos += tc->size;
	}
    }
 out_finish:
    if (rcount)
	*rcount = pos;
 out_unlock:
    if (buf)
	solll->o->free(solll->o, buf);
    sol_unlock(solll);

    return err;
}

static int
sol_data_received(ipmi_sol_conn_t *conn,
		  const void *idata, size_t count, void *user_data)
{
    struct sol_ll *solll = user_data;
    int rv = 0;

    sol_lock(solll);
    if (count <= gensio_buffer_left(&solll->read_data)) {
	gensio_buffer_output(&solll->read_data, idata, count);
	check_for_read_delivery(solll);
    } else {
	solll->nacks_sent++;
	rv = 1;
    }
    sol_unlock(solll);
    return rv;
}

static void
sol_break_detected(ipmi_sol_conn_t *conn, void *user_data)
{
}

static void
bmc_transmit_overrun(ipmi_sol_conn_t *conn, void *user_data)
{
}

static void
connection_closed(ipmi_con_t *ipmi, void *cb_data)
{
    struct sol_ll *solll = cb_data;
    enum sol_state old_state;

    sol_lock(solll);
    old_state = solll->state;
    solll->state = SOL_CLOSED;
    solll->ipmi = NULL;
    sol_unlock(solll);

    if (old_state == SOL_IN_SOL_OPEN) {
	if (solll->open_done)
	    solll->open_done(solll->cb_data, solll->read_err, solll->open_data);
    } else {
	if (solll->close_done)
	    solll->close_done(solll->cb_data, solll->open_data);
    }
}

static void
sol_connection_state(ipmi_sol_conn_t *conn, ipmi_sol_state state,
		     int err, void *cb_data)
{
    struct sol_ll *solll = cb_data;

    if (err)
	err = sol_xlat_ipmi_err(solll->o, err);

    sol_lock(solll);
    switch (state) {
    case ipmi_sol_state_closed:
	if (solll->state == SOL_IN_SOL_OPEN) {
	    solll->read_err = GE_CONNREFUSE;
	    if (solll->sol) {
		ipmi_sol_free(solll->sol);
		solll->sol = NULL;
		sol_unlock(solll);
		solll->ipmi->close_connection_done(solll->ipmi,
						   connection_closed,
						   solll);
		return;
	    }
	} else if (solll->state == SOL_IN_CLOSE) {
	    if (solll->sol) {
		ipmi_sol_free(solll->sol);
		solll->sol = NULL;
		sol_unlock(solll);
		solll->ipmi->close_connection_done(solll->ipmi,
						   connection_closed,
						   solll);
		return;
	    }
	} else if (solll->state == SOL_OPEN && !solll->read_err) {
	    if (err)
		solll->read_err = err;
	    else
		solll->read_err = GE_NOTREADY;
	    check_for_read_delivery(solll);
	}
	break;

    case ipmi_sol_state_connecting:
	break;

    case ipmi_sol_state_connected:
	if (solll->state == SOL_IN_SOL_OPEN) {
	    solll->state = SOL_OPEN;
	    sol_unlock(solll);
	    solll->open_done(solll->cb_data, err, solll->open_data);
	    sol_lock(solll);
	}
	break;

    case ipmi_sol_state_connected_ctu:
	break;

    case ipmi_sol_state_closing:
	break;
    }
    sol_unlock(solll);
}

static void
conn_changed(ipmi_con_t   *ipmi,
	     int          err,
	     unsigned int port_num,
	     int          any_port_up,
	     void         *cb_data)
{
    struct sol_ll *solll = cb_data;

    if (err)
	err = sol_xlat_ipmi_err(solll->o, err);

    sol_lock(solll);
    if (any_port_up == solll->last_any_port_up)
	goto out_unlock;

    solll->last_any_port_up = any_port_up;

    if (solll->state == SOL_IN_OPEN || solll->state == SOL_IN_SOL_OPEN) {
	if (any_port_up && solll->state == SOL_IN_OPEN) {
	    solll->state = SOL_IN_SOL_OPEN;
	    err = ipmi_sol_open(solll->sol);
	    if (!err) {
		sol_unlock(solll);
		return;
	    }
	    any_port_up = 0;
	    err = sol_xlat_ipmi_err(solll->o, err);
	}
	if (!any_port_up && (err || solll->read_err)) {
	    solll->state = SOL_CLOSED;
	    if (solll->read_err)
		err = solll->read_err; /* Prefer the first error we got. */
	    if (solll->sol) {
		ipmi_sol_free(solll->sol);
		solll->sol = NULL;
	    }
	    if (solll->ipmi) {
		solll->ipmi->close_connection(solll->ipmi);
		solll->ipmi = NULL;
	    }
	    sol_unlock(solll);
	    solll->open_done(solll->cb_data, err, solll->open_data);
	    return;
	}
    } else if (solll->state == SOL_IN_CLOSE) {
	if (!any_port_up) {
	    solll->state = SOL_CLOSED;
	    sol_unlock(solll);
	    solll->close_done(solll->cb_data, solll->open_data);
	    return;
	}
    } else if (err) {
	solll->read_err = err;
	check_for_read_delivery(solll);
    } else if (!any_port_up) {
	solll->read_err = GE_NOTREADY;
	check_for_read_delivery(solll);
    }

 out_unlock:
    sol_unlock(solll);
}

static int
sol_open(struct gensio_ll *ll, gensio_ll_open_done done, void *open_data)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int err;

    sol_lock(solll);
    if (solll->state != SOL_CLOSED) {
	err = GE_INUSE;
	goto out_unlock;
    }

    solll->in_read = false;
    solll->write_outstanding = 0;
    solll->read_err = 0;
    solll->deferred_read = false;
    solll->deferred_write = false;
    gensio_buffer_reset(&solll->read_data);
    solll->nacks_sent = 0;

    err = ipmi_args_setup_con(solll->args, gensio_os_handler, NULL,
			      &solll->ipmi);
    if (err)
	goto out_unlock;

    err = ipmi_sol_create(solll->ipmi, &solll->sol);
    if (err)
	goto out_err;

    err = ipmi_sol_register_data_received_callback(solll->sol,
						   sol_data_received, solll);
    if (err)
	goto out_err;

    err = ipmi_sol_register_break_detected_callback(solll->sol,
						    sol_break_detected, solll);
    if (err)
	goto out_err;

    err = ipmi_sol_register_bmc_transmit_overrun_callback(solll->sol,
							  bmc_transmit_overrun,
							  solll);
    if (err)
	goto out_err;

    err = ipmi_sol_register_connection_state_callback(solll->sol,
						      sol_connection_state,
						      solll);
    if (err)
	goto out_err;

    ipmi_sol_set_ACK_retries(solll->sol, solll->ack_retries);
    ipmi_sol_set_ACK_timeout(solll->sol, solll->ack_timeout);
    ipmi_sol_set_use_authentication(solll->sol, solll->authenticated);
    ipmi_sol_set_use_encryption(solll->sol, solll->encrypted);
    ipmi_sol_set_shared_serial_alert_behavior(solll->sol,
				solll->shared_serial_alert_behavior);
    ipmi_sol_set_deassert_CTS_DCD_DSR_on_connect(solll->sol,
				solll->deassert_CTS_DCD_DSR_on_connect);

    ipmi_sol_set_bit_rate(solll->sol, solll->speed);

    err = solll->ipmi->add_con_change_handler(solll->ipmi, conn_changed, solll);
    if (err)
	goto out_err;

    solll->last_any_port_up = 0;
    solll->state = SOL_IN_OPEN;
    solll->open_done = done;
    solll->open_data = open_data;

    err = solll->ipmi->start_con(solll->ipmi);
    if (err)
	goto out_err;

    sol_unlock(solll);
    return GE_INPROGRESS;

 out_err:
    if (solll->sol) {
	ipmi_sol_close(solll->sol);
	ipmi_sol_free(solll->sol);
	solll->sol = NULL;
    }
    if (solll->ipmi) {
	solll->ipmi->close_connection(solll->ipmi);
	solll->ipmi = NULL;
    }
 out_unlock:
    sol_unlock(solll);
    if (err)
	err = sol_xlat_ipmi_err(solll->o, err);
    return err;
}

static int sol_close(struct gensio_ll *ll, gensio_ll_close_done done,
		    void *close_data)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int err = GE_NOTREADY;

    sol_lock(solll);
    if (solll->state == SOL_OPEN || solll->state == SOL_IN_OPEN ||
		solll->state == SOL_IN_SOL_OPEN) {
	solll->read_enabled = false;
	solll->write_enabled = false;
	solll->close_done = done;
	solll->close_data = close_data;
	solll->state = SOL_IN_CLOSE;
	if (solll->sol) {
	    if (solll->write_outstanding == 0)
		err = ipmi_sol_close(solll->sol);
	    else
		err = 0;
	} else {
	    err = solll->ipmi->close_connection_done(solll->ipmi,
						     connection_closed,
						     solll);
	}

	if (err)
	    err = sol_xlat_ipmi_err(solll->o, err);
    }
    sol_unlock(solll);

    return err;
}

static void
sol_set_read_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct sol_ll *solll = ll_to_sol(ll);

    sol_lock(solll);
    if (solll->read_enabled != enabled) {
	solll->read_enabled = enabled;

	if (enabled && solll->state == SOL_OPEN) {
	    solll->deferred_read = true;
	    sol_sched_deferred_op(solll);
	}
    }
    sol_unlock(solll);
}

static void
sol_set_write_callback_enable(struct gensio_ll *ll, bool enabled)
{
    struct sol_ll *solll = ll_to_sol(ll);

    sol_lock(solll);
    if (solll->write_enabled != enabled) {
	solll->write_enabled = enabled;

	if (enabled && solll->state == SOL_OPEN &&
		solll->write_outstanding < solll->max_write_size) {
	    solll->deferred_write = true;
	    sol_sched_deferred_op(solll);
	}
    }
    sol_unlock(solll);
}

static void sol_free(struct gensio_ll *ll)
{
    struct sol_ll *solll = ll_to_sol(ll);

    sol_lock(solll);
    sol_deref_and_unlock(solll);
}

static void sol_disable(struct gensio_ll *ll)
{
    struct sol_ll *solll = ll_to_sol(ll);

    solll->read_enabled = false;
    solll->write_enabled = false;
    solll->close_done = NULL;
    solll->state = SOL_CLOSED;
    if (solll->sol) {
	ipmi_sol_force_close_wsend(solll->sol, 0);
	solll->ipmi->disable(solll->ipmi);
	solll->ipmi->close_connection(solll->ipmi);
    }
}

static int ipmisol_do_break(struct gensio_ll *ll);

static int
sol_control(struct gensio_ll *ll, bool get, unsigned int option,
	    char *data, gensiods *datalen)
{
    switch(option) {
    case GENSIO_CONTROL_RADDR:
	if (!get)
	    return GE_NOTSUP;
	if (strtoul(data, NULL, 0) > 0)
	    return GE_NOTFOUND;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "ipmisol");
	return 0;

    case GENSIO_CONTROL_SEND_BREAK:
	if (get)
	    return GE_NOTSUP;
	return ipmisol_do_break(ll);

    default:
	return GE_NOTSUP;
    }
}

static int
gensio_ll_sol_func(struct gensio_ll *ll, int op, gensiods *count,
		   void *buf, const void *cbuf, gensiods buflen,
		   const char *const *auxdata)
{
    switch (op) {
    case GENSIO_LL_FUNC_SET_CALLBACK:
	sol_set_callbacks(ll, cbuf, buf);
	return 0;

    case GENSIO_LL_FUNC_WRITE_SG:
	return sol_write(ll, count, cbuf, buflen);

    case GENSIO_LL_FUNC_OPEN:
	return sol_open(ll, cbuf, buf);

    case GENSIO_LL_FUNC_CLOSE:
	return sol_close(ll, cbuf, buf);

    case GENSIO_LL_FUNC_SET_READ_CALLBACK:
	sol_set_read_callback_enable(ll, buflen);
	return 0;

    case GENSIO_LL_FUNC_SET_WRITE_CALLBACK:
	sol_set_write_callback_enable(ll, buflen);
	return 0;

    case GENSIO_LL_FUNC_FREE:
	sol_free(ll);
	return 0;

    case GENSIO_LL_FUNC_DISABLE:
	sol_disable(ll);
	return 0;

    case GENSIO_LL_FUNC_CONTROL:
	return sol_control(ll, *((bool *) cbuf), buflen, buf, count);

    default:
	return GE_NOTSUP;
    }
}

static void
ipmisol_flush_done(ipmi_sol_conn_t *conn, int error,
		   int queue_selectors_flushed, void *cb_data)
{
    struct sol_ll *solll = cb_data;
    int rv;

    sol_lock(solll);
    if (solll->state == SOL_OPEN && solll->pending_break) {
	/* A flush came in while one was pending, do it. */
	rv = ipmi_sol_flush(solll->sol, solll->pending_break,
			    ipmisol_flush_done, solll);
	if (!rv) {
	    solll->pending_flush = 0;
	    sol_ref(solll);
	}
    }
    sol_deref_and_unlock(solll);
}

static int ipmisol_do_flush(struct gensio_ll *ll, int val)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int rv;

    switch(val) {
    case SERGENSIO_FLUSH_RCV_BUFFER:
	val = IPMI_SOL_BMC_RECEIVE_QUEUE;
	break;

    case SERGENSIO_FLUSH_XMIT_BUFFER:
	val = IPMI_SOL_BMC_TRANSMIT_QUEUE;
	break;

    case SERGENSIO_FLUSH_RCV_XMIT_BUFFERS:
	return GE_NOTSUP;

    default:
	return GE_INVAL;
    }

    sol_lock(solll);
    rv = ipmi_sol_flush(solll->sol, val, ipmisol_flush_done, solll);
    if (!rv) {
	sol_ref(solll);
    } else if (rv == EAGAIN) {
	solll->pending_flush |= val;
    } else if (rv == IPMI_SOL_ERR_VAL(IPMI_SOL_UNCONFIRMABLE_OPERATION)) {
	rv = 0; /* Operation done, but won't get a callback. */
    } else {
	rv = sol_xlat_ipmi_err(solll->o, rv);
    }
    sol_unlock(solll);

    return rv;
}

static void
ipmisol_break_done(ipmi_sol_conn_t *conn, int err, void *cb_data)
{
    struct sol_ll *solll = cb_data;
    int rv;

    sol_lock(solll);
    if (solll->state == SOL_OPEN && solll->pending_break) {
	/* A flush came in while one was pending, do it. */
	rv = ipmi_sol_send_break(solll->sol, ipmisol_break_done, solll);
	if (!rv) {
	    solll->pending_break = 0;
	    sol_ref(solll);
	}
    }
    sol_deref_and_unlock(solll);
}

static int ipmisol_do_break(struct gensio_ll *ll)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int rv;

    sol_lock(solll);
    rv = ipmi_sol_send_break(solll->sol, ipmisol_break_done, solll);
    if (!rv) {
	sol_ref(solll);
    } else if (rv == EAGAIN) {
	solll->pending_break = 1;
    } else if (rv == IPMI_SOL_ERR_VAL(IPMI_SOL_UNCONFIRMABLE_OPERATION)) {
	rv = 0; /* Operation done, but won't get a callback. */
    } else {
	rv = sol_xlat_ipmi_err(solll->o, rv);
    }
    sol_unlock(solll);

    return rv;
}

static void
ipmisol_op_done(ipmi_sol_conn_t *conn, int err, void *icb_data)
{
    struct sol_op_done **op_done = icb_data;
    struct sol_ll *solll = (*op_done)->solll;

    sol_lock(solll);
    sol_op_done(solll, err, op_done);
    sol_deref_and_unlock(solll);
}

static int
sol_start_op(struct sol_ll *solll, struct sol_op_done *op,
	     struct sol_op_done **op_done)
{
    int rv;

    rv = op->func(solll->sol, op->val, ipmisol_op_done, op_done);
    switch (rv) {
    case 0:
	op->started = true;
	sol_ref(solll);
	break;

    case IPMI_SOL_ERR_VAL(IPMI_SOL_UNCONFIRMABLE_OPERATION):
	op->started = true;
	op->use_runner = true;
	rv = 0; /* Operation done, but won't get a callback. */
	/* Schedule the callback in the runner. */
	sol_sched_deferred_op(solll);
	break;

    case EAGAIN:
	/* Should not happen. */
	rv = GE_INUSE;
	break;

    default:
	rv = sol_xlat_ipmi_err(solll->o, rv);
	break;
    }

    return rv;
}

static void
sol_op_done(struct sol_ll *solll, int err, struct sol_op_done **op_done)
{
    struct gensio_os_funcs *o = solll->o;
    struct sol_op_done *op = *op_done;
    sergensio_done cb;
    void *cb_data;
    int val;

 restart:
    if (err)
	err = sol_xlat_ipmi_err(solll->o, err);

    cb = op->cb;
    cb_data = op->cb_data;
    val = op->done_val;
    *op_done = op->next;
    o->free(o, op);
    if (cb) {
	sol_unlock(solll);
	cb(solll->sio, err, val, cb_data);
	sol_lock(solll);
    }
    op = *op_done;
    if (op && !op->started) {
	err = sol_start_op(solll, op, op_done);
	if (err)
	    goto restart;
    }
}

static int
sol_do_op(struct sol_ll *solll, struct sol_op_done **op_done,
	  int (*func)(ipmi_sol_conn_t *, int, ipmi_sol_transmit_complete_cb,
		      void *),
	  int val, int done_val, sergensio_done done, void *cb_data)
{
    struct gensio_os_funcs *o = solll->o;
    struct sol_op_done *op, *op2;
    int rv = 0;

    op = o->zalloc(o, sizeof(*op));
    if (!op)
	return GE_NOMEM;

    op->use_runner = false;
    op->solll = solll;
    op->cb = done;
    op->cb_data = cb_data;
    op->val = val;
    op->done_val = done_val;
    op->func = func;
    op->next = NULL;

    if (*op_done) {
	/* Something already in progress, just queue it. */
	op2 = *op_done;
	while (op2->next)
	    op2 = op2->next;
	op2->next = op;
    } else {
	rv = sol_start_op(solll, op, op_done);
	if (rv)
	    o->free(o, op);
	else
	    *op_done = op;
    }

    return rv;
}

static int ipmisol_do_cts(struct gensio_ll *ll, int ival,
			  sergensio_done done, void *cb_data)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int rv, val;

    sol_lock(solll);
    switch (ival) {
    case SERGENSIO_CTS_AUTO:
	val = 1;
	break;
    case SERGENSIO_CTS_OFF:
	val = 0;
	break;
    default:
	rv = GE_INVAL;
	goto out_unlock;
    }
    rv = sol_do_op(solll, &solll->cts_done, ipmi_sol_set_CTS_assertable,
		   val, ival, done, cb_data);
 out_unlock:
    sol_unlock(solll);

    return rv;
}

static int ipmisol_do_dcd_dsr(struct gensio_ll *ll, int ival,
			      sergensio_done done, void *cb_data)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int rv, val;

    sol_lock(solll);
    switch (ival) {
    case SERGENSIO_DCD_DSR_ON:
	val = 1;
	break;
    case SERGENSIO_DCD_DSR_OFF:
	val = 0;
	break;
    default:
	rv = GE_INVAL;
	goto out_unlock;
    }
    rv = sol_do_op(solll, &solll->dcd_dsr_done, ipmi_sol_set_DCD_DSR_asserted,
		   val, ival, done, cb_data);
 out_unlock:
    sol_unlock(solll);

    return rv;
}

static int ipmisol_do_ri(struct gensio_ll *ll, int ival,
			  sergensio_done done, void *cb_data)
{
    struct sol_ll *solll = ll_to_sol(ll);
    int rv, val;

    sol_lock(solll);
    switch (ival) {
    case SERGENSIO_RI_ON:
	val = 1;
	break;
    case SERGENSIO_RI_OFF:
	val = 0;
	break;
    default:
	rv = GE_INVAL;
	goto out_unlock;
    }
    rv = sol_do_op(solll, &solll->ri_done, ipmi_sol_set_RI_asserted,
		   val, ival, done, cb_data);
 out_unlock:
    sol_unlock(solll);

    return rv;
}

static int
ipmisol_ser_ops(struct gensio_ll *ll, int op,
		int val, char *buf,
		void *done, void *cb_data)
{
    switch (op) {
    case SERGENSIO_FUNC_FLUSH:
	return ipmisol_do_flush(ll, val);

    case SERGENSIO_FUNC_SEND_BREAK:
	return ipmisol_do_break(ll);

    case SERGENSIO_FUNC_CTS:
	return ipmisol_do_cts(ll, val, done, cb_data);

    case SERGENSIO_FUNC_DCD_DSR:
	return ipmisol_do_dcd_dsr(ll, val, done, cb_data);

    case SERGENSIO_FUNC_RI:
	return ipmisol_do_ri(ll, val, done, cb_data);

    /* You really can't set much on a SOL connection once it's up. */
    case SERGENSIO_FUNC_BAUD:
    case SERGENSIO_FUNC_DATASIZE:
    case SERGENSIO_FUNC_PARITY:
    case SERGENSIO_FUNC_STOPBITS:
    case SERGENSIO_FUNC_FLOWCONTROL:
    case SERGENSIO_FUNC_IFLOWCONTROL:
    case SERGENSIO_FUNC_SBREAK:
    case SERGENSIO_FUNC_DTR:
    case SERGENSIO_FUNC_RTS:
    case SERGENSIO_FUNC_MODEMSTATE:
    case SERGENSIO_FUNC_LINESTATE:
    case SERGENSIO_FUNC_FLOWCONTROL_STATE:
    case SERGENSIO_FUNC_SIGNATURE:
    default:
	return GE_NOTSUP;
    }
}

static int
sol_get_defaults(struct sol_ll *solll)
{
    struct gensio_os_funcs *o = solll->o;
    char *speed;
    int ival, err;

    err = gensio_get_default(o, "sol", "speed", false,
			     GENSIO_DEFAULT_STR, &speed, NULL);
    if (err) {
	gensio_log(o, GENSIO_LOG_ERR, "Failed getting default sol speed: %s\n",
		   gensio_err_to_str(err));
	return err;
    }
    if (speed) {
	if (strncmp(speed, "9600", 4) == 0)
	    solll->speed = IPMI_SOL_BIT_RATE_9600;
	else if (strncmp(speed, "19200", 5) == 0)
	    solll->speed = IPMI_SOL_BIT_RATE_19200;
	else if (strncmp(speed, "38400", 5) == 0)
	    solll->speed = IPMI_SOL_BIT_RATE_38400;
	else if (strncmp(speed, "57600", 5) == 0)
	    solll->speed = IPMI_SOL_BIT_RATE_57600;
	else if (strncmp(speed, "115200", 6) == 0)
	    solll->speed = IPMI_SOL_BIT_RATE_115200;
	else {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Invalid default speed for SOL %s: %s."
		       " Defaulting to 9600",
		       solll->devname, speed);
	    solll->speed = IPMI_SOL_BIT_RATE_9600;
	}
	o->free(o, speed);
    }

    /* Enable authentication and encryption by default. */
    err = gensio_get_default(o, "sol", "authenticated", false,
			     GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    solll->authenticated = ival;
    err = gensio_get_default(o, "sol", "encrypted", false,
			     GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    solll->encrypted = ival;
    err = gensio_get_default(o, "sol", "nobreak", false,
			     GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    ival = solll->disablebreak;
    err = gensio_get_default(o, "sol", "ack-timeout", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    solll->ack_timeout = ival;
    err = gensio_get_default(o, "sol", "ack-retries", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    solll->ack_retries = ival;
    err = gensio_get_default(o, "sol", "shared-serial-alert", false,
			     GENSIO_DEFAULT_INT, NULL, &ival);
    if (err)
	return err;
    solll->shared_serial_alert_behavior = ival;
    err = gensio_get_default(o, "sol", "deassert-CTS-DCD-DSR-on-connect", false,
			     GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (err)
	return err;
    solll->deassert_CTS_DCD_DSR_on_connect = ival;

    return 0;
}

static int
sol_process_parm(struct sol_ll *solll, char *arg)
{
    if (strncmp(arg, "9600", 4) == 0) {
	solll->speed = IPMI_SOL_BIT_RATE_9600;
    } else if (strncmp(arg, "19200", 5) == 0) {
	solll->speed = IPMI_SOL_BIT_RATE_19200;
    } else if (strncmp(arg, "38400", 5) == 0) {
	solll->speed = IPMI_SOL_BIT_RATE_38400;
    } else if (strncmp(arg, "57600", 5) == 0) {
	solll->speed = IPMI_SOL_BIT_RATE_57600;
    } else if (strncmp(arg, "115200", 6) == 0) {
	solll->speed = IPMI_SOL_BIT_RATE_115200;
    } else if (gensio_check_keybool(arg, "nobreak", &solll->disablebreak) > 0) {
    } else if (gensio_check_keybool(arg, "authenticated",
				    &solll->authenticated) > 0) {
    } else if (gensio_check_keybool(arg, "encrypted", &solll->encrypted) > 0) {
    } else if (gensio_check_keybool(arg, "deassert-CTS-DCD-DSR-on-connect",
				    &solll->deassert_CTS_DCD_DSR_on_connect)
	       > 0) {
    } else if (strcasecmp(arg, "shared-serial-alert-fail") == 0) {
	solll->shared_serial_alert_behavior = ipmi_sol_serial_alerts_fail;
    } else if (strcmp(arg, "shared-serial-alert-deferred") == 0) {
	solll->shared_serial_alert_behavior = ipmi_sol_serial_alerts_deferred;
    } else if (strcmp(arg, "shared-serial-alert-succeed") == 0) {
	solll->shared_serial_alert_behavior = ipmi_sol_serial_alerts_succeed;
    } else if (gensio_check_keyuint(arg, "ack-timeout",
				    &solll->ack_timeout) > 0) {

    } else if (gensio_check_keyuint(arg, "ack-retries",
				    &solll->ack_retries) > 0) {

    /* The rest of the ones below are deprecated. */
    } else if (strcmp(arg, "-NOBREAK") == 0) {
	solll->disablebreak = false;
    } else if (strcmp(arg, "-authenticated") == 0) {
	solll->authenticated = false;
    } else if (strcmp(arg, "-encrypted") == 0) {
	solll->encrypted = false;
    } else if (strcmp(arg, "-deassert_CTS_DCD_DSR_on_connect") == 0) {
	solll->deassert_CTS_DCD_DSR_on_connect = false;
    } else if (strcmp(arg, "deassert_CTS_DCD_DSR_on_connect") == 0) {
	solll->deassert_CTS_DCD_DSR_on_connect = true;
    } else if (strcmp(arg, "shared_serial_alert_fail") == 0) {
	solll->shared_serial_alert_behavior = ipmi_sol_serial_alerts_fail;
    } else if (strcmp(arg, "shared_serial_alert_deferred") == 0) {
	solll->shared_serial_alert_behavior = ipmi_sol_serial_alerts_deferred;
    } else if (strcmp(arg, "shared_serial_alert_succeed") == 0) {
	solll->shared_serial_alert_behavior = ipmi_sol_serial_alerts_succeed;
    } else {
	return GE_INVAL;
    }

    return 0;
}

static int
sol_process_parms(struct sol_ll *solll)
{
    char *pos, *strtok_data;
    int err;

    pos = strchr(solll->devname, ',');
    if (!pos)
	return 0;

    *pos++ = '\0';
    for (pos = strtok_r(pos, ",", &strtok_data); pos;
	 pos = strtok_r(NULL, ",", &strtok_data)) {
	err = sol_process_parm(solll, pos);
	if (err)
	    return err;
    }

    return 0;
}

static struct gensio_once gensio_ipmi_initialized;
static int ipmi_init_err;


static void
gensio_sol_cleanup_mem(void)
{
    ipmi_shutdown();
}

static struct gensio_class_cleanup sol_cleanup = {
    gensio_sol_cleanup_mem
};


static void
gensio_ipmi_init(void *cb_data)
{
    struct gensio_os_funcs *o = cb_data;

    gensio_os_handler = gio_alloc(o);
    if (!gensio_os_handler)
	abort();
    ipmi_init_err = ipmi_init(gensio_os_handler);
    if (!ipmi_init_err)
	gensio_register_class_cleanup(&sol_cleanup);
}

int
ipmisol_gensio_ll_alloc(struct gensio_os_funcs *o,
			const char *devname,
			gensio_ll_ipmisol_cb ser_cbs,
			void *ser_cbs_data,
			gensiods max_read_size,
			gensiods max_write_size,
			gensio_ll_ipmisol_ops *rops,
			struct gensio_ll **rll)
{
    struct sol_ll *solll;
    int err, argc, curr_arg = 0;
    const char **argv;

    o->call_once(o, &gensio_ipmi_initialized, gensio_ipmi_init, o);

    if (ipmi_init_err)
	return sol_xlat_ipmi_err(o, ipmi_init_err);

    solll = o->zalloc(o, sizeof(*solll));
    if (!solll)
	return GE_NOMEM;

    solll->o = o;
    solll->refcount = 1;
    solll->state = SOL_CLOSED;
    solll->last_any_port_up = -1;

    solll->devname = gensio_strdup(o, devname);
    if (!solll->devname)
	goto out_nomem;

    err = sol_get_defaults(solll);
    if (!err)
	err = sol_process_parms(solll);
    if (err)
	goto out_err;

    err = gensio_str_to_argv(o, solll->devname, &argc, &argv, NULL);
    if (err)
	goto out_err;
    if (argc == 0) {
	err = GE_INVAL;
	goto out_err;
    }

    err = ipmi_parse_args2(&curr_arg, argc, (char **) argv, &solll->args);
    if (err) {
	gensio_argv_free(o, argv);
	goto out_err;
    }

    if (curr_arg != argc) {
	gensio_log(o, GENSIO_LOG_WARNING,
		   "Extra SOL arguments starting with %s\n", argv[curr_arg]);
	err = GE_INVAL;
	gensio_argv_free(o, argv);
	goto out_err;
    }
    gensio_argv_free(o, argv);

    solll->deferred_op_runner = o->alloc_runner(o, sol_deferred_op, solll);
    if (!solll->deferred_op_runner)
	goto out_nomem;

    solll->lock = o->alloc_lock(o);
    if (!solll->lock)
	goto out_nomem;

    solll->xmit_done_lock = o->alloc_lock(o);
    if (!solll->xmit_done_lock)
	goto out_nomem;
    gensio_list_init(&solll->xmit_dones);

    solll->xmit_done_runner = o->alloc_runner(o, handle_xmit_dones, solll);
    if (!solll->xmit_done_runner)
	goto out_nomem;

    solll->read_data.maxsize = max_read_size;
    solll->read_data.buf = o->zalloc(o, max_read_size);
    if (!solll->read_data.buf)
	goto out_nomem;

    solll->max_write_size = max_write_size;

    solll->ll = gensio_ll_alloc_data(o, gensio_ll_sol_func, solll);
    if (!solll->ll)
	goto out_nomem;

    /* Don't set these until here lest a failure call the free operation. */
    solll->ser_cbs = ser_cbs;
    solll->ser_cbs_data = ser_cbs_data;

    *rops = ipmisol_ser_ops;
    *rll = solll->ll;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    sol_finish_free(solll);
    return err;
}

void
ipmisol_gensio_ll_set_sio(struct gensio_ll *ll, struct sergensio *sio)
{
    struct sol_ll *solll = ll_to_sol(ll);

    solll->sio = sio;
}
