/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2025  Corey Minyard <minyard@acm.org>
 *
 *  This is an OpenIPMI os handler that you can create from a
 *  gensio_os_funcs.
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_utils.h>
#include <gensio/gensio_openipmi_oshandler.h>

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

static void
gio_free_os_handler(os_handler_t *handler)
{
    struct igensio_info *info = handler->internal_data;

    ipmi_free_os_handler(handler);
    free(info);
}

void ipmi_malloc_init(os_handler_t *oshandler);
void ipmi_malloc_shutdown(void);

os_handler_t *
gensio_openipmi_oshandler_alloc(struct gensio_os_funcs *o)
{
    struct igensio_info *info;
    os_handler_t *handler;
    os_handler_t dummyh;

    info = malloc(sizeof(*info));
    if (!info)
	return NULL;
    info->o = o;
    info->log_handler = NULL;

    /*
     * This is a cheap hack, get enough of an os handler to allocate one
     * with ipmi_alloc_os_handler(), then shut it down and let the main
     * os handler take over.
     */
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
    handler->free_os_handler = gio_free_os_handler;

    handler->internal_data = info;
    return handler;
};
