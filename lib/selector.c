/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This file holds code to abstract the "select" call and make it
   easier to use.  The main thread lives here, the rest of the code
   uses a callback interface.  Basically, other parts of the program
   can register file descriptors with this code, when interesting
   things happen on those file descriptors this code will call
   routines registered with it. */

#include "config.h"
#include <gensio/selector.h>

#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_EPOLL_PWAIT
#include <sys/epoll.h>
#else
#define EPOLL_CTL_ADD 0
#define EPOLL_CTL_DEL 0
#define EPOLL_CTL_MOD 0
#endif
#include "errtrig.h"

#ifndef EBADFD
/* At least MacOS doesn't have EBADFD. */
#define EBADFD EBADF
#endif

static void *
sel_alloc(unsigned int size)
{
    void *d;

    if (do_errtrig())
	return NULL;

    d = malloc(size);
    if (d)
	memset(d, 0, size);
    return d;
}

struct sel_runner_s
{
    struct selector_s *sel;
    sel_runner_func_t func;
    void *cb_data;
    int in_use;
    sel_runner_t *next;
};

typedef struct fd_state_s
{
    int               deleted;
    unsigned int      use_count;
    sel_fd_cleared_cb done;
    sel_runner_t      done_runner;
    int               tmp_fd;
    void              *done_cbdata;
} fd_state_t;

/* The control structure for each file descriptor. */
typedef struct fd_control_s
{
    /* This structure is allocated when an FD is set and it holds
       whether the FD has been deleted and information to handle the
       deletion. */
    fd_state_t       *state;

    /* Link in the hash list. */
    struct fd_control_s *next;

    /* Handlers for various events on an fd. */
    void             *data; /* Passed to the handlers */
    sel_fd_handler_t handle_read;
    sel_fd_handler_t handle_write;
    sel_fd_handler_t handle_except;

    int fd;

    /* Keep track of whether the event is enabled here. */
    char read_enabled;
    char write_enabled;
    char except_enabled;

#ifdef HAVE_EPOLL_PWAIT
    /* See the comment in process_fds_epoll() on the use of this. */
    uint32_t saved_events;
#endif
} fd_control_t;

typedef struct heap_val_s
{
    /* Set this to the function to call when the timeout occurs. */
    sel_timeout_handler_t handler;

    /* Set this to whatever you like.  You can use this to store your
       own data. */
    void *user_data;

    /* Set this to the time when the timer will go off. */
    struct timeval timeout;

    /* Who owns me? */
    struct selector_s *sel;

    /* Am I currently running? */
    int in_heap;

    /* Am I currently stopped? */
    int stopped;

    /* Have I been freed? */
    int freed;

    /* Am I currently in a handler? */
    int in_handler;

    sel_timeout_handler_t done_handler;
    void *done_cb_data;
} heap_val_t;

typedef struct theap_s theap_t;
#define heap_s theap_s
#define heap_node_s sel_timer_s
#define HEAP_EXPORT_NAME(s) theap_ ## s
#define HEAP_NAMES_LOCAL static
#define HEAP_OUTPUT_PRINTF "(%ld.%7.7ld)"
#define HEAP_OUTPUT_DATA pos->timeout.tv_sec, pos->timeout.tv_usec

static int
cmp_timeval(const struct timeval *tv1, const struct timeval *tv2)
{
    if (tv1->tv_sec < tv2->tv_sec)
	return -1;

    if (tv1->tv_sec > tv2->tv_sec)
	return 1;

    if (tv1->tv_usec < tv2->tv_usec)
	return -1;

    if (tv1->tv_usec > tv2->tv_usec)
	return 1;

    return 0;
}

static int
heap_cmp_key(heap_val_t *v1, heap_val_t *v2)
{
    return cmp_timeval(&v1->timeout, &v2->timeout);
}

#include "heap.h"

/* Used to build a list of threads that may need to be woken if a
   timer on the top of the heap changes, or an FD is added/removed.
   See i_wake_sel_thread() for more info. */
typedef struct sel_wait_list_s
{
    /* The thread to wake up. */
    long            thread_id;

    /* How to wake it. */
    sel_send_sig_cb send_sig;
    void            *send_sig_cb_data;

    /* The time when the thread is set to wake up. */
    struct timeval wake_time;
#ifdef BROKEN_PSELECT
    struct timespec *wait_time;
    bool signalled;
#endif
    struct sel_wait_list_s *next, *prev;
} sel_wait_list_t;

struct selector_s
{
    /* This is an hash table of file descriptors. */
    fd_control_t *fds[FD_SETSIZE];

    /* If something is deleted, we increment this count.  This way when
       a select/epoll returns a non-timeout, we know that we need to ignore
       it as it may be  from the just deleted fd. */
    unsigned long fd_del_count;

    void *fd_lock;

    /* The timer heap. */
    theap_t timer_heap;

    /* This is a list of items waiting to be woken up because they are
       sitting in a select.  See i_wake_sel_thread() for more info. */
    sel_wait_list_t wait_list;

    void *timer_lock;

    sel_runner_t *runner_head;
    sel_runner_t *runner_tail;

    int wake_sig;

#ifdef HAVE_EPOLL_PWAIT
    int epollfd;
#endif
    sel_lock_t *(*sel_lock_alloc)(void *cb_data);
    void (*sel_lock_free)(sel_lock_t *);
    void (*sel_lock)(sel_lock_t *);
    void (*sel_unlock)(sel_lock_t *);

    /* Everything below is only used for select() and ignore for epoll. */

    /* These are the offical fd_sets used to track what file descriptors
       need to be monitored. */
    volatile fd_set read_set;
    volatile fd_set write_set;
    volatile fd_set except_set;

    volatile int maxfd; /* The largest file descriptor registered with
			   this code. */
};

static void
sel_timer_lock(struct selector_s *sel)
{
    if (sel->sel_lock)
	sel->sel_lock(sel->timer_lock);
}

static void
sel_timer_unlock(struct selector_s *sel)
{
    if (sel->sel_lock)
	sel->sel_unlock(sel->timer_lock);
}

static void
sel_fd_lock(struct selector_s *sel)
{
    if (sel->sel_lock)
	sel->sel_lock(sel->fd_lock);
}

static void
sel_fd_unlock(struct selector_s *sel)
{
    if (sel->sel_lock)
	sel->sel_unlock(sel->fd_lock);
}

/* This function will wake the SEL thread.  It must be called with the
   timer lock held, because it messes with timeout.

   For broken pselect(), where the signal mask is not applied
   atomically, we have a workaround.  The operation is is subtle, but
   it does work.  We have a pointer to the actual timeout passed in to
   pselect.  When we want to wake the pselect, we set the timeout to
   zero first.  That way, if the select has calculated the timeout but
   has not yet called select, then this will set it to zero (causing
   it to wait zero time).  If select has already been called, then the
   signal send should wake it up.  We only need to do this after we
   have calculated the timeout, but before we have called select, thus
   only things in the wait list matter. */
static void
i_wake_sel_thread(struct selector_s *sel, struct timeval *new_timeout)
{
    sel_wait_list_t *item;

    item = sel->wait_list.next;
    while (item != &sel->wait_list) {
	if (item->send_sig && (!new_timeout ||
			       cmp_timeval(new_timeout, &item->wake_time) < 0))
	{
#ifdef BROKEN_PSELECT
	    item->signalled = true;
	    item->wait_time->tv_sec = 0;
	    item->wait_time->tv_nsec = 0;
#endif
	    item->send_sig(item->thread_id, item->send_sig_cb_data);
	}
	item = item->next;
    }
}

void
sel_wake_all(struct selector_s *sel)
{
    sel_timer_lock(sel);
    i_wake_sel_thread(sel, NULL);
    sel_timer_unlock(sel);
}

static void
i_sel_wake_first(struct selector_s *sel)
{
    sel_wait_list_t *item;

    item = sel->wait_list.next;
    if (item->send_sig && item != &sel->wait_list) {
#ifdef BROKEN_PSELECT
	item->signalled = true;
	item->wait_time->tv_sec = 0;
	item->wait_time->tv_nsec = 0;
#endif
	item->send_sig(item->thread_id, item->send_sig_cb_data);
    }
}

/* See comment on i_wake_sel_thread() for notes on BROKEN_PSELECT. */
void
sel_wake_one(struct selector_s *sel, long thread_id, sel_send_sig_cb killer,
	     void *cb_data)
{
#ifdef BROKEN_PSELECT
    sel_wait_list_t *item;
#endif

    sel_timer_lock(sel);
#ifdef BROKEN_PSELECT
    item = sel->wait_list.next;
    while (item != &sel->wait_list) {
	if (thread_id == item->thread_id) {
	    item->signalled = true;
	    item->wait_time->tv_sec = 0;
	    item->wait_time->tv_nsec = 0;
	    break;
	}
	item = item->next;
    }
#endif
    killer(thread_id, cb_data);
    sel_timer_unlock(sel);
}

static void
wake_timer_sel_thread(struct selector_s *sel, volatile sel_timer_t *old_top,
		      struct timeval *new_timeout)
{
    if (old_top != theap_get_top(&sel->timer_heap))
	/* If the top value changed, restart the waiting threads if required. */
	i_wake_sel_thread(sel, new_timeout);
}

/* Wait list management.  These *must* be called with the timer list
   locked, and the values in the item *must not* change while in the
   list. */
static void
add_sel_wait_list(struct selector_s *sel, sel_wait_list_t *item,
		  sel_send_sig_cb send_sig,
		  void            *cb_data,
		  long thread_id,
		  struct timeval *wake_time, struct timespec *wait_time)
{
    item->thread_id = thread_id;
    item->send_sig = send_sig;
    item->send_sig_cb_data = cb_data;
    item->wake_time = *wake_time;
#ifdef BROKEN_PSELECT
    item->wait_time = wait_time;
    item->signalled = false;
#endif
    item->next = sel->wait_list.next;
    item->prev = &sel->wait_list;
    sel->wait_list.next->prev = item;
    sel->wait_list.next = item;
}
static void
remove_sel_wait_list(struct selector_s *sel, sel_wait_list_t *item)
{
    item->next->prev = item->prev;
    item->prev->next = item->next;
}

/* Initialize a single file descriptor. */
static void
init_fd(fd_control_t *fd)
{
    fd->state = NULL;
    fd->data = NULL;
    fd->handle_read = NULL;
    fd->handle_write = NULL;
    fd->handle_except = NULL;
    fd->read_enabled = 0;
    fd->write_enabled = 0;
    fd->except_enabled = 0;
}

#ifdef HAVE_EPOLL_PWAIT
static int
sel_update_fd(struct selector_s *sel, fd_control_t *fdc, int op)
{
    struct epoll_event event;
    int rv;

    if (sel->epollfd < 0)
	return 1;

    memset(&event, 0, sizeof(event));
    event.events = EPOLLONESHOT;
    event.data.fd = fdc->fd;
    if (fdc->saved_events) {
	if (op == EPOLL_CTL_DEL)
	    return 0;
	if (!fdc->read_enabled && !fdc->except_enabled)
	    return 0;
	fdc->saved_events = 0;
	op = EPOLL_CTL_ADD;
	if (fdc->read_enabled)
	    event.events |= EPOLLIN | EPOLLHUP;
	if (fdc->except_enabled)
	    event.events |= EPOLLERR | EPOLLPRI;
    } else if (op != EPOLL_CTL_DEL) {
	if (fdc->read_enabled)
	    event.events |= EPOLLIN | EPOLLHUP;
	if (fdc->write_enabled)
	    event.events |= EPOLLOUT;
	if (fdc->except_enabled)
	    event.events |= EPOLLERR | EPOLLPRI;
    }
    /* This should only fail due to system problems, and if that's the case,
       well, we should probably terminate. */
    rv = epoll_ctl(sel->epollfd, op, fdc->fd, &event);
    if (rv) {
	perror("epoll_ctl");
	assert(0);
    }
    return 0;
}
#else
static int
sel_update_fd(struct selector_s *sel, fd_control_t *fdc, int op)
{
    return 1;
}
#endif

static void
finish_oldstate(sel_runner_t *runner, void *cbdata)
{
    fd_state_t *oldstate = cbdata;

    if (oldstate->done)
	oldstate->done(oldstate->tmp_fd, oldstate->done_cbdata);
    free(oldstate);
}

/* Must be called with sel fd lock held. */
static fd_control_t *
get_fd(struct selector_s *sel, int fd)
{
    fd_control_t *fdc = sel->fds[fd % FD_SETSIZE];

    while (fdc && fdc->fd != fd)
	fdc = fdc->next;
    return fdc;
}

static void
valid_fd(struct selector_s *sel, int fd, fd_control_t **rfdc)
{
    fd_control_t *fdc;

    assert(fd >= 0);
    fdc = get_fd(sel, fd);
    assert(fdc != NULL);
    *rfdc = fdc;
}

/* Set the handlers for a file descriptor. */
int
sel_set_fd_handlers(struct selector_s *sel,
		    int               fd,
		    void              *data,
		    sel_fd_handler_t  read_handler,
		    sel_fd_handler_t  write_handler,
		    sel_fd_handler_t  except_handler,
		    sel_fd_cleared_cb done)
{
    fd_control_t *fdc;
    fd_state_t   *state, *oldstate = NULL;
    void         *olddata = NULL;
    int          added = 1;

#ifdef HAVE_EPOLL_PWAIT
    if (sel->epollfd < 0 && fd >= FD_SETSIZE)
	return EMFILE;
#endif

    state = sel_alloc(sizeof(*state));
    if (!state)
	return ENOMEM;
    memset(state, 0, sizeof(*state));
    state->done = done;
    memset(&state->done_runner, 0, sizeof(state->done_runner));
    state->done_runner.sel = sel;

    sel_fd_lock(sel);
    fdc = get_fd(sel, fd);
    if (!fdc) {
	fdc = sel_alloc(sizeof(*fdc));
	if (!fdc) {
	    sel_fd_unlock(sel);
	    free(state);
	    return ENOMEM;
	}
	fdc->fd = fd;
	/* Add it to the list. */
	fdc->next = sel->fds[fd % FD_SETSIZE];
	sel->fds[fd % FD_SETSIZE] = fdc;
    }

    if (fdc->state) {
	oldstate = fdc->state;
	olddata = fdc->data;
	added = 0;
#ifdef HAVE_EPOLL_PWAIT
	fdc->saved_events = 0;
#endif
	sel->fd_del_count++;
    }
    fdc->state = state;
    fdc->data = data;
    fdc->handle_read = read_handler;
    fdc->handle_write = write_handler;
    fdc->handle_except = except_handler;

    if (added) {
	/* Move maxfd up if necessary. */
	if (fd > sel->maxfd)
	    sel->maxfd = fd;

	if (sel_update_fd(sel, fdc, EPOLL_CTL_ADD))
	    sel_wake_all(sel);
    } else {
	if (sel_update_fd(sel, fdc, EPOLL_CTL_MOD))
	    sel_wake_all(sel);
    }
    sel_fd_unlock(sel);

    if (oldstate) {
	oldstate->deleted = 1;
	if (oldstate->use_count == 0) {
	    oldstate->tmp_fd = fd;
	    oldstate->done_cbdata = olddata;
	    sel_run(&oldstate->done_runner, finish_oldstate, oldstate);
	}
    }
    return 0;
}

static void
i_sel_clear_fd_handler(struct selector_s *sel, int fd, int rpt)
{
    fd_control_t *fdc;
    fd_state_t   *oldstate = NULL;
    void         *olddata = NULL;

    sel_fd_lock(sel);
    valid_fd(sel, fd, &fdc);

    if (fdc->state) {
	oldstate = fdc->state;
	olddata = fdc->data;
	fdc->state = NULL;

	sel_update_fd(sel, fdc, EPOLL_CTL_DEL);
#ifdef HAVE_EPOLL_PWAIT
	fdc->saved_events = 0;
#endif
	sel->fd_del_count++;
    }

    init_fd(fdc);
#ifdef HAVE_EPOLL_PWAIT
    if (sel->epollfd < 0)
#endif
    {
	FD_CLR(fd, &sel->read_set);
	FD_CLR(fd, &sel->write_set);
	FD_CLR(fd, &sel->except_set);
    }

    /* Move maxfd down if necessary. */
    if (fd == sel->maxfd) {
	while (sel->maxfd >= 0 && (!sel->fds[sel->maxfd] ||
				   !sel->fds[sel->maxfd]->state))
	    sel->maxfd--;
    }

    if (oldstate) {
	oldstate->deleted = 1;
	if (!rpt)
	    oldstate->done = NULL;
	if (oldstate->use_count == 0) {
	    oldstate->tmp_fd = fd;
	    oldstate->done_cbdata = olddata;
	    sel_run(&oldstate->done_runner, finish_oldstate, oldstate);
	}
    }

    sel_fd_unlock(sel);
}

/* Clear the handlers for a file descriptor and remove it from
   select's monitoring. */
void
sel_clear_fd_handlers(struct selector_s *sel, int fd)
{
    i_sel_clear_fd_handler(sel, fd, 1);
}

/* Clear the handlers for a file descriptor and remove it from
   select's monitoring, except that fd_cleared is not called. */
void
sel_clear_fd_handlers_norpt(struct selector_s *sel, int fd)
{
    i_sel_clear_fd_handler(sel, fd, 0);
}

/* Set whether the file descriptor will be monitored for data ready to
   read on the file descriptor. */
void
sel_set_fd_read_handler(struct selector_s *sel, int fd, int state)
{
    fd_control_t *fdc;

    sel_fd_lock(sel);
    valid_fd(sel, fd, &fdc);

    if (!fdc->state)
	goto out;

    if (state == SEL_FD_HANDLER_ENABLED) {
	if (fdc->read_enabled)
	    goto out;
	fdc->read_enabled = 1;
#ifdef HAVE_EPOLL_PWAIT
	if (sel->epollfd < 0)
#endif
	    FD_SET(fd, &sel->read_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	if (!fdc->read_enabled)
	    goto out;
	fdc->read_enabled = 0;
#ifdef HAVE_EPOLL_PWAIT
	if (sel->epollfd < 0)
#endif
	    FD_CLR(fd, &sel->read_set);
    }
    if (sel_update_fd(sel, fdc, EPOLL_CTL_MOD))
	sel_wake_all(sel);

 out:
    sel_fd_unlock(sel);
}

/* Set whether the file descriptor will be monitored for when the file
   descriptor can be written to. */
void
sel_set_fd_write_handler(struct selector_s *sel, int fd, int state)
{
    fd_control_t *fdc;

    sel_fd_lock(sel);
    valid_fd(sel, fd, &fdc);

    if (!fdc->state)
	goto out;

    if (state == SEL_FD_HANDLER_ENABLED) {
	if (fdc->write_enabled)
	    goto out;
	fdc->write_enabled = 1;
#ifdef HAVE_EPOLL_PWAIT
	if (sel->epollfd < 0)
#endif
	    FD_SET(fd, &sel->write_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	if (!fdc->write_enabled)
	    goto out;
	fdc->write_enabled = 0;
#ifdef HAVE_EPOLL_PWAIT
	if (sel->epollfd < 0)
#endif
	    FD_CLR(fd, &sel->write_set);
    }
    if (sel_update_fd(sel, fdc, EPOLL_CTL_MOD))
	sel_wake_all(sel);

 out:
    sel_fd_unlock(sel);
}

/* Set whether the file descriptor will be monitored for exceptions
   on the file descriptor. */
void
sel_set_fd_except_handler(struct selector_s *sel, int fd, int state)
{
    fd_control_t *fdc;

    sel_fd_lock(sel);
    valid_fd(sel, fd, &fdc);

    if (!fdc->state)
	goto out;

    if (state == SEL_FD_HANDLER_ENABLED) {
	if (fdc->except_enabled)
	    goto out;
	fdc->except_enabled = 1;
#ifdef HAVE_EPOLL_PWAIT
	if (sel->epollfd < 0)
#endif
	    FD_SET(fd, &sel->except_set);
    } else if (state == SEL_FD_HANDLER_DISABLED) {
	if (!fdc->except_enabled)
	    goto out;
	fdc->except_enabled = 0;
#ifdef HAVE_EPOLL_PWAIT
	if (sel->epollfd < 0)
#endif
	    FD_CLR(fd, &sel->except_set);
    }
    if (sel_update_fd(sel, fdc, EPOLL_CTL_MOD))
	sel_wake_all(sel);

 out:
    sel_fd_unlock(sel);
}

static void
diff_timeval(struct timeval *dest,
	     struct timeval *left,
	     struct timeval *right)
{
    if (   (left->tv_sec < right->tv_sec)
	|| (   (left->tv_sec == right->tv_sec)
	    && (left->tv_usec < right->tv_usec)))
    {
	/* If left < right, just force to zero, don't allow negative
           numbers. */
	dest->tv_sec = 0;
	dest->tv_usec = 0;
	return;
    }

    dest->tv_sec = left->tv_sec - right->tv_sec;
    dest->tv_usec = left->tv_usec - right->tv_usec;
    while (dest->tv_usec < 0) {
	dest->tv_usec += 1000000;
	dest->tv_sec--;
    }
}

static void
add_timeval(struct timeval *dest,
	    struct timeval *left,
	    struct timeval *right)
{
    dest->tv_sec = left->tv_sec + right->tv_sec;
    dest->tv_usec = left->tv_usec + right->tv_usec;
    while (dest->tv_usec > 1000000) {
	dest->tv_usec -= 1000000;
	dest->tv_sec++;
    }
}

int
sel_alloc_timer(struct selector_s     *sel,
		sel_timeout_handler_t handler,
		void                  *user_data,
		sel_timer_t           **new_timer)
{
    sel_timer_t *timer;

    timer = sel_alloc(sizeof(*timer));
    if (!timer)
	return ENOMEM;
    memset(timer, 0, sizeof(*timer));

    timer->val.handler = handler;
    timer->val.user_data = user_data;
    timer->val.sel = sel;
    timer->val.stopped = 1;
    *new_timer = timer;

    return 0;
}

static int
sel_stop_timer_i(struct selector_s *sel, sel_timer_t *timer)
{
    int rv = 0;

    if (timer->val.stopped)
	rv = ETIMEDOUT;
    /*
     * It should not be possible for the timer to be stopped but in
     * the heap, but that's happening sometimes.  (The opposite is
     * possible, a timer can be not stopped but not in the heap; that
     * is used to signal a timer restart on return from a timer
     * handler.)  So make sure it's not in the heap.
     */
    if (timer->val.in_heap) {
	theap_remove(&sel->timer_heap, timer);
	timer->val.in_heap = 0;
    }
    timer->val.stopped = 1;

    return rv;
}

int
sel_free_timer(sel_timer_t *timer)
{
    struct selector_s *sel = timer->val.sel;
    int in_handler;

    sel_timer_lock(sel);
    if (timer->val.in_heap)
	sel_stop_timer_i(sel, timer);
    timer->val.freed = 1;
    in_handler = timer->val.in_handler;
    sel_timer_unlock(sel);

    if (!in_handler)
	free(timer);

    return 0;
}

int
sel_start_timer(sel_timer_t    *timer,
		struct timeval *timeout)
{
    struct selector_s *sel = timer->val.sel;
    volatile sel_timer_t *old_top;

    sel_timer_lock(sel);
    if (timer->val.in_heap) {
	sel_timer_unlock(sel);
	return EBUSY;
    }

    old_top = theap_get_top(&sel->timer_heap);

    timer->val.timeout = *timeout;

    if (!timer->val.in_handler) {
	/* Wait until the handler returns to start the timer. */
	theap_add(&sel->timer_heap, timer);
	timer->val.in_heap = 1;
    }
    timer->val.stopped = 0;

    wake_timer_sel_thread(sel, old_top, timeout);

    sel_timer_unlock(sel);

    return 0;
}

int
sel_stop_timer(sel_timer_t *timer)
{
    struct selector_s *sel = timer->val.sel;
    int rv;

    sel_timer_lock(sel);
    rv = sel_stop_timer_i(sel, timer);
    sel_timer_unlock(sel);

    return rv;
}

int
sel_stop_timer_with_done(sel_timer_t *timer,
			 sel_timeout_handler_t done_handler,
			 void *cb_data)
{
    struct selector_s *sel = timer->val.sel;
    int rv = EBUSY;

    sel_timer_lock(sel);
    if (timer->val.done_handler)
	goto out_unlock;
    rv = ETIMEDOUT;
    if (timer->val.stopped || timer->val.in_handler)
	goto out_unlock;

    rv = 0;
    timer->val.stopped = 1;

    timer->val.done_handler = done_handler;
    timer->val.done_cb_data = cb_data;

    /*
     * We don't want to run the done handler here to avoid locking
     * issues.  So set it in_handler and stick it on the top of the
     * heap with an immediate timeout so it will be processed now.
     */
    timer->val.in_handler = 1;
    if (timer->val.in_heap) {
	theap_remove(&sel->timer_heap, timer);
	timer->val.in_heap = 0;
    }
    sel_get_monotonic_time(&timer->val.timeout);
    theap_add(&sel->timer_heap, timer);
    timer->val.in_heap = 1;

 out_unlock:
    sel_timer_unlock(sel);
    return rv;
}

void
sel_get_monotonic_time(struct timeval *tv)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = (ts.tv_nsec + 500) / 1000;
}

/*
 * Process timers on selector.  The timeout is always set, to a very
 * long value if no timers are waiting.  Note that this *must* be
 * called with sel->timer_lock held.  Note that if this processes
 * any timers, the timeout will be set to { 0,0 }.
 */
static void
process_timers(struct selector_s       *sel,
	       unsigned int            *count,
	       volatile struct timeval *timeout,
	       struct timeval          *abstime)
{
    struct timeval now;
    sel_timer_t    *timer;

    timer = theap_get_top(&sel->timer_heap);
    sel_get_monotonic_time(&now);
    while (timer && cmp_timeval(&now, &timer->val.timeout) >= 0) {
	theap_remove(&(sel->timer_heap), timer);
	timer->val.in_heap = 0;
	timer->val.stopped = 1;

	/*
	 * A timer may be in a handler here if it has been stopped with
	 * a done_handler.  In that case the timer was stopped, so we
	 * don't call the main handler.
	 */
	if (!timer->val.in_handler) {
	    timer->val.in_handler = 1;
	    sel_timer_unlock(sel);
	    timer->val.handler(sel, timer, timer->val.user_data);
	    sel_timer_lock(sel);
	}
	(*count)++;
	if (timer->val.done_handler) {
	    sel_timeout_handler_t done_handler = timer->val.done_handler;
	    void *done_cb_data = timer->val.done_cb_data;

	    timer->val.done_handler = NULL;
	    timer->val.in_handler = 1;
	    sel_timer_unlock(sel);
	    done_handler(sel, timer, done_cb_data);
	    sel_timer_lock(sel);
	}
	timer->val.in_handler = 0;
	if (timer->val.freed)
	    free(timer);
	else if (!timer->val.stopped) {
	    /* We were restarted while in the handler. */
	    theap_add(&sel->timer_heap, timer);
	    timer->val.in_heap = 1;
	}

	timer = theap_get_top(&sel->timer_heap);
    }

    if (*count) {
	/* If called, set the timeout to zero. */
	timeout->tv_sec = 0;
	timeout->tv_usec = 0;
	*abstime = now;
    } else if (timer) {
	diff_timeval((struct timeval *) timeout,
		     (struct timeval *) &timer->val.timeout,
		     &now);
	*abstime = timer->val.timeout;
    } else {
	/* No timers, just set a long time. */
	timeout->tv_sec = 100000;
	timeout->tv_usec = 0;
	now.tv_sec +=timeout->tv_sec;
	*abstime = now;
    }
}

int
sel_alloc_runner(struct selector_s *sel, sel_runner_t **new_runner)
{
    sel_runner_t *runner;

    runner = sel_alloc(sizeof(*runner));
    if (!runner)
	return ENOMEM;
    memset(runner, 0, sizeof(*runner));
    runner->sel = sel;
    *new_runner = runner;
    return 0;
}

int
sel_free_runner(sel_runner_t *runner)
{
    struct selector_s *sel = runner->sel;

    sel_timer_lock(sel);
    if (runner->in_use) {
	sel_timer_unlock(sel);
	return EBUSY;
    }
    sel_timer_unlock(sel);
    free(runner);
    return 0;
}

int
sel_run(sel_runner_t *runner, sel_runner_func_t func, void *cb_data)
{
    struct selector_s *sel = runner->sel;

    sel_timer_lock(sel);
    if (runner->in_use) {
	sel_timer_unlock(sel);
	return EBUSY;
    }

    runner->func = func;
    runner->cb_data = cb_data;
    runner->next = NULL;
    runner->in_use = 1;

    if (sel->runner_tail) {
	sel->runner_tail->next = runner;
	sel->runner_tail = runner;
    } else {
	sel->runner_head = runner;
	sel->runner_tail = runner;
    }
    /* Make sure someone is awake to run the runner. */
    i_sel_wake_first(sel);
    sel_timer_unlock(sel);
    return 0;
}

static unsigned int
process_runners(struct selector_s *sel)
{
    sel_runner_t *runner = sel->runner_head, *next_runner;
    int count = 0;

    sel->runner_head = NULL;
    sel->runner_tail = NULL;
    while (runner) {
	sel_runner_func_t func;
	void *cb_data;

	next_runner = runner->next;
	runner->in_use = 0;
	func = runner->func;
	cb_data = runner->cb_data;
	sel_timer_unlock(sel);
	func(runner, cb_data);
	count++;
	sel_timer_lock(sel);
	runner = next_runner;
    }

    return count;
}

static void
handle_selector_call(struct selector_s *sel, fd_control_t *fdc,
		     volatile fd_set *fdset, int enabled,
		     sel_fd_handler_t handler)
{
    void             *data;
    fd_state_t       *state;

    if (handler == NULL) {
	/* Somehow we don't have a handler for this.
	   Just shut it down. */
	if (fdset)
	    FD_CLR(fdc->fd, fdset);
	return;
    }

    if (!enabled)
	/* The value was cleared, ignore it. */
	return;

    data = fdc->data;
    state = fdc->state;
    if (!state)
	/*
	 * Can happen because we are called multiple times in succession.
	 * Just ignore it.
	 */
	return;
    state->use_count++;
    sel_fd_unlock(sel);
    handler(fdc->fd, data);
    sel_fd_lock(sel);
    state->use_count--;
    if (state->deleted && state->use_count == 0) {
	fdc->state = NULL;
	if (state->done) {
	    sel_fd_unlock(sel);
	    state->done(fdc->fd, data);
	    sel_fd_lock(sel);
	}
	free(state);
    }
}

static void
setup_my_sigmask(sigset_t *sigmask, sigset_t *isigmask)
{
    if (isigmask) {
	*sigmask = *isigmask;
    } else {
#ifdef USE_PTHREADS
	pthread_sigmask(SIG_SETMASK, NULL, sigmask);
#else
	sigprocmask(SIG_SETMASK, NULL, sigmask);
#endif
    }
}

/*
 * return == 0  when timeout
 * 	  >  0  when successful
 * 	  <  0  when error
 */
static int
process_fds(struct selector_s	    *sel,
	    volatile struct timespec *timeout,
	    sigset_t *isigmask)
{
    fd_set      tmp_read_set;
    fd_set      tmp_write_set;
    fd_set      tmp_except_set;
    int i;
    int err;
    int num_fds;
    sigset_t sigmask;
    unsigned long entry_fd_del_count = sel->fd_del_count;
    fd_control_t *fdc;

    setup_my_sigmask(&sigmask, isigmask);
 retry:
    sel_fd_lock(sel);
    memcpy(&tmp_read_set, (void *) &sel->read_set, sizeof(tmp_read_set));
    memcpy(&tmp_write_set, (void *) &sel->write_set, sizeof(tmp_write_set));
    memcpy(&tmp_except_set, (void *) &sel->except_set, sizeof(tmp_except_set));
    num_fds = sel->maxfd + 1;
    sel_fd_unlock(sel);

    sigdelset(&sigmask, sel->wake_sig);
    err = pselect(num_fds,
		  &tmp_read_set,
		  &tmp_write_set,
		  &tmp_except_set,
		  (struct timespec *) timeout, &sigmask);
    if (err < 0) {
	if (errno == EBADF || errno == EBADFD)
	    /* We raced, just retry it. */
	    goto retry;
	goto out;
    }

    /* We got some I/O. */
    sel_fd_lock(sel);
    if (entry_fd_del_count != sel->fd_del_count)
	/* Something was deleted from the FD set, don't process this as it
	   may be from the old fd wakeup. */
	goto out_unlock;
    for (i = 0; i <= sel->maxfd; i++) {
	if (FD_ISSET(i, &tmp_read_set)) {
	    valid_fd(sel, i, &fdc);
	    handle_selector_call(sel, fdc, &sel->read_set, fdc->read_enabled,
				 fdc->handle_read);
	}
	if (FD_ISSET(i, &tmp_write_set)) {
	    valid_fd(sel, i, &fdc);
	    handle_selector_call(sel, fdc, &sel->write_set, fdc->write_enabled,
				 fdc->handle_write);
	}
	if (FD_ISSET(i, &tmp_except_set)) {
	    valid_fd(sel, i, &fdc);
	    handle_selector_call(sel, fdc, &sel->except_set,
				 fdc->except_enabled, fdc->handle_except);
	}
    }
 out_unlock:
    sel_fd_unlock(sel);
out:
    return err;
}

#ifdef HAVE_EPOLL_PWAIT
static int
process_fds_epoll(struct selector_s *sel, struct timespec *tstimeout,
		  sigset_t *isigmask)
{
    int rv;
    struct epoll_event event;
    int timeout;
    sigset_t sigmask;
    fd_control_t *fdc;
    unsigned long entry_fd_del_count = sel->fd_del_count;

    setup_my_sigmask(&sigmask, isigmask);

    if (tstimeout->tv_sec > 600)
	 /* Don't wait over 10 minutes, to work around an old epoll bug
	    and avoid issues with timeout overflowing on 64-bit systems,
	    which is much larger that 10 minutes, but who cares. */
	timeout = 600 * 1000;
    else
	timeout = ((tstimeout->tv_sec * 1000) +
		   (tstimeout->tv_nsec + 999999) / 1000000);

    sigdelset(&sigmask, sel->wake_sig);
    rv = epoll_pwait(sel->epollfd, &event, 1, timeout, &sigmask);
    if (rv <= 0)
	return rv;

    sel_fd_lock(sel);
    valid_fd(sel, event.data.fd, &fdc);
    if (entry_fd_del_count != sel->fd_del_count)
	/* Something was deleted from the FD set, don't process this as it
	   may be from the old fd wakeup. */
	goto rearm;
    if (event.events & (EPOLLHUP | EPOLLERR)) {
	/*
	 * The crazy people that designed epoll made it so that EPOLLHUP
	 * and EPOLLERR always wake it up, even if they are not set.  That
	 * makes this fairly inconvenient, because we don't want to wake
	 * up in that case unless we explicitly ask for it.  Fortunately,
	 * in those cases we can pretty easily simulate it by just deleting
	 * it, since in those cases you will not get anything but an
	 * EPOLLHUP or EPOLLERR, anyway, and then doing the callback
	 * by hand.
	 */
	sel_update_fd(sel, fdc, EPOLL_CTL_DEL);
	fdc->saved_events = event.events & (EPOLLHUP | EPOLLERR);
	/*
	 * Have it handle read data, too, so if there is a pending
	 * error it will get handled.
	 */
	event.events |= EPOLLIN;
    }
    if (event.events & (EPOLLIN | EPOLLHUP))
	handle_selector_call(sel, fdc, NULL, fdc->read_enabled,
			     fdc->handle_read);
    if (event.events & EPOLLOUT)
	handle_selector_call(sel, fdc, NULL, fdc->write_enabled,
			     fdc->handle_write);
    if (event.events & (EPOLLPRI | EPOLLERR))
	handle_selector_call(sel, fdc, NULL, fdc->except_enabled,
			     fdc->handle_except);

 rearm:
    /* Rearm the event.  Remember it could have been deleted in the handler. */
    if (fdc->state)
	sel_update_fd(sel, fdc, EPOLL_CTL_MOD);
    sel_fd_unlock(sel);

    return rv;
}

int
sel_setup_forked_process(struct selector_s *sel)
{
    int i;

    /*
     * More epoll stupidity.  In a forked process we must create a new
     * epoll because the epoll state is shared between a parent and a
     * child.  If it worked like it should, each epoll instance would
     * be independent.  If you don't do this, disabling an fd in the
     * child disables the parent, too, and vice versa.
     */
    close(sel->epollfd);
    sel->epollfd = epoll_create(32768);
    if (sel->epollfd == -1) {
	return errno;
    }

    for (i = 0; i <= sel->maxfd; i++) {
	fd_control_t *fdc = sel->fds[i];
	if (fdc && fdc->state)
	    sel_update_fd(sel, fdc, EPOLL_CTL_ADD);
    }
    return 0;
}
#else
int
sel_setup_forked_process(struct selector_s *sel)
{
    /* Nothing to do. */
    return 0;
}
#endif

int
sel_select_intr_sigmask(struct selector_s *sel,
			sel_send_sig_cb send_sig,
			long            thread_id,
			void            *cb_data,
			struct timeval  *timeout,
			sigset_t        *sigmask)
{
    int             err = 0, old_errno;
    struct timeval  wake_time, tmp_timeout;
    struct timespec loc_timeout;
    sel_wait_list_t wait_entry;
    unsigned int    count;
    struct timeval  end = { 0, 0 }, now;
    int user_timeout = 0;

    if (timeout) {
	sel_get_monotonic_time(&now);
	add_timeval(&end, &now, timeout);
    }

    sel_timer_lock(sel);
    count = process_runners(sel);
    process_timers(sel, &count, &tmp_timeout, &wake_time);

    if (count == 0 && !sel->runner_head) {
	/* Didn't do anything and no runners waiting, wait for something. */
	if (timeout) {
	    if (cmp_timeval(&tmp_timeout, timeout) >= 0) {
		tmp_timeout = *timeout;
		user_timeout = 1;
	    }
	}

	loc_timeout.tv_sec = tmp_timeout.tv_sec;
	loc_timeout.tv_nsec = tmp_timeout.tv_usec * 1000;

	add_sel_wait_list(sel, &wait_entry, send_sig, cb_data, thread_id,
			  &wake_time, &loc_timeout);
	sel_timer_unlock(sel);

#ifdef HAVE_EPOLL_PWAIT
	if (sel->epollfd >= 0)
	    err = process_fds_epoll(sel, &loc_timeout, sigmask);
	else
#endif
	    err = process_fds(sel, &loc_timeout, sigmask);

	old_errno = errno;

	sel_timer_lock(sel);
	if (err == 0) {
#ifdef BROKEN_PSELECT
	    if (wait_entry.signalled) {
		err = -1;
		old_errno = EINTR;
	    } else
#endif
	    if (!user_timeout) {
		/*
		 * Only return a timeout if we waited on the user's timeout
		 * Otherwise there is a timer to process.
		 */
		count++;
	    }
	}

	remove_sel_wait_list(sel, &wait_entry);

	/*
	 * Process runners before and after the wait.  This way any
	 * runners added while waiting will get processed.  Otherwise
	 * we would have to wake up other threads so the runners get
	 * handled immediately.  Do not add to the count, though, if
	 * we timed out we want to alert the user of that.
	 */
	process_runners(sel);
    }
    sel_timer_unlock(sel);
    if (timeout) {
	sel_get_monotonic_time(&now);
	diff_timeval(timeout, &end, &now);
    }

    if (err < 0) {
	errno = old_errno;
	return err;
    }

    return err + count;
}

int
sel_select_intr(struct selector_s *sel,
		sel_send_sig_cb send_sig,
		long            thread_id,
		void            *cb_data,
		struct timeval  *timeout)
{
    return sel_select_intr_sigmask(sel, send_sig, thread_id, cb_data, timeout,
				   NULL);
}

int
sel_select(struct selector_s *sel,
	   sel_send_sig_cb send_sig,
	   long            thread_id,
	   void            *cb_data,
	   struct timeval  *timeout)
{
    int err;

    err = sel_select_intr_sigmask(sel, send_sig, thread_id, cb_data, timeout,
				  NULL);
    if (err < 0 && errno == EINTR)
	/*
	 * If we get an EINTR, we don't want to report a timeout.  Just
	 * return that we did something.
	 */
	return 1;
    return err;
}

/* The main loop for the program.  This will select on the various
   sets, then scan for any available I/O to process.  It also monitors
   the time and call the timeout handlers periodically. */
int
sel_select_loop(struct selector_s *sel,
		sel_send_sig_cb send_sig,
		long            thread_id,
		void            *cb_data)
{
    for (;;) {
	int err = sel_select(sel, send_sig, thread_id, cb_data, NULL);

	if ((err < 0) && (errno != EINTR)) {
	    err = errno;
	    /* An error occurred. */
	    /* An error is bad, we need to abort. */
	    syslog(LOG_ERR, "select_loop() - select: %m");
	    return err;
	}
    }
}

/* Initialize the select code. */
int
sel_alloc_selector_thread(struct selector_s **new_selector, int wake_sig,
			  sel_lock_t *(*sel_lock_alloc)(void *cb_data),
			  void (*sel_lock_free)(sel_lock_t *),
			  void (*sel_lock)(sel_lock_t *),
			  void (*sel_unlock)(sel_lock_t *),
			  void *cb_data)
{
    struct selector_s *sel;
    int rv;
    sigset_t sigset;

    sel = sel_alloc(sizeof(*sel));
    if (!sel)
	return ENOMEM;
    memset(sel, 0, sizeof(*sel));

    sel->sel_lock_alloc = sel_lock_alloc;
    sel->sel_lock_free = sel_lock_free;
    sel->sel_lock = sel_lock;
    sel->sel_unlock = sel_unlock;

    /* The list is initially empty. */
    sel->wait_list.next = &sel->wait_list;
    sel->wait_list.prev = &sel->wait_list;

    sel->wake_sig = wake_sig;

    FD_ZERO((fd_set *) &sel->read_set);
    FD_ZERO((fd_set *) &sel->write_set);
    FD_ZERO((fd_set *) &sel->except_set);

    memset(sel->fds, 0, sizeof(sel->fds));

    theap_init(&sel->timer_heap);

    if (sel->sel_lock_alloc) {
	sel->timer_lock = sel->sel_lock_alloc(cb_data);
	if (!sel->timer_lock) {
	    free(sel);
	    return ENOMEM;
	}
	sel->fd_lock = sel->sel_lock_alloc(cb_data);
	if (!sel->fd_lock) {
	    sel->sel_lock_free(sel->fd_lock);
	    free(sel);
	    return ENOMEM;
	}
    }

    sigemptyset(&sigset);
    sigaddset(&sigset, wake_sig);
    rv = sigprocmask(SIG_BLOCK, &sigset, NULL);
    if (rv == -1) {
	rv = errno;
	if (sel->sel_lock_alloc) {
	    sel->sel_lock_free(sel->fd_lock);
		sel->sel_lock_free(sel->timer_lock);
	}
	free(sel);
	return rv;
    }

#ifdef HAVE_EPOLL_PWAIT
    sel->epollfd = epoll_create(32768);
    if (sel->epollfd == -1)
	syslog(LOG_ERR, "Unable to set up epoll, falling back to select: %m");
#endif

    *new_selector = sel;

    return 0;
}

int
sel_alloc_selector_nothread(struct selector_s **new_selector)
{
    return sel_alloc_selector_thread(new_selector, 0, NULL, NULL, NULL, NULL,
				     NULL);
}

int
sel_free_selector(struct selector_s *sel)
{
    sel_timer_t *elem;
    unsigned int i;

    elem = theap_get_top(&(sel->timer_heap));
    while (elem) {
	theap_remove(&(sel->timer_heap), elem);
	elem->val.in_heap = 0;
	free(elem);
	elem = theap_get_top(&(sel->timer_heap));
    }
#ifdef HAVE_EPOLL_PWAIT
    if (sel->epollfd >= 0)
	close(sel->epollfd);
#endif
    for (i = 0; i < FD_SETSIZE; i++) {
	while (sel->fds[i]) {
	    fd_control_t *fdc = sel->fds[i];

	    sel->fds[i] = fdc->next;
	    if (fdc->state)
		free(fdc->state);
	    free(fdc);
	}
    }
    if (sel->fd_lock)
	sel->sel_lock_free(sel->fd_lock);
    if (sel->timer_lock)
	sel->sel_lock_free(sel->timer_lock);
    free(sel);

    return 0;
}
