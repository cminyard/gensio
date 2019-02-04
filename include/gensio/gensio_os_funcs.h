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

/*
 * This include file defines OS abstractions that gensio requires.
 */

#ifndef GENSIO_OS_FUNCS
#define GENSIO_OS_FUNCS
#include <stdbool.h>
#include <stdarg.h>
#include <sys/time.h> /* For timeval */

/*
 * Function pointers to provide OS functions.
 */

struct gensio_lock;
struct gensio_timer;
struct gensio_runner;

struct gensio_once {
    bool called;
};

enum gensio_log_levels {
    GENSIO_LOG_FATAL,
    GENSIO_LOG_ERR,
    GENSIO_LOG_WARNING,
    GENSIO_LOG_INFO,
    GENSIO_LOG_DEBUG
};

#define GENSIO_LOG_MASK_ALL (1 << GENSIO_LOG_FATAL | 1 << GENSIO_LOG_ERR | \
	1 << GENSIO_LOG_WARNING | 1 << GENSIO_LOG_INFO | 1 << GENSIO_LOG_DEBUG)
/*
 * A bitmask of log levels to tell what to log.  Defaults to fatal and err
 * only.
 */
void gensio_set_log_mask(unsigned int mask);
unsigned int gensio_get_log_mask(void);
const char *gensio_log_level_to_str(enum gensio_log_levels level);

struct gensio_os_funcs {
    /* For use by the code doing the os function translation. */
    void *user_data;

    /* For use by other code. */
    void *other_data;

    /****** Memory Allocation ******/
    /* Return allocated and zeroed data.  Return NULL on error. */
    void *(*zalloc)(struct gensio_os_funcs *f, unsigned int size);

    /* Free data allocated by zalloc. */
    void (*free)(struct gensio_os_funcs *f, void *data);

    /****** Mutexes ******/
    /* Allocate a lock.  Return NULL on error. */
    struct gensio_lock *(*alloc_lock)(struct gensio_os_funcs *f);

    /* Free a lock allocated with alloc_lock. */
    void (*free_lock)(struct gensio_lock *lock);

    /* Lock the lock. */
    void (*lock)(struct gensio_lock *lock);

    /* Unlock the lock. */
    void (*unlock)(struct gensio_lock *lock);

    /****** File Descriptor Handling ******/
    /*
     * Setup handlers to be called on the fd for various reasons:
     *
     * read_handler - called when data is ready to read.
     * write_handler - called when there is room to write data.
     * except_handler - called on exception cases (tcp urgent data).
     * cleared_handler - called when clear_fd_handlers completes.
     *
     * Note that all handlers are disabled when this returns, you must
     * enable them for the callbacks to be called.
     */
    int (*set_fd_handlers)(struct gensio_os_funcs *f,
			   int fd,
			   void *cb_data,
			   void (*read_handler)(int fd, void *cb_data),
			   void (*write_handler)(int fd, void *cb_data),
			   void (*except_handler)(int fd, void *cb_data),
			   void (*cleared_handler)(int fd, void *cb_data));

    /*
     * Clear the handlers for an fd.  Note that the operation is not
     * complete when the function returns.  The code may be running in
     * callbacks during this call, and it won't wait.  Instead,
     * cleared_handler is called when the operation completes, you
     * need to wait for that.
     */
    void (*clear_fd_handlers)(struct gensio_os_funcs *f, int fd);

    /*
     * Like the above, but does not call the cleared_handler function
     * when done.  This can only be called if you never enabled the
     * handlers, it is only for shutdown when an error occurs at startup.
     */
    void (*clear_fd_handlers_norpt)(struct gensio_os_funcs *f, int fd);

    /*
     * Enable/disable the various handlers.  Note that if you disable
     * a handler, it may still be running in a callback, this does not
     * wait.
     */
    void (*set_read_handler)(struct gensio_os_funcs *f, int fd, bool enable);
    void (*set_write_handler)(struct gensio_os_funcs *f, int fd, bool enable);
    void (*set_except_handler)(struct gensio_os_funcs *f, int fd, bool enable);

    /****** Timers ******/
    /*
     * Allocate a timer that calls the given handler when it goes
     * off.  Return NULL on error.
     */
    struct gensio_timer *(*alloc_timer)(struct gensio_os_funcs *f,
					void (*handler)(struct gensio_timer *t,
							void *cb_data),
					void *cb_data);

    /*
     * Free a timer allocated with alloc_timer.  The timer should not
     * be running.
     */
    void (*free_timer)(struct gensio_timer *timer);

    /*
     * Start the timer running.  Returns EBUSY if the timer is already
     * running.  This is a relative timeout.
     */
    int (*start_timer)(struct gensio_timer *timer, struct timeval *timeout);

    /*
     * Start the timer running.  Returns EBUSY if the timer is already
     * running.  This is an absolute timeout based on the monotonic
     * time returned by get_monotonic_time.
     */
    int (*start_timer_abs)(struct gensio_timer *timer, struct timeval *timeout);

    /*
     * Stop the timer.  Returns ETIMEDOUT if the timer is not running.
     * Note that the timer may still be running in a timeout handler
     * when this returns.
     */
    int (*stop_timer)(struct gensio_timer *timer);

    /*
     * Like the above, but the done_handler is called when the timer is
     * completely stopped and no handler is running.  If ETIMEDOUT is
     * returned, the done_handler is not called.
     */
    int (*stop_timer_with_done)(struct gensio_timer *timer,
				void (*done_handler)(struct gensio_timer *t,
						     void *cb_data),
				void *cb_data);

    /****** Runners ******/
    /*
     * Allocate a runner.  Return NULL on error.  A runner runs things
     * at a base context.  This is useful for handling situations
     * where you need to run something outside of a lock or context,
     * you schedule the runner.
     */
    struct gensio_runner *(*alloc_runner)(struct gensio_os_funcs *f,
				void (*handler)(struct gensio_runner *r,
						void *cb_data),
				void *cb_data);

    /* Free a runner allocated with alloc_runner. */
    void (*free_runner)(struct gensio_runner *runner);

    /*
     * Run a runner.  Return EBUSY if the runner is already scheduled
     * to run.
     */
    int (*run)(struct gensio_runner *runner);

    /****** Waiters ******/
    /*
     * Allocate a waiter, returns NULL on error.  A waiter is used to
     * wait for some action to occur.  When the action occurs, that code
     * should call wake to wake the waiter.  Normal operation of the
     * file descriptors, timers, runners, etc. happens while waiting.
     * You should be careful of the context of calling a waiter, like
     * what locks you are holding or what callbacks you are in.
     *
     * Note that waiters and wakes are count based, if you call wake()
     * before wait() that's ok.  If you call wake() 3 times, there
     * are 3 wakes pending.
     */
    struct gensio_waiter *(*alloc_waiter)(struct gensio_os_funcs *f);

    /* Free a waiter allocated by alloc_waiter. */
    void (*free_waiter)(struct gensio_waiter *waiter);

    /*
     * Wait for count wakeups for up to the amount of time (relative)
     * given in timeout.  If timeout is NULL wait forever.  This
     * returns ETIMEDOUT on a timeout.  It can return other errors.
     * The timeout is updated to the remaining time.
     * Note that if you get a timeout, none of the wakeups will be
     * "used" by this call.
     */
    int (*wait)(struct gensio_waiter *waiter, unsigned int count,
		struct timeval *timeout);

    /*
     * Like wait, but return if a signal is received by the thread.
     * This is useful if you want to handle SIGINT or something like
     * that.
     */
    int (*wait_intr)(struct gensio_waiter *waiter, unsigned int count,
		     struct timeval *timeout);

    /* Wake the given waiter. */
    void (*wake)(struct gensio_waiter *waiter);

    /****** Misc ******/
    /*
     * Run the timers, fd handling, runners, etc.  This does one
     * operation and returns.  If timeout is non-NULL, if nothing
     * happens before the relative time given it will return.
     * The timeout is updated to the remaining time.
     */
    int (*service)(struct gensio_os_funcs *f, struct timeval *timeout);

    /* Free this structure. */
    void (*free_funcs)(struct gensio_os_funcs *f);

    /* Call this function once. */
    void (*call_once)(struct gensio_os_funcs *f, struct gensio_once *once,
		      void (*func)(void *cb_data), void *cb_data);

    void (*get_monotonic_time)(struct gensio_os_funcs *f, struct timeval *time);

    void (*vlog)(struct gensio_os_funcs *f, enum gensio_log_levels level,
		 const char *log, va_list args);

    /*
     * Must be called after a fork() in the child if the gensio will
     * continue to be used in both the parent and the child.  If you
     * don't do this you may get undefined results.  If this returns
     * an error, the child is likely to be unusable.
     */
    int (*handle_fork)(struct gensio_os_funcs *f);
};

void gensio_vlog(struct gensio_os_funcs *o, enum gensio_log_levels level,
		 const char *str, va_list args);
void gensio_log(struct gensio_os_funcs *o, enum gensio_log_levels level,
		const char *str, ...);

/*
 * Allocate the OS handler for the platform.  This will return the
 * same OS handler each time.
 */
int gensio_default_os_hnd(int wake_sig, struct gensio_os_funcs **o);

#endif /* GENSIO_OS_FUNCS */
