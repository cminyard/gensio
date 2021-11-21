/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_OS_FUNCS_PUBLIC_H
#define GENSIO_OS_FUNCS_PUBLIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gensio/gensio_types.h>

/*
 * Allocate the OS handler for the platform.  This will return the
 * same OS handler each time.  Can return GE_NOMEM if out of memory.
 */
GENSIO_DLL_PUBLIC
int gensio_default_os_hnd(int wake_sig, struct gensio_os_funcs **o);

/*
 * Process setup for gensio OS handlers.  These are machine-specific.
 * You should call this after allocating the OS handlers and if you use
 * wait_intr_sigmask you should pass the process data from this into that
 * function.
 *
 * For Windows this currently just returns NULL data and doesn't do
 * anything.
 *
 * For Unix, this blocks SIGPIPE, SIGCHLD, and the wake signal passed
 * in to the allocation function (if the wake signal is non-zero).  It
 * then sets a sigmask to be installed on the wait_intr_sigmask with
 * the wake signal and SIGCHLD not blocked.
 *
 * It also installs signal handlers for SIGCHLD and (if non-zero) the
 * wake signal.
 *
 * For Unix this is generally what you want, you don't want SIGPIPE
 * doing bad things and having SIGCHLD wake up a wait can speed things
 * up a bit when waiting for subprograms.
 *
 * If you need to modify that signal mask used in wait_intr_signmask,
 * use gensio_os_proc_unix_get_wait_sigset() defined below to fetch it
 * and modify it.
 *
 * Note that you can override SIGCHLD and SIGPIPE if you like.  Don't
 * mess with the wake signal.
 */
GENSIO_DLL_PUBLIC
int gensio_os_proc_setup(struct gensio_os_funcs *o,
			 struct gensio_os_proc_data **data);

/*
 * Undo the proc setup.
 *
 * On Windows this currently does nothing.
 *
 * On Unix this restores the signal mask to what it was when
 * proc_setup was called and it removes the signal handlers it
 * installed.
 */
GENSIO_DLL_PUBLIC
void gensio_os_proc_cleanup(struct gensio_os_proc_data *data);

/*
 * Set the function to call when a termination (SIGINT, SIGQUIT,
 * SIGTERM on Unix, console control handler or WM_CLOSE on windows) is
 * requested by the operating system.  data should point to a struct
 * gensio_control_register_handler.  Set to handler NULL to disable.
 */
GENSIO_DLL_PUBLIC
int gensio_os_proc_register_term_handler(struct gensio_os_proc_data *data,
					 void (*handler)(void *handler_data),
					 void *handler_data);
/*
 * Set the function to call when a reaload is requested by the
 * operating system (SIGHUP on Unix).  data should point to a struct
 * gensio_control_register_handler.  Set handler to NULL to disable.
 */
GENSIO_DLL_PUBLIC
int gensio_os_proc_register_reload_handler(struct gensio_os_proc_data *data,
					   void (*handler)(void *handler_data),
					   void *handler_data);


/*
 * Start a new thread running at start_func, passing in the given
 * data.  The thread_id is returned, use that to wait for the thread
 * to complete after it should stop.
 */
GENSIO_DLL_PUBLIC
int gensio_os_new_thread(struct gensio_os_funcs *o,
			 void (*start_func)(void *data), void *data,
			 struct gensio_thread **thread_id);

/*
 * Wait for the given thread to stop.  Note that this does not cause
 * the thread to stop, it waits for the thread to stop after it has
 * been stopped to avoid race condition.
 */
GENSIO_DLL_PUBLIC
int gensio_os_wait_thread(struct gensio_thread *thread_id);

GENSIO_DLL_PUBLIC
void *gensio_os_funcs_zalloc(struct gensio_os_funcs *o, unsigned int len);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_zfree(struct gensio_os_funcs *o, void *data);

/* Allocate a lock.  Return NULL on error. */
GENSIO_DLL_PUBLIC
struct gensio_lock *gensio_os_funcs_alloc_lock(struct gensio_os_funcs *o);

/* Free a lock allocated with alloc_lock. */
GENSIO_DLL_PUBLIC
void gensio_os_funcs_free_lock(struct gensio_os_funcs *o,
			       struct gensio_lock *lock);

/* Lock the lock. */
GENSIO_DLL_PUBLIC
void gensio_os_funcs_lock(struct gensio_os_funcs *o,
			  struct gensio_lock *lock);

/* Unlock the lock. */
GENSIO_DLL_PUBLIC
void gensio_os_funcs_unlock(struct gensio_os_funcs *o,
			    struct gensio_lock *lock);

/* Get the monotonic clock, used for gensio_os_start_timer_abs(). */
GENSIO_DLL_PUBLIC
void gensio_os_funcs_get_monotonic_time(struct gensio_os_funcs *o,
					gensio_time *time);
/*
 * Allocate a timer that calls the given handler when it goes
 * off.  Return NULL on error.
 */
GENSIO_DLL_PUBLIC
struct gensio_timer *gensio_os_funcs_alloc_timer(struct gensio_os_funcs *o,
				    void (*handler)(struct gensio_timer *t,
						    void *cb_data),
				    void *cb_data);

/*
 * Free a timer allocated with alloc_timer.  The timer should not
 * be running.
 */
GENSIO_DLL_PUBLIC
void gensio_os_funcs_free_timer(struct gensio_os_funcs *o,
				struct gensio_timer *timer);

/*
 * Start the timer running.  Returns GE_INUSE if the timer is already
 * running.  This is a relative timeout.
 */
GENSIO_DLL_PUBLIC
int gensio_os_funcs_start_timer(struct gensio_os_funcs *o,
				struct gensio_timer *timer,
				gensio_time *timeout);

/*
 * Start the timer running.  Returns GE_INUSE if the timer is already
 * running.  This is an absolute timeout based on the monotonic
 * time returned by get_monotonic_time.
 */
GENSIO_DLL_PUBLIC
int gensio_os_funcs_start_timer_abs(struct gensio_os_funcs *o,
				    struct gensio_timer *timer,
				    gensio_time *timeout);

/*
 * Stop the timer.  Returns GE_TIMEDOUT if the timer is not
 * running.  Note that the timer may still be running in a timeout
 * handler when this returns.
 */
GENSIO_DLL_PUBLIC
int gensio_os_funcs_stop_timer(struct gensio_os_funcs *o,
			       struct gensio_timer *timer);

/*
 * Like the above, but the done_handler is called when the timer
 * is completely stopped and no handler is running.  If
 * GE_TIMEDOUT is returned, the done_handler is not called.  If
 * GE_INUSE is returned, that means the timer has already been
 * stopped and the done handler for the previous call has not been
 * called.
 *
 * Note that if you stop a timer with a done handler, you cannot
 * start the timer until the done handler is called.
 */
GENSIO_DLL_PUBLIC
int gensio_os_funcs_stop_timer_with_done(struct gensio_os_funcs *o,
			    struct gensio_timer *timer,
			    void (*done_handler)(struct gensio_timer *t,
						 void *cb_data),
			    void *cb_data);

/*
 * Allocate a runner.  Return NULL on error.  A runner runs things
 * at a base context.  This is useful for handling situations
 * where you need to run something outside of a lock or context,
 * you schedule the runner.
 */
GENSIO_DLL_PUBLIC
struct gensio_runner *gensio_os_funcs_alloc_runner(struct gensio_os_funcs *o,
				      void (*handler)(struct gensio_runner *r,
						      void *cb_data),
				      void *cb_data);

/* Free a runner allocated with alloc_runner. */
GENSIO_DLL_PUBLIC
void gensio_os_funcs_free_runner(struct gensio_os_funcs *o,
				 struct gensio_runner *runner);

/*
 * Run a runner.  Return GE_INUSE if the runner is already scheduled
 * to run.
 */
GENSIO_DLL_PUBLIC
int gensio_os_funcs_run(struct gensio_os_funcs *o,
			struct gensio_runner *runner);

/*
 * Register a function to receive internal logs if they happen.  The
 * user must do this.
 */
typedef void (gensio_vlog_func)(struct gensio_os_funcs *o,
				enum gensio_log_levels level,
				const char *log, va_list args);
GENSIO_DLL_PUBLIC
void gensio_os_funcs_set_vlog(struct gensio_os_funcs *o, gensio_vlog_func func);

/* Used to free an allocates os funcs. */
GENSIO_DLL_PUBLIC
void gensio_os_funcs_free(struct gensio_os_funcs *o);

/*
 * Run the timers, fd handling, runners, etc.  This does one
 * operation and returns.  If timeout is non-NULL, if nothing
 * happens before the relative time given it will return.  The
 * timeout is updated to the remaining time.  Returns
 * GE_INTERRUPTED if interrupted by a signal or GE_TIMEDOUT if the
 * timeout expired.  Note that really long timeouts (days) may be
 * shortened to some value.
 */
GENSIO_DLL_PUBLIC
int gensio_os_funcs_service(struct gensio_os_funcs *o, gensio_time *timeout);

/*
 * Must be called after a fork() in the child if the gensio will
 * continue to be used in both the parent and the child.  If you
 * don't do this you may get undefined results.  If this returns
 * an error (gensio err), the child is likely to be unusable.
 */
GENSIO_DLL_PUBLIC
int gensio_os_funcs_handle_fork(struct gensio_os_funcs *o);

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
GENSIO_DLL_PUBLIC
struct gensio_waiter *gensio_os_funcs_alloc_waiter(struct gensio_os_funcs *o);

/* Free a waiter allocated by alloc_waiter. */
GENSIO_DLL_PUBLIC
void gensio_os_funcs_free_waiter(struct gensio_os_funcs *o,
				 struct gensio_waiter *waiter);

/*
 * Wait for count wakeups for up to the amount of time (relative)
 * given in timeout.  If timeout is NULL wait forever.  This
 * returns GE_TIMEDOUT on a timeout.  It can return other errors.
 * The timeout is updated to the remaining time.
 * Note that if you get a timeout, none of the wakeups will be
 * "used" by this call.
 */
GENSIO_DLL_PUBLIC
int gensio_os_funcs_wait(struct gensio_os_funcs *o,
			 struct gensio_waiter *waiter, unsigned int count,
			 gensio_time *timeout);

/*
 * Like wait, but return if a signal is received by the thread.
 * This is useful if you want to handle SIGINT or something like
 * that.  This will return GE_INTERRUPTED if interrupted by a
 * signal, GE_TIMEDOUT if it times out.
 */
GENSIO_DLL_PUBLIC
int gensio_os_funcs_wait_intr(struct gensio_os_funcs *o,
			      struct gensio_waiter *waiter, unsigned int count,
			      gensio_time *timeout);

/*
 * Like wait_intr, but allows machine-specific handling to be set
 * up.  See gensio_os_proc_setup() for info.
 */
GENSIO_DLL_PUBLIC
int gensio_os_funcs_wait_intr_sigmask(struct gensio_os_funcs *o,
				      struct gensio_waiter *waiter,
				      unsigned int count,
				      gensio_time *timeout,
				      struct gensio_os_proc_data *proc_data);

/* Wake the given waiter. */
GENSIO_DLL_PUBLIC
void gensio_os_funcs_wake(struct gensio_os_funcs *o,
			  struct gensio_waiter *waiter);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_set_data(struct gensio_os_funcs *o, void *data);

GENSIO_DLL_PUBLIC
void *gensio_os_funcs_get_data(struct gensio_os_funcs *o);


#ifdef _WIN32
#define GENSIO_DEF_WAKE_SIG 0
#else
#include <signal.h>
#define GENSIO_DEF_WAKE_SIG SIGUSR1
#endif

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_OS_FUNCS_PUBLIC_H */
