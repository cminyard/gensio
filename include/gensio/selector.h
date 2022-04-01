/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef SELECTOR
#define SELECTOR
#include <sys/time.h> /* For timeval */
#include <signal.h>

#if defined GENSIO_LINK_STATIC
  #define SEL_DLL_PUBLIC
  #define SEL_DLL_LOCAL
#elif defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_GENSIO_DLL
    #ifdef __GNUC__
      #define SEL_DLL_PUBLIC __attribute__ ((dllexport))
    #else
      #define SEL_DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define SEL_DLL_PUBLIC __attribute__ ((dllimport))
    #else
      #define SEL_DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
  #define SEL_DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define SEL_DLL_PUBLIC __attribute__ ((visibility ("default")))
    #define SEL_DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define SEL_DLL_PUBLIC
    #define SEL_DLL_LOCAL
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* The main data structure used by the selector. */
struct selector_s;

/* You have to create a selector before you can use it. */

/*
 * Create a selector for use with threads.  You have to pass in the
 * lock functions and a signal used to wake waiting threads.
 *
 * Note that this function will block wake_sig in the calling thread, and you
 * must have it blocked on all threads.
 */
typedef struct sel_lock_s sel_lock_t;
SEL_DLL_PUBLIC
int sel_alloc_selector_thread(struct selector_s **new_selector, int wake_sig,
			      sel_lock_t *(*sel_lock_alloc)(void *cb_data),
			      void (*sel_lock_free)(sel_lock_t *),
			      void (*sel_lock)(sel_lock_t *),
			      void (*sel_unlock)(sel_lock_t *),
			      void *cb_data);

  /* Create a selector for use in a single-threaded environment.  No
     need for locks or wakeups.  This just call the above call with
     NULL for all the values. */
SEL_DLL_PUBLIC
int sel_alloc_selector_nothread(struct selector_s **new_selector);

/* Used to destroy a selector. */
SEL_DLL_PUBLIC
int sel_free_selector(struct selector_s *new_selector);

/* A function to call when select sees something on a file
   descriptor. */
typedef void (*sel_fd_handler_t)(int fd, void *data);

/* Set the handlers for a file descriptor.  The "data" parameter is
   not used, it is just passed to the exception handlers.  The done
   handler (if non-NULL) will be called when the data is removed or
   replaced. */
typedef void (*sel_fd_cleared_cb)(int fd, void *data);
SEL_DLL_PUBLIC
int sel_set_fd_handlers(struct selector_s *sel,
			int               fd,
			void              *data,
			sel_fd_handler_t  read_handler,
			sel_fd_handler_t  write_handler,
			sel_fd_handler_t  except_handler,
			sel_fd_cleared_cb done);

/* Remove the handlers for a file descriptor.  This will also disable
   the handling of all I/O for the fd.  Note that when this returns,
   some other thread may be in a handler.  To avoid races with
   clearing the data (SMP only), you should provide a done handler in
   the set routine; it will be called when the registered handler is
   sure to not be called again. */
SEL_DLL_PUBLIC
void sel_clear_fd_handlers(struct selector_s *sel,
			   int        fd);
/* Like above, but the fd_cleared function will not be called. */
SEL_DLL_PUBLIC
void sel_clear_fd_handlers_norpt(struct selector_s *sel, int fd);

/* Turn on and off handling for I/O from a file descriptor. */
#define SEL_FD_HANDLER_ENABLED	0
#define SEL_FD_HANDLER_DISABLED	1
SEL_DLL_PUBLIC
void sel_set_fd_read_handler(struct selector_s *sel, int fd, int state);
SEL_DLL_PUBLIC
void sel_set_fd_write_handler(struct selector_s *sel, int fd, int state);
SEL_DLL_PUBLIC
void sel_set_fd_except_handler(struct selector_s *sel, int fd, int state);

struct sel_timer_s;
typedef struct sel_timer_s sel_timer_t;

typedef void (*sel_timeout_handler_t)(struct selector_s *sel,
				      sel_timer_t *timer,
				      void        *data);

SEL_DLL_PUBLIC
int sel_alloc_timer(struct selector_s     *sel,
		    sel_timeout_handler_t handler,
		    void                  *user_data,
		    sel_timer_t           **new_timer);

SEL_DLL_PUBLIC
int sel_free_timer(sel_timer_t *timer);

SEL_DLL_PUBLIC
int sel_start_timer(sel_timer_t    *timer,
		    struct timeval *timeout);

SEL_DLL_PUBLIC
int sel_stop_timer(sel_timer_t *timer);

/* Stops the timer and calls the done handler when the stop is
   complete.  This will return an error if the timer is not
   running or if another done handler is pending running, and
   the done handler will not be called. */
SEL_DLL_PUBLIC
int sel_stop_timer_with_done(sel_timer_t *timer,
			     sel_timeout_handler_t done_handler,
			     void *cb_data);

/* Use this for times provided to sel_start_time() */
SEL_DLL_PUBLIC
void sel_get_monotonic_time(struct timeval *tv);

typedef struct sel_runner_s sel_runner_t;
typedef void (*sel_runner_func_t)(sel_runner_t *runner, void *cb_data);
SEL_DLL_PUBLIC
int sel_alloc_runner(struct selector_s *sel, sel_runner_t **new_runner);
SEL_DLL_PUBLIC
int sel_free_runner(sel_runner_t *runner);
SEL_DLL_PUBLIC
int sel_run(sel_runner_t *runner, sel_runner_func_t func, void *cb_data);

/* For multi-threaded programs, you will need to wake the selector
   thread if you add a timer to the top of the heap or change the fd
   mask.  This code should send a signal to the thread that calls
   sel-select_loop.  The user will have to allocate the signal, set
   the handlers, etc.  The thread_id and cb_data are just the values
   passed into sel_select_loop(). */
typedef void (*sel_send_sig_cb)(long thread_id, void *cb_data);

/*
 * This is the select interface for program. All handlers on timers and
 * fds will get chances to be called.
 * return >0 if sel_select did something (ran a timer or fd)
 *         0 if timeout
 *        <0 if error (errno will be set)
 * The timeout is a relative timeout (just like normal select() on
 * *nix).
 */
SEL_DLL_PUBLIC
int sel_select(struct selector_s *sel,
	       sel_send_sig_cb send_sig,
	       long            thread_id,
	       void            *cb_data,
	       struct timeval  *timeout);

/*
 * Like the above call, but it will return EINTR if interrupted.
 */
SEL_DLL_PUBLIC
int sel_select_intr(struct selector_s *sel,
		    sel_send_sig_cb send_sig,
		    long            thread_id,
		    void            *cb_data,
		    struct timeval  *timeout);

/*
 * Like the above call, but allows the user to install their own sigmask
 * while waiting.
 */
SEL_DLL_PUBLIC
int sel_select_intr_sigmask(struct selector_s *sel,
			    sel_send_sig_cb send_sig,
			    long            thread_id,
			    void            *cb_data,
			    struct timeval  *timeout,
			    sigset_t        *sigmask);

/* This is the main loop for the program.  If NULL is passed in to
   send_sig, then the signal sender is not used.  If this encounters
   an unrecoverable problem with select(), it will return the errno.
   Otherwise it will loop forever. */
SEL_DLL_PUBLIC
int sel_select_loop(struct selector_s *sel,
		    sel_send_sig_cb send_sig,
		    long            thread_id,
		    void            *cb_data);

/* Wake all threads in all select loops. */
SEL_DLL_PUBLIC
void sel_wake_all(struct selector_s *sel);

/* Wake one thread in a select loop. */
SEL_DLL_PUBLIC
void sel_wake_one(struct selector_s *sel, long thread_id, sel_send_sig_cb killer,
		  void *cb_data);

/*
 * If you fork and expect to use the selector in the forked process,
 * you *must* call this function in the forked process or you may
 * get strange results.
 */
SEL_DLL_PUBLIC
int sel_setup_forked_process(struct selector_s *sel);

#ifdef __cplusplus
}
#endif

#endif /* SELECTOR */
