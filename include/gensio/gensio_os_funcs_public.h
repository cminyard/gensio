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

#include <stdarg.h>
#include <gensio/gensio_types.h>
#include <gensio/gensio_dllvisibility.h>

GENSIO_DLL_PUBLIC
int gensio_default_os_hnd(int wake_sig, struct gensio_os_funcs **o);

GENSIO_DLL_PUBLIC
int gensio_os_proc_setup(struct gensio_os_funcs *o,
			 struct gensio_os_proc_data **data);

GENSIO_DLL_PUBLIC
void gensio_os_proc_cleanup(struct gensio_os_proc_data *data);

GENSIO_DLL_PUBLIC
int gensio_os_proc_register_term_handler(struct gensio_os_proc_data *data,
					 void (*handler)(void *handler_data),
					 void *handler_data);

GENSIO_DLL_PUBLIC
int gensio_os_proc_register_reload_handler(struct gensio_os_proc_data *data,
					   void (*handler)(void *handler_data),
					   void *handler_data);


GENSIO_DLL_PUBLIC
int gensio_os_proc_register_winsize_handler(struct gensio_os_proc_data *data,
					struct gensio_iod *console_iod,
					void (*handler)(int x_chrs, int y_chrs,
							int x_bits, int y_bits,
							void *handler_data),
					void *handler_data);

GENSIO_DLL_PUBLIC
int gensio_os_new_thread(struct gensio_os_funcs *o,
			 void (*start_func)(void *data), void *data,
			 struct gensio_thread **thread_id);

GENSIO_DLL_PUBLIC
int gensio_os_wait_thread(struct gensio_thread *thread_id);

GENSIO_DLL_PUBLIC
void *gensio_os_funcs_zalloc(struct gensio_os_funcs *o, gensiods len);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_zfree(struct gensio_os_funcs *o, void *data);

GENSIO_DLL_PUBLIC
struct gensio_lock *gensio_os_funcs_alloc_lock(struct gensio_os_funcs *o);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_free_lock(struct gensio_os_funcs *o,
			       struct gensio_lock *lock);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_lock(struct gensio_os_funcs *o,
			  struct gensio_lock *lock);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_unlock(struct gensio_os_funcs *o,
			    struct gensio_lock *lock);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_get_monotonic_time(struct gensio_os_funcs *o,
					gensio_time *time);

GENSIO_DLL_PUBLIC
struct gensio_timer *gensio_os_funcs_alloc_timer(struct gensio_os_funcs *o,
				    void (*handler)(struct gensio_timer *t,
						    void *cb_data),
				    void *cb_data);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_free_timer(struct gensio_os_funcs *o,
				struct gensio_timer *timer);

GENSIO_DLL_PUBLIC
int gensio_os_funcs_start_timer(struct gensio_os_funcs *o,
				struct gensio_timer *timer,
				gensio_time *timeout);

GENSIO_DLL_PUBLIC
int gensio_os_funcs_start_timer_abs(struct gensio_os_funcs *o,
				    struct gensio_timer *timer,
				    gensio_time *timeout);

GENSIO_DLL_PUBLIC
int gensio_os_funcs_stop_timer(struct gensio_os_funcs *o,
			       struct gensio_timer *timer);

GENSIO_DLL_PUBLIC
int gensio_os_funcs_stop_timer_with_done(struct gensio_os_funcs *o,
			    struct gensio_timer *timer,
			    void (*done_handler)(struct gensio_timer *t,
						 void *cb_data),
			    void *cb_data);

GENSIO_DLL_PUBLIC
struct gensio_runner *gensio_os_funcs_alloc_runner(struct gensio_os_funcs *o,
				      void (*handler)(struct gensio_runner *r,
						      void *cb_data),
				      void *cb_data);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_free_runner(struct gensio_os_funcs *o,
				 struct gensio_runner *runner);

GENSIO_DLL_PUBLIC
int gensio_os_funcs_run(struct gensio_os_funcs *o,
			struct gensio_runner *runner);

typedef void (gensio_vlog_func)(struct gensio_os_funcs *o,
				enum gensio_log_levels level,
				const char *log, va_list args);
GENSIO_DLL_PUBLIC
void gensio_os_funcs_set_vlog(struct gensio_os_funcs *o, gensio_vlog_func func);
GENSIO_DLL_PUBLIC
gensio_vlog_func *gensio_os_funcs_get_vlog(struct gensio_os_funcs *o);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_free(struct gensio_os_funcs *o);

GENSIO_DLL_PUBLIC
int gensio_os_funcs_service(struct gensio_os_funcs *o, gensio_time *timeout);

GENSIO_DLL_PUBLIC
int gensio_os_funcs_handle_fork(struct gensio_os_funcs *o);

GENSIO_DLL_PUBLIC
struct gensio_waiter *gensio_os_funcs_alloc_waiter(struct gensio_os_funcs *o);

GENSIO_DLL_PUBLIC
void gensio_os_funcs_free_waiter(struct gensio_os_funcs *o,
				 struct gensio_waiter *waiter);

GENSIO_DLL_PUBLIC
int gensio_os_funcs_wait(struct gensio_os_funcs *o,
			 struct gensio_waiter *waiter, unsigned int count,
			 gensio_time *timeout);

GENSIO_DLL_PUBLIC
int gensio_os_funcs_wait_intr(struct gensio_os_funcs *o,
			      struct gensio_waiter *waiter, unsigned int count,
			      gensio_time *timeout);

GENSIO_DLL_PUBLIC
int gensio_os_funcs_wait_intr_sigmask(struct gensio_os_funcs *o,
				      struct gensio_waiter *waiter,
				      unsigned int count,
				      gensio_time *timeout,
				      struct gensio_os_proc_data *proc_data);

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
