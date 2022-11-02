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
#include <gensio/gensioosh_dllvisibility.h>

GENSIOOSH_DLL_PUBLIC
int gensio_default_os_hnd(int wake_sig, struct gensio_os_funcs **o);

GENSIOOSH_DLL_PUBLIC
int gensio_os_proc_setup(struct gensio_os_funcs *o,
			 struct gensio_os_proc_data **data);

GENSIOOSH_DLL_PUBLIC
void gensio_os_proc_cleanup(struct gensio_os_proc_data *data);

GENSIOOSH_DLL_PUBLIC
int gensio_os_proc_register_term_handler(struct gensio_os_proc_data *data,
					 void (*handler)(void *handler_data),
					 void *handler_data);

GENSIOOSH_DLL_PUBLIC
int gensio_os_proc_register_reload_handler(struct gensio_os_proc_data *data,
					   void (*handler)(void *handler_data),
					   void *handler_data);


GENSIOOSH_DLL_PUBLIC
int gensio_os_proc_register_winsize_handler(struct gensio_os_proc_data *data,
					struct gensio_iod *console_iod,
					void (*handler)(int x_chrs, int y_chrs,
							int x_bits, int y_bits,
							void *handler_data),
					void *handler_data);

GENSIOOSH_DLL_PUBLIC
int gensio_os_new_thread(struct gensio_os_funcs *o,
			 void (*start_func)(void *data), void *data,
			 struct gensio_thread **thread_id);

GENSIOOSH_DLL_PUBLIC
int gensio_os_wait_thread(struct gensio_thread *thread_id);

GENSIOOSH_DLL_PUBLIC
void *gensio_os_funcs_zalloc(struct gensio_os_funcs *o, gensiods len);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_zfree(struct gensio_os_funcs *o, void *data);

GENSIOOSH_DLL_PUBLIC
struct gensio_lock *gensio_os_funcs_alloc_lock(struct gensio_os_funcs *o);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_free_lock(struct gensio_os_funcs *o,
			       struct gensio_lock *lock);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_lock(struct gensio_os_funcs *o,
			  struct gensio_lock *lock);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_unlock(struct gensio_os_funcs *o,
			    struct gensio_lock *lock);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_get_monotonic_time(struct gensio_os_funcs *o,
					gensio_time *time);

GENSIOOSH_DLL_PUBLIC
struct gensio_timer *gensio_os_funcs_alloc_timer(struct gensio_os_funcs *o,
				    void (*handler)(struct gensio_timer *t,
						    void *cb_data),
				    void *cb_data);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_free_timer(struct gensio_os_funcs *o,
				struct gensio_timer *timer);

GENSIOOSH_DLL_PUBLIC
int gensio_os_funcs_start_timer(struct gensio_os_funcs *o,
				struct gensio_timer *timer,
				gensio_time *timeout);

GENSIOOSH_DLL_PUBLIC
int gensio_os_funcs_start_timer_abs(struct gensio_os_funcs *o,
				    struct gensio_timer *timer,
				    gensio_time *timeout);

GENSIOOSH_DLL_PUBLIC
int gensio_os_funcs_stop_timer(struct gensio_os_funcs *o,
			       struct gensio_timer *timer);

GENSIOOSH_DLL_PUBLIC
int gensio_os_funcs_stop_timer_with_done(struct gensio_os_funcs *o,
			    struct gensio_timer *timer,
			    void (*done_handler)(struct gensio_timer *t,
						 void *cb_data),
			    void *cb_data);

GENSIOOSH_DLL_PUBLIC
struct gensio_runner *gensio_os_funcs_alloc_runner(struct gensio_os_funcs *o,
				      void (*handler)(struct gensio_runner *r,
						      void *cb_data),
				      void *cb_data);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_free_runner(struct gensio_os_funcs *o,
				 struct gensio_runner *runner);

GENSIOOSH_DLL_PUBLIC
int gensio_os_funcs_run(struct gensio_os_funcs *o,
			struct gensio_runner *runner);

typedef void (gensio_vlog_func)(struct gensio_os_funcs *o,
				enum gensio_log_levels level,
				const char *log, va_list args);
GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_set_vlog(struct gensio_os_funcs *o, gensio_vlog_func func);
GENSIOOSH_DLL_PUBLIC
gensio_vlog_func *gensio_os_funcs_get_vlog(struct gensio_os_funcs *o);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_free(struct gensio_os_funcs *o);

GENSIOOSH_DLL_PUBLIC
int gensio_os_funcs_service(struct gensio_os_funcs *o, gensio_time *timeout);

GENSIOOSH_DLL_PUBLIC
int gensio_os_funcs_handle_fork(struct gensio_os_funcs *o);

GENSIOOSH_DLL_PUBLIC
struct gensio_waiter *gensio_os_funcs_alloc_waiter(struct gensio_os_funcs *o);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_free_waiter(struct gensio_os_funcs *o,
				 struct gensio_waiter *waiter);

GENSIOOSH_DLL_PUBLIC
int gensio_os_funcs_wait(struct gensio_os_funcs *o,
			 struct gensio_waiter *waiter, unsigned int count,
			 gensio_time *timeout);

GENSIOOSH_DLL_PUBLIC
int gensio_os_funcs_wait_intr(struct gensio_os_funcs *o,
			      struct gensio_waiter *waiter, unsigned int count,
			      gensio_time *timeout);

GENSIOOSH_DLL_PUBLIC
int gensio_os_funcs_wait_intr_sigmask(struct gensio_os_funcs *o,
				      struct gensio_waiter *waiter,
				      unsigned int count,
				      gensio_time *timeout,
				      struct gensio_os_proc_data *proc_data);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_wake(struct gensio_os_funcs *o,
			  struct gensio_waiter *waiter);

GENSIOOSH_DLL_PUBLIC
void gensio_os_funcs_set_data(struct gensio_os_funcs *o, void *data);

GENSIOOSH_DLL_PUBLIC
void *gensio_os_funcs_get_data(struct gensio_os_funcs *o);

/*
 * Set the program name, used by TCPD (and possibly others).  You should
 * do this very early in initialization, first if possible.  The default
 * progname is "gensio".
 *
 * The string is *NOT* copied, so you must make sure it stays around.
 * Generally you are passing in a constant string or part of argv[0],
 * so it's not a problem
 */
GENSIOOSH_DLL_PUBLIC
bool gensio_set_progname(const char *progname);
GENSIOOSH_DLL_PUBLIC
const char *gensio_get_progname(void);

/*
 * Scan for a network port in the form:
 *
 *   <ipspec><protocol>,<hostnames>
 *
 *   protocol = [tcp|udp|sctp|unix[(<args>)]]
 *
 * for unix:
 *   hostnames = <file path>
 *
 * for others:
 *   hostnames = [[...]<ipspec>[<hostname>,]<port>,]<ipspec>[<hostname>,]<port>
 *
 *   ipspec = [ipv4|ipv6|ipv6n4,]
 *
 * ipspec is not allowed with unix.
 *
 * The initial ipspec sets the default for all the addresses.  If it
 * is not specified, the default if AF_UNSPEC and everything will
 * be returned.
 *
 * If a protocol is not specified, the TCP is assumed.
 *
 * If the args parameter supplied is NULL, then you cannot specify
 * args in the string, EINVAL will be returned.
 *
 * You can specify the IP address type on each hostname/port and it
 * overrides the default.  The hostname can be a resolvable hostname,
 * an IPv4 octet, an IPv6 address, or an empty string.  If it is not
 * supplied, inaddr_any is used.  In the absence of a hostname
 * specification, a wildcard address is used.  The mandatory second
 * part is the port number or a service name.
 *
 * An all zero port means use any port. If the port is all zero on any
 * address, then is_port_set is set to false, true otherwise.
 *
 * The protocol type is returned, either TCP, UDP, or SCTP.  Protocol
 * may be NULL.
 *
 * ai should be freed with gensio_addr_free().
 *
 * args should be freed with str_to_argv_free().
 */
GENSIOOSH_DLL_PUBLIC
int gensio_scan_network_port(struct gensio_os_funcs *o, const char *str,
			     bool listen, struct gensio_addr **ai,
			     int *protocol, bool *is_port_set,
			     int *argc, const char ***args);

/*
 * Like the above, but only scan for addresses in a list, no ports, no
 * protocol, like: "::1,ipv4,10.0.2.3".  This only works on IP
 * addresses.
 */
GENSIOOSH_DLL_PUBLIC
int gensio_scan_network_addr(struct gensio_os_funcs *o, const char *str,
			     int protocol, struct gensio_addr **ai);

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
