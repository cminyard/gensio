/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This include file defines event loop abstractions that gensio requires.
 *
 * This is misnamed to some extent, it's not really os funcs, it's
 * event loop handling, but there are some OS things in here.
 */

#ifndef GENSIO_OS_FUNCS
#define GENSIO_OS_FUNCS

#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#include <gensio/gensio_types.h>

/* Avoid having to include SCTP headers. */
struct sctp_sndrcvinfo;

struct gensio_lock;
struct gensio_timer;
struct gensio_runner;

/* I/O descriptor. */
struct gensio_iod {
    struct gensio_os_funcs *f;
};

enum gensio_iod_type {
    GENSIO_IOD_SOCKET,
    GENSIO_IOD_PIPE,
    GENSIO_IOD_DEV,
    GENSIO_IOD_FILE,
    GENSIO_IOD_SIGNAL,
    GENSIO_IOD_STDIO
};

struct gensio_once {
    bool called;
};

/* Used by open_listen_sockets() to return the opened sockets. */
struct gensio_opensocks
{
    struct gensio_iod *iod;
    int family;
    unsigned int port;
    int flags;
};

#define GENSIO_LOG_MASK_ALL (1 << GENSIO_LOG_FATAL | 1 << GENSIO_LOG_ERR | \
	1 << GENSIO_LOG_WARNING | 1 << GENSIO_LOG_INFO | 1 << GENSIO_LOG_DEBUG)
/*
 * A bitmask of log levels to tell what to log.  Defaults to fatal and err
 * only.
 */
GENSIO_DLL_PUBLIC
void gensio_set_log_mask(unsigned int mask);
GENSIO_DLL_PUBLIC
unsigned int gensio_get_log_mask(void);
GENSIO_DLL_PUBLIC
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
     *
     * Return GE_NOMEM if it could not allocate memory to do this,
     * or GE_INVAL if fd is invalid.
     */
    int (*set_fd_handlers)(struct gensio_iod *iod,
			   void *cb_data,
			   void (*read_handler)(struct gensio_iod *iod,
						void *cb_data),
			   void (*write_handler)(struct gensio_iod *iod,
						 void *cb_data),
			   void (*except_handler)(struct gensio_iod *iod,
						  void *cb_data),
			   void (*cleared_handler)(struct gensio_iod *iod,
						   void *cb_data));

    /*
     * Clear the handlers for an fd.  Note that the operation is not
     * complete when the function returns.  The code may be running in
     * callbacks during this call, and it won't wait.  Instead,
     * cleared_handler is called when the operation completes, you
     * need to wait for that.
     */
    void (*clear_fd_handlers)(struct gensio_iod *iod);

    /*
     * Like the above, but does not call the cleared_handler function
     * when done.  This can only be called if you never enabled the
     * handlers, it is only for shutdown when an error occurs at startup.
     */
    void (*clear_fd_handlers_norpt)(struct gensio_iod *iod);

    /*
     * Enable/disable the various handlers.  Note that if you disable
     * a handler, it may still be running in a callback, this does not
     * wait.
     */
    void (*set_read_handler)(struct gensio_iod *iod, bool enable);
    void (*set_write_handler)(struct gensio_iod *iod, bool enable);
    void (*set_except_handler)(struct gensio_iod *iod, bool enable);

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
     * Start the timer running.  Returns GE_INUSE if the timer is already
     * running.  This is a relative timeout.
     */
    int (*start_timer)(struct gensio_timer *timer, gensio_time *timeout);

    /*
     * Start the timer running.  Returns GE_INUSE if the timer is already
     * running.  This is an absolute timeout based on the monotonic
     * time returned by get_monotonic_time.
     */
    int (*start_timer_abs)(struct gensio_timer *timer, gensio_time *timeout);

    /*
     * Stop the timer.  Returns GE_TIMEDOUT if the timer is not
     * running.  Note that the timer may still be running in a timeout
     * handler when this returns.
     */
    int (*stop_timer)(struct gensio_timer *timer);

    /*
     * Like the above, but the done_handler is called when the timer
     * is completely stopped and no handler is running.  If
     * GE_TIMEDOUT is returned, the done_handler is not called.  If
     * GE_INUSE is returned, that means the timer has already been
     * stopped and the done handler for the previous call has not been
     * called.
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
     * Run a runner.  Return GE_INUSE if the runner is already scheduled
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
     * returns GE_TIMEDOUT on a timeout.  It can return other errors.
     * The timeout is updated to the remaining time.
     * Note that if you get a timeout, none of the wakeups will be
     * "used" by this call.
     */
    int (*wait)(struct gensio_waiter *waiter, unsigned int count,
		gensio_time *timeout);

    /*
     * Like wait, but return if a signal is received by the thread.
     * This is useful if you want to handle SIGINT or something like
     * that.  This will return GE_INTERRUPTED if interrupted by a
     * signal, GE_TIMEDOUT if it times out.
     */
    int (*wait_intr)(struct gensio_waiter *waiter, unsigned int count,
		     gensio_time *timeout);

    /* Wake the given waiter. */
    void (*wake)(struct gensio_waiter *waiter);

    /****** Misc ******/
    /*
     * Run the timers, fd handling, runners, etc.  This does one
     * operation and returns.  If timeout is non-NULL, if nothing
     * happens before the relative time given it will return.  The
     * timeout is updated to the remaining time.  Returns
     * GE_INTERRUPTED if interrupted by a signal or GE_TIMEDOUT if the
     * timeout expired.
     */
    int (*service)(struct gensio_os_funcs *f, gensio_time *timeout);

    /* Free this structure. */
    void (*free_funcs)(struct gensio_os_funcs *f);

    /*
     * Use the "gensio_once" structure to ensure that the func is only
     * called one time.
     */
    void (*call_once)(struct gensio_os_funcs *f, struct gensio_once *once,
		      void (*func)(void *cb_data), void *cb_data);

    void (*get_monotonic_time)(struct gensio_os_funcs *f, gensio_time *time);

    /*
     * Called from the gensio library when it logs something.  This must
     * generally be set by the user, the library providing the os funcs
     * will set it to NULL.
     */
    void (*vlog)(struct gensio_os_funcs *f, enum gensio_log_levels level,
		 const char *log, va_list args);

    /*
     * Must be called after a fork() in the child if the gensio will
     * continue to be used in both the parent and the child.  If you
     * don't do this you may get undefined results.  If this returns
     * an error (gensio err), the child is likely to be unusable.
     */
    int (*handle_fork)(struct gensio_os_funcs *f);


    /****** Waiters ******/
    /*
     * Like wait_intr, but allows the user to install their own sigmask
     * atomically while waiting.  On *nix systems, sigmask is sigset_t,
     * void here to avoid type issues.
     */
    int (*wait_intr_sigmask)(struct gensio_waiter *waiter, unsigned int count,
			     gensio_time *timeout, void *sigmask);

    /****** I/O Descriptors ******/
    /*
     * Allocate an I/O descriptor for an fd.
     */
    int (*add_iod)(struct gensio_os_funcs *o, enum gensio_iod_type type,
		   int fd, struct gensio_iod **iod);

    /*
     * Release an allocated I/O descriptor.
     */
    void (*release_iod)(struct gensio_iod *iod);

    int (*iod_get_type)(struct gensio_iod *iod);
    int (*iod_get_fd)(struct gensio_iod *iod);
    int (*iod_get_protocol)(struct gensio_iod *iod);
    void (*iod_set_protocol)(struct gensio_iod *iod, int protocol);

    /****** Net Address Handling.  See gensio_addr_xxx functions for info *****/
    int (*addr_create)(struct gensio_os_funcs *o,
		       int nettype, const void *iaddr, gensiods len,
		       unsigned int port, struct gensio_addr **newaddr);
    bool (*addr_equal)(const struct gensio_addr *a1,
		       const struct gensio_addr *a2,
		       bool compare_ports, bool compare_all);
    int (*addr_to_str)(const struct gensio_addr *addr,
		       char *buf, gensiods *pos, gensiods buflen);
    int (*addr_to_str_all)(const struct gensio_addr *addr,
			   char *buf, gensiods *pos, gensiods buflen);
    struct gensio_addr *(*addr_dup)(const struct gensio_addr *iaddr);
    struct gensio_addr *(*addr_cat)(const struct gensio_addr *addr1,
				    const struct gensio_addr *addr2);
    bool (*addr_addr_present)(const struct gensio_addr *gai,
			      const void *addr, gensiods addrlen,
			      bool compare_ports);
    void (*addr_free)(struct gensio_addr *addr);
    bool (*addr_next)(struct gensio_addr *addr);
    void (*addr_rewind)(struct gensio_addr *addr);
    int (*addr_get_nettype)(const struct gensio_addr *addr);
    bool (*addr_family_supports)(const struct gensio_addr *addr,
				 int family, int flags);
    void (*addr_getaddr)(const struct gensio_addr *addr,
			 void *oaddr, gensiods *rlen);

    /*
     * Scan the str for IP addresses and create an address structure
     * from the found IPs.
     */
    int (*addr_scan_ips)(struct gensio_os_funcs *o, const char *str,
			 bool listen, int ifamily,
			 int gprotocol, bool *is_port_set, bool scan_port,
			 struct gensio_addr **raddr);

    /****** Socket Handling ******/
    int (*recv)(struct gensio_iod *iod, void *buf, gensiods buflen,
		gensiods *rcount, int gflags);
    int (*send)(struct gensio_iod *iod,
		const struct gensio_sg *sg, gensiods sglen,
		gensiods *rcount, int gflags);
    int (*sendto)(struct gensio_iod *iod,
		  const struct gensio_sg *sg, gensiods sglen,
		  gensiods *rcount, int gflags,
		  const struct gensio_addr *raddr);
    struct gensio_addr *(*addr_alloc_recvfrom)(struct gensio_os_funcs *o);
    int (*recvfrom)(struct gensio_iod *iod, void *buf, gensiods buflen,
		    gensiods *rcount, int flags, struct gensio_addr *addr);
    int (*accept)(struct gensio_iod *iod,
		  struct gensio_addr **raddr, struct gensio_iod **newiod);
    int (*check_socket_open)(struct gensio_iod *iod);
    int (*socket_open)(struct gensio_os_funcs *o,
		       const struct gensio_addr *addr, int protocol,
		       struct gensio_iod **iod);
    int (*socket_setup)(struct gensio_iod *iod,
			bool keepalive, bool nodelay,
			unsigned int opensock_flags,
			struct gensio_addr *bindaddr);
    int (*connect)(struct gensio_iod *iod,
		   const struct gensio_addr *addr);
    int (*close_socket)(struct gensio_iod **iod);
    int (*mcast_add)(struct gensio_iod *iod,
		     struct gensio_addr *mcast_addrs, int iface,
		     bool curr_only);
    int (*mcast_del)(struct gensio_iod *iod,
		     struct gensio_addr *mcast_addrs, int iface,
		     bool curr_only);
    int (*set_mcast_loop)(struct gensio_iod *iod,
			  const struct gensio_addr *addr, bool ival);
    int (*get_nodelay)(struct gensio_iod *iod, int protocol,
		       int *val);
    int (*set_nodelay)(struct gensio_iod *iod, int protocol,
		       int val);
    int (*getsockname)(struct gensio_iod *iod,
		       struct gensio_addr **raddr);
    int (*getpeername)(struct gensio_iod *iod,
		       struct gensio_addr **raddr);
    int (*getpeerraw)(struct gensio_iod *iod, void *addr, gensiods *addrlen);
    int (*socket_get_port)(struct gensio_iod *iod,
			   unsigned int *port);
    int (*setsockopt)(struct gensio_iod *iod, int level, int optname,
		      const void *optval, int optlen);
    int (*getsockopt)(struct gensio_iod *iod, int level, int optname,
		      void *optval, int *optlen);

    /*
     * Open a set of sockets given in the addr list, one per address.
     * Return the actual number of sockets opened in nr_fds.  Set the
     * I/O handler to readhndlr, with the given data.
     *
     * Note that if the function is unable to open an address, it just
     * goes on.  It returns NULL if it is unable to open any addresses.
     * Also, open IPV6 addresses first.  This way, addresses in shared
     * namespaces (like IPV4 and IPV6 on INADDR6_ANY) will work properly
     */
    int (*open_listen_sockets)(struct gensio_os_funcs *o,
			       struct gensio_addr *addr,
			       int (*call_b4_listen)(struct gensio_iod *,
						     void *),
			       void *data, unsigned int opensock_flags,
			       struct gensio_opensocks **rfds,
			       unsigned int *nr_fds);

    /****** SCTP-specific ******/
    int (*sctp_connectx)(struct gensio_iod *iod, struct gensio_addr *addrs);
    int (*sctp_recvmsg)(struct gensio_iod *iod, void *msg, gensiods len,
			gensiods *rcount,
			struct sctp_sndrcvinfo *sinfo, int *flags);
    int (*sctp_send)(struct gensio_iod *iod,
		     const struct gensio_sg *sg, gensiods sglen,
		     gensiods *rcount,
		     const struct sctp_sndrcvinfo *sinfo, uint32_t flags);
};

GENSIO_DLL_PUBLIC
void gensio_vlog(struct gensio_os_funcs *o, enum gensio_log_levels level,
		 const char *str, va_list args);
GENSIO_DLL_PUBLIC
void gensio_log(struct gensio_os_funcs *o, enum gensio_log_levels level,
		const char *str, ...);

/*
 * Allocate the OS handler for the platform.  This will return the
 * same OS handler each time.  Can return GE_NOMEM if out of memory.
 */
GENSIO_DLL_PUBLIC
int gensio_default_os_hnd(int wake_sig, struct gensio_os_funcs **o);

/* For testing, do not use in normal code. */
GENSIO_DLL_PUBLIC
void gensio_osfunc_exit(int rv);

#endif /* GENSIO_OS_FUNCS */
