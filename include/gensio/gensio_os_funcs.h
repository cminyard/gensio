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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#include <gensio/gensio_types.h>
#include <gensio/gensio_dllvisibility.h>

/* Avoid having to include SCTP headers. */
struct sctp_sndrcvinfo;
struct sctp_initmsg;
struct sctp_sack_info;
struct sctp_status;

struct gensio_lock;
struct gensio_timer;
struct gensio_runner;
struct gensio_waiter;

/* I/O descriptor. */
struct gensio_iod {
    /*
     * All iods have a gensio_os_funcs in them, make it available to aovid
     * having to pass it around.
     */
    struct gensio_os_funcs *f;
};

enum gensio_iod_type {
    GESNIO_IOD_INVALID, /* Not used for anything the user will see. */
    GENSIO_IOD_SOCKET,
    GENSIO_IOD_PIPE,
    GENSIO_IOD_DEV,
    GENSIO_IOD_FILE,
    GENSIO_IOD_SIGNAL,

    /*
     * The stdio iod works differently than the other ones.  It will
     * actually not create a stdio iod, instead it will detect the
     * type of device or file that stdio uses and create one of those
     * iods.
     */
    GENSIO_IOD_STDIO,

    /*
     * Console iods will open /dev/tty on *nix or CONxx$ on Windows.
     * It takes 0 or 1 for input and output for the fd, but the actual
     * fd will be different.
     */
    GENSIO_IOD_CONSOLE,

    /* Must be last */
    NR_GENSIO_IOD_TYPES
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

/*
 * Flags for opensock_flags.  For the set function, add the _SET_
 * flags for the options you want to set, and set the option bits for
 * the options' values.  For get, add the _SET_ flag and the values
 * will be set upon return.
 */
#define GENSIO_OPENSOCK_REUSEADDR	(1 << 0)
#define GENSIO_SET_OPENSOCK_REUSEADDR	(1 << 1)
#define GENSIO_OPENSOCK_KEEPALIVE	(1 << 2)
#define GENSIO_SET_OPENSOCK_KEEPALIVE	(1 << 3)
#define GENSIO_OPENSOCK_NODELAY		(1 << 4)
#define GENSIO_SET_OPENSOCK_NODELAY	(1 << 5)

/* For recv and send */
#define GENSIO_MSG_OOB 1

/******************************************************************
 * For sock_control()
 */

/*
 * Enable/disable loopback mode on a socket.  Default is disabled.
 * data is the gensio address and datalen is a bool pointer to the value.
 */
#define GENSIO_SOCKCTL_SET_MCAST_LOOP	1

/*
 * Get the address info for the local socket connection.  This can be
 * called on all types of sockets.  data is a pointer to the gensio
 * address, datalen is not used and should be NULL.
 */
#define GENSIO_SOCKCTL_GET_SOCKNAME	2

/*
 * Get the address info for the remote end of the socket connection.
 * Only valid on connected sockets.  data is a pointer to the gensio
 * address, datalen is not used and should be NULL.
 */
#define GENSIO_SOCKCTL_GET_PEERNAME	3

/*
 * Get the address info for the remote end of the socket in it's raw
 * form.  data points to a block of data and datalen points to the
 * data size.  datalen will be updated with the actual length used.
 */
#define GENSIO_SOCKCTL_GET_PEERRAW	4

/*
 * Get the port for the socket.  data points to an unsigned integer,
 * datalen should point to an integer with sizeof(unsigned int) in it.
 */
#define GENSIO_SOCKCTL_GET_PORT		5

/*
 * The check_socket_open can be called to check for open status.
 * Returns the open status for the socket.  data and datalen are not
 * used and should be NULL.
 */
#define GENSIO_SOCKCTL_CHECK_OPEN	6

/******************************************************************
 * For iod_control()
 */

/*
 * Serial port settings.  SERDATA get gets the current serial port
 * data info in a form that can be re-applied with a set operation.
 * The individual controls (BAUD, PARITY, etc) can be changed, but
 * this only changes the internal data, not the actual settings on the
 * port.  To copy the internal data to the port, use APPLY set
 * operation.
 */
/*
 * Get returns an allocated block of data with serial data.  Set sets
 * the current settings from the block of data, but does not apply it.
 */
#define GENSIO_IOD_CONTROL_SERDATA	1

/* Free an allocated block of serial data. */
#define GENSIO_IOD_CONTROL_FREE_SERDATA	2

/* The baud, as an int */
#define GENSIO_IOD_CONTROL_BAUD		3

/* Parity as an int, SERGENSIO_PARITY_xxx */
#define GENSIO_IOD_CONTROL_PARITY	4

/* xonxoff output flow-control as an int, bool */
#define GENSIO_IOD_CONTROL_XONXOFF	5

/* rtscts flow-control as an int, bool */
#define GENSIO_IOD_CONTROL_RTSCTS	6

/* datasize as an int (5, 6, 7, 8) */
#define GENSIO_IOD_CONTROL_DATASIZE	7

/* stopbits as an int (1, 2) */
#define GENSIO_IOD_CONTROL_STOPBITS	8

/* local as an int, bool */
#define GENSIO_IOD_CONTROL_LOCAL	9

/* HUPCL as an int, bool */
#define GENSIO_IOD_CONTROL_HANGUP_ON_DONE 10

/* RS485 as an string */
#define GENSIO_IOD_CONTROL_RS485	11

/* xonxoff input flow-control as an int, bool */
#define GENSIO_IOD_CONTROL_IXONXOFF	12

/* Apply the set values to the serial port. */
#define GENSIO_IOD_CONTROL_APPLY	19

/*
 * These are modem line operations, they occur immediately.  Send
 * break sends a break for a period of time.  MODEMSTATE returns the
 * current modem lines in the form specified in sergensio.h.
 */

/* get/set the break as an int, bool */
#define GENSIO_IOD_CONTROL_SET_BREAK	20

/* get/et the break, val is ignored */
#define GENSIO_IOD_CONTROL_SEND_BREAK	21

/* get/set the DTR line as an int, bool */
#define GENSIO_IOD_CONTROL_DTR		22

/* get/set the RTS line as an int, bool */
#define GENSIO_IOD_CONTROL_RTS		23

/* Get the modem control lines, SERGENSIO_MODEMSTATE_[CTS|DSR|RI|CD] bitmask */
#define GENSIO_IOD_CONTROL_MODEMSTATE   24

/* Set the flow control state, int as a bool. */
#define GENSIO_IOD_CONTROL_FLOWCTL_STATE 25

/* Windows sockets only, is the socket closed? */
#define GENSIO_IOD_CONTROL_IS_CLOSED 26

/*
 * Used by wait functions and general handling for process setup and
 * cleanup.
 */
struct gensio_os_proc_data;


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
     *
     * Note that if you stop a timer with a done handler, you cannot
     * start the timer until the done handler is called.
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

    /*
     * Like wait_intr, but allows machine-specific handling to be set
     * up.  See gensio_os_proc_setup() for info.
     */
    int (*wait_intr_sigmask)(struct gensio_waiter *waiter, unsigned int count,
			     gensio_time *timeout,
			     struct gensio_os_proc_data *proc_data);

    /* Wake the given waiter. */
    void (*wake)(struct gensio_waiter *waiter);

    /****** Misc ******/
    /*
     * Run the timers, fd handling, runners, etc.  This does one
     * operation and returns.  If timeout is non-NULL, if nothing
     * happens before the relative time given it will return.  The
     * timeout is updated to the remaining time.  Returns
     * GE_INTERRUPTED if interrupted by a signal or GE_TIMEDOUT if the
     * timeout expired.  Note that really long timeouts (days) may be
     * shortened to some value.
     */
    int (*service)(struct gensio_os_funcs *f, gensio_time *timeout);

    /*
     * Returns the Unix signal used for waking other threads.  Will be
     * NULL if not supported.  Returns zero if the single-threaded.
     */
    int (*get_wake_sig)(struct gensio_os_funcs *f);

    /*
     * get/free this structure.  At allocation the refcount is one,
     * get increments the refcounta and free decrements it.  If the
     * refcount reaches zero, free the structure.
     */
    struct gensio_os_funcs *(*get_funcs)(struct gensio_os_funcs *f);
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

    /*
     * Return some random data.  May not be cryptographically secure.
     */
    int (*get_random)(struct gensio_os_funcs *f,
		      void *data, unsigned int len);

    /****** I/O Descriptors ******/
    /*
     * Allocate an I/O descriptor for an fd.
     */
    int (*add_iod)(struct gensio_os_funcs *o, enum gensio_iod_type type,
		   intptr_t fd, struct gensio_iod **iod);

    /*
     * Release an allocated I/O descriptor.  Note that close() will
     * also call this, so if you call close you shouldn't call this.
     * And you should generally use close unless you have already
     * closed the I/O device and just need to release the memory.
     */
    void (*release_iod)(struct gensio_iod *iod);

    /*
     * Get/set some iod internals.  Setting is only for OS handlers.
     */
    int (*iod_get_type)(struct gensio_iod *iod);
    int (*iod_get_fd)(struct gensio_iod *iod);
    int (*iod_get_protocol)(struct gensio_iod *iod);
    void (*iod_set_protocol)(struct gensio_iod *iod, int protocol);

    /*
     * iod-specific control operations.
     */
    int (*iod_control)(struct gensio_iod *iod, int op, bool get, intptr_t val);

    /****** Generic OS functions ******/
    /*
     * Set the I/O descriptor non-blocking.  Note that release_iod
     * will restore the original value if necessary.
     */
    int (*set_non_blocking)(struct gensio_iod *iod);
    /* Close the I/O descriptor.  Sets what iod point to to NULL. */
    int (*close)(struct gensio_iod **iod);
    /*
     * Like close, but if the close would result in data being lost,
     * return GE_INPROGRESS and don't close
     */
    int (*graceful_close)(struct gensio_iod **iod);
    /* Write some data to the I/O descriptor. */
    int (*write)(struct gensio_iod *iod, const struct gensio_sg *sg,
		 gensiods sglen, gensiods *rcount);
    /* Read some data from the I/O descriptor. */
    int (*read)(struct gensio_iod *iod, void *buf, gensiods buflen,
		gensiods *rcount);

    /*
     * Return true if the if is a nornal file, or false if not.  If it
     * cannot determine, return false.
     */

    bool (*is_regfile)(struct gensio_os_funcs *f, intptr_t fd);

#define GENSIO_IN_BUF	(1 << 0)
#define GENSIO_OUT_BUF	(1 << 1)
    /*
     * Return the number of pending bytes on a buffer.  It only works
     * on a few iods, and returns GE_NOSUP if it's not supported.
     * whichbuf only takes one value, not a bitmask.
     */
    int (*bufcount)(struct gensio_iod *iod, int whichbuf, gensiods *count);

    /*
     * Remove all the data from the I/O's buffer without sending it.
     * whichbuf is a bitmask.
     */
    void (*flush)(struct gensio_iod *iod, int whichbuf);

    /*
     * Put the device into "raw" mode.  For most iods you will get
     * GE_NOTSUP, but for consoles, serial ports (UNIX) and stdio it
     * will put the device into character-at-a-time.  For stdio you
     * should set both stdin (0) and stdout (1) to raw.
     */
    int (*makeraw)(struct gensio_iod *iod);

#define GENSIO_OPEN_OPTION_READABLE	(1 << 0)
#define GENSIO_OPEN_OPTION_WRITEABLE	(1 << 1)
    int (*open_dev)(struct gensio_os_funcs *o, const char *name, int options,
		    struct gensio_iod **iod);

    /*
     * Execute a sub-program and return the pid, stdin, stdout,
     * stderr.  If you set stderr_to_stdout, then stderr will be sent
     * to stdout and rstderr should be NULL.  Otherwise if you want to
     * leave stderr to the caller's stderr, then set rstderr to NULL.
     *
     * Note that you must wait for the subprogram after you think it
     * has terminated, and the wait must return without error, to
     * avoid leaking resources.
     */
    int (*exec_subprog)(struct gensio_os_funcs *o,
			const char *argv[], const char **env,
			bool stderr_to_stdout,
			intptr_t *rpid,
			struct gensio_iod **rstdin,
			struct gensio_iod **rstdout,
			struct gensio_iod **rstderr);
    /*
     * Attempt to stop a subprogram.  If force is given, don't get the
     * subprogram an option (kill -1).  You still must wait on the
     * subprogramm.
     */
    int (*kill_subprog)(struct gensio_os_funcs *o, intptr_t pid, bool force);
    /* Wait for a program to terminate. */
    int (*wait_subprog)(struct gensio_os_funcs *o, intptr_t pid, int *retcode);

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
     *
     * If listen is set, then addresses suitable for listen sockets
     * are created.
     *
     * protocol is one of GENSIO_NET_PROTOCOL_xxx.

     * If scan_port is true, scan for port numbers after the
     * addresses, seperated by a ','.  If the port is not there then
     * is_port_set will be set to false.  If the port is there, it
     * will be set to true.  The ports must all be the same or
     * GE_INCONSISTENT is returned.
     */
    int (*addr_scan_ips)(struct gensio_os_funcs *o, const char *str,
			 bool listen, int ifamily,
			 int protocol, bool *is_port_set, bool scan_port,
			 struct gensio_addr **raddr);

    /****** Socket Handling ******/
    /* Allocate an address suitable for using with recvfrom. */
    struct gensio_addr *(*addr_alloc_recvfrom)(struct gensio_os_funcs *o);

    /* Standard socket functions. */
    int (*recv)(struct gensio_iod *iod, void *buf, gensiods buflen,
		gensiods *rcount, int gflags);
    int (*send)(struct gensio_iod *iod,
		const struct gensio_sg *sg, gensiods sglen,
		gensiods *rcount, int gflags);
    int (*sendto)(struct gensio_iod *iod,
		  const struct gensio_sg *sg, gensiods sglen,
		  gensiods *rcount, int gflags,
		  const struct gensio_addr *raddr);
    int (*recvfrom)(struct gensio_iod *iod, void *buf, gensiods buflen,
		    gensiods *rcount, int flags, struct gensio_addr *addr);
    int (*accept)(struct gensio_iod *iod,
		  struct gensio_addr **raddr, struct gensio_iod **newiod);
    int (*connect)(struct gensio_iod *iod,
		   const struct gensio_addr *addr);

    /*
     * Note that close_socket can only be used on sockets.  The normal
     * close should be used on sockets, this is only for internal use
     * for OS handlers to do special socket handling on close.  If this
     * returns GE_INPROGRESS, it should be retried until it returns zero
     * or another error.  If force is true, the socket will be closed
     * and data will be lost.  If force is false, if data is still pending
     * and the close would lose it, return GE_INPROGRESS.
     */
    int (*close_socket)(struct gensio_iod *iod, bool retry, bool force);

    /*
     * Open a socket, non-blocking.  The iod can be added with
     * set_fd_handlers and the write handler will be called then the
     * open completes.
     */
    int (*socket_open)(struct gensio_os_funcs *o,
		       const struct gensio_addr *addr, int protocol,
		       struct gensio_iod **iod);

    /*
     * Set/get options on sockets.  See GENSIO_SET_OPENSOCK_xxx for
     * details.  If bindaaddr is set in the set_setup function, bind
     * the socket to the given address.
     */
    int (*socket_set_setup)(struct gensio_iod *iod,
			    unsigned int opensock_flags,
			    struct gensio_addr *bindaddr);
    int (*socket_get_setup)(struct gensio_iod *iod,
			    unsigned int *opensock_flags);

    /*
     * For UDP sockets, modify the multicast addresses for the socket.
     * curr_only says whether to only use the current address os
     * mcast_addrs, or if all the addresses in mcast_addrs should be
     * added/deleted.
     */
    int (*mcast_add)(struct gensio_iod *iod,
		     struct gensio_addr *mcast_addrs, int iface,
		     bool curr_only);
    int (*mcast_del)(struct gensio_iod *iod,
		     struct gensio_addr *mcast_addrs, int iface,
		     bool curr_only);

    /* Various control functions, see GENSIO_SOCKCTL_xxx for functions. */
    int (*sock_control)(struct gensio_iod *iod, int func,
			void *data, gensiods *datalen);

    /*
     * Open a set of sockets given in the addr list, binding them and
     * enabling listen, one per address.  Returns the sockets and info
     * in fds and the actual number of sockets opened in nr_fds.  The
     * sockets are set non-blocking.
     *
     * After the socket is set up but before listen is called,
     * call_b4_listen is called.
     *
     * Note that if the function is unable to open an address, it just
     * goes on.  It returns GE_NOTFOUND if it is unable to open any
     * addresses.
     *
     * Opens IPV6 addresses first.  This way, addresses in shared
     * namespaces (like IPV4 and IPV6 on INADDR6_ANY) will work
     * properly
     */
    int (*open_listen_sockets)(struct gensio_os_funcs *o,
			       struct gensio_addr *addr,
			       int (*call_b4_listen)(struct gensio_iod *,
						     void *),
			       void *data, unsigned int opensock_flags,
			       struct gensio_opensocks **fds,
			       unsigned int *nr_fds);

    /* SCTP-specific socket functions.  May be NULL if SCTP not supported. */
    int (*sctp_connectx)(struct gensio_iod *iod, struct gensio_addr *addrs);
    int (*sctp_recvmsg)(struct gensio_iod *iod, void *msg, gensiods len,
			gensiods *rcount,
			struct sctp_sndrcvinfo *sinfo, int *flags);
    int (*sctp_send)(struct gensio_iod *iod,
		     const struct gensio_sg *sg, gensiods sglen,
		     gensiods *rcount,
		     const struct sctp_sndrcvinfo *sinfo, uint32_t flags);
    int (*sctp_socket_setup)(struct gensio_iod *iod, bool events,
			     struct sctp_initmsg *initmsg,
			     struct sctp_sack_info *sackinfo);
    int (*sctp_get_socket_status)(struct gensio_iod *iod,
				  struct sctp_status *status);
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

#ifdef _WIN32
#define GENSIO_DEF_WAKE_SIG 0
#else
#include <signal.h>
#define GENSIO_DEF_WAKE_SIG SIGUSR1
GENSIO_DLL_PUBLIC
sigset_t *gensio_os_proc_unix_get_wait_sigset(struct gensio_os_proc_data *data);
#endif

/*
 * Basic thread handling.  You can use the standard OS functions to do
 * this, too, this is here for genericity.  It may not cover all your
 * needs.
 */
struct gensio_thread;

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

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_OS_FUNCS */
