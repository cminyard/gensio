/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This file defines general OS internal handling.  It's not really a
 * public include file, and is subject to change, but it useful if you
 * write your own OS handler.
 *
 * On windows, to include this file you must compile with
 *    -DNTDDI_VERSION=0x0a000006 -DWINVER=0x0602
 * to get the proper stuff.
 */

#ifndef GENSIO_OSOPS_H
#define GENSIO_OSOPS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

/*
 * Take a string in the form [ipv4|ipv6,][hostname,]port and convert
 * it to an addr structure.  If this returns success, the user
 * must free rai with gensio_free_addr().  If protocol is
 * non-zero, allocate for the given protocol only.  The value of
 * protocol is the same as for gensio_scan_network_port().
 */
GENSIO_DLL_PUBLIC
int gensio_os_scan_netaddr(struct gensio_os_funcs *o, const char *str,
			   bool listen, int protocol, struct gensio_addr **rai);

/*
 * Call o->open_listen_sockets() then set the I/O handlers with the
 * given data.
 */
GENSIO_DLL_PUBLIC
int gensio_os_open_listen_sockets(struct gensio_os_funcs *o,
		      struct gensio_addr *addr,
		      void (*readhndlr)(struct gensio_iod *, void *),
		      void (*writehndlr)(struct gensio_iod *, void *),
		      void (*fd_handler_cleared)(struct gensio_iod *, void *),
		      int (*call_b4_listen)(struct gensio_iod *, void *),
		      void *data, unsigned int opensock_flags,
		      struct gensio_opensocks **rfds, unsigned int *rnr_fds);

#include <gensio/netif.h>

/*
 * Returns a NULL if the fd is ok, a non-NULL error string if not.
 * Uses the default progname ("gensio", or set with
 * gensio_set_progname() if progname is NULL.
 */
GENSIO_DLL_PUBLIC
const char *gensio_os_check_tcpd_ok(struct gensio_iod *iod,
				    const char *progname);


/*
 * OS-specific functions for various things.  This are primarily for
 * use by OS handlers inside outside of the main library.
 */

struct stdio_mode;

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

GENSIO_DLL_PUBLIC
int gensio_win_stdin_makeraw(struct gensio_os_funcs *o, HANDLE h,
			     struct stdio_mode **m);

GENSIO_DLL_PUBLIC
int gensio_win_stdout_makeraw(struct gensio_os_funcs *o, HANDLE h,
			      struct stdio_mode **m);

GENSIO_DLL_PUBLIC
void gensio_win_stdio_cleanup(struct gensio_os_funcs *o, HANDLE h,
			      struct stdio_mode **m);

struct gensio_win_commport;

GENSIO_DLL_PUBLIC
int gensio_win_setup_commport(struct gensio_os_funcs *o, HANDLE h,
			      struct gensio_win_commport **c,
			      HANDLE *break_timer);

GENSIO_DLL_PUBLIC
void gensio_win_cleanup_commport(struct gensio_os_funcs *o, HANDLE h,
				 struct gensio_win_commport **c);

GENSIO_DLL_PUBLIC
int gensio_win_commport_control(struct gensio_os_funcs *o, int op, bool get,
				intptr_t val,
				struct gensio_win_commport **c, HANDLE h);

GENSIO_DLL_PUBLIC
DWORD gensio_win_commport_break_done(struct gensio_os_funcs *o, HANDLE h,
				     struct gensio_win_commport **c);

GENSIO_DLL_PUBLIC
int gensio_win_do_exec(struct gensio_os_funcs *o,
		       const char *argv[], const char **env,
		       const char *start_dir,
		       unsigned int flags,
		       HANDLE *phandle,
		       HANDLE *rin, HANDLE *rout, HANDLE *rerr);

/*
 * Create a user authentication token for the given user with the
 * given password.  If password is NULL, this will attempt an S4U
 * logon.  The resulting token is really only usable for impersonation
 * or query.  A normal login is attempted otherwise.
 *
 * If a domain is in the user (in the form domain\username), a
 * kerberos logon is attempted.  Otherwise a normal Windows logon is
 * done.
 *
 * groups is an array of pointers to characters (const char *groups[])
 * that holds SID strings for groups to add to the token.  This may be
 * NULL and only applies for interactive logons.
 *
 * If interactive is true, the token will be good for logon.
 * Otherwise it will only be good for impersonation or query.
 */
GENSIO_DLL_PUBLIC
int gensio_win_get_user_token(const char *user, const char *password,
			      const char *src_module, const char **groups,
			      bool interactive, HANDLE *userh);

/*
 * Allocate a PseudoConsole.
 *
 * rreadh and rwriteh are return values for the handle to read from
 * here and the handle to write to here in this process.
 *
 * child_in and child_out are handles that the child process will use
 * for it's stdin and stdout.  You should close these when done, or
 * let gensio_win_pty_start close them for you.
 */
GENSIO_DLL_PUBLIC
int gensio_win_pty_alloc(struct gensio_os_funcs *o,
			 HANDLE *rreadh, HANDLE *rwriteh,
			 HANDLE *child_in, HANDLE *child_out,
			 HPCON *rptyh);

/*
 * Start an allocated PseudoConsole.
 *
 * Start the process specified by argv on the given pseudoconsole.
 * Set it's environment to env, and start it in start_dir.  The new
 * processes' stdin is set to child_in, and its stdout and stderr are
 * set to child_out.
 *
 * The child process handle is returned in child.
 *
 * If an impersonation token is set when this is called, the token is
 * extracted from the thread and the new process will be started with
 * that token.
 *
 * Note: If this is successful, it will NULL child_in and child_out.
 */
GENSIO_DLL_PUBLIC
int gensio_win_pty_start(struct gensio_os_funcs *o,
			 HPCON ptyh, HANDLE *child_in, HANDLE *child_out,
			 const char **argv, const char **env,
			 const char *start_dir, HANDLE *child);

#else

#include <sys/types.h>

GENSIO_DLL_PUBLIC
int gensio_unix_do_nonblock(struct gensio_os_funcs *o, int fd,
			    struct stdio_mode **m);

GENSIO_DLL_PUBLIC
void gensio_unix_do_cleanup_nonblock(struct gensio_os_funcs *o, int fd,
				     struct stdio_mode **m);

struct gensio_unix_termios;

GENSIO_DLL_PUBLIC
int gensio_unix_setup_termios(struct gensio_os_funcs *o, int fd,
			      struct gensio_unix_termios **t);

GENSIO_DLL_PUBLIC
void gensio_unix_cleanup_termios(struct gensio_os_funcs *o,
				 struct gensio_unix_termios **t, int fd);

GENSIO_DLL_PUBLIC
int gensio_unix_termios_control(struct gensio_os_funcs *o, int op, bool get,
				intptr_t val,
				struct gensio_unix_termios **t, int fd);

GENSIO_DLL_PUBLIC
void gensio_unix_do_flush(struct gensio_os_funcs *o, int fd, int whichbuf);

GENSIO_DLL_PUBLIC
int gensio_unix_get_bufcount(struct gensio_os_funcs *o,
			     int fd, int whichbuf, gensiods *rcount);

GENSIO_DLL_PUBLIC
int gensio_unix_do_exec(struct gensio_os_funcs *o,
			const char *argv[], const char **env,
			const char *start_dir,
			unsigned int flags,
			int *rpid,
			int *rin, int *rout, int *rerr);

GENSIO_DLL_PUBLIC
int gensio_unix_os_setupnewprog(void);

GENSIO_DLL_PUBLIC
int gensio_unix_pty_alloc(struct gensio_os_funcs *o, int *rfd);

GENSIO_DLL_PUBLIC
int gensio_unix_pty_start(struct gensio_os_funcs *o,
			  int pfd, const char **argv, const char **env,
			  const char *start_dir, pid_t *rpid);

#endif /* _WIN32 */

/*
 * Memory error testing.  If GENSIO_MEMTRACK is set in the
 * environment, track all memory allocated and freed and validate it.
 * To use this, allocate one, and pass it in to the alloc and free
 * functions.  When done, after freeing all memory (we hope), call
 * cleanup.  Cleanup will report if any memory wasn't freed.
 *
 * If GENSIO_MEMTRACK has "abort" in the string, it will abort on a
 * memory error.  If it has "checkall" in the string, check all memory
 * on every free.
 */
struct gensio_memtrack;

GENSIO_DLL_PUBLIC
struct gensio_memtrack *gensio_memtrack_alloc(void);

GENSIO_DLL_PUBLIC
void gensio_memtrack_cleanup(struct gensio_memtrack *m);

GENSIO_DLL_PUBLIC
void *gensio_i_zalloc(struct gensio_memtrack *m, unsigned int size);

GENSIO_DLL_PUBLIC
void gensio_i_free(struct gensio_memtrack *m, void *data);

#ifdef __cplusplus
}
#endif
#endif /* GENSIO_OSOPS_H */
