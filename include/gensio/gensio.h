/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This include file defines a network I/O abstraction to allow code
 * to use TCP, UDP, stdio, telnet, ssl, etc. without having to know
 * the underlying details.
 */

#ifndef GENSIO_H
#define GENSIO_H

#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>
#include <gensio/gensio_deprecated.h>
#include <gensio/gensio_err.h>
#include <gensio/gensio_version.h>

/*
 * This should eventually go away in preference to the functions given
 * inthe include just below.
 */
#include <gensio/gensio_os_funcs.h>

/*
 * The gensio_os_funcs_xxx() functions in the following are accessors
 * for user-visible operations on the os functions.  Do not use the
 * functions in gensio_os_funcs directly from user code.
 */
#include <gensio/gensio_os_funcs_public.h>

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

GENSIO_DLL_PUBLIC
void gensio_vlog(struct gensio_os_funcs *o, enum gensio_log_levels level,
		 const char *str, va_list args);
GENSIO_DLL_PUBLIC
void gensio_log(struct gensio_os_funcs *o, enum gensio_log_levels level,
		const char *str, ...);

/*
 * The following are documented in gensio_event.3
 */
#define GENSIO_EVENT_READ		1
#define GENSIO_EVENT_WRITE_READY	2
#define GENSIO_EVENT_NEW_CHANNEL	3
#define GENSIO_EVENT_SEND_BREAK		4
#define GENSIO_EVENT_AUTH_BEGIN		5
#define GENSIO_EVENT_PRECERT_VERIFY	6
#define GENSIO_EVENT_POSTCERT_VERIFY	7
#define GENSIO_EVENT_PASSWORD_VERIFY	8
#define GENSIO_EVENT_REQUEST_PASSWORD	9
#define GENSIO_EVENT_REQUEST_2FA	10
#define GENSIO_EVENT_2FA_VERIFY		11

/*
 * Serial callbacks start here and run to 2000.
 */
#define SERGENSIO_EVENT_BASE	1000
#define SERGENSIO_EVENT_MAX	1999

/*
 * If a user creates their own gensio with their own events, they should
 * use this range.
 */
#define GENSIO_EVENT_USER_MIN		100000
#define GENSIO_EVENT_USER_MAX		199999

GENSIO_DLL_PUBLIC
int str_to_gensio(const char *str,
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **gensio);

GENSIO_DLL_PUBLIC
int str_to_gensio_child(struct gensio *child, const char *str,
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **gensio);

GENSIO_DLL_PUBLIC
void gensio_set_callback(struct gensio *io, gensio_event cb, void *user_data);

GENSIO_DLL_PUBLIC
void *gensio_get_user_data(struct gensio *io);

GENSIO_DLL_PUBLIC
void gensio_set_user_data(struct gensio *io, void *user_data);

GENSIO_DLL_PUBLIC
int gensio_write(struct gensio *io, gensiods *count,
		 const void *buf, gensiods buflen,
		 const char *const *auxdata);

GENSIO_DLL_PUBLIC
int gensio_write_sg(struct gensio *io, gensiods *count,
		    const struct gensio_sg *sg, gensiods sglen,
		    const char *const *auxdata);

/* DEPRECATED - Do not use this function. */
GENSIO_DLL_PUBLIC
int gensio_raddr_to_str(struct gensio *io, gensiods *pos,
			char *buf, gensiods buflen)
    GENSIO_FUNC_DEPRECATED;

/* DEPRECATED - Do not use this function. */
GENSIO_DLL_PUBLIC
int gensio_get_raddr(struct gensio *io, void *addr, gensiods *addrlen)
    GENSIO_FUNC_DEPRECATED;

GENSIO_DLL_PUBLIC
int gensio_open(struct gensio *io, gensio_done_err open_done, void *open_data);

GENSIO_DLL_PUBLIC
int gensio_open_s(struct gensio *io);

GENSIO_DLL_PUBLIC
int gensio_open_nochild(struct gensio *io, gensio_done_err open_done,
			void *open_data);

GENSIO_DLL_PUBLIC
int gensio_open_nochild_s(struct gensio *io);

GENSIO_DLL_PUBLIC
int gensio_alloc_channel(struct gensio *io, const char * const args[],
			 gensio_event cb, void *user_data,
			 struct gensio **new_io);

GENSIO_DLL_PUBLIC
int gensio_close(struct gensio *io, gensio_done close_done, void *close_data);

GENSIO_DLL_PUBLIC
int gensio_close_s(struct gensio *io);

GENSIO_DLL_PUBLIC
void gensio_disable(struct gensio *io);

GENSIO_DLL_PUBLIC
void gensio_free(struct gensio *io);

/*
 * Enable or disable data to be read from the network connection.
 */
GENSIO_DLL_PUBLIC
void gensio_set_read_callback_enable(struct gensio *io, bool enabled);

/*
 * Enable the write_callback when data can be written on the
 * network connection.
 */
GENSIO_DLL_PUBLIC
void gensio_set_write_callback_enable(struct gensio *io, bool enabled);

GENSIO_DLL_PUBLIC
int gensio_control(struct gensio *io, int depth, bool get,
		   unsigned int option, char *data, gensiods *datalen);

#include <gensio/gensio_control.h>

GENSIO_DLL_PUBLIC
const char *gensio_get_type(struct gensio *io, unsigned int depth);
GENSIO_DLL_PUBLIC
struct gensio *gensio_get_child(struct gensio *io, unsigned int depth);
GENSIO_DLL_PUBLIC
bool gensio_is_client(struct gensio *io);
GENSIO_DLL_PUBLIC
bool gensio_is_reliable(struct gensio *io);
GENSIO_DLL_PUBLIC
bool gensio_is_packet(struct gensio *io);
GENSIO_DLL_PUBLIC
bool gensio_is_authenticated(struct gensio *io);
GENSIO_DLL_PUBLIC
bool gensio_is_encrypted(struct gensio *io);
GENSIO_DLL_PUBLIC
bool gensio_is_message(struct gensio *io);

GENSIO_DLL_PUBLIC
int gensio_set_sync(struct gensio *io);
GENSIO_DLL_PUBLIC
int gensio_clear_sync(struct gensio *io);
GENSIO_DLL_PUBLIC
int gensio_read_s(struct gensio *io, gensiods *count,
		  void *data, gensiods datalen,
		  gensio_time *timeout);
GENSIO_DLL_PUBLIC
int gensio_read_s_intr(struct gensio *io, gensiods *count,
		       void *data, gensiods datalen,
		       gensio_time *timeout);
GENSIO_DLL_PUBLIC
int gensio_write_s(struct gensio *io, gensiods *count,
		   const void *data, gensiods datalen,
		   gensio_time *timeout);
GENSIO_DLL_PUBLIC
int gensio_write_s_intr(struct gensio *io, gensiods *count,
			const void *data, gensiods datalen,
			gensio_time *timeout);

/*
 * Increment the gensio's refcount.  Internally there are situations
 * where one piece of code passes a gensio into another piece of code,
 * and that other piece of code that might free it on an error, but
 * the upper layer gets the error and wants to free it, too.  This
 * keeps it around for that situation.  It may also be used externally
 * for refcounting, every ref will require an extra free.
 */
GENSIO_DLL_PUBLIC
void gensio_ref(struct gensio *io);

/*
 * This is data for frameworks that sit on top of gensio, added to do
 * a clean addition of a C++ framework on top of gensio.  It's data
 * you can set on a gensio that has a destructor that is called when
 * the final free is done on the gensio data.
 */
struct gensio_frdata {
    void (*freed)(struct gensio *io, struct gensio_frdata *frdata);
};

GENSIO_DLL_PUBLIC
void gensio_set_frdata(struct gensio *io, struct gensio_frdata *frdata);
GENSIO_DLL_PUBLIC
struct gensio_frdata *gensio_get_frdata(struct gensio *io);

/****** Accepters ******/

GENSIO_DLL_PUBLIC
struct gensio_accepter *gensio_acc_get_child(struct gensio_accepter *acc,
					     unsigned int depth);

#define GENSIO_ACC_EVENT_NEW_CONNECTION	1
#define GENSIO_ACC_EVENT_LOG		2
struct gensio_loginfo {
    enum gensio_log_levels level;
    char *str;
    va_list args;
};

#define GENSIO_ACC_EVENT_PRECERT_VERIFY		3
#define GENSIO_ACC_EVENT_AUTH_BEGIN		4

#define GENSIO_ACC_EVENT_PASSWORD_VERIFY	5
#define GENSIO_ACC_EVENT_REQUEST_PASSWORD	6
struct gensio_acc_password_verify_data {
    struct gensio *io;
    char *password;
    gensiods password_len;
};

#define GENSIO_ACC_EVENT_POSTCERT_VERIFY	7
struct gensio_acc_postcert_verify_data {
    struct gensio *io;
    int err;
    const char *errstr;
};

#define GENSIO_ACC_EVENT_2FA_VERIFY		8
#define GENSIO_ACC_EVENT_REQUEST_2FA		9
/* Uses struct gensio_acc_password_verify_data */

GENSIO_DLL_PUBLIC
int str_to_gensio_accepter(const char *str, struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter);

GENSIO_DLL_PUBLIC
int str_to_gensio_accepter_child(struct gensio_accepter *child,
				 const char *str,
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb, void *user_data,
				 struct gensio_accepter **accepter);

GENSIO_DLL_PUBLIC
void *gensio_acc_get_user_data(struct gensio_accepter *accepter);

GENSIO_DLL_PUBLIC
void gensio_acc_set_user_data(struct gensio_accepter *accepter,
			      void *user_data);

GENSIO_DLL_PUBLIC
void gensio_acc_set_callback(struct gensio_accepter *accepter,
			     gensio_accepter_event cb, void *user_data);

GENSIO_DLL_PUBLIC
int gensio_acc_startup(struct gensio_accepter *accepter);

GENSIO_DLL_PUBLIC
int gensio_acc_shutdown(struct gensio_accepter *accepter,
			gensio_acc_done shutdown_done, void *shutdown_data);

GENSIO_DLL_PUBLIC
int gensio_acc_shutdown_s(struct gensio_accepter *accepter);

GENSIO_DLL_PUBLIC
void gensio_acc_disable(struct gensio_accepter *accepter);

GENSIO_DLL_PUBLIC
void gensio_acc_free(struct gensio_accepter *accepter);

GENSIO_DLL_PUBLIC
void gensio_acc_set_accept_callback_enable(struct gensio_accepter *accepter,
					   bool enabled);

GENSIO_DLL_PUBLIC
int gensio_acc_set_accept_callback_enable_cb(struct gensio_accepter *accepter,
					     bool enabled,
					     gensio_acc_done done,
					     void *done_data);

GENSIO_DLL_PUBLIC
int gensio_acc_set_accept_callback_enable_s(struct gensio_accepter *accepter,
					    bool enabled);

GENSIO_DLL_PUBLIC
int gensio_acc_control(struct gensio_accepter *accepter, int depth, bool get,
		       unsigned int option, char *data, gensiods *datalen);

GENSIO_DLL_PUBLIC
int gensio_acc_set_sync(struct gensio_accepter *acc);

GENSIO_DLL_PUBLIC
int gensio_acc_accept_s(struct gensio_accepter *acc, gensio_time *timeout,
			struct gensio **new_io);
GENSIO_DLL_PUBLIC
int gensio_acc_accept_s_intr(struct gensio_accepter *acc,
			     gensio_time *timeout,
			     struct gensio **new_io);

GENSIO_DLL_PUBLIC
int gensio_acc_str_to_gensio(struct gensio_accepter *accepter,
			     const char *str,
			     gensio_event cb, void *user_data,
			     struct gensio **new_io);
/*
 * Returns if the accepter requests exit on close.  A hack for stdio.
 * Do not use.
 */
GENSIO_DLL_PUBLIC
bool gensio_acc_exit_on_close(struct gensio_accepter *accepter);

GENSIO_DLL_PUBLIC
const char *gensio_acc_get_type(struct gensio_accepter *acc,
				unsigned int depth);

GENSIO_DLL_PUBLIC
bool gensio_acc_is_reliable(struct gensio_accepter *accepter);
GENSIO_DLL_PUBLIC
bool gensio_acc_is_packet(struct gensio_accepter *accepter);
GENSIO_DLL_PUBLIC
bool gensio_acc_is_message(struct gensio_accepter *accepter);

/*
 * This is data for frameworks that sit on top of gensio, added to do
 * a clean addition of a C++ framework on top of gensio.  It's data
 * you can set on a gensio that has a destructor that is called when
 * the final free is done on the gensio data.
 */
struct gensio_acc_frdata {
    void (*freed)(struct gensio_accepter *acc,
		  struct gensio_acc_frdata *frdata);
};

GENSIO_DLL_PUBLIC
void gensio_acc_set_frdata(struct gensio_accepter *acc,
			   struct gensio_acc_frdata *frdata);
GENSIO_DLL_PUBLIC
struct gensio_acc_frdata *gensio_acc_get_frdata(struct gensio_accepter *acc);

/*
 * These are the low-level network protocol that gensio support.  Used
 * mostly in interacting with addresses, anything named protocol.
 * zero is reserved.
 */
#define GENSIO_NET_PROTOCOL_TCP 1
#define GENSIO_NET_PROTOCOL_UDP 2
#define GENSIO_NET_PROTOCOL_SCTP 3
#define GENSIO_NET_PROTOCOL_UNIX 4

/*
 * Dealing with iterators.
 */
GENSIO_DLL_PUBLIC
void gensio_addr_rewind(struct gensio_addr *addr);
/* Return false if no more addresses exist. */
GENSIO_DLL_PUBLIC
bool gensio_addr_next(struct gensio_addr *addr);
/*
 * Gets the current address.  len must be provided, it is the size of
 * the buffer and is updated to the actual size (which may be larger
 * than len).  The copy may be partial if len is not enough.
 */
GENSIO_DLL_PUBLIC
void gensio_addr_getaddr(const struct gensio_addr *addr,
			 void *oaddr, gensiods *len);

#define GENSIO_NETTYPE_UNSPEC	0
#define GENSIO_NETTYPE_IPV4	1
#define GENSIO_NETTYPE_IPV6	2
#define GENSIO_NETTYPE_UNIX	3
#define GENSIO_NETTYPE_AX25	4

/*
 * Create a gensio address from raw address data.  Note that the iaddr
 * data is type in_addr for ipv4, in6_addr for ipv6, and the path for
 * unix.  ipv6 also takes a sockaddr_in6 (it can tell by the length)
 * and it will pull the address and scope id from that.  That way you
 * can set the scope id.
 */
GENSIO_DLL_PUBLIC
int gensio_addr_create(struct gensio_os_funcs *o,
		       int nettype, const void *iaddr, gensiods len,
		       unsigned int port, struct gensio_addr **newaddr);

/*
 * Return the network type (ipv4, ipv6, unix socket, etc.) for the
 * current address.
 */
GENSIO_DLL_PUBLIC
int gensio_addr_get_nettype(const struct gensio_addr *addr);

/*
 * If the address can be supported by a socket with the given
 * family/flags combo, return true.  This will return true if the
 * families match or if address ipv4, family is IPv6, and flags has
 * AI_V4MAPPED.
 */
GENSIO_DLL_PUBLIC
bool gensio_addr_family_supports(const struct gensio_addr *addr, int family,
				 int flags);

/*
 * A routine for converting a current address to a string representation
 *
 * The output is put into buf starting at *epos (or zero if epos is NULL)
 * and will fill in buf up to buf + buflen.  If the buffer is not large
 * enough, it is truncated, but if epos is not NULL, it will be set to the
 * byte position where the ending NIL character would have been, one less
 * than the buflen that would have been required to hold the entire buffer.
 */
GENSIO_DLL_PUBLIC
int gensio_addr_to_str(const struct gensio_addr *addr,
		       char *buf, gensiods *epos, gensiods buflen);

/*
 * Like the above, but does all the addresses, not just the current
 * one, separated by ';'.
 */
GENSIO_DLL_PUBLIC
int gensio_addr_to_str_all(const struct gensio_addr *addr,
			   char *buf, gensiods *epos, gensiods buflen);

/*
 * Compare two addresses and return TRUE if they are equal and FALSE
 * if not.  If compare_ports is false, then the port comparison is
 * ignored.
 *
 * If compare_all is true, verify that all the addresses are the same.
 * If it is false, only compare the current address.
 */
GENSIO_DLL_PUBLIC
bool gensio_addr_equal(const struct gensio_addr *a1,
		       const struct gensio_addr *a2,
		       bool compare_ports, bool compare_all);

/*
 * Create a new address structure with the same addresses.
 */
GENSIO_DLL_PUBLIC
struct gensio_addr *gensio_addr_dup(const struct gensio_addr *ai);

/*
 * Concatenate two addr structures and return a new one.
 */
GENSIO_DLL_PUBLIC
struct gensio_addr *gensio_addr_cat(const struct gensio_addr *ai1,
				    const struct gensio_addr *ai2);

/*
 * Decrement the refcount on the structure and free if not in use.
 */
GENSIO_DLL_PUBLIC
void gensio_addr_free(struct gensio_addr *ai);

/*
 * See if addr is present in ai.  Ports are not compared unless
 * compare_ports is true.
 */
GENSIO_DLL_PUBLIC
bool gensio_addr_addr_present(const struct gensio_addr *ai,
			      const void *addr, gensiods addrlen,
			      bool compare_ports);

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
GENSIO_DLL_PUBLIC
int gensio_scan_network_port(struct gensio_os_funcs *o, const char *str,
			     bool listen, struct gensio_addr **ai,
			     int *protocol, bool *is_port_set,
			     int *argc, const char ***args);

/*
 * Like the above, but only scan for addresses in a list, no ports, no
 * protocol, like: "::1,ipv4,10.0.2.3".  This only works on IP
 * addresses.
 */
GENSIO_DLL_PUBLIC
int gensio_scan_network_addr(struct gensio_os_funcs *o, const char *str,
			     int protocol, struct gensio_addr **ai);

/*
 * Handling for gensio parameters.
 */
enum gensio_default_type {
    GENSIO_DEFAULT_INT,
    GENSIO_DEFAULT_BOOL,
    GENSIO_DEFAULT_ENUM,
    GENSIO_DEFAULT_STR,
    GENSIO_DEFAULT_DATA
};

struct gensio_enum_val {
    char *name;
    int val;
};

GENSIO_DLL_PUBLIC
int gensio_add_default(struct gensio_os_funcs *o,
		       const char *name,
		       enum gensio_default_type type,
		       const char *strval, int intval,
		       int minval, int maxval,
		       const struct gensio_enum_val *enums);

GENSIO_DLL_PUBLIC
int gensio_reset_defaults(struct gensio_os_funcs *o);

GENSIO_DLL_PUBLIC
int gensio_set_default(struct gensio_os_funcs *o,
		       const char *classstr, const char *name,
		       const char *strval, int intval);


GENSIO_DLL_PUBLIC
int gensio_get_default(struct gensio_os_funcs *o,
		       const char *classstr, const char *name, bool classonly,
		       enum gensio_default_type type,
		       char **strval, int *intval);

GENSIO_DLL_PUBLIC
int gensio_get_defaultaddr(struct gensio_os_funcs *o,
			   const char *classstr, const char *name,
			   bool classonly,
			   int iprotocol, bool listen, bool require_port,
			   struct gensio_addr **rai);

GENSIO_DLL_PUBLIC
int gensio_del_default(struct gensio_os_funcs *o,
		       const char *classstr, const char *name, bool delclasses);

/*
 * Clean up all the internal gensio memory.  Not really necessary, but
 * useful for memory leak testing.
 */
GENSIO_DLL_PUBLIC
void gensio_cleanup_mem(struct gensio_os_funcs *o);

/********************************************************************
 * Everything below this point in the file are helper functions
 * that aren't really gensio-specific, but are useful for other
 * programs.  These are not documented at the moment in man
 * pages, but are available for your use.
 *******************************************************************/

/*
 * This allows a global to disable uucp locking for everything.
 */
GENSIO_DLL_PUBLIC
extern bool gensio_uucp_locking_enabled;

/*
 * These are some general key/value string handling functions to fetch
 * various items from a "key=value" pair.  These return -1 on invalid
 * data, 0, on no match, and 1 a successful match.  Any string value
 * returned is from the passed in string, it is not allocated.
 */
GENSIO_DLL_PUBLIC
int gensio_check_keyvalue(const char *str, const char *key, const char **value);
GENSIO_DLL_PUBLIC
int gensio_check_keyds(const char *str, const char *key, gensiods *value);
GENSIO_DLL_PUBLIC
int gensio_check_keyuint(const char *str, const char *key, unsigned int *value);
GENSIO_DLL_PUBLIC
int gensio_check_keyint(const char *str, const char *key, int *value);
GENSIO_DLL_PUBLIC
int gensio_check_keybool(const char *str, const char *key, bool *rvalue);
GENSIO_DLL_PUBLIC
int gensio_check_keyboolv(const char *str, const char *key,
			  const char *trueval, const char *falseval,
			  bool *rvalue);
GENSIO_DLL_PUBLIC
int gensio_check_keyenum(const char *str, const char *key,
			 struct gensio_enum_val *enums, int *rval);
/* The value of protocol is the same as for gensio_scan_network_port(). */
GENSIO_DLL_PUBLIC
int gensio_check_keyaddrs(struct gensio_os_funcs *o,
			  const char *str, const char *key, int protocol,
			  bool listen, bool require_port,
			  struct gensio_addr **ai);
GENSIO_DLL_PUBLIC
int gensio_check_keyaddrs_noport(struct gensio_os_funcs *o,
				 const char *str, const char *key,
				 int protocol, struct gensio_addr **ai);
GENSIO_DLL_PUBLIC
int gensio_check_keymode(const char *str, const char *key, unsigned int *rmode);
GENSIO_DLL_PUBLIC
int gensio_check_keyperm(const char *str, const char *key, unsigned int *rmode);
/*
 * Get a gensio time structure. Time consists of a set of numbers each
 * followed by a single letter.  That letter may be 'D', 'H', 'M',
 * 's', 'm', 'u', or 'n', meaning days, hours, minutes, seconds,
 * milliseconds, microseconds, or nanoseconds.  So, for instance,
 * "10D5H4M9s100u" would be ten days, 5 hours, 4 minutes, 9 seconds,
 * 100 microseconds.  If a plain number with no letter at the end is
 * given, then the value passed in "mod" is used.  Pass in 0 for "mod"
 * to require the user to specify the modifier.
 */
GENSIO_DLL_PUBLIC
int gensio_check_keytime(const char *str, const char *key, char mod,
			 gensio_time *rgt);

/*
 * Helper functions that don't fit anywhere else.
 */

/*
 * Returns true of str is in one of auxdata, false if not.
 */
GENSIO_DLL_PUBLIC
bool gensio_str_in_auxdata(const char *const *auxdata, const char *str);

/*
 * Set the program name, used by TCPD (and possibly others).  You should
 * do this very early in initialization, first if possible.  The default
 * progname is "gensio".
 *
 * The string is *NOT* copied, so you must make sure it stays around.
 * Generally you are passing in a constant string or part of argv[0],
 * so it's not a problem
 */
GENSIO_DLL_PUBLIC
bool gensio_set_progname(const char *progname);

/*
 * Various conversion helpers.  These may become inline someday...
 */
GENSIO_DLL_PUBLIC
uint32_t gensio_buf_to_u32(unsigned char *data);
GENSIO_DLL_PUBLIC
void gensio_u32_to_buf(unsigned char *data, uint32_t v);
GENSIO_DLL_PUBLIC
uint16_t gensio_buf_to_u16(unsigned char *data);
GENSIO_DLL_PUBLIC
void gensio_u16_to_buf(unsigned char *data, uint16_t v);

/*
 * A helper function, very useful for raddr handling.  Do an
 * snprintf() at buf + *pos, writing to up to buf + len.  If *pos > len,
 * then don't do anything, but always return the number of characters
 * that would have been output if there was enough room. Pos is updated
 * to the new location it would have been if there was enough room.
 */
GENSIO_DLL_PUBLIC
gensiods gensio_pos_snprintf(char *buf, gensiods len, gensiods *pos,
			     char *format, ...);

/*
 * Like the above, but it handles converting an argv to a string, properly
 * quoting everything.
 */
GENSIO_DLL_PUBLIC
gensiods gensio_argv_snprintf(char *buf, gensiods len, gensiods *pos,
			      const char **argv);

/*
 * An sprintf that allocates the memory
 */
GENSIO_DLL_PUBLIC
char *gensio_alloc_vsprintf(struct gensio_os_funcs *o,
			    const char *fmt, va_list va);
GENSIO_DLL_PUBLIC
char *gensio_alloc_sprintf(struct gensio_os_funcs *o,
			   const char *fmt, ...);

GENSIO_DLL_PUBLIC
char *gensio_strdup(struct gensio_os_funcs *o, const char *str);

GENSIO_DLL_PUBLIC
char *gensio_strndup(struct gensio_os_funcs *o, const char *str, gensiods len);

/*
 * Take the input string, put " around it, and put a \ infront of
 * every \ and ".  This allows you to take a string with " and \ in it
 * and have them pass through the str_to_gensio() and such functions
 * properly.
 */
GENSIO_DLL_PUBLIC
char *gensio_quote_string(struct gensio_os_funcs *o, const char *str);

/*
 * Return the number of allocated gensios.  This is primarily for
 * testing and may change, use at your own risk.
 */
GENSIO_DLL_PUBLIC
gensiods gensio_num_alloced(void);

/* For testing, do not use in normal code. */
GENSIO_DLL_PUBLIC
void gensio_osfunc_exit(int rv);

/*
 * Generic functions for dumping buffer data to stdio
 */
struct gensio_fdump {
    unsigned int column;
    unsigned int pos;
    unsigned int indent;
    unsigned char data[16];
};

/*
 * Call this before using an fdump structure.
 */
GENSIO_DLL_PUBLIC
void gensio_fdump_init(struct gensio_fdump *h, unsigned int indent);

/*
 * Format len bytes of data in buf to file f.  You can call this
 * multiple times and it will continue the dump where it left off.
 */
GENSIO_DLL_PUBLIC
void gensio_fdump_buf(FILE *f, const unsigned char *buf, gensiods len,
		      struct gensio_fdump *h);

/*
 * When you are done dumping a buffer, call this.  It will output the
 * last bits of information.
 */
GENSIO_DLL_PUBLIC
void gensio_fdump_buf_finish(FILE *f, struct gensio_fdump *h);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_H */
