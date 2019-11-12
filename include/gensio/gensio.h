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
 * This include file defines a network I/O abstraction to allow code
 * to use TCP, UDP, stdio, telnet, ssl, etc. without having to know
 * the underlying details.
 */

#ifndef GENSIO_H
#define GENSIO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_err.h>

struct gensio;

typedef size_t gensiods; /* Data size */

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

/*
 * Serial callbacks start here and run to 2000.
 */
#define SERGENIO_EVENT_BASE	1000

/*
 * If a user creates their own gensio with their own events, they should
 * use this range.
 */
#define GENSIO_EVENT_USER_MIN		100000
#define GENSIO_EVENT_USER_MAX		199999

typedef int (*gensio_event)(struct gensio *io, void *user_data,
			    int event, int err,
			    unsigned char *buf, gensiods *buflen,
			    const char *const *auxdata);

/*
 * Callbacks for functions that don't give an error (close);
 */
typedef void (*gensio_done)(struct gensio *io, void *open_data);

/*
 * Callbacks for functions that give an error (open);
 */
typedef void (*gensio_done_err)(struct gensio *io, int err, void *open_data);

int str_to_gensio(const char *str,
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **gensio);

int str_to_gensio_child(struct gensio *child, const char *str,
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **gensio);

void gensio_set_callback(struct gensio *io, gensio_event cb, void *user_data);

void *gensio_get_user_data(struct gensio *io);

void gensio_set_user_data(struct gensio *io, void *user_data);

int gensio_write(struct gensio *io, gensiods *count,
		 const void *buf, gensiods buflen,
		 const char *const *auxdata);

/* Purposefully exactly the same as iovev (see writev(2)) */
struct gensio_sg {
    const void *buf;
    gensiods buflen;
};

int gensio_write_sg(struct gensio *io, gensiods *count,
		    const struct gensio_sg *sg, gensiods sglen,
		    const char *const *auxdata);

int gensio_raddr_to_str(struct gensio *io, gensiods *pos,
			char *buf, gensiods buflen);

int gensio_get_raddr(struct gensio *io, void *addr, gensiods *addrlen);

int gensio_remote_id(struct gensio *io, int *id);

int gensio_open(struct gensio *io, gensio_done_err open_done, void *open_data);

int gensio_open_s(struct gensio *io);

int gensio_open_nochild(struct gensio *io, gensio_done_err open_done,
			void *open_data);

int gensio_open_nochild_s(struct gensio *io);

int gensio_alloc_channel(struct gensio *io, const char * const args[],
			 gensio_event cb, void *user_data,
			 struct gensio **new_io);

int gensio_close(struct gensio *io, gensio_done close_done, void *close_data);

int gensio_close_s(struct gensio *io);

void gensio_disable(struct gensio *io);

void gensio_free(struct gensio *io);

/*
 * Enable or disable data to be read from the network connection.
 */
void gensio_set_read_callback_enable(struct gensio *io, bool enabled);

/*
 * Enable the write_callback when data can be written on the
 * network connection.
 */
void gensio_set_write_callback_enable(struct gensio *io, bool enabled);

int gensio_control(struct gensio *io, int depth, bool get,
		   unsigned int option, char *data, gensiods *datalen);
#define GENSIO_CONTROL_DEPTH_ALL	-1
#define GENSIO_CONTROL_DEPTH_FIRST	-2

#define GENSIO_CONTROL_NODELAY			1
#define GENSIO_CONTROL_STREAMS			2
#define GENSIO_CONTROL_SEND_BREAK		3
#define GENSIO_CONTROL_GET_PEER_CERT_NAME	4
#define GENSIO_CONTROL_CERT_AUTH		5
#define GENSIO_CONTROL_USERNAME			6
#define GENSIO_CONTROL_SERVICE			7
#define GENSIO_CONTROL_CERT			8
#define GENSIO_CONTROL_CERT_FINGERPRINT		9
#define GENSIO_CONTROL_ENVIRONMENT		10
#define GENSIO_CONTROL_MAX_WRITE_PACKET		11
#define GENSIO_CONTROL_ARGS			12

const char *gensio_get_type(struct gensio *io, unsigned int depth);
struct gensio *gensio_get_child(struct gensio *io, unsigned int depth);
bool gensio_is_client(struct gensio *io);
bool gensio_is_reliable(struct gensio *io);
bool gensio_is_packet(struct gensio *io);
bool gensio_is_authenticated(struct gensio *io);
bool gensio_is_encrypted(struct gensio *io);
bool gensio_is_message(struct gensio *io);

int gensio_set_sync(struct gensio *io);
int gensio_clear_sync(struct gensio *io);
int gensio_read_s(struct gensio *io, gensiods *count,
		  void *data, gensiods datalen,
		  struct timeval *timeout);
int gensio_write_s(struct gensio *io, gensiods *count,
		   const void *data, gensiods datalen,
		   struct timeval *timeout);


struct gensio_accepter;

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

typedef int (*gensio_accepter_event)(struct gensio_accepter *accepter,
				     void *user_data, int event, void *data);

/*
 * Callbacks for functions that don't give an error (shutdown);
 */
typedef void (*gensio_acc_done)(struct gensio_accepter *acc, void *cb_data);

int str_to_gensio_accepter(const char *str, struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter);

int str_to_gensio_accepter_child(struct gensio_accepter *child,
				 const char *str,
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb, void *user_data,
				 struct gensio_accepter **accepter);

void *gensio_acc_get_user_data(struct gensio_accepter *accepter);

void gensio_acc_set_user_data(struct gensio_accepter *accepter,
			      void *user_data);

void gensio_acc_set_callback(struct gensio_accepter *accepter,
			     gensio_accepter_event cb, void *user_data);

int gensio_acc_startup(struct gensio_accepter *accepter);

int gensio_acc_shutdown(struct gensio_accepter *accepter,
			gensio_acc_done shutdown_done, void *shutdown_data);

int gensio_acc_shutdown_s(struct gensio_accepter *accepter);

void gensio_acc_disable(struct gensio_accepter *accepter);

void gensio_acc_free(struct gensio_accepter *accepter);

void gensio_acc_set_accept_callback_enable(struct gensio_accepter *accepter,
					   bool enabled);

int gensio_acc_set_accept_callback_enable_cb(struct gensio_accepter *accepter,
					     bool enabled,
					     gensio_acc_done done,
					     void *done_data);

int gensio_acc_set_accept_callback_enable_s(struct gensio_accepter *accepter,
					    bool enabled);

int gensio_acc_control(struct gensio_accepter *accepter, int depth, bool get,
		       unsigned int option, char *data, gensiods *datalen);

int gensio_acc_str_to_gensio(struct gensio_accepter *accepter,
			     const char *str,
			     gensio_event cb, void *user_data,
			     struct gensio **new_io);
/*
 * Returns if the accepter requests exit on close.  A hack for stdio.
 * Do not use.
 */
bool gensio_acc_exit_on_close(struct gensio_accepter *accepter);

const char *gensio_acc_get_type(struct gensio_accepter *acc,
				unsigned int depth);
    
bool gensio_acc_is_reliable(struct gensio_accepter *accepter);
bool gensio_acc_is_packet(struct gensio_accepter *accepter);
bool gensio_acc_is_message(struct gensio_accepter *accepter);


enum gensio_default_type {
    GENSIO_DEFAULT_INT,
    GENSIO_DEFAULT_BOOL,
    GENSIO_DEFAULT_ENUM,
    GENSIO_DEFAULT_STR
};

struct gensio_enum_val {
    char *name;
    int val;
};

int gensio_add_default(struct gensio_os_funcs *o,
		       const char *name,
		       enum gensio_default_type type,
		       const char *strval, int intval,
		       int minval, int maxval,
		       const struct gensio_enum_val *enums);

void gensio_reset_defaults(struct gensio_os_funcs *o);

int gensio_set_default(struct gensio_os_funcs *o,
		       const char *class, const char *name,
		       const char *strval, int intval);


int gensio_get_default(struct gensio_os_funcs *o,
		       const char *class, const char *name, bool classonly,
		       enum gensio_default_type type,
		       char **strval, int *intval);

int gensio_get_defaultaddr(struct gensio_os_funcs *o,
			   const char *class, const char *name, bool classonly,
			   int iprotocol, bool listen, bool require_port,
			   struct addrinfo **rai);

int gensio_del_default(struct gensio_os_funcs *o,
		       const char *class, const char *name, bool delclasses);

/********************************************************************
 * Everything below this point in the file are helper functions
 * that aren't really gensio-specific, but are useful for other
 * programs.  These are not documented at the moment in man
 * pages, but are available for your use.
 *******************************************************************/

/*
 * Compare two sockaddr structure and return TRUE if they are equal
 * and FALSE if not.  Only works for AF_INET and AF_INET6.
 * If compare_ports is false, then the port comparison is ignored.
 */
bool gensio_sockaddr_equal(const struct sockaddr *a1, socklen_t l1,
			   const struct sockaddr *a2, socklen_t l2,
			   bool compare_ports);

/*
 * Extract the port from a sockaddr.  If the sockaddr is not AF_INET
 * or AF_INET6, return -1.
 */
int gensio_sockaddr_get_port(const struct sockaddr *s);

/*
 * Scan for a network port in the form:
 *
 *   <ipspec><protocol>,<hostnames>
 *
 *   protocol = [tcp|udp|sctp[(<args>)]]
 *
 *   hostnames = [[...]<ipspec>[<hostname>,]<port>,]<ipspec>[<hostname>,]<port>
 *
 *   ipspec = [ipv4|ipv6|ipv6n4,]
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
 * The socktype and protocol values are returned for the socket()
 * call.  For UDP, it's SOCK_DGRAM and IPPROTO_UDP, for TCP it's
 * SOCK_SCTREAM and IPPROTO_TCP, and for SCTP it's SOCKSETPACKET and
 * IPPROTO_SCTP.
 *
 * ai should be freed with gensio_free_addrinfo().
 *
 * args should be freed with str_to_argv_free().
 */
int gensio_scan_network_port(struct gensio_os_funcs *o, const char *str,
			     bool listen, struct addrinfo **ai,
			     int *socktype, int *protocol,
			     bool *is_port_set,
			     int *argc, const char ***args);

/*
 * This allows a global to disable uucp locking for everything.
 */
extern bool gensio_uucp_locking_enabled;

/*
 * Create an addrinfo from a string for a unix socket.
 */
int gensio_scan_unixaddr(struct gensio_os_funcs *o, const char *str,
			 struct addrinfo **rai,
			 int *rargc, const char ***rargs);

/*
 * There are no provided routines to duplicate addrinfo structures,
 * so we really need to do it ourselves.
 */
struct addrinfo *gensio_dup_addrinfo(struct gensio_os_funcs *o,
				     struct addrinfo *ai);
/*
 * Concatenate to addrinfo functions.  If successful (non-NULL return),
 * ai1 and ai2 are not usable any more.
 */
struct addrinfo *gensio_cat_addrinfo(struct gensio_os_funcs *o,
				     struct addrinfo *ai1,
				     struct addrinfo *ai2);
void gensio_free_addrinfo(struct gensio_os_funcs *o, struct addrinfo *ai);

/*
 * A routine for converting a sockaddr to a numeric IP address.
 *
 * If addrlen is non-NULL and is non-zero, it is compared against what
 * the actual address length should have been and EINVAL is returned
 * if it doesn't match.  If addrlen is non-NULL and is zero, it will
 * be updated to the address length.
 *
 * The output is put into buf starting at *epos (or zero if epos is NULL)
 * and will fill in buf up to buf + buflen.  If the buffer is not large
 * enough, it is truncated, but if epos is not NULL, it will be set to the
 * byte position where the ending NIL character would have been, one less
 * than the buflen that would have been required to hold the entire buffer.
 *
 * If addr is not AF_INET or AF_INET6, return EINVAL.
 */
int gensio_sockaddr_to_str(const struct sockaddr *addr, socklen_t *addrlen,
			   char *buf, gensiods *epos, gensiods buflen);

/*
 * This allows a global to disable uucp locking for everything.
 */
extern bool gensio_uucp_locking_enabled;

/*
 * These are some general key/value string handling functions to fetch
 * various items from a "key=value" pair.  These return -1 on invalid
 * data, 0, on no match, and 1 a successful match.  Any string value
 * returned is from the passed in string, it is not allocated.
 */
int gensio_check_keyvalue(const char *str, const char *key, const char **value);
int gensio_check_keyds(const char *str, const char *key, gensiods *value);
int gensio_check_keyuint(const char *str, const char *key, unsigned int *value);
int gensio_check_keybool(const char *str, const char *key, bool *rvalue);
int gensio_check_keyboolv(const char *str, const char *key,
			  const char *trueval, const char *falseval,
			  bool *rvalue);
int gensio_check_keyenum(const char *str, const char *key,
			 struct gensio_enum_val *enums, int *rval);
int gensio_check_keyaddrs(struct gensio_os_funcs *o,
			  const char *str, const char *key, int protocol,
			  bool listen, bool require_port, struct addrinfo **ai);

/*
 * Helper functions that don't fit anywhere else.
 */

/*
 * Returns true of str is in one of auxdata, false if not.
 */
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
bool gensio_set_progname(const char *progname);

/*
 * Various conversion helpers.  These may become inline someday...
 */
uint32_t gensio_buf_to_u32(unsigned char *data);
void gensio_u32_to_buf(unsigned char *data, uint32_t v);
uint16_t gensio_buf_to_u16(unsigned char *data);
void gensio_u16_to_buf(unsigned char *data, uint16_t v);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_H */
