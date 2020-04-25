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

#ifdef __cplusplus
extern "C" {
#endif

#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_err.h>
#include <gensio/gensio_version.h>

struct gensio;

typedef unsigned long gensiods; /* Data size */

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
#define GENSIO_CONTROL_EXIT_CODE		13
#define GENSIO_CONTROL_WAIT_TASK		14
#define GENSIO_CONTROL_ADD_MCAST		15
#define GENSIO_CONTROL_DEL_MCAST		16
#define GENSIO_CONTROL_LADDR			17
#define GENSIO_CONTROL_LPORT			18
#define GENSIO_CONTROL_CLOSE_OUTPUT		19

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
		  gensio_time *timeout);
int gensio_read_s_intr(struct gensio *io, gensiods *count,
		       void *data, gensiods datalen,
		       gensio_time *timeout);
int gensio_write_s(struct gensio *io, gensiods *count,
		   const void *data, gensiods datalen,
		   gensio_time *timeout);
int gensio_write_s_intr(struct gensio *io, gensiods *count,
			const void *data, gensiods datalen,
			gensio_time *timeout);


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
/* Uses GENSIO_CONTROL_DEPTH_xxx options above. */
#define GENSIO_ACC_CONTROL_LADDR	1
#define GENSIO_ACC_CONTROL_LPORT	2

int gensio_acc_set_sync(struct gensio_accepter *acc);

int gensio_acc_accept_s(struct gensio_accepter *acc, gensio_time *timeout,
			struct gensio **new_io);
int gensio_acc_accept_s_intr(struct gensio_accepter *acc,
			     gensio_time *timeout,
			     struct gensio **new_io);

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

/*
 * These are the low-level network protocol that gensio support.  Used
 * mostly in interacting with addresses.  zero is reserved.
 */
#define GENSIO_NET_PROTOCOL_TCP 1
#define GENSIO_NET_PROTOCOL_UDP 2
#define GENSIO_NET_PROTOCOL_SCTP 3
#define GENSIO_NET_PROTOCOL_UNIX 4

/*
 * Gensio address structure
 *
 * This is used to hide the details of address handling for network
 * gensios.  A gensio_addr has a set of addresses embedded in it.  The
 * list is immutable after allocation.
 *
 * The address has the concept of a current address in it that can be
 * iterated.  You get an address, and you can use the iterater
 * function to iterate over it and extract information from the
 * individual addresses.
 *
 * Note that some function use the current address, and some use all
 * the addresses.
 */
struct gensio_addr;

/*
 * Dealing with iterators.
 */
void gensio_addr_rewind(struct gensio_addr *addr);
/* Return false if no more addresses exist. */
bool gensio_addr_next(struct gensio_addr *addr);
bool gensio_addr_at_end(struct gensio_addr *addr);
/*
 * Gets the current address.  len must be provided, it is the size of
 * the buffer and is updated to the actual size (which may be larger
 * than len).  The copy may be partial if len is not enough.
 */
void gensio_addr_getaddr(const struct gensio_addr *addr,
			 void *oaddr, gensiods *len);

/*
 * Return the network type (ipv4, ipv6, unix socket, etc.) for the
 * current address.  These numbers are currently internal, but can be
 * used for comparison.
 */
int gensio_addr_get_nettype(const struct gensio_addr *addr);

/*
 * A routine for converting a current address to a string representation
 *
 * The output is put into buf starting at *epos (or zero if epos is NULL)
 * and will fill in buf up to buf + buflen.  If the buffer is not large
 * enough, it is truncated, but if epos is not NULL, it will be set to the
 * byte position where the ending NIL character would have been, one less
 * than the buflen that would have been required to hold the entire buffer.
 */
int gensio_addr_to_str(const struct gensio_addr *addr,
		       char *buf, gensiods *epos, gensiods buflen);

/*
 * Like the above, but does all the addresses, not just the current
 * one, separated by ';'.
 */
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
bool gensio_addr_equal(const struct gensio_addr *a1,
		       const struct gensio_addr *a2,
		       bool compare_ports, bool compare_all);

/*
 * Create a new address stucture with the same addresses.
 */
struct gensio_addr *gensio_addr_dup(struct gensio_addr *ai);

/*
 * Concatenate two addr structures and return a new one.
 */
struct gensio_addr *gensio_addr_cat(const struct gensio_addr *ai1,
				    const struct gensio_addr *ai2);

/*
 * Decrement the refcount on the structure and free if not in use.
 */
void gensio_addr_free(struct gensio_addr *ai);

/*
 * Compare two addresses.  If compare_ports is false, ignore ports in
 * the comparison, otherwise compare the ports.  If all_addr is true,
 * compare all the sub-addresses in the addresses.  Otherwise only
 * compare the current address.
 */
bool gensio_addr_cmp(const struct gensio_addr *addr1,
		     const struct gensio_addr *addr2,
		     bool compare_ports, bool all_addr);

/*
 * See if addr is present in ai.  Ports are not compared unless
 * compare_ports is true.
 */
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
 * ai should be freed with gensio_free_addr().
 *
 * args should be freed with str_to_argv_free().
 */
int gensio_scan_network_port(struct gensio_os_funcs *o, const char *str,
			     bool listen, struct gensio_addr **ai,
			     int *protocol, bool *is_port_set,
			     int *argc, const char ***args);

/*
 * Like the above, but only scan for addresses in a list, no ports, no
 * protocol, like: "::1,ipv4,10.0.2.3".  This only works on IP
 * addresses.
 */
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

int gensio_add_default(struct gensio_os_funcs *o,
		       const char *name,
		       enum gensio_default_type type,
		       const char *strval, int intval,
		       int minval, int maxval,
		       const struct gensio_enum_val *enums);

int gensio_reset_defaults(struct gensio_os_funcs *o);

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
			   struct gensio_addr **rai);

int gensio_del_default(struct gensio_os_funcs *o,
		       const char *class, const char *name, bool delclasses);

/*
 * Clean up all the internal gensio memory.  Not really necessary, but
 * useful for memory leak testing.
 */
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
extern bool gensio_uucp_locking_enabled;

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
/* The value of protocol is the same as for gensio_scan_network_port(). */
int gensio_check_keyaddrs(struct gensio_os_funcs *o,
			  const char *str, const char *key, int protocol,
			  bool listen, bool require_port,
			  struct gensio_addr **ai);
int gensio_check_keyaddrs_noport(struct gensio_os_funcs *o,
				 const char *str, const char *key,
				 int protocol, struct gensio_addr **ai);

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

/*
 * A helper function, very useful for raddr handling.  Do an
 * snprintf() at buf + *pos, writing to up to buf + len.  If *pos > len,
 * then don't do anything, but alway return the number of characters
 * that would have been output if there was enough room.  Pos is updated
 * to the new location it would have been if there was enough room.
 */
int gensio_pos_snprintf(char *buf, gensiods len, gensiods *pos,
			char *format, ...);

/*
 * Like the above, but it handles converting an argv to a string, properly
 * quoting everything.
 */
int gensio_argv_snprintf(char *buf, gensiods len, gensiods *pos,
			 const char **argv);

/*
 * An sprintf that allocates the memory
 */
char *gensio_alloc_vsprintf(struct gensio_os_funcs *o,
			    const char *fmt, va_list va);
char *gensio_alloc_sprintf(struct gensio_os_funcs *o,
			   const char *fmt, ...);
    
char *gensio_strdup(struct gensio_os_funcs *o, const char *str);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_H */
