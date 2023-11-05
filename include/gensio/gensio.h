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

#include <gensio/gensio_utils.h>
#include <gensio/gensio_addr.h>

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

struct gensio_parmlog_data {
    const char *log;
    va_list args;
};
#define GENSIO_EVENT_PARMLOG		12
#define GENSIO_EVENT_WIN_SIZE		13

struct gensio_log_data {
    enum gensio_log_levels level;
    const char *log;
    va_list args;
};
#define GENSIO_EVENT_LOG		14

/*
 * Serial callbacks start here and run to 2000.
 */
#define SERGENSIO_EVENT_BASE	1000
#define SERGENSIO_EVENT_MAX	1999

/*
 * Events for dynamic changes to the serial port.  Users can ignore these
 * if they don't care.
 */

/*
 * Client side only, these are for reporting changes to the user.  buf
 * points to an unsigned integer holding the modem or line state.
 */
#define GENSIO_EVENT_SER_MODEMSTATE	(SERGENSIO_EVENT_BASE + 1)
#define GENSIO_EVENT_SER_LINESTATE	(SERGENSIO_EVENT_BASE + 2)

/*
 * On the server side, these are for reporting that the client is
 * requesting the signature.  Not for client.
 */
#define GENSIO_EVENT_SER_SIGNATURE	(SERGENSIO_EVENT_BASE + 3)

/*
 * The remote end is asking the user to flow control or flush.  Client
 * or server.
 */
#define GENSIO_EVENT_SER_FLOW_STATE	(SERGENSIO_EVENT_BASE + 4)
#define GENSIO_EVENT_SER_FLUSH		(SERGENSIO_EVENT_BASE + 5)

/* Got a sync from the other end.  Client or server. */
#define GENSIO_EVENT_SER_SYNC		(SERGENSIO_EVENT_BASE + 6)

/*
 * Server callbacks.  These only come in in server mode, you must
 * call the equivalent sergensio_xxx() function to return the response,
 * though the done callback is ignored in that case.  buf points to
 * an integer holding the value.
 */
#define GENSIO_EVENT_SER_BAUD		(SERGENSIO_EVENT_BASE + 7)
#define GENSIO_EVENT_SER_DATASIZE	(SERGENSIO_EVENT_BASE + 8)
#define GENSIO_EVENT_SER_PARITY		(SERGENSIO_EVENT_BASE + 9)
#define GENSIO_EVENT_SER_STOPBITS	(SERGENSIO_EVENT_BASE + 10)
#define GENSIO_EVENT_SER_FLOWCONTROL	(SERGENSIO_EVENT_BASE + 11)
#define GENSIO_EVENT_SER_IFLOWCONTROL	(SERGENSIO_EVENT_BASE + 12)
#define GENSIO_EVENT_SER_SBREAK		(SERGENSIO_EVENT_BASE + 13)
#define GENSIO_EVENT_SER_DTR		(SERGENSIO_EVENT_BASE + 14)
#define GENSIO_EVENT_SER_RTS		(SERGENSIO_EVENT_BASE + 15)

/*
 * On the server side, this is for reporting that the client has
 * requested the mask be changed.  buf points to an unsigned integer
 * holding the new modem or line state mask.
 */
#define GENSIO_EVENT_SER_MODEMSTATE_MASK (SERGENSIO_EVENT_BASE + 16)
#define GENSIO_EVENT_SER_LINESTATE_MASK	(SERGENSIO_EVENT_BASE + 17)

/*
 * For linestate and modemstate, on a client this sets the mask, on
 * the server this is reporting the current state to the client.
 */
#define GENSIO_LINESTATE_DATA_READY		(1 << 0)
#define GENSIO_LINESTATE_OVERRUN_ERR		(1 << 1)
#define GENSIO_LINESTATE_PARITY_ERR		(1 << 2)
#define GENSIO_LINESTATE_FRAMING_ERR		(1 << 3)
#define GENSIO_LINESTATE_BREAK		(1 << 4)
#define GENSIO_LINESTATE_XMIT_HOLD_EMPTY	(1 << 5)
#define GENSIO_LINESTATE_XMIT_SHIFT_EMPTY	(1 << 6)
#define GENSIO_LINESTATE_TIMEOUT_ERR		(1 << 7)

/* Note that for modemstate you should use the low 4 bits. */
#define GENSIO_MODEMSTATE_CTS_CHANGED	(1 << 0)
#define GENSIO_MODEMSTATE_DSR_CHANGED	(1 << 1)
#define GENSIO_MODEMSTATE_RI_CHANGED		(1 << 2)
#define GENSIO_MODEMSTATE_CD_CHANGED		(1 << 3)
#define GENSIO_MODEMSTATE_CTS		(1 << 4)
#define GENSIO_MODEMSTATE_DSR		(1 << 5)
#define GENSIO_MODEMSTATE_RI			(1 << 6)
#define GENSIO_MODEMSTATE_CD			(1 << 7)

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
int gensio_terminal_alloc(const char *gensiotype, const void *gdata,
			  const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_event cb, void *user_data,
			  struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int gensio_filter_alloc(const char *gensiotype,
			struct gensio *child,
			const char * const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **new_gensio);

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

GENSIO_DLL_PUBLIC
int gensio_acontrol(struct gensio *io, int depth, bool get,
		    unsigned int option, const char *data,
		    gensiods datalen,
		    gensio_control_done done, void *cb_data);

GENSIO_DLL_PUBLIC
int gensio_acontrol_s(struct gensio *io, int depth, bool get,
		      unsigned int option, char *data,
		      gensiods *datalen);

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
bool gensio_is_mux(struct gensio *io);
GENSIO_DLL_PUBLIC
bool gensio_is_serial(struct gensio *io);

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
    const char *str;
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

#define GENSIO_ACC_EVENT_PARMLOG		10

GENSIO_DLL_PUBLIC
int str_to_gensio_accepter(const char *str, struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter);

GENSIO_DLL_PUBLIC
int gensio_terminal_acc_alloc(const char *gensiotype, const void *gdata,
			      const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb, void *user_data,
			      struct gensio_accepter **accepter);

GENSIO_DLL_PUBLIC
int gensio_filter_acc_alloc(const char *gensiotype,
			    struct gensio_accepter *child,
			    const char * const args[],
			    struct gensio_os_funcs *o,
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
GENSIO_DLL_PUBLIC
bool gensio_acc_is_mux(struct gensio_accepter *accepter);
GENSIO_DLL_PUBLIC
bool gensio_acc_is_serial(struct gensio_accepter *accepter);

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
 * Handling for gensio parameters.
 */
enum gensio_default_type {
    GENSIO_DEFAULT_INT,
    GENSIO_DEFAULT_BOOL,
    GENSIO_DEFAULT_ENUM,
    GENSIO_DEFAULT_STR,
    GENSIO_DEFAULT_DATA
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

GENSIO_DLL_PUBLIC
int gensio_check_keyfloat(const char *str, const char *key, float *rfl);

/*
 * Return the number of allocated gensios.  This is primarily for
 * testing and may change, use at your own risk.
 */
GENSIO_DLL_PUBLIC
gensiods gensio_num_alloced(void);

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
