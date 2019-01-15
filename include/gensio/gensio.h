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

struct gensio;

typedef size_t gensiods; /* Data size */

/*
 * Called when data is read from the I/O device.
 *
 * If err is zero, buf points to a data buffer and buflen is the
 * number of bytes available.
 *
 * If err is set, buf and buflen are undefined.  readerr is a standard
 * *nix errno.
 *
 * You must set the number of bytes consumed in buflen.  Note that you must
 * disable read if you don't consume all the bytes or in other
 * situations where you don't want the read handler called.  auxdata,
 * if not NULL, may contain information about the message, like if it
 * is out of band (oob) data.
 *
 * Return value is ignored.
 */
#define GENSIO_EVENT_READ		1

/*
 * Called when data can be written to the I/O device.  Only io is
 * set, all other parameters are unused and the return value is
 * ignored.
 */
#define GENSIO_EVENT_WRITE_READY	2

/*
 * A new channel has been created by the remote end of the connection.
 * The new channel gensio is in auxdata.  buf may contain a string
 * with information about the new channel.  If this returns an error,
 * the channel creation is refused and the channel is closed.
 */
#define GENSIO_EVENT_NEW_CHANNEL	3

/*
 * Got a request from the other end to send a break.  Client or
 * server.
 */
#define GENSIO_EVENT_SEND_BREAK		4

/*
 * The connection has received a certificate but has not verified it
 * yet.  This lets the user modify the certificate authority based on
 * certificate information.  Return ENOTSUP or zero for standard
 * verification.  If this returns an error besides ENOTSUP, the
 * verification fails and the connection is terminated.
 */
#define GENSIO_EVENT_PRECERT_VERIFY	5

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

/*
 * Called for any event from the I/O.  Parameters are:
 *
 *   event - What event is being reported?  One of GENSIO_EVENT_xxx.
 *
 *   err - If zero, there is no error.  If non-zero, this is reporting
 *         an error.  Generally only on read events.
 *
 *   buf - For events reporting data transferred (generally read), this
 *         is the data.  Undefined for events not transferring data.
 *
 *   buflen - The length of data being transferred.  This passes in the
 *            lenth, the user should update it with the number of bytes
 *            actually processed.  NULL for events not transferring data.
 *
 *   auxdata - Depending on the event, other data may be transferred.
 *             this holds a pointer to it.
 *
 * This function should return 0 if it handled the event, or ENOTSUP if
 * it didn't.
 */
typedef int (*gensio_event)(struct gensio *io, int event, int err,
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

/*
 * Set the callback data for the net.  This must be done in the
 * new_connection callback for the accepter before any other operation
 * is done on the gensio.  The only exception is that gensio_close() may
 * be called with callbacks not set.  This function may be called
 * again if the gensio is not enabled.
 */
void gensio_set_callback(struct gensio *io, gensio_event cb, void *user_data);

/*
 * Return the user data supplied in gensio_set_callbacks().
 */
void *gensio_get_user_data(struct gensio *io);

/*
 * Set the user data.  May be called if the gensio is not enabled.
 */
void gensio_set_user_data(struct gensio *io, void *user_data);

/*
 * Write data to the gensio.  This should only be called from the
 * write callback for most general usage.  Writes buflen bytes
 * from buf.
 *
 * Returns errno on error, or 0 on success.  This will NEVER return
 * EAGAIN, EWOULDBLOCK, or EINTR.  Those are handled internally.
 *
 * On a non-error return, count is set to the number of bytes
 * consumed by the write call, which may be less than buflen.  If
 * it is less than buflen, then not all the data was written.
 * Note that count may be set to zero.  This can happen on an
 * EAGAIN type situation.  count may be NULL if you don't care.
 * auxdata contains additional information about the write,
 * and depends on the particular gensio type.
 */
int gensio_write(struct gensio *io, gensiods *count,
		 const void *buf, gensiods buflen,
		 const char *const *auxdata);

/*
 * Convert the remote address for this network connection to a
 * string.  The string starts at buf + *pos and goes to buf +
 * buflen.  If pos is NULL, then zero is used.  The string is
 * NIL terminated.
 *
 * Returns an errno on an error, and a string error will be put
 * into the buffer.
 *
 * In all cases, if pos is non-NULL and the output string fits into
 * the buffer, it will be updated to be the NIL char after the last
 * byte of the string, where you would want to put any new data into
 * the string.
 *
 * If the output string does not fit, pos is updated to where it would
 * have been if it had enough bytes (one less than the total number of
 * bytes required), but the output in buf is truncated.  This can be
 * used to probe to see how long a buffer is required by passing in a
 * zero buflen and *pos, and then allocating *pos + 1 and calling the
 * function again with that data.
 */
int gensio_raddr_to_str(struct gensio *io, gensiods *pos,
			char *buf, gensiods buflen);

/*
 * Return the remote address for the connection.  addrlen must be
 * set to the size of addr and will be updated to the actual size.
 * If addrlen is not large enough to hold the data, the updated
 * addrlen will be set to the number of bytes required to hold the
 * address, though the data in the address will be truncated.
 *
 * The value returned here is connection dependent, and for filter
 * layers it will pass the call down to the lowest layer to get
 * the addresses.
 *
 * For TCP and UDP connections, this is sockaddr type.  For SCTP,
 * this is a packed sockaddr buffer per SCTP semantics.  For serial
 * ports, this return an error.
 */
int gensio_get_raddr(struct gensio *io, void *addr, gensiods *addrlen);

/*
 * Returns an id for the remote end.  For stdio clients this is the
 * pid.  For serialdev this is the fd.  It returns an error
 * for all others.
 */
int gensio_remote_id(struct gensio *io, int *id);

/*
 * Open the gensio.  gensios recevied from an accepter are open upon
 * receipt, but client gensios are started closed and need to be opened
 * before use.  If no error is returned, the gensio will be open when
 * the open_done callback is called.
 */
int gensio_open(struct gensio *io, gensio_done_err open_done, void *open_data);

/*
 * Like gensio_open(), but waits for the open to complete.
 */
int gensio_open_s(struct gensio *io);

/*
 * Open a channel on the given gensio.  The gensio must one that
 * supports channels (like SCTP, SSH, or stdio).  The args parm is
 * specific to the gensio type, and contains information that
 * describes how to set up the new channel.  The channel open creates
 * a new gensio object with its own callbacks and user data.
 *
 * For stdio, this only opens a channel for stderr input, args can be
 * "readbuf=<num>" and sets the size of the input buffer.  This is how
 * you get stderr output from a stdio channel, and it only works for
 * client-created stdio, not acceptor-created stdio.
 */
int gensio_open_channel(struct gensio *io, const char * const args[],
			gensio_event cb, void *user_data,
			gensio_done_err open_done, void *open_data,
			struct gensio **new_io);

/*
 * Like gensio_open_channel, but waits for the open to complete and
 * returns the gensio for the channel.
 */
int gensio_open_channel_s(struct gensio *io, const char * const args[],
			  gensio_event cb, void *user_data,
			  struct gensio **new_io);

/*
 * Perform a gensio-specific operation on the gensio (if depth is 0) or
 * one of its children (depth > 0).  If depth is GENSIO_CONTROL_DEPTH_ALL,
 * then call all the children with the data.  ENOTSUP is ignored in
 * that case, but it will stop at the first error besides that.  If
 * depth is GENSIO_CONTROL_DEPTH_FIRST, it will return on the first
 * gensio that doesn't return ENOTSUP.  It returns ENOTSUP is nothing
 * handled it.
 *
 * If get is true, attempt to fetch the option.  You cannot use
 * GENSIO_CONTROL_DEPTH_ALL with get==true.  To fetch an option, you
 * must pass in a string long enough to hold the output and set
 * datalen to the number of bytes available.  It will return the
 * length of the string (like strlen, not including the terminating
 * nil) in datalen.  datalen is not used in a put operation or
 * for determining the length of the input string, it must be a
 * nil terminated string.
 *
 * A get operation is alway indepotent (it won't change anything, so
 * multiple calls will not have any effect on the state of the system).
 * A get operation may or may not have data passed in, and returns
 * information in the passed string.
 *
 * If the output string does not fit, data is updated to where it
 * would have been if it had enough bytes (one less than the total
 * number of bytes required), but the output in buf is truncated (and
 * nil terminated if possible).  This can be used to probe to see how
 * long a buffer is required by passing in a zero *datalen, and then
 * allocating *datalen + 1 and calling the function again with that
 * data.
 */
int gensio_control(struct gensio *io, int depth, bool get,
		   unsigned int option, char *data, gensiods *datalen);
#define GENSIO_CONTROL_DEPTH_ALL	-1
#define GENSIO_CONTROL_DEPTH_FIRST	-2

/*
 * Set the enable/disable for any NAGLE type algorithms.
 * auxdata points to an integer with a boolean value.
 */
#define GENSIO_CONTROL_NODELAY		1

/*
 * Return information about incoming and outgoing streams for
 * the gensio.  This is read(get)-only and returns the value in
 * the data in the form "instream=<n>,ostream=<n>".
 */
#define GENSIO_CONTROL_STREAMS		2

/*
 * Request that a break be sent over the line (primarily for telnet).
 */
#define GENSIO_CONTROL_SEND_BREAK	3

/*
 * Return the object from the certificate from the remote end.  This
 * is primarily for SSL so the application can validate the
 * certificate's common name, but it can fetch any object from the
 * certificate.  The object to fetch is pass in to data (along with
 * all the space padding), the SN or LN descriptor per
 * /usr/include/openssl/object.h.  Like "CN" or "commonName".
 *
 * There may be more than one of an object in a certificate, so this
 * interface can handle that.  The value returned in data will be
 * in the form: "<n>,<value>" where <n> is a number.  To fetch the
 * next value, pass in this number when requesting before the
 * object type in the form: "<n>,<object type>".
 *
 * Returns ENXIO if there is no remote certificate, EINVAL if the
 * pass in object name is not valid, and ENOENT if the object was
 * not available in the certificate.
 */
#define GENSIO_CONTROL_GET_PEER_CERT_NAME	4

/*
 * Set the certificate authority file to the string in "data".  If
 * it ends in '/', it is assumed to be a directory, otherwise it is
 * assumed to be a file.  This generally must be done before
 * authorization is done, generally before open or in the
 * GENSIO_EVENT_PRECERT_VERIFY event.
 */
#define GENSIO_CONTROL_CERT_AUTH		5

/*
 * Return the type string for the gensio (if depth is 0) or one of its
 * children (depth > 0).  Return NULL if the depth is greater than the
 * number of children.
 */
const char *gensio_get_type(struct gensio *io, unsigned int depth);

/*
 * Close the gensio.  Note that the close operation is not complete
 * until close_done() is called.  This shuts down internal file
 * descriptors and such, but does not free the gensio.
 */
int gensio_close(struct gensio *io, gensio_done close_done, void *close_data);

/*
 * Like gensio_close, but blocks until the operation is complete.
 *
 * BE VERY CAREFUL WITH THIS FUNCTION.  Do not call it from a callback
 * because it waits until all operations on the gensio are done, and
 * they won't be done until the callback returns.  You will deadlock
 * if you do this.
 */
int gensio_close_s(struct gensio *io);

/*
 * Frees data assoicated with the gensio.  If it is open, the gensio is
 * closed.  Note that you should not call gensio_free() after gensio_close()
 * before the done callback is called.  The results are undefined.
 */
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

/*
 * Is the gensio a client or server?
 */
bool gensio_is_client(struct gensio *io);

/*
 * Is the genio reliable (won't loose data).
 */
bool gensio_is_reliable(struct gensio *io);

/*
 * Is the genio packet-oriented.  In a packet-oriented genio, if one
 * side writes a chunk of data, when the other side does a read it
 * will get the same chunk of data as a single unit assuming it's
 * buffer sizes are set properly.
 */
bool gensio_is_packet(struct gensio *io);

/*
 * Is the remote end authenticated?  In the SSL case, this means that
 * the remote certificate was received and verified.
 */
bool gensio_is_authenticated(struct gensio *io);

/*
 * Is the connection encrypted?
 */
bool gensio_is_encrypted(struct gensio *io);


struct gensio_accepter;

/*
 * Got a new connection on the event.  data points to the new gensio.
 */
#define GENSIO_ACC_EVENT_NEW_CONNECTION	1

/*
 * The gensio accepter had an issue that wouldn't otherwise be reported
 * as an error return.  data points to a gensio_loginfo.
 */
#define GENSIO_ACC_EVENT_LOG		2
struct gensio_loginfo {
    enum gensio_log_levels level;
    char *str;
    va_list args;
};

/*
 * Called right before certificate verification on a new incoming
 * connection.  See GENSIO_EVENT_PRECERT_VERIFY for details.  data
 * points to the new gensio object.
 */
#define GENSIO_ACC_EVENT_PRECERT_VERIFY	3


/*
 * Report an event from the accepter to the user.
 *
 *  event - The event that occurred, of the type GENSIO_ACC_EVENT_xxx.
 *
 *  data - Specific data for the event, see the event description.
 *
 */
typedef int (*gensio_accepter_event)(struct gensio_accepter *accepter,
				     int event,
				     void *data);

/*
 * Callbacks for functions that don't give an error (close);
 */
typedef void (*gensio_acc_done)(struct gensio_accepter *acc, void *open_data);

/*
 * Return the type string for the gensio accepter (if depth is 0) or
 * one of its children (depth > 0).  Return NULL if the depth is
 * greater than the number of children.
 */
const char *gensio_acc_get_type(struct gensio_accepter *acc,
				unsigned int depth);
    
/*
 * Return the user data supplied to the allocator.
 */
void *gensio_acc_get_user_data(struct gensio_accepter *accepter);

/*
 * Set the user data.  May be called if the accepter is not enabled.
 */
void gensio_acc_set_user_data(struct gensio_accepter *accepter,
			      void *user_data);

/*
 * Set the callbacks and user data.  May be called if the accepter is
 * not enabled.
 */
void gensio_acc_set_callback(struct gensio_accepter *accepter,
			     gensio_accepter_event cb, void *user_data);

/*
 * An accepter is allocated without opening any sockets.  This
 * actually starts up the accepter, allocating the sockets and
 * such.  It is started with accepts enabled.
 *
 * Returns a standard errno on an error, zero otherwise.
 */
int gensio_acc_startup(struct gensio_accepter *accepter);

/*
 * Closes all sockets and disables everything.  shutdown_complete()
 * will be called if successful after the shutdown is complete, if it
 * is not NULL.
 *
 * Returns a EAGAIN if the accepter is already shut down, zero
 * otherwise.
 */
int gensio_acc_shutdown(struct gensio_accepter *accepter,
			gensio_acc_done shutdown_done, void *shutdown_data);

/*
 * Enable the accept callback when connections come in.
 */
void gensio_acc_set_accept_callback_enable(struct gensio_accepter *accepter,
					   bool enabled);

/*
 * Free the network accepter.  If the network accepter is started
 * up, this shuts it down first and shutdown_complete() is NOT called.
 */
void gensio_acc_free(struct gensio_accepter *accepter);

/*
 * Create a new connecting gensio from the given gensio accepter.
 * This will come from the first address/port that the accepter is on
 * for TCP and UDP.  It will bind to all the address/ports for SCTP.
 * To use this, you must specify a string that exactly matches the
 * layers of the accepter.  So, for instance, if the accepter is
 * "telnet,ssl(CA=x1,key=x2,cert=x3),sctp,3095", then the
 * string must be in the form "telnet,ssl(CA=x2),sctp,otherserver,3820"
 * The layers are exactly the same, but you can vary the options to
 * the layers.
 */
int gensio_acc_str_to_gensio(struct gensio_accepter *accepter,
			     const char *str,
			     gensio_event cb, void *user_data,
			     struct gensio **new_io);
/*
 * Returns if the accepter requests exit on close.  A hack for stdio.
 */
bool gensio_acc_exit_on_close(struct gensio_accepter *accepter);

/*
 * Is the genio reliable (won't loose data).
 */
bool gensio_acc_is_reliable(struct gensio_accepter *accepter);

/*
 * Is the genio packet-oriented.  In a packet-oriented genio, if one
 * side writes a chunk of data, when the other side does a read it
 * will get the same chunk of data as a single unit assuming it's
 * buffer sizes are set properly.
 */
bool gensio_acc_is_packet(struct gensio_accepter *accepter);

/*
 * Convert a string representation of an I/O location into an accepter.
 */
int str_to_gensio_accepter(const char *str, struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter);

/*
 * Handler registered so that str_to_gensio_accepter can process an
 * accepter.  This is so users can create their own gensio accepter
 * types.
 */
typedef int (*str_to_gensio_acc_handler)(const char *str,
					 const char * const args[],
					 struct gensio_os_funcs *o,
					 gensio_accepter_event cb,
					 void *user_data,
					 struct gensio_accepter **new_gensio);
/*
 * Add a gensio accepter to the set of registered gensio accepters.
 */
int register_gensio_accepter(struct gensio_os_funcs *o,
			     const char *name,
			     str_to_gensio_acc_handler handler);

/*
 * Allocators for the various gensio accepter types, compatible with
 * register_gensio_accepter().
 */
int str_to_tcp_gensio_accepter(const char *str, const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_acc);
int str_to_udp_gensio_accepter(const char *str, const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_acc);
int str_to_sctp_gensio_accepter(const char *str, const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **new_acc);
int str_to_stdio_gensio_accepter(const char *str, const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **new_acc);
int str_to_ssl_gensio_accepter(const char *str, const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_acc);
int str_to_certauth_gensio_accepter(const char *str, const char * const args[],
				    struct gensio_os_funcs *o,
				    gensio_accepter_event cb,
				    void *user_data,
				    struct gensio_accepter **acc);
int str_to_telnet_gensio_accepter(const char *str, const char * const args[],
				  struct gensio_os_funcs *o,
				  gensio_accepter_event cb,
				  void *user_data,
				  struct gensio_accepter **acc_gensio);

/*
 * Convert a string representation of an I/O location into a client
 * gensio.
 */
int str_to_gensio(const char *str,
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **gensio);

/*
 * Allocators for the various gensio types, compatible with
 * register_gensio().
 */
int str_to_tcp_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
int str_to_udp_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
int str_to_sctp_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);
int str_to_stdio_gensio(const char *str, const char * const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **new_gensio);
int str_to_ssl_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
int str_to_certauth_gensio(const char *str, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_event cb, void *user_data,
			   struct gensio **new_gensio);
int str_to_telnet_gensio(const char *str, const char * const args[],
			 struct gensio_os_funcs *o,
			 gensio_event cb, void *user_data,
			 struct gensio **new_gensio);
int str_to_serialdev_gensio(const char *str, const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_event cb, void *user_data,
			    struct gensio **new_gensio);
int str_to_ipmisol_gensio(const char *str, const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_event cb, void *user_data,
			  struct gensio **new_gensio);


/*
 * Allocators for accepters for different I/O types.
 */
int tcp_gensio_accepter_alloc(struct addrinfo *ai, const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **accepter);

int udp_gensio_accepter_alloc(struct addrinfo *ai, const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **accepter);

int sctp_gensio_accepter_alloc(struct addrinfo *ai, const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **accepter);

int stdio_gensio_accepter_alloc(const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **accepter);

int ssl_gensio_accepter_alloc(struct gensio_accepter *child,
			      const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **accepter);

int certauth_gensio_accepter_alloc(struct gensio_accepter *child,
				   const char * const args[],
				   struct gensio_os_funcs *o,
				   gensio_accepter_event cb, void *user_data,
				   struct gensio_accepter **accepter);

int telnet_gensio_accepter_alloc(struct gensio_accepter *child,
				 const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **accepter);

/* Client allocators. */

/*
 * Create a TCP gensio for the given ai.
 */
int tcp_gensio_alloc(struct addrinfo *ai, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

/*
 * Create a UDP gensio for the given ai.  It uses the first entry in
 * ai.
 */
int udp_gensio_alloc(struct addrinfo *ai, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

/*
 * Create a SCTP gensio for the given ai.
 */
int sctp_gensio_alloc(struct addrinfo *ai, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

/* Run a program (in argv[0]) and attach to it's stdio. */
int stdio_gensio_alloc(const char *const argv[], const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);

/*
 * Make an SSL connection over another gensio.
 */
int ssl_gensio_alloc(struct gensio *child, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **io);

int certauth_gensio_alloc(struct gensio *child, const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_event cb, void *user_data,
			  struct gensio **net);

int serialdev_gensio_alloc(const char *devname, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_event cb, void *user_data,
			   struct gensio **io);

int telnet_gensio_alloc(struct gensio *child, const char * const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **io);

int ipmisol_gensio_alloc(const char *devname, const char * const args[],
			 struct gensio_os_funcs *o,
			 gensio_event cb, void *user_data,
			 struct gensio **io);

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
 * Defaults provide a way to set overall or class-based defaults for
 * gensio values (or you can use it yourself to create your own defaults).
 *
 * For default values, each class will use gensio_get_default with
 * their class (serialdev, telnet, ssl, etc.).  If a value has been set
 * for its class, it will use that value.  If a value has been set with
 * class set to NULL (the "global" defaults") then the value will be
 * used from there.  Otherwise the code will use it's own internal value.
 *
 * The classonly parameter to getdefault means to not look in the global
 * defaults.
 *
 * If you use this for your own default, it is recommended that you use
 * your own "class" name and set "classonly" to true.
 *
 * int and bool are pretty self-explanatory.  Except that if you pass in
 * a non-NULL strval, the code will attempt to get the value from the
 * strval and will return NULL if the value is not valid.  If the value
 * is <minval or >maxval, ERANGE is returned.
 *
 * When setting a str, the value is copied.  The return value of the str
 * is the saved value, you should *not* free it.
 *
 * If it's a enum, setting the value you will pass in a string and a
 * table of possible values in "enum" (terminated with a NULL name).
 * The code will look up the string you pass in in the enums table,
 * and set the value to the integer value.  If the string is not in
 * the enums table, it will return EINVAL.  When you get the value, it
 * will return the value in intval.
 *
 * When getting the value, the type must match what is set in the set
 * call.  If the name is not found, ENOENT is returned.  If the type
 * does not match, then EINVAL is returned.  Note that if you save
 * a value as an enum, you can fetch it as an int.
 *
 * Setting the same default again will replace the old value.
 */
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
		       const char **strval, int *intval);

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

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_H */
