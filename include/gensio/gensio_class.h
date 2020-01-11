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

#ifndef GENSIO_CLASS_H
#define GENSIO_CLASS_H

#include <gensio/gensio.h>
#include <gensio/gensio_list.h>

/*
 * This is the default for most gensio layers.  Some have specific buffer
 * sizes, especially packet protocols like UDP and SSL.
 */
#define GENSIO_DEFAULT_BUF_SIZE		1024

/*
 * Functions for gensio_func...
 */

/*
 * count => count
 * sg => buf
 * sgnum => buflen
 * auxdata => auxdata
 */
#define GENSIO_FUNC_WRITE_SG		1

/*
 * pos => count
 * buf => buf
 * buflen => buflen
 */
#define GENSIO_FUNC_RADDR_TO_STR	2

/*
 * addr => buf
 * addrlen => count
 */
#define GENSIO_FUNC_GET_RADDR		3

/*
 * id => buf
 */
#define GENSIO_FUNC_REMOTE_ID		4

/*
 * open_done => cbuf
 * open_data => buf
 */
#define GENSIO_FUNC_OPEN		5

/*
 * close_done => cbuf
 * close_data => buf
 */
#define GENSIO_FUNC_CLOSE		6

/* No translations needed, return value not used */
#define GENSIO_FUNC_FREE		7

/* No translations needed, return value not used */
#define GENSIO_FUNC_REF			8

/* enabled => buflen, return value not used. */
#define GENSIO_FUNC_SET_READ_CALLBACK	9

/* enabled => buflen, return value not used. */
#define GENSIO_FUNC_SET_WRITE_CALLBACK	10

/*
 * Following struct in buf
 */
struct gensio_func_alloc_channel_data {
    const char * const *args;
    gensio_event cb;
    void *user_data;
    struct gensio *new_io;
};
#define GENSIO_FUNC_ALLOC_CHANNEL	11

/*
 * get => cbuf
 * option => buflen
 * auxdata => buf
 * datalen => count
 */
#define GENSIO_FUNC_CONTROL		12

/*
 * Disable the function of the gensio so it can be freed without
 * generating any I/O.
 */
#define GENSIO_FUNC_DISABLE		13

/*
 * See GENSIO_FUNC_OPEN for details.
 */
#define GENSIO_FUNC_OPEN_NOCHILD	14

typedef int (*gensio_func)(struct gensio *io, int func, gensiods *count,
			   const void *cbuf, gensiods buflen, void *buf,
			   const char *const *auxdata);

/*
 * Increment the gensio's refcount.  There are situations where one
 * piece of code passes a gensio into another piece of code, and
 * that other piece of code that might free it on an error, but
 * the upper layer gets the error and wants to free it, too.  This
 * keeps it around for that situation.
 */
void gensio_ref(struct gensio *io);

struct gensio *gensio_data_alloc(struct gensio_os_funcs *o,
				 gensio_event cb, void *user_data,
				 gensio_func func, struct gensio *child,
				 const char *typename, void *gensio_data);
void gensio_data_free(struct gensio *io);
void *gensio_get_gensio_data(struct gensio *io);

void gensio_set_is_client(struct gensio *io, bool is_client);
void gensio_set_is_packet(struct gensio *io, bool is_packet);
void gensio_set_is_reliable(struct gensio *io, bool is_reliable);
void gensio_set_is_authenticated(struct gensio *io, bool is_authenticate);
void gensio_set_is_encrypted(struct gensio *io, bool is_encrypted);
void gensio_set_is_message(struct gensio *io, bool is_message);
gensio_event gensio_get_cb(struct gensio *io);
void gensio_set_cb(struct gensio *io, gensio_event cb, void *user_data);
int gensio_cb(struct gensio *io, int event, int err,
	      unsigned char *buf, gensiods *buflen,
	      const char *const *auxdata);

/*
 * Add and get the classdata for a gensio.
 */
int gensio_addclass(struct gensio *io, const char *name, void *classdata);
void *gensio_getclass(struct gensio *io, const char *name);

/*
 * Functions for gensio_acc_func...
 */

/*
 * No translation needed
 */
#define GENSIO_ACC_FUNC_STARTUP			1

/*
 * shutdown_done => done
 * shutdown_data => data
 */
#define GENSIO_ACC_FUNC_SHUTDOWN		2

/*
 * enabled => val
 */
#define GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK	3

/*
 * No translation needed
 */
#define GENSIO_ACC_FUNC_FREE			4

/*
 * str => addr
 * cb => done
 * user_data => data
 * new_io => ret
 */
#define GENSIO_ACC_FUNC_STR_TO_GENSIO		5

/*
 * get => val
 * &option => done
 * data => data
 * datalen => ret
 */
#define GENSIO_ACC_FUNC_CONTROL			6

/*
 * Like GENSIO_FUNC_DISABLE, see that for details.
 */
#define GENSIO_ACC_FUNC_DISABLE			7

typedef int (*gensio_acc_func)(struct gensio_accepter *acc, int func, int val,
			       const char *addr, void *done, void *data,
			       const void *data2, void *ret);

struct gensio_accepter *gensio_acc_data_alloc(struct gensio_os_funcs *o,
		      gensio_accepter_event cb, void *user_data,
		      gensio_acc_func func, struct gensio_accepter *child,
		      const char *typename, void *gensio_acc_data);
void gensio_acc_data_free(struct gensio_accepter *acc);
void *gensio_acc_get_gensio_data(struct gensio_accepter *acc);
int gensio_acc_cb(struct gensio_accepter *acc, int event, void *data);
int gensio_acc_addclass(struct gensio_accepter *acc,
			const char *name, void *classdata);
void *gensio_acc_getclass(struct gensio_accepter *acc, const char *name);

/*
 * Keep track of the gensios pending on an accepter.  Primarily so that
 * disable can handle them.
 */
void gensio_acc_add_pending_gensio(struct gensio_accepter *acc,
				   struct gensio *io);
void gensio_acc_remove_pending_gensio(struct gensio_accepter *acc,
				      struct gensio *io);

/*
 * Close all the pending ios with the done.  Returns the number of close
 * calls that failed and had gensio_free() called on them.
 */
unsigned int gensio_acc_close_pending_ios(struct gensio_accepter *acc,
					  gensio_done done, void *done_data);

void gensio_acc_set_is_packet(struct gensio_accepter *io, bool is_packet);
void gensio_acc_set_is_reliable(struct gensio_accepter *io, bool is_reliable);
void gensio_acc_set_is_message(struct gensio_accepter *io, bool is_message);

void gensio_acc_vlog(struct gensio_accepter *acc, enum gensio_log_levels level,
		     char *str, va_list args);
void gensio_acc_log(struct gensio_accepter *acc, enum gensio_log_levels level,
		    char *str, ...);

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
typedef int (*str_to_gensio_acc_child_handler)(struct gensio_accepter *child,
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
 * Like above, but use for filter gensios so str_to_gensio_accepter_child()
 * will work.
 */
int register_filter_gensio_accepter(struct gensio_os_funcs *o,
				    const char *name,
				    str_to_gensio_acc_handler handler,
				    str_to_gensio_acc_child_handler chandler);

/*
 * Handler registered so that str_to_gensio can process a gensio.
 * This is so users can create their own gensio types.
 */
typedef int (*str_to_gensio_handler)(const char *str, const char * const args[],
				     struct gensio_os_funcs *o,
				     gensio_event cb, void *user_data,
				     struct gensio **new_gensio);

/*
 * Add a gensio to the set of registered gensios.
 */
int register_gensio(struct gensio_os_funcs *o,
		    const char *name, str_to_gensio_handler handler);

/*
 * Handler registered so that str_to_gensio_child can process a filter
 * gensio with a child.  This is so users can create their own gensio
 * filter types.
 */
typedef int (*str_to_gensio_child_handler)(struct gensio *child,
					   const char * const args[],
					   struct gensio_os_funcs *o,
					   gensio_event cb, void *user_data,
					   struct gensio **new_gensio);

/*
 * Add a filter gensio to the set of gensios.
 */
int register_filter_gensio(struct gensio_os_funcs *o,
			   const char *name, str_to_gensio_handler handler,
			   str_to_gensio_child_handler chandler);


/*
 * Take a string in the form [ipv4|ipv6,][hostname,]port and convert
 * it to an addrinfo structure.  If this returns success, the user
 * must free rai with gensio_free_addrinfo().  If socktype or protocol
 * are non-zero, allocate for the given socktype and protocol.
 */
int gensio_scan_netaddr(struct gensio_os_funcs *o, const char *str, bool listen,
			int socktype, int protocol, struct addrinfo **rai);

char *gensio_strdup(struct gensio_os_funcs *o, const char *str);

int gensio_scan_args(struct gensio_os_funcs *o,
		     const char **rstr, int *argc, const char ***args);

#endif /* GENSIO_CLASS_H */
