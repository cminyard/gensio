/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_CLASS_H
#define GENSIO_CLASS_H

#include <stdarg.h>

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

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
 * Was RADDR_TO_STR
 */
#define GENSIO_FUNC_unused1		2

/*
 * Was GET_RADDR
 */
#define GENSIO_FUNC_unused2		3

/*
 * Was REMOTE_ID
 */
#define GENSIO_FUNC_unused3		4

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

/* Used to be GENSIO_FUNC_REF, the main gensio code handles refcounts now */
#define GENSIO_FUNC_xxx			8

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

GENSIO_DLL_PUBLIC
struct gensio *gensio_data_alloc(struct gensio_os_funcs *o,
				 gensio_event cb, void *user_data,
				 gensio_func func, struct gensio *child,
				 const char *typename, void *gensio_data);
GENSIO_DLL_PUBLIC
void gensio_data_free(struct gensio *io);
GENSIO_DLL_PUBLIC
void *gensio_get_gensio_data(struct gensio *io);

GENSIO_DLL_PUBLIC
int gensio_call_func(struct gensio *io, int func, gensiods *count,
		     const void *cbuf, gensiods buflen, void *buf,
		     const char *const *auxdata);

GENSIO_DLL_PUBLIC
void gensio_set_is_client(struct gensio *io, bool is_client);
GENSIO_DLL_PUBLIC
void gensio_set_is_packet(struct gensio *io, bool is_packet);
GENSIO_DLL_PUBLIC
void gensio_set_is_reliable(struct gensio *io, bool is_reliable);
GENSIO_DLL_PUBLIC
void gensio_set_is_authenticated(struct gensio *io, bool is_authenticate);
GENSIO_DLL_PUBLIC
void gensio_set_is_encrypted(struct gensio *io, bool is_encrypted);
GENSIO_DLL_PUBLIC
void gensio_set_is_message(struct gensio *io, bool is_message);
GENSIO_DLL_PUBLIC
void gensio_set_attr_from_child(struct gensio *io, struct gensio *child);
GENSIO_DLL_PUBLIC
gensio_event gensio_get_cb(struct gensio *io);
GENSIO_DLL_PUBLIC
int gensio_cb(struct gensio *io, int event, int err,
	      unsigned char *buf, gensiods *buflen,
	      const char *const *auxdata);

/*
 * Add and get the classdata for a gensio.
 */
struct gensio_classops {
    int (*propagate_to_parent)(struct gensio *parent, struct gensio *child,
			       void *classdata);
    void (*cleanup)(struct gensio *io, void *classdata);
};
#define GENSIO_CLASSOPS_VERSION 1
GENSIO_DLL_PUBLIC
int gensio_addclass(struct gensio *io, const char *name, int classops_ver,
		    struct gensio_classops *ops, void *classdata);
GENSIO_DLL_PUBLIC
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

GENSIO_DLL_PUBLIC
struct gensio_accepter *gensio_acc_data_alloc(struct gensio_os_funcs *o,
		      gensio_accepter_event cb, void *user_data,
		      gensio_acc_func func, struct gensio_accepter *child,
		      const char *typename, void *gensio_acc_data);
GENSIO_DLL_PUBLIC
void gensio_acc_data_free(struct gensio_accepter *acc);
GENSIO_DLL_PUBLIC
void *gensio_acc_get_gensio_data(struct gensio_accepter *acc);
GENSIO_DLL_PUBLIC
int gensio_acc_cb(struct gensio_accepter *acc, int event, void *data);
struct gensio_acc_classops {
    int (*propagate_to_parent)(struct gensio_accepter *parent,
			       struct gensio_accepter *child,
			       void *classdata);
    void (*cleanup)(struct gensio_accepter *io, void *classdata);
};
#define GENSIO_ACC_CLASSOPS_VERSION 1
GENSIO_DLL_PUBLIC
int gensio_acc_addclass(struct gensio_accepter *acc,
			const char *name, int classops_ver,
			struct gensio_acc_classops *ops,
			void *classdata);
GENSIO_DLL_PUBLIC
void *gensio_acc_getclass(struct gensio_accepter *acc, const char *name);

/*
 * Keep track of the gensios pending on an accepter.  Primarily so that
 * disable can handle them.
 */
GENSIO_DLL_PUBLIC
void gensio_acc_add_pending_gensio(struct gensio_accepter *acc,
				   struct gensio *io);
GENSIO_DLL_PUBLIC
void gensio_acc_remove_pending_gensio(struct gensio_accepter *acc,
				      struct gensio *io);

GENSIO_DLL_PUBLIC
void gensio_acc_set_is_packet(struct gensio_accepter *io, bool is_packet);
GENSIO_DLL_PUBLIC
void gensio_acc_set_is_reliable(struct gensio_accepter *io, bool is_reliable);
GENSIO_DLL_PUBLIC
void gensio_acc_set_is_message(struct gensio_accepter *io, bool is_message);

GENSIO_DLL_PUBLIC
void gensio_acc_vlog(struct gensio_accepter *acc, enum gensio_log_levels level,
		     char *str, va_list args);
GENSIO_DLL_PUBLIC
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
GENSIO_DLL_PUBLIC
int register_gensio_accepter(struct gensio_os_funcs *o,
			     const char *name,
			     str_to_gensio_acc_handler handler);

/*
 * Like above, but use for filter gensios so str_to_gensio_accepter_child()
 * will work.
 */
GENSIO_DLL_PUBLIC
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
GENSIO_DLL_PUBLIC
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
GENSIO_DLL_PUBLIC
int register_filter_gensio(struct gensio_os_funcs *o,
			   const char *name, str_to_gensio_handler handler,
			   str_to_gensio_child_handler chandler);

struct gensio_class_cleanup {
    void (*cleanup)(void);
    struct gensio_class_cleanup *next;
};

GENSIO_DLL_PUBLIC
void gensio_register_class_cleanup(struct gensio_class_cleanup *cleanup);

#endif /* GENSIO_CLASS_H */
