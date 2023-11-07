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

/*
 * Following struct in buf
 */
struct gensio_func_acontrol {
    const char *data;
    gensiods datalen;
    gensio_time *timeout;
    gensio_control_done done;
    void *cb_data;
};
#define GENSIO_FUNC_ACONTROL		15

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
void gensio_set_is_mux(struct gensio *io, bool is_mux);
GENSIO_DLL_PUBLIC
void gensio_set_is_serial(struct gensio *io, bool is_serial);
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
void gensio_acc_set_is_mux(struct gensio_accepter *io, bool is_mux);
GENSIO_DLL_PUBLIC
void gensio_acc_set_is_serial(struct gensio_accepter *io, bool is_serial);

GENSIO_DLL_PUBLIC
void gensio_acc_vlog(struct gensio_accepter *acc, enum gensio_log_levels level,
		     const char *str, va_list args);
GENSIO_DLL_PUBLIC
void gensio_acc_log(struct gensio_accepter *acc, enum gensio_log_levels level,
		    const char *str, ...);

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
typedef int (*gensio_terminal_acc_alloch)(const void *gdata,
					 const char * const args[],
					 struct gensio_os_funcs *o,
					 gensio_accepter_event cb,
					 void *user_data,
					 struct gensio_accepter **new_accepter);
typedef int (*gensio_filter_acc_alloch)(struct gensio_accepter *child,
					const char * const args[],
					struct gensio_os_funcs *o,
					gensio_accepter_event cb,
					void *user_data,
					struct gensio_accepter **new_accepter);


/*
 * Add a gensio accepter to the set of registered gensio accepters.
 */
GENSIO_DLL_PUBLIC
int register_gensio_accepter(struct gensio_os_funcs *o,
			     const char *name,
			     str_to_gensio_acc_handler handler,
			     gensio_terminal_acc_alloch alloc);

/*
 * Like above, but use for filter gensios so str_to_gensio_accepter_child()
 * will work.
 */
GENSIO_DLL_PUBLIC
int register_filter_gensio_accepter(struct gensio_os_funcs *o,
				    const char *name,
				    str_to_gensio_acc_handler handler,
				    gensio_filter_acc_alloch alloc);

/*
 * Handler registered so that str_to_gensio can process a gensio.
 * This is so users can create their own gensio types.
 */
typedef int (*str_to_gensio_handler)(const char *str, const char * const args[],
				     struct gensio_os_funcs *o,
				     gensio_event cb, void *user_data,
				     struct gensio **new_gensio);
typedef int (*gensio_terminal_alloch)(const void *gdata,
				     const char * const args[],
				     struct gensio_os_funcs *o,
				     gensio_event cb, void *user_data,
				     struct gensio **new_gensio);

/*
 * Add a gensio to the set of registered gensios.
 */
GENSIO_DLL_PUBLIC
int register_gensio(struct gensio_os_funcs *o,
		    const char *name, str_to_gensio_handler handler,
		    gensio_terminal_alloch alloc);

/*
 * Handler registered so that str_to_gensio_child can process a filter
 * gensio with a child.  This is so users can create their own gensio
 * filter types.
 */
typedef int (*gensio_filter_alloch)(struct gensio *child,
				    const char * const args[],
				    struct gensio_os_funcs *o,
				    gensio_event cb, void *user_data,
				    struct gensio **new_gensio);

/*
 * Add a filter gensio to the set of gensios.
 */
GENSIO_DLL_PUBLIC
int register_filter_gensio(struct gensio_os_funcs *o,
			   const char *name,
			   str_to_gensio_handler handler,
			   gensio_filter_alloch alloc);

struct gensio_class_cleanup {
    void (*cleanup)(void);

    /* For internal used by gensio, set to NULL before calling and do not use. */
    void *ginfo;

    struct gensio_class_cleanup *next;
};

/*
 * Register a class cleanup handler.  Everything in this except
 * cleanup must be NULL or zero.  You may call this multiple times
 * with the same item and secondary ones will be ignored.
 */
GENSIO_DLL_PUBLIC
void gensio_register_class_cleanup(struct gensio_class_cleanup *cleanup);

/*
 * Parameter parsing helpers.
 */
struct gensio_pparm_info {
    struct gensio_os_funcs *o;
    gensio_event ghandler;
    gensio_accepter_event acchandler;
    int err;
    const char *gensio_name;
    void *user_data;
};

#define GENSIO_DECLARE_PPINFO(name, po, ghandler, acchandler, gname, user) \
    struct gensio_pparm_info name = { po, ghandler, acchandler, 0, gname, user }
#define GENSIO_DECLARE_PPGENSIO(name, po, handler, gname, user)		\
    GENSIO_DECLARE_PPINFO(name, po, handler, NULL, gname, user)
#define GENSIO_DECLARE_PPACCEPTER(name, po, handler, gname, user)	\
    GENSIO_DECLARE_PPINFO(name, po, NULL, handler, gname, user)
#define GENSIO_DECLARE_PPNULL(name)	\
    GENSIO_DECLARE_PPINFO(name, NULL, NULL, NULL, NULL, NULL)

GENSIO_DLL_PUBLIC
int gensio_pparm_value(struct gensio_pparm_info *p,
		       const char *str, const char *key, const char **value);
GENSIO_DLL_PUBLIC
int gensio_pparm_ds(struct gensio_pparm_info *p,
		    const char *str, const char *key, gensiods *value);
GENSIO_DLL_PUBLIC
int gensio_pparm_uint(struct gensio_pparm_info *p,
		      const char *str, const char *key, unsigned int *value);
GENSIO_DLL_PUBLIC
int gensio_pparm_int(struct gensio_pparm_info *p,
		     const char *str, const char *key, int *value);
GENSIO_DLL_PUBLIC
int gensio_pparm_bool(struct gensio_pparm_info *p,
		      const char *str, const char *key, bool *rvalue);
GENSIO_DLL_PUBLIC
int gensio_pparm_boolv(struct gensio_pparm_info *p,
		       const char *str, const char *key,
		       const char *trueval, const char *falseval,
		       bool *rvalue);
GENSIO_DLL_PUBLIC
int gensio_pparm_enum(struct gensio_pparm_info *p,
		      const char *str, const char *key,
		      struct gensio_enum_val *enums, int *rval);
/* The value of protocol is the same as for gensio_scan_network_port(). */
GENSIO_DLL_PUBLIC
int gensio_pparm_addrs(struct gensio_pparm_info *p,
		       const char *str, const char *key, int protocol,
		       bool listen, bool require_port,
		       struct gensio_addr **ai);
GENSIO_DLL_PUBLIC
int gensio_pparm_addrs_noport(struct gensio_pparm_info *p,
			      const char *str, const char *key,
			      int protocol, struct gensio_addr **ai);
GENSIO_DLL_PUBLIC
int gensio_pparm_mode(struct gensio_pparm_info *p,
		      const char *str, const char *key, unsigned int *rmode);
GENSIO_DLL_PUBLIC
int gensio_pparm_perm(struct gensio_pparm_info *p,
		      const char *str, const char *key, unsigned int *rmode);
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
int gensio_pparm_time(struct gensio_pparm_info *p,
		      const char *str, const char *key, char mod,
		      gensio_time *rgt);

GENSIO_DLL_PUBLIC
int gensio_pparm_float(struct gensio_pparm_info *p,
		       const char *str, const char *key, float *rfl);

/*
 * Report an unknown parameter when allocating a gensio.
 */
GENSIO_DLL_PUBLIC
void gensio_pparm_unknown_parm(struct gensio_pparm_info *p,
			       const char *arg);

GENSIO_DLL_PUBLIC
void gensio_pparm_vlog(struct gensio_pparm_info *p, const char *log,
		       va_list args);
GENSIO_DLL_PUBLIC
void i_gensio_pparm_log(struct gensio_pparm_info *p, const char *log, ...);
#define gensio_pparm_log(p, log, ...) \
    i_gensio_pparm_log(p, "%s %s: " log,				\
		       (p)->ghandler ? "gensio" : "accepter",		\
		       (p)->gensio_name,				\
		       __VA_ARGS__)

/* Use if just a string and no arguments. */
#define gensio_pparm_slog(p, log, ...) \
    i_gensio_pparm_log(p, "%s %s: " log,				\
		       (p)->ghandler ? "gensio" : "accepter",		\
		       (p)->gensio_name)

/*
 * The following two functions are for logging information to a
 * gensio.  If the gensio doesn't handle the log (returns GE_NOTSUP)
 * then it logs through the os handler.
 *
 * Because of this, you must be careful to call this without holding
 * locks.  If you really need to log with locks enabled, only log
 * through the os handler.
 */
GENSIO_DLL_PUBLIC
void gensio_gvlog(struct gensio *io, enum gensio_log_levels level,
		  const char *log, va_list args);

GENSIO_DLL_PUBLIC
void gensio_glog(struct gensio *io, enum gensio_log_levels level,
		 const char *log, ...);

#endif /* GENSIO_CLASS_H */
