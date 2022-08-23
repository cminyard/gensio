/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * These are the interface functions for built-in gensios.
 */

#ifndef GENSIO_BUILTINS_H
#define GENSIO_BUILTINS_H

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Allocators for accepters for different I/O types.
 * const struct gensio_addr *
 */
GENSIO_DLL_PUBLIC
int tcp_gensio_accepter_alloc(const void *gdata,
			      const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **new_accepter);

/* const struct gensio_addr * */
GENSIO_DLL_PUBLIC
int unix_gensio_accepter_alloc(const void *gdata,
			       const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);

/* const struct gensio_addr * */
GENSIO_DLL_PUBLIC
int udp_gensio_accepter_alloc(const void *gdata,
			      const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **new_accepter);

/* const struct gensio_addr * */
GENSIO_DLL_PUBLIC
int sctp_gensio_accepter_alloc(const void *gdata,
			       const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);

/* const char * const args[] */
GENSIO_DLL_PUBLIC
int stdio_gensio_accepter_alloc(const void *gdata,
				const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int dummy_gensio_accepter_alloc(const void *gdata,
				const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **new_accepter);

/* const char *gensio_str */
GENSIO_DLL_PUBLIC
int conacc_gensio_accepter_alloc(const void *gdata,
				 const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb, void *user_data,
				 struct gensio_accepter **accepter);

/*
 * Filter accepters.
 */
GENSIO_DLL_PUBLIC
int ssl_gensio_accepter_alloc(struct gensio_accepter *child,
			      const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int mux_gensio_accepter_alloc(struct gensio_accepter *child,
			      const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int certauth_gensio_accepter_alloc(struct gensio_accepter *child,
				   const char * const args[],
				   struct gensio_os_funcs *o,
				   gensio_accepter_event cb, void *user_data,
				   struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int telnet_gensio_accepter_alloc(struct gensio_accepter *child,
				 const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int msgdelim_gensio_accepter_alloc(struct gensio_accepter *child,
				   const char * const args[],
				   struct gensio_os_funcs *o,
				   gensio_accepter_event cb,
				   void *user_data,
				   struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int relpkt_gensio_accepter_alloc(struct gensio_accepter *child,
				 const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int ratelimit_gensio_accepter_alloc(struct gensio_accepter *child,
				    const char * const args[],
				    struct gensio_os_funcs *o,
				    gensio_accepter_event cb,
				    void *user_data,
				    struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int trace_gensio_accepter_alloc(struct gensio_accepter *child,
				const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int perf_gensio_accepter_alloc(struct gensio_accepter *child,
			       const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int kiss_gensio_accepter_alloc(struct gensio_accepter *child,
			       const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int ax25_gensio_accepter_alloc(struct gensio_accepter *child,
			       const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb, void *user_data,
			       struct gensio_accepter **accepter);

GENSIO_DLL_PUBLIC
int xlt_gensio_accepter_alloc(struct gensio_accepter *child,
			      const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int script_gensio_accepter_alloc(struct gensio_accepter *child,
				 const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **new_accepter);

/* Client allocators. */

/*
 * Create a TCP gensio for the given ai.
 * const struct gensio_addr *
 */
GENSIO_DLL_PUBLIC
int tcp_gensio_alloc(const void *gdata, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

/*
 * Create a unix gensio for the given ai.
 * const struct gensio_addr *
 */
GENSIO_DLL_PUBLIC
int unix_gensio_alloc(const void *gdata, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

/*
 * Create a UDP gensio for the given ai.  It uses the first entry in
 * ai.
 * const struct gensio_addr *
 */
GENSIO_DLL_PUBLIC
int udp_gensio_alloc(const void *gdata, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

/*
 * Create a SCTP gensio for the given ai.
 * const struct gensio_addr *
 */
GENSIO_DLL_PUBLIC
int sctp_gensio_alloc(const void *gdata, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

/* Run a program (in argv[0]) and attach to it's stdio. */
/* const char *const argv[] */
GENSIO_DLL_PUBLIC
int stdio_gensio_alloc(const void *gdata, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);

/* const char *const argv[] */
/* Run a program (in argv[0]) in a pty and attach to the pty master. */
GENSIO_DLL_PUBLIC
int pty_gensio_alloc(const void *gdata, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

/* const char * */
GENSIO_DLL_PUBLIC
int serialdev_gensio_alloc(const void *gdata, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_event cb, void *user_data,
			   struct gensio **new_gensio);

/* const char * */
GENSIO_DLL_PUBLIC
int ipmisol_gensio_alloc(const void *gdata, const char * const args[],
			 struct gensio_os_funcs *o,
			 gensio_event cb, void *user_data,
			 struct gensio **new_gensio);

/* NULL */
GENSIO_DLL_PUBLIC
int echo_gensio_alloc(const void *gdata,
		      const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

/* NULL */
GENSIO_DLL_PUBLIC
int file_gensio_alloc(const void *gdata,
		      const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

/* const char *str */
GENSIO_DLL_PUBLIC
int mdns_gensio_alloc(const void *gdata, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

/* const char *devname */
GENSIO_DLL_PUBLIC
int sound_gensio_alloc(const void *gdata, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **rio);

/*
 * Filter gensios
 */
GENSIO_DLL_PUBLIC
int ssl_gensio_alloc(struct gensio *child, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int mux_gensio_alloc(struct gensio *child, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int certauth_gensio_alloc(struct gensio *child, const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_event cb, void *user_data,
			  struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int telnet_gensio_alloc(struct gensio *child, const char * const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int msgdelim_gensio_alloc(struct gensio *child, const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_event cb, void *user_data,
			  struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int relpkt_gensio_alloc(struct gensio *child, const char * const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int ratelimit_gensio_alloc(struct gensio *child, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_event cb, void *user_data,
			   struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int trace_gensio_alloc(struct gensio *child, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int perf_gensio_alloc(struct gensio *child, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int kiss_gensio_alloc(struct gensio *child, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int ax25_gensio_alloc(struct gensio *child, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int xlt_gensio_alloc(struct gensio *child, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int keepopen_gensio_alloc(struct gensio *child, const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_event cb, void *user_data,
			  struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int script_gensio_alloc(struct gensio *child, const char * const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **new_gensio);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_BUILTINS_H */
