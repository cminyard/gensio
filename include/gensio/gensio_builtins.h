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
 * Allocators for the various gensio accepter types, compatible with
 * register_gensio_accepter().
 */
GENSIO_DLL_PUBLIC
int str_to_tcp_gensio_accepter(const char *str, const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_udp_gensio_accepter(const char *str, const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_sctp_gensio_accepter(const char *str, const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_unix_gensio_accepter(const char *str, const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_stdio_gensio_accepter(const char *str, const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_dummy_gensio_accepter(const char *str, const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_ssl_gensio_accepter(const char *str, const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_mux_gensio_accepter(const char *str, const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_certauth_gensio_accepter(const char *str, const char * const args[],
				    struct gensio_os_funcs *o,
				    gensio_accepter_event cb,
				    void *user_data,
				    struct gensio_accepter **acc);
GENSIO_DLL_PUBLIC
int str_to_telnet_gensio_accepter(const char *str, const char * const args[],
				  struct gensio_os_funcs *o,
				  gensio_accepter_event cb,
				  void *user_data,
				  struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_msgdelim_gensio_accepter(const char *str, const char * const args[],
				    struct gensio_os_funcs *o,
				    gensio_accepter_event cb,
				    void *user_data,
				    struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_relpkt_gensio_accepter(const char *str, const char * const args[],
				  struct gensio_os_funcs *o,
				  gensio_accepter_event cb,
				  void *user_data,
				  struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_ratelimit_gensio_accepter(const char *str, const char * const args[],
				     struct gensio_os_funcs *o,
				     gensio_accepter_event cb,
				     void *user_data,
				     struct gensio_accepter **new_accepter);
GENSIO_DLL_PUBLIC
int str_to_trace_gensio_accepter(const char *str, const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int str_to_perf_gensio_accepter(const char *str, const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int str_to_conacc_gensio_accepter(const char *str, const char * const args[],
				  struct gensio_os_funcs *o,
				  gensio_accepter_event cb,
				  void *user_data,
				  struct gensio_accepter **acc);

GENSIO_DLL_PUBLIC
int str_to_kiss_gensio_accepter(const char *str, const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int str_to_ax25_gensio_accepter(const char *str, const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **acc);

GENSIO_DLL_PUBLIC
int str_to_xlt_gensio_accepter(const char *str, const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int str_to_script_gensio_accepter(const char *str, const char * const args[],
				  struct gensio_os_funcs *o,
				  gensio_accepter_event cb,
				  void *user_data,
				  struct gensio_accepter **new_accepter);

/*
 * Allocators for the various gensio types, compatible with
 * register_gensio().
 */
GENSIO_DLL_PUBLIC
int str_to_tcp_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_udp_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_sctp_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_unix_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_stdio_gensio(const char *str, const char * const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_pty_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_ssl_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_mux_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_certauth_gensio(const char *str, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_event cb, void *user_data,
			   struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_telnet_gensio(const char *str, const char * const args[],
			 struct gensio_os_funcs *o,
			 gensio_event cb, void *user_data,
			 struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_serialdev_gensio(const char *str, const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_event cb, void *user_data,
			    struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_ipmisol_gensio(const char *str, const char * const args[],
			  struct gensio_os_funcs *o,
			  gensio_event cb, void *user_data,
			  struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_echo_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_file_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_msgdelim_gensio(const char *str, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_event cb, void *user_data,
			   struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_relpkt_gensio(const char *str, const char * const args[],
			 struct gensio_os_funcs *o,
			 gensio_event cb, void *user_data,
			 struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_ratelimit_gensio(const char *str, const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_event cb, void *user_data,
			    struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_trace_gensio(const char *str, const char * const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_perf_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_mdns_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_kiss_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_ax25_gensio(const char *str, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_xlt_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);
GENSIO_DLL_PUBLIC
int str_to_keepopen_gensio(const char *str, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_event cb, void *user_data,
			   struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int str_to_script_gensio(const char *str, const char * const args[],
			 struct gensio_os_funcs *o,
			 gensio_event cb, void *user_data,
			 struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int str_to_sound_gensio(const char *str, const char * const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio **new_gensio);

/*
 * Allocators for accepters for different I/O types.
 */
GENSIO_DLL_PUBLIC
int tcp_gensio_accepter_alloc(struct gensio_addr *ai,
			      const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int unix_gensio_accepter_alloc(struct gensio_addr *ai,
			       const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int udp_gensio_accepter_alloc(struct gensio_addr *ai,
			      const char * const args[],
			      struct gensio_os_funcs *o,
			      gensio_accepter_event cb,
			      void *user_data,
			      struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int sctp_gensio_accepter_alloc(struct gensio_addr *ai,
			       const char * const args[],
			       struct gensio_os_funcs *o,
			       gensio_accepter_event cb,
			       void *user_data,
			       struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int stdio_gensio_accepter_alloc(const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **new_accepter);

GENSIO_DLL_PUBLIC
int dummy_gensio_accepter_alloc(const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb,
				void *user_data,
				struct gensio_accepter **new_accepter);

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
int conacc_gensio_accepter_alloc(const char *gensio_str,
				 const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb, void *user_data,
				 struct gensio_accepter **accepter);

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
 */
GENSIO_DLL_PUBLIC
int tcp_gensio_alloc(const struct gensio_addr *ai, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

/*
 * Create a TCP gensio for the given ai.
 */
GENSIO_DLL_PUBLIC
int unix_gensio_alloc(const struct gensio_addr *ai, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

/*
 * Create a UDP gensio for the given ai.  It uses the first entry in
 * ai.
 */
GENSIO_DLL_PUBLIC
int udp_gensio_alloc(const struct gensio_addr *ai, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

/*
 * Create a SCTP gensio for the given ai.
 */
GENSIO_DLL_PUBLIC
int sctp_gensio_alloc(const struct gensio_addr *ai, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

/* Run a program (in argv[0]) and attach to it's stdio. */
GENSIO_DLL_PUBLIC
int stdio_gensio_alloc(const char *const argv[], const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **new_gensio);

/* Run a program (in argv[0]) in a pty and attach to the pty master. */
GENSIO_DLL_PUBLIC
int pty_gensio_alloc(const char * const argv[], const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int serialdev_gensio_alloc(const char *devname, const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_event cb, void *user_data,
			   struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int ipmisol_gensio_alloc(const char *devname, const char * const args[],
			 struct gensio_os_funcs *o,
			 gensio_event cb, void *user_data,
			 struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int echo_gensio_alloc(const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int file_gensio_alloc(const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int mdns_gensio_alloc(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio);

GENSIO_DLL_PUBLIC
int sound_gensio_alloc(const char *devname, const char * const args[],
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
