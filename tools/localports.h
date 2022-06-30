/*
 *  localport - A library for handling local gensio connections to mux channel
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  gensio give you permission to combine gensio with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for gensio and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of gensio are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
 */

#ifndef LOCALPORTS_H
#define LOCALPORTS_H

#include <stdarg.h>
#include <gensio/gensio.h>

struct local_ports;

struct local_ports *alloc_local_ports(struct gensio_os_funcs *o,
				      void (*localport_err)(void *cb_data,
							    const char *format,
							    va_list ap),
				      void *cb_data);

void free_local_ports(struct local_ports *p);

void start_local_ports(struct local_ports *p, struct gensio *user_io);

int add_local_port(struct local_ports *p,
		   const char *gensio_str, const char *service_str,
		   const char *id_str);

void remote_port_new_con(struct local_ports *p, struct gensio *io,
			 const char *connecter_str, char *id_str);

#endif /* LOCALPORTS_H */
