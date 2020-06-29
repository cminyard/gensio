/*
 *  localport - A library for handling local gensio connections to mux channel
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef LOCALPORTS_H
#define LOCALPORTS_H

#include <stdarg.h>
#include <gensio/gensio.h>

void start_local_ports(struct gensio *user_io);

int add_local_port(struct gensio_os_funcs *o,
		   const char *gensio_str, const char *service_str,
		   const char *id_str);

void remote_port_new_con(struct gensio_os_funcs *o, struct gensio *io,
			 const char *connecter_str, char *id_str);

extern void (*localport_err)(const char *format, va_list ap);

#endif /* LOCALPORTS_H */
