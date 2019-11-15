/*
 *  localport - A library for handling local gensio connections to mux channel
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

void (*localport_err)(const char *format, va_list ap);

#endif /* LOCALPORTS_H */
