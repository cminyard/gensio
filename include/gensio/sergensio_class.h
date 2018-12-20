/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.  These licenses are available
 *  in the root directory of this package named COPYING.LIB and
 *  COPYING.BSD, respectively.
 */

#ifndef SERGENSIO_CLASS_H
#define SERGENSIO_CLASS_H

#include <stddef.h>
#include <gensio/gensio_class.h>
#include <gensio/sergensio.h>

#define SERGENSIO_FUNC_BAUD			1
#define SERGENSIO_FUNC_DATASIZE			2
#define SERGENSIO_FUNC_PARITY			3
#define SERGENSIO_FUNC_STOPBITS			4
#define SERGENSIO_FUNC_FLOWCONTROL		5
#define SERGENSIO_FUNC_IFLOWCONTROL		6
#define SERGENSIO_FUNC_SBREAK			7
#define SERGENSIO_FUNC_DTR			8
#define SERGENSIO_FUNC_RTS			9
#define SERGENSIO_FUNC_MODEMSTATE		10
#define SERGENSIO_FUNC_LINESTATE		11
#define SERGENSIO_FUNC_FLOWCONTROL_STATE	12
#define SERGENSIO_FUNC_FLUSH			13
#define SERGENSIO_FUNC_SIGNATURE		14
#define SERGENSIO_FUNC_SEND_BREAK		15

typedef int (*sergensio_func)(struct sergensio *sio, int op, int val, char *buf,
			      void *done, void *cb_data);


struct sergensio *sergensio_data_alloc(struct gensio_os_funcs *o,
				       struct gensio *io,
				       sergensio_func func,
				       void *gensio_data);
void sergensio_data_free(struct sergensio *sio);

void *sergensio_get_gensio_data(struct sergensio *sio);

#endif /* SERGENSIO_CLASS_H */
