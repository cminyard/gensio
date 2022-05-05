/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef SERGENSIO_CLASS_H
#define SERGENSIO_CLASS_H

#include <stddef.h>
#include <gensio/gensio_dllvisibility.h>
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
#define SERGENSIO_FUNC_CTS			16
#define SERGENSIO_FUNC_DCD_DSR			17
#define SERGENSIO_FUNC_RI			18

typedef int (*sergensio_func)(struct sergensio *sio, int op, int val, char *buf,
			      void *done, void *cb_data);


GENSIO_DLL_PUBLIC /* Deprecated, use sergensio_addclass(). */
struct sergensio *sergensio_data_alloc(struct gensio_os_funcs *o,
				       struct gensio *io,
				       sergensio_func func,
				       void *gensio_data);
GENSIO_DLL_PUBLIC
void sergensio_data_free(struct sergensio *sio);

GENSIO_DLL_PUBLIC
int sergensio_addclass(struct gensio_os_funcs *o, struct gensio *io,
		       sergensio_func func, void *gensio_data,
		       struct sergensio **sio);

GENSIO_DLL_PUBLIC
void *sergensio_get_gensio_data(struct sergensio *sio);

GENSIO_DLL_PUBLIC
struct gensio *sergensio_get_my_gensio(struct sergensio *sio);

typedef int (*sergensio_acc_func)(struct sergensio_accepter *sio,
				  int op, int val,
				  char *buf, void *done, void *cb_data);

GENSIO_DLL_PUBLIC /* Deprecated, use sergensio_acc_addclass(). */
struct sergensio_accepter *sergensio_acc_data_alloc(struct gensio_os_funcs *o,
						    struct gensio_accepter *acc,
						    sergensio_acc_func func,
						    void *gensio_acc_data);
GENSIO_DLL_PUBLIC
void sergensio_acc_data_free(struct sergensio_accepter *sio);
GENSIO_DLL_PUBLIC
int sergensio_acc_addclass(struct gensio_os_funcs *o,
			   struct gensio_accepter *acc,
			   sergensio_acc_func func, void *gensio_data,
			   struct sergensio_accepter **rsacc);

#endif /* SERGENSIO_CLASS_H */
