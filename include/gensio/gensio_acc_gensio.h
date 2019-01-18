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

#ifndef GENSIO_ACC_GENSIO_H
#define GENSIO_ACC_GENSIO_H

#include <gensio/gensio_base.h>

/*
 * Create the new parent gensio over the child, for the
 * "str_to_gensio" function of the gensio accepter.
 *
 * args => data4
 * child => data1
 * *new_io => data2
 */
#define GENSIO_GENSIO_ACC_ALLOC_GENSIO		1

/*
 * A new child gensio was created on an incoming connection, create a
 * filter for it's parent gensio.  Whatever you return in finish_data
 * will be passed in to finish parent when that is called.
 *
 * *finish_data => data1
 * *new_filter => data2
 * child => data3
 */
#define GENSIO_GENSIO_ACC_NEW_CHILD		2

/*
 * The parent gensio has been created for the child, finish things up.
 *
 * finish_data => data1
 * new_parent => data2
 * child => data3
 */
#define GENSIO_GENSIO_ACC_FINISH_PARENT		3

/*
 * Free the data.
 */
#define GENSIO_GENSIO_ACC_FREE			4

/*
 * Standard control interface is passed through here.
 *
 * get => data1
 * option => data4
 * data => data2
 * datalen => data3
 */
#define GENSIO_GENSIO_ACC_CONTROL		5

typedef int (*gensio_gensio_acc_cb)(void *acc_data, int op,
				    void *data1, void *data2, void *data3,
				    const void *data4);

int gensio_gensio_accepter_alloc(struct gensio_accepter *child,
				 struct gensio_os_funcs *o,
				 const char *typename,
				 gensio_accepter_event cb, void *user_data,
				 gensio_gensio_acc_cb acc_cb,
				 void *acc_data,
				 struct gensio_accepter **accepter);

#endif /* GENSIO_ACC_GENSIO_H */
