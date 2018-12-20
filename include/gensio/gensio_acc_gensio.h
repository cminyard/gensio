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

#ifndef GENSIO_ACC_GENSIO_H
#define GENSIO_ACC_GENSIO_H

#include <gensio/gensio_base.h>

/*
 * Create the new parent gensio over the child, for the "connect" function
 * of the genio.  This creates a client gensio.
 *
 * child => data1
 * *new_io => data2
 */
#define GENSIO_GENSIO_ACC_CONNECT_START		1

/*
 * A new child gensio was created, create a filter for it's parent
 * gensio.  Whatever you return in finish_data will be passed in to
 * finish parent when that is called.
 *
 * *finish_data => data1
 * *new_filter => data2
 */
#define GENSIO_GENSIO_ACC_NEW_CHILD		2

/*
 * The parent gensio has been created for the child, finish things up.
 *
 * finish_data => data1
 * new_parent => data2
 */
#define GENSIO_GENSIO_ACC_FINISH_PARENT		3

/*
 * Free the data.
 */
#define GENSIO_GENSIO_ACC_FREE			4

typedef int (*gensio_gensio_acc_cb)(void *acc_data, int op,
				    void *data1, void *data2);

int gensio_gensio_accepter_alloc(struct gensio_accepter *child,
				 struct gensio_os_funcs *o,
				 const char *typename,
				 gensio_accepter_event cb, void *user_data,
				 gensio_gensio_acc_cb acc_cb,
				 void *acc_data,
				 struct gensio_accepter **accepter);

#endif /* GENSIO_ACC_GENSIO_H */
