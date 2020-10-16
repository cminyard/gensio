/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_ACC_GENSIO_H
#define GENSIO_ACC_GENSIO_H

#include <gensio/gensio_dllvisibility.h>
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

/*
 * The disable interface.
 */
#define GENSIO_GENSIO_ACC_DISABLE		6

/*
 * Allocate a new child without filter, the function returns the io,
 * not a filter.  If you enable this, you should not implement
 * GENSIO_GENSIO_ACC_NEW_CHILD and that should return GE_NOTSUP.
 * finish_data => data1
 * struct gensio_new_child_io => data2;
 */
struct gensio_new_child_io {
    struct gensio *child;
    gensio_done_err open_done;
    void *open_data;
    struct gensio *new_io;
};
#define GENSIO_GENSIO_ACC_NEW_CHILD_IO		7

typedef int (*gensio_gensio_acc_cb)(void *acc_data, int op,
				    void *data1, void *data2, void *data3,
				    const void *data4);

GENSIO_DLL_PUBLIC
int gensio_gensio_accepter_alloc(struct gensio_accepter *child,
				 struct gensio_os_funcs *o,
				 const char *typename,
				 gensio_accepter_event cb, void *user_data,
				 gensio_gensio_acc_cb acc_cb,
				 void *acc_data,
				 struct gensio_accepter **accepter);

/*
 * This is a special-case free if there is a failure after allocating
 * the accepter above.  It does *not* free the child accepter.
 */
GENSIO_DLL_PUBLIC
void gensio_gensio_acc_free_nochild(struct gensio_accepter *accepter);

#endif /* GENSIO_ACC_GENSIO_H */
