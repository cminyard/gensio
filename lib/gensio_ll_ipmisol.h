/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_LL_IPMISOL_H
#define GENSIO_LL_IPMISOL_H

#include <gensio/gensio_base.h>

#define GENSIO_SOL_LL_FREE	GENSIO_EVENT_USER_MIN
/*
 * op is client values from sergenio.h serial callbacks, plus
 * GENSIO_SOL_LL_FREE to tell the user that it can free its data.
 */
typedef void (*gensio_ll_ipmisol_cb)(void *handler_data, int op, void *data);

/* op is values from sergensio_class.h. */
typedef int (*gensio_ll_ipmisol_ops)(struct gensio_ll *ll, int op,
				     int val, char *buf,
				     void *done, void *cb_data);

int ipmisol_gensio_ll_alloc(struct gensio_os_funcs *o,
			    const char *devname,
			    gensio_ll_ipmisol_cb ser_cbs,
			    void *ser_cbs_data,
			    gensiods max_read_size,
			    gensiods max_write_size,
			    gensio_ll_ipmisol_ops *rops,
			    struct gensio_ll **rll);

void ipmisol_gensio_ll_set_sio(struct gensio_ll *ll, struct sergensio *sio);

#endif /* GENSIO_LL_IPMISOL_H */
