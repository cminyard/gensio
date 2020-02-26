/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <gensio/sergensio_class.h>

#include "utils.h"
#include "gensio_ll_ipmisol.h"

struct iterm_data {
    struct sergensio *sio;
    struct gensio_os_funcs *o;

    struct gensio_ll *ll;
    struct gensio *io;

    gensio_ll_ipmisol_ops ops;
};

static void
iterm_free(struct iterm_data *idata)
{
    if (idata->sio)
	sergensio_data_free(idata->sio);
    idata->o->free(idata->o, idata);
}

static void
iterm_ser_cb(void *handler_data, int op, void *data)
{
    struct iterm_data *idata = handler_data;

    if (op == GENSIO_SOL_LL_FREE) {
	iterm_free(handler_data);
	return;
    }

    gensio_cb(idata->io, op, 0, NULL, NULL, NULL);
}

static int
sergensio_iterm_func(struct sergensio *sio, int op, int val, char *buf,
		     void *done, void *cb_data)
{
    struct iterm_data *idata = sergensio_get_gensio_data(sio);

    return idata->ops(idata->ll, op, val, buf, done, cb_data);
}

int
ipmisol_gensio_alloc(const char *devname, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio **rio)
{
    struct iterm_data *idata;
    int err;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    gensiods max_write_size = GENSIO_DEFAULT_BUF_SIZE;
    int i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "writebuf", &max_write_size) > 0)
	    continue;
	return GE_INVAL;
    }

    idata = o->zalloc(o, sizeof(*idata));
    if (!idata)
	return GE_NOMEM;

    idata->o = o;

    err = ipmisol_gensio_ll_alloc(o, devname, iterm_ser_cb, idata,
				  max_read_size, max_write_size,
				  &idata->ops, &idata->ll);
    if (err)
	goto out_err;

    idata->io = base_gensio_alloc(o, idata->ll, NULL, NULL, "ipmisol", cb,
				  user_data);
    if (!idata->io) {
	gensio_ll_free(idata->ll);
	return GE_NOMEM;
    }

    idata->sio = sergensio_data_alloc(o, idata->io,
				      sergensio_iterm_func, idata);
    if (!idata->sio) {
	gensio_free(idata->io);
	return GE_NOMEM;
    }

    err = gensio_addclass(idata->io, "sergensio", idata->sio);
    if (err) {
	gensio_free(idata->io);
	return err;
    }

    *rio = idata->io;
    return 0;

 out_err:
    iterm_free(idata);
    return err;
}

int
str_to_ipmisol_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio)
{
    return ipmisol_gensio_alloc(str, args, o, cb, user_data, new_gensio);
}
