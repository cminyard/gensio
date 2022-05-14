/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <gensio/sergensio_class.h>

#include "utils.h"

struct sergensio {
    struct gensio_os_funcs *o;

    struct gensio *io;

    sergensio_func func;

    void *gensio_data;

    struct gensio_lock *lock;

    bool autofree;
};

struct gensio *
sergensio_to_gensio(struct sergensio *sio)
{
    return sio->io;
}

struct sergensio *
gensio_to_sergensio(struct gensio *io)
{
    return gensio_getclass(io, "sergensio");
}

struct sergensio *
sergensio_data_alloc(struct gensio_os_funcs *o, struct gensio *io,
		     sergensio_func func, void *gensio_data)
{
    struct sergensio *sio = o->zalloc(o, sizeof(*sio));

    if (!sio)
	return NULL;

    sio->lock = o->alloc_lock(o);
    if (!sio->lock) {
	o->free(o, sio);
	return NULL;
    }
    sio->o = o;
    sio->io = io;
    sio->func = func;
    sio->gensio_data = gensio_data;
    return sio;
}

void
sergensio_data_free(struct sergensio *sio)
{
    sio->o->free_lock(sio->lock);
    sio->o->free(sio->o, sio);
}

static int sergensio_prop_func(struct sergensio *sio, int op, int val,
			       char *buf, void *done, void *cb_data)
{
    struct sergensio *child_sio = sergensio_get_gensio_data(sio);

    return child_sio->func(child_sio, op, val, buf, done, cb_data);
}

static int
sergensio_prop_class(struct gensio *parent, struct gensio *child,
		     void *classdata)
{
    struct sergensio *sio, *child_sio = classdata;
    int rv;

    rv = sergensio_addclass(child_sio->o, parent, sergensio_prop_func,
			    child_sio, &sio);
    if (rv)
	return rv;
    sio->autofree = true;
    return 0;
}

static void sergensio_prop_cleanup(struct gensio *io, void *classdata)
{
    struct sergensio *sio = classdata;

    if (sio->autofree)
	sergensio_data_free(sio);
}

static struct gensio_classops sergensio_classops = {
    sergensio_prop_class,
    sergensio_prop_cleanup
};

int
sergensio_addclass(struct gensio_os_funcs *o, struct gensio *io,
		   sergensio_func func, void *gensio_data,
		   struct sergensio **rsio)
{
    struct sergensio *sio;
    int rv;

    sio = sergensio_data_alloc(o, io, func, gensio_data);
    if (!sio)
	return GE_NOMEM;
    rv = gensio_addclass(io, "sergensio", GENSIO_CLASSOPS_VERSION,
			 &sergensio_classops, sio);
    if (rv)
	sergensio_data_free(sio);
    else if (rsio)
	*rsio = sio;
    return rv;
}

void *
sergensio_get_gensio_data(struct sergensio *sio)
{
    return sio->gensio_data;
}

struct gensio *
sergensio_get_my_gensio(struct sergensio *sio)
{
    return sio->io;
}

/*
 * Because sergensio classes can stack, we have to catch each call and
 * coming back up the stack to pass in the right sergensio structure.
 */
struct sergensio_done_data {
    struct sergensio *sio;
    sergensio_done done;
    void *cb_data;
};

static void
sg_done(struct sergensio *sio, int err, unsigned int val, void *cb_data)
{
    struct sergensio_done_data *d = cb_data;

    d->done(d->sio, err, val, d->cb_data);
    d->sio->o->free(d->sio->o, d);
}

static int
setup_sergensio_done(struct sergensio *sio, sergensio_done *done,
		     void **cb_data)
{
    struct sergensio_done_data *d;
    struct gensio_os_funcs *o = sio->o;

    if (!*done)
	return 0;

    d = o->zalloc(o, sizeof(*d));
    if (!d)
	return GE_NOMEM;
    d->sio = sio;
    d->done = *done;
    d->cb_data = *cb_data;
    *done = sg_done;
    *cb_data = d;

    return 0;
}

static int
finish_sergensio_done(struct sergensio *sio, sergensio_done done,
		      void *cb_data, int rv)
{
    if (rv && done) {
	struct gensio_os_funcs *o = sio->o;

	o->free(o, cb_data);
    }
    return rv;
}

int
sergensio_baud(struct sergensio *sio, unsigned int baud,
	       sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_BAUD, baud, NULL, done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_datasize(struct sergensio *sio, unsigned int datasize,
		   sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_DATASIZE, datasize, NULL,
		   done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_parity(struct sergensio *sio, unsigned int parity,
		 sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_PARITY, parity, NULL, done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_stopbits(struct sergensio *sio, unsigned int stopbits,
		   sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_STOPBITS, stopbits, NULL,
		   done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_flowcontrol(struct sergensio *sio, unsigned int flowcontrol,
		      sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_FLOWCONTROL, flowcontrol, NULL,
		   done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_iflowcontrol(struct sergensio *sio, unsigned int iflowcontrol,
		       sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_IFLOWCONTROL, iflowcontrol, NULL,
		   done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_sbreak(struct sergensio *sio, unsigned int breakv,
		 sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_SBREAK, breakv, NULL,
		   done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_dtr(struct sergensio *sio, unsigned int dtr,
	      sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_DTR, dtr, NULL, done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_rts(struct sergensio *sio, unsigned int rts,
	      sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_RTS, rts, NULL, done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_cts(struct sergensio *sio, unsigned int cts,
	      sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_CTS, cts, NULL, done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_dcd_dsr(struct sergensio *sio, unsigned int dcd_dsr,
	      sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_DCD_DSR, dcd_dsr, NULL, done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

int
sergensio_ri(struct sergensio *sio, unsigned int ri,
	     sergensio_done done, void *cb_data)
{
    int rv = setup_sergensio_done(sio, &done, &cb_data);
    if (rv)
	return rv;
    rv = sio->func(sio, SERGENSIO_FUNC_RI, ri, NULL, done, cb_data);
    return finish_sergensio_done(sio, done, cb_data, rv);
}

struct sergensio_done_sig_data {
    struct sergensio *sio;
    sergensio_done_sig done;
    void *cb_data;
};

static void
sg_done_sig(struct sergensio *sio, int err, const char *sig, unsigned int len,
	    void *cb_data)
{
    struct sergensio_done_sig_data *d = cb_data;

    d->done(d->sio, err, sig, len, d->cb_data);
    d->sio->o->free(d->sio->o, d);
}

int
sergensio_signature(struct sergensio *sio, const char *sig, unsigned int len,
		    sergensio_done_sig done, void *cb_data)
{
    struct sergensio_done_sig_data *d = NULL;
    struct gensio_os_funcs *o = sio->o;
    int rv;

    if (done) {
	d = o->zalloc(o, sizeof(*d));
	if (!d)
	    return GE_NOMEM;
	d->sio = sio;
	d->done = done;
	d->cb_data = cb_data;
	done = sg_done_sig;
	cb_data = d;
    }
    rv = sio->func(sio, SERGENSIO_FUNC_SIGNATURE, len, (char *) sig,
		   done, cb_data);
    if (d && rv) {
	o->free(o, cb_data);
    }
    return rv;
}

int
sergensio_modemstate(struct sergensio *sio, unsigned int val)
{
    return sio->func(sio, SERGENSIO_FUNC_MODEMSTATE, val, NULL, NULL, NULL);
}

int
sergensio_linestate(struct sergensio *sio, unsigned int val)
{
    return sio->func(sio, SERGENSIO_FUNC_LINESTATE, val, NULL, NULL, NULL);
}

int
sergensio_flowcontrol_state(struct sergensio *sio, bool val)
{
    return sio->func(sio, SERGENSIO_FUNC_FLOWCONTROL_STATE, val,
		     NULL, NULL, NULL);
}

int
sergensio_flush(struct sergensio *sio, unsigned int val)
{
    return sio->func(sio, SERGENSIO_FUNC_FLUSH, val, NULL, NULL, NULL);
}

int
sergensio_send_break(struct sergensio *sio)
{
    return sio->func(sio, SERGENSIO_FUNC_SEND_BREAK, 0, NULL, NULL, NULL);
}

bool
sergensio_is_client(struct sergensio *sio)
{
    struct gensio *io = sergensio_get_my_gensio(sio);

    return gensio_is_client(io);
}

void *
sergensio_get_user_data(struct sergensio *sio)
{
    return gensio_get_user_data(sio->io);
}

struct sergensio_b {
    struct sergensio *sio;
    struct gensio_os_funcs *o;
};

struct sergensio_b_data {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    int err;
    unsigned int val;
};

int
sergensio_b_alloc(struct sergensio *sio, struct gensio_os_funcs *o,
		  struct sergensio_b **new_sbio)
{
    struct sergensio_b *sbio = malloc(sizeof(*sbio));

    if (!sbio)
	return GE_NOMEM;

    sbio->sio = sio;
    sbio->o = o;
    *new_sbio = sbio;

    return 0;
}

void sergensio_b_free(struct sergensio_b *sbio)
{
    free(sbio);
}

static void sergensio_op_done(struct sergensio *sio, int err,
			      unsigned int val, void *cb_data)
{
    struct sergensio_b_data *data = cb_data;

    data->err = err;
    data->val = val;
    data->o->wake(data->waiter);
}

int
sergensio_baud_b_timeout(struct sergensio_b *sbio, int *baud,
			 gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_baud(sbio->sio, *baud, sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*baud = data.val;

    return err;
}

int
sergensio_baud_b(struct sergensio_b *sbio, int *baud)
{
    return sergensio_baud_b_timeout(sbio, baud, NULL);
}

int
sergensio_datasize_b_timeout(struct sergensio_b *sbio, int *datasize,
			     gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_datasize(sbio->sio, *datasize, sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*datasize = data.val;

    return err;
}

int
sergensio_datasize_b(struct sergensio_b *sbio, int *datasize)
{
    return sergensio_datasize_b_timeout(sbio, datasize, NULL);
}

int
sergensio_parity_b_timeout(struct sergensio_b *sbio, int *parity,
			   gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_parity(sbio->sio, *parity, sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*parity = data.val;

    return err;
}

int
sergensio_parity_b(struct sergensio_b *sbio, int *parity)
{
    return sergensio_parity_b_timeout(sbio, parity, NULL);
}

int
sergensio_stopbits_b_timeout(struct sergensio_b *sbio, int *stopbits,
			     gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_stopbits(sbio->sio, *stopbits, sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*stopbits = data.val;

    return err;
}

int
sergensio_stopbits_b(struct sergensio_b *sbio, int *stopbits)
{
    return sergensio_stopbits_b_timeout(sbio, stopbits, NULL);
}

int
sergensio_flowcontrol_b_timeout(struct sergensio_b *sbio, int *flowcontrol,
				gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_flowcontrol(sbio->sio, *flowcontrol,
				sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*flowcontrol = data.val;

    return err;
}

int
sergensio_flowcontrol_b(struct sergensio_b *sbio, int *flowcontrol)
{
    return sergensio_flowcontrol_b_timeout(sbio, flowcontrol, NULL);
}

int
sergensio_iflowcontrol_b_timeout(struct sergensio_b *sbio, int *iflowcontrol,
				 gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_iflowcontrol(sbio->sio, *iflowcontrol, sergensio_op_done,
				 &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*iflowcontrol = data.val;

    return err;
}

int
sergensio_iflowcontrol_b(struct sergensio_b *sbio, int *iflowcontrol)
{
    return sergensio_iflowcontrol_b_timeout(sbio, iflowcontrol, NULL);
}

int
sergensio_sbreak_b_timeout(struct sergensio_b *sbio, int *breakv,
			   gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_sbreak(sbio->sio, *breakv, sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*breakv = data.val;

    return err;
}

int
sergensio_sbreak_b(struct sergensio_b *sbio, int *breakv)
{
    return sergensio_sbreak_b_timeout(sbio, breakv, NULL);
}

int
sergensio_dtr_b_timeout(struct sergensio_b *sbio, int *dtr,
			gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_dtr(sbio->sio, *dtr, sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*dtr = data.val;

    return err;
}

int
sergensio_dtr_b(struct sergensio_b *sbio, int *dtr)
{
    return sergensio_dtr_b_timeout(sbio, dtr, NULL);
}

int
sergensio_rts_b_timeout(struct sergensio_b *sbio, int *rts,
			gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_rts(sbio->sio, *rts, sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*rts = data.val;

    return err;
}

int
sergensio_rts_b(struct sergensio_b *sbio, int *rts)
{
    return sergensio_rts_b_timeout(sbio, rts, NULL);
}

int
sergensio_cts_b_timeout(struct sergensio_b *sbio, int *cts,
			gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_cts(sbio->sio, *cts, sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*cts = data.val;

    return err;
}

int
sergensio_cts_b(struct sergensio_b *sbio, int *cts)
{
    return sergensio_cts_b_timeout(sbio, cts, NULL);
}

int
sergensio_dcd_dsr_b_timeout(struct sergensio_b *sbio, int *dcd_dsr,
			    gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_dcd_dsr(sbio->sio, *dcd_dsr, sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*dcd_dsr = data.val;

    return err;
}

int
sergensio_dcd_dsr_b(struct sergensio_b *sbio, int *dcd_dsr)
{
    return sergensio_dcd_dsr_b_timeout(sbio, dcd_dsr, NULL);
}

int
sergensio_ri_b_timeout(struct sergensio_b *sbio, int *ri,
		       gensio_time *timeout)
{
    struct sergensio_b_data data;
    int err;

    data.waiter = sbio->o->alloc_waiter(sbio->o);
    if (!data.waiter)
	return GE_NOMEM;

    data.err = 0;
    data.o = sbio->o;
    err = sergensio_ri(sbio->sio, *ri, sergensio_op_done, &data);
    if (!err)
	err = sbio->o->wait(data.waiter, 1, timeout);
    sbio->o->free_waiter(data.waiter);
    if (!err)
	err = data.err;
    if (!err)
	*ri = data.val;

    return err;
}

int
sergensio_ri_b(struct sergensio_b *sbio, int *ri)
{
    return sergensio_ri_b_timeout(sbio, ri, NULL);
}

struct sergensio_accepter {
    struct gensio_os_funcs *o;

    struct gensio_accepter *acc;

    sergensio_acc_func func;

    void *gensio_data;

    struct gensio_lock *lock;

    struct gensio_accepter *assoc_acc;

    bool autofree;
};

struct gensio_accepter *
sergensio_acc_to_gensio_acc(struct sergensio_accepter *sacc)
{
    return sacc->assoc_acc;
}

struct sergensio_accepter *
gensio_acc_to_sergensio_acc(struct gensio_accepter *acc)
{
    struct sergensio_accepter *rv;

    rv = gensio_acc_getclass(acc, "sergensio");
    if (rv) {
	rv->o->lock(rv->lock);
	if (!rv->assoc_acc)
	    rv->assoc_acc = acc;
	else
	    assert(rv->assoc_acc == acc);
	rv->o->unlock(rv->lock);
    }
    return rv;
}

struct sergensio_accepter *
sergensio_acc_data_alloc(struct gensio_os_funcs *o, struct gensio_accepter *acc,
			 sergensio_acc_func func, void *gensio_data)
{
    struct sergensio_accepter *sacc = o->zalloc(o, sizeof(*sacc));

    if (!sacc)
	return NULL;

    sacc->lock = o->alloc_lock(o);
    if (!sacc->lock) {
	o->free(o, sacc);
	return NULL;
    }
    sacc->o = o;
    sacc->acc = acc;
    sacc->func = func;
    sacc->gensio_data = gensio_data;

    return sacc;
}

void
sergensio_acc_data_free(struct sergensio_accepter *sacc)
{
    sacc->o->free_lock(sacc->lock);
    sacc->o->free(sacc->o, sacc);
}

static int sergensio_acc_prop_func(struct sergensio_accepter *sio,
				   int op, int val,
				   char *buf, void *done, void *cb_data)
{
    struct sergensio_accepter *child_sio = sio->gensio_data;

    return child_sio->func(child_sio, op, val, buf, done, cb_data);
}

static int
sergensio_acc_prop_class(struct gensio_accepter *parent,
			 struct gensio_accepter *child,
			 void *classdata)
{
    struct sergensio_accepter *sio, *child_sio = classdata;
    int rv;

    rv = sergensio_acc_addclass(child_sio->o, parent, sergensio_acc_prop_func,
				child_sio, &sio);
    if (rv)
	return rv;
    sio->autofree = true;
    return 0;
}

static void sergensio_acc_prop_cleanup(struct gensio_accepter *acc,
				       void *classdata)
{
    struct sergensio_accepter *sio = classdata;

    if (sio->autofree)
	sergensio_acc_data_free(sio);
}

static struct gensio_acc_classops sergensio_acc_classops = {
    sergensio_acc_prop_class,
    sergensio_acc_prop_cleanup,
};

int
sergensio_acc_addclass(struct gensio_os_funcs *o, struct gensio_accepter *acc,
		       sergensio_acc_func func, void *gensio_data,
		       struct sergensio_accepter **rsacc)
{
    struct sergensio_accepter *sacc;
    int rv;

    sacc = sergensio_acc_data_alloc(o, acc, func, gensio_data);
    if (!sacc)
	return GE_NOMEM;
    rv = gensio_acc_addclass(acc, "sergensio", GENSIO_ACC_CLASSOPS_VERSION,
			     &sergensio_acc_classops, sacc);
    if (rv)
	sergensio_acc_data_free(sacc);
    else if (rsacc)
	*rsacc = sacc;
    return rv;
}
