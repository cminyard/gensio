/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2026  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <gensio/gensio_err.h>

#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "convcode.h"

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_time.h>

/*
 * Holds data for deliver to the upper or lower layer.
 */
struct delivermsg {
    unsigned char *data;
    gensiods pos;
    gensiods len;
    gensiods bitlen;
};

struct convcode_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;

    struct convcode *ce;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    int err;

    /* Data to deliver to the upper layer. */
    gensiods max_read_size;
#define MAX_READ_DELIVER_MSGS 8
    struct delivermsg readmsgs[MAX_READ_DELIVER_MSGS];
    unsigned int num_readmsgs;
    unsigned int curr_readmsg;

    /* Data to deliver to the lower layer. */
    gensiods max_write_size;
#define MAX_WRITE_DELIVER_MSGS 2
    struct delivermsg writemsgs[MAX_WRITE_DELIVER_MSGS];
    unsigned int num_writemsgs;
    unsigned int curr_writemsg;
};

#define filter_to_convcode(v) ((struct convcode_filter *)		\
			       gensio_filter_get_user_data(v))

static void
convcode_lock(struct convcode_filter *sfilter)
{
    sfilter->o->lock(sfilter->lock);
}

static void
convcode_unlock(struct convcode_filter *sfilter)
{
    sfilter->o->unlock(sfilter->lock);
}

static void
convcode_set_callbacks(struct gensio_filter *filter,
		      gensio_filter_cb cb, void *cb_data)
{
    struct convcode_filter *sfilter = filter_to_convcode(filter);

    sfilter->filter_cb = cb;
    sfilter->filter_cb_data = cb_data;
}

static bool
convcode_ul_read_pending(struct gensio_filter *filter)
{
    struct convcode_filter *sfilter = filter_to_convcode(filter);
    bool rv;

    convcode_lock(sfilter);
    rv = sfilter->num_readmsgs > 0;
    convcode_unlock(sfilter);
    return rv;
}

static bool
convcode_ll_write_pending(struct gensio_filter *filter)
{
    struct convcode_filter *sfilter = filter_to_convcode(filter);
    bool rv;

    convcode_lock(sfilter);
    rv = sfilter->num_writemsgs > 0;
    convcode_unlock(sfilter);
    return rv;
}

static bool
convcode_ll_read_needed(struct gensio_filter *filter)
{
    return false;
}

static int
convcode_ul_can_write(struct gensio_filter *filter, bool *val)
{
    struct convcode_filter *sfilter = filter_to_convcode(filter);

    convcode_lock(sfilter);
    *val = sfilter->num_writemsgs < MAX_WRITE_DELIVER_MSGS;
    convcode_unlock(sfilter);

    return 0;
}

static int
convcode_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static int
convcode_try_connect(struct gensio_filter *filter, gensio_time *timeout,
		     bool was_timeout)
{
    return 0;
}

static int
convcode_try_disconnect(struct gensio_filter *filter, gensio_time *timeout,
			bool was_timeout)
{
    return 0;
}

static int
convcode_ul_write(struct gensio_filter *filter,
		  gensio_ul_filter_data_handler handler, void *cb_data,
		  gensiods *rcount,
		  const struct gensio_sg *sg, gensiods sglen,
		  const char *const *auxdata)
{
    struct convcode_filter *sfilter = filter_to_convcode(filter);
    gensiods i, count = 0, pos, len;
    unsigned int cbuf, outbitpos, ndecbits, nbits, nbytes;
    unsigned char *outbuf;
    const char *nbitstr;
    int rv = 0;

    convcode_lock(sfilter);
    if (sfilter->err) {
	rv = sfilter->err;
	goto out;
    }

    if (sfilter->num_writemsgs >= MAX_WRITE_DELIVER_MSGS || sglen == 0)
	goto out_process;

    for (i = 0, count = 0; i < sglen; i++)
	count += sg[i].buflen;

    if (count == 0)
	goto out_process;
    if (count > sfilter->max_write_size) {
	rv = GE_TOOBIG;
	goto out;
    }

    cbuf = ((sfilter->curr_writemsg + sfilter->num_writemsgs)
	    % MAX_WRITE_DELIVER_MSGS);
    outbuf = sfilter->writemsgs[cbuf].data;
    outbitpos = 0;

    nbitstr = gensio_find_auxdata(auxdata, "nbits=");
    if (nbitstr)
	ndecbits = strtoul(nbitstr, NULL, 0);
    else
	ndecbits = count * 8;

    nbits = convcode_encoded_size(ndecbits, sfilter->ce->num_polys,
				  sfilter->ce->k, true, NULL, 0);
    nbytes = CONVCODE_ROUND_UP_BYTE(nbits);
    reinit_convencode(sfilter->ce);
    memset(outbuf, 0, nbytes);

    for (i = 0; i < sglen; i++)
	convencode_block_partial(sfilter->ce, sg[i].buf, sg[i].buflen * 8,
				 &outbuf, &outbitpos);
    convencode_block_final(sfilter->ce, &outbuf, &outbitpos);
    sfilter->writemsgs[cbuf].len = nbytes;
    sfilter->writemsgs[cbuf].bitlen = nbits;
    sfilter->writemsgs[cbuf].pos = 0;
    
    sfilter->num_writemsgs++;

 out_process:
    if (sfilter->num_writemsgs > 0) {
	struct gensio_sg sg;
	char auxbuf[20];
	const char *auxdata[2] = { auxbuf, NULL };

	cbuf = sfilter->curr_writemsg;
	pos = sfilter->writemsgs[cbuf].pos;
	sg.buf = sfilter->writemsgs[cbuf].data + pos;
	sg.buflen = sfilter->writemsgs[cbuf].len - pos;
	snprintf(auxbuf, sizeof(auxbuf), "nbits=%lu",
		 sfilter->writemsgs[cbuf].bitlen);
	rv = handler(cb_data, &len, &sg, 1, auxdata);
	if (rv) {
	    sfilter->err = rv;
	    sfilter->num_writemsgs = 0;
	} else if (len < sg.buflen) {
	    sfilter->writemsgs[cbuf].pos += len;
	    sfilter->writemsgs[cbuf].bitlen -= len * 8;
	} else {
	    sfilter->curr_writemsg = (cbuf + 1) % MAX_WRITE_DELIVER_MSGS;
	    sfilter->num_writemsgs--;
	}
    }
 out:
    convcode_unlock(sfilter);
    if (!rv && rcount)
	*rcount = count;

    return rv;
}

static int
convcode_ll_write(struct gensio_filter *filter,
		  gensio_ll_filter_data_handler handler, void *cb_data,
		  gensiods *rcount,
		  unsigned char *buf, gensiods buflen,
		  const char *const *auxdata)
{
    struct convcode_filter *sfilter = filter_to_convcode(filter);
    unsigned char *uncertainty;
    unsigned int nbits, ndecbits, nbytes, cbuf;
    gensiods count;
    const char *nbitstr;
    struct delivermsg *d;
    int err = 0;

    if (gensio_str_in_auxdata(auxdata, "oob")) {
	/* Ignore oob data. */
	if (rcount)
	    *rcount = buflen;
	return 0;
    }

    convcode_lock(sfilter);
    if (sfilter->err) {
	err = sfilter->err;
	goto out;
    }

    if (sfilter->num_readmsgs >= MAX_READ_DELIVER_MSGS || buflen == 0) {
	buflen = 0; /* Didn't accept any data. */
	goto out_process;
    }

    nbitstr = gensio_find_auxdata(auxdata, "nbits=");

    if (nbitstr) {
	nbits = strtoul(nbitstr, NULL, 0);
    } else {
	if (convcode_encoded_bits_from_encoded_bytes(buflen,
						     sfilter->ce->num_polys,
						     sfilter->ce->k,
						     true, &nbits,
						     NULL, 0))
	    goto out_process;
    }

    if (convcode_decoded_size(nbits, sfilter->ce->num_polys,
			      sfilter->ce->k, true, NULL, 0, &ndecbits))
	goto out_process;
    nbytes = CONVCODE_ROUND_UP_BYTE(ndecbits);
    if (nbytes > sfilter->max_read_size)
	goto out_process;

    uncertainty = gensio_find_auxdata_ptr(auxdata, "uncert=");

    cbuf = ((sfilter->curr_readmsg + sfilter->num_readmsgs)
	    % MAX_READ_DELIVER_MSGS);
    d = &sfilter->readmsgs[cbuf];
    reinit_convdecode(sfilter->ce);
    if (convdecode_block(sfilter->ce, buf, nbits, uncertainty, d->data,
			 NULL, NULL))
	goto out_process;
    d->len = nbytes;
    d->bitlen = ndecbits;
    d->pos = 0;
    sfilter->num_readmsgs++;

 out_process:
    if (sfilter->num_readmsgs > 0) {
	char auxbuf[20];
	const char *auxdata[2] = { auxbuf, NULL };

	cbuf = sfilter->curr_readmsg;
	d = &sfilter->readmsgs[cbuf];
	snprintf(auxbuf, sizeof(auxbuf), "nbits=%lu", d->bitlen);

	convcode_unlock(sfilter);
	err = handler(cb_data, &count,
		      d->data + d->pos,
		      d->len - d->pos,
		      auxdata);
	convcode_lock(sfilter);
	if (!err) {
	    if (count + d->pos >= d->len) {
		d->len = 0;
		sfilter->num_readmsgs--;
		sfilter->curr_readmsg++;
	    } else {
		d->pos += count;
		d->bitlen -= count * 8;
	    }
	}
    }

 out:
    convcode_unlock(sfilter);
    if (!err && rcount)
	*rcount = buflen;
    return err;
}

static int
convcode_setup(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static void
convcode_cleanup(struct gensio_filter *filter)
{
    struct convcode_filter *sfilter = filter_to_convcode(filter);

    sfilter->num_readmsgs = 0;
    sfilter->num_writemsgs = 0;
}

static void
convcode_sfilter_free(struct convcode_filter *sfilter)
{
    struct gensio_os_funcs *o = sfilter->o;
    unsigned int i;

    if (sfilter->lock)
	o->free_lock(sfilter->lock);
    for (i = 0; i < MAX_READ_DELIVER_MSGS; i++) {
	if (sfilter->readmsgs[i].data)
	    o->free(o, sfilter->readmsgs[i].data);
    }
    for (i = 0; i < MAX_WRITE_DELIVER_MSGS; i++) {
	if (sfilter->writemsgs[i].data)
	    o->free(o, sfilter->writemsgs[i].data);
    }
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    if (sfilter->ce)
	free_convcode(sfilter->ce);
    o->free(o, sfilter);
}

static void
convcode_free(struct gensio_filter *filter)
{
    struct convcode_filter *sfilter = filter_to_convcode(filter);

    return convcode_sfilter_free(sfilter);
}

static int
convcode_filter_control(struct gensio_filter *filter, bool get, int op,
		       char *data, gensiods *datalen)
{
    return GE_NOTSUP;
}

static int gensio_convcode_filter_func(struct gensio_filter *filter, int op,
				      void *func, void *data,
				      gensiods *count,
				      void *buf, const void *cbuf,
				      gensiods buflen,
				      const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	convcode_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return convcode_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return convcode_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return convcode_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_UL_CAN_WRITE:
	return convcode_ul_can_write(filter, data);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return convcode_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return convcode_try_connect(filter, data, buflen);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return convcode_try_disconnect(filter, data, buflen);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return convcode_ul_write(filter, func, data, count, cbuf, buflen, buf);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return convcode_ll_write(filter, func, data, count, buf, buflen, NULL);

    case GENSIO_FILTER_FUNC_SETUP:
	return convcode_setup(filter, data);

    case GENSIO_FILTER_FUNC_CLEANUP:
	convcode_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	convcode_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return convcode_filter_control(filter, *((bool *) cbuf), buflen, data,
				  count);

    default:
	return GE_NOTSUP;
    }
}

struct gensio_convcode_data {
    gensiods max_read_size;
    gensiods max_write_size;
    unsigned int num_polys;
    convcode_state polys[CONVCODE_MAX_POLYNOMIALS];
    unsigned int k;
};

static struct gensio_filter *
gensio_convcode_filter_raw_alloc(struct gensio_pparm_info *p,
				 struct gensio_os_funcs *o,
				 struct gensio *child,
				 struct gensio_convcode_data *data)
{
    struct convcode_filter *sfilter;
    unsigned int i, read_deliver_size, write_deliver_size;

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return NULL;

    sfilter->o = o;
    sfilter->max_write_size = data->max_write_size;
    sfilter->max_read_size = data->max_read_size;

    /*
     * Get the number of bits we can get from the lower layer.  This
     * sets the decoder trellis size.
     */
    read_deliver_size = convcode_encoded_size(sfilter->max_read_size * 8,
					      data->num_polys,
					      data->k,
					      true, NULL, 0);

    sfilter->ce = alloc_convcode(o, data->k, data->polys, data->num_polys,
				 read_deliver_size, 0, true, false, false,
				 NULL, 0);

    /* Now the maximum we will deliver to the lower layer, in bits. */
    write_deliver_size = convcode_encoded_size(sfilter->max_write_size * 8,
					       data->num_polys,
					       data->k,
					       true, NULL, 0);
    /* Convert to necessary number of bytes. */
    write_deliver_size = CONVCODE_ROUND_UP_BYTE(write_deliver_size);

    sfilter->lock = o->alloc_lock(o);
    if (!sfilter->lock)
	goto out_nomem;

    for (i = 0; i < MAX_READ_DELIVER_MSGS; i++) {
	sfilter->readmsgs[i].data = o->zalloc(o, sfilter->max_read_size);
	if (!sfilter->readmsgs[i].data)
	    goto out_nomem;
    }

    for (i = 0; i < MAX_WRITE_DELIVER_MSGS; i++) {
	sfilter->writemsgs[i].data = o->zalloc(o, write_deliver_size);
	if (!sfilter->writemsgs[i].data)
	    goto out_nomem;
    }

    sfilter->filter = gensio_filter_alloc_data(o, gensio_convcode_filter_func,
					       sfilter);
    if (!sfilter->filter)
	goto out_nomem;

    return sfilter->filter;

 out_nomem:
    convcode_sfilter_free(sfilter);
    return NULL;
}

static int
gensio_convcode_filter_alloc(struct gensio_pparm_info *p,
			     struct gensio_os_funcs *o,
			     struct gensio *child,
			     const char * const args[],
			     struct gensio_base_parms *parms,
			     struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    struct gensio_convcode_data data = {
	.max_read_size = 256,
	.max_write_size = 256,
    };
    unsigned int i, poly;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_ds(p, args[i], "readbuf", &data.max_read_size) > 0)
	    continue;
	if (gensio_pparm_ds(p, args[i], "writebuf", &data.max_write_size) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "k", &data.k) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "p", &poly) > 0) {
	    if (data.num_polys >= CONVCODE_MAX_POLYNOMIALS) {
		gensio_pparm_log(p, "Too many polynomials, limit is %u\n",
				 CONVCODE_MAX_POLYNOMIALS);
		return GE_INVAL;
	    }
	    data.polys[data.num_polys] = poly;
	    data.num_polys++;
	    continue;
	}
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

    if (data.k < CONVCODE_MIN_K || data.k > CONVCODE_MAX_K) {
	gensio_pparm_log(p, "Invalid or unspecified k, must be between %u and %u\n",
			 CONVCODE_MIN_K, CONVCODE_MAX_K);
	return GE_INVAL;
    }

    filter = gensio_convcode_filter_raw_alloc(p, o, child, &data);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}

static int
convcode_gensio_alloc(struct gensio *child, const char *const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    struct gensio_base_parms *parms = NULL;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "convcode", user_data);

    err = gensio_base_parms_alloc(o, true, "convcode", &parms);
    if (err)
	goto out_err;

    err = gensio_convcode_filter_alloc(&p, o, child, args, parms, &filter);
    if (err)
	goto out_err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	goto out_nomem;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "convcode", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	goto out_nomem;
    }

    err = gensio_base_parms_set(io, &parms);
    if (err) {
	gensio_free(io);
	goto out_err;
    }

    gensio_set_is_packet(io, true);
    gensio_free(child); /* Lose the ref we acquired. */

    *net = io;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
str_to_convcode_gensio(const char *str, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    int err;
    struct gensio *io2;

    /* cb is passed in for parmerr handling, it will be overriden later. */
    err = str_to_gensio(str, o, cb, user_data, &io2);
    if (err)
	return err;

    err = convcode_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

int
gensio_init_convcode(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "convcode",
				str_to_convcode_gensio, convcode_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
