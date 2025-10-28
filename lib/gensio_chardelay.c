/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020-2025  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <assert.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_time.h>

struct chardelay_config {
    gensio_time min_delay;
    gensio_time max_delay;
    gensiods writebuf_len;
    const unsigned char **sendon;
    gensiods *sendon_lens;
    int sendonc;
};

struct chardelay_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct chardelay_config config;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    unsigned char *writebuf;
    gensiods writebuf_pos;

    bool xmit_ready;
    bool firstchar_in;
    bool in_close;
    gensio_time max_end_time;

    gensiods *sendon_pos;
};

#define filter_to_chardelay(v) ((struct chardelay_filter *) \
				gensio_filter_get_user_data(v))

static void
chardelay_lock(struct chardelay_filter *rfilter)
{
    rfilter->o->lock(rfilter->lock);
}

static void
chardelay_unlock(struct chardelay_filter *rfilter)
{
    rfilter->o->unlock(rfilter->lock);
}

static void
chardelay_filter_start_timer(struct chardelay_filter *rfilter)
{
    gensio_time now, end_time, delay;
    struct gensio_os_funcs *o = rfilter->o;

    o->get_monotonic_time(o, &now);

    if (!rfilter->firstchar_in) {
	/*
	 * First character is not in, we calculate a maximum time until
	 * we must send the data no matter what.
	 */
	rfilter->max_end_time = now;
	gensio_time_add(&rfilter->max_end_time, &rfilter->config.max_delay);
	rfilter->firstchar_in = true;
    }

    /*
     * When a character comes in, extend the time until we send the data.
     */
    end_time = now;
    gensio_time_add(&end_time, &rfilter->config.min_delay);

    /*
     * If the maximum end time is < the current delay, use that instead.
     */
    if (gensio_time_cmp(&rfilter->max_end_time, &end_time) < 0)
	end_time = rfilter->max_end_time;

    /*
     * Convert the absolute end time to a relative delay.
     */
    gensio_nsecs_to_time(&delay, gensio_time_diff_nsecs(&end_time, &now));

    rfilter->filter_cb(rfilter->filter_cb_data,
		       GENSIO_FILTER_CB_START_TIMER, &delay);
}

static void
chardelay_set_callbacks(struct chardelay_filter *rfilter,
			gensio_filter_cb cb, void *cb_data)
{
    rfilter->filter_cb = cb;
    rfilter->filter_cb_data = cb_data;
}

static bool
chardelay_ul_read_pending(struct chardelay_filter *rfilter)
{
    return false; /* We don't hold any read data. */
}

static bool
chardelay_ll_write_pending(struct chardelay_filter *rfilter)
{
    return rfilter->xmit_ready && rfilter->writebuf_pos > 0;
}

static int
chardelay_ul_can_write(struct chardelay_filter *rfilter, bool *rv)
{
    *rv = rfilter->writebuf_pos < rfilter->config.writebuf_len;
    return 0;
}

static bool
chardelay_ll_read_needed(struct chardelay_filter *rfilter)
{
    return false;
}

static int
chardelay_check_open_done(struct chardelay_filter *rfilter, struct gensio *io)
{
    return 0;
}

static int
chardelay_try_connect(struct chardelay_filter *rfilter, gensio_time *timeout,
		      bool was_timeout)
{
    return 0;
}

static int
chardelay_try_disconnect(struct chardelay_filter *rfilter, gensio_time *timeout,
			 bool was_timeout)
{
    if (rfilter->writebuf_pos == 0) {
	rfilter->xmit_ready = false;
	return 0;
    }

    /* Flush immediately on close. */
    rfilter->xmit_ready = true;

    rfilter->in_close = true;
    timeout->secs = 0;
    timeout->nsecs = 1000000;
    return GE_RETRY;
}

static int
chardelay_ul_write(struct chardelay_filter *rfilter,
		   gensio_ul_filter_data_handler handler, void *cb_data,
		   gensiods *rcount,
		   const struct gensio_sg *sg, gensiods sglen,
		   const char *const *auxdata)
{
    gensiods i, j, k, count = 0;
    int err = 0;

    chardelay_lock(rfilter);

    /* Copy any data we can into the output buffer. */
    for (i = 0;
	 i < sglen && rfilter->writebuf_pos < rfilter->config.writebuf_len;
	 i++) {
	gensiods len = sg[i].buflen;
	gensiods left = rfilter->config.writebuf_len - rfilter->writebuf_pos;
	const unsigned char *buf = sg[i].buf;

	if (len > left)
	    len = left;

	/*
	 * For each character in the buffer, scan each sendon string.
	 * If the current character matches the sendon's next
	 * character, then advance the sendon's position.  If we hit
	 * the end of a sendon string, we have a match.
	 */
	for (j = 0; j < left; j++) {
	    for (k = 0; k < rfilter->config.sendonc; k++) {
		gensiods pos = rfilter->sendon_pos[k];

		if (rfilter->config.sendon[k][pos] == buf[j]) {
		    rfilter->sendon_pos[k]++;
		    if (rfilter->sendon_pos[k] >=
				rfilter->config.sendon_lens[k]) {
			/* We got a sendon match, send it now. */
			rfilter->xmit_ready = true;
			rfilter->sendon_pos[k] = 0;
		    }
		} else {
		    rfilter->sendon_pos[k] = 0;
		}
	    }
	}

	memcpy(rfilter->writebuf + rfilter->writebuf_pos, buf, len);
	rfilter->writebuf_pos += len;
	count += len;
    }

    /* If the timeout has gone off or the output buffer is full, write it. */
    if (rfilter->xmit_ready ||
		rfilter->writebuf_pos >= rfilter->config.writebuf_len) {
	struct gensio_sg xsg;
	gensiods sent;

	xsg.buf = rfilter->writebuf;
	xsg.buflen = rfilter->writebuf_pos;

	chardelay_unlock(rfilter);
	err = handler(cb_data, &sent, &xsg, 1, auxdata);
	chardelay_lock(rfilter);

	if (sent > 0 && !rfilter->in_close)
	    /* Sent something, restart the timer. */
	    rfilter->xmit_ready = false;
	if (sent >= rfilter->writebuf_pos) {
	    rfilter->writebuf_pos = 0;
	    /* No characters to send now. */
	    rfilter->firstchar_in = false;
	} else {
	    memmove(rfilter->writebuf, rfilter->writebuf + sent,
		    rfilter->writebuf_pos - sent);
	    rfilter->writebuf_pos -= sent;
	}
    }

    rfilter->filter_cb(rfilter->filter_cb_data,
		       GENSIO_FILTER_CB_STOP_TIMER, NULL);

    if (!err && rfilter->writebuf_pos > 0 && !rfilter->in_close)
	chardelay_filter_start_timer(rfilter);

    chardelay_unlock(rfilter);
    if (!err && rcount)
	*rcount = count;
    return err;
}

static int
chardelay_ll_write(struct chardelay_filter *rfilter,
		gensio_ll_filter_data_handler handler, void *cb_data,
		gensiods *rcount,
		unsigned char *buf, gensiods buflen,
		const char *const *auxdata)
{
    return handler(cb_data, rcount, buf, buflen, auxdata);
}

static int
chardelay_setup(struct chardelay_filter *rfilter)
{
    rfilter->xmit_ready = false;
    rfilter->in_close = false;
    return 0;
}

static void
chardelay_filter_cleanup(struct chardelay_filter *rfilter)
{
}

static void
chardelay_free(struct chardelay_filter *rfilter)
{
    struct gensio_os_funcs *o = rfilter->o;

    if (rfilter->config.sendon)
	gensio_bufv_free(o, rfilter->config.sendon,
			 rfilter->config.sendon_lens);
    if (rfilter->sendon_pos)
	o->free(o, rfilter->sendon_pos);
    if (rfilter->lock)
	o->free_lock(rfilter->lock);
    if (rfilter->writebuf)
	o->free(o, rfilter->writebuf);
    if (rfilter->filter)
	gensio_filter_free_data(rfilter->filter);
    o->free(o, rfilter);
}

static int
chardelay_filter_timeout(struct chardelay_filter *rfilter)
{
    chardelay_lock(rfilter);
    rfilter->xmit_ready = true;
    rfilter->filter_cb(rfilter->filter_cb_data,
		       GENSIO_FILTER_CB_OUTPUT_READY, NULL);
    chardelay_unlock(rfilter);
    return 0;
}

static int gensio_chardelay_filter_func(struct gensio_filter *filter, int op,
					void *func, void *data,
					gensiods *count,
					void *buf, const void *cbuf,
					gensiods buflen,
					const char *const *auxdata)
{
    struct chardelay_filter *rfilter = filter_to_chardelay(filter);

    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	chardelay_set_callbacks(rfilter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return chardelay_ul_read_pending(rfilter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return chardelay_ll_write_pending(rfilter);

    case GENSIO_FILTER_FUNC_UL_CAN_WRITE:
	return chardelay_ul_can_write(rfilter, data);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return chardelay_ll_read_needed(rfilter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return chardelay_check_open_done(rfilter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return chardelay_try_connect(rfilter, data, buflen);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return chardelay_try_disconnect(rfilter, data, buflen);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return chardelay_ul_write(rfilter, func, data, count, cbuf, buflen,
			       auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return chardelay_ll_write(rfilter, func, data, count, buf, buflen,
			       auxdata);

    case GENSIO_FILTER_FUNC_SETUP:
	return chardelay_setup(rfilter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	chardelay_filter_cleanup(rfilter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	chardelay_free(rfilter);
	return 0;

    case GENSIO_FILTER_FUNC_TIMEOUT:
	return chardelay_filter_timeout(rfilter);

    default:
	return GE_NOTSUP;
    }
}

static struct gensio_filter *
gensio_chardelay_filter_raw_alloc(struct gensio_os_funcs *o,
				  struct chardelay_config *config)
{
    struct chardelay_filter *rfilter;
    int rv;

    rfilter = o->zalloc(o, sizeof(*rfilter));
    if (!rfilter)
	return NULL;

    rfilter->o = o;
    rfilter->config = *config;

    if (config->sendon) {
	rv = gensio_bufv_copy(o, config->sendon, config->sendon_lens,
			      &rfilter->config.sendonc,
			      &rfilter->config.sendon,
			      &rfilter->config.sendon_lens);
	if (rv)
	    goto out_nomem;
    }

    if (rfilter->config.sendonc > 0) {
	rfilter->sendon_pos = o->zalloc(o, sizeof(*rfilter->sendon_pos) *
					rfilter->config.sendonc);
	if (!rfilter->sendon_pos)
	    goto out_nomem;
    }

    rfilter->writebuf = o->zalloc(o, config->writebuf_len);
    if (!rfilter->writebuf)
	goto out_nomem;

    rfilter->lock = o->alloc_lock(o);
    if (!rfilter->lock)
	goto out_nomem;

    rfilter->filter = gensio_filter_alloc_data(o, gensio_chardelay_filter_func,
					       rfilter);
    if (!rfilter->filter)
	goto out_nomem;

    return rfilter->filter;

 out_nomem:
    chardelay_free(rfilter);
    return NULL;
}

static int
gensio_chardelay_config(struct gensio_pparm_info *p,
			struct gensio_os_funcs *o,
			const char * const args[],
			struct gensio_base_parms *parms,
			struct chardelay_config *config)
{
    gensiods i;
    const unsigned char **sendon;
    gensiods *sendon_lens;
    int sendonc;
    int err;

    gensio_msecs_to_time(&config->min_delay, 1000);
    gensio_msecs_to_time(&config->max_delay, 20);
    config->writebuf_len = GENSIO_DEFAULT_BUF_SIZE;

    err = gensio_get_default_time(o, "chardelay", "min-delay", false,
				  &config->min_delay);
    if (err)
	return err;

    err = gensio_get_default_time(o, "chardelay", "max-delay", false,
				  &config->max_delay);
    if (err)
	return err;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_ds(p, args[i], "writebuf", &config->writebuf_len) > 0)
	    continue;
	if (gensio_pparm_time(p, args[i], "min-delay", 0,
			      &config->min_delay) > 0)
	    continue;
	if (gensio_pparm_time(p, args[i], "max-delay", 0,
			      &config->max_delay) > 0)
	    continue;
	if (gensio_pparm_bufv(p, args[i], "sendon", " ",
			      &sendonc, &sendon, &sendon_lens) > 0) {
	    if (config->sendon)
		gensio_bufv_free(o, config->sendon, config->sendon_lens);
	    config->sendon = sendon;
	    config->sendon_lens = sendon_lens;
	    config->sendonc = sendonc;
	    continue;
	}
	if (gensio_base_parm(parms, p, args[i]) > 0)
	    continue;
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

    if (config->sendon) {
	for (i = 0; i < config->sendonc; i++) {
	    if (config->sendon_lens[i] == 0) {
		gensio_pparm_slog(p, "sendon strings must not be empty");
		goto out_inval;
	    }
	}
    }

    if (config->min_delay.secs == 0 && config->min_delay.nsecs == 0) {
	gensio_pparm_slog(p, "min_delay cannot be zero");
	goto out_inval;
    }
    if (gensio_time_le_zero(config->min_delay)) {
	gensio_pparm_slog(p, "min_delay must be > 0");
	goto out_inval;
    }
    if (gensio_time_le_zero(config->max_delay)) {
	gensio_pparm_slog(p, "max_delay must be > 0");
	goto out_inval;
    }
    if (gensio_time_cmp(&config->min_delay, &config->max_delay) > 0) {
	gensio_pparm_slog(p, "min_delay must be <= max_delay");
	goto out_inval;
    }

    return 0;

 out_inval:
    if (config->sendon)
	gensio_bufv_free(o, config->sendon, config->sendon_lens);
    return GE_INVAL;
}

static int
gensio_chardelay_filter_alloc(struct gensio_os_funcs *o,
			      struct chardelay_config *config,
			      struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;

    filter = gensio_chardelay_filter_raw_alloc(o, config);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}

static int
chardelay_gensio_alloc2(struct gensio *child, const char *const args[],
			struct gensio_os_funcs *o,
			gensio_event cb, void *user_data,
			struct gensio_base_parms **parms,
			struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    struct chardelay_config config;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "chardelay", user_data);

    memset(&config, 0, sizeof(config));

    err = gensio_chardelay_config(&p, o, args, *parms, &config);
    if (err)
	return err;

    err = gensio_chardelay_filter_alloc(o, &config, &filter);
    if (err)
	return err;

    if (config.sendon)
	gensio_bufv_free(o, config.sendon, config.sendon_lens);

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "chardelay", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	return GE_NOMEM;
    }
    gensio_free(child); /* Lose the ref we acquired. */

    err = gensio_base_parms_set(io, parms);
    if (err) {
	gensio_free(io);
	return err;
    }

    *net = io;
    return 0;
}

static int
chardelay_gensio_alloc(struct gensio *child, const char *const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **net)
{
    struct gensio_base_parms *parms;
    int err;

    err = gensio_base_parms_alloc(o, true, "chardelay", &parms);
    if (err)
	return err;

    err = chardelay_gensio_alloc2(child, args, o, cb, user_data, &parms, net);

    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
str_to_chardelay_gensio(const char *str, const char * const args[],
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

    err = chardelay_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct chardelayna_data {
    struct gensio_accepter *acc;
    struct chardelay_config config;
    struct gensio_os_funcs *o;
    gensio_accepter_event cb;
    void *user_data;
};

static void
chardelayna_free(void *acc_data)
{
    struct chardelayna_data *nadata = acc_data;

    if (nadata->config.sendon)
	gensio_bufv_free(nadata->o,
			 nadata->config.sendon, nadata->config.sendon_lens);
    nadata->o->free(nadata->o, nadata);
}

static int
chardelayna_alloc_gensio(void *acc_data, const char * const *iargs,
			 struct gensio *child, struct gensio **rio)
{
    struct chardelayna_data *nadata = acc_data;
    struct gensio_base_parms *parms = NULL;
    int err;

    parms = gensio_acc_base_parms_dup(nadata->acc);
    if (!parms)
	return GE_NOMEM;

    err = chardelay_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);

    if (parms)
	gensio_base_parms_free(&parms);

    return err;
}

static int
chardelayna_new_child(void *acc_data, void **finish_data,
		      struct gensio_filter **filter)
{
    struct chardelayna_data *nadata = acc_data;

    return gensio_chardelay_filter_alloc(nadata->o, &nadata->config, filter);
}

static int
chardelayna_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    struct chardelayna_data *nadata = acc_data;
    int err;

    err = gensio_acc_base_parms_apply(nadata->acc, io);
    if (err)
      return err;

    return 0;
}

static int
gensio_gensio_acc_chardelay_cb(void *acc_data, int op, void *data1, void *data2,
			       void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return chardelayna_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return chardelayna_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return chardelayna_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	chardelayna_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
chardelay_gensio_accepter_alloc(struct gensio_accepter *child,
				const char * const args[],
				struct gensio_os_funcs *o,
				gensio_accepter_event cb, void *user_data,
				struct gensio_accepter **accepter)
{
    struct chardelayna_data *nadata = NULL;
    int err;
    struct gensio_base_parms *parms = NULL;
    GENSIO_DECLARE_PPACCEPTER(p, o, cb, "chardelay", user_data);

    err = gensio_base_parms_alloc(o, true, "chardelay", &parms);
    if (err)
	goto out_err;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	goto out_nomem;

    err = gensio_chardelay_config(&p, o, args, parms, &nadata->config);
    if (err)
	goto out_err;

    nadata->o = o;
    nadata->cb = cb;
    nadata->user_data = user_data;

    err = gensio_gensio_accepter_alloc(child, o, "chardelay", cb, user_data,
				       gensio_gensio_acc_chardelay_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;
    *accepter = nadata->acc;

    err = gensio_acc_base_parms_set(nadata->acc, &parms);
    if (err)
	goto out_err;

    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (nadata) {
	if (nadata->acc)
	    gensio_acc_free(nadata->acc);
	else
	    chardelayna_free(nadata);
    }
    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
str_to_chardelay_gensio_accepter(const char *str, const char * const args[],
				 struct gensio_os_funcs *o,
				 gensio_accepter_event cb,
				 void *user_data,
				 struct gensio_accepter **acc)
{
    int err;
    struct gensio_accepter *acc2 = NULL;

    /* cb is passed in for parmerr handling, it will be overriden later. */
    err = str_to_gensio_accepter(str, o, cb, user_data, &acc2);
    if (!err) {
	err = chardelay_gensio_accepter_alloc(acc2, args, o, cb, user_data,
					      acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_chardelay(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "chardelay",
				str_to_chardelay_gensio,
				chardelay_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "chardelay",
					 str_to_chardelay_gensio_accepter,
					 chardelay_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
