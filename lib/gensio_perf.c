/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018-2025  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <stdio.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/argvutils.h>

struct perf_filter {
    struct gensio_filter *filter;
    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    /* Data waiting to be delivered to the lower layer. */
    unsigned char *write_data;
    gensiods writebuf_size;
    gensiods write_len;
    gensiods write_data_left;

    gensiods read_count;
    gensiods expect_len;
    gensiods orig_expect_len;

    struct gensio_time start_time;
    bool read_end_time_set;
    struct gensio_time read_end_time;
    bool write_end_time_set;
    struct gensio_time write_end_time;
    unsigned int timeouts_since_print;
    gensiods read_since_last_timeout;
    gensiods write_since_last_timeout;

    gensiods print_pending;
    gensiods print_pos;
    char print_buffer[1024];
    bool final_started;
};

#define filter_to_perf(v) ((struct perf_filter *) \
			   gensio_filter_get_user_data(v))

static void
perf_lock(struct perf_filter *pfilter)
{
    pfilter->o->lock(pfilter->lock);
}

static void
perf_unlock(struct perf_filter *pfilter)
{
    pfilter->o->unlock(pfilter->lock);
}

static bool
perf_ul_read_pending(struct gensio_filter *filter)
{
    struct perf_filter *pfilter = filter_to_perf(filter);

    return pfilter->print_pending;
}

static bool
perf_ll_write_pending(struct gensio_filter *filter)
{
    struct perf_filter *pfilter = filter_to_perf(filter);

    /*
     * Always return true if we are supplying data.  We want it to
     * supply data and then return a GE_REMCLOSE when out of data.
     * But we want to get our data out to the lower layer before
     * reporting that.
     */
    return (pfilter->write_len > 0 &&
	    !(pfilter->final_started &&
	      (pfilter->print_pending > 0 || pfilter->expect_len > 0))) ||
	    (pfilter->orig_expect_len && pfilter->expect_len == 0 &&
	     pfilter->print_pending == 0);
}

static bool
perf_ll_read_needed(struct gensio_filter *filter)
{
    return false;
}

static void
perf_filter_start_timer(struct perf_filter *pfilter)
{
    gensio_time timeout = { 1, 0 };

    pfilter->filter_cb(pfilter->filter_cb_data,
		       GENSIO_FILTER_CB_START_TIMER, &timeout);
}

static void
perf_set_callbacks(struct gensio_filter *filter,
		   gensio_filter_cb cb, void *cb_data)
{
    struct perf_filter *pfilter = filter_to_perf(filter);

    pfilter->filter_cb = cb;
    pfilter->filter_cb_data = cb_data;
}

static int
perf_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    struct perf_filter *pfilter = filter_to_perf(filter);

    perf_filter_start_timer(pfilter);
    pfilter->o->get_monotonic_time(pfilter->o, &pfilter->start_time);
    return 0;
}

static int
perf_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

static void
set_read_end_time(struct perf_filter *pfilter)
{
    if (!pfilter->read_end_time_set) {
	pfilter->o->get_monotonic_time(pfilter->o, &pfilter->read_end_time);
	pfilter->read_end_time_set = true;
    }
}

static void
set_write_end_time(struct perf_filter *pfilter)
{
    if (!pfilter->write_end_time_set) {
	pfilter->o->get_monotonic_time(pfilter->o, &pfilter->write_end_time);
	pfilter->write_end_time_set = true;
    }
}

static int
perf_handle_end_check(struct perf_filter *pfilter)
{
    if (pfilter->final_started && pfilter->print_pending == 0)
	return 0;

    set_read_end_time(pfilter);
    set_write_end_time(pfilter);

    if (!pfilter->final_started && pfilter->print_pending == 0) {
	gensiods write_count;
	double total_read_time;
	double total_write_time;

	pfilter->read_end_time.secs -= pfilter->start_time.secs;
	pfilter->read_end_time.nsecs -= pfilter->start_time.nsecs;
	while (pfilter->read_end_time.nsecs < 0) {
	    pfilter->read_end_time.nsecs += 1000000000;
	    pfilter->read_end_time.secs -= 1;
	}

	pfilter->write_end_time.secs -= pfilter->start_time.secs;
	pfilter->write_end_time.nsecs -= pfilter->start_time.nsecs;
	while (pfilter->write_end_time.nsecs < 0) {
	    pfilter->write_end_time.nsecs += 1000000000;
	    pfilter->write_end_time.secs -= 1;
	}

	write_count = pfilter->write_len - pfilter->write_data_left;
	total_read_time = ((double) pfilter->read_end_time.secs +
			   ((double) pfilter->read_end_time.nsecs /
			    1000000000.0));
	total_write_time = ((double) pfilter->write_end_time.secs +
			   ((double) pfilter->write_end_time.nsecs /
			    1000000000.0));

	/* Flip read and write, this is from the user's perspective. */
	pfilter->print_pending = snprintf(pfilter->print_buffer,
			  sizeof(pfilter->print_buffer),
			  "TOTAL: Wrote %ld in %llu.%3.3u seconds\n"
			  "         %lf write bytes/sec\n"
			  "       Read %ld in %llu.%3.3u seconds\n"
			  "         %lf read bytes/sec\n",
			  write_count,
			  (unsigned long long) pfilter->write_end_time.secs,
			  (pfilter->write_end_time.nsecs + 500000) / 1000000,
			  (double) write_count / total_write_time,
			  pfilter->read_count,
			  (unsigned long long) pfilter->read_end_time.secs,
			  (pfilter->read_end_time.nsecs + 500000) / 1000000,
			  (double) pfilter->read_count / total_read_time);
	pfilter->final_started = true;
	pfilter->print_pos = 0;
    }
    return GE_INPROGRESS;
}

static int
perf_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

static int
perf_ul_write(struct gensio_filter *filter,
	      gensio_ul_filter_data_handler handler, void *cb_data,
	      gensiods *rcount,
	      const struct gensio_sg *isg, gensiods sglen,
	      const char *const *auxdata)
{
    struct perf_filter *pfilter = filter_to_perf(filter);
    int err = 0;
    gensiods i, writelen = 0;

    /* Just ignore data from the upper layer. */
    for (i = 0; i < sglen; i++)
	writelen += isg[i].buflen;
    if (rcount)
	*rcount = writelen;

    perf_lock(pfilter);
    if (pfilter->write_data_left > 0) {
	gensiods count = pfilter->write_data_left, ocount;
	struct gensio_sg sg = { pfilter->write_data, 0 };

	if (count > pfilter->writebuf_size)
	    count = pfilter->writebuf_size;
	sg.buflen = count;
	ocount = count;

	perf_unlock(pfilter);
	err = handler(cb_data, &count, &sg, 1, NULL);
	perf_lock(pfilter);
	if (!err) {
	    if (count > ocount)
		count = ocount;

	    pfilter->write_since_last_timeout += count;
	    pfilter->write_data_left -= count;
	    if (pfilter->write_data_left == 0)
		set_write_end_time(pfilter);
	}
    } else if (pfilter->write_len || pfilter->orig_expect_len) {
	if (!pfilter->final_started && pfilter->expect_len == 0)
	    /* We were supplying data and we are out of data. */
	    perf_handle_end_check(pfilter);
	else if (pfilter->final_started && pfilter->print_pending == 0)
	    err = GE_REMCLOSE;
    }

    perf_unlock(pfilter);

    return err;
}

static int
perf_ll_write(struct gensio_filter *filter,
	      gensio_ll_filter_data_handler handler, void *cb_data,
	      gensiods *rcount,
	      unsigned char *buf, gensiods buflen,
	      const char *const *auxdata)
{
    struct perf_filter *pfilter = filter_to_perf(filter);
    int err = 0;

    if (rcount)
	*rcount = buflen; /* Ignore data from below. */

    perf_lock(pfilter);
    pfilter->read_count += buflen;
    pfilter->read_since_last_timeout += buflen;
    if (buflen > pfilter->expect_len)
	pfilter->expect_len = 0;
    else
	pfilter->expect_len -= buflen;

    if (pfilter->orig_expect_len && pfilter->expect_len == 0)
	set_read_end_time(pfilter);

    if (pfilter->print_pending) {
	gensiods count = pfilter->print_pending - pfilter->print_pos;

	perf_unlock(pfilter);
	err = handler(cb_data, &count,
	      (unsigned char *) pfilter->print_buffer + pfilter->print_pos,
	      count, NULL);
	perf_lock(pfilter);
	if (!err) {
	    if (count > pfilter->print_pending - pfilter->print_pos)
		count = pfilter->print_pending - pfilter->print_pos;
	    pfilter->print_pos += count;
	    if (pfilter->print_pos == pfilter->print_pending)
		pfilter->print_pending = 0;
	}
    }
    perf_unlock(pfilter);

    return err;
}

static int
perf_filter_timeout(struct gensio_filter *filter)
{
    struct perf_filter *pfilter = filter_to_perf(filter);

    perf_lock(pfilter);
    pfilter->timeouts_since_print++;
    if (!pfilter->print_pending) {
	pfilter->print_pending = snprintf(pfilter->print_buffer,
			  sizeof(pfilter->print_buffer),
			  "Wrote %ld, Read %ld in %u second%s\n",
			  pfilter->write_since_last_timeout,
			  pfilter->read_since_last_timeout,
			  pfilter->timeouts_since_print,
			  pfilter->timeouts_since_print == 1 ? "" : "s");
	pfilter->write_since_last_timeout = 0;
	pfilter->read_since_last_timeout = 0;
	pfilter->timeouts_since_print = 0;
	pfilter->print_pos = 0;
    }
    perf_filter_start_timer(pfilter);
    perf_unlock(pfilter);

    return 0;
}

static void
perf_filter_io_err(struct gensio_filter *filter, int err)
{
    struct perf_filter *pfilter = filter_to_perf(filter);

    perf_lock(pfilter);
    perf_handle_end_check(pfilter);
    perf_unlock(pfilter);
}

static int
perf_setup(struct gensio_filter *filter)
{
    return 0;
}

static void
perf_filter_cleanup(struct gensio_filter *filter)
{
    struct perf_filter *pfilter = filter_to_perf(filter);

    pfilter->write_data_left = pfilter->write_len;
    pfilter->expect_len = pfilter->orig_expect_len;
    pfilter->read_count = 0;
    pfilter->read_end_time_set = false;
    pfilter->write_end_time_set = false;
    pfilter->read_since_last_timeout = 0;
    pfilter->write_since_last_timeout = 0;
    pfilter->timeouts_since_print = 0;
    pfilter->print_pending = 0;
    pfilter->final_started = false;
}

static void
pfilter_free(struct perf_filter *pfilter)
{
    if (pfilter->lock)
	pfilter->o->free_lock(pfilter->lock);
    if (pfilter->write_data)
	pfilter->o->free(pfilter->o, pfilter->write_data);
    if (pfilter->filter)
	gensio_filter_free_data(pfilter->filter);
    pfilter->o->free(pfilter->o, pfilter);
}

static void
perf_free(struct gensio_filter *filter)
{
    struct perf_filter *pfilter = filter_to_perf(filter);

    pfilter_free(pfilter);
}

static int gensio_perf_filter_func(struct gensio_filter *filter, int op,
				   void *func, void *data,
				   gensiods *count,
				   void *buf, const void *cbuf,
				   gensiods buflen,
				   const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	perf_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return perf_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return perf_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return perf_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return perf_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return perf_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return perf_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return perf_ul_write(filter, func, data, count, cbuf, buflen, auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return perf_ll_write(filter, func, data, count, buf, buflen, auxdata);

    case GENSIO_FILTER_FUNC_TIMEOUT:
	return perf_filter_timeout(filter);

    case GENSIO_FILTER_FUNC_SETUP:
	return perf_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	perf_filter_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_IO_ERR:
	perf_filter_io_err(filter, *((int *) data));
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	perf_free(filter);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static struct gensio_filter *
gensio_perf_filter_raw_alloc(struct gensio_os_funcs *o,
			     gensiods writebuf_size, gensiods write_len,
			     gensiods expect_len)
{
    struct perf_filter *pfilter;

    pfilter = o->zalloc(o, sizeof(*pfilter));
    if (!pfilter)
	return NULL;

    pfilter->o = o;
    pfilter->writebuf_size = writebuf_size;
    pfilter->write_len = write_len;
    pfilter->write_data_left = write_len;
    pfilter->expect_len = expect_len;
    pfilter->orig_expect_len = expect_len;

    pfilter->lock = o->alloc_lock(o);
    if (!pfilter->lock)
	goto out_nomem;

    pfilter->write_data = o->zalloc(o, writebuf_size);
    if (!pfilter->write_data)
	goto out_nomem;

    pfilter->filter = gensio_filter_alloc_data(o, gensio_perf_filter_func,
					       pfilter);
    if (!pfilter->filter)
	goto out_nomem;

    return pfilter->filter;

 out_nomem:
    pfilter_free(pfilter);
    return NULL;
}

static int
gensio_perf_filter_alloc(struct gensio_pparm_info *p,
			 struct gensio_os_funcs *o,
			 const char * const args[],
			 struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    gensiods writebuf_size = 1024;
    gensiods write_len = 0;
    gensiods expect_len = 0;
    unsigned int i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_ds(p, args[i], "writebuf", &writebuf_size) > 0)
	    continue;
	if (gensio_pparm_ds(p, args[i], "write_len", &write_len) > 0)
	    continue;
	if (gensio_pparm_ds(p, args[i], "expect_len", &expect_len) > 0)
	    continue;
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

    filter = gensio_perf_filter_raw_alloc(o, writebuf_size, write_len,
					  expect_len);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}

static int
perf_gensio_alloc(struct gensio *child, const char *const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "perf", user_data);

    err = gensio_perf_filter_alloc(&p, o, args, &filter);
    if (err)
	return err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "perf", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	return GE_NOMEM;
    }

    gensio_set_is_reliable(io, gensio_is_reliable(child));
    gensio_set_is_packet(io, gensio_is_packet(child));
    gensio_set_is_authenticated(io, gensio_is_authenticated(child));
    gensio_set_is_encrypted(io, gensio_is_encrypted(child));
    gensio_set_is_message(io, gensio_is_message(child));

    gensio_free(child); /* Lose the ref we acquired. */

    *net = io;
    return 0;
}

static int
str_to_perf_gensio(const char *str, const char * const args[],
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

    err = perf_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct perfna_data {
    struct gensio_accepter *acc;
    const char **args;
    struct gensio_os_funcs *o;
    gensio_accepter_event cb;
    void *user_data;
};

static void
perfna_free(void *acc_data)
{
    struct perfna_data *nadata = acc_data;

    if (nadata->args)
	gensio_argv_free(nadata->o, nadata->args);
    nadata->o->free(nadata->o, nadata);
}

static int
perfna_alloc_gensio(void *acc_data, const char * const *iargs,
		     struct gensio *child, struct gensio **rio)
{
    struct perfna_data *nadata = acc_data;

    return perf_gensio_alloc(child, iargs, nadata->o, NULL, NULL, rio);
}

static int
perfna_new_child(void *acc_data, void **finish_data,
		  struct gensio_filter **filter)
{
    struct perfna_data *nadata = acc_data;
    GENSIO_DECLARE_PPACCEPTER(p, nadata->o, nadata->cb, "perf",
			      nadata->user_data);

    return gensio_perf_filter_alloc(&p, nadata->o, nadata->args, filter);
}

static int
perfna_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    gensio_set_attr_from_child(io, gensio_get_child(io, 0));
    return 0;
}

static int
gensio_gensio_acc_perf_cb(void *acc_data, int op, void *data1, void *data2,
			   void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return perfna_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return perfna_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return perfna_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	perfna_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
perf_gensio_accepter_alloc(struct gensio_accepter *child,
			    const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb, void *user_data,
			    struct gensio_accepter **accepter)
{
    struct perfna_data *nadata;
    int err;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;

    err = gensio_argv_copy(o, args, NULL, &nadata->args);
    if (err) {
	o->free(o, nadata);
	return err;
    }

    nadata->o = o;
    nadata->cb = cb;
    nadata->user_data = user_data;

    err = gensio_gensio_accepter_alloc(child, o, "perf", cb, user_data,
				       gensio_gensio_acc_perf_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;
    gensio_acc_set_is_reliable(nadata->acc, gensio_acc_is_reliable(child));
    gensio_acc_set_is_packet(nadata->acc, gensio_acc_is_packet(child));
    gensio_acc_set_is_message(nadata->acc, gensio_acc_is_message(child));
    *accepter = nadata->acc;

    return 0;

 out_err:
    perfna_free(nadata);
    return err;
}

static int
str_to_perf_gensio_accepter(const char *str, const char * const args[],
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
	err = perf_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_perf(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "perf",
				str_to_perf_gensio, perf_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "perf",
					 str_to_perf_gensio_accepter,
					 perf_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
