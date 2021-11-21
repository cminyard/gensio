/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <stdio.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>

#include "gensio_filter_perf.h"

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
	      const struct gensio_sg *sg, gensiods sglen,
	      const char *const *auxdata)
{
    struct perf_filter *pfilter = filter_to_perf(filter);
    int err = 0;
    gensiods i, writelen = 0;

    /* Just ignore data from the upper layer. */
    for (i = 0; i < sglen; i++)
	writelen += sg[i].buflen;
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

int
gensio_perf_filter_alloc(struct gensio_os_funcs *o,
			 const char * const args[],
			 struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    gensiods writebuf_size = 1024;
    gensiods write_len = 0;
    gensiods expect_len = 0;
    unsigned int i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "writebuf", &writebuf_size) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "write_len", &write_len) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "expect_len", &expect_len) > 0)
	    continue;
	return GE_INVAL;
    }

    filter = gensio_perf_filter_raw_alloc(o, writebuf_size, write_len,
					  expect_len);
    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}
