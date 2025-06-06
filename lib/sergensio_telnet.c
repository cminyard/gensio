/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>

#include <gensio/gensio.h>
#include <gensio/gensio_base.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>

#include "utils.h"
#include "telnet.h"

struct gensio_telnet_filter_callbacks {
    void (*got_sync)(void *handler_data);
    void (*got_cmd)(void *handler_data, unsigned char cmd);
    int (*com_port_will_do)(void *handler_data, unsigned char cmd);
    void (*com_port_cmd)(void *handler_data, const unsigned char *option,
			 unsigned int len);
    int (*rfc1073_will_do)(void *handler_data, unsigned char cmd);
    void (*rfc1073_cmd)(void *handler_data, const unsigned char *option,
			unsigned int len);
    void (*timeout)(void *handler_data);
    void (*free)(void *handler_data);
    int (*control)(void *handler_data, bool get, int option,
		   char *data, gensiods *datalen);
    int (*acontrol)(void *hander_data, bool get, int option,
		     struct gensio_func_acontrol *data);
};

struct gensio_telnet_filter_rops {
    void (*send_option)(struct gensio_filter *filter,
			const unsigned char *buf, unsigned int len);
    void (*send_cmd)(struct gensio_filter *filter,
		     const unsigned char *buf, unsigned int len);
    void (*start_timer)(struct gensio_filter *filter, gensio_time *timeout);
};

enum telnet_write_state {
    TELNET_NOT_WRITING,
    TELNET_IN_TN_WRITE,
    TELNET_IN_USER_WRITE
};

struct telnet_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;
    bool is_client;

    struct gensio_lock *lock;

    bool setup_done;
    int in_urgent;

    struct telnet_cmd *telnet_cmds;
    struct telnet_cmd *working_telnet_cmds;
    unsigned char *telnet_init_seq;
    unsigned int telnet_init_seq_len;

    bool allow_rfc2217;
    bool rfc2217_set;
    bool allow_rfc1073;
    bool rfc1073_set;
    bool rfc1073_enabled;
    gensio_time init_end_wait;

    const struct gensio_telnet_filter_callbacks *telnet_cbs;
    void *handler_data;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    /*
     * To avoid problems with splitting TN_IACs, we do not split up
     * telnet chunks or user chunks.  We use this to mark what we
     * are doing.
     */
    enum telnet_write_state write_state;

    struct telnet_data_s tn_data;

    /* Data waiting to be delivered to the user. */
    unsigned char *read_data;
    gensiods max_read_size;
    gensiods read_data_pos;
    gensiods read_data_len;

    /* Data waiting to be written. */
    unsigned char *write_data;
    gensiods max_write_size;
    gensiods write_data_pos;
    gensiods write_data_len;
};

#define filter_to_telnet(v) ((struct telnet_filter *) \
			     gensio_filter_get_user_data(v))

static void telnet_filter_send_cmd(struct gensio_filter *filter,
				   const unsigned char *buf,
				   unsigned int len);

static void
telnet_lock(struct telnet_filter *tfilter)
{
    tfilter->o->lock(tfilter->lock);
}

static void
telnet_unlock(struct telnet_filter *tfilter)
{
    tfilter->o->unlock(tfilter->lock);
}

static void
telnet_set_callbacks(struct gensio_filter *filter,
		     gensio_filter_cb cb, void *cb_data)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    struct gensio_filter_cb_control_data ctrl;
    gensiods datalen = 1;

    tfilter->filter_cb = cb;
    tfilter->filter_cb_data = cb_data;

    /* Enable OOB data, as we need it from TCP for proper mark handling. */
    ctrl.depth = 0;
    ctrl.get = false;
    ctrl.option = GENSIO_CONTROL_ENABLE_OOB;
    ctrl.data = "1";
    ctrl.datalen = &datalen;
    cb(cb_data, GENSIO_FILTER_CB_CONTROL, &ctrl);
}

static bool
telnet_ul_read_pending(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    bool rv;

    telnet_lock(tfilter);
    rv = tfilter->read_data_len;
    telnet_unlock(tfilter);
    return rv;
}

static bool
telnet_ll_write_pending(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    bool rv;

    telnet_lock(tfilter);
    rv = tfilter->write_data_len ||
	gensio_buffer_cursize(&tfilter->tn_data.out_telnet_cmd);
    telnet_unlock(tfilter);
    return rv;
}

static void
telnet_clear_write(struct telnet_filter *tfilter)
{
    tfilter->write_data_len = 0;
    gensio_buffer_reset(&tfilter->tn_data.out_telnet_cmd);
}

static bool
telnet_ll_read_needed(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    return ((tfilter->allow_rfc2217 && !tfilter->rfc2217_set) ||
	    (tfilter->allow_rfc1073 && !tfilter->rfc1073_set));
}

static int
telnet_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    return 0;
}

static int
telnet_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    gensio_time now;

    if (tfilter->rfc2217_set && tfilter->rfc1073_set)
	return 0;

    tfilter->o->get_monotonic_time(tfilter->o, &now);
    if (gensio_time_cmp(&now, &tfilter->init_end_wait) > 0) {
	tfilter->rfc2217_set = true;
	tfilter->rfc1073_set = true;
	return 0;
    }

    timeout->secs = 0;
    timeout->nsecs = 500000000;
    return GE_RETRY;
}

static int
telnet_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

struct telnet_buffer_data {
    gensio_ul_filter_data_handler handler;
    void *cb_data;
    const char *const *auxdata;
};

static int
telnet_buffer_do_write(void *cb_data, void *buf, unsigned int buflen,
		       unsigned int *written)
{
    struct telnet_buffer_data *data = cb_data;
    gensiods count;
    struct gensio_sg sg = { buf, buflen };
    int err;

    err = data->handler(data->cb_data, &count, &sg, 1, data->auxdata);
    if (!err)
	*written = count;
    return err;
}

static int
telnet_ul_write(struct gensio_filter *filter,
		gensio_ul_filter_data_handler handler, void *cb_data,
		gensiods *rcount,
		const struct gensio_sg *isg, gensiods sglen,
		const char *const *auxdata)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    int err = 0;

    telnet_lock(tfilter);
    if (tfilter->write_data_len) {
	if (rcount)
	    *rcount = 0;
    } else {
	gensiods i, writelen = 0;

	for (i = 0; i < sglen; i++) {
	    size_t inlen = isg[i].buflen;
	    const unsigned char *buf = isg[i].buf;

	    tfilter->write_data_len =
		process_telnet_xmit(tfilter->write_data,
				    tfilter->max_write_size,
				    &buf, &inlen);
	    writelen += isg[i].buflen - inlen;
	    if (inlen != isg[i].buflen)
		break;
	}
	if (rcount)
	    *rcount = writelen;
    }

    if (tfilter->write_state != TELNET_IN_USER_WRITE &&
		gensio_buffer_cursize(&tfilter->tn_data.out_telnet_cmd)) {
	struct telnet_buffer_data data = { handler, cb_data, auxdata };

	err = gensio_buffer_write(telnet_buffer_do_write, &data,
				  &tfilter->tn_data.out_telnet_cmd);
	if (err) {
	    telnet_clear_write(tfilter);
	} else {
	    if (gensio_buffer_cursize(&tfilter->tn_data.out_telnet_cmd))
		tfilter->write_state = TELNET_IN_TN_WRITE;
	    else
		tfilter->write_state = TELNET_NOT_WRITING;
	}
    }

    if (tfilter->write_state != TELNET_IN_TN_WRITE &&
		tfilter->write_data_len) {
	gensiods count = 0;
	struct gensio_sg sg = { tfilter->write_data + tfilter->write_data_pos,
				tfilter->write_data_len };

	err = handler(cb_data, &count, &sg, 1, auxdata);
	if (err) {
	    telnet_clear_write(tfilter);
	} else {
	    if (count >= tfilter->write_data_len) {
		tfilter->write_state = TELNET_NOT_WRITING;
		tfilter->write_data_len = 0;
		tfilter->write_data_pos = 0;
	    } else {
		tfilter->write_state = TELNET_IN_USER_WRITE;
		tfilter->write_data_len -= count;
		tfilter->write_data_pos += count;
	    }
	}
    }
    telnet_unlock(tfilter);

    return err;
}

static int
telnet_ll_write(struct gensio_filter *filter,
		gensio_ll_filter_data_handler handler, void *cb_data,
		gensiods *rcount,
		unsigned char *buf, gensiods buflen,
		const char *const *auxdata)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    int err = 0;

    telnet_lock(tfilter);
    if (gensio_str_in_auxdata(auxdata, "oobtcp")) {
	/*
	 * Just ignore OOB data, but set that we are looking for a
	 * telnet mark.  In some cases the IAC comes before the data
	 * mark (so telnet_cmd_pos == 1), so we have to have a hack
	 * for that.
	 */
	if (tfilter->tn_data.telnet_cmd_pos == 1)
	    tfilter->in_urgent = 2;
	else
	    tfilter->in_urgent = 1;
	/* Abandon any command handling on a sync. */
	tfilter->tn_data.telnet_cmd_pos = 0;
    } else if (gensio_str_in_auxdata(auxdata, "oob")) {
	/* Ignore other oob data. */
	if (rcount)
	    *rcount = buflen;
	goto out_unlock;
    }

    if (tfilter->read_data_len || buflen == 0) {
	if (rcount)
	    *rcount = 0;
    } else {
	unsigned int inlen = buflen, proclen;

	if (tfilter->in_urgent) {
	    /* We are in urgent data, just read until we get a mark. */
	    for (; inlen > 0; inlen--, buf++) {
		if (tfilter->in_urgent == 2) {
		    if (*buf == TN_DATA_MARK) {
			/* Found it. */
			tfilter->in_urgent = 0;
			if (tfilter->telnet_cbs &&
				    tfilter->telnet_cbs->got_sync) {
			    telnet_unlock(tfilter);
			    tfilter->telnet_cbs->got_sync
				(tfilter->handler_data);
			    telnet_lock(tfilter);
			}
			break;
		    }
		    tfilter->in_urgent = 1;
		} else if (*buf == TN_IAC) {
		    tfilter->in_urgent = 2;
		}
	    }
	}

	/*
	 * Process the telnet receive data unlocked.  It can do callbacks to
	 * the users, and we are guaranteed to be single-threaded in the
	 * data handling here.
	 */
	telnet_unlock(tfilter);
	proclen =
	    process_telnet_data(tfilter->read_data + tfilter->read_data_len,
				tfilter->max_read_size - tfilter->read_data_len,
				&buf, &inlen, &tfilter->tn_data);
	telnet_lock(tfilter);
	tfilter->read_data_len += proclen;
	if (rcount)
	    *rcount = buflen - inlen;
    }

    if (tfilter->read_data_len) {
	gensiods count = 0;

	telnet_unlock(tfilter);
	err = handler(cb_data, &count,
		      tfilter->read_data + tfilter->read_data_pos,
		      tfilter->read_data_len, NULL);
	telnet_lock(tfilter);
	if (!err) {
	    if (count >= tfilter->read_data_len) {
		tfilter->read_data_len = 0;
		tfilter->read_data_pos = 0;
	    } else {
		tfilter->read_data_len -= count;
		tfilter->read_data_pos += count;
	    }
	}
    }
 out_unlock:
    telnet_unlock(tfilter);

    return err;
}

static int
com_port_will_do(void *cb_data, unsigned char cmd)
{
    struct telnet_filter *tfilter = cb_data;
    int err = 0;

    if (tfilter->telnet_cbs)
	err = tfilter->telnet_cbs->com_port_will_do(tfilter->handler_data, cmd);
    tfilter->rfc2217_set = true;
    return err;
}

static void
com_port_handler(void *cb_data, unsigned char *option, int len)
{
    struct telnet_filter *tfilter = cb_data;

    if (tfilter->telnet_cbs)
	tfilter->telnet_cbs->com_port_cmd(tfilter->handler_data,
					  option, len);
}

static int
rfc1073_will_do(void *cb_data, unsigned char cmd)
{
    struct telnet_filter *tfilter = cb_data;
    int err = 0;

    if (tfilter->telnet_cbs)
	err = tfilter->telnet_cbs->rfc1073_will_do(tfilter->handler_data, cmd);
    tfilter->rfc1073_set = true;
    tfilter->rfc1073_enabled = !!err;
    return err;
}

static void
rfc1073_handler(void *cb_data, unsigned char *option, int len)
{
    struct telnet_filter *tfilter = cb_data;

    if (tfilter->telnet_cbs)
	tfilter->telnet_cbs->rfc1073_cmd(tfilter->handler_data, option, len);
}

static void
telnet_output_ready(void *cb_data)
{
    struct telnet_filter *tfilter = cb_data;

    if (tfilter->setup_done && tfilter->filter_cb)
	tfilter->filter_cb(tfilter->filter_cb_data,
			   GENSIO_FILTER_CB_OUTPUT_READY, NULL);
}

static void
telnet_cmd_handler(void *cb_data, unsigned char cmd)
{
    struct telnet_filter *tfilter = cb_data;

    if (tfilter->telnet_cbs && tfilter->telnet_cbs->got_cmd)
	tfilter->telnet_cbs->got_cmd(tfilter->handler_data, cmd);
}

static struct telnet_cmd *
telnet_cmds_copy(struct gensio_os_funcs *o, const struct telnet_cmd *in)
{
    unsigned int i;
    struct telnet_cmd *out;

    for (i = 0; in[i].option != TELNET_CMD_END_OPTION; i++)
	;
    i++;

    out = o->zalloc(o, i * sizeof(*out));
    if (!out)
	return NULL;
    memcpy(out, in, i * sizeof(*out));
    return out;
}

static int
telnet_setup(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    struct telnet_cmd *cmds;

    cmds = telnet_cmds_copy(tfilter->o, tfilter->telnet_cmds);
    if (!cmds)
	return GE_NOMEM;
    if (tfilter->working_telnet_cmds)
	tfilter->o->free(tfilter->o, tfilter->working_telnet_cmds);
    tfilter->working_telnet_cmds = cmds;
    telnet_init(&tfilter->tn_data, tfilter, telnet_output_ready,
		telnet_cmd_handler, cmds,
		tfilter->telnet_init_seq, tfilter->telnet_init_seq_len);
    tfilter->rfc2217_set = !tfilter->allow_rfc2217;
    tfilter->rfc1073_set = !tfilter->allow_rfc1073;
    if (!tfilter->rfc2217_set || !tfilter->rfc1073_set) {
	tfilter->o->get_monotonic_time(tfilter->o,
				       &tfilter->init_end_wait);
	tfilter->init_end_wait.secs += 4; /* FIXME - magic number */
	tfilter->setup_done = true;
	if (gensio_buffer_cursize(&tfilter->tn_data.out_telnet_cmd))
	    tfilter->write_state = TELNET_IN_TN_WRITE;
	else
	    tfilter->write_state = TELNET_NOT_WRITING;
    }
    return 0;
}

static void
telnet_filter_cleanup(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    tfilter->setup_done = false;
    tfilter->in_urgent = 0;
    tfilter->read_data_len = 0;
    tfilter->read_data_pos = 0;
    tfilter->write_data_len = 0;
    tfilter->write_data_pos = 0;
    telnet_cleanup(&tfilter->tn_data);
}

static void
telnet_filter_timeout(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    if (tfilter->telnet_cbs && tfilter->telnet_cbs->timeout)
	tfilter->telnet_cbs->timeout(tfilter->handler_data);
}

static void
tfilter_free(struct telnet_filter *tfilter)
{
    if (tfilter->lock)
	tfilter->o->free_lock(tfilter->lock);
    if (tfilter->telnet_cmds)
	tfilter->o->free(tfilter->o, tfilter->telnet_cmds);
    if (tfilter->working_telnet_cmds)
	tfilter->o->free(tfilter->o, tfilter->working_telnet_cmds);
    if (tfilter->telnet_init_seq)
	tfilter->o->free(tfilter->o, tfilter->telnet_init_seq);
    if (tfilter->read_data)
	tfilter->o->free(tfilter->o, tfilter->read_data);
    if (tfilter->write_data)
	tfilter->o->free(tfilter->o, tfilter->write_data);
    if (tfilter->telnet_cbs)
	tfilter->telnet_cbs->free(tfilter->handler_data);
    if (tfilter->filter)
	gensio_filter_free_data(tfilter->filter);
    telnet_cleanup(&tfilter->tn_data);
    tfilter->o->free(tfilter->o, tfilter);
}

static void
telnet_free(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    tfilter_free(tfilter);
}

static int
telnet_filter_control(struct gensio_filter *filter, bool get, int op,
		      char *data, gensiods *datalen)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    unsigned char buf[9];
    unsigned int width, height;
    int rv;

    if (get)
	return GE_NOTSUP;
    switch (op) {
    case GENSIO_CONTROL_SEND_BREAK:
	buf[0] = TN_IAC;
	buf[1] = TN_BREAK;
	telnet_filter_send_cmd(filter, buf, 2);
	return 0;

    case GENSIO_CONTROL_WIN_SIZE:
	if (!tfilter->rfc1073_enabled)
	    return GE_NOTSUP;
	buf[0] = TN_IAC;
	buf[1] = TN_SB;
	buf[2] = TN_OPT_NAWS;
	rv = sscanf(data, "%u:%u", &height, &width);
	if (rv != 2)
	    return GE_INVAL;
	buf[3] = width >> 8;
	buf[4] = width;
	buf[5] = height >> 8;
	buf[6] = height;
	buf[7] = TN_IAC;
	buf[8] = TN_SE;
	telnet_filter_send_cmd(filter, buf, 9);
	return 0;

    default:
	if (tfilter->telnet_cbs->control)
	    return tfilter->telnet_cbs->control(tfilter->handler_data,
						get, op, data, datalen);
	return GE_NOTSUP;
    }
}

static int
telnet_filter_acontrol(struct gensio_filter *filter, bool get, int op,
		       struct gensio_func_acontrol *data)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    if (tfilter->telnet_cbs->acontrol)
	return tfilter->telnet_cbs->acontrol(tfilter->handler_data,
					     get, op, data);
    return GE_NOTSUP;
}

static int gensio_telnet_filter_func(struct gensio_filter *filter, int op,
				     void *func, void *data,
				     gensiods *count,
				     void *buf, const void *cbuf,
				     gensiods buflen,
				     const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	telnet_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return telnet_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return telnet_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return telnet_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return telnet_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return telnet_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return telnet_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return telnet_ul_write(filter, func, data, count, cbuf, buflen, auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return telnet_ll_write(filter, func, data, count, buf, buflen, auxdata);

    case GENSIO_FILTER_FUNC_SETUP:
	return telnet_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	telnet_filter_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	telnet_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_TIMEOUT:
	telnet_filter_timeout(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return telnet_filter_control(filter, *((bool *) cbuf), buflen, data,
				     count);

    case GENSIO_FILTER_FUNC_ACONTROL:
	return telnet_filter_acontrol(filter, *((bool *) cbuf), buflen, data);

    default:
	return GE_NOTSUP;
    }
}

static void telnet_filter_send_option(struct gensio_filter *filter,
				      const unsigned char *buf,
				      unsigned int len)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    telnet_lock(tfilter);
    telnet_send_option(&tfilter->tn_data, buf, len);
    tfilter->filter_cb(tfilter->filter_cb_data,
		       GENSIO_FILTER_CB_OUTPUT_READY, NULL);
    telnet_unlock(tfilter);
}

static void telnet_filter_send_cmd(struct gensio_filter *filter,
				   const unsigned char *buf,
				   unsigned int len)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    telnet_lock(tfilter);
    telnet_cmd_send(&tfilter->tn_data, buf, len);
    tfilter->filter_cb(tfilter->filter_cb_data,
		       GENSIO_FILTER_CB_OUTPUT_READY, NULL);
    telnet_unlock(tfilter);
}

static void telnet_filter_start_timer(struct gensio_filter *filter,
				      gensio_time *timeout)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    tfilter->filter_cb(tfilter->filter_cb_data,
		       GENSIO_FILTER_CB_START_TIMER, timeout);
}

const struct gensio_telnet_filter_rops telnet_filter_rops = {
    .send_option = telnet_filter_send_option,
    .send_cmd = telnet_filter_send_cmd,
    .start_timer = telnet_filter_start_timer
};

static struct gensio_filter *
gensio_telnet_filter_raw_alloc(struct gensio_os_funcs *o,
			       bool is_client,
			       bool allow_rfc2217, bool allow_rfc1073,
			       gensiods max_read_size,
			       gensiods max_write_size,
			       const struct gensio_telnet_filter_callbacks *cbs,
			       void *handler_data,
			       struct telnet_cmd *telnet_cmds,
			       unsigned char *telnet_init_seq,
			       unsigned int telnet_init_seq_len,
			       const struct gensio_telnet_filter_rops **rops)
{
    struct telnet_filter *tfilter;

    tfilter = o->zalloc(o, sizeof(*tfilter));
    if (!tfilter)
	return NULL;

    tfilter->o = o;
    tfilter->is_client = is_client;
    tfilter->allow_rfc2217 = allow_rfc2217;
    tfilter->allow_rfc1073 = allow_rfc1073;
    tfilter->max_write_size = max_write_size;
    tfilter->max_read_size = max_read_size;
    tfilter->telnet_cmds = telnet_cmds;
    tfilter->telnet_init_seq = telnet_init_seq;
    tfilter->telnet_init_seq_len = telnet_init_seq_len;

    tfilter->lock = o->alloc_lock(o);
    if (!tfilter->lock)
	goto out_nomem;

    tfilter->read_data = o->zalloc(o, max_read_size);
    if (!tfilter->read_data)
	goto out_nomem;

    tfilter->write_data = o->zalloc(o, max_write_size);
    if (!tfilter->write_data)
	goto out_nomem;

    *rops = &telnet_filter_rops;
    tfilter->filter = gensio_filter_alloc_data(o, gensio_telnet_filter_func,
					       tfilter);
    if (!tfilter->filter)
	goto out_nomem;
    tfilter->telnet_cbs = cbs;
    tfilter->handler_data = handler_data;

    return tfilter->filter;

 out_nomem:
    tfilter_free(tfilter);
    return NULL;
}

static struct telnet_cmd telnet_server_cmds[] =
{
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   1,     1,          1,       1, },
    { TN_OPT_ECHO,		   1,     0,          1,       1, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          1,       1, },
#define SERV_COM_PORT_POS 3
    { TN_OPT_COM_PORT,		   0,     0,          0,       0, },
#define SERV_RFC1073_POS 4
    { TN_OPT_NAWS,		   0,     0,          0,       0, },
    { TELNET_CMD_END_OPTION }
};

static unsigned char telnet_server_init_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_DO,   TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_WILL, TN_OPT_ECHO,
    TN_IAC, TN_DONT, TN_OPT_ECHO,
    TN_IAC, TN_DO,   TN_OPT_BINARY_TRANSMISSION,
    TN_IAC, TN_WILL, TN_OPT_BINARY_TRANSMISSION,
};
static unsigned char telnet_server_rfc2217_seq[] = {
    TN_IAC, TN_DO,   TN_OPT_COM_PORT,
};
static unsigned char telnet_server_rfc1073_seq[] = {
    TN_IAC, TN_DO,   TN_OPT_NAWS,
};

static const struct telnet_cmd telnet_client_cmds[] = {
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   1,     0,          0,       0, },
    { TN_OPT_ECHO,		   1,     0,          0,       0, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          0,       0, },
#define CLIENT_COM_PORT_POS 3
    { TN_OPT_COM_PORT,		   0,     0,          0,       0, },
#define CLIENT_RFC1073_POS 4
    { TN_OPT_NAWS,		   0,     0,          0,       0, },
    { TELNET_CMD_END_OPTION }
};

static const unsigned char telnet_client_rfc2217_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_COM_PORT,
};
static const unsigned char telnet_client_rfc1073_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_NAWS,
};

static int
gensio_telnet_filter_alloc(struct gensio_pparm_info *p,
			   struct gensio_os_funcs *o, const char * const args[],
			   bool default_is_client,
			   const struct gensio_telnet_filter_callbacks *cbs,
			   void *handler_data,
			   const struct gensio_telnet_filter_rops **rops,
			   struct gensio_base_parms *parms,
			   struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    unsigned int i;
    gensiods max_read_size = 4096; /* FIXME - magic number. */
    gensiods max_write_size = 4096; /* FIXME - magic number. */
    bool allow_rfc2217 = false;
    bool allow_rfc1073 = false;
    bool is_client = default_is_client;
    struct telnet_cmd *telnet_cmds = NULL;
    unsigned char *init_seq = NULL;
    unsigned int init_seq_len, pos;
    int rv, ival;
    char *str;

    rv = gensio_get_default(o, "telnet", "rfc2217", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    allow_rfc2217 = ival;

    rv = gensio_get_default(o, "telnet", "winsize", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    allow_rfc1073 = ival;

    rv = gensio_get_default(o, "telnet", "mode", false,
			    GENSIO_DEFAULT_STR, &str, NULL);
    if (rv) {
	gensio_log(o, GENSIO_LOG_ERR,
		   "Failed getting telnet mode: %s", gensio_err_to_str(rv));
	return rv;
    }
    if (str) {
	if (strcasecmp(str, "client") == 0)
	    is_client = true;
	else if (strcasecmp(str, "server") == 0)
	    is_client = false;
	else {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unknown default telnet mode (%s), ignoring", str);
	}
	o->free(o, str);
    }

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_bool(p, args[i], "rfc2217", &allow_rfc2217) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "winsize", &allow_rfc1073) > 0)
	    continue;
	if (gensio_pparm_ds(p, args[i], "writebuf", &max_write_size) > 0)
	    continue;
	if (gensio_pparm_ds(p, args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_pparm_boolv(p, args[i], "mode", "client", "server",
			       &is_client) > 0)
	    continue;
	if (parms && gensio_base_parm(parms, p, args[i]) > 0)
	    continue;
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

    if (is_client) {
	telnet_cmds = o->zalloc(o, sizeof(telnet_client_cmds));
	if (!telnet_cmds)
	    goto out_nomem;
	memcpy(telnet_cmds, telnet_client_cmds, sizeof(telnet_client_cmds));

	init_seq_len = 0;
	if (allow_rfc2217) {
	    telnet_cmds[CLIENT_COM_PORT_POS].i_will = 1;
	    telnet_cmds[CLIENT_COM_PORT_POS].sent_will = 1;
	    telnet_cmds[CLIENT_COM_PORT_POS].option_handler = com_port_handler;
	    telnet_cmds[CLIENT_COM_PORT_POS].will_do_handler = com_port_will_do;
	    init_seq_len += 3;
	}
	if (allow_rfc1073) {
	    telnet_cmds[CLIENT_RFC1073_POS].i_will = 1;
	    telnet_cmds[CLIENT_RFC1073_POS].sent_will = 1;
	    telnet_cmds[CLIENT_RFC1073_POS].option_handler = rfc1073_handler;
	    telnet_cmds[CLIENT_RFC1073_POS].will_do_handler = rfc1073_will_do;
	    init_seq_len += 3;
	}

	if (init_seq_len != 0) {
	    init_seq = o->zalloc(o, init_seq_len);
	    if (!init_seq)
		goto out_nomem;
	    pos = 0;
	    if (allow_rfc2217) {
		memcpy(init_seq + pos, telnet_client_rfc2217_seq, 3);
		pos += 3;
	    }
	    if (allow_rfc1073) {
		memcpy(init_seq + pos, telnet_client_rfc1073_seq, 3);
		pos += 3;
	    }
	}
    } else {
	telnet_cmds = o->zalloc(o, sizeof(telnet_server_cmds));
	if (!telnet_cmds)
	    goto out_nomem;
	memcpy(telnet_cmds, telnet_server_cmds, sizeof(telnet_server_cmds));

	init_seq_len = sizeof(telnet_server_init_seq);
	if (allow_rfc2217) {
	    telnet_cmds[SERV_COM_PORT_POS].option_handler = com_port_handler;
	    telnet_cmds[SERV_COM_PORT_POS].will_do_handler = com_port_will_do;
	    init_seq_len += 3;
	}
	if (allow_rfc1073) {
	    telnet_cmds[SERV_RFC1073_POS].option_handler = rfc1073_handler;
	    telnet_cmds[SERV_RFC1073_POS].will_do_handler = rfc1073_will_do;
	    init_seq_len += 3;
	}
	init_seq = o->zalloc(o, init_seq_len);
	if (!init_seq)
	    goto out_nomem;
	pos = 0;
	memcpy(init_seq + pos, telnet_server_init_seq,
	       sizeof(telnet_server_init_seq));
	pos += sizeof(telnet_server_init_seq);
	if (allow_rfc2217) {
	    memcpy(init_seq + pos, telnet_server_rfc2217_seq, 3);
	    pos += 3;
	}
	if (allow_rfc1073) {
	    memcpy(init_seq + pos, telnet_server_rfc1073_seq, 3);
	    pos += 3;
	}
    }

    filter = gensio_telnet_filter_raw_alloc(o, is_client,
					    allow_rfc2217, allow_rfc1073,
					    max_read_size, max_write_size,
					    cbs, handler_data,
					    telnet_cmds,
					    init_seq, init_seq_len, rops);

    if (!filter)
	goto out_nomem;

    *rfilter = filter;
    return 0;

 out_nomem:
    if (init_seq)
	o->free(o, init_seq);
    if (telnet_cmds)
	o->free(o, telnet_cmds);
    return GE_NOMEM;
}

#define SERCTL_WAIT_TIME 5

struct stel_xlat_str {
    const char *sval;
    int ival;
};

struct stel_req {
    int option;
    int minval;
    int maxval;
    gensio_control_done cdone;
    const struct stel_xlat_str *xlatstr;
    void *cb_data;
    int time_left;
    struct stel_req *next;
};

struct stel_data {
    struct gensio *io;

    struct gensio_os_funcs *o;

    struct gensio_filter *filter;
    const struct gensio_telnet_filter_rops *rops;
    struct gensio_lock *lock;

    bool allow_rfc2217;
    bool do_rfc2217;
    bool allow_rfc1073;
    bool do_rfc1073;
    bool cisco_baud;
    bool reported_modemstate;
    bool is_client;

    struct stel_req *reqs;
};

static struct cisco_baud_rates_s {
    int real_rate;
    int cisco_ios_val;
} cisco_baud_rates[] = {
    { 300, 3 },
    { 600 , 4},
    { 1200, 5 },
    { 2400, 6 },
    { 4800, 7 },
    { 9600, 8 },
    { 19200, 10 },
    { 38400, 12 },
    { 57600, 13 },
    { 115200, 14 },
    { 230400, 15 },
};
#define CISCO_BAUD_RATES_LEN \
    ((sizeof(cisco_baud_rates) / sizeof(struct cisco_baud_rates_s)))

/*
 * Convert a Cisco version RFC2217 baud rate to an integer baud rate.
 * Returns 0 if unsuccessful.
 */
static int
cisco_baud_to_baud(int cisco_val)
{
    unsigned int i;

    for (i = 0; i < CISCO_BAUD_RATES_LEN; i++) {
	if (cisco_val == cisco_baud_rates[i].cisco_ios_val)
	    return cisco_baud_rates[i].real_rate;
    }

    return 0;
}

/*
 * Convert an integer baud rate to a Cisco version RFC2217 baud rate.
 * Returns 0 if unsuccessful.
 */
static int
baud_to_cisco_baud(int val)
{
    unsigned int i;

    for (i = 0; i < CISCO_BAUD_RATES_LEN; i++) {
	if (val == cisco_baud_rates[i].real_rate)
	    return cisco_baud_rates[i].cisco_ios_val;
    }

    return 0;
}

static void
stel_lock(struct stel_data *sdata)
{
    sdata->o->lock(sdata->lock);
}

static void
stel_unlock(struct stel_data *sdata)
{
    sdata->o->unlock(sdata->lock);
}

static int
stel_queue(struct stel_data *sdata, int option,
	   int minval, int maxval,
	   gensio_control_done cdone,
	   const struct stel_xlat_str *xlatstr,
	   void *cb_data,
	   gensio_time *timeout)
{
    struct stel_req *curr, *req;
    gensio_time ntimeout;

    if (!sdata->do_rfc2217)
	return GE_NOTSUP;

    req = sdata->o->zalloc(sdata->o, sizeof(*req));
    if (!req)
	return GE_NOMEM;

    req->option = option;
    req->cdone = cdone;
    req->xlatstr = xlatstr;
    req->cb_data = cb_data;
    req->minval = minval;
    if (!maxval)
	maxval = INT_MAX;
    req->maxval = maxval;
    if (timeout) {
	req->time_left = timeout->secs;
	if (timeout->nsecs > 0)
	    req->time_left++;
    } else {
	req->time_left = SERCTL_WAIT_TIME;
    }
    req->next = NULL;

    stel_lock(sdata);
    curr = sdata->reqs;
    if (!curr) {
	sdata->reqs = req;
    } else {
	while (curr->next)
	    curr = curr->next;
	curr->next = req;
    }
    stel_unlock(sdata);

    ntimeout.secs = 1;
    ntimeout.nsecs = 0;
    sdata->rops->start_timer(sdata->filter, &ntimeout);
    return 0;
}

static int
stel_baud(struct stel_data *sdata, int baud, const char *sbaud,
	  gensio_control_done cdone,
	  void *cb_data,
	  gensio_time *timeout)
{
    bool is_client = gensio_is_client(sdata->io);
    unsigned char buf[6];
    int err;

    if (sbaud)
	baud = strtol(sbaud, NULL, 0);

    if (is_client) {
	err = stel_queue(sdata, 1, 0, 0, cdone, NULL, cb_data,
			 timeout);
	if (err)
	    return err;
	buf[1] = 1;
    } else {
	buf[1] = 101;
    }

    buf[0] = 44;
    if (sdata->cisco_baud) {
	buf[2] = baud_to_cisco_baud(baud);
	sdata->rops->send_option(sdata->filter, buf, 3);
    } else {
	buf[2] = baud >> 24;
	buf[3] = baud >> 16;
	buf[4] = baud >> 8;
	buf[5] = baud;
	sdata->rops->send_option(sdata->filter, buf, 6);
    }
    return 0;
}

static int
stel_queue_and_send(struct stel_data *sdata, int option, int val,
		    const char *sval,
		    int xmitbase, int minval, int maxval,
		    gensio_control_done cdone,
		    const struct stel_xlat_str *xlatstr,
		    void *cb_data,
		    gensio_time *timeout)
{
    unsigned char buf[3];
    bool is_client = gensio_is_client(sdata->io);
    int err;

    if (sval) {
	if (xlatstr) {
	    unsigned int i;

	    for (i = 0; xlatstr && xlatstr[i].sval; i++) {
		if (strcmp(xlatstr[i].sval, sval) == 0) {
		    val = xlatstr[i].ival;
		    goto found;
		}
	    }
	    return GE_INVAL;
	} else {
	    val = strtoul(sval, NULL, 0);
	}
    }
 found:
    if (val < minval || val > maxval)
	return GE_INVAL;

    if (is_client) {
	err = stel_queue(sdata, option, xmitbase, xmitbase + maxval,
			 cdone, xlatstr, cb_data, timeout);
	if (err)
	    return err;
    } else {
	option += 100;
    }

    buf[0] = 44;
    buf[1] = option;
    buf[2] = val + xmitbase;
    sdata->rops->send_option(sdata->filter, buf, 3);

    return 0;
}

static int
stel_datasize(struct stel_data *sdata, int datasize, const char *sdatasize,
	      gensio_control_done cdone,
	      void *cb_data,
	      gensio_time *timeout)
{
    return stel_queue_and_send(sdata, 2, datasize, sdatasize, 0, 0, 8,
			       cdone, NULL, cb_data, timeout);
}

static const struct stel_xlat_str stel_parity_xlatstr[] = {
    { "0", 0 },
    { "", 0 },
    { "none", GENSIO_SER_PARITY_NONE },
    { "odd", GENSIO_SER_PARITY_ODD },
    { "even", GENSIO_SER_PARITY_EVEN },
    { "mark", GENSIO_SER_PARITY_MARK },
    { "space", GENSIO_SER_PARITY_SPACE },
    {}
};

static int
stel_parity(struct stel_data *sdata, int parity, const char *sparity,
	    gensio_control_done cdone,
	    void *cb_data,
	    gensio_time *timeout)
{
    return stel_queue_and_send(sdata, 3, parity, sparity, 0, 0, 5,
			       cdone, stel_parity_xlatstr, cb_data,
			       timeout);
}

static int
stel_stopbits(struct stel_data *sdata, int stopbits, const char *sstopbits,
	      gensio_control_done cdone,
	      void *cb_data,
	      gensio_time *timeout)
{
    return stel_queue_and_send(sdata, 4, stopbits, sstopbits, 0, 0, 3,
			       cdone, NULL, cb_data, timeout);
}

static const struct stel_xlat_str stel_flow_xlatstr[] = {
    { "0", 0 },
    { "", 0 },
    { "none", GENSIO_SER_FLOWCONTROL_NONE },
    { "xonxoff", GENSIO_SER_FLOWCONTROL_XON_XOFF },
    { "rtscts", GENSIO_SER_FLOWCONTROL_RTS_CTS },
    {}
};

static int
stel_flowcontrol(struct stel_data *sdata, int flowcontrol,
		 const char *sflowcontrol,
		 gensio_control_done cdone,
		 void *cb_data,
		 gensio_time *timeout)
{
    return stel_queue_and_send(sdata, 5, flowcontrol, sflowcontrol, 0, 0, 3,
			       cdone, stel_flow_xlatstr, cb_data,
			       timeout);
}

static const struct stel_xlat_str stel_iflow_xlatstr[] = {
    { "0", 0 },
    { "", 0 },
    { "none", GENSIO_SER_FLOWCONTROL_NONE },
    { "dcd", GENSIO_SER_FLOWCONTROL_DCD },
    { "dtr", GENSIO_SER_FLOWCONTROL_DTR },
    { "dsr", GENSIO_SER_FLOWCONTROL_DSR },
    {}
};

static int
stel_iflowcontrol(struct stel_data *sdata, int iflowcontrol,
		  const char *siflowcontrol,
		  gensio_control_done cdone,
		  void *cb_data,
		  gensio_time *timeout)
{
    return stel_queue_and_send(sdata, 5, iflowcontrol, siflowcontrol,13, 0, 6,
			       cdone, stel_iflow_xlatstr, cb_data,
			       timeout);
}

static const struct stel_xlat_str stel_on_off_xlatstr[] = {
    { "0", 0 },
    { "", 0 },
    { "on", GENSIO_SER_ON },
    { "off", GENSIO_SER_OFF },
    {}
};

static int
stel_sbreak(struct stel_data *sdata, int breakv, const char *sbreakv,
	    gensio_control_done cdone,
	    void *cb_data,
	    gensio_time *timeout)
{
    return stel_queue_and_send(sdata, 5, breakv, sbreakv, 4, 0, 2,
			       cdone, stel_on_off_xlatstr, cb_data,
			       timeout);
}

static int
stel_dtr(struct stel_data *sdata, int dtr, const char *sdtr,
	 gensio_control_done cdone,
	 void *cb_data,
	 gensio_time *timeout)
{
    return stel_queue_and_send(sdata, 5, dtr, sdtr, 7, 0, 2,
			       cdone, stel_on_off_xlatstr, cb_data,
			       timeout);
}

static int
stel_rts(struct stel_data *sdata, int rts, const char *srts,
	 gensio_control_done cdone,
	 void *cb_data,
	 gensio_time *timeout)
{
    return stel_queue_and_send(sdata, 5, rts, srts, 10, 0, 2,
			       cdone, stel_on_off_xlatstr, cb_data,
			       timeout);
}

static int
stel_signature(struct stel_data *sdata, const char *sig, unsigned int sig_len,
	       gensio_control_done cdone,
	       void *cb_data,
	       gensio_time *timeout)
{
    unsigned char outopt[MAX_TELNET_CMD_XMIT_BUF];
    bool is_client = gensio_is_client(sdata->io);

    if (sig_len > (MAX_TELNET_CMD_XMIT_BUF - 2))
	sig_len = MAX_TELNET_CMD_XMIT_BUF - 2;

    if (is_client) {
	int err = stel_queue(sdata, 0, 0, 0, cdone, NULL, cb_data, timeout);
	if (err)
	    return err;

	outopt[0] = 44;
	outopt[1] = 0;
	sdata->rops->send_option(sdata->filter, outopt, 2);
    } else {
	outopt[0] = 44;
	outopt[1] = 100;
	strncpy((char *) outopt + 2, sig, sig_len);

	sdata->rops->send_option(sdata->filter, outopt, sig_len + 2);
    }

    return 0;
}

static int
stel_send(struct stel_data *sdata, unsigned int opt, unsigned int val)
{
    unsigned char buf[3];

    buf[0] = 44;
    buf[1] = opt;
    buf[2] = val;

    if (!gensio_is_client(sdata->io))
	buf[1] += 100;

    sdata->rops->send_option(sdata->filter, buf, 3);

    return 0;
}

static int
stel_modemstate(struct stel_data *sdata, unsigned int val, const char *sval)
{
    unsigned int opt;

    if (sval)
	val = strtol(sval, NULL, 0);

    if (gensio_is_client(sdata->io))
	opt = 11;
    else
	opt = 7;
    return stel_send(sdata, opt, val);
}

static int
stel_linestate(struct stel_data *sdata, unsigned int val, const char *sval)
{
    unsigned int opt;

    if (sval)
	val = strtol(sval, NULL, 0);

    if (gensio_is_client(sdata->io))
	opt = 10;
    else
	opt = 6;
    return stel_send(sdata, opt, val);
}

static int
stel_send_modemstate(struct stel_data *sdata, unsigned int val,
		     const char *sval)
{
    if (sval)
	val = strtol(sval, NULL, 0);

    return stel_send(sdata, 7, val);
}

static int
stel_set_modemstate_mask(struct stel_data *sdata, unsigned int val,
			 const char *sval, gensio_control_done cdone,
			 void *cb_data,
			 gensio_time *timeout)
{
    if (sval)
	val = strtol(sval, NULL, 0);

    return stel_queue_and_send(sdata, 11, val, NULL, 0, 0, 255, cdone,
			       NULL, cb_data, timeout);
}

static int
stel_send_linestate(struct stel_data *sdata, unsigned int val, const char *sval)
{
    if (sval)
	val = strtol(sval, NULL, 0);
    return stel_send(sdata, 6, val);
}

static int
stel_set_linestate_mask(struct stel_data *sdata, unsigned int val,
			const char *sval, gensio_control_done cdone,
			void *cb_data,
			gensio_time *timeout)
{
    if (sval)
	val = strtol(sval, NULL, 0);

    return stel_queue_and_send(sdata, 10, val, NULL, 0, 0, 255, cdone,
			       NULL, cb_data, timeout);
}

static int
stel_flowcontrol_state(struct stel_data *sdata, bool val, const char *sval)
{
    unsigned char buf[2];

    if (sval) {
	if (strcmp(sval, "true") == 0 || strcmp(sval, "on") == 0)
	    val = true;
	else if (strcmp(sval, "false") == 0 || strcmp(sval, "off") == 0)
	    val = false;
	else
	    val = strtol(sval, NULL, 0);
    }

    buf[0] = 44;

    if (val)
	buf[1] = 8;
    else
	buf[1] = 9;
    if (!gensio_is_client(sdata->io))
	buf[1] += 100;

    sdata->rops->send_option(sdata->filter, buf, 2);

    return 0;
}

static const struct stel_xlat_str stel_flush_xlatstr[] = {
    { "0", 0 },
    { "", 0 },
    { "recv", GENSIO_SER_FLUSH_RECV },
    { "xmit", GENSIO_SER_FLUSH_XMIT },
    { "both", GENSIO_SER_FLUSH_BOTH },
    {}
};

static int
stel_flush(struct stel_data *sdata, unsigned int val, const char *sval,
	   gensio_control_done cdone,
	   void *cb_data,
	   gensio_time *timeout)
{
    return stel_queue_and_send(sdata, 12, val, sval, 0, 0, 3, cdone,
			       stel_flush_xlatstr, cb_data, timeout);
}

static int
stel_send_break(struct stel_data *sdata)
{
    unsigned char buf[2];

    buf[0] = TN_IAC;
    buf[1] = TN_BREAK;
    sdata->rops->send_cmd(sdata->filter, buf, 2);
    return 0;
}

static int
stel_control(void *handler_data, bool get, int option,
	     char *data, gensiods *datalen)
{
    struct stel_data *sdata = handler_data;

    if (!gensio_is_serial(sdata->io))
	return GE_NOTSUP;

    switch (option) {
    case GENSIO_CONTROL_SER_MODEMSTATE:
	return stel_modemstate(sdata, 0, data);

    case GENSIO_CONTROL_SER_LINESTATE:
	return stel_linestate(sdata, 0, data);

    case GENSIO_CONTROL_SER_SEND_MODEMSTATE:
	return stel_send_modemstate(sdata, 0, data);

    case GENSIO_CONTROL_SER_SEND_LINESTATE:
	return stel_send_linestate(sdata, 0, data);

    case GENSIO_CONTROL_SER_FLOWCONTROL_STATE:
	return stel_flowcontrol_state(sdata, 0, data);

    case GENSIO_CONTROL_SER_FLUSH:
	return stel_flush(sdata, 0, data, NULL, NULL, NULL);

    case GENSIO_CONTROL_SER_SEND_BREAK:
	return stel_send_break(sdata);

    default:
	return GE_NOTSUP;
    }
}

static int
stel_acontrol(void *handler_data, bool get, int option,
	      struct gensio_func_acontrol *idata)
{
    struct stel_data *sdata = handler_data;
    const char *data = idata->data;
    gensio_control_done cdone = idata->done;
    void *cb_data = idata->cb_data;
    gensio_time *timeout = idata->timeout;
    gensiods datalen = idata->datalen;

    if (!gensio_is_serial(sdata->io))
	return GE_NOTSUP;

    if (get)
	data = NULL;

    switch (option) {
    case GENSIO_ACONTROL_SER_BAUD:
	return stel_baud(sdata, 0, data, cdone, cb_data, timeout);

    case GENSIO_ACONTROL_SER_DATASIZE:
	return stel_datasize(sdata, 0, data, cdone, cb_data, timeout);

    case GENSIO_ACONTROL_SER_PARITY:
	return stel_parity(sdata, 0, data, cdone, cb_data, timeout);

    case GENSIO_ACONTROL_SER_STOPBITS:
	return stel_stopbits(sdata, 0, data, cdone, cb_data, timeout);

    case GENSIO_ACONTROL_SER_FLOWCONTROL:
	return stel_flowcontrol(sdata, 0, data, cdone, cb_data, timeout);

    case GENSIO_ACONTROL_SER_IFLOWCONTROL:
	return stel_iflowcontrol(sdata, 0, data, cdone, cb_data, timeout);

    case GENSIO_ACONTROL_SER_SBREAK:
	return stel_sbreak(sdata, 0, data, cdone, cb_data, timeout);

    case GENSIO_ACONTROL_SER_DTR:
	return stel_dtr(sdata, 0, data, cdone, cb_data, timeout);

    case GENSIO_ACONTROL_SER_RTS:
	return stel_rts(sdata, 0, data, cdone, cb_data, timeout);

    case GENSIO_ACONTROL_SER_FLUSH:
	return stel_flush(sdata, 0, data, cdone, cb_data, timeout);

    case GENSIO_ACONTROL_SER_SET_MODEMSTATE_MASK:
	return stel_set_modemstate_mask(sdata, 0, data, cdone, cb_data,
					timeout);

    case GENSIO_ACONTROL_SER_SET_LINESTATE_MASK:
	return stel_set_linestate_mask(sdata, 0, data, cdone, cb_data,
				       timeout);

    case GENSIO_ACONTROL_SER_SIGNATURE:
	if (get)
	    datalen = 0;
	return stel_signature(sdata, data, datalen,
			      cdone, cb_data, timeout);

    default:
	return GE_NOTSUP;
    }
}

static int
stelc_com_port_will_do(void *handler_data, unsigned char cmd)
{
    struct stel_data *sdata = handler_data;

    if (cmd != TN_DO && cmd != TN_DONT)
	/* We only handle these. */
	return 0;

    if (cmd == TN_DONT)
	/* The remote end turned off RFC2217 handling. */
	sdata->do_rfc2217 = false;
    else
	sdata->do_rfc2217 = sdata->allow_rfc2217;

    return sdata->do_rfc2217;
}

static void
stelc_com_port_cmd(void *handler_data, const unsigned char *option,
		   unsigned int len)
{
    struct stel_data *sdata = handler_data;
    int val = 0, cmd;
    struct stel_req *curr, *prev = NULL;
    char *sig = NULL;
    unsigned int sig_len;
    gensiods vlen = sizeof(int);
    struct gensio *io = sdata->io;

    if (len < 2)
	return;
    if (option[1] < 100)
	return;
    cmd = option[1] - 100;

    switch (cmd) {
    case 0:
	sig = (char *) (option + 2);
	sig_len = len - 2;
	break;

    case 1:
	if (len < 3)
	    return;
	if (len < 6) {
	    sdata->cisco_baud = true;
	    val = cisco_baud_to_baud(option[2]);
	} else {
	    val = option[2] << 24;
	    val |= option[3] << 16;
	    val |= option[4] << 8;
	    val |= option[5];
	}
	break;

    case 6:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_LINESTATE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	return;

    case 7:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	return;

    case 8:
	val = 1;
	gensio_cb(io, GENSIO_EVENT_SER_FLOW_STATE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	return;

    case 9:
	val = 0;
	gensio_cb(io, GENSIO_EVENT_SER_FLOW_STATE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	return;

    default:
	if (len < 3)
	    return;
	val = option[2];
	break;
    }

    stel_lock(sdata);
    curr = sdata->reqs;
    while (curr && !(curr->option == cmd &&
		     val >= curr->minval && val <= curr->maxval)) {
	prev = curr;
	curr = curr->next;
    }
    if (curr) {
	if (prev)
	    prev->next = curr->next;
	else
	    sdata->reqs = curr->next;
    }
    stel_unlock(sdata);

    if (curr) {
	if (curr->cdone) {
	    if (sig) {
		curr->cdone(sdata->io, 0, sig, sig_len, curr->cb_data);
	    } else {
		unsigned int i;
		const char *sval = NULL;
		char str[20];

		val -= curr->minval;
		if (curr->xlatstr) {
		    for (i = 0; curr->xlatstr[i].sval; i++) {
			if (val == curr->xlatstr[i].ival) {
			    sval = curr->xlatstr[i].sval;
			    break;
			}
		    }
		}
		if (!sval) {
		    snprintf(str, sizeof(str), "%d", val);
		    sval = str;
		}
		curr->cdone(sdata->io, 0, sval, strlen(sval), curr->cb_data);
	    }
	}
	sdata->o->free(sdata->o, curr);
	return;
    }
}

static int
stelc_rfc1073_will_do(void *handler_data, unsigned char cmd)
{
    struct stel_data *sdata = handler_data;

    if (cmd != TN_DO && cmd != TN_DONT)
	/* We only handle these. */
	return 0;

    if (cmd == TN_DONT)
	/* The remote end turned off RFC1073 handling. */
	sdata->do_rfc1073 = false;
    else
	sdata->do_rfc1073 = sdata->allow_rfc1073;

    return sdata->do_rfc1073;
}

static void
stelc_rfc1073_cmd(void *handler_data, const unsigned char *option,
		  unsigned int len)
{
    /* We don't get these. */
}

static void
stelc_timeout(void *handler_data)
{
    struct stel_data *sdata = handler_data;
    gensio_time timeout;
    struct stel_req *req, *curr, *prev = NULL, *to_complete = NULL;

    stel_lock(sdata);
    req = sdata->reqs;
    while (req) {
	if (--req->time_left == 0) {
	    if (!prev)
		sdata->reqs = req->next;
	    else
		prev->next = req->next;
	    req->next = NULL;
	    curr = to_complete;
	    if (!curr) {
		to_complete = req;
	    } else {
		while (curr->next)
		    curr = curr->next;
		curr->next = req;
	    }
	} else {
	    prev = req;
	    req = req->next;
	}
    }

    if (sdata->reqs) {
	timeout.secs = 1;
	timeout.nsecs = 0;
	sdata->rops->start_timer(sdata->filter, &timeout);
    }
    stel_unlock(sdata);

    req = to_complete;
    while (req) {
	if (req->cdone)
	    req->cdone(sdata->io, GE_TIMEDOUT, NULL, 0, req->cb_data);
	prev = req;
	req = req->next;
	sdata->o->free(sdata->o, prev);
    }
}

static void
stelc_got_sync(void *handler_data)
{
    /* Nothing to do, break handling is only on the server side. */
}

static void
stel_free(void *handler_data)
{
    struct stel_data *sdata = handler_data;

    if (sdata->lock)
	sdata->o->free_lock(sdata->lock);
    while (sdata->reqs) {
	struct stel_req *req = sdata->reqs;

	sdata->reqs = req->next;
	sdata->o->free(sdata->o, req);
    }
    sdata->o->free(sdata->o, sdata);
}

struct gensio_telnet_filter_callbacks sergensio_telnet_filter_cbs = {
    .got_sync = stelc_got_sync,
    .com_port_will_do = stelc_com_port_will_do,
    .com_port_cmd = stelc_com_port_cmd,
    .rfc1073_will_do = stelc_rfc1073_will_do,
    .rfc1073_cmd = stelc_rfc1073_cmd,
    .timeout = stelc_timeout,
    .free = stel_free,
    .control = stel_control,
    .acontrol = stel_acontrol
};

static int
stels_cb_com_port_will_do(void *handler_data, unsigned char cmd)
{
    struct stel_data *sdata = handler_data;

    if (cmd != TN_WILL && cmd != TN_WONT)
	/* We only handle these. */
	return 0;
    stel_lock(sdata);
    if (cmd == TN_WONT)
	/* The remote end turned off RFC2217 handling. */
	sdata->do_rfc2217 = false;
    else
	sdata->do_rfc2217 = sdata->allow_rfc2217;

    if (!sdata->reported_modemstate && sdata->do_rfc2217) {
	struct gensio *io = sdata->io;

	if (gensio_get_cb(io)) {
	    int val = 255;
	    gensiods vlen = sizeof(val);

	    sdata->reported_modemstate = true;
	    gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE_MASK, 0,
		      (unsigned char *) &val, &vlen, NULL);
	} else {
	    gensio_time timeout;

	    /* Schedule a modemstate report once the callbacks are set. */
	    timeout.secs = 0;
	    timeout.nsecs = 1000000;
	    sdata->rops->start_timer(sdata->filter, &timeout);
	}
    }
    stel_unlock(sdata);

    return sdata->do_rfc2217;
}

static void
stels_cb_com_port_cmd(void *handler_data, const unsigned char *option,
		      unsigned int len)
{
    struct stel_data *sdata = handler_data;
    int val = 0;
    gensiods vlen = sizeof(int);
    struct gensio *io = sdata->io;

    if (len < 2)
	return;
    if (option[1] >= 100)
	return;

    switch (option[1]) {
    case 0:
	vlen = len - 2;
	gensio_cb(io, GENSIO_EVENT_SER_SIGNATURE, 0,
		  (unsigned char *) (option + 2), &vlen, NULL);
	break;

    case 1:
	if (len < 3)
	    return;
	if (len < 6) {
	    sdata->cisco_baud = true;
	    val = cisco_baud_to_baud(option[2]);
	} else {
	    val = option[2] << 24;
	    val |= option[3] << 16;
	    val |= option[4] << 8;
	    val |= option[5];
	}
	gensio_cb(io, GENSIO_EVENT_SER_BAUD, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 2:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_DATASIZE, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 3:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_PARITY, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 4:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_STOPBITS, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 5:
	if (len < 3)
	    return;
	switch(option[2]) {
	case 0: case 1: case 2: case 3:
	    val = option[2];
	    gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		      (unsigned char *) &val, &vlen, NULL);
	    break;
	case 4: case 5: case 6:
	    val = option[2] - 4;
	    gensio_cb(io, GENSIO_EVENT_SER_SBREAK, 0,
		      (unsigned char *) &val, &vlen, NULL);
	    break;
	case 7: case 8: case 9:
	    val = option[2] - 7;
	    gensio_cb(io, GENSIO_EVENT_SER_DTR, 0,
		      (unsigned char *) &val, &vlen, NULL);
	    break;
	case 10: case 11: case 12:
	    val = option[2] - 10;
	    gensio_cb(io, GENSIO_EVENT_SER_RTS, 0,
		      (unsigned char *) &val, &vlen, NULL);
	    break;
	case 13: case 14: case 15: case 16: case 17: case 18: case 19:
	    val = option[2] - 13;
	    gensio_cb(io, GENSIO_EVENT_SER_IFLOWCONTROL, 0,
		      (unsigned char *) &val, &vlen, NULL);
	}
	break;

    case 8:
	val = 1;
	gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 9:
	val = 0;
	gensio_cb(io, GENSIO_EVENT_SER_FLOWCONTROL, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 10:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_LINESTATE_MASK, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 11:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE_MASK, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    case 12:
	if (len < 3)
	    return;
	val = option[2];
	gensio_cb(io, GENSIO_EVENT_SER_FLUSH, 0,
		  (unsigned char *) &val, &vlen, NULL);
	break;

    default:
	break;
    }
}

static int
stels_cb_rfc1073_will_do(void *handler_data, unsigned char cmd)
{
    struct stel_data *sdata = handler_data;

    if (cmd != TN_WILL && cmd != TN_WONT)
	/* We only handle these. */
	return 0;

    if (cmd == TN_WONT)
	/* The remote end turned off RFC1073 handling. */
	sdata->do_rfc1073 = false;
    else
	sdata->do_rfc1073 = sdata->allow_rfc1073;

    return sdata->do_rfc1073;
}

static void
stels_cb_rfc1073_cmd(void *handler_data, const unsigned char *option,
		     unsigned int len)
{
    struct stel_data *sdata = handler_data;
    struct gensio *io = sdata->io;
    char buf[30];
    gensiods buflen;
    unsigned int width, height;

    if (len < 5)
	return;
    option++; /* Skip the option number. */
    width = (option[0] << 8) | option[1];
    height = (option[2] << 8) | option[3];
    buflen = snprintf(buf, sizeof(buf), "%u:%u", height, width);
    if (buflen >= sizeof(buf))
	buflen = sizeof(buf) - 1;
    gensio_cb(io, GENSIO_EVENT_WIN_SIZE, 0,
	      (unsigned char *) buf, &buflen, NULL);
}

static void
stels_got_cmd(void *handler_data, unsigned char cmd)
{
    struct stel_data *sdata = handler_data;
    struct gensio *io = sdata->io;

    if (cmd == TN_BREAK)
	gensio_cb(io, GENSIO_EVENT_SEND_BREAK, 0, NULL, NULL, NULL);
}

static void
stels_cb_got_sync(void *handler_data)
{
    struct stel_data *sdata = handler_data;
    struct gensio *io = sdata->io;

    gensio_cb(io, GENSIO_EVENT_SER_SYNC, 0, NULL, NULL, NULL);
}

static void
stels_timeout(void *handler_data)
{
    struct stel_data *sdata = handler_data;

    stel_lock(sdata);
    if (!sdata->reported_modemstate && sdata->do_rfc2217) {
	struct gensio *io = sdata->io;
	int val = 255;
	gensiods vlen = sizeof(val);

	if (gensio_get_cb(io)) {
	    sdata->reported_modemstate = true;
	    gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE_MASK, 0,
		      (unsigned char *) &val, &vlen, NULL);
	} else {
	    gensio_time timeout;

	    timeout.secs = 0;
	    timeout.nsecs = 1000000;
	    sdata->rops->start_timer(sdata->filter, &timeout);
	}
    }
    stel_unlock(sdata);
}

struct gensio_telnet_filter_callbacks sergensio_telnet_server_filter_cbs = {
    .got_sync = stels_cb_got_sync,
    .got_cmd = stels_got_cmd,
    .com_port_will_do = stels_cb_com_port_will_do,
    .com_port_cmd = stels_cb_com_port_cmd,
    .rfc1073_will_do = stels_cb_rfc1073_will_do,
    .rfc1073_cmd = stels_cb_rfc1073_cmd,
    .timeout = stels_timeout,
    .free = stel_free,
    .control = stel_control,
    .acontrol = stel_acontrol
};

static int
stel_setup(struct gensio_pparm_info *p,
	   const char * const args[], bool default_is_client,
	   struct gensio_os_funcs *o, struct gensio_base_parms *parms,
	   struct stel_data **rsdata)
{
    struct stel_data *sdata;
    unsigned int i;
    bool allow_rfc2217 = false;
    bool allow_rfc1073 = false;
    bool is_client = default_is_client;
    int err;
    int rv, ival;

    rv = gensio_get_default(o, "telnet", "rfc2217", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    allow_rfc2217 = ival;

    rv = gensio_get_default(o, "telnet", "winsize", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    allow_rfc1073 = ival;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_bool(p, args[i], "rfc2217", &allow_rfc2217) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "winsize", &allow_rfc1073) > 0)
	    continue;
	if (gensio_pparm_boolv(p, args[i], "mode", "client", "server",
			       &is_client) > 0)
	    continue;
	/* Ignore everything else, the filter will handle it. */
    }
    if (p->err)
	return GE_INVAL;

    sdata = o->zalloc(o, sizeof(*sdata));
    if (!sdata)
	return GE_NOMEM;

    sdata->o = o;
    sdata->allow_rfc2217 = allow_rfc2217;
    sdata->allow_rfc1073 = allow_rfc1073;
    sdata->is_client = is_client;

    sdata->lock = o->alloc_lock(o);
    if (!sdata->lock)
	goto out_nomem;

    err = gensio_telnet_filter_alloc(p, o, args, true,
				     (is_client ?
				      &sergensio_telnet_filter_cbs :
				      &sergensio_telnet_server_filter_cbs),
				     sdata, &sdata->rops, parms,
				     &sdata->filter);
    if (err)
	goto out_err;

    if (is_client) {
	sdata->reported_modemstate = true;
    }

    *rsdata = sdata;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    /* Freeing the filter frees sdata. */
    if (sdata->filter)
	gensio_filter_free(sdata->filter);
    else
	stel_free(sdata);
    return err;
}

static int
telnet_gensio_alloc2(struct gensio *child, const char * const args[],
		     struct gensio_os_funcs *o,
		     gensio_event cb, void *user_data,
		     struct gensio_base_parms *parms,
		     struct gensio **rio)
{
    struct stel_data *sdata;
    struct gensio_ll *ll = NULL;
    struct gensio *io = NULL;
    int err;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "telnet", user_data);

    if (!parms) {
	err = gensio_base_parms_alloc(o, true, "telnet", &parms);
	if (err)
	    goto out_err2;
    }

    err = stel_setup(&p, args, true, o, parms, &sdata);
    if (err)
	goto out_err2;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll)
	goto out_nomem;

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, sdata->filter, child, "telnet", cb,
			   user_data);
    if (!io)
	goto out_nomem;

    err = gensio_base_parms_set(io, &parms);
    if (err)
	goto out_err;

    sdata->io = io;

    if (sdata->allow_rfc2217)
	gensio_set_is_serial(io, true);

    gensio_free(child); /* Lose the ref we acquired. */
    gensio_set_is_client(io, sdata->is_client);
    *rio = io;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (io) {
	gensio_free(io);
    } else {
	/* Freeing the filter frees sdata. */
	if (sdata->filter)
	    gensio_filter_free(sdata->filter);
	else
	    stel_free(sdata);
	if (ll)
	    gensio_ll_free(ll);
    }
 out_err2:
    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
telnet_gensio_alloc(struct gensio *child, const char * const args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **rio)
{
    return telnet_gensio_alloc2(child, args, o, cb, user_data, NULL, rio);
}

static int
str_to_telnet_gensio(const char *str, const char * const args[],
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

    err = telnet_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct stela_data {
    struct gensio_accepter *acc;

    gensiods max_read_size;
    gensiods max_write_size;

    struct gensio_os_funcs *o;
    gensio_accepter_event cb;
    void *user_data;

    bool allow_rfc2217;
    bool allow_rfc1073;
    bool is_client;
};

static void
stela_free(void *acc_data)
{
    struct stela_data *stela = acc_data;

    /* stela->acc will be freed in the class callback. */
    stela->o->free(stela->o, stela);
}

static int
stela_alloc_gensio(void *acc_data, const char * const *iargs,
		   struct gensio *child, struct gensio **rio)
{
    struct stela_data *stela = acc_data;
    struct gensio_os_funcs *o = stela->o;
    const char *args[6] = { NULL, NULL, NULL, NULL, NULL, NULL };
    char buf1[50], buf2[50];
    unsigned int i;
    bool allow_rfc2217 = stela->allow_rfc2217;
    bool allow_rfc1073 = stela->allow_rfc1073;
    gensiods max_write_size = stela->max_write_size;
    gensiods max_read_size = stela->max_read_size;
    bool is_client = stela->is_client;
    struct gensio_base_parms *parms = NULL;
    GENSIO_DECLARE_PPACCEPTER(p, stela->o, stela->cb, "telnet",
			      stela->user_data);

    parms = gensio_acc_base_parms_dup(stela->acc);
    if (!parms)
	return GE_NOMEM;

    for (i = 0; iargs && iargs[i]; i++) {
	if (gensio_pparm_bool(&p, iargs[i], "rfc2217", &allow_rfc2217) > 0)
	    continue;
	if (gensio_pparm_bool(&p, iargs[i], "winsize", &allow_rfc1073) > 0)
	    continue;
	if (gensio_pparm_ds(&p, iargs[i], "writebuf", &max_write_size) > 0)
	    continue;
	if (gensio_pparm_ds(&p, iargs[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_pparm_boolv(&p, iargs[i], "mode", "client", "server",
			       &is_client) > 0)
	    continue;
	if (gensio_base_parm(parms, &p, iargs[i]) > 0)
	    continue;
	gensio_pparm_unknown_parm(&p, iargs[i]);
	gensio_base_parms_free(&parms);
	return GE_INVAL;
    }

    i = 0;
    if (allow_rfc2217)
	args[i++] = "rfc2217=true";
    if (allow_rfc1073)
	args[i++] = "winsize=true";
    if (max_read_size != GENSIO_DEFAULT_BUF_SIZE) {
	snprintf(buf1, sizeof(buf1), "readbuf=%lu",
		 (unsigned long) max_read_size);
	args[i++] = buf1;
    }
    if (max_write_size != GENSIO_DEFAULT_BUF_SIZE) {
	snprintf(buf2, sizeof(buf2), "writebuf=%lu",
		 (unsigned long) max_write_size);
	args[i++] = buf2;
    }
    if (!is_client)
	args[i++] = "mode=server";

    return telnet_gensio_alloc2(child, args, o, NULL, NULL, parms, rio);
}

static int
stela_new_child(void *acc_data, void **finish_data,
		struct gensio_filter **filter, struct gensio *child)
{
    struct stela_data *stela = acc_data;
    struct gensio_os_funcs *o = stela->o;
    struct stel_data *sdata;
    int err;
    char arg1[25], arg2[25], arg3[25], arg4[25], arg5[25];
    const char *args[6] = { arg1, arg2, arg3, arg4, arg5, NULL };
    GENSIO_DECLARE_PPACCEPTER(p, stela->o, stela->cb, "telnet",
			      stela->user_data);

    snprintf(arg1, sizeof(arg1), "rfc2217=%d", stela->allow_rfc2217);
    snprintf(arg2, sizeof(arg2), "winsize=%d", stela->allow_rfc1073);
    snprintf(arg3, sizeof(arg3), "writebuf=%lu",
	     (unsigned long) stela->max_write_size);
    snprintf(arg4, sizeof(arg4), "readbuf=%lu",
             (unsigned long) stela->max_read_size);
    snprintf(arg5, sizeof(arg5), "mode=%s",
	     stela->is_client ? "client" : "server");

    err = stel_setup(&p, args, false, o, NULL, &sdata);
    if (err)
	return err;

    *filter = sdata->filter;
    *finish_data = sdata;

    return 0;
}

static int
stela_finish_parent(void *acc_data, void *finish_data, struct gensio *io,
		    struct gensio *child)
{
    struct stel_data *sdata = finish_data;
    struct stela_data *stela = acc_data;
    int err;

    err = gensio_acc_base_parms_apply(stela->acc, io);
    if (err)
      return err;

    sdata->io = io;

    if (sdata->allow_rfc2217)
	gensio_set_is_serial(io, true);

    gensio_set_is_client(io, sdata->is_client);

    return 0;
}

static int
gensio_gensio_acc_telnet_cb(void *acc_data, int op, void *data1, void *data2,
			    void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return stela_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return stela_new_child(acc_data, data1, data2, data3);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return stela_finish_parent(acc_data, data1, data2, data3);

    case GENSIO_GENSIO_ACC_FREE:
	stela_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
telnet_gensio_accepter_alloc(struct gensio_accepter *child,
			     const char * const args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb, void *user_data,
			     struct gensio_accepter **raccepter)
{
    struct stela_data *stela;
    unsigned int i;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    gensiods max_write_size = GENSIO_DEFAULT_BUF_SIZE;
    bool allow_rfc2217 = false;
    bool allow_rfc1073 = false;
    bool is_client = false;
    struct gensio_accepter *accepter = NULL;
    int rv, ival;
    struct gensio_base_parms *parms;
    GENSIO_DECLARE_PPACCEPTER(p, o, cb, "telnet", user_data);

    rv = gensio_base_parms_alloc(o, true, "telnet", &parms);
    if (rv)
	goto out_err2;

    rv = gensio_get_default(o, "telnet", "rfc2217", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	goto out_err2;
    allow_rfc2217 = ival;

    rv = gensio_get_default(o, "telnet", "winsize", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	goto out_err2;
    allow_rfc1073 = ival;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_bool(&p, args[i], "rfc2217", &allow_rfc2217) > 0)
	    continue;
	if (gensio_pparm_bool(&p, args[i], "winsize", &allow_rfc1073) > 0)
	    continue;
	if (gensio_pparm_ds(&p, args[i], "writebuf", &max_write_size) > 0)
	    continue;
	if (gensio_pparm_ds(&p, args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_pparm_boolv(&p, args[i], "mode", "client", "server",
			       &is_client) > 0)
	    continue;
	if (gensio_base_parm(parms, &p, args[i]) > 0)
	    continue;
	gensio_pparm_unknown_parm(&p, args[i]);
	rv = GE_INVAL;
	goto out_err2;
    }

    stela = o->zalloc(o, sizeof(*stela));
    if (!stela) {
	rv = GE_NOMEM;
	goto out_err2;
    }

    stela->o = o;
    stela->cb = cb;
    stela->user_data = user_data;
    stela->max_write_size = max_write_size;
    stela->max_read_size = max_read_size;
    stela->allow_rfc2217 = allow_rfc2217;
    stela->allow_rfc1073 = allow_rfc1073;
    stela->is_client = is_client;

    rv = gensio_gensio_accepter_alloc(child, o, "telnet",
				       cb, user_data,
				       gensio_gensio_acc_telnet_cb, stela,
				       &accepter);
    if (rv)
	goto out_err;

    rv = gensio_acc_base_parms_set(accepter, &parms);
    if (rv)
	goto out_err;
    
    if (allow_rfc2217)
	gensio_acc_set_is_serial(accepter, true);

    stela->acc = accepter;
    gensio_acc_set_is_reliable(accepter, gensio_acc_is_reliable(child));

    *raccepter = accepter;

    return 0;

 out_err:
    if (accepter)
	gensio_gensio_acc_free_nochild(accepter);
    else
	stela_free(stela);
 out_err2:
    if (parms)
	gensio_base_parms_free(&parms);
    return rv;
}

static int
str_to_telnet_gensio_accepter(const char *str, const char * const args[],
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
	err = telnet_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_telnet(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "telnet",
				str_to_telnet_gensio, telnet_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "telnet",
					 str_to_telnet_gensio_accepter,
					 telnet_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
