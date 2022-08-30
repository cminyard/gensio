/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>

#include "gensio_filter_telnet.h"

#include "telnet.h"
#include "utils.h"

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

    const struct telnet_cmd *telnet_cmds;
    struct telnet_cmd *working_telnet_cmds;
    const unsigned char *telnet_init_seq;
    unsigned int telnet_init_seq_len;

    bool allow_2217;
    bool rfc2217_set;
    gensio_time rfc2217_end_wait;

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

    return tfilter->allow_2217 && !tfilter->rfc2217_set;
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

    if (tfilter->rfc2217_set)
	return 0;

    tfilter->o->get_monotonic_time(tfilter->o, &now);
    if (gensio_time_cmp(&now, &tfilter->rfc2217_end_wait) > 0) {
	tfilter->rfc2217_set = true;
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
		const struct gensio_sg *sg, gensiods sglen,
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
	    size_t inlen = sg[i].buflen;
	    const unsigned char *buf = sg[i].buf;

	    tfilter->write_data_len =
		process_telnet_xmit(tfilter->write_data,
				    tfilter->max_write_size,
				    &buf, &inlen);
	    writelen += sg[i].buflen - inlen;
	    if (inlen != sg[i].buflen)
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
	 * telnet mark.
	 */
	tfilter->in_urgent = true;
	if (rcount)
	    *rcount = buflen;
	goto out_unlock;
    }
    if (gensio_str_in_auxdata(auxdata, "oob")) {
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
    if (tfilter->is_client)
	tfilter->rfc2217_set = !tfilter->allow_2217;
    else {
	tfilter->rfc2217_set = true; /* Don't wait for this on the server. */
	tfilter->setup_done = true;
    }
    if (!tfilter->rfc2217_set) {
	tfilter->o->get_monotonic_time(tfilter->o,
				       &tfilter->rfc2217_end_wait);
	tfilter->rfc2217_end_wait.secs += 4; /* FIXME - magic number */
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
    if (tfilter->working_telnet_cmds)
	tfilter->o->free(tfilter->o, tfilter->working_telnet_cmds);
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
    unsigned char buf[2];

    if (get)
	return GE_NOTSUP;
    if (op != GENSIO_CONTROL_SEND_BREAK)
	return GE_NOTSUP;

    buf[0] = TN_IAC;
    buf[1] = TN_BREAK;
    telnet_filter_send_cmd(filter, buf, 2);
    return 0;
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
			       bool allow_2217,
			       gensiods max_read_size,
			       gensiods max_write_size,
			       const struct gensio_telnet_filter_callbacks *cbs,
			       void *handler_data,
			       const struct telnet_cmd *telnet_cmds,
			       const unsigned char *telnet_init_seq,
			       unsigned int telnet_init_seq_len,
			       const struct gensio_telnet_filter_rops **rops)
{
    struct telnet_filter *tfilter;

    tfilter = o->zalloc(o, sizeof(*tfilter));
    if (!tfilter)
	return NULL;

    tfilter->o = o;
    tfilter->is_client = is_client;
    tfilter->allow_2217 = allow_2217;
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

static struct telnet_cmd telnet_server_cmds_2217[] =
{
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   1,     1,          1,       0, },
    { TN_OPT_ECHO,		   1,     0,          1,       1, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          1,       1, },
    { TN_OPT_COM_PORT,		   1,     0,          0,       1,
      .option_handler = com_port_handler, .will_do_handler = com_port_will_do },
    { TELNET_CMD_END_OPTION }
};

static struct telnet_cmd telnet_server_cmds[] =
{
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   1,     1,          1,       1, },
    { TN_OPT_ECHO,		   1,     0,          1,       1, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          1,       1, },
    { TN_OPT_COM_PORT,		   0,     0,          0,       0,
      .option_handler = com_port_handler, .will_do_handler = com_port_will_do },
    { TELNET_CMD_END_OPTION }
};

static unsigned char telnet_server_init_seq_2217[] = {
    TN_IAC, TN_WILL, TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_DO,   TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_WILL, TN_OPT_ECHO,
    TN_IAC, TN_DONT, TN_OPT_ECHO,
    TN_IAC, TN_DO,   TN_OPT_BINARY_TRANSMISSION,
    TN_IAC, TN_WILL, TN_OPT_BINARY_TRANSMISSION,
    TN_IAC, TN_DO,   TN_OPT_COM_PORT,
};

static unsigned char telnet_server_init_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_DO,   TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_WILL, TN_OPT_ECHO,
    TN_IAC, TN_DONT, TN_OPT_ECHO,
    TN_IAC, TN_DO,   TN_OPT_BINARY_TRANSMISSION,
    TN_IAC, TN_WILL, TN_OPT_BINARY_TRANSMISSION,
};

static const struct telnet_cmd telnet_client_cmds[] = {
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   1,     0,          0,       0, },
    { TN_OPT_ECHO,		   1,     0,          0,       0, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          0,       0, },
    { TN_OPT_COM_PORT,		   1,     0,          1,       0,
      .option_handler = com_port_handler, .will_do_handler = com_port_will_do },
    { TELNET_CMD_END_OPTION }
};

static const unsigned char telnet_client_init_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_COM_PORT,
};

int
gensio_telnet_filter_alloc(struct gensio_os_funcs *o, const char * const args[],
			   bool default_is_client,
			   const struct gensio_telnet_filter_callbacks *cbs,
			   void *handler_data,
			   const struct gensio_telnet_filter_rops **rops,
			   struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    unsigned int i;
    gensiods max_read_size = 4096; /* FIXME - magic number. */
    gensiods max_write_size = 4096; /* FIXME - magic number. */
    bool allow_2217 = false;
    bool is_client = default_is_client;
    const struct telnet_cmd *telnet_cmds;
    const unsigned char *init_seq;
    unsigned int init_seq_len;
    int rv, ival;
    char *str;

    rv = gensio_get_default(o, "telnet", "rfc2217", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    allow_2217 = ival;

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
	if (gensio_check_keybool(args[i], "rfc2217", &allow_2217) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "writebuf", &max_write_size) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keyboolv(args[i], "mode", "client", "server",
				  &is_client) > 0)
	    continue;
	return GE_INVAL;
    }

    if (is_client) {
	telnet_cmds = telnet_client_cmds;
	init_seq = telnet_client_init_seq;
	init_seq_len = (allow_2217 ? sizeof(telnet_client_init_seq) : 0);
    } else if (allow_2217) {
	telnet_cmds = telnet_server_cmds_2217;
	init_seq_len = sizeof(telnet_server_init_seq_2217);
	init_seq = telnet_server_init_seq_2217;
    } else {
	telnet_cmds = telnet_server_cmds;
	init_seq_len = sizeof(telnet_server_init_seq);
	init_seq = telnet_server_init_seq;
    }

    filter = gensio_telnet_filter_raw_alloc(o, is_client, allow_2217,
					    max_read_size, max_write_size,
					    cbs, handler_data,
					    telnet_cmds,
					    init_seq, init_seq_len, rops);

    if (!filter)
	return GE_NOMEM;

    *rfilter = filter;
    return 0;
}
