/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_ll_gensio.h>
#include <gensio/gensio_acc_gensio.h>
#include <gensio/argvutils.h>

struct kiss_config {
    bool server;
    gensiods max_read_size;
    gensiods max_write_size;
    bool tncs[16];
    unsigned int txdelay;
    unsigned int persist;
    unsigned int slot_time;
    bool full_duplex;
    unsigned int set_hardware;
    unsigned int setup_delay;
    bool set_hardware_set;
    char *setupstr;
    gensiods setupstr_len;
};

static void
gensio_kiss_config_cleanup(struct gensio_os_funcs *o,
			   struct kiss_config *config)
{
    if (config->setupstr)
	o->free(o, config->setupstr);
}

struct kiss_filter {
    struct gensio_filter *filter;

    struct gensio_os_funcs *o;

    struct kiss_config config;

    struct gensio_lock *lock;
    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    bool waiting_setup_timer;
    unsigned char *setupstr;
    gensiods setupstr_pos;
    unsigned int setup_delay;

    bool in_esc; /* Currently processing message data (after a start). */
    bool in_msg_complete; /* A full message is ready. */
    bool out_msg_ready;
    bool in_bad_packet;

    /* Data waiting to be delivered to the user. */
    unsigned char *read_data;
    gensiods read_data_pos;
    gensiods read_data_len;

    /* Data waiting to be written. */
    unsigned char *write_data;
    gensiods buf_max_write; /* Maximum raw bytes (escaping c0s, etc.) */
    gensiods write_data_pos;
    gensiods write_data_len;

    gensiods user_write_pos; /* Current user position. */

    uint8_t curr_tnc;
    unsigned char startdata[320];
    unsigned char startdata_len;
};

#define filter_to_kiss(v) ((struct kiss_filter *) \
			   gensio_filter_get_user_data(v))

static void
kiss_lock(struct kiss_filter *kfilter)
{
    kfilter->o->lock(kfilter->lock);
}

static void
kiss_unlock(struct kiss_filter *kfilter)
{
    kfilter->o->unlock(kfilter->lock);
}

static bool
kiss_ul_read_pending(struct gensio_filter *filter)
{
    struct kiss_filter *kfilter = filter_to_kiss(filter);

    return kfilter->in_msg_complete;
}

static bool
kiss_ll_write_pending(struct gensio_filter *filter)
{
    struct kiss_filter *kfilter = filter_to_kiss(filter);

    return kfilter->out_msg_ready ||
	kfilter->setupstr_pos < kfilter->config.setupstr_len;
}

static bool
kiss_ll_read_needed(struct gensio_filter *filter)
{
    return false;
}

static int
kiss_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    gensio_set_is_packet(io, true);
    return 0;
}

static void
kiss_add_wrbyte(struct kiss_filter *kfilter, unsigned char byte)
{
    if (byte == 0xc0) {
	kfilter->write_data[kfilter->write_data_len++] = 0xdb;
	kfilter->write_data[kfilter->write_data_len++] = 0xdc;
    } else if (byte == 0xdb) {
	kfilter->write_data[kfilter->write_data_len++] = 0xdb;
	kfilter->write_data[kfilter->write_data_len++] = 0xdd;
    } else {
	kfilter->write_data[kfilter->write_data_len++] = byte;
    }
}

static int
kiss_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct kiss_filter *kfilter = filter_to_kiss(filter);
    unsigned int i;

    if (!kfilter->waiting_setup_timer && kfilter->config.setupstr_len) {
	kfilter->setupstr_pos = 0;
	kfilter->waiting_setup_timer = true;
	timeout->secs = kfilter->setup_delay / 1000;
	timeout->nsecs = kfilter->setup_delay % 1000 * 1000000;
	return GE_RETRY;
    } else {
	kfilter->waiting_setup_timer = false;
    }
    for (i = 0; i < kfilter->startdata_len; i++)
	kiss_add_wrbyte(kfilter, kfilter->startdata[i]);
    if (i > 0)
	kfilter->out_msg_ready = true;
    return 0;
}

static int
kiss_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct kiss_filter *kfilter = filter_to_kiss(filter);

    if (kfilter->write_data_len == 0 || !kfilter->out_msg_ready)
	return 0;
    else
	return GE_INPROGRESS;
}

static int
kiss_ul_write(struct gensio_filter *filter,
	      gensio_ul_filter_data_handler handler, void *cb_data,
	      gensiods *rcount,
	      const struct gensio_sg *isg, gensiods sglen,
	      const char *const *auxdata)
{
    struct kiss_filter *kfilter = filter_to_kiss(filter);
    unsigned int tnc = 0;
    int rv = 0;

    if (auxdata) {
	unsigned int i;

	for (i = 0; auxdata[i]; i++) {
	    if (strncmp(auxdata[i], "tnc:", 4) == 0) {
		char *end;

		tnc = strtoul(auxdata[i] + 4, &end, 10);
		if (!isdigit(auxdata[i][4]) || tnc > 15 || *end)
		    return GE_INVAL;
	    } else {
		return GE_INVAL;
	    }
	}
    }
    kiss_lock(kfilter);
    if (!kfilter->config.tncs[tnc]) {
	printf("A\n");
	rv = GE_INVAL;
    } else if (kfilter->setupstr_pos < kfilter->config.setupstr_len) {
	struct gensio_sg sg[1];
	gensiods count;

	kiss_unlock(kfilter);
	sg[0].buflen = kfilter->config.setupstr_len - kfilter->setupstr_pos;
	sg[0].buf = kfilter->setupstr + kfilter->setupstr_pos;
	rv = handler(cb_data, &count, sg, 1, NULL);
	kiss_lock(kfilter);
	if (!rv) {
	    kfilter->setupstr_pos += count;
	    if (rcount)
		*rcount = 0;
	}
    } else if (kfilter->out_msg_ready) {
	if (rcount)
	    *rcount = 0;
    } else {
	gensiods i, j, writelen = 0;

	kfilter->write_data[kfilter->write_data_len++] = 0xc0;
	kiss_add_wrbyte(kfilter, tnc << 4);
	for (i = 0; i < sglen; i++) {
	    gensiods inlen = isg[i].buflen;
	    const unsigned char *buf = isg[i].buf;

	    for (j = 0; j < inlen; j++) {
		if (kfilter->user_write_pos >= kfilter->config.max_write_size)
		    break;
		kfilter->user_write_pos++;
		kiss_add_wrbyte(kfilter, buf[j]);
	    }
	    writelen += inlen;
	}
	if (rcount)
	    *rcount = writelen;

	if (kfilter->user_write_pos > 0) {
	    kfilter->out_msg_ready = true;
	    kfilter->write_data[kfilter->write_data_len++] = 0xc0;
	}
    }

    if (kfilter->out_msg_ready) {
	struct gensio_sg sg[1];
	gensiods len = kfilter->write_data_len - kfilter->write_data_pos;
	gensiods count;

	sg[0].buflen = len;
	sg[0].buf = kfilter->write_data + kfilter->write_data_pos;

	kiss_unlock(kfilter);
	rv = handler(cb_data, &count, sg, 1, NULL);
	kiss_lock(kfilter);
	if (rv) {
	    kfilter->out_msg_ready = false;
	} else {
	    if (count >= len) {
		kfilter->write_data_len = 0;
		kfilter->write_data_pos = 0;
		kfilter->out_msg_ready = false;
		kfilter->user_write_pos = 0;
	    } else {
		kfilter->write_data_pos += count;
	    }
	}
    }
    kiss_unlock(kfilter);

    return rv;
}

static int
kiss_ll_write(struct gensio_filter *filter,
		gensio_ll_filter_data_handler handler, void *cb_data,
		gensiods *rcount,
		unsigned char *buf, gensiods buflen,
		const char *const *iauxdata)
{
    struct kiss_filter *kfilter = filter_to_kiss(filter);
    gensiods in_buflen = buflen, count = 0;
    int err = 0;

    kiss_lock(kfilter);
    if (kfilter->in_msg_complete || buflen == 0) {
	if (rcount)
	    *rcount = 0;
    } else {
	while (buflen && !kfilter->in_msg_complete) {
	    unsigned char b = *buf++;

	    buflen--;

	    if (b == 0xc0) { /* Frame end char */
		kfilter->in_esc = 0;
		if (kfilter->in_bad_packet) {
		    kfilter->read_data_len = 0;
		    kfilter->in_bad_packet = false;
		} else if (kfilter->read_data_len > 0) {
		    kfilter->read_data_pos = 0;
		    kfilter->in_msg_complete = true;
		}
		continue;
	    } else if (kfilter->in_bad_packet) {
		/* Ignore input until a frame end. */
	    } else if (kfilter->in_esc) {
		kfilter->in_esc = false;
		if (b == 0xdc) {
		    b = 0xc0;
		} else if (b == 0xdd) {
		    b = 0xdb;
		} else {
		    kfilter->in_bad_packet = true;
		    continue;
		}
	    } else if (b == 0xdb) { /* escape char */
		kfilter->in_esc = true;
		continue;
	    }
	    if (kfilter->read_data_len >= kfilter->config.max_read_size) {
		kfilter->in_bad_packet = true;
		continue;
	    }
	    kfilter->read_data[kfilter->read_data_len++] = b;
	}

	if (rcount)
	    *rcount = in_buflen - buflen;
    }

    if (kfilter->in_msg_complete) {
	char tncbuf[10];
	const char *auxdata[2] = { tncbuf, NULL };

	count = 0;
	if (kfilter->read_data_pos == 0) {
	    kfilter->curr_tnc = kfilter->read_data[0] >> 4;

	    /* Throw away everything but data to tncs we have. */
	    if (kfilter->read_data[0] & 0xf ||
			!kfilter->config.tncs[kfilter->curr_tnc]) {
		kfilter->in_msg_complete = false;
		kfilter->read_data_len = 0;
		kfilter->in_esc = 0;
		goto out_unlock;
	    }
	    kfilter->read_data_pos = 1;
	    kfilter->read_data_len--;
	}
	snprintf(tncbuf, sizeof(tncbuf), "tnc:%u", kfilter->curr_tnc);
	kiss_unlock(kfilter);
	err = handler(cb_data, &count,
		      kfilter->read_data + kfilter->read_data_pos,
		      kfilter->read_data_len, auxdata);
	kiss_lock(kfilter);
	if (!err) {
	    if (count >= kfilter->read_data_len) {
		kfilter->in_msg_complete = false;
		kfilter->read_data_len = 0;
		kfilter->read_data_pos = 0;
	    } else {
		kfilter->read_data_len -= count;
		kfilter->read_data_pos += count;
	    }
	}
    }
 out_unlock:
    kiss_unlock(kfilter);

    return err;
}

static int
kiss_setup(struct gensio_filter *filter)
{
    return 0;
}

static void
kiss_filter_cleanup(struct gensio_filter *filter)
{
    struct kiss_filter *kfilter = filter_to_kiss(filter);

    kfilter->read_data_len = 0;
    kfilter->read_data_pos = 0;
    kfilter->write_data_len = 0;
    kfilter->write_data_pos = 0;
    kfilter->user_write_pos = 0;
    kfilter->in_msg_complete = false;
    kfilter->in_esc = false;
    kfilter->out_msg_ready = false;
}

static void
kfilter_free(struct kiss_filter *kfilter)
{
    struct gensio_os_funcs *o = kfilter->o;

    gensio_kiss_config_cleanup(o, &kfilter->config);
    if (kfilter->lock)
	o->free_lock(kfilter->lock);
    if (kfilter->setupstr)
	o->free(o, kfilter->setupstr);
    if (kfilter->read_data)
	o->free(o, kfilter->read_data);
    if (kfilter->write_data)
	o->free(o, kfilter->write_data);
    if (kfilter->filter)
	gensio_filter_free_data(kfilter->filter);
    o->free(o, kfilter);
}

static void
kiss_free(struct gensio_filter *filter)
{
    struct kiss_filter *kfilter = filter_to_kiss(filter);

    kfilter_free(kfilter);
}

static int gensio_kiss_filter_func(struct gensio_filter *filter, int op,
				     void *func, void *data,
				     gensiods *count,
				     void *buf, const void *cbuf,
				     gensiods buflen,
				     const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return kiss_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return kiss_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return kiss_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return kiss_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return kiss_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return kiss_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return kiss_ul_write(filter, func, data, count, cbuf, buflen, auxdata);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return kiss_ll_write(filter, func, data, count, buf, buflen, auxdata);

    case GENSIO_FILTER_FUNC_SETUP:
	return kiss_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	kiss_filter_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	kiss_free(filter);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
handle_get_ranges(bool vals[16], const char *str)
{
    unsigned int v1, v2, i;
    char *end;

    while (*str) {
	if (!isdigit(*str))
	    return GE_INVAL;
	v1 = strtoul(str, &end, 10);
	if (*end && *end != ',' && *end != '-')
	    return GE_INVAL;
	if (v1 > 15)
	    return GE_INVAL;
	if (*end == '-') {
	    str = end + 1;
	    if (!isdigit(*str))
		return GE_INVAL;
	    v2 = strtoul(str, &end, 10);
	    if (*end && *end != ',')
		return GE_INVAL;
	    if (v2 > 15)
		return GE_INVAL;
	    for (i = v1; i < v2; i++)
		vals[i] = true;
	} else {
	    vals[v1] = true;
	}
	if (*end)
	    str = end + 1;
	else
	    str = end;
    }
    return 0;
}

static int
gensio_kiss_config(struct gensio_pparm_info *p,
		   struct gensio_os_funcs *o, const char * const args[],
		   struct gensio_base_parms *parms,
		   struct kiss_config *config)
{
    unsigned int i;
    const char *str, *setupstr = NULL;
    bool bval;
    int rv;

    config->max_read_size = 1024; /* FIXME - magic number. */
    config->max_write_size = 1024; /* FIXME - magic number. */
    config->tncs[0] = true;
    config->txdelay = 500;
    config->persist = 63;
    config->slot_time = 100;
    config->full_duplex = false;
    config->set_hardware = 0;
    config->setup_delay = 1000;
    config->set_hardware_set = false;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_ds(p, args[i], "readbuf", &config->max_read_size) > 0)
	    continue;
	if (gensio_pparm_ds(p, args[i], "writebuf", &config->max_write_size) > 0)
	    continue;
	if (gensio_pparm_value(p, args[i], "tncs", &str) > 0) {
	    rv = handle_get_ranges(config->tncs, str);
	    if (rv)
		return rv;
	    continue;
	}
	if (gensio_pparm_uint(p, args[i], "txdelay", &config->txdelay) > 0) {
	    if (config->txdelay > 2550)
		return GE_INVAL;
	    continue;
	}
	if (gensio_pparm_uint(p, args[i], "persist", &config->persist) > 0) {
	    if (config->persist > 255)
		return GE_INVAL;
	    continue;
	}
	if (gensio_pparm_uint(p, args[i], "slottime", &config->slot_time) > 0) {
	    if (config->slot_time > 2550)
		return GE_INVAL;
	    continue;
	}
	if (gensio_pparm_bool(p, args[i], "fullduplex",
			      &config->full_duplex) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "sethardware",
			      &config->set_hardware) > 0) {
	    if (config->set_hardware > 255)
		return GE_INVAL;
	    config->set_hardware_set = true;
	    continue;
	}
	if (gensio_pparm_bool(p, args[i], "server", &config->server) > 0)
	    continue;
	if (gensio_pparm_value(p, args[i], "setupstr", &setupstr) > 0)
	    continue;
	if (gensio_pparm_uint(p, args[i], "setup-delay",
			      &config->setup_delay) > 0)
	    continue;
	if (gensio_pparm_bool(p, args[i], "d710", &bval) > 0) {
	    if (bval)
		config->setupstr = "xflow on\rhbaud 1200\rkiss on\rrestart\r";
	    continue;
	}
	if (gensio_pparm_bool(p, args[i], "d710-9600", &bval) > 0) {
	    if (bval)
		config->setupstr = "xflow on\rhbaud 9600\rkiss on\rrestart\r";
	    continue;
	}
	if (gensio_base_parm(parms, p, args[i]) > 0)
	    continue;
	gensio_pparm_unknown_parm(p, args[i]);
	return GE_INVAL;
    }

    if (config->max_read_size < 256) {
	gensio_pparm_slog(p, "readbuf must be >= 256");
	return GE_INVAL;
    }
    if (config->max_write_size < 256) {
	gensio_pparm_slog(p, "writebuf must be >= 256");
	return GE_INVAL;
    }

    if (setupstr) {
	config->setupstr = gensio_strdup(o, setupstr);
	if (!config->setupstr)
	    return GE_NOMEM;
	config->setupstr_len = strlen(config->setupstr);
    }

    return 0;
}

static int
gensio_kiss_filter_alloc(struct gensio_os_funcs *o,
			 struct kiss_config *config,
			 struct gensio_filter **rfilter)
{
    struct kiss_filter *kfilter;
    unsigned int i;

    kfilter = o->zalloc(o, sizeof(*kfilter));
    if (!kfilter)
	return GE_NOMEM;

    kfilter->o = o;
    kfilter->config = *config;

    if (config->setupstr) {
	kfilter->config.setupstr = gensio_strdup(o, config->setupstr);
	if (!kfilter->config.setupstr)
	    goto out_nomem;
    }

    /* Room to double every byte and the begin and end frame markers. */
    kfilter->buf_max_write = ((config->max_write_size + 2) * 2) + 2;

    kfilter->lock = o->alloc_lock(o);
    if (!kfilter->lock)
	goto out_nomem;

    kfilter->read_data = o->zalloc(o, config->max_read_size);
    if (!kfilter->read_data)
	goto out_nomem;

    kfilter->write_data = o->zalloc(o, kfilter->buf_max_write);
    if (!kfilter->write_data)
	goto out_nomem;

    kfilter->filter = gensio_filter_alloc_data(o, gensio_kiss_filter_func,
					       kfilter);
    if (!kfilter->filter)
	goto out_nomem;

    for (i = 0; !config->server && i < 16; i++) {
	if (!config->tncs[i])
	    continue;

	kfilter->startdata[kfilter->startdata_len++] = 0xc0;
	kfilter->startdata[kfilter->startdata_len++] = (i << 4) | 1;
	kfilter->startdata[kfilter->startdata_len++] = (config->txdelay + 5) / 10;
	kfilter->startdata[kfilter->startdata_len++] = 0xc0;
	kfilter->startdata[kfilter->startdata_len++] = 0xc0;
	kfilter->startdata[kfilter->startdata_len++] = (i << 4) | 2;
	kfilter->startdata[kfilter->startdata_len++] = config->persist;
	kfilter->startdata[kfilter->startdata_len++] = 0xc0;
	kfilter->startdata[kfilter->startdata_len++] = 0xc0;
	kfilter->startdata[kfilter->startdata_len++] = (i << 4) | 3;
	kfilter->startdata[kfilter->startdata_len++] = (config->slot_time + 5) / 10;
	kfilter->startdata[kfilter->startdata_len++] = 0xc0;
	kfilter->startdata[kfilter->startdata_len++] = 0xc0;
	kfilter->startdata[kfilter->startdata_len++] = (i << 4) | 5;
	kfilter->startdata[kfilter->startdata_len++] = config->full_duplex;
	kfilter->startdata[kfilter->startdata_len++] = 0xc0;
	if (config->set_hardware_set) {
	    kfilter->startdata[kfilter->startdata_len++] = 0xc0;
	    kfilter->startdata[kfilter->startdata_len++] = (i << 4) | 6;
	    kfilter->startdata[kfilter->startdata_len++] = config->set_hardware;
	    kfilter->startdata[kfilter->startdata_len++] = 0xc0;
	}
    }

    *rfilter = kfilter->filter;
    return 0;

 out_nomem:
    kfilter_free(kfilter);
    return GE_NOMEM;
}

static int
kiss_gensio_alloc2(struct gensio *child, const char *const args[],
		   bool server,
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio_base_parms **parms,
		   struct gensio **net)
{
    int err;
    struct gensio_filter *filter;
    struct gensio_ll *ll;
    struct gensio *io;
    struct kiss_config config;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "kiss", user_data);

    memset(&config, 0, sizeof(config));
    config.server = server;

    err = gensio_kiss_config(&p, 0, args, *parms, &config);
    if (err)
	goto out_err;

    err = gensio_kiss_filter_alloc(o, &config, &filter);
    if (err)
	goto out_err;

    ll = gensio_gensio_ll_alloc(o, child);
    if (!ll) {
	gensio_filter_free(filter);
	goto out_nomem;
    }

    gensio_ref(child); /* So gensio_ll_free doesn't free the child if fail */
    io = base_gensio_alloc(o, ll, filter, child, "kiss", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	gensio_filter_free(filter);
	goto out_nomem;
    }
    gensio_free(child); /* Lose the ref we acquired. */

    err = gensio_base_parms_set(io, parms);
    if (err) {
	gensio_free(io);
	goto out_err;
    }

    gensio_set_is_packet(io, true);

    *net = io;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    gensio_kiss_config_cleanup(o, &config);
    return err;
}

static int
kiss_gensio_alloc(struct gensio *child, const char *const args[],
		  struct gensio_os_funcs *o,
		  gensio_event cb, void *user_data,
		  struct gensio **net)
{
    struct gensio_base_parms *parms;
    int err;

    err = gensio_base_parms_alloc(o, true, "kiss", &parms);
    if (err)
	return err;

    err = kiss_gensio_alloc2(child, args, false, o, cb, user_data,
			     &parms, net);

    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
str_to_kiss_gensio(const char *str, const char * const args[],
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

    err = kiss_gensio_alloc(io2, args, o, cb, user_data, new_gensio);
    if (err)
	gensio_free(io2);

    return err;
}

struct kissna_data {
    struct gensio_accepter *acc;
    struct gensio_os_funcs *o;
    gensio_accepter_event cb;
    struct kiss_config config;
    void *user_data;
};

static void
kissna_free(void *acc_data)
{
    struct kissna_data *nadata = acc_data;

    gensio_kiss_config_cleanup(nadata->o, &nadata->config);
    nadata->o->free(nadata->o, nadata);
}

static int
kissna_alloc_gensio(void *acc_data, const char * const *iargs,
		    struct gensio *child, struct gensio **rio)
{
    struct kissna_data *nadata = acc_data;
    struct gensio_base_parms *parms = NULL;
    int err;

    parms = gensio_acc_base_parms_dup(nadata->acc);
    if (!parms)
	return GE_NOMEM;

    err = kiss_gensio_alloc2(child, iargs, false, nadata->o, NULL, NULL,
			     &parms, rio);

    if (parms)
	gensio_base_parms_free(&parms);

    return err;
}

static int
kissna_new_child(void *acc_data, void **finish_data,
		 struct gensio_filter **filter)
{
    struct kissna_data *nadata = acc_data;

    return gensio_kiss_filter_alloc(nadata->o, &nadata->config, filter);
}

static int
kissna_finish_parent(void *acc_data, void *finish_data, struct gensio *io)
{
    gensio_set_is_packet(io, true);
    return 0;
}

static int
gensio_gensio_acc_kiss_cb(void *acc_data, int op, void *data1, void *data2,
			  void *data3, const void *data4)
{
    switch (op) {
    case GENSIO_GENSIO_ACC_ALLOC_GENSIO:
	return kissna_alloc_gensio(acc_data, data4, data1, data2);

    case GENSIO_GENSIO_ACC_NEW_CHILD:
	return kissna_new_child(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FINISH_PARENT:
	return kissna_finish_parent(acc_data, data1, data2);

    case GENSIO_GENSIO_ACC_FREE:
	kissna_free(acc_data);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
kiss_gensio_accepter_alloc(struct gensio_accepter *child,
			   const char * const args[],
			   struct gensio_os_funcs *o,
			   gensio_accepter_event cb, void *user_data,
			   struct gensio_accepter **accepter)
{
    struct kissna_data *nadata;
    int err;
    struct gensio_base_parms *parms = NULL;
    GENSIO_DECLARE_PPACCEPTER(p, o, cb, "kiss", user_data);

    err = gensio_base_parms_alloc(o, true, "kiss", &parms);
    if (err)
	goto out_err;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	goto out_nomem;

    nadata->config.server = true;
    err = gensio_kiss_config(&p, o, args, parms, &nadata->config);
    if (err)
	goto out_err;

    nadata->o = o;
    nadata->cb = cb;
    nadata->user_data = user_data;

    err = gensio_gensio_accepter_alloc(child, o, "kiss", cb, user_data,
				       gensio_gensio_acc_kiss_cb, nadata,
				       &nadata->acc);
    if (err)
	goto out_err;

    err = gensio_acc_base_parms_set(nadata->acc, &parms);
    if (err)
	goto out_err;

    gensio_acc_set_is_packet(nadata->acc, true);
    *accepter = nadata->acc;

    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (nadata) {
	if (nadata->acc)
	    gensio_acc_free(nadata->acc);
	else
	    kissna_free(nadata);
    }
    if (parms)
	gensio_base_parms_free(&parms);
    return err;
}

static int
str_to_kiss_gensio_accepter(const char *str, const char * const args[],
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
	err = kiss_gensio_accepter_alloc(acc2, args, o, cb, user_data, acc);
	if (err)
	    gensio_acc_free(acc2);
    }

    return err;
}

int
gensio_init_kiss(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_filter_gensio(o, "kiss",
				str_to_kiss_gensio, kiss_gensio_alloc);
    if (rv)
	return rv;
    rv = register_filter_gensio_accepter(o, "kiss",
					 str_to_kiss_gensio_accepter,
					 kiss_gensio_accepter_alloc);
    if (rv)
	return rv;
    return 0;
}
