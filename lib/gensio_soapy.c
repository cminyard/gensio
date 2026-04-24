/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2026  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>

#include <SoapySDR/Device.h>
#include <SoapySDR/Formats.h>

#include <gensio/gensio.h>
#include <gensio/gensio_base.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_time.h>

static struct {
    const char *gstr; /* Gensio string version */
    const char *sstr; /* Soapy string version */
} soapy_formats[] = {
    { "float64c",	SOAPY_SDR_CF64 },
    { "floatc",		SOAPY_SDR_CF32 },
    { "s32c",		SOAPY_SDR_CS32 },
    { "u32c",		SOAPY_SDR_CU32 },
    { "s16c",		SOAPY_SDR_CS16 },
    { "u16c",		SOAPY_SDR_CU16 },
    { "s8c",		SOAPY_SDR_CS8 },
    { "u8c",		SOAPY_SDR_CU8 },
    { "float64",	SOAPY_SDR_F64 },
    { "float",		SOAPY_SDR_F32 },
    { "s32",		SOAPY_SDR_S32 },
    { "u32",		SOAPY_SDR_U32 },
    { "s16",		SOAPY_SDR_S16 },
    { "u16",		SOAPY_SDR_U16 },
    { "s8",		SOAPY_SDR_S8 },
    { "u8",		SOAPY_SDR_U8 },
    { }
};

static const char *
gtos_format(const char *infmt)
{
    unsigned int i;

    for (i = 0; soapy_formats[i].gstr; i++) {
	if (strcmp(soapy_formats[i].gstr, infmt) == 0)
	    return soapy_formats[i].sstr;
    }
    return NULL;
}

static const char *
stog_format(const char *infmt)
{
    unsigned int i;

    for (i = 0; soapy_formats[i].gstr; i++) {
	if (strcmp(soapy_formats[i].sstr, infmt) == 0)
	    return soapy_formats[i].gstr;
    }
    return NULL;
}

enum gensio_soapy_ll_state {
    GENSIO_SOAPY_LL_CLOSED,
    GENSIO_SOAPY_LL_IN_OPEN,
    GENSIO_SOAPY_LL_OPEN,
    GENSIO_SOAPY_LL_IN_CLOSE,
    GENSIO_SOAPY_LL_IN_OPEN_CLOSE
};

struct soapy_config {
    unsigned int samplerate;
    const char *format;
    bool agc;
    bool gainset;
    double frequency;
    double bandwidth;
    double gain;
    char *antenna;
    int channel;
};

struct soapy_bufs {
    unsigned char **bufs;
    unsigned int bufslen; /* Size of bufs above. */
    unsigned int bufsize; /* Size of an individual buffer in frames. */
    unsigned int bufbsize; /* Size of an individual buffer in bytes. */
    unsigned int framesize;

    unsigned int curbuf;  /* Current buffer to deliver. */
    unsigned int numbufs; /* Number of buffers ready to deliver. */
    unsigned int curreadpos;  /* Current first buffer's read pos (bytes). */
    unsigned int curwritepos;  /* Current last buffer's write pos (bytes). */
    unsigned int curbuflen; /* For transmitting buffers, see outthread. */
    bool blocked; /* reader/writer is out of buffers and waiting. */
    bool stop; /* In close, stop the reader/write. */
    bool stopped; /* Reader is not running. */
};

struct soapy_ll {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    struct gensio_runner *runner;
    bool deferred_op_pending;

    unsigned int refcount;

    int err;

    struct gensio_ll *ll;
    gensio_ll_cb cb;
    void *cb_data;

    enum gensio_soapy_ll_state state;

    SoapySDRDevice *sdr;

    gensio_ll_open_done open_done;
    void *open_done_data;
    gensio_ll_close_done close_done;
    void *close_done_data;
    bool do_close_now;

    /* For the threads, we are currently being freed, shut down. */
    bool in_free;

    bool read_enabled;
    bool write_enabled;

    bool in_read;
    bool in_write;

    SoapySDRStream *instream;
    SoapySDRStream *outstream;

    struct gensio_thread *inthread;
    struct gensio_norun_waiter *inwaiter;
    struct gensio_thread *outthread;
    struct gensio_norun_waiter *outwaiter;

    struct soapy_bufs inbufs;
    struct soapy_bufs outbufs;

    char *devname;
    /* Configured values */
    struct soapy_config inc;
    struct soapy_config outc;

    /* Actual values */
    struct soapy_config realinc;
    struct soapy_config realoutc;

    unsigned int overflows;
    unsigned int underflows;
};

#define ll_to_soapy(v) ((struct soapy_ll *) gensio_ll_get_user_data(v))

static void gensio_soapy_sched_deferred_op(struct soapy_ll *soapyll);
static void gensio_soapy_ll_check_read(struct soapy_ll *soapyll);
static void gensio_soapy_ll_check_write(struct soapy_ll *soapyll);

static void
gensio_soapy_ll_free(struct soapy_ll *soapyll)
{
    struct gensio_os_funcs *o = soapyll->o;
    unsigned int i;

    soapyll->in_free = true;
    if (soapyll->inwaiter)
	gensio_os_norun_waiter_wake(soapyll->inwaiter);
    if (soapyll->outwaiter)
	gensio_os_norun_waiter_wake(soapyll->outwaiter);
    if (soapyll->inthread)
	gensio_os_wait_thread(soapyll->inthread);
    if (soapyll->outthread)
	gensio_os_wait_thread(soapyll->outthread);
    if (soapyll->inwaiter)
	gensio_os_free_norun_waiter(soapyll->inwaiter);
    if (soapyll->outwaiter)
	gensio_os_free_norun_waiter(soapyll->outwaiter);

    if (soapyll->inc.antenna)
	o->free(o, soapyll->inc.antenna);
    if (soapyll->outc.antenna)
	o->free(o, soapyll->outc.antenna);
    if (soapyll->devname)
	o->free(o, soapyll->devname);

    if (soapyll->instream)
	SoapySDRDevice_closeStream(soapyll->sdr, soapyll->instream);
    if (soapyll->outstream)
	SoapySDRDevice_closeStream(soapyll->sdr, soapyll->outstream);
    if (soapyll->sdr)
	SoapySDRDevice_unmake(soapyll->sdr);

    if (soapyll->inbufs.bufs) {
	for (i = 0; i < soapyll->inbufs.bufslen; i++)
	    o->free(o, soapyll->inbufs.bufs[i]);
	o->free(o, soapyll->inbufs.bufs);
    }
    if (soapyll->outbufs.bufs) {
	for (i = 0; i < soapyll->outbufs.bufslen; i++)
	    o->free(o, soapyll->outbufs.bufs[i]);
	o->free(o, soapyll->outbufs.bufs);
    }

    if (soapyll->ll)
	gensio_ll_free_data(soapyll->ll);
    if (soapyll->lock)
	o->free_lock(soapyll->lock);
    if (soapyll->runner)
	o->free_runner(soapyll->runner);
    o->free(o, soapyll);
}

static void
gensio_soapy_ll_lock(struct soapy_ll *soapyll)
{
    soapyll->o->lock(soapyll->lock);
}

static void
gensio_soapy_ll_unlock(struct soapy_ll *soapyll)
{
    soapyll->o->unlock(soapyll->lock);
}

static void
gensio_soapy_ll_ref(struct soapy_ll *soapyll)
{
    soapyll->refcount++;
}

static void
gensio_soapy_ll_deref(struct soapy_ll *soapyll)
{
    assert(soapyll->refcount > 1);
    soapyll->refcount--;
}

static void
gensio_soapy_ll_deref_and_unlock(struct soapy_ll *soapyll)
{
    unsigned int refcount;

    assert(soapyll->refcount > 0);
    refcount = --soapyll->refcount;
    gensio_soapy_ll_unlock(soapyll);
    if (refcount == 0)
	gensio_soapy_ll_free(soapyll);
}

static void
gensio_soapy_ll_check_read(struct soapy_ll *soapyll)
{
    struct soapy_bufs *sb = &soapyll->inbufs;
    unsigned int cbuf;

    if (soapyll->in_read)
	return;
    if (soapyll->read_enabled && (sb->numbufs > 0 || soapyll->err)) {
	gensiods count;

	if (soapyll->err) {
	    soapyll->in_read = true;
	    gensio_soapy_ll_unlock(soapyll);
	    soapyll->cb(soapyll->cb_data, GENSIO_LL_CB_READ,
			soapyll->err, NULL, 0, NULL);
	    gensio_soapy_ll_lock(soapyll);
	    soapyll->in_read = false;
	    goto out;
	}

	cbuf = sb->curbuf;
	soapyll->in_read = true;
	gensio_soapy_ll_unlock(soapyll);
	count = soapyll->cb(soapyll->cb_data, GENSIO_LL_CB_READ, 0,
			    sb->bufs[cbuf] + sb->curreadpos,
			    (gensiods) sb->bufbsize - sb->curreadpos, NULL);
	gensio_soapy_ll_lock(soapyll);
	soapyll->in_read = false;
	if (soapyll->state != GENSIO_SOAPY_LL_OPEN)
	    goto out;
	if (count + sb->curreadpos >= sb->bufbsize) {
	    sb->numbufs--;
	    sb->curbuf++;
	    if (sb->curbuf >= sb->bufslen)
		sb->curbuf = 0;
	    if (sb->blocked) {
		sb->blocked = false;
		gensio_os_norun_waiter_wake(soapyll->inwaiter);
	    }
	} else {
	    sb->curreadpos += count;
	}
    }
 out:
    if (soapyll->read_enabled && (sb->numbufs > 0 || soapyll->err))
	gensio_soapy_sched_deferred_op(soapyll);
}

static void
gensio_soapy_ll_check_write(struct soapy_ll *soapyll)
{
    struct soapy_bufs *sb = &soapyll->outbufs;

    if (soapyll->in_write)
	return;
    if (soapyll->write_enabled && sb->numbufs < sb->bufslen) {
	soapyll->in_write = true;
	gensio_soapy_ll_unlock(soapyll);
	soapyll->cb(soapyll->cb_data, GENSIO_LL_CB_WRITE_READY, 0,
		    NULL, 0, NULL);
	gensio_soapy_ll_lock(soapyll);
	soapyll->in_write = false;
    }
    if (soapyll->write_enabled && sb->numbufs < sb->bufslen)
	gensio_soapy_sched_deferred_op(soapyll);
}

static void
gensio_soapy_ll_do_close(struct soapy_ll *soapyll)
{
    gensio_ll_close_done close_done = soapyll->close_done;
    void *close_done_data = soapyll->close_done_data;

    soapyll->close_done = NULL;
    gensio_soapy_ll_unlock(soapyll);
    close_done(soapyll->cb_data, close_done_data);
    gensio_soapy_ll_lock(soapyll);
}

static void
gensio_soapy_ll_do_open(struct soapy_ll *soapyll, int err)
{
    gensio_ll_open_done open_done = soapyll->open_done;
    void *open_done_data = soapyll->open_done_data;

    soapyll->open_done = NULL;
    gensio_soapy_ll_unlock(soapyll);
    open_done(soapyll->cb_data, err, open_done_data);
    gensio_soapy_ll_lock(soapyll);
}

static void
gensio_soapy_do_read_enable(struct soapy_ll *soapyll)
{
    if (soapyll->inbufs.numbufs > 0 || soapyll->err)
	gensio_soapy_sched_deferred_op(soapyll);
}

static void
gensio_soapy_do_write_enable(struct soapy_ll *soapyll)
{
    if (soapyll->outbufs.numbufs < soapyll->outbufs.bufslen || soapyll->err)
	gensio_soapy_sched_deferred_op(soapyll);
}

static void
gensio_soapy_ll_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct soapy_ll *soapyll = cbdata;

    gensio_soapy_ll_lock(soapyll);
    soapyll->deferred_op_pending = false;
    switch(soapyll->state) {
    case GENSIO_SOAPY_LL_CLOSED:
	break;

    case GENSIO_SOAPY_LL_IN_OPEN: {
	bool oldread = soapyll->read_enabled, oldwrite = soapyll->write_enabled;

	soapyll->state = GENSIO_SOAPY_LL_OPEN;
	gensio_soapy_ll_do_open(soapyll, 0);
	if (soapyll->state != GENSIO_SOAPY_LL_OPEN)
	    break;
	/*
	 * These won't be activated if they were enabled before the
	 * open callback, handle that.
	 */
	if (oldread && soapyll->read_enabled)
	    gensio_soapy_do_read_enable(soapyll);
	if (oldwrite && soapyll->write_enabled)
	    gensio_soapy_do_write_enable(soapyll);
	break;
    }

    case GENSIO_SOAPY_LL_OPEN:
	gensio_soapy_ll_check_read(soapyll);
	gensio_soapy_ll_check_write(soapyll);
	break;

    case GENSIO_SOAPY_LL_IN_OPEN_CLOSE:
	if (soapyll->do_close_now)
	    gensio_soapy_ll_do_open(soapyll, GE_LOCALCLOSED);
	/* Fallthrough */
    case GENSIO_SOAPY_LL_IN_CLOSE:
	if (soapyll->inbufs.stopped && soapyll->outbufs.stopped) {
	    soapyll->state = GENSIO_SOAPY_LL_CLOSED;
	    gensio_soapy_ll_do_close(soapyll);
	    gensio_soapy_ll_deref(soapyll);
	}
	break;

    default:
	break;
    }
    gensio_soapy_ll_deref_and_unlock(soapyll);
}

/* Must be called with the lock held. */
static void
gensio_soapy_sched_deferred_op(struct soapy_ll *soapyll)
{
    if (!soapyll->deferred_op_pending) {
	gensio_soapy_ll_ref(soapyll);
	soapyll->deferred_op_pending = true;
	soapyll->o->run(soapyll->runner);
    }
}

static void
gensio_soapy_inthread(void *data)
{
    struct soapy_ll *soapyll = data;
    struct soapy_bufs *sb = &soapyll->inbufs;
    unsigned int cbuf;

    gensio_soapy_ll_lock(soapyll);
    while (!soapyll->in_free) {
    block:
	if (!sb->stop) {
	    sb->blocked = true;
	    gensio_soapy_ll_unlock(soapyll);
	    gensio_os_norun_waiter_wait(soapyll->inwaiter);
	    gensio_soapy_ll_lock(soapyll);
	}
	if (soapyll->in_free)
	    break;

	if (sb->stop) {
	    SoapySDRDevice_deactivateStream(soapyll->sdr, soapyll->instream,
					    0, 0);
	    sb->stopped = true;
	    sb->stop = false;
	    gensio_soapy_sched_deferred_op(soapyll);
	    continue;
	}
	if (sb->stopped || soapyll->err)
	    continue;

	/* We have been woken, start processing input data. */

	while (sb->numbufs < sb->bufslen && !sb->stop) {
	    void *vbufs[1];
	    int rv;
	    int flags; /* FIXME - do something with flags. */
	    long long timeNs;

	    gensio_soapy_ll_unlock(soapyll);
	    cbuf = sb->curbuf + sb->numbufs;
	    if (cbuf >= sb->bufslen)
		cbuf -= sb->bufslen;

	    vbufs[0] = sb->bufs[cbuf] + (sb->curwritepos * sb->framesize);
	    rv = SoapySDRDevice_readStream(soapyll->sdr, soapyll->instream,
					   vbufs, sb->bufsize - sb->curwritepos,
					   &flags, &timeNs, 1000000);
	    gensio_soapy_ll_lock(soapyll);
	    if (rv < 0) {
		gensio_log(soapyll->o, GENSIO_LOG_INFO,
			   "soapy read stream failed: %s\n",
			   SoapySDRDevice_lastError());
		soapyll->err = GE_IOERR;
		if (soapyll->read_enabled)
		    gensio_soapy_sched_deferred_op(soapyll);		
		goto block;
	    }
	    if (rv + sb->curwritepos >= sb->bufsize) {
		/* Filled the buffer.  Wake the read delivery. */
		sb->numbufs++;
		sb->curwritepos = 0;
		if (soapyll->read_enabled)
		    gensio_soapy_sched_deferred_op(soapyll);		
	    } else {
		sb->curwritepos += rv;
	    }
	}
    }
    gensio_soapy_ll_unlock(soapyll);
}

static void
gensio_soapy_outthread(void *data)
{
    struct soapy_ll *soapyll = data;
    struct soapy_bufs *sb = &soapyll->outbufs;
    unsigned int cbuf;

    gensio_soapy_ll_lock(soapyll);
    while (!soapyll->in_free) {
    block:
	if (!sb->stop) {
	    sb->blocked = true;
	    gensio_soapy_ll_unlock(soapyll);
	    gensio_os_norun_waiter_wait(soapyll->outwaiter);
	    gensio_soapy_ll_lock(soapyll);
	}
	if (soapyll->in_free)
	    break;

	if (sb->stop) {
	    SoapySDRDevice_deactivateStream(soapyll->sdr, soapyll->outstream,
					    0, 0);
	    sb->stopped = true;
	    sb->stop = false;
	    gensio_soapy_sched_deferred_op(soapyll);
	    continue;
	}
	if (sb->stopped || soapyll->err)
	    continue;

	/* We have been woken, handle output buffers. */
	while ((sb->numbufs > 0 || sb->curwritepos > 0) && !sb->stop) {
	    const void *vbufs[1];
	    int rv;
	    int flags; /* FIXME - do something with flags. */
	    long long timeNs = 0;

	    cbuf = sb->curbuf;
	    if (sb->numbufs == 0) {
		/* We only have a partial buffer to write. */
		sb->numbufs++;
		sb->curbuflen = sb->curwritepos;
		sb->curwritepos = 0;
	    } else if (sb->curbuflen == 0) {
		/* Full buffer. */
		sb->curbuflen = sb->bufbsize;
	    }

	    vbufs[0] = sb->bufs[cbuf] + (sb->curreadpos * sb->framesize);
	    gensio_soapy_ll_unlock(soapyll);
	    rv = SoapySDRDevice_writeStream(soapyll->sdr, soapyll->outstream,
					    vbufs,
					    sb->curbuflen - sb->curreadpos,
					    &flags, timeNs, 1000000);
	    gensio_soapy_ll_lock(soapyll);
	    if (rv < 0) {
		gensio_log(soapyll->o, GENSIO_LOG_INFO,
			   "soapy write stream failed: %s\n",
			   SoapySDRDevice_lastError());
		soapyll->err = GE_IOERR;
		if (soapyll->write_enabled)
		    gensio_soapy_sched_deferred_op(soapyll);		
		sb->stopped = true;
		sb->stop = false;
		goto block;
	    }
	    if (rv + sb->curreadpos >= sb->bufsize) {
		/* Filled the buffer.  Wake the write ready. */
		sb->numbufs--;
		sb->curbuf++;
		if (sb->curbuf >= sb->bufslen)
		    sb->curbuf = 0;
		sb->curreadpos = 0;
		sb->curbuflen = 0;
		if (soapyll->write_enabled)
		    gensio_soapy_sched_deferred_op(soapyll);		
	    } else {
		sb->curreadpos += rv;
	    }
	}
    }
    gensio_soapy_ll_unlock(soapyll);
}

static int
gensio_soapy_ll_write(struct soapy_ll *soapyll, gensiods *rcount,
		      const struct gensio_sg *sg, gensiods sglen)
{
    int err = 0;
    gensiods i = 0, count = 0, len, pos;
    struct soapy_bufs *sb = &soapyll->outbufs;
    unsigned int cbuf;
    const unsigned char *buf;

    if (soapyll->outc.channel < 0)
	return GE_NOTSUP;

    gensio_soapy_ll_lock(soapyll);
    if (soapyll->err) {
	err = soapyll->err;
	goto out_unlock;
    }
    if (soapyll->state != GENSIO_SOAPY_LL_OPEN) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    for (i = 0; i < sglen; i++) {
	if (sg[i].buflen % soapyll->outbufs.framesize != 0) {
	    err = GE_INVAL;
	    goto out_unlock;
	}
    }

    for (i = 0, buf = sg[i].buf, pos = 0;
		i < sglen && sb->numbufs < sb->bufslen; ) {
	cbuf = sb->curbuf + sb->numbufs;
	if (cbuf >= sb->bufslen)
	    cbuf -= sb->bufslen;

	len = sg[i].buflen - pos;
	if (len > sb->bufbsize - sb->curwritepos)
	    len = sb->bufbsize - sb->curwritepos;
	memcpy(sb->bufs[cbuf] + sb->curwritepos, buf + pos, len);
	count += len;

	sb->curwritepos += len;
	if (sb->curwritepos >= sb->bufbsize) {
	    sb->numbufs++;
	    if (sb->blocked) {
		sb->blocked = false;
		gensio_os_norun_waiter_wake(soapyll->inwaiter);
	    }
	}

	pos += len;
	if (pos >= sg[i].buflen) {
	    i++;
	    if (i < sglen) {
		buf = sg[i].buf;
		pos = 0;
	    }
	}
    }    

 out_unlock:
    gensio_soapy_ll_unlock(soapyll);
    if (!err && rcount)
	*rcount = count;
    return err;
}

static int
gensio_soapy_config(struct soapy_ll *soapyll, struct gensio_pparm_info *p,
		    int rxtx,
		    struct soapy_config *conf, struct soapy_config *realconf,
		    SoapySDRStream **stream)
{
    const char *rxtxs = rxtx == SOAPY_SDR_TX ? "tx" : "rx";
    size_t chans[1] = { conf->channel };

    if (conf->antenna &&
	SoapySDRDevice_setAntenna(soapyll->sdr, rxtx, conf->channel,
				  conf->antenna) != 0) {
	gensio_pparm_log(p, "soapy set %s antenna failed: %s\n", rxtxs,
			 SoapySDRDevice_lastError());
	return GE_INVAL;
    }

    if (SoapySDRDevice_setSampleRate(soapyll->sdr, rxtx, conf->channel,
				     conf->samplerate) != 0) {
	gensio_pparm_log(p, "soapy set %s sample rate failed: %s\n", rxtxs,
			 SoapySDRDevice_lastError());
	return GE_INVAL;
    }

    if (SoapySDRDevice_setGainMode(soapyll->sdr, rxtx, conf->channel,
				   conf->agc) != 0) {
	gensio_pparm_log(p, "soapy set %s gain mod failed: %s\n", rxtxs,
			 SoapySDRDevice_lastError());
	return GE_INVAL;
    }

    if (conf->gainset &&
	SoapySDRDevice_setGain(soapyll->sdr, rxtx, conf->channel,
			       conf->gain) != 0) {
	gensio_pparm_log(p, "soapy set %s gain failed: %s\n", rxtxs,
			 SoapySDRDevice_lastError());
	return GE_INVAL;
    }

    if (conf->frequency > .1 &&
	SoapySDRDevice_setFrequency(soapyll->sdr, rxtx, conf->channel,
				    conf->frequency, NULL) != 0) {
	gensio_pparm_log(p, "soapy set %s frequency failed: %s\n", rxtxs,
			 SoapySDRDevice_lastError());
	return GE_INVAL;
    }

    if (conf->bandwidth > .1 &&
	SoapySDRDevice_setBandwidth(soapyll->sdr, rxtx, conf->channel,
				    conf->bandwidth) != 0) {
	gensio_pparm_log(p, "soapy set %s bandwidth failed: %s\n", rxtxs,
			 SoapySDRDevice_lastError());
	return GE_INVAL;
    }

    *stream = SoapySDRDevice_setupStream(soapyll->sdr, rxtx,
					 conf->format, chans, 1, NULL);
    if (!*stream) {
	gensio_pparm_log(p, "soapy setup %s stream failed: %s\n", rxtxs,
			 SoapySDRDevice_lastError());
	return GE_INVAL;
    }

    realconf->antenna = SoapySDRDevice_getAntenna(soapyll->sdr, rxtx,
						  conf->channel);
    realconf->samplerate = SoapySDRDevice_getSampleRate(soapyll->sdr, rxtx,
							conf->channel);
    realconf->frequency = SoapySDRDevice_getFrequency(soapyll->sdr, rxtx,
						      conf->channel);
    realconf->bandwidth = SoapySDRDevice_getBandwidth(soapyll->sdr, rxtx,
						      conf->channel);
    realconf->agc = SoapySDRDevice_getGainMode(soapyll->sdr, rxtx,
						   conf->channel);
    realconf->gain = SoapySDRDevice_getGain(soapyll->sdr, rxtx,
					    conf->channel);

    return 0;
}

static int
gensio_soapy_ll_open(struct soapy_ll *soapyll,
		     gensio_ll_open_done open_done, void *open_data)
{
    int err = 0;

    gensio_soapy_ll_lock(soapyll);
    if (soapyll->state != GENSIO_SOAPY_LL_CLOSED) {
	err = GE_INUSE;
	goto out_unlock;
    }

    if (soapyll->inc.channel >= 0) {
	if (SoapySDRDevice_activateStream(soapyll->sdr, soapyll->instream,
					  0, 0, 0) != 0) {
	    gensio_log(soapyll->o, GENSIO_LOG_INFO,
		       "soapy activate rx stream failed: %s\n",
		       SoapySDRDevice_lastError());
	    err = GE_INVAL;
	    goto out_unlock;
	}
    }

    if (soapyll->outc.channel >= 0) {
	if (SoapySDRDevice_activateStream(soapyll->sdr, soapyll->outstream,
					  0, 0, 0)) {
	    gensio_log(soapyll->o, GENSIO_LOG_INFO,
		       "soapy activate tx stream failed: %s\n",
		       SoapySDRDevice_lastError());
	    goto out_unlock;
	}
    }

    soapyll->err = 0;
    soapyll->state = GENSIO_SOAPY_LL_IN_OPEN;
    soapyll->open_done = open_done;
    soapyll->open_done_data = open_data;
    gensio_soapy_sched_deferred_op(soapyll);

    /* Start receiving packets in the inthread. */
    if (soapyll->inc.channel >= 0) {
	soapyll->inbufs.stopped = false;
	soapyll->inbufs.blocked = false;
	gensio_os_norun_waiter_wake(soapyll->inwaiter);
    }
    /* Tell the transmitter thread it can go. */
    if (soapyll->outc.channel >= 0)
	soapyll->outbufs.stopped = false;

 out_unlock:
    if (err) {
	SoapySDRDevice_deactivateStream(soapyll->sdr, soapyll->instream,
					0, 0);
	SoapySDRDevice_deactivateStream(soapyll->sdr, soapyll->outstream,
					0, 0);
    }
    gensio_soapy_ll_unlock(soapyll);
    return err;
}

static int
gensio_soapy_ll_close(struct soapy_ll *soapyll,
		      gensio_ll_close_done close_done, void *close_data)
{
    int err = 0;

    gensio_soapy_ll_lock(soapyll);
    if (soapyll->state == GENSIO_SOAPY_LL_IN_OPEN)
	soapyll->state = GENSIO_SOAPY_LL_IN_OPEN_CLOSE;
    else if (soapyll->state == GENSIO_SOAPY_LL_OPEN)
	soapyll->state = GENSIO_SOAPY_LL_IN_CLOSE;
    else
	err = GE_INUSE;
    if (!err) {
	gensio_soapy_ll_ref(soapyll); /* For the close */
	soapyll->close_done = close_done;
	soapyll->close_done_data = close_data;

	if (soapyll->inc.channel >= 0 && !soapyll->inbufs.stopped) {
	    soapyll->inbufs.stop = true;
	    if (soapyll->inbufs.blocked) {
		soapyll->inbufs.blocked = false;
		gensio_os_norun_waiter_wake(soapyll->inwaiter);
	    }
	}
	if (soapyll->outc.channel >= 0 && !soapyll->inbufs.stopped) {
	    soapyll->outbufs.stop = true;
	    if (soapyll->outbufs.blocked) {
		soapyll->outbufs.blocked = false;
		gensio_os_norun_waiter_wake(soapyll->outwaiter);
	    }
	}
	if (soapyll->inbufs.stopped && soapyll->outbufs.stopped)
	    gensio_soapy_sched_deferred_op(soapyll);
    }
    gensio_soapy_ll_unlock(soapyll);
    return err;
}

static int
gensio_soapy_ll_control(struct soapy_ll *soapyll, bool get, unsigned int option,
			char *data, gensiods *datalen)
{
    const char *s;

    switch(option) {
    case GENSIO_CONTROL_RADDR:
	if (!get)
	    return GE_NOTSUP;
	if (strtoul(data, NULL, 0) > 0)
	    return GE_NOTFOUND;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "soapy");
	return 0;

    case GENSIO_CONTROL_LADDR:
	if (!get)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%s",
				       soapyll->devname);
	return 0;

    case GENSIO_CONTROL_IN_RATE:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->inc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%u",
				       soapyll->realinc.samplerate);
	return 0;

    case GENSIO_CONTROL_OUT_RATE:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->outc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%u",
				       soapyll->realoutc.samplerate);
	return 0;

    case GENSIO_CONTROL_IN_BUFSIZE:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->inc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%lu",
				       (unsigned long) soapyll->inbufs.bufsize);
	return 0;

    case GENSIO_CONTROL_OUT_BUFSIZE:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->outc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%lu",
				      (unsigned long) soapyll->outbufs.bufsize);
	return 0;

    case GENSIO_CONTROL_IN_FORMAT:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->inc.channel < 0)
	    return GE_NOTSUP;
	s = soapyll->inc.format;
	goto get_si_format;

    case GENSIO_CONTROL_OUT_FORMAT:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->outc.channel < 0)
	    return GE_NOTSUP;
	s = soapyll->outc.format;
    get_si_format:
	s = stog_format(s);
	if (!s)
	    s = "unknown";
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%s", s);
	return 0;

    case GENSIO_CONTROL_DRAIN_COUNT: {
	unsigned int cbuf, i;
	unsigned long frames_left = 0;
	struct soapy_bufs *sb;

	if (!get)
	    return GE_NOTSUP;
	if (soapyll->outc.channel < 0)
	    return GE_NOTSUP;
	sb = &soapyll->outbufs;
	cbuf = sb->curbuf;
	for (i = 0; i < sb->numbufs; i++) {
	    frames_left += sb->bufsize;
	    cbuf++;
	    if (cbuf >= sb->bufslen)
		cbuf -= sb->bufslen;
	}
	
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%lu",
				       frames_left);
	return 0;
    }

    case GENSIO_CONTROL_IN_ANTENNA:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->inc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%s",
				       soapyll->realinc.antenna);
	return 0;

    case GENSIO_CONTROL_OUT_ANTENNA:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->outc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%s",
				       soapyll->realoutc.antenna);
	return 0;

    case GENSIO_CONTROL_IN_AGC:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->inc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%d",
				       soapyll->realinc.agc);
	return 0;

    case GENSIO_CONTROL_OUT_AGC:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->outc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%d",
				       soapyll->realoutc.agc);
	return 0;

    case GENSIO_CONTROL_IN_GAIN:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->inc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%f",
				       soapyll->realinc.gain);
	return 0;

    case GENSIO_CONTROL_OUT_GAIN:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->outc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%f",
				       soapyll->realoutc.gain);
	return 0;

    case GENSIO_CONTROL_IN_FREQUENCY: {
	double freq;
	char *end;

	if (soapyll->inc.channel < 0)
	    return GE_NOTSUP;
	if (!get) {
	    if (!data || !*data)
		return GE_INVAL;
	    freq = strtod(data, &end);
	    if (*end)
		return GE_INVAL;
	    if (SoapySDRDevice_setFrequency(soapyll->sdr, SOAPY_SDR_RX,
					    soapyll->inc.channel,
					    freq, NULL) != 0) {
		gensio_log(soapyll->o, GENSIO_LOG_INFO,
			   "soapy set rx frequency failed: %s\n",
			   SoapySDRDevice_lastError());
		return GE_INVAL;
	    }
	    soapyll->realinc.frequency =
		SoapySDRDevice_getFrequency(soapyll->sdr, SOAPY_SDR_RX,
					    soapyll->inc.channel);
	}
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%f",
				       soapyll->realinc.frequency);
	return 0;
    }

    case GENSIO_CONTROL_OUT_FREQUENCY: {
	double freq;
	char *end;

	if (soapyll->outc.channel < 0)
	    return GE_NOTSUP;
	if (!get) {
	    if (!data || !*data)
		return GE_INVAL;
	    freq = strtod(data, &end);
	    if (*end)
		return GE_INVAL;
	    if (SoapySDRDevice_setFrequency(soapyll->sdr, SOAPY_SDR_TX,
					    soapyll->outc.channel,
					    freq, NULL) != 0) {
		gensio_log(soapyll->o, GENSIO_LOG_INFO,
			   "soapy set rx frequency failed: %s\n",
			   SoapySDRDevice_lastError());
		return GE_INVAL;
	    }
	    soapyll->realoutc.frequency =
		SoapySDRDevice_getFrequency(soapyll->sdr, SOAPY_SDR_TX,
					    soapyll->outc.channel);
	}
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%f",
				       soapyll->realoutc.frequency);
	return 0;
    }

    case GENSIO_CONTROL_IN_BANDWIDTH:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->inc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%f",
				       soapyll->realinc.bandwidth);
	return 0;

    case GENSIO_CONTROL_OUT_BANDWIDTH:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->outc.channel < 0)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%f",
				       soapyll->realoutc.bandwidth);
	return 0;

    case GENSIO_CONTROL_IN_CHANNEL:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->inc.channel < 0)
	    return GE_NOTSUP;
	return 0;

    case GENSIO_CONTROL_OUT_CHANNEL:
	if (!get)
	    return GE_NOTSUP;
	if (soapyll->outc.channel < 0)
	    return GE_NOTSUP;
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
gensio_soapy_ll_do_free(struct soapy_ll *soapyll)
{
    gensio_soapy_ll_lock(soapyll);
    switch (soapyll->state) {
    case GENSIO_SOAPY_LL_IN_OPEN:
    case GENSIO_SOAPY_LL_OPEN:
	gensio_soapy_ll_close(soapyll, NULL, NULL);
	break;

    default:
	break;
    }
    gensio_soapy_ll_deref_and_unlock(soapyll);
    return 0;
}

static int
gensio_soapy_ll_func(struct gensio_ll *ll, int op,
		     gensiods *count,
		     void *buf, const void *cbuf,
		     gensiods buflen,
		     const char *const *auxdata)
{
    struct soapy_ll *soapyll = ll_to_soapy(ll);

    switch (op) {
    case GENSIO_LL_FUNC_SET_CALLBACK:
	soapyll->cb = (gensio_ll_cb) cbuf;
	soapyll->cb_data = buf;
	return 0;

    case GENSIO_LL_FUNC_WRITE_SG:
	return gensio_soapy_ll_write(soapyll, count, cbuf, buflen);

    case GENSIO_LL_FUNC_OPEN:
	return gensio_soapy_ll_open(soapyll, (gensio_ll_open_done) cbuf, buf);

    case GENSIO_LL_FUNC_CLOSE:
	return gensio_soapy_ll_close(soapyll, (gensio_ll_close_done) cbuf, buf);

    case GENSIO_LL_FUNC_SET_READ_CALLBACK: {
	bool enable = !!buflen;

	if (soapyll->inc.channel < 0)
	    /* Output only, just ignore. */
	    return 0;

	gensio_soapy_ll_lock(soapyll);
	if (soapyll->read_enabled != enable) {
	    soapyll->read_enabled = enable;
	    if (soapyll->state == GENSIO_SOAPY_LL_OPEN) {
		if (enable)
		    gensio_soapy_do_read_enable(soapyll);
	    }
	}
	gensio_soapy_ll_unlock(soapyll);
	return 0;
    }

    case GENSIO_LL_FUNC_SET_WRITE_CALLBACK: {
	bool enable = !!buflen;

	if (soapyll->outc.channel < 0)
	    /* Input only, just ignore. */
	    return 0;

	gensio_soapy_ll_lock(soapyll);
	if (soapyll->write_enabled != enable) {
	    soapyll->write_enabled = enable;
	    if (soapyll->state == GENSIO_SOAPY_LL_OPEN)
		gensio_soapy_do_write_enable(soapyll);
	}
	gensio_soapy_ll_unlock(soapyll);
	return 0;
    }

    case GENSIO_LL_FUNC_FREE:
	return gensio_soapy_ll_do_free(soapyll);

    case GENSIO_LL_FUNC_DISABLE:
	soapyll->inbufs.stop = true;
	gensio_os_norun_waiter_wake(soapyll->inwaiter);
	soapyll->outbufs.stop = true;
	gensio_os_norun_waiter_wake(soapyll->outwaiter);
	soapyll->state = GENSIO_SOAPY_LL_CLOSED;
	return 0;

    case GENSIO_LL_FUNC_CONTROL:
	return gensio_soapy_ll_control(soapyll, *((bool *) cbuf), buflen, buf,
				       count);

    }

    return GE_NOTSUP;
}

struct soapy_info {
    const char *devname;
    unsigned int inbufsize;
    unsigned int innumbufs;
    unsigned int outbufsize;
    unsigned int outnumbufs;
    const char *inantenna;
    const char *outantenna;
    struct soapy_config inc;
    struct soapy_config outc;
};

static int
gensio_soapy_ll_alloc(struct gensio_pparm_info *p,
		      struct gensio_os_funcs *o,
		      struct soapy_info *info,
		      struct gensio_ll **newll)
{
    int err;
    unsigned int errcount = 0;
    struct soapy_ll *soapyll;
    unsigned int i;

    if (!info->devname) {
	gensio_pparm_slog(p, "No device info specified");
	return GE_INVAL;
    }

    if (info->inc.channel < 0 && info->outc.channel < 0) {
	gensio_pparm_slog(p, "Must set an input and/or output channel");
	return GE_INVAL;
    }

    if (info->inc.channel >= 0) {
	if (info->inbufsize == 0) {
	    gensio_pparm_slog(p, "Input buffer size must be > 0");
	    errcount++;
	}
	if (info->innumbufs == 0) {
	    gensio_pparm_slog(p, "Input buffer count must be > 0");
	    errcount++;
	}
    }
    if (info->outc.channel >= 0) {
	if (info->outbufsize == 0) {
	    gensio_pparm_slog(p, "Output buffer size must be > 0");
	    errcount++;
	}
	if (info->outnumbufs == 0) {
	    gensio_pparm_slog(p, "Output buffer count must be > 0");
	    errcount++;
	}
    }
    if (errcount > 0)
	return GE_INVAL;

    soapyll = o->zalloc(o, sizeof(*soapyll));
    if (!soapyll)
	return GE_NOMEM;

    soapyll->refcount = 1;
    soapyll->o = o;
    soapyll->inbufs.stopped = true;
    soapyll->outbufs.stopped = true;

    soapyll->inc = info->inc;
    soapyll->outc = info->outc;

    soapyll->devname = gensio_strdup(o, info->devname);
    if (!soapyll->devname)
	goto out_nomem;

    if (info->inantenna) {
	soapyll->inc.antenna = gensio_strdup(o, info->inc.antenna);
	if (!soapyll->inc.antenna)
	    goto out_nomem;
    }
    if (info->outantenna) {
	soapyll->outc.antenna = gensio_strdup(o, info->outc.antenna);
	if (!soapyll->outc.antenna)
	    goto out_nomem;
    }

    if (info->inc.format) {
	soapyll->inc.format = gtos_format(info->inc.format);
	if (!soapyll->inc.format) {
	    gensio_pparm_log(p, "unknown format: %s", info->inc.format);
	    goto out_nomem;
	}
    } else {
	soapyll->inc.format = SOAPY_SDR_CF32;
    }

    if (info->outc.format) {
	soapyll->outc.format = gtos_format(info->outc.format);
	if (!soapyll->outc.format) {
	    gensio_pparm_log(p, "unknown format: %s", info->outc.format);
	    goto out_nomem;
	}
    } else {
	soapyll->outc.format = SOAPY_SDR_CF32;
    }

    soapyll->inbufs.bufslen = info->innumbufs;
    soapyll->inbufs.bufsize = info->inbufsize;
    soapyll->inbufs.framesize = SoapySDR_formatToSize(soapyll->inc.format);
    soapyll->inbufs.bufbsize = (soapyll->inbufs.bufsize
				* soapyll->inbufs.framesize);
    soapyll->inbufs.bufs = o->zalloc(o, (soapyll->inbufs.bufslen
					 * sizeof(unsigned char *)));
    if (!soapyll->inbufs.bufs)
	goto out_nomem;
    for (i = 0; i < soapyll->inbufs.bufslen; i++) {
	soapyll->inbufs.bufs[i] = o->zalloc(o, soapyll->inbufs.bufbsize);
	if (!soapyll->inbufs.bufs[i])
	    goto out_nomem;
    }

    soapyll->outbufs.bufslen = info->outnumbufs;
    soapyll->outbufs.bufsize = info->outbufsize;
    soapyll->outbufs.framesize = SoapySDR_formatToSize(soapyll->outc.format);
    soapyll->outbufs.bufbsize = (soapyll->inbufs.bufsize
				 * soapyll->outbufs.framesize);
    soapyll->outbufs.bufs = o->zalloc(o, (soapyll->outbufs.bufslen
					  * sizeof(unsigned char *)));
    if (!soapyll->outbufs.bufs)
	goto out_nomem;
    for (i = 0; i < soapyll->outbufs.bufslen; i++) {
	soapyll->outbufs.bufs[i] = o->zalloc(o, soapyll->outbufs.bufbsize);
	if (!soapyll->outbufs.bufs[i])
	    goto out_nomem;
    }

    soapyll->sdr = SoapySDRDevice_makeStrArgs(info->devname);
    if (!soapyll->sdr) {
	gensio_pparm_log(p, "Error allocating soapy input device: %s",
			 SoapySDRDevice_lastError());
	goto out_nomem;
    }

    if (soapyll->inc.channel >= 0) {
	err = gensio_soapy_config(soapyll, p, SOAPY_SDR_RX,
				  &soapyll->inc, &soapyll->realinc,
				  &soapyll->instream);
	if (err)
	    goto out_err;
    }

    if (soapyll->outc.channel >= 0) {
	err = gensio_soapy_config(soapyll, p, SOAPY_SDR_TX,
				  &soapyll->outc, &soapyll->realoutc,
				  &soapyll->outstream);
	if (err)
	    goto out_err;
    }

    soapyll->runner = o->alloc_runner(o, gensio_soapy_ll_deferred_op, soapyll);
    if (!soapyll->runner)
	goto out_nomem;

    soapyll->lock = o->alloc_lock(o);
    if (!soapyll->lock)
	goto out_nomem;

    soapyll->inwaiter = gensio_os_alloc_norun_waiter(o);
    if (!soapyll->inwaiter)
	goto out_nomem;
    err = gensio_os_new_thread(o, gensio_soapy_inthread,
			       soapyll, &soapyll->inthread);
    if (err) {
	if (err == GE_NOTSUP)
	    gensio_pparm_slog(p, "soapy gensio requires threaded os handler");
	goto out_err;
    }

    soapyll->outwaiter = gensio_os_alloc_norun_waiter(o);
    if (!soapyll->outwaiter)
	goto out_nomem;
    err = gensio_os_new_thread(o, gensio_soapy_outthread,
			       soapyll, &soapyll->outthread);
    if (err)
	goto out_err;

    soapyll->ll = gensio_ll_alloc_data(o, gensio_soapy_ll_func, soapyll);
    if (!soapyll->ll)
	goto out_nomem;

    *newll = soapyll->ll;

    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    gensio_soapy_ll_free(soapyll);
    return err;
}

static int
soapy_gensio_alloc(const void *gdata, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **rio)
{
    int err;
    struct soapy_info info;
    struct gensio_ll *ll;
    struct gensio *io;
    gensiods dsval;
    unsigned int uival;
    double dval;
    bool bval;
    const char *sval;
    int i;
    GENSIO_DECLARE_PPGENSIO(p, o, cb, "soapy", user_data);

    memset(&info, 0, sizeof(info));
    info.devname = gdata;

    info.inbufsize = 1024;
    info.innumbufs = 100;

    info.outbufsize = 1024;
    info.outnumbufs = 100;

    info.inc.frequency = 0.0;
    info.outc.frequency = 0.0;
    info.inc.bandwidth = 0.0;
    info.outc.bandwidth = 0.0;
    info.inc.samplerate = 48000;
    info.outc.samplerate = 48000;
    info.inc.gain = 0.0;
    info.outc.gain = 0.0;
    info.inc.format = "floatc";
    info.outc.format = "floatc";
    info.inc.channel = -1;
    info.outc.channel = -1;

    for (i = 0; args && args[i]; i++) {
	if (gensio_pparm_ds(&p, args[i], "inbufsize", &dsval) > 0) {
	    info.inbufsize = dsval;
	    continue;
	}
	if (gensio_pparm_ds(&p, args[i], "outbufsize", &dsval) > 0) {
	    info.outbufsize = dsval;
	    continue;
	}
	if (gensio_pparm_ds(&p, args[i], "bufsize", &dsval) > 0) {
	    info.inbufsize = dsval;
	    info.outbufsize = dsval;
	    continue;
	}
	if (gensio_pparm_uint(&p, args[i], "innbufs", &info.innumbufs) > 0)
	    continue;
	if (gensio_pparm_uint(&p, args[i], "outnbufs", &info.outnumbufs) > 0)
	    continue;
	if (gensio_pparm_uint(&p, args[i], "nbufs", &uival) > 0) {
	    info.innumbufs = uival;
	    info.outnumbufs = uival;
	    continue;
	}

	if (gensio_pparm_int(&p, args[i], "inchannel", &info.inc.channel) > 0)
	    continue;
	if (gensio_pparm_int(&p, args[i], "outchannel", &info.outc.channel) > 0)
	    continue;

	if (gensio_pparm_uint(&p, args[i], "rate", &uival) > 0) {
	    info.inc.samplerate = uival;
	    info.outc.samplerate = uival;
	    continue;
	}
	if (gensio_pparm_uint(&p, args[i], "inrate", &info.inc.samplerate) > 0)
	    continue;
	if (gensio_pparm_uint(&p, args[i], "outrate",
			      &info.outc.samplerate) > 0)
	    continue;

	if (gensio_pparm_value(&p, args[i], "format", &sval) > 0) {
	    info.inc.format = sval;
	    info.outc.format = sval;
	    continue;
	}
	if (gensio_pparm_value(&p, args[i], "informat", &info.inc.format) > 0)
	    continue;
	if (gensio_pparm_value(&p, args[i], "outformat", &info.outc.format) > 0)
	    continue;

	if (gensio_pparm_double(&p, args[i], "frequency", &dval) > 0) {
	    info.inc.frequency = dval;
	    info.outc.frequency = dval;
	    continue;
	}
	if (gensio_pparm_double(&p, args[i], "infrequency",
				&info.inc.frequency) > 0)
	    continue;
	if (gensio_pparm_double(&p, args[i], "outfrequency",
				&info.outc.frequency) > 0)
	    continue;

	if (gensio_pparm_double(&p, args[i], "bandwidth", &dval) > 0) {
	    info.inc.bandwidth = dval;
	    info.outc.bandwidth = dval;
	    continue;
	}
	if (gensio_pparm_double(&p, args[i], "inbandwidth",
				&info.inc.bandwidth) > 0)
	    continue;
	if (gensio_pparm_double(&p, args[i], "outbandwidth",
				&info.outc.bandwidth) > 0)
	    continue;

	if (gensio_pparm_bool(&p, args[i], "agc", &bval) > 0) {
	    info.inc.agc = bval;
	    info.outc.agc = bval;
	    continue;
	}
	if (gensio_pparm_bool(&p, args[i], "inagc", &info.inc.agc) > 0)
	    continue;
	if (gensio_pparm_bool(&p, args[i], "outagc", &info.outc.agc) > 0)
	    continue;

	if (gensio_pparm_double(&p, args[i], "gain", &dval) > 0) {
	    info.inc.gainset = true;
	    info.inc.gain = dval;
	    info.outc.gainset = true;
	    info.outc.gain = dval;
	    continue;
	}
	if (gensio_pparm_double(&p, args[i], "ingain", &info.inc.gain) > 0) {
	    info.inc.gainset = true;
	    continue;
	}
	if (gensio_pparm_double(&p, args[i], "outgain", &info.outc.gain) > 0) {
	    info.outc.gainset = true;
	    continue;
	}

	if (gensio_pparm_value(&p, args[i], "antenna", &sval) > 0) {
	    info.inantenna = sval;
	    info.outantenna = sval;
	    continue;
	}
	if (gensio_pparm_value(&p, args[i], "inantenna", &info.inantenna) > 0)
	    continue;
	if (gensio_pparm_value(&p, args[i], "outantenna", &info.outantenna) > 0)
	    continue;

	gensio_pparm_unknown_parm(&p, args[i]);
	return GE_INVAL;
    }

    err = gensio_soapy_ll_alloc(&p, o, &info, &ll);
    if (err)
	goto out_err;

    io = base_gensio_alloc(o, ll, NULL, NULL, "soapy", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	return GE_NOMEM;
    }

    *rio = io;
    return 0;

 out_err:
    return err;
}

static int
str_to_soapy_gensio(const char *str, const char * const args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **new_gensio)
{
    return soapy_gensio_alloc(str, args, o, cb, user_data, new_gensio);
}

int
gensio_init_soapy(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "soapy", str_to_soapy_gensio, soapy_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
