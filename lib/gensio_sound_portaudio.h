/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2023  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <portaudio.h>

struct win_sound_format_cnv {
    enum gensio_sound_fmt_type gformat;
    PaSampleFormat fmt;
} pa_sound_fmt_cnv[] = {
    {
	.gformat = GENSIO_SOUND_FMT_FLOAT,
	.fmt = paFloat32,
    },
    {
	.gformat = GENSIO_SOUND_FMT_S32,
	.fmt = paInt32,
    },
    {
	.gformat = GENSIO_SOUND_FMT_S24,
	.fmt = paInt24,
    },
    {
	.gformat = GENSIO_SOUND_FMT_S16,
	.fmt = paInt16,
    },
    {
	.gformat = GENSIO_SOUND_FMT_S8,
	.fmt = paInt8,
    },
    { .gformat = GENSIO_SOUND_FMT_UNKNOWN }
};

static int
i_gensio_pa_err_to_err(struct gensio_os_funcs *o, PaErrorCode pa_err,
		       const char *caller, const char *file,
		       unsigned int lineno)
{
    int err;

    switch (pa_err) {
    case paNotInitialized:			err = GE_NOTREADY; break;
    case paInvalidChannelCount:			err = GE_INVAL; break;
    case paInvalidSampleRate:			err = GE_INVAL; break;
    case paInvalidDevice:			err = GE_INVAL; break;
    case paInvalidFlag:				err = GE_INVAL; break;
    case paSampleFormatNotSupported:		err = GE_INVAL; break;
    case paBadIODeviceCombination:		err = GE_INVAL; break;
    case paInsufficientMemory:			err = GE_NOMEM; break;
    case paBufferTooBig:			err = GE_INVAL; break;
    case paBufferTooSmall:			err = GE_INVAL; break;
    case paNullCallback:			err = GE_INVAL; break;
    case paBadStreamPtr:			err = GE_INVAL; break;
    case paTimedOut:				err = GE_TIMEDOUT; break;

    case paInternalError:
    case paDeviceUnavailable:
    case paIncompatibleHostApiSpecificStreamInfo:
    case paStreamIsStopped:
    case paStreamIsNotStopped:
    case paInputOverflowed:
    case paOutputUnderflowed:
    case paHostApiNotFound:
    case paInvalidHostApi:
    case paCanNotReadFromACallbackStream:
    case paCanNotWriteToACallbackStream:
    case paCanNotReadFromAnOutputOnlyStream:
    case paCanNotWriteToAnInputOnlyStream:
    case paIncompatibleStreamHostApi:
    case paBadBufferPtr:
    case paUnanticipatedHostError:
    default:					err = GE_OSERR; break;
    }

    if (err == GE_OSERR || err == GE_INVAL) {
	const char *errstr = Pa_GetErrorText(pa_err);
      
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled portaudio error in %s:%d: %s (%d)",
		   caller, lineno, errstr, pa_err);
    }
    
    return err;
}
#define gensio_pa_err_to_err(o, pa_err)				\
    i_gensio_pa_err_to_err(o, pa_err, __func__, __FILE__, __LINE__)

static int
gensio_sound_pa_get_wavefmt(enum gensio_sound_fmt_type gformat,
			    PaSampleFormat *fmt)
{
    unsigned int i;

    for (i = 0; pa_sound_fmt_cnv[i].gformat != GENSIO_SOUND_FMT_UNKNOWN;
		i++) {
	if (gformat == pa_sound_fmt_cnv[i].gformat)
	    break;
    }
    if (gformat != pa_sound_fmt_cnv[i].gformat)
	return GE_INVAL;

    *fmt = pa_sound_fmt_cnv[i].fmt;
    return 0;
}

struct pa_sound_info {
    PaStream *stream;

    int devidx;

    /*
     * Used to avoid stutter at start, wait until we have a few buffers
     * before starting the transmitter.
     */
    bool started;

    double latency;

    /* Position of pcm data, in cnv.buf, both receive and transmit. */
    unsigned int size; /* Total buffer size in bytes. */
    unsigned int pos; /* Output position in bytes. */
    unsigned int len; /* Available data in cnv.buf, in bytes. */
};

#define BASE_LATENCY .1

static unsigned long
gensio_sound_pa_drain_count(struct sound_info *si)
{
    struct pa_sound_info *w = si->pinfo;

    /*
     * FIXME - This isn't entirely accurate.  You really need to get
     * the number of frames outstanding in portaudio, but there
     * doesn't seem to be a way to do it.  You can't call
     * Pa_GetStreamWriteAvailable on a callback stream.
     */
    return w->latency * si->samplerate + w->len / si->cnv.pframesize;
}

static void
gensio_sound_pa_api_close_dev(struct sound_info *si)
{
    struct pa_sound_info *w = si->pinfo;

    if (!w)
	return;

    Pa_CloseStream(w->stream);
    w->stream = NULL;
}

static void
gensio_sound_pa_copy_sample(const unsigned char **in, unsigned char **out,
			    struct sound_cnv_info *info)
{
    memcpy(*out, *in, info->usize);
    *out += info->usize;
    *in += info->usize;
}

static void
gensio_sound_pa_process_read_buffer(struct sound_info *si)
{
    struct pa_sound_info *w = si->pinfo;
    const unsigned char *inbuf;
    unsigned char *outbuf;
    gensiods psize;
    void (*convin)(const unsigned char **in, unsigned char **out,
		   struct sound_cnv_info *info);

    /* Not enough data or data still left for the user to pick up. */
    if (w->len < si->bufsize * si->cnv.pframesize || si->ready)
	return;

    psize = si->cnv.psize;
    if (si->cnv.enabled)
	convin = si->cnv.convin;
    else
	convin = gensio_sound_pa_copy_sample;

    inbuf = si->cnv.buf + w->pos;
    outbuf = si->buf + (si->len * si->framesize);

    while (w->len > 0 && si->len < si->bufsize) {
	convin(&inbuf, &outbuf, &si->cnv);
	si->len++;
	w->len -= psize;
	w->pos += psize;
	if (w->pos >= w->size)
	    w->pos = 0;
    }

    si->ready = true;
    gensio_sound_sched_deferred_op(si->soundll);
}

static void
gensio_sound_pa_api_next_read(struct sound_info *si)
{
    gensio_sound_pa_process_read_buffer(si);
}

static void
gensio_sound_pa_api_set_read(struct sound_info *si, bool enable)
{
    if (enable)
	gensio_sound_pa_process_read_buffer(si);
}

static void
gensio_sound_pa_api_set_write(struct sound_info *si, bool enable)
{
    /* Nothing to do here. */
}

static void
gensio_sound_pa_stream_finished(void *userData)
{
    struct sound_info *si = userData;

    gensio_sound_ll_lock(si->soundll);
    si->soundll->do_close_now = true;
    gensio_sound_sched_deferred_op(si->soundll);
    gensio_sound_ll_unlock(si->soundll);
}

static unsigned int
gensio_sound_pa_api_start_close(struct sound_info *si)
{
    struct pa_sound_info *w = si->pinfo;
    unsigned int rv = 0;
    int err;

    if (si->is_input)
	return 0; /* Nothing to do to stop the input. */
    if (!w->started)
	return 0; /* We haven't queued anything, not worth sending. */

    if (w->len > 0)
	rv++; /* Data in our buffer to write. */

    err = Pa_SetStreamFinishedCallback(w->stream,
				       gensio_sound_pa_stream_finished);
    if (err) {
	rv = 0;
	Pa_AbortStream(w->stream);
    } else {
	rv++;
    }

    return rv;
}

static int
gensio_sound_pa_api_write(struct sound_info *out, gensiods *rcount,
			  const struct gensio_sg *sg, gensiods sglen)
{
    struct pa_sound_info *w = out->pinfo;
    gensiods count = 0, i, usize, psize, ppos;
    void (*convout)(const unsigned char **in, unsigned char **out,
		    struct sound_cnv_info *info);
    unsigned char *obuf;
    gensiods obuflen = w->size - w->len;

    usize = out->cnv.usize;
    if (out->cnv.enabled) {
	psize = out->cnv.psize;
	convout = out->cnv.convout;
    } else {
	convout = gensio_sound_pa_copy_sample;
	psize = usize;
    }

    ppos = w->pos + w->len;
    if (ppos >= w->size)
	ppos -= w->size;
    obuf = out->cnv.buf + ppos;
    for (i = 0; obuflen > 0 && i < sglen; i++) {
	const unsigned char *ibuf = sg[i].buf;
	gensiods ibuflen = sg[i].buflen;

	while (ibuflen > 0 && obuflen > 0) {
	    convout(&ibuf, &obuf, &out->cnv);
	    obuflen -= psize;
	    ibuflen -= usize;
	    w->len += psize;
	    ppos += psize;
	    if (ppos >= w->size) {
		ppos = 0;
		obuf = out->cnv.buf;
	    }
	    count += usize;
	}
    }

    /* Is there a buffer's worth of free space to write? */
    out->ready = w->size - w->len >= out->bufsize * out->cnv.pframesize;

    /* Wait until we have two buffers before starting the sender. */
    if (!w->started && w->len > out->bufsize * out->cnv.pframesize * 2) {
	PaError perr;

	w->started = true;
	perr = Pa_StartStream(w->stream);
	if (perr)
	    return gensio_pa_err_to_err(out->soundll->o, perr);
    }

    if (rcount)
	*rcount = count;
    return 0;
}

static int
gensio_sound_pa_stream_cb(const void *input, void *output,
			  unsigned long frameCount,
			  const PaStreamCallbackTimeInfo* timeInfo,
			  PaStreamCallbackFlags statusFlags,
			  void *userData)
{
    struct sound_info *si = userData;
    struct pa_sound_info *w = si->pinfo;
    gensiods datalen = frameCount * si->cnv.pframesize;
    gensiods ppos, to_copy;
    const unsigned char *inbuf;
    unsigned char *outbuf;

    gensio_sound_ll_lock(si->soundll);
    if (si->is_input) {
	if (w->len + datalen > w->size)
	    /* Not enough room, just drop it. */
	    goto out_unlock;

	inbuf = input;
	ppos = w->pos + w->len; /* Place to put new data. */
	if (ppos >= w->size)
	    ppos -= w->size;
	outbuf = si->cnv.buf + ppos;
	if (ppos + datalen > w->size) {
	    to_copy = w->size - ppos;
	    memcpy(outbuf, inbuf, to_copy);
	    w->len += to_copy;
	    datalen -= to_copy;
	    inbuf += to_copy;
	    outbuf = si->cnv.buf;
	}
	memcpy(outbuf, inbuf, datalen);
	w->len += datalen;
	gensio_sound_pa_process_read_buffer(si);
    } else {
	if (w->len < datalen) {
	    /* Not enough room, just send zeros. */
	    memset(output, 0, datalen);
	    goto out_unlock;
	}

	outbuf = output;
	inbuf = si->cnv.buf + w->pos;
	if (w->pos + datalen > w->size) {
	    to_copy = w->size - w->pos;
	    w->len -= datalen;
	    memcpy(outbuf, inbuf, to_copy);
	    datalen -= to_copy;
	    w->pos = 0;
	    outbuf = si->cnv.buf;
	    inbuf += to_copy;
	}
	memcpy(output, inbuf, datalen);
	w->len -= datalen;
	w->pos += datalen;
	if (w->pos >= w->size)
	    w->pos = 0;

	/* Is there a buffer's worth of free space to write? */
	si->ready = w->size - w->len >= si->bufsize * si->cnv.pframesize;
    }
    gensio_sound_sched_deferred_op(si->soundll);
 out_unlock:
    gensio_sound_ll_unlock(si->soundll);

    return paContinue;
}

static int
gensio_sound_pa_api_open_dev(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct pa_sound_info *w = si->pinfo;
    PaSampleFormat pa_fmt;
    enum gensio_sound_fmt_type pfmt;
    PaStreamParameters parms, *iparms = NULL, *oparms = NULL;
    const PaStreamInfo *streaminfo;
    int err;
    PaError perr;

    if (si->cnv.pfmt != GENSIO_SOUND_FMT_UNKNOWN)
	pfmt = si->cnv.pfmt;
    else
	pfmt = si->cnv.ufmt;

    err = gensio_sound_pa_get_wavefmt(pfmt, &pa_fmt);
    if (err)
	return err;

    memset(&parms, 0, sizeof(parms));
    parms.device = w->devidx;
    parms.channelCount = si->chans;
    parms.sampleFormat = pa_fmt;
    parms.suggestedLatency = BASE_LATENCY;
    if (si->is_input)
	iparms = &parms;
    else
	oparms = &parms;

    si->cnv.pframesize = si->cnv.psize * si->chans;
    if (si->is_input) {
	w->size = si->num_bufs * si->bufsize * si->cnv.pframesize;
	si->cnv.buf = o->zalloc(o, w->size);
    } else {
	/*
	 * For output buffers, we allocate two buffers worth of data
	 * for our buffering.  The rest of the buffering should hannen
	 * in portaudio.
	 */
	w->size = si->num_bufs * si->bufsize * si->cnv.pframesize;
	si->cnv.buf = o->zalloc(o, w->size);
    }
    if (!si->cnv.buf)
	return GE_NOMEM;

    w->len = 0;
    w->pos = 0;

    perr = Pa_OpenStream(&w->stream, iparms, oparms,
			 si->samplerate, si->bufsize, 0,
			 gensio_sound_pa_stream_cb, si);
    if (perr) {
	err = gensio_pa_err_to_err(o, perr);
	o->free(o, si->cnv.buf);
	si->cnv.buf = NULL;
	return err;
    }

    streaminfo = Pa_GetStreamInfo(w->stream);
    if (si->is_input) {
	w->latency = streaminfo->inputLatency;
    } else {
	w->latency = streaminfo->outputLatency;
	si->ready = true;
    }

    if (si->is_input) {
	perr = Pa_StartStream(w->stream);
	if (perr) {
	    err = gensio_pa_err_to_err(o, perr);
	    Pa_CloseStream(w->stream);
	    w->stream = NULL;
	    o->free(o, si->cnv.buf);
	    si->cnv.buf = NULL;
	    return err;
	}
	w->started = true;
    }

    return 0;
}

static PaDeviceIndex
gensio_sound_pa_lookup_dev_by_name(char *name, bool is_input)
{
    PaDeviceIndex i, ndevs;

    ndevs = Pa_GetDeviceCount();
    for (i = 0; i < ndevs; i++) {
	const struct PaDeviceInfo *padev = Pa_GetDeviceInfo(i);
	char tstr[100];

	if (!padev)
	    continue;
	if (is_input && padev->maxInputChannels == 0)
	    continue;
	if (!is_input && padev->maxOutputChannels == 0)
	    continue;

	snprintf(tstr, sizeof(tstr), "%d:%s", i, padev->name);
	if (strstr(tstr, name))
	    return i;
    }

    return -1;
}

static int
gensio_sound_pa_api_setup(struct gensio_pparm_info *p,
			  struct sound_info *si, struct gensio_sound_info *io)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct pa_sound_info *w = NULL;
    int err;
    PaError pa_err;

    pa_err = Pa_Initialize();
    if (pa_err) {
	err = gensio_pa_err_to_err(o, pa_err);
	return err;
    }

    si->cardname = gensio_strdup(o, io->devname);
    if (!si->cardname)
	goto out_nomem;

    w = o->zalloc(o, sizeof(struct pa_sound_info));
    if (!w)
	goto out_nomem;
    si->pinfo = w;

    w->devidx = gensio_sound_pa_lookup_dev_by_name(si->cardname, si->is_input);
    if (w->devidx == -1) {
	err = GE_NOTFOUND;
	goto out_err;
    }

    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (si->cardname) {
	o->free(o, si->cardname);
	si->cardname = NULL;
    }
    if (w) {
	si->pinfo = NULL;
	o->free(o, w);
    }
    Pa_Terminate();
    return err;
}

static void
gensio_sound_pa_api_cleanup(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct pa_sound_info *w = si->pinfo;

    gensio_sound_pa_api_close_dev(si);
    if (w) {
	o->free(o, w);
	si->pinfo = NULL;
    }
    Pa_Terminate();
}

static int
gensio_sound_pa_api_devices(struct gensio_os_funcs *o,
			    char ***rnames, char ***rspecs, gensiods *rcount)
{
    gensiods count = 0, size = 0;
    PaDeviceIndex i, ndevs;
    char **names = NULL, **specs = NULL;
    char *name = NULL, *spec = NULL;
    int err;
    PaError pa_err;

    pa_err = Pa_Initialize();
    if (pa_err) {
	err = gensio_pa_err_to_err(o, pa_err);
	return err;
    }

    ndevs = Pa_GetDeviceCount();
    names = calloc(ndevs, sizeof(char *));
    if (!names)
	goto out_nomem;
    specs = calloc(ndevs, sizeof(char *));
    if (!specs)
	goto out_nomem;

    for (i = 0; i < ndevs; i++) {
	const struct PaDeviceInfo *padev = Pa_GetDeviceInfo(i);
	char tstr[100];

	if (!padev) {
	    err = GE_INCONSISTENT;
	    goto out_err;
	}

	snprintf(tstr, sizeof(tstr), "%d:%s", i, padev->name);
	name = strdup(tstr);
	if (!name)
	    goto out_nomem;
	if (padev->maxInputChannels && padev->maxOutputChannels)
	    snprintf(tstr, sizeof(tstr), "input,inchans=%d,output,outchans=%d",
		     padev->maxInputChannels, padev->maxOutputChannels);
	else if (padev->maxInputChannels)
	    snprintf(tstr, sizeof(tstr), "input,inchans=%d",
		     padev->maxInputChannels);
	else if (padev->maxOutputChannels)
	    snprintf(tstr, sizeof(tstr), "output,outchans=%d",
		     padev->maxOutputChannels);
	else
	    tstr[0] = '\0';
	spec = strdup(tstr);
	if (!spec)
	    goto out_nomem;
	if (count >= size) {
	    if (extend_sound_devs(&names, &specs, &size))
		goto out_nomem;
	}
	names[count] = name;
	name = NULL;
	specs[count] = spec;
	spec = NULL;
	count++;
    }

    *rnames = names;
    *rspecs = specs;
    *rcount = count;

    Pa_Terminate();

    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    if (name)
	free(name);
    if (spec)
	free(spec);
    gensio_sound_devices_free(names, specs, count);
    Pa_Terminate();
    return err;
}

static struct sound_type pa_sound_type = {
    "portaudio",
    .setup = gensio_sound_pa_api_setup,
    .cleanup = gensio_sound_pa_api_cleanup,
    .open_dev = gensio_sound_pa_api_open_dev,
    .close_dev = gensio_sound_pa_api_close_dev,
    .write = gensio_sound_pa_api_write,
    .set_write_enable = gensio_sound_pa_api_set_write,
    .set_read_enable = gensio_sound_pa_api_set_read,
    .next_read = gensio_sound_pa_api_next_read,
    .start_close = gensio_sound_pa_api_start_close,
    .drain_count = gensio_sound_pa_drain_count,
    .devices = gensio_sound_pa_api_devices
};

#define PORTAUDIO_INIT &pa_sound_type,
