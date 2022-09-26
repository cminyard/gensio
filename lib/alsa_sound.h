/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2022  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */


#include <alsa/asoundlib.h>
#include <gensio/gensio_class.h>

struct alsa_info {
    snd_pcm_t *pcm;
    /* File descriptor info from ALSA. */
    struct pollfd *fds;
    struct gensio_iod **iods;
    unsigned int nrfds;
    struct gensio_timer *close_timer;
};

static void
gensio_sound_alsa_api_close_dev(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct alsa_info *a = si->pinfo;
    unsigned int i;

    if (!a)
	return;

    for (i = 0; a->iods && i < a->nrfds; i++) {
	if (!a->iods[i])
	    continue;
	if (!si->soundll->stream_running)
	    o->clear_fd_handlers_norpt(a->iods[i]);
	o->release_iod(a->iods[i]);
    }

    if (a->pcm) {
	snd_pcm_close(a->pcm);
	a->pcm = NULL;
    }
    if (a->fds) {
	o->free(o, a->fds);
	a->fds = NULL;
    }
    if (a->iods) {
	o->free(o, a->iods);
	a->iods = NULL;
    }
    a->nrfds = 0;
}

struct alsa_sound_format_cnv {
    enum gensio_sound_fmt_type gformat;
    snd_pcm_format_t format;
} alsa_sound_format_cnv[] = {
    { GENSIO_SOUND_FMT_DOUBLE,SND_PCM_FORMAT_FLOAT64 },
    { GENSIO_SOUND_FMT_FLOAT, SND_PCM_FORMAT_FLOAT },
    { GENSIO_SOUND_FMT_S32, SND_PCM_FORMAT_S32 },
    { GENSIO_SOUND_FMT_S24, SND_PCM_FORMAT_S24 },
    { GENSIO_SOUND_FMT_S16, SND_PCM_FORMAT_S16 },
    { GENSIO_SOUND_FMT_S8, SND_PCM_FORMAT_S8 },
    { GENSIO_SOUND_FMT_U32, SND_PCM_FORMAT_U32 },
    { GENSIO_SOUND_FMT_U24, SND_PCM_FORMAT_U24 },
    { GENSIO_SOUND_FMT_U16, SND_PCM_FORMAT_U16 },
    { GENSIO_SOUND_FMT_U8, SND_PCM_FORMAT_U8 },
    { GENSIO_SOUND_FMT_DOUBLE_BE, SND_PCM_FORMAT_FLOAT64_BE },
    { GENSIO_SOUND_FMT_FLOAT_BE, SND_PCM_FORMAT_FLOAT_BE },
    { GENSIO_SOUND_FMT_S32_BE, SND_PCM_FORMAT_S32_BE },
    { GENSIO_SOUND_FMT_U32_BE, SND_PCM_FORMAT_U32_BE },
    { GENSIO_SOUND_FMT_S24_BE, SND_PCM_FORMAT_S24_BE },
    { GENSIO_SOUND_FMT_U24_BE, SND_PCM_FORMAT_U24_BE },
    { GENSIO_SOUND_FMT_S16_BE, SND_PCM_FORMAT_S16_BE },
    { GENSIO_SOUND_FMT_U16_BE, SND_PCM_FORMAT_U16_BE },
    { GENSIO_SOUND_FMT_DOUBLE_LE, SND_PCM_FORMAT_FLOAT64_LE },
    { GENSIO_SOUND_FMT_FLOAT_LE, SND_PCM_FORMAT_FLOAT_LE },
    { GENSIO_SOUND_FMT_S32_LE, SND_PCM_FORMAT_S32_LE },
    { GENSIO_SOUND_FMT_U32_LE, SND_PCM_FORMAT_U32_LE },
    { GENSIO_SOUND_FMT_S24_LE, SND_PCM_FORMAT_S24_LE },
    { GENSIO_SOUND_FMT_U24_LE, SND_PCM_FORMAT_U24_LE },
    { GENSIO_SOUND_FMT_S16_LE, SND_PCM_FORMAT_S16_LE },
    { GENSIO_SOUND_FMT_U16_LE, SND_PCM_FORMAT_U16_LE },

    { GENSIO_SOUND_FMT_UNKNOWN }
};

static enum gensio_sound_fmt_type fallback_order[] = {
    GENSIO_SOUND_FMT_DOUBLE,
    GENSIO_SOUND_FMT_DOUBLE_ALT,
    GENSIO_SOUND_FMT_S32,
    GENSIO_SOUND_FMT_U32,
    GENSIO_SOUND_FMT_S32_ALT,
    GENSIO_SOUND_FMT_U32_ALT,
    GENSIO_SOUND_FMT_FLOAT,
    GENSIO_SOUND_FMT_FLOAT_ALT,
    GENSIO_SOUND_FMT_S16,
    GENSIO_SOUND_FMT_U16,
    GENSIO_SOUND_FMT_S16_ALT,
    GENSIO_SOUND_FMT_U16_ALT,
    GENSIO_SOUND_FMT_S8,
    GENSIO_SOUND_FMT_U8,

    GENSIO_SOUND_FMT_UNKNOWN,
};

static snd_pcm_format_t
gensio_sound_fmt_to_pcm(enum gensio_sound_fmt_type gfmt)
{
    unsigned int i;

    for (i = 0;
	 alsa_sound_format_cnv[i].gformat != GENSIO_SOUND_FMT_UNKNOWN;
	 i++) {
	if (alsa_sound_format_cnv[i].gformat == gfmt)
	    return alsa_sound_format_cnv[i].format;
    }
    assert(0);
    return 0;
}

static int
gensio_sound_alsa_set_hwparams(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct alsa_info *a = si->pinfo;
    snd_pcm_hw_params_t *params;
    snd_pcm_uframes_t frsize;
    int err;

    snd_pcm_hw_params_alloca(&params);

    err = snd_pcm_hw_params_any(a->pcm, params);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "alsa error from snd_pcm_hw_params_any: %s\n",
		   snd_strerror(err));
	goto out_err;
    }

    err = snd_pcm_hw_params_set_rate_resample(a->pcm, params, 1);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "alsa error from snd_pcm_hw_params_set_rate_resample: %s\n",
		   snd_strerror(err));
	goto out_err;
    }

    err = snd_pcm_hw_params_set_access(a->pcm, params,
				       SND_PCM_ACCESS_RW_INTERLEAVED);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "alsa error from snd_pcm_hw_params_set_access: %s\n",
		   snd_strerror(err));
	goto out_err;
    }

    if (si->cnv.pfmt != GENSIO_SOUND_FMT_UNKNOWN) {
	err = snd_pcm_hw_params_set_format(a->pcm, params,
					gensio_sound_fmt_to_pcm(si->cnv.pfmt));
    } else {
	err = snd_pcm_hw_params_set_format(a->pcm, params,
					gensio_sound_fmt_to_pcm(si->cnv.ufmt));
	if (err < 0) {
	    unsigned int i;

	    /*
	     * We didn't get the requested one, try the possible values
	     * and use the one we find.
	     */
	    for (i = 0; fallback_order[i] != GENSIO_SOUND_FMT_UNKNOWN; i++) {
		err = snd_pcm_hw_params_set_format(a->pcm, params,
				gensio_sound_fmt_to_pcm(fallback_order[i]));
		if (err >= 0) {
		    setup_convv(si, fallback_order[i]);
		    break;
		}
	    }
	}
    }
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "alsa error from snd_pcm_hw_params_set_format %d: %s\n",
		   si->cnv.ufmt, snd_strerror(err));
	goto out_err;
    }
    if (si->cnv.enabled) {
	si->cnv.pframesize = si->cnv.psize * si->chans;
	si->cnv.buf = o->zalloc(o, si->bufsize * si->cnv.pframesize);
	if (!si->cnv.buf)
	    return GE_NOMEM;
    }

    err = snd_pcm_hw_params_set_channels(a->pcm, params, si->chans);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "alsa error from snd_pcm_hw_params_set_channels: %s\n",
		   snd_strerror(err));
	goto out_err;
    }

    err = snd_pcm_hw_params_set_rate(a->pcm, params, si->samplerate, 0);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "alsa error from snd_pcm_hw_params_set_rate: %s\n",
		   snd_strerror(err));
	goto out_err;
    }

    frsize = si->bufsize * si->num_bufs;
    err = snd_pcm_hw_params_set_buffer_size_near(a->pcm, params, &frsize);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		"alsa error from snd_pcm_hw_params_set_buffer_size_max: %s\n",
		snd_strerror(err));
	goto out_err;
    }

#if 0
    {
	/* Period time, in usecs.  Do u64 arithmetic to avoid overflow. */
	uint64_t lperiod_time = (si->bufsize * 1000000ULL) / si->samplerate;
	unsigned int period_time = lperiod_time;
	int dir;

	err = snd_pcm_hw_params_set_period_time_near(a->pcm, params,
						     &period_time, &dir);
	if (err < 0) {
	    gensio_log(o, GENSIO_LOG_INFO,
		"alsa error from snd_pcm_hw_params_ser_period_time_near: %s\n",
		snd_strerror(err));
	    goto out_err;
	}
    }
#endif

    /* write the parameters to device */
    err = snd_pcm_hw_params(a->pcm, params);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "alsa error from snd_pcm_hw_params: %s\n",
		   snd_strerror(err));
	goto out_err;
    }

    return 0;
 out_err:
    return GE_OSERR;
}

static int
gensio_sound_alsa_set_swparams(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct alsa_info *a = si->pinfo;
    snd_pcm_sw_params_t *params;
    int err;

    snd_pcm_sw_params_alloca(&params);

    /* get the current swparams */
    err = snd_pcm_sw_params_current(a->pcm, params);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "alsa error from snd_pcm_sw_params_current: %s\n",
		   snd_strerror(err));
	goto out_err;
    }

    /* start the transfer when a buffer is written: */
    err = snd_pcm_sw_params_set_start_threshold(a->pcm, params, si->bufsize);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		  "alsa error from snd_pcm_sw_params_set_start_threshold: %s\n",
		  snd_strerror(err));
	goto out_err;
    }

    /*
     * Allow the transfer when at least period_size ont buffer can be
     * processed.
     */
    err = snd_pcm_sw_params_set_avail_min(a->pcm, params, si->bufsize);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		  "alsa error from snd_pcm_sw_params_set_avail_min: %s\n",
		  snd_strerror(err));
	goto out_err;
    }

#if 0
    err = snd_pcm_sw_params_set_period_event(a->pcm, params, 1);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		  "alsa error from snd_pcm_sw_params_set_period_event: %s\n",
		  snd_strerror(err));
	goto out_err;
    }
#endif

    err = snd_pcm_sw_params(a->pcm, params);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		  "alsa error from snd_pcm_sw_params: %s\n",
		  snd_strerror(err));
	goto out_err;
    }

    return 0;

 out_err:
    return GE_OSERR;
}

static bool
gensio_sound_alsa_check_xrun_recovery(struct sound_info *si, int rv)
{
    struct alsa_info *a = si->pinfo;
    snd_pcm_state_t state = snd_pcm_state(a->pcm);

    switch (state) {
    case SND_PCM_STATE_XRUN:
	rv = snd_pcm_prepare(a->pcm);
	if (rv == 0)
	    return true;
	return rv;

    case SND_PCM_STATE_SUSPENDED:
	rv = snd_pcm_resume(a->pcm);
	if (rv == -EAGAIN)
	    return false;
	if (rv < 0)
            rv = snd_pcm_prepare(a->pcm);
	if (rv == 0)
	    return true;
	break;

    default:
	break;
    }

    if (rv) {
	gensio_log(si->soundll->o, GENSIO_LOG_INFO,
		   "alsa error from xrun_recovery: %s\n",
		   snd_strerror(rv));
	si->soundll->err = GE_OSERR;
	gensio_sound_sched_deferred_op(si->soundll);
    }

    return false;
}

static void
gensio_sound_alsa_do_read(struct sound_info *si)
{
    struct alsa_info *a = si->pinfo;
    struct sound_ll *soundll = si->soundll;
    int rv;

    gensio_sound_alsa_check_xrun_recovery(si, 0);
    if (soundll->err)
	return;

    if (si->cnv.enabled) {
	rv = snd_pcm_readi(a->pcm,
			   si->cnv.buf + (si->len * si->cnv.pframesize),
			   si->bufsize - si->len);
    } else {
	rv = snd_pcm_readi(a->pcm, si->buf + (si->len * si->framesize),
			   si->bufsize - si->len);
    }

    if (rv < 0) {
	if (rv == -EAGAIN || rv == -EBUSY)
	    return;
	gensio_sound_alsa_check_xrun_recovery(si, rv);
    } else {
	si->len += rv;
	assert(si->len <= si->bufsize);
	if (si->len == si->bufsize) {
	    if (si->cnv.enabled) {
		const unsigned char *ibuf = si->cnv.buf;
		unsigned char *obuf = si->buf;
		gensiods i;

		for (i = 0; i < si->bufsize * si->chans; i++)
		    si->cnv.convin(&ibuf, &obuf, &si->cnv);
	    }
	    si->ready = true;
	}
    }
}

static void
gensio_sound_alsa_api_set_read(struct sound_info *si, bool enable)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct alsa_info *a = si->pinfo;
    unsigned int i;

    for (i = 0; i < a->nrfds; i++) {
	if (a->fds[i].events & POLLIN)
	    o->set_read_handler(a->iods[i], enable);
	if (a->fds[i].events & POLLOUT)
	    o->set_write_handler(a->iods[i], enable);
	if (a->fds[i].events & POLLERR)
	    o->set_except_handler(a->iods[i], enable);
    }
    if (enable && !si->ready)
	gensio_sound_alsa_do_read(si);
}

static void
gensio_sound_alsa_api_set_write(struct sound_info *si, bool enable)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct alsa_info *a = si->pinfo;
    unsigned int i;

    for (i = 0; i < a->nrfds; i++) {
	if (a->fds[i].events & POLLIN)
	    o->set_read_handler(a->iods[i], enable);
	if (a->fds[i].events & POLLOUT)
	    o->set_write_handler(a->iods[i], enable);
	if (a->fds[i].events & POLLERR)
	    o->set_except_handler(a->iods[i], enable);
    }
}

static void
gensio_sound_alsa_read_handlerb(struct gensio_iod *iod, void *cb_data,
				unsigned short ievents)
{
    struct sound_info *si = cb_data;
    struct alsa_info *a = si->pinfo;
    struct sound_ll *soundll = si->soundll;
    unsigned int i;
    unsigned short revents;

    gensio_sound_ll_lock(soundll);
    for (i = 0; i < a->nrfds; i++)
	a->fds[i].revents = ievents;
    revents = 0;
    snd_pcm_poll_descriptors_revents(a->pcm, a->fds, a->nrfds, &revents);
    if (revents & (POLLERR | POLLIN | POLLOUT)) {
 restart:
	if (soundll->in.ready || soundll->err)
	    gensio_sound_ll_check_read(soundll);
	if (!soundll->in.ready && !soundll->err) {
	    gensio_sound_alsa_do_read(&soundll->in);
	    if (soundll->in.ready || soundll->err)
		goto restart;
	}
    }
    gensio_sound_ll_unlock(soundll);
}

static void
gensio_sound_alsa_read_handler(struct gensio_iod *iod, void *cb_data)
{
    gensio_sound_alsa_read_handlerb(iod, cb_data, POLLIN);
}

static void
gensio_sound_alsa_read_write_handler(struct gensio_iod *iod, void *cb_data)
{
    gensio_sound_alsa_read_handlerb(iod, cb_data, POLLOUT);
}

static void
gensio_sound_alsa_read_exc_handler(struct gensio_iod *iod, void *cb_data)
{
    gensio_sound_alsa_read_handlerb(iod, cb_data, POLLERR);
}

static void
gensio_sound_alsa_write_handlerb(struct gensio_iod *iod, void *cb_data,
				 unsigned short ievents)
{
    struct sound_info *si = cb_data;
    struct alsa_info *a = si->pinfo;
    struct sound_ll *soundll = si->soundll;
    unsigned int i;
    unsigned short revents;

    gensio_sound_ll_lock(soundll);
    for (i = 0; i < a->nrfds; i++)
	a->fds[i].revents = ievents;
    revents = 0;
    snd_pcm_poll_descriptors_revents(a->pcm, a->fds, a->nrfds, &revents);
    /* For some weird reason we get POLLIN on the output device. */
    if (revents & (POLLERR | POLLOUT | POLLIN)) {
	si->ready = true;
	gensio_sound_ll_check_write(soundll);
    }
    gensio_sound_ll_unlock(soundll);
}

static void
gensio_sound_alsa_write_handler(struct gensio_iod *iod, void *cb_data)
{
    gensio_sound_alsa_write_handlerb(iod, cb_data, POLLOUT);
}

static void
gensio_sound_alsa_write_read_handler(struct gensio_iod *iod, void *cb_data)
{
    gensio_sound_alsa_write_handlerb(iod, cb_data, POLLIN);
}

static void
gensio_sound_alsa_write_exc_handler(struct gensio_iod *iod, void *cb_data)
{
    gensio_sound_alsa_write_handlerb(iod, cb_data, POLLERR);
}

static void
gensio_sound_alsa_cleared_handler(struct gensio_iod *iod, void *cb_data)
{
    struct sound_info *si = cb_data;
    struct sound_ll *soundll = si->soundll;

    gensio_sound_ll_lock(soundll);
    soundll->nr_waiting_close--;
    if (soundll->nr_waiting_close == 0) {
	soundll->do_close_now = true;
	gensio_sound_sched_deferred_op(soundll);
    }
    gensio_sound_ll_unlock(soundll);
}


static void
gensio_sound_alsa_timeout(struct gensio_timer *t, void *cb_data)
{
    struct sound_info *si = cb_data;
    struct alsa_info *a = si->pinfo;
    unsigned int i;

    for (i = 0; i < a->nrfds; i++)
	si->soundll->o->clear_fd_handlers(a->iods[i]);
}

static unsigned long
gensio_sound_alsa_drain_count(struct sound_info *si)
{
    struct alsa_info *a = si->pinfo;
    snd_pcm_sframes_t frames_left;

    snd_pcm_delay(a->pcm, &frames_left);
    return frames_left;
}

static unsigned int
gensio_sound_alsa_api_start_close(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct alsa_info *a = si->pinfo;
    gensio_time timeout;
    snd_pcm_sframes_t frames_left = 0;
    uint64_t drain_time;

    if (!si->is_input && a->nrfds > 0) {
	/* Wait for output to drain. */
	snd_pcm_delay(a->pcm, &frames_left);
	drain_time = frames_left * GENSIO_NSECS_IN_SEC / si->samplerate;
	timeout.secs = drain_time / GENSIO_NSECS_IN_SEC;
	timeout.nsecs = drain_time % GENSIO_NSECS_IN_SEC;
	assert(o->start_timer(a->close_timer, &timeout) == 0);
    } else if (a->nrfds > 0) {
	gensio_sound_alsa_timeout(NULL, si);
    }
    return a->nrfds;
}

static int
gensio_sound_alsa_api_write(struct sound_info *out, const unsigned char *buf,
			    gensiods buflen, gensiods *nr_written)
{
    struct alsa_info *a = out->pinfo;
    snd_pcm_sframes_t rv;

 retry:
    rv = snd_pcm_writei(a->pcm, buf, buflen);
    if (rv < 0) {
	if (rv == -EBUSY || rv == -EAGAIN) {
	    out->ready = false;
	    *nr_written = 0;
	    return 0;
	}
	if (gensio_sound_alsa_check_xrun_recovery(out, rv))
	    goto retry;
	return out->soundll->err;
    } else {
	*nr_written = rv;
    }
    return 0;
}

static int
gensio_sound_alsa_api_open_dev(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct alsa_info *a = si->pinfo;
    int err;
    unsigned int i;
    snd_pcm_stream_t stype = (si->is_input ? SND_PCM_STREAM_CAPTURE :
			      SND_PCM_STREAM_PLAYBACK);

    err = snd_pcm_open(&a->pcm, si->devname, stype, SND_PCM_NONBLOCK);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "alsa error from snd_pcm_open: %s",
		   snd_strerror(err));
	return GE_OSERR;
    }

    err = gensio_sound_alsa_set_hwparams(si);
    if (err) {
	gensio_sound_alsa_api_close_dev(si);
	return err;
    }
    err = gensio_sound_alsa_set_swparams(si);
    if (err) {
	gensio_sound_alsa_api_close_dev(si);
	return err;
    }

    a->nrfds = snd_pcm_poll_descriptors_count(a->pcm);
    if (a->nrfds == 0) {
	gensio_sound_alsa_api_close_dev(si);
	return GE_INCONSISTENT;
    }

    a->fds = o->zalloc(o, a->nrfds * sizeof(struct pollfd));
    if (!a->fds) {
	gensio_sound_alsa_api_close_dev(si);
	return GE_NOMEM;
    }

    a->iods = o->zalloc(o, a->nrfds * sizeof(struct gensio_iod *));
    if (!a->iods) {
	gensio_sound_alsa_api_close_dev(si);
	return GE_NOMEM;
    }

    err = snd_pcm_poll_descriptors(a->pcm, a->fds, a->nrfds);
    if (err < 0) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "alsa error from snd_pcm_poll_descriptors: %s",
		   snd_strerror(err));
	gensio_sound_alsa_api_close_dev(si);
	return GE_OSERR;
    }

    for (i = 0; i < a->nrfds; i++) {
	err = o->add_iod(o, GENSIO_IOD_PIPE, a->fds[i].fd,
			 &(a->iods[i]));
	if (err) {
	    gensio_sound_alsa_api_close_dev(si);
	    return err;
	}
	err = o->set_fd_handlers(a->iods[i], si,
				 (stype == SND_PCM_STREAM_CAPTURE ?
				  gensio_sound_alsa_read_handler :
				  gensio_sound_alsa_write_read_handler),
				 (stype == SND_PCM_STREAM_PLAYBACK ?
				  gensio_sound_alsa_write_handler :
				  gensio_sound_alsa_read_write_handler),
				 (stype == SND_PCM_STREAM_CAPTURE ?
				  gensio_sound_alsa_read_exc_handler :
				  gensio_sound_alsa_write_exc_handler),
				 gensio_sound_alsa_cleared_handler);
	if (err) {
	    gensio_sound_alsa_api_close_dev(si);
	    return err;
	}
    }

    return 0;
}

static int
gensio_sound_alsa_api_devices(char ***rnames, char ***rspecs, gensiods *rcount)
{
    void **hints, **n;
    gensiods count = 0, size = 0;
    char **names = NULL, **specs = NULL;

    if (snd_device_name_hint(-1, "pcm", &hints) < 0) {
	*rcount = 0;
	return 0;
    }

    for (n = hints; *n != NULL; n++) {
	char *name = NULL, *io = NULL;

	name = snd_device_name_get_hint(*n, "NAME");
	io = snd_device_name_get_hint(*n, "IOID");
	if (!name)
	    goto next;
	if (io) {
	    io[0] = tolower(io[0]);
	} else {
	    io = strdup("input,output");
	    if (!io)
		goto out_nomem;
	}

	if (count >= size) {
	    if (extend_sound_devs(&names, &specs, &size)) {
		free(name);
		free(io);
		goto out_nomem;
	    }
	}
	names[count] = name;
	name = NULL;
	specs[count] = io;
	io = NULL;
	count++;

    next:
	if (io)
	    free(io);
    }
    snd_device_name_free_hint(hints);
    *rnames = names;
    *rspecs = specs;
    *rcount = count;

    return 0;

 out_nomem:
    snd_device_name_free_hint(hints);
    gensio_sound_devices_free(names, specs, count);
    return GE_NOMEM;
}

static void
gensio_sound_alsa_cleanup_func(void)
{
    snd_config_update_free_global();
}

static struct gensio_class_cleanup gensio_sound_alsa_class_cleanup = {
    /*
     * If you don't call this, lots of cached information gets left
     * lying around in the alsa code and valgrind complains.
     */
    .cleanup = gensio_sound_alsa_cleanup_func
};

static int
gensio_sound_alsa_api_setup(struct sound_info *si, struct gensio_sound_info *io)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct alsa_info *a;

    gensio_register_class_cleanup(&gensio_sound_alsa_class_cleanup);
    si->pinfo = o->zalloc(o, sizeof(struct alsa_info));
    if (!si->pinfo)
	return GE_NOMEM;
    a = si->pinfo;

    a->close_timer = o->alloc_timer(o, gensio_sound_alsa_timeout, si);
    if (!a->close_timer) {
	o->free(o, si->pinfo);
	si->pinfo = NULL;
	return GE_NOMEM;
    }

    return 0;
}

static void
gensio_sound_alsa_api_cleanup(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct alsa_info *a = si->pinfo;

    if (a) {
	if (a->close_timer)
	    o->free_timer(a->close_timer);
	o->free(o, a);
	si->pinfo = NULL;
    }
}

static struct sound_type alsa_sound_type = {
    "alsa",
    .setup = gensio_sound_alsa_api_setup,
    .cleanup = gensio_sound_alsa_api_cleanup,
    .open_dev = gensio_sound_alsa_api_open_dev,
    .close_dev = gensio_sound_alsa_api_close_dev,
    .sub_write = gensio_sound_alsa_api_write,
    .write = gensio_sound_api_default_write,
    .set_write_enable = gensio_sound_alsa_api_set_write,
    .set_read_enable = gensio_sound_alsa_api_set_read,
    .start_close = gensio_sound_alsa_api_start_close,
    .drain_count = gensio_sound_alsa_drain_count,
    .devices = gensio_sound_alsa_api_devices
};

#define ALSA_INIT &alsa_sound_type,
