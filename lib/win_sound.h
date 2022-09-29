/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2022  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <windows.h>
#include <mmsystem.h>
#include <mmreg.h>

struct win_sound_format_cnv {
    enum gensio_sound_fmt_type gformat;
    WAVEFORMATEX fmt;
} win_sound_fmt_cnv[] = {
    { .gformat = GENSIO_SOUND_FMT_DOUBLE,
      .fmt = {
	  .wFormatTag = WAVE_FORMAT_IEEE_FLOAT,
	  .wBitsPerSample = 64
      },
    },
    { .gformat = GENSIO_SOUND_FMT_FLOAT,
      .fmt = {
	  .wFormatTag = WAVE_FORMAT_IEEE_FLOAT,
	  .wBitsPerSample = 32
      },
    },
    { .gformat = GENSIO_SOUND_FMT_S32,
      .fmt = {
	  .wFormatTag = WAVE_FORMAT_PCM,
	  .wBitsPerSample = 32
      },
    },
    { .gformat = GENSIO_SOUND_FMT_S24,
      .fmt = {
	  .wFormatTag = WAVE_FORMAT_PCM,
	  .wBitsPerSample = 24
      },
    },
    { .gformat = GENSIO_SOUND_FMT_S16,
      .fmt = {
	  .wFormatTag = WAVE_FORMAT_PCM,
	  .wBitsPerSample = 16
      },
    },
    { .gformat = GENSIO_SOUND_FMT_S8,
      .fmt = {
	  .wFormatTag = WAVE_FORMAT_PCM,
	  .wBitsPerSample = 8
      },
    },
    { .gformat = GENSIO_SOUND_FMT_UNKNOWN }
};

static int
i_gensio_mres_err_to_err(struct sound_info *si, MMRESULT mres,
			 const char *caller, const char *file,
			 unsigned int lineno)
{
    struct gensio_os_funcs *o = si->soundll->o;
    int err;
    char errbuf[128];

    switch (mres) {
    case MMSYSERR_ALLOCATED:	err = GE_INUSE; break;
    case MMSYSERR_BADDEVICEID:
    case MMSYSERR_NODRIVER:	err = GE_COMMERR; break;
    case MMSYSERR_NOMEM:	err = GE_NOMEM; break;
    default:			err = GE_OSERR; break;
    }

    if (err == GE_OSERR) {
	errbuf[0] = '\0';
	if (si->is_input)
	    waveInGetErrorText(mres, errbuf, sizeof(errbuf));
	else
	    waveOutGetErrorText(mres, errbuf, sizeof(errbuf));
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled eounr error in %s:%d: %s (%d)", caller, lineno,
		   errbuf, mres);
    }
    
    return err;
}
#define gensio_mres_err_to_err(o, mres)				\
    i_gensio_mres_err_to_err(o, mres, __func__, __FILE__, __LINE__)

static int
gensio_sound_win_get_wavefmt(enum gensio_sound_fmt_type gformat,
			     WAVEFORMATEX *fmt)
{
    unsigned int i;

    for (i = 0; win_sound_fmt_cnv[i].gformat != GENSIO_SOUND_FMT_UNKNOWN;
		i++) {
	if (gformat == win_sound_fmt_cnv[i].gformat)
	    break;
    }
    if (gformat != win_sound_fmt_cnv[i].gformat)
	return GE_INVAL;

    *fmt = win_sound_fmt_cnv[i].fmt;
    return 0;
}

struct win_bufhdr {
    struct sound_info *si;
    unsigned int bufnum;
    struct win_bufhdr *next;
    gensiods pos; /* Position in bytes. */
    gensiods len; /* Total length of the buffer. */
    WAVEHDR whdr;
    bool in_driver; /* Is the driver handling this buffer now? */
};

struct gensio_sound_win_close_info {
    CRITICAL_SECTION lock;
    struct sound_info *si;
};

struct win_sound_info {
    union {
	HWAVEIN inh;
	HWAVEOUT outh;
    };
    struct gensio_sound_win_close_info *ci;

    /* array of si->num_bufs, each points to part of si->cnv.buf */

    bool started;

    /*
     * When starting, to avoid stutter at startup, wait until two
     * buffers are ready to go.  This holds the waiting buffer.
     */
    struct win_bufhdr *waiting_xmit_buf;
    unsigned int num_bufs_in_driver;

    struct win_bufhdr *hdrs;

    /* List of buffers ready to process. */
    struct win_bufhdr *head;
    struct win_bufhdr *tail;
};

static unsigned long
gensio_sound_win_drain_count(struct sound_info *si)
{
    struct win_sound_info *w = si->pinfo;
    unsigned long buffers_left = 0, i;

    /* Count the buffers still in the driver. */
    for (i = 0; i < si->num_bufs; i++) {
	struct win_bufhdr *hdr = &w->hdrs[i];

	if (hdr->in_driver)
	    buffers_left++;
    }

    return buffers_left * si->bufsize;
}

static void
gensio_sound_win_api_close_dev(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct win_sound_info *w = si->pinfo;
    unsigned int i;

    if (si->is_input) {
	if (w->inh) {
	    if (w->started)
		assert(waveInReset(w->inh) == MMSYSERR_NOERROR);
	    for (i = 0; i < si->num_bufs; i++)
		waveInUnprepareHeader(w->inh, &w->hdrs[i].whdr,
			              sizeof(WAVEHDR));
	    assert(waveInClose(w->inh) == MMSYSERR_NOERROR);
	    w->inh = NULL;
	}
    } else {
	if (w->outh) {
	    assert(waveOutReset(w->outh) == MMSYSERR_NOERROR);
	    for (i = 0; i < si->num_bufs; i++)
		waveOutUnprepareHeader(w->outh, &w->hdrs[i].whdr,
				       sizeof(WAVEHDR));
	    assert(waveOutClose(w->outh) == MMSYSERR_NOERROR);
	    w->outh = NULL;
	}
    }

    w->started = false;

    if (w->ci) {
	o->free(o, w->ci);
	w->ci = NULL;
    }

    if (w->hdrs) {
	o->free(o, w->hdrs);
	w->hdrs = NULL;
    }

    w->waiting_xmit_buf = NULL;
}

static void
gensio_sound_win_process_read_buffer(struct sound_info *si)
{
    struct win_sound_info *w = si->pinfo;
    struct win_bufhdr *hdr;
    WAVEHDR *whdr;
    const unsigned char *ibuf;
    unsigned char *obuf;
    gensiods len;

    if (!w->head || si->ready)
	return;

    hdr = w->head;
    whdr = &hdr->whdr;

    len = whdr->dwBytesRecorded; /* In bytes. */

    ibuf = (unsigned char *) whdr->lpData;
    ibuf += hdr->pos;
    obuf = si->buf + (si->len * si->framesize);

    if (si->cnv.enabled) {
	while (len > 0 && si->len < si->bufsize) {
	    si->cnv.convin(&ibuf, &obuf, &si->cnv);
	    si->len++;
	    len -= si->cnv.psize;
	    hdr->pos += si->cnv.psize;
	}
	whdr->dwBytesRecorded = len;
    } else {
	if (len > (si->bufsize - si->len) * si->framesize)
	    len = (si->bufsize - si->len) * si->framesize;
	memcpy(obuf, ibuf, len);
	si->len += len / si->framesize;
	hdr->pos += len;
	whdr->dwBytesRecorded -= len;
    }

    if (si->len >= si->bufsize) {
	si->ready = true;
	gensio_sound_sched_deferred_op(si->soundll);
    }

    if (whdr->dwBytesRecorded == 0) {
	/* Send it back to the wave input processor for more data. */
	if (hdr->next) {
	    w->head = hdr->next;
	} else {
	    w->head = NULL;
	    w->tail = NULL;
	}

	hdr->pos = 0;
	whdr->dwFlags = 0;
	hdr->in_driver = true;
	w->num_bufs_in_driver++;
	gensio_sound_ll_unlock(si->soundll);
	/* Like write, this will deadlock if called with the lock held. */
	assert(waveInUnprepareHeader(w->inh, whdr, sizeof(WAVEHDR)) ==
	       MMSYSERR_NOERROR);
	assert(waveInPrepareHeader(w->inh, whdr, sizeof(WAVEHDR)) ==
	       MMSYSERR_NOERROR);
	assert(waveInAddBuffer(w->inh, whdr, sizeof(WAVEHDR)) ==
	       MMSYSERR_NOERROR);
	gensio_sound_ll_lock(si->soundll);
    }
}

static void
gensio_sound_win_api_set_read(struct sound_info *si, bool enable)
{
    if (enable) {
	struct win_sound_info *w = si->pinfo;

	if (!w->started) {
	    waveInStart(w->inh);
	    w->started = true;
	    EnterCriticalSection(&w->ci->lock);
	    w->ci->si = si;
	    LeaveCriticalSection(&w->ci->lock);
	}
	gensio_sound_win_process_read_buffer(si);
    }
}

static void
gensio_sound_win_api_set_write(struct sound_info *si, bool enable)
{
    /* Nothing to do here. */
}

static void
gensio_sound_win_start_buf_xmit(struct sound_ll *soundll,
				struct win_sound_info *w,
				struct win_bufhdr *hdr)
{
    WAVEHDR *whdr = &hdr->whdr;

    whdr->dwBufferLength = hdr->pos;
    hdr->in_driver = true;
    w->num_bufs_in_driver++;
    gensio_sound_ll_unlock(soundll);
    /*
     * If you call write while locked, you will deadlock with
     * the out_handler code.
     */

    assert(waveOutUnprepareHeader(w->outh, whdr, sizeof(WAVEHDR)) ==
	   MMSYSERR_NOERROR);
    whdr->dwFlags = 0;
    assert(waveOutPrepareHeader(w->outh, whdr, sizeof(WAVEHDR)) ==
	   MMSYSERR_NOERROR);
    assert(waveOutWrite(w->outh, whdr, sizeof(WAVEHDR))  ==
	   MMSYSERR_NOERROR);

    gensio_sound_ll_lock(soundll);
}

static unsigned int
gensio_sound_win_api_start_close(struct sound_info *si)
{
    struct win_sound_info *w = si->pinfo;
    unsigned int rv = 0, i;

    for (i = 0; i < si->num_bufs; i++) {
	struct win_bufhdr *hdr = &w->hdrs[i];

	/* Wait until all the headers are out of the driver. */
	if (hdr->in_driver)
	    rv++;
    }
    /* Also buffers that are waiting to send. */
    if (w->waiting_xmit_buf) {
	struct win_bufhdr *thdr = w->waiting_xmit_buf;

	w->waiting_xmit_buf = NULL;
	gensio_sound_win_start_buf_xmit(si->soundll, w, thdr);
	rv++;
    }
    if (w->head && w->head->pos > 0) {
	struct win_bufhdr *thdr = w->head;

	w->head = thdr->next;
	if (!w->head)
	    w->tail = NULL;
	gensio_sound_win_start_buf_xmit(si->soundll, w, thdr);
	rv++;
    }

    return rv;
}

static int
gensio_sound_win_api_write(struct sound_info *out, gensiods *rcount,
			   const struct gensio_sg *sg, gensiods sglen)
{
    struct sound_ll *soundll = out->soundll;
    struct win_sound_info *w = out->pinfo;
    struct win_bufhdr *hdr;
    WAVEHDR *whdr;
    gensiods count = 0, i, obuflen;
    unsigned char *obuf;

    if (!w->head)
	goto out;
    hdr = w->head;
    whdr = &hdr->whdr;
    obuf = (unsigned char *) whdr->lpData;
    obuf += hdr->pos;
    obuflen = hdr->len - hdr->pos;

    for (i = 0; i < sglen; i++) {
	const unsigned char *ibuf = sg[i].buf;
	gensiods ibuflen = sg[i].buflen, j;

	while (ibuflen > 0) {
	    if (out->cnv.enabled) {
		j = 0;
		while (ibuflen > 0 && obuflen > 0) {
		    out->cnv.convout(&ibuf, &obuf, &out->cnv);
		    obuflen -= out->cnv.psize;
		    ibuflen -= out->cnv.usize;
		    hdr->pos += out->cnv.psize;
		    j += out->cnv.usize;
		}
	    } else {
		if (ibuflen > obuflen)
		    j = obuflen;
		else
		    j = ibuflen;
		memcpy(obuf, ibuf, j);
		ibuf += j;
		ibuflen -= j;
		obuf += j;
		obuflen -= j;
		hdr->pos += j;
	    }
	    count += j;

	    if (hdr->pos == hdr->len) {
		/* We have a full buffer to write to the driver. */
		w->head = hdr->next;
		if (!w->head)
		    w->tail = NULL;
		if (w->waiting_xmit_buf) {
		    struct win_bufhdr *thdr = w->waiting_xmit_buf;

		    w->waiting_xmit_buf = NULL;
		    gensio_sound_win_start_buf_xmit(soundll, w, thdr);
		}
		if (w->num_bufs_in_driver == 0)
		    w->waiting_xmit_buf = hdr;
		else
		    gensio_sound_win_start_buf_xmit(soundll, w, hdr);

		if (!w->head) {
		    out->ready = false;
		    goto out;
		}
		hdr = w->head;
		whdr = &hdr->whdr;
		obuf = (unsigned char *) whdr->lpData;
		obuf += hdr->pos;
		obuflen = hdr->len - hdr->pos;
	    }
	}
    }
 out:
    if (rcount)
	*rcount = count;
    return 0;
}

static void
gensio_sound_win_api_next_read(struct sound_info *si)
{
    gensio_sound_win_process_read_buffer(si);
}

static void
gensio_sound_win_close_one(struct sound_info *si)
{
    struct sound_ll *soundll = si->soundll;

    soundll->nr_waiting_close--;
    if (soundll->nr_waiting_close == 0) {
	soundll->do_close_now = true;
	gensio_sound_sched_deferred_op(soundll);
    }
}

static void
gensio_sound_win_in_handler(HWAVEIN   hwi,
			    UINT      uMsg,
			    DWORD_PTR dwInstance,
			    DWORD_PTR dwParam1,
			    DWORD_PTR dwParam2)
{
    struct sound_info *si;
    WAVEHDR *whdr;
    struct win_bufhdr *hdr;
    struct win_sound_info *w;

    if (uMsg != WIM_DATA)
	return;

    whdr = (WAVEHDR *) dwParam1;
    hdr = (struct win_bufhdr *) whdr->dwUser;
    si = hdr->si;
    w = si->pinfo;
    hdr->next = NULL;

    gensio_sound_ll_lock(si->soundll);
    hdr->in_driver = false;
    w->num_bufs_in_driver--;
    if (si->soundll->state == GENSIO_SOUND_LL_IN_CLOSE) {
	gensio_sound_win_close_one(si);
	goto out;
    }

    hdr->next = NULL;
    if (!w->head) {
	w->head = hdr;
	w->tail = hdr;
    } else {
	w->tail->next = hdr;
	w->tail = hdr;
    }
    gensio_sound_win_process_read_buffer(si);
out:
    gensio_sound_ll_unlock(si->soundll);
}

static void
gensio_sound_win_out_handler(HWAVEOUT  hwo,
			     UINT      uMsg,
			     DWORD_PTR dwInstance,
			     DWORD_PTR dwParam1,
			     DWORD_PTR dwParam2)
{
    struct sound_info *si;
    WAVEHDR *whdr;
    struct win_bufhdr *hdr;
    struct win_sound_info *w;

    if (uMsg != WOM_DONE)
	return;

    whdr = (WAVEHDR *) dwParam1;
    hdr = (struct win_bufhdr *) whdr->dwUser;
    si = hdr->si;
    w = si->pinfo;
    gensio_sound_ll_lock(si->soundll);
    hdr->in_driver = false;
    w->num_bufs_in_driver--;
    hdr->pos = 0;
    hdr->next = NULL;
    if (!w->head) {
	w->head = hdr;
	w->tail = hdr;
    } else {
	w->tail->next = hdr;
	w->tail = hdr;
    }

    if (si->soundll->state == GENSIO_SOUND_LL_IN_CLOSE) {
	gensio_sound_win_close_one(si);
    } else if (!si->ready) {
	si->ready = true;
	gensio_sound_sched_deferred_op(si->soundll);
    }

    /*
     * If we are transmitting the last queued buffer, and there is a
     * partial buffer left, go ahead and send the partial buffer.
     */
    if (w->num_bufs_in_driver == 1 && w->head && w->head->pos > 0) {
	struct win_bufhdr *thdr = w->head;

	w->head = thdr->next;
	if (!w->head)
	    w->tail = NULL;
	gensio_sound_win_start_buf_xmit(si->soundll, w, thdr);
    }
    gensio_sound_ll_unlock(si->soundll);
}

static int
gensio_sound_win_api_open_dev(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;
    struct win_sound_info *w = si->pinfo;
    WAVEFORMATEX wfx;
    MMRESULT mres;
    UINT dev, ndevs;
    enum gensio_sound_fmt_type pfmt;
    char tmpstr[100];
    unsigned int i;
    int err;

    if (si->cnv.pfmt != GENSIO_SOUND_FMT_UNKNOWN)
	pfmt = si->cnv.pfmt;
    else
	pfmt = si->cnv.ufmt;

    err = gensio_sound_win_get_wavefmt(pfmt, &wfx);
    if (err)
	return err;

    wfx.nChannels = si->chans;
    wfx.nSamplesPerSec = si->samplerate;
    wfx.nAvgBytesPerSec = si->cnv.pframesize * si->samplerate;
    wfx.nBlockAlign = si->cnv.pframesize;

    w->ci = o->zalloc(o, sizeof(struct gensio_sound_win_close_info));
    if (!w->ci)
	return GE_NOMEM;
    InitializeCriticalSection(&w->ci->lock);
    w->ci->si = NULL;

    si->cnv.buf = o->zalloc(o, (si->num_bufs * si->bufsize *
				si->cnv.pframesize));
    if (!si->cnv.buf) {
	gensio_sound_win_api_close_dev(si);
	return GE_NOMEM;
    }

    w->hdrs = o->zalloc(o, sizeof(struct win_bufhdr) * si->num_bufs);
    if (!w->hdrs) {
	gensio_sound_win_api_close_dev(si);
	return GE_NOMEM;
    }

    for (i = 0; i < si->num_bufs; i++) {
	w->hdrs[i].si = si;
	w->hdrs[i].bufnum = i;
	w->hdrs[i].len = si->bufsize * si->cnv.pframesize;
	w->hdrs[i].whdr.dwBufferLength = w->hdrs[i].len;
	w->hdrs[i].whdr.lpData = (char *) si->cnv.buf + (w->hdrs[i].len * i);
	w->hdrs[i].whdr.dwUser = (DWORD_PTR) &w->hdrs[i];
    }

    if (si->is_input) {
	WAVEINCAPS icaps;

	ndevs = waveInGetNumDevs();
	for (dev = 0; dev < ndevs; dev++) {
	    mres = waveInGetDevCaps(dev, &icaps, sizeof(icaps));
	    if (mres != MMSYSERR_NOERROR)
		continue;
	    snprintf(tmpstr, sizeof(tmpstr), "%d:%s", dev, icaps.szPname);
	    if (strstr(tmpstr, si->devname))
		break;
	}
	if (dev == ndevs) {
	    gensio_sound_win_api_close_dev(si);
	    return GE_NOTFOUND;
	}

	/* Windows does the conversion for us. */
	mres = waveInOpen(&w->inh, dev, &wfx,
			  (DWORD_PTR) gensio_sound_win_in_handler,
			  (DWORD_PTR) w->ci, CALLBACK_FUNCTION);
	if (mres != MMSYSERR_NOERROR) {
	    gensio_sound_win_api_close_dev(si);
	    return gensio_mres_err_to_err(si, mres);
	}

	for (i = 0; i < si->num_bufs; i++) {
	    assert(waveInPrepareHeader(w->inh, &w->hdrs[i].whdr,
				       sizeof(WAVEHDR)) ==
		   MMSYSERR_NOERROR);
	    assert(waveInAddBuffer(w->inh, &w->hdrs[i].whdr, sizeof(WAVEHDR))
		   == MMSYSERR_NOERROR);
	    w->hdrs[i].in_driver = true;
	}
	w->num_bufs_in_driver = si->num_bufs;
    } else {
	WAVEOUTCAPS ocaps;

	ndevs = waveOutGetNumDevs();
	for (dev = 0; dev < ndevs; dev++) {
	    mres = waveOutGetDevCaps(dev, &ocaps, sizeof(ocaps));
	    if (mres != MMSYSERR_NOERROR)
		continue;
	    snprintf(tmpstr, sizeof(tmpstr), "%d:%s", dev, ocaps.szPname);
	    if (strstr(tmpstr, si->devname))
		break;
	}
	if (dev == ndevs) {
	    gensio_sound_win_api_close_dev(si);
	    return GE_NOTFOUND;
	}

	/* Windows does the conversion for us. */
	mres = waveOutOpen(&w->outh, dev, &wfx,
			   (DWORD_PTR) gensio_sound_win_out_handler,
			   (DWORD_PTR) w->ci, CALLBACK_FUNCTION);
	if (mres != MMSYSERR_NOERROR) {
	    gensio_sound_win_api_close_dev(si);
	    return gensio_mres_err_to_err(si, mres);
	}

	for (i = 0; i < si->num_bufs; i++) {
	    struct win_bufhdr *hdr = &w->hdrs[i];

	    hdr->in_driver = false;
	    hdr->next = NULL;
	    if (!w->head) {
		w->head = hdr;
		w->tail = hdr;
	    } else {
		w->tail->next = hdr;
		w->tail = hdr;
	    }
	}

	/* We unprepare them in the write routine. */
	for (i = 0; i < si->num_bufs; i++) {
	    assert(waveOutPrepareHeader(w->outh, &w->hdrs[i].whdr,
					sizeof(WAVEHDR)) ==
		   MMSYSERR_NOERROR);
	}

	w->num_bufs_in_driver = 0;
	si->ready = true;
    }

    return 0;
}

static int
gensio_sound_win_api_setup(struct sound_info *si, struct gensio_sound_info *io)
{
    struct gensio_os_funcs *o = si->soundll->o;

    si->pinfo = o->zalloc(o, sizeof(struct win_sound_info));
    if (!si->pinfo)
	return GE_NOMEM;

    return 0;
}

static void
gensio_sound_win_api_cleanup(struct sound_info *si)
{
    struct gensio_os_funcs *o = si->soundll->o;

    gensio_sound_win_api_close_dev(si);
    if (si->pinfo)
	o->free(o, si->pinfo);
    si->pinfo = NULL;
}

static int
gensio_sound_win_api_devices(char ***rnames, char ***rspecs, gensiods *rcount)
{
    gensiods count = 0, size = 0;
    UINT i, ndevs;
    MMRESULT mres;
    WAVEINCAPS icaps;
    WAVEOUTCAPS ocaps;
    char **names = NULL, **specs = NULL;

    ndevs = waveInGetNumDevs();
    for (i = 0; i < ndevs; i++) {
	char *name = NULL, *spec = NULL, tspec[100];
	mres = waveInGetDevCaps(i, &icaps, sizeof(icaps));
	if (mres != MMSYSERR_NOERROR)
	    continue;
	snprintf(tspec, sizeof(tspec), "%d:%s", i, icaps.szPname);
	name = strdup(tspec);
	if (!name)
	    goto nextin;
	snprintf(tspec, sizeof(tspec), "input,inchans=%d",
		 icaps.wChannels);
	spec = strdup(tspec);
	if (!spec)
	    goto nextin;
	if (count >= size) {
	    if (extend_sound_devs(&names, &specs, &size)) {
		free(name);
		free(spec);
		goto out_nomem;
	    }
	}
	names[count] = name;
	name = NULL;
	specs[count] = spec;
	spec = NULL;
	count++;

    nextin:
	if (name)
	    free(name);
	if (spec)
	    free(spec);
    }

    ndevs = waveOutGetNumDevs();
    for (i = 0; i < ndevs; i++) {
	char *name = NULL, *spec = NULL, tspec[100];
	mres = waveOutGetDevCaps(i, &ocaps, sizeof(ocaps));
	if (mres != MMSYSERR_NOERROR)
	    continue;
	snprintf(tspec, sizeof(tspec), "%d:%s", i, ocaps.szPname);
	name = strdup(tspec);
	if (!name)
	    goto nextout;
	snprintf(tspec, sizeof(tspec), "output,outchans=%d",
		 ocaps.wChannels);
	spec = strdup(tspec);
	if (!spec)
	    goto nextout;
	if (count >= size) {
	    if (extend_sound_devs(&names, &specs, &size)) {
		free(name);
		free(spec);
		goto out_nomem;
	    }
	}
	names[count] = name;
	name = NULL;
	specs[count] = spec;
	spec = NULL;
	count++;

    nextout:
	if (name)
	    free(name);
	if (spec)
	    free(spec);
    }

    *rnames = names;
    *rspecs = specs;
    *rcount = count;

    return 0;

 out_nomem:
    gensio_sound_devices_free(names, specs, count);
    return GE_NOMEM;
}

static struct sound_type win_sound_type = {
    "win",
    .setup = gensio_sound_win_api_setup,
    .cleanup = gensio_sound_win_api_cleanup,
    .open_dev = gensio_sound_win_api_open_dev,
    .close_dev = gensio_sound_win_api_close_dev,
    .write = gensio_sound_win_api_write,
    .set_write_enable = gensio_sound_win_api_set_write,
    .set_read_enable = gensio_sound_win_api_set_read,
    .next_read = gensio_sound_win_api_next_read,
    .start_close = gensio_sound_win_api_start_close,
    .drain_count = gensio_sound_win_drain_count,
    .devices = gensio_sound_win_api_devices
};

#define WIN_INIT &win_sound_type,
