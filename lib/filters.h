/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2026  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This is filters for RF and audio, not a gensio filter. */

#ifndef GENSIO_RF_FILTER
#define GENSIO_RF_FILTER

struct filterinfo {
    unsigned int coefs_n;
    float gain;
    float *coefs;
    float *hold;

    /* IIR or FIR filter function. */
    void (*do_filter)(float *inbuf, float *outbuf, unsigned int nsamples,
		      unsigned int nchans, unsigned int chan,
		      struct filterinfo *filt);
};

/*
 * Implement a basic 2nd-order IIR filter.
 */
static void
float_iir_filter(float *inbuf, float *outbuf, unsigned int nsamples,
		 unsigned int nchans, unsigned int chan,
		 struct filterinfo *filt)
{
    unsigned int i;
    float *coefa = filt->coefs;
    float *coefb = filt->coefs + 2;
    float tmp;

    /* hold[0] = z^-1, hold[1] = z^-2 */
    for (i = chan; i < nsamples * nchans; i += nchans) {
	tmp = inbuf[i] + coefa[0] * filt->hold[0] + coefa[1] * filt->hold[1];
	outbuf[i] = (tmp * coefb[0] + coefb[1] * filt->hold[0]
		     + coefb[2] * filt->hold[1]);
	outbuf[i] *= filt->gain;
	filt->hold[1] = filt->hold[0];
	filt->hold[0] = tmp;
    }
}

/* Complex version of the above. */
static void
floatc_iir_filter(float *in_inbuf, float *in_outbuf, unsigned int nsamples,
		  unsigned int nchans, unsigned int chan,
		  struct filterinfo *filt)
{
    float complex *inbuf = (float complex *) in_inbuf;
    float complex *outbuf = (float complex *) in_outbuf;
    float complex *hold = (float complex *) filt->hold;
    float *coefa = filt->coefs;
    float *coefb = filt->coefs + 2;
    unsigned int i;
    float complex tmp;

    /* hold[0] = z^-1, hold[1] = z^-2 */
    for (i = chan; i < nsamples * nchans; i += nchans) {
	tmp = inbuf[i] + coefa[0] * hold[0] + coefa[1] * hold[1];
	outbuf[i] = tmp * coefb[0] + coefb[1] * hold[0] + coefb[2] * hold[1];
	outbuf[i] *= filt->gain;
	hold[1] = hold[0];
	hold[0] = tmp;
    }
}

/*
 * Calculate 2nd order IIR filter coefficients for a low-pass
 * or high pass Butterworth filter.  The lpf parameter tells which
 * filter to calculate.
 *
 * See https://www.staff.ncl.ac.uk/oliver.hinton/eee305/Chapter5.pdf
 * for more explanation.
 *
 * Also see IIR_Filter.txt in this directory for the equations worked
 * out.
 */
static void
calc_iir_coefs(bool lpf, float samplerate, float cutoff,
	       float coefa[], float coefb[])
{
    float w1 = 2 * M_PI * cutoff / samplerate;
    float w = tan(w1 / 2); /* omega */
    float w2 = w * w; /* omega ^ 2 */
    float denom = w2 + M_SQRT2 * w + 1;

    coefa[0] = (2 - 2 * w2) / denom;
    coefa[1] = - (1 - M_SQRT2 * w + w2) / denom;
    coefb[0] = 1 / denom;
    if (lpf)
	coefb[0] *= w2;
    coefb[1] = 2 * coefb[0];
    if (!lpf)
	coefb[0] *= -1.0;
    coefb[2] = coefb[0];
}

static float
get_fir_val(unsigned int i, unsigned int holdsize, float *inbuf, float *hold,
	    unsigned int nchans, unsigned int chan)
{
    if (i < holdsize)
	return hold[i];
    i -= holdsize;
    i = (i * nchans) + chan;
    return inbuf[i];
}

/*
 * Process a buffer with a fir filter.  h and n come from
 * calc_fir_coefs(), hold must be of size n * 2.
 */
static void
float_fir_filter(float *inbuf, float *outbuf, unsigned int nsamples,
		 unsigned int nchans, unsigned int chan,
		 struct filterinfo *filt)
{
    unsigned int i, j, k;
    unsigned int n = filt->coefs_n;
    unsigned int holdsize = n * 2;
    float *h = filt->coefs;
    float tmp;

    for (i = 0; i < nsamples; i++) {
	/* Get the middle value, it's always multiplied by 1. */
	tmp = get_fir_val(n + i, holdsize, inbuf, filt->hold, nchans, chan);

	/*
	 * The h array is half of a symmetric waveform.  That waveform
	 * is always an odd number of values, but we don't include the
	 * middle value (it's always one, handled above) and h only
	 * holds the left half of the waveform.
	 */
	for (j = 0, k = holdsize; j < n; j++, k--) {
	    tmp += h[j] * (get_fir_val(i + j, holdsize, inbuf, filt->hold,
				       nchans, chan) +
			   get_fir_val(i + k, holdsize, inbuf, filt->hold,
				       nchans, chan));
	}

	outbuf[i * nchans + chan] = tmp * filt->gain;
    }
    for (i = 0; i < holdsize; i++) {
	unsigned int pos = nsamples - holdsize + i;
	filt->hold[i] = inbuf[pos * nchans + chan];
    }
}

/*
 * Complex version of the above.
 */
static float complex
getc_fir_val(unsigned int i, unsigned int holdsize,
	     float complex *inbuf, float complex *hold,
	     unsigned int nchans, unsigned int chan)
{
    if (i < holdsize)
	return hold[i];
    i -= holdsize;
    i = (i * nchans) + chan;
    return inbuf[i];
}

static void
floatc_fir_filter(float *in_inbuf, float *in_outbuf, unsigned int nsamples,
		  unsigned int nchans, unsigned int chan,
		  struct filterinfo *filt)
{
    float complex *inbuf = (float complex *) in_inbuf;
    float complex *outbuf = (float complex *) in_outbuf;
    float complex *hold = (float complex *) filt->hold;
    unsigned int n = filt->coefs_n;
    unsigned int i, j, k;
    unsigned int holdsize = n * 2;
    float *h = filt->coefs;
    float complex tmp;

    for (i = 0; i < nsamples; i++) {
	/* Get the middle value, it's always multiplied by 1. */
	tmp = getc_fir_val(n + i, holdsize, inbuf, hold, nchans, chan);

	/*
	 * The h array is half of a symmetric waveform.  That waveform
	 * is always an odd number of values, but we don't include the
	 * middle value (it's always one, handled above) and h only
	 * holds the left half of the waveform.
	 */
	for (j = 0, k = holdsize; j < n; j++, k--) {
	    tmp += h[j] * (getc_fir_val(i + j, holdsize, inbuf, hold,
					nchans, chan) +
			   getc_fir_val(i + k, holdsize, inbuf, hold,
					nchans, chan));
	}

	outbuf[i * nchans + chan] = tmp * filt->gain;
    }
    for (i = 0; i < holdsize; i++) {
	unsigned int pos = nsamples - holdsize + i;
	hold[i] = inbuf[pos * nchans + chan];
    }
}

static void
filter_cleanup(struct gensio_os_funcs *o, struct filterinfo *filt)
{
    if (filt->coefs)
	o->free(o, filt->coefs);
    if (filt->hold)
	o->free(o, filt->hold);
}

/*
 * Calculate FIR filter coefficients for a lowpass filter with the
 * given transition band size, sample rate and cutoff frequency.
 * The total number of coefficients is:
 *
 *   N = (n * 2) + 1
 *
 * but the middle value is always 1 and the coefficients are symmetric
 * about the middle value.  Thus we only really need n values because
 * h[n] would be 1 and h[i] == h[N - i - 1].
 *
 * A hamming filter is applied to the coefficients.
 *
 * Adapted from http://www.labbookpages.co.uk/audio/firWindowing.html
 * and https://www.staff.ncl.ac.uk/oliver.hinton/eee305/Chapter4.pdf
 */
static float *
calc_fir_coefs(struct gensio_os_funcs *o,
	       double samplerate, double cutoff, double transband,
	       unsigned int *rn)
{
    double tba = transband / samplerate;
    double coa = cutoff / samplerate;
    double w = 2 * M_PI * (coa + .5 * tba);
    unsigned int i;
    /* For a hamming filter, transition band ~ (3.3 / N). */
    double N = ceil(3.3 / tba);
    unsigned int n;
    double x = 1.0;
    float *h;

    n = (int) (N + .1); /* N should be at a whole number, add .1 to be sure. */
    if (n % 2 == 0)
       N += 1.0;       /* N must be odd. */
    n /= 2;
    /* Here, N = n * 2 + 1 */

    h = o->zalloc(o, n * sizeof(float));
    if (!h)
	return NULL;

    for (i = n - 1; ; i--) {
	double tmp;

	/* h(x) = 2 * f * sinc() */
	tmp = sin(x * w) / (x * M_PI);

	/* Hamming window */
	tmp *= .54 - .46 * cos(2 * M_PI * (i + 1) / N);

	h[i] = tmp;

	if (i == 0)
	    break;
	x += 1.0;
    }
    *rn = n;
    return h;
}

static bool
setup_iir_filter(struct gensio_os_funcs *o,
		 struct filterinfo *filt, bool is_complex, bool lpf,
		 unsigned int framerate,
		 unsigned int cutoff, float gain)
{
    unsigned int samplesize = is_complex ? sizeof(float complex) : sizeof(float);

    if (is_complex)
	filt->do_filter = floatc_iir_filter;
    else
	filt->do_filter = float_iir_filter;

    filt->gain = gain;
    filt->coefs_n = 5;
    filt->coefs = o->zalloc(o, 5 * sizeof(float));
    if (!filt->coefs)
	return true;
    filt->hold = o->zalloc(o, 2 * samplesize);
    if (!filt->hold)
	return true;
    calc_iir_coefs(lpf, framerate, cutoff, filt->coefs, filt->coefs + 2);

    return false;
}

static bool
setup_fir_filter(struct gensio_os_funcs *o,
		 struct filterinfo *filt, bool is_complex, bool lpf,
		 unsigned int framerate,
		 unsigned int cutoff, unsigned int transition_freq, float gain)
{
    unsigned int samplesize = is_complex ? sizeof(float complex) : sizeof(float);

    /* Only support low pass filters for now. */
    if (!lpf)
	return true;

    if (is_complex)
	filt->do_filter = floatc_fir_filter;
    else
	filt->do_filter = float_fir_filter;

    /* Calculate the FIR h parameters. */
    filt->coefs = calc_fir_coefs(o, framerate, cutoff, transition_freq,
				 &filt->coefs_n);
    if (!filt->coefs)
	return true;
    filt->hold = o->zalloc(o, (2 * filt->coefs_n * samplesize));
    if (!filt->hold)
	return true;

    return false;
}

#endif /* GENSIO_RF_FILTER */
