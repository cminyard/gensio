/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2026  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This is for synthesizing frequencies. */

#include <stdbool.h>
#include <complex.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_err.h>

struct freqsynth {
    bool is_complex;
    unsigned int wave_len;
    float *wave;

    /* Used to convert a 0 - 2 * M_PI to an index into wave. */
    float to_idx;
};

struct freqsynth_iter {
    struct freqsynth *synth;
    float pos;
    float incr;
};

/*
 * Create a single sin wave with wave_len positions, either float or
 * complex.
 */
static int
setup_freqsynth(struct gensio_os_funcs *o, struct freqsynth *synth,
		bool is_complex, unsigned int wave_len)
{
    float incr = 2 * M_PI / (float) wave_len;
    unsigned int i;

    synth->is_complex = is_complex;
    synth->wave_len = wave_len;
    synth->to_idx = (float) wave_len;
    if (synth->is_complex) {
	complex float *w;

	w = o->zalloc(o, sizeof(complex float) * synth->wave_len);
	if (!w)
	    return GE_NOMEM;
	for (i = 0; i < synth->wave_len; i++)
	    w[i] = cexpf(I * incr * i);
	synth->wave = (float *) w;
    } else {
	synth->wave = o->zalloc(o, sizeof(float) * synth->wave_len);
	if (!synth->wave)
	    return GE_NOMEM;
	for (i = 0; i < synth->wave_len; i++)
	    synth->wave[i] = sinf(incr * i);
    }
    return 0;
}

static void
cleanup_freqsynth(struct gensio_os_funcs *o, struct freqsynth *synth)
{
    o->free(o, synth->wave);
}

/*
 * Initialize an iterator for the frequency synthesizer.  It will go
 * through the waveform incrementing the current position by wave_incr
 * each time a value is fetched.  Note that wave_incr is in radians and
 * should be 0 - 2*pi.
 */
static void
setup_freqsynth_iter_incr(struct freqsynth *synth, struct freqsynth_iter *iter,
			  float wave_incr)
{
    iter->synth = synth;
    iter->pos = 0;
    iter->incr = wave_incr;
}

/*
 * Given a framerate (samples/sec) and frequency, calculate the
 * wave_incr to pass into setup_freqsynth_iter().  
 */
static float
freqsynth_calc_iter(unsigned int framerate, float freq)
{
    return freq / (float) framerate;
}

/*
 * Set up a freqsynth iterator to put out the given frequency.
 */
static void
setup_freqsynth_iter(struct freqsynth *synth, struct freqsynth_iter *iter,
		     unsigned int framerate, float freq)
{
    setup_freqsynth_iter_incr(synth, iter,
			      freqsynth_calc_iter(framerate, freq));
}

/*
 * Return the next value for the frequency synthesizer.  It returns
 * the current position then increments the position by the increment
 * amount plus the adjust amount.  adj must be < iter->incr.
 */
static float
freqsynth_next_f(struct freqsynth_iter *iter, float adj)
{
    struct freqsynth *synth = iter->synth;
    unsigned int idx = (iter->pos * synth->to_idx) + .5;

    if (idx >= synth->wave_len)
	idx = 0;
    iter->pos += iter->incr + adj;
    if (iter->pos >= 1)
	iter->pos -= 1;
    return synth->wave[idx];
}

/* Like above, but for a complex frequency synthesizer. */
static complex float
freqsynth_next_c(struct freqsynth_iter *iter, float adj)
{
    struct freqsynth *synth = iter->synth;
    unsigned int idx = (iter->pos * synth->to_idx) + .5;
    complex float *w = (complex float *) synth->wave;

    if (idx >= synth->wave_len)
	idx = 0;
    iter->pos += iter->incr + adj;
    if (iter->pos >= 1)
	iter->pos -= 1;
    return w[idx];
}
