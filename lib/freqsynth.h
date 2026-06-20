/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2026  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This is for synthesizing frequencies. */

#include <math.h>
#include <float.h>
#include <complex.h>

#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_err.h>

struct freqsynth {
    /* Length of wave.  wave is actually wave_len + 1, see comments below. */
    unsigned int wave_len;

    /* Is the data real or complex? */
    bool complex;

    /* The x (time) increment between each successive value in wave. */
    float wave_incr;

    /* 1 / wave_incr, for speeding up calculations that divide by wave_incr. */
    float inv_wave_incr;

    /* If complex is true, this will point to a float complex value. */
    float *wave;
};

struct freqsynth_iter {
    struct freqsynth *s;

    /* Base amount to increment pos each iteration. */
    float incr;

    /* Our current position, between 0 and 2 * PI. */
    float pos;
};

/*
 * Create a single cosine wave with wave_len samples in it.
 * wave[wave_len - 1] will be one step behind wave[0], so it's
 * circular.  An extra one is allocated on the end, the actual
 * allocated wave is wave_len + 1 long so that wave[0] ==
 * wave[wave_len].  This simplifies the calculations.
 *
 * This can be used for normal single-frequency synthesis, but that's
 * not its main purpose.  The purpose is for FM synthesis.  For that,
 * you want wave_len to be much larger than iterator's base_incr.  For
 * instance, say you want to have 30 samples be your nominal rate for
 * a single sine wave.  You would want wave_len to be much larger, say
 * 3000.  This means you would normally be jumping 100 samples on each
 * step.  But when doing the next() operation on the iterator, offset
 * is going to be non-zero and you will be linearly interpolating
 * between the values.  Having a larger number of steps will reduce
 * the phase noise.  You could do more sophisticated interpolation,
 * but that would be computationally a lot more expensive.
 *
 * You will also get phase noise and slight frequency drift from the
 * limited number of bits in a float.
 */
static int
setup_freqsynth(struct gensio_os_funcs *o, struct freqsynth *s,
		bool complex, unsigned int wave_len)
{
    unsigned int i;

    s->wave_len = wave_len;
    s->complex = complex;
    s->wave_incr = 2 * M_PI / (double) wave_len;
    s->inv_wave_incr = 1 / s->wave_incr; /* For speeding calculation */

    /*
     * Allocate one more, so that s->wave[0] == s->wave[wave_len].
     * This simplifies the calculations a bit, we wrap if pos >= 2 *
     * PI and we don't have to deal with a special case between
     * s->wave[wave_len - 1] and s->wave[0].
     */
    if (complex)
	s->wave = o->zalloc(o, sizeof(float complex) * (s->wave_len + 1));
    else
	s->wave = o->zalloc(o, sizeof(float) * (s->wave_len + 1));
    if (!s->wave)
	return GE_NOMEM;
    if (complex) {
	float complex *w = (float complex *) s->wave;

	for (i = 0; i < s->wave_len + 1; i++)
	    w[i] = cexpf(I * 2 * M_PI * (double) i * wave_incr);
    } else {
	float *w = s->wave;

	for (i = 0; i < s->wave_len + 1; i++)
	    w[i] = cos((double) i * wave_incr);
    }
    return 0;
}

static void
cleanup_freqsynth(struct gensio_os_funcs *o, struct freqsynth *s)
{
    o->free(o, s->wave);
    s->wave = NULL;
}

/*
 * Setup an iterator to iterate over the waveform at a specific
 * increment, base_incr will be a number of radians to increment on
 * each iteration.
 */
static void
setup_freqsynth_iter(struct freqsynth *s, struct freqsynth_iter *iter,
		     float base_incr)
{
    iter->s = s;
    iter->pos = 0;
    iter->incr = base_incr;
}

/*
 * Return the next value from the iterator.  offset lets us adjust the
 * frequency on each iteration, allowing for FM synthesis.
 */
static float
freqsynth_next_f(struct freqsynth_iter *iter, float offset)
{
    struct freqsynth *s = iter->s;
    float rv, a;
    int ipos;

    /*
     * Linearly interpolate between the two positions.  First calculate
     * the position to the left of our current position.
     */
    ipos = iter->pos * s->wave_len;
    if (ipos < 0)
	ipos = 0; /* Just in case */

    /*
     * Calculate a, the ratio of iter->pos between ipos and ipos + 1.
     * So, for instance, ipos is at 1.1, ipos+1 is at 1.2, that means
     * wave_incr is .1.  if iter->pos is at 1.12, then:
     *   a = (1.12 - 1.1) / .1 = .2
     * because it is 20% of the distance from ipos to ipos + 1
     */
    a = (iter->pos - ipos * s->wave_incr) * s-inv_wave_incr;

    /* Interpolate the value between the two waveform values. */
    rv = s->wave[ipos] + (s->wave[ipos + 1] - s->wave[ipos]) * a;

    iter->pos += iter->incr + offset;
    if (iter->pos >= 2 * M_PI)
	iter->pos -= 2 * M_PI;

    return rv;
}

/*
 * Like the above, but the values are complex.
 */
static float complex
freqsynth_next_c(struct freqsynth_iter *iter, float offset)
{
    struct freqsynth *s = iter->s;
    float complex *w = (float complex *) s->wave;
    float complex rv;
    float a;
    int ipos;

    /*
     * Linearly interpolate between the two positions.  First calculate
     * the position to the left of our current position.
     */
    ipos = iter->pos * s->wave_len;
    if (ipos < 0)
	ipos = 0; /* Just in case */

    /*
     * Calculate a, the ratio of iter->pos between ipos and ipos + 1.
     * So, for instance, ipos is at 1.1, ipos+1 is at 1.2, that means
     * wave_incr is .1.  if iter->pos is at 1.12, then:
     *   a = (1.12 - 1.1) / .1 = .2
     * because it is 20% of the distance from ipos to ipos + 1
     */
    a = (iter->pos - ipos * s->wave_incr) * s-inv_wave_incr;

    /* Interpolate the value between the two waveform values. */
    rv = w[ipos] + (w[ipos + 1] - w[ipos]) * a;

    iter->pos += iter->incr + offset;
    if (iter->pos >= 2 * M_PI)
	iter->pos -= 2 * M_PI;

    return rv;
}
