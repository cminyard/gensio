/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2026  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This is a phase locked loop. */

#include <stdbool.h>
#include <math.h>
#include <float.h>
#include <complex.h>

#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_err.h>

#include "freqsynth.h"
#include "filters.h"

struct pll {
    struct freqsynth synth;
    struct freqsynth_iter iter;


    struct filterinfo lpfilt1; /* Feedback filter. */
    struct filterinfo lpfilt2; /* Feedback filter. */
    struct filterinfo lpfilt_out; /* Output filter. */

    float val; /* Current PLL value. */

    float last_in1;
    float last_in2;
    float curr_peak1;
    float curr_peak2;
    unsigned int peak_check_count1;
    unsigned int peak_check_count2;

    float peak; /* Running average of the peak input value. */
    float peak_inv; /* Above inverted for faster processing. */
    float damping; /* Damping factor for pll feedback. */
    float peak_damping; /* Damping factor for peak measurement. */
};

/*
 * Setup a pll object.  Setting up a pll requires careful balancing
 * for the parameters.  This can handle both real and complex input
 * streams, but will only generate real output.  See the complex
 * handling function for details on how that works.
 *
 * wave_len - A single sine wave is generated for creating the
 * waveform for the PLL.  This tells how many points to generate.  A
 * larger number will reduce the noise by making a more finely grained
 * wave, but takes more memory.  If unsure, use 1000.
 *
 * framerate - The number of samples per second for the incoming data.
 *
 * lp_cutoff - The pll has two filters, one for filtering the feedback
 * loop and one for filtering the pll output.  The necessity of the
 * output filter is questionable, but it smooths things a bit.  This
 * parameter set the cutoff value for those filters.  An IIR filter is
 * used for both.  This should be around twice the maximum frequency
 * deviation.  If it is too low it will cause instability issues.  If
 * it is too high it will let in unwanted frequencies.
 *
 * center_freq - The center frequency for the PLL.
 *
 * damping - This limits the rate of change of the PLL.  It should be
 * less than 1 or the pll will be unstable.  Too low a number and the
 * PLL won't be able to change fast enough, too high and you can get
 * unwanted oscillations.  .7 is a good value, generally.
 *
 * peak_damping - The input value is normalized to try to keep the
 * input values between -1 and 1.  If you don't do this the pll will
 * be unstable. This is done by keeping a running average of the
 * highest value seen between zero crossings.  This value sets the
 * length of the running average as the inversion of this value.  .1
 * (last 10 values) is a good number, generally.
 */
static int
setup_pll(struct gensio_os_funcs *o, struct pll *pll,
	  bool is_complex, unsigned int wave_len,
	  float framerate, float lp_cutoff,
	  float center_freq, float damping, float peak_damping)
{
    int err;

    err = setup_freqsynth(o, &pll->synth, is_complex, wave_len);
    if (err)
	return err;

    setup_freqsynth_iter(&pll->synth, &pll->iter, framerate, center_freq);

    if (setup_iir_filter(o, &pll->lpfilt1, false, true, framerate,
			 lp_cutoff, 1)) {
	cleanup_freqsynth(o, &pll->synth);
	return GE_NOMEM;
    }
    
    if (setup_iir_filter(o, &pll->lpfilt2, false, true, framerate,
			 lp_cutoff, 1)) {
	filter_cleanup(o, &pll->lpfilt1);
	cleanup_freqsynth(o, &pll->synth);
	return GE_NOMEM;
    }
    
    if (setup_iir_filter(o, &pll->lpfilt_out, false, true, framerate,
			 lp_cutoff, 1)) {
	filter_cleanup(o, &pll->lpfilt1);
	filter_cleanup(o, &pll->lpfilt2);
	cleanup_freqsynth(o, &pll->synth);
	return GE_NOMEM;
    }
    
    pll->val = 0;
    pll->peak_check_count1 = 10;
    pll->peak_check_count2 = 10;
    pll->peak = 1;
    pll->peak_inv = 1;
    pll->curr_peak1 = 0;
    pll->curr_peak2 = 0;
    pll->damping = damping;
    pll->peak_damping = peak_damping;
    return 0;
}

/*
 * Free memory associated with the PLL.
 */
static void
cleanup_pll(struct gensio_os_funcs *o, struct pll *pll)
{
    cleanup_freqsynth(o, &pll->synth);
    filter_cleanup(o, &pll->lpfilt1);
    filter_cleanup(o, &pll->lpfilt2);
    filter_cleanup(o, &pll->lpfilt_out);
}

/*
 * Internal function.  Return -1 or 1 depending on the sign of the value.
 */
static int pll_sign(float x) {
    return (x > 0) - (x < 0);
}

/*
 * Internal function.  Do the peak detection algorithm.
 */
static void
check_peak(struct pll *pll, unsigned int *peak_check_count,
	   float *last_in, float *curr_peak, float in)
{
    if (*peak_check_count == 0) {
	if (pll_sign(*last_in) != pll_sign(in)) {
	    /* Zero crossing. */

	    /* Running average of the last 1/peak_damping values. */
	    pll->peak -= pll->peak * pll->peak_damping;
	    pll->peak += *curr_peak * pll->peak_damping;
	    pll->peak_inv = 1 / pll->peak;
	    *curr_peak = 0;

	    /*
	     * Wait a while before checking again to avoid values
	     * bouncing around zero.
	     * FIXME - this should probably be tunable.
	     */
	    *peak_check_count = 1;
	} else {
	    float inp = in;

	    if (inp < 0) /* fabs()? */
		inp = -inp;
	    if (inp > *curr_peak)
		*curr_peak = inp;
	}
    } else {
	*peak_check_count -= 1;
    }
}

/*
 * Take an input to the PLL and generate an output value.  This mixes
 * the input value with the frequency synthesizer, filters the high
 * frequencies out, and thus measures the phase difference.  That is
 * used to compute the pll value.
 */
static float
pll_next_input_f(struct pll *pll, float in)
{
    float s, o, rv, n;

    /*
     * Mix the synthesizer output and the input, scaling the input to
     * try to keep it between -1 and 1.
     */
    n = freqsynth_next_f(&pll->iter, pll->val * pll->damping);
    s = n * (in * pll->peak_inv);

    /*
     * Here "s" will be sin(fin) * cos(fsynth), or:
     *
     *  .5 sin(fin + fsynth + phi) + .5 sin(fin - (fsync + phi)).
     *
     * filter out the higher frequency value to just the this
     * frequency and phase difference into "o".
     */
    pll->lpfilt1.do_filter(&s, &o, 1, 1, 0, &pll->lpfilt1);
    //printf("in=%f, n=%f, s=%f o=%f pki=%f\n", in, n, s, o, pll->peak_inv);

    /*
     * o should be a value normalized from -.5 to 0.5 telling us how
     * far we are out of sync, which will be -pi/2 to pi/2.  If
     * the input peak is 1, then the output of the filter will be
     * .5 * sin(<phase diff>).
     *
     * Note there is no way to know the difference between being
     * between 0 and pi/2 and between pi/2 and pi.  But the value will
     * move towards 0 either way, so this still works, just not as
     * fast as you might like in the pi/2 to pi range.
     */
    pll->val = - o * pll->iter.incr;

    check_peak(pll, &pll->peak_check_count1, &pll->last_in1,
	       &pll->curr_peak1, in);

    pll->last_in1 = in;

    o = -o;
    pll->lpfilt_out.do_filter(&o, &rv, 1, 1, 0, &pll->lpfilt_out);
    return rv;
}

/*
 * Like the float version, but for complex input values.
 *
 * This splits the complex input into its cosine and sine values and
 * individually mixes and filters those with the cosine and sine
 * values from the synthesizer.  The two outputs are averaged for the
 * output.
 *
 * You can't just mix the complex values.  That would mix the real and
 * imaginary parts together, and that's not what you want.  If there's
 * an incoming signal at a specific frequency, it will have a cosine
 * and sine component in the real and imaginary parts.  If all was
 * perfect, you would mix these with the cosine and sine components
 * from the synthesizer and they would produce the same value.
 */
static float
pll_next_input_c(struct pll *pll, complex float in)
{
    complex float n;
    float s1, s2, o, o1, o2, rv;

    /*
     * Mix the synthesizer output and the input, scaling the input to
     * try to keep it between -1 and 1.
     */
    n = freqsynth_next_c(&pll->iter, pll->val * pll->damping);
    s1 = creal(n) * (creal(in) * pll->peak_inv);
    s2 = cimag(n) * (cimag(in) * pll->peak_inv);

    /*
     * Here "s" will be sin(fin) * cos(fsynth), or:
     *
     *  .5 sin(fin + fsynth + phi) + .5 sin(fin - (fsync + phi)).
     *
     * filter out the higher frequency value to just the this
     * frequency and phase difference into "o".
     */
    pll->lpfilt1.do_filter(&s1, &o1, 1, 1, 0, &pll->lpfilt1);
    pll->lpfilt2.do_filter(&s2, &o2, 1, 1, 0, &pll->lpfilt2);

    o = (o1 + o2) / 2;

#if 0
    printf("in=%f+j%f, n=%f+j%f, s=%f+j%f o=%f+j%f oa=%f pki=%f\n",
	   crealf(in), cimagf(in),
	   crealf(n), cimagf(n),
	   s1, s1, o1, o2,
	   o, pll->peak_inv);
#endif

    /*
     * o1 and o2 should be a value normalized from -.5 to 0.5 telling
     * us how far we are out of sync, which will be -pi/2 to pi/2.  If
     * the input peak is 1, then the output of the filter will be .5 *
     * sin(<phase diff>).
     *
     * Note there is no way to know the difference between being
     * between 0 and pi/2 and between pi/2 and pi.  But the value will
     * move towards 0 either way, so this still works, just not as
     * fast as you might like in the pi/2 to pi range.
     */
    pll->val = - o * pll->iter.incr;

    check_peak(pll, &pll->peak_check_count1, &pll->last_in1,
	       &pll->curr_peak1, creal(in));
    check_peak(pll, &pll->peak_check_count2, &pll->last_in2,
	       &pll->curr_peak2, cimag(in));

    pll->last_in1 = creal(in);
    pll->last_in2 = cimag(in);

    o = -o;
    pll->lpfilt_out.do_filter(&o, &rv, 1, 1, 0, &pll->lpfilt_out);
    return rv;
}
