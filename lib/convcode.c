/*
 * Copyright 2023-2026 Corey Minyard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#define CONVCODE_DEBUG_ASSERT 1
#if CONVCODE_DEBUG_ASSERT
#include <assert.h>
#define DEBUG_ASSERT(x) assert(x)
#else
#define DEBUG_ASSERT(x) do {} while(0)
#endif

#include "convcode.h"

#define CONVCODE_DEBUG_STATES 0

#if CONVCODE_DEBUG_STATES
#include <stdio.h>
#endif

#define FORCE_INLINE __attribute__((always_inline)) inline

#if 0
/* Convenience for debugging. */
#include <stdio.h>
static void
print_bits(char *header, unsigned char *b, unsigned int len)
{
    unsigned int i;

    printf("%s: ", header);
    for (i = 0; i < len; i++) {
	printf("%d", (b[i / 8] >> (i % 8)) & 1);
    }
    printf("\n");
}
#endif

/*
 * The trellis is a two-dimensional matrix, but the size is dynamic
 * based upon how it is created.  So we use a one-dimensional matrix
 * and do our own indexing with the below two functions/macros.
 */
static convcode_state *
get_trellis_column(struct convcode *ce, unsigned int column)
{
    return ce->trellis + column * ce->trelw;
}

static convcode_state
get_trellis_entry(struct convcode *ce, unsigned int column, unsigned int row)
{
    return get_trellis_column(ce, column)[row];
}

static void
set_trellis_entry(struct convcode *ce, unsigned int column, unsigned int row,
		  convcode_state val)
{
    get_trellis_column(ce, column)[row] = val;
}

unsigned int
convcode_encoded_size(unsigned int size, unsigned int num_polys, unsigned int k,
		      bool do_tail, char *puncture, unsigned int puncture_len)
{
    size *= num_polys;
    if (do_tail)
	size += num_polys * (k - 1);

    if (puncture) {
	unsigned int i, osize, p = 0;

	/* p is the number of bits set in the puncture. */
	for (i = 0; i < puncture_len; i++) {
	    if (puncture[i])
		p++;
	}

	osize = size / puncture_len * p;

	/*
	 * The above doesn't count the items at the end if size is not
	 * a multiple of puncture_len.  So get the items at the end.
	 */
	for (i = 0; i < size % puncture_len; i++) {
	    if (puncture[i])
		osize++;
	}
	size = osize;
    }
    return size;
}

int
convcode_decoded_size(unsigned int size, unsigned int num_polys, unsigned int k,
		      bool do_tail, char *puncture, unsigned int puncture_len,
		      unsigned int *dsize)
{
    if (puncture) {
	unsigned int i, j, osize, p = 0;

	/* p is the number of bits set in the puncture. */
	for (i = 0; i < puncture_len; i++) {
	    if (puncture[i])
		p++;
	}

	osize = size / p * puncture_len;
	/*
	 * The above doesn't count the items at the end if size is not
	 * a multiple of puncture_len.  So get the items at the end.
	 * We go through the puncture matrix until we have found all
	 * the values that are punctured.
	 */
	for (i = 0, j = 0; j < size % p; i++) {
	    osize++;
	    if (puncture[i])
		j++;
	}
	/*
	 * We may have a few punctured values at the end of the
	 * current symbol, so account for those.
	 */
	while (osize % num_polys != 0 && i < puncture_len && !puncture[i]) {
	    osize++;
	    i++;
	}
	size = osize;
    }

    if (size % num_polys != 0)
	return 1;

    size /= num_polys;
    if (do_tail)
	size -= k - 1;

    *dsize = size;
    return 0;
}

int
convcode_encoded_bits_from_encoded_bytes
(unsigned int nbytes, unsigned int num_polys,
 unsigned int k, bool do_tail, unsigned int *nbits,
 char *puncture, unsigned int puncture_len)
{
    unsigned int size = nbytes * 8;
    unsigned int tail_size = 0;
    unsigned int nsyms, p = 0, i;
    int err;

    if (puncture) {
	/* p is the number of bits set in the puncture. */
	for (i = 0; i < puncture_len; i++) {
	    if (puncture[i])
		p++;
	}

	/* Go backwards until we find one that works. */
	err = convcode_decoded_size(size, num_polys, k, do_tail,
				    puncture, puncture_len, &nsyms);
	while (size >= num_polys && (err || nsyms % 8 != 0)) {
	    size--;
	    err = convcode_decoded_size(size, num_polys, k, do_tail,
					puncture, puncture_len, &nsyms);
	}
	if (size < num_polys)
	    return 1;

	*nbits = convcode_encoded_size(nsyms, num_polys, k, do_tail,
				       puncture, puncture_len);

	return 0;
    }

    if (do_tail) {
	tail_size = num_polys * (k - 1);
	if (size < tail_size)
	    return 1;
    }

    /* Total possibly symbols (decoded bits) in the actual data. */
    nsyms = (size - tail_size) / num_polys;
    /* Decrease until we are a multiple of 8. */
    nsyms -= nsyms % 8;

    *nbits = convcode_encoded_size(nsyms, num_polys, k, do_tail,
				   puncture, puncture_len);

    return 0;
}

#define CONVCODE_DEFAULT_START_STATE 0
#define CONVCODE_DEFAULT_INIT_OTHER_STATES (UINT_MAX / 4)

void
reinit_convencode(struct convcode *ce)
{
    ce->enc_state = CONVCODE_DEFAULT_START_STATE;
    ce->enc_out.out_bits = 0;
    ce->enc_out.out_bit_pos = 0;
    ce->enc_out.total_out_bits = 0;
    ce->enc_puncture_pos = 0;
}

static unsigned int
get_min_pos(struct convcode *ce)
{
    unsigned int i, cstate, min_val;

    if (ce->trelmap) {
	/* Minimum value is always at 0 because it's sorted. */
	cstate = 0;
	min_val = ce->prev_path_values[0];
    } else {
	min_val = ce->prev_path_values[0];
	cstate = 0;
	for (i = 1; i < ce->num_states; i++) {
	    if (ce->prev_path_values[i] < min_val) {
		cstate = i;
		min_val = ce->prev_path_values[i];
	    }
	}
    }

    return cstate;
}

static int
reinit_convdecode_i(struct convcode *ce, bool tail_bite)
{
    unsigned int i, cstate;

    if (!ce->prev_path_values)
	return 1;

    ce->dec_out.out_bits = 0;
    ce->dec_out.out_bit_pos = 0;
    ce->dec_out.total_out_bits = 0;

    if (tail_bite) {
	cstate = get_min_pos(ce);
	if (ce->trelmap)
	    ce->trelmap[cstate] = 0;
	ce->prev_path_values[cstate] = 0;
    } else {
	ce->prev_path_values[CONVCODE_DEFAULT_START_STATE] = 0;
	for (i = 0; i < ce->num_states; i++) {
	    if (i == CONVCODE_DEFAULT_START_STATE) {
		if (ce->trelmap)
		    ce->trelmap[i] = 0;
	    } else {
		ce->prev_path_values[i] = CONVCODE_DEFAULT_INIT_OTHER_STATES;
		if (ce->trelmap)
		    ce->trelmap[i] = CONVCODE_PSTATE_SET_BIT(i, 1);
	    }
	}
	/*
	 * Set things up so that the trelmap loop in
	 * convdecode_symbol_i() works on the first value without
	 * having to check if it's the first value.
	 */
	if (ce->tmptrel) {
	    for (i = 0; i < ce->trelw; i++)
		ce->tmptrel[i] = 0;
	}
	for (i = 0; i < ce->num_states; i++) {
	    if (i == CONVCODE_DEFAULT_START_STATE) {
		if (ce->trelmap)
		    ce->trelmap[i] = 0;
	    } else {
		ce->prev_path_values[i] = CONVCODE_DEFAULT_INIT_OTHER_STATES;
		if (ce->trelmap)
		    ce->trelmap[i] = CONVCODE_PSTATE_SET_BIT(i, 1);
	    }
	}
    }
    ce->ctrellis = 0;
    ce->leftover_bits = 0;
    ce->dec_puncture_pos = 0;
    return 0;
}

int
reinit_convdecode(struct convcode *ce)
{
    return reinit_convdecode_i(ce, false);
}

int
reinit_convdecode_tail_bite(struct convcode *ce)
{
    return reinit_convdecode_i(ce, true);
}

void
reinit_convcode(struct convcode *ce)
{
    reinit_convencode(ce);
    if (ce->prev_path_values)
	reinit_convdecode(ce);
}

/*
 * Reverse the order of the bottom "k" bits of the value.
 */
static unsigned int
reverse_bits(unsigned int k, unsigned int val)
{
    unsigned int i, rv = 0;

    for (i = 0; i < k; i++) {
	rv <<= 1;
	rv |= val & 1;
	val >>= 1;
    }
    return rv;
}

static FORCE_INLINE unsigned int
num_bits_set(unsigned int v)
{

#if 1 /* Just assume we have this. */
    return __builtin_popcount(v);
#else /* Leave this in just in case. */
    unsigned int count = 0;

    while (v) {
	count += v & 1;
	v >>= 1;
    }
    return count;
#endif
}

/* Is the number of set bits in the value odd?  Return 1 if true, 0 if false */
static FORCE_INLINE unsigned int
num_bits_is_odd(unsigned int v)
{
    return num_bits_set(v) % 2;
}

void
free_convcode(struct convcode *ce)
{
    convcode_os_funcs *o = ce->o;

    if (ce->states_alloced && ce->convert[0])
	o->free(o, (void *) ce->convert[0]);
    if (ce->states_alloced && ce->convert[1])
	o->free(o, (void *) ce->convert[1]);
    if (ce->states_alloced && ce->next_state[0])
	o->free(o, (void *) ce->next_state[0]);
    if (ce->states_alloced && ce->next_state[1])
	o->free(o, (void *) ce->next_state[1]);
    if (ce->trellis)
	o->free(o, ce->trellis);
    if (ce->tmptrel)
	o->free(o, ce->tmptrel);
    if (ce->tmptrelmap)
	o->free(o, ce->tmptrelmap);
    if (ce->trelmap)
	o->free(o, ce->trelmap);
    if (ce->prev_path_values)
	o->free(o, ce->prev_path_values);
    if (ce->curr_path_values)
	o->free(o, ce->curr_path_values);
    o->free(o, ce);
}

static int convdecode_symbol_u_t_r(struct convcode *ce, convcode_symsize symbol,
				   const uint8_t *uncertainty);
static int convdecode_symbol_nu_t_r(struct convcode *ce, convcode_symsize symbol,
				    const uint8_t *uncertainty);
static int convdecode_symbol_u_nt_r(struct convcode *ce, convcode_symsize symbol,
				    const uint8_t *uncertainty);
static int convdecode_symbol_nu_nt_r(struct convcode *ce, convcode_symsize symbol,
				     const uint8_t *uncertainty);
static int convdecode_symbol_u_t_nr(struct convcode *ce, convcode_symsize symbol,
				    const uint8_t *uncertainty);
static int convdecode_symbol_nu_t_nr(struct convcode *ce, convcode_symsize symbol,
				     const uint8_t *uncertainty);
static int convdecode_symbol_u_nt_nr(struct convcode *ce, convcode_symsize symbol,
				     const uint8_t *uncertainty);
static int convdecode_symbol_nu_nt_nr(struct convcode *ce, convcode_symsize symbol,
				      const uint8_t *uncertainty);
static int output_bits(struct convcode *ce, struct convcode_outdata *of,
		       unsigned int bits, unsigned int len);

int
setup_convcode1(struct convcode *ce, unsigned int k,
		convcode_state *polynomials, unsigned int num_polynomials,
		unsigned int max_decode_len_bits,
		unsigned int trellis_width,
		bool do_tail, bool recursive, bool do_uncertainty)
{
    unsigned int i;

    if (num_polynomials < 1 || num_polynomials > CONVCODE_MAX_POLYNOMIALS)
	return 1;
    if (k < CONVCODE_MIN_K || k > CONVCODE_MAX_K)
	return 1;

    memset(ce, 0, sizeof(*ce));
    ce->k = k;
    ce->num_states = 1 << (k - 1);
    if (trellis_width == 0 || trellis_width > ce->num_states)
	ce->trelw = ce->num_states;
    else
	ce->trelw = trellis_width;
    ce->tail_bits = do_tail ? (ce->k - 1) : 0;
    ce->recursive = recursive;
    ce->uncertainty_100 = 100;
    ce->do_uncertainty = do_uncertainty;
    ce->enc_out.output_bits = output_bits;
    ce->dec_out.output_bits = output_bits;

    /* Get the proper function for decoding symbols. */
    if (recursive) {
	if (ce->trelw < ce->num_states) {
	    if (ce->do_uncertainty)
		ce->decode_symbol = convdecode_symbol_u_t_r;
	    else
		ce->decode_symbol = convdecode_symbol_nu_t_r;
	} else {
	    if (ce->do_uncertainty)
		ce->decode_symbol = convdecode_symbol_u_nt_r;
	    else
		ce->decode_symbol = convdecode_symbol_nu_nt_r;
	}
    } else {
	if (ce->trelw < ce->num_states) {
	    if (ce->do_uncertainty)
		ce->decode_symbol = convdecode_symbol_u_t_nr;
	    else
		ce->decode_symbol = convdecode_symbol_nu_t_nr;
	} else {
	    if (ce->do_uncertainty)
		ce->decode_symbol = convdecode_symbol_u_nt_nr;
	    else
		ce->decode_symbol = convdecode_symbol_nu_nt_nr;
	}
    }

    if (num_polynomials == 2 || num_polynomials == 4 || num_polynomials == 8)
	ce->optimize_no_span = true;

    /*
     * Polynomials come in as the first bit being the high bit.  We
     * have to spin them around because we process using the first bit
     * as the low bit because it's a lot more efficient.
     */
    ce->num_polys = num_polynomials;
    for (i = 0; i < ce->num_polys; i++)
	ce->polys[i] = reverse_bits(k, polynomials[i]);

    if (max_decode_len_bits > 0)
	ce->trellis_size = max_decode_len_bits + k * ce->num_polys;

    return 0;
}

void
setup_convcode2(struct convcode *ce)
{
    unsigned int val, i, j;
    convcode_state state_mask = ce->num_states - 1;
    /*
     * Convert and next_state are read-only, but if allocated we need to
     * fill them in.
     */
    convcode_symsize *conv[2] = { (convcode_symsize *) ce->convert[0],
				  (convcode_symsize *) ce->convert[1] };
    convcode_state *next_state[2] = { (convcode_state *) ce->next_state[0],
				      (convcode_state *) ce->next_state[1] };

    if (!ce->states_alloced)
	/* Tables were passed in. */
	return;

    /*
     * Calculate the encoder output arrays and the next state arrays.
     * These are pre-calculated so encoding is just a matter of using
     * the convert arrays to get the output and the next_state arrays
     * to get the next state.
     */
    if (!ce->recursive) {
	for (i = 0; i < ce->num_states; i++) {
	    conv[0][i] = 0;
	    conv[1][i] = 0;
	    /* Go through each polynomial to calculate the output. */
	    for (j = 0; j < ce->num_polys; j++) {
		val = num_bits_is_odd((i << 1) & ce->polys[j]);
		conv[0][i] |= val << j;
		val = num_bits_is_odd(((i << 1) | 1) & ce->polys[j]);
		conv[1][i] |= val << j;
	    }

	    /* Next state is easy, just shift in the value and mask. */
	    next_state[0][i] = (i << 1) & state_mask;
	    next_state[1][i] = ((i << 1) | 1) & state_mask;
	}
    } else {
	for (i = 0; i < ce->num_states; i++) {
	    convcode_state bval0, bval1;

	    /* In recursive, the first output bit is always the value. */
	    conv[0][i] = 0;
	    conv[1][i] = 1;

	    /*
	     * This is the recursive bit calculated from the feedback
	     * and the input.
	     */
	    bval0 = num_bits_is_odd((i << 1) & ce->polys[0]);
	    bval1 = num_bits_is_odd(((i << 1) | 1) & ce->polys[0]);

	    /*
	     * Generate output from the rest of the polynomials.
	     */
	    for (j = 1; j < ce->num_polys; j++) {
		val = num_bits_is_odd(((i << 1) | bval0) & ce->polys[j]);
		conv[0][i] |= val << j;
		val = num_bits_is_odd(((i << 1) | bval1) & ce->polys[j]);
		conv[1][i] |= val << j;
	    }

	    /* Shift the recursive bit in to get the next state. */
	    next_state[0][i] = ((i << 1) | bval0) & state_mask;
	    next_state[1][i] = ((i << 1) | bval1) & state_mask;
	}
    }
#if CONVCODE_DEBUG_STATES
    printf("S0:");
    for (i = 0; i < ce->num_states; i++)
	printf(" %4.4d", ce->next_state[0][i]);
    printf("\nS1:");
    for (i = 0; i < ce->num_states; i++)
	printf(" %4.4d", ce->next_state[1][i]);
    printf("\nC0:");
    for (i = 0; i < ce->num_states; i++)
	printf(" %4.4d", ce->convert[0][i]);
    printf("\nC1:");
    for (i = 0; i < ce->num_states; i++)
	printf(" %4.4d", ce->convert[1][i]);
    printf("\n");
#endif
}

struct convcode *
alloc_convcode(convcode_os_funcs *o,
	       unsigned int k, convcode_state *polynomials,
	       unsigned int num_polynomials,
	       unsigned int max_decode_len_bits,
	       unsigned int trellis_width,
	       bool do_tail, bool recursive, bool do_uncertainty,
	       const convcode_symsize * const *convert,
	       const convcode_state * const *next_state)
{
    struct convcode *ce;

    if (!!convert != !!next_state)
	/* if you provide one state table, you must provide both. */
	return NULL;

    ce = o->zalloc(o, sizeof(*ce));
    if (!ce)
	return NULL;
    if (setup_convcode1(ce, k, polynomials, num_polynomials,
			max_decode_len_bits, trellis_width, do_tail,
			recursive, do_uncertainty)) {
	o->free(o, ce);
	return NULL;
    }

    ce->o = o;
    ce->states_alloced = !convert;

    if (!ce->states_alloced) {
	ce->convert[0] = convert[0];
	ce->convert[1] = convert[1];
	ce->next_state[0] = next_state[0];
	ce->next_state[1] = next_state[1];
    } else {
	ce->convert[0] = o->zalloc(o, sizeof(convcode_symsize) * ce->num_states);
	if (!ce->convert[0])
	    goto out_err;

	ce->convert[1] = o->zalloc(o, sizeof(convcode_symsize) * ce->num_states);
	if (!ce->convert[1])
	    goto out_err;

	ce->next_state[0] = o->zalloc(o, sizeof(convcode_state) * ce->num_states);
	if (!ce->next_state[0])
	    goto out_err;

	ce->next_state[1] = o->zalloc(o, sizeof(convcode_state) * ce->num_states);
	if (!ce->next_state[1])
	    goto out_err;
    }

    if (max_decode_len_bits > 0) {
	/* Add on a bit for the stuff at the end. */
	ce->trellis = o->zalloc(o, sizeof(*ce->trellis) *
				ce->trellis_size * ce->trelw);
	if (!ce->trellis)
	    goto out_err;

	if (ce->trelw < ce->num_states) {
	    ce->tmptrel = o->zalloc(o, sizeof(*ce->tmptrel) * ce->num_states);
	    if (!ce->tmptrel)
		goto out_err;
	    ce->tmptrelmap = o->zalloc(o, (sizeof(*ce->tmptrelmap)
					   * ce->num_states));
	    if (!ce->tmptrelmap)
		goto out_err;
	    ce->trelmap = o->zalloc(o, sizeof(*ce->trellis) * ce->num_states);
	    if (!ce->trelmap)
		goto out_err;
	}

	ce->prev_path_values = o->zalloc(o, sizeof(*ce->prev_path_values)
					 * ce->num_states);
	if (!ce->prev_path_values)
	    goto out_err;
	ce->curr_path_values = o->zalloc(o, sizeof(*ce->curr_path_values)
					 * ce->num_states);
	if (!ce->curr_path_values)
	    goto out_err;
    }

    setup_convcode2(ce);
    reinit_convcode(ce);

    return ce;

 out_err:
    free_convcode(ce);
    return NULL;
}

void
convencode_set_output(struct convcode *ce,
		      convcode_output enc_output,
		      void *enc_out_user_data)
{
    ce->enc_out.output = enc_output;
    ce->enc_out.user_data = enc_out_user_data;
}

void
convdecode_set_output(struct convcode *ce,
		      convcode_output dec_output,
		      void *dec_out_user_data)
{
    ce->dec_out.output = dec_output;
    ce->dec_out.user_data = dec_out_user_data;
}

void
convdecode_set_max_uncertainty(struct convcode *ce, uint8_t max_uncertainty)
{
    ce->uncertainty_100 = max_uncertainty;
}

static int
output_bits(struct convcode *ce, struct convcode_outdata *of,
	    unsigned int bits, unsigned int len)
{
    int rv = 0;

    of->out_bits |= bits << of->out_bit_pos;
    while (of->out_bit_pos + len >= 8) {
	unsigned int used = 8 - of->out_bit_pos;

	rv = of->output(ce, of->user_data, of->out_bits, 8);
	if (rv)
	    return rv;

	of->total_out_bits += used;
	bits >>= used;
	len -= used;
	of->out_bit_pos = 0;
	of->out_bits = bits;
    }
    of->out_bit_pos += len;
    of->total_out_bits += len;
    return rv;
}

static int
output_bits_puncture(struct convcode *ce, struct convcode_outdata *of,
		     unsigned int bits, unsigned int len)
{
    int rv;

    while (len > 0) {
	if (ce->puncture[ce->enc_puncture_pos]) {
	    rv = output_bits(ce, of, bits & 1, 1);
	    if (rv)
		return rv;
	}
	bits >>= 1;
	ce->enc_puncture_pos++;
	if (ce->enc_puncture_pos >= ce->puncture_len)
	    ce->enc_puncture_pos = 0;
	len--;
    }

    return 0;
}

static int
user_output_bits(struct convcode *ce, struct convcode_outdata *of,
		 unsigned int bits, unsigned int len)
{
    return of->output(ce, of->user_data, bits, len);
}

void
convencode_set_output_per_symbol(struct convcode *ce, bool val)
{
    if (val)
	ce->enc_out.output_bits = user_output_bits;
    else if (ce->puncture_len > 0)
	ce->enc_out.output_bits = output_bits_puncture;
    else
	ce->enc_out.output_bits = output_bits;
}

void
convcode_set_puncture(struct convcode *ce, const char *puncture_array,
		      unsigned int puncture_len)
{
    ce->puncture = puncture_array;
    ce->puncture_len = puncture_len;
    if (ce->enc_out.output_bits != user_output_bits) {
	if (ce->puncture_len > 0)
	    ce->enc_out.output_bits = output_bits_puncture;
	else
	    ce->enc_out.output_bits = output_bits;
    }
}

void
convencode_set_byte_span(struct convcode *ce, bool do_span)
{
    ce->optimize_no_span = !do_span;
}

int
convencode_bit(struct convcode *ce, unsigned int bit)
{
    convcode_state state = ce->enc_state;
    unsigned int outbits;

    /* Next state */
    ce->enc_state = ce->next_state[bit][state];

    /* Get the bits to send in the bottom bits of outbits. */
    outbits = ce->convert[bit][state];

    return ce->enc_out.output_bits(ce, &ce->enc_out, outbits, ce->num_polys);
}

int
convencode_data(struct convcode *ce,
		const unsigned char *bytes, unsigned int nbits)
{
    unsigned int nbytes = nbits / 8;
    unsigned int extra_bits = nbits % 8;
    unsigned char byte;
    unsigned int i, j;
    int rv;

    for (i = 0; i < nbytes; i++) {
	byte = bytes[i];
	for (j = 0; j < 8; j++) {
	    rv = convencode_bit(ce, byte & 1);
	    if (rv)
		return rv;
	    byte >>= 1;
	}
    }

    if (extra_bits > 0) {
	byte = bytes[i];
	for (i = 0; i < extra_bits; i++) {
	    rv = convencode_bit(ce, byte & 1);
	    if (rv)
		return rv;
	    byte >>= 1;
	}
    }

    return 0;
}

int
convencode_finish(struct convcode *ce, unsigned int *total_out_bits)
{
    unsigned int i;
    int rv;

    for (i = 0; i < ce->tail_bits; i++) {
	rv = convencode_bit(ce, 0);
	if (rv)
	    return rv;
    }
    if (ce->enc_out.out_bit_pos > 0)
	ce->enc_out.output(ce, ce->enc_out.user_data,
			   ce->enc_out.out_bits, ce->enc_out.out_bit_pos);
    if (total_out_bits)
	*total_out_bits = ce->enc_out.total_out_bits;
    return 0;
}

/*
 * Calculate the next state and output bits.  Put the output bits into
 * the output byte array.
 *
 * If do_bit_span is set, that means bits can possibly span a byte, so
 * special handling is required.  If it is not set, that means
 * num_polys is 2, 4, or 8 and the starting bit is 0, thus the bits
 * will never span a byte.  This lets the compiler optimize that code
 * away if do_bit_span is false.
 */
static FORCE_INLINE void
convencode_block_bit(struct convcode *ce, unsigned int bit,
		     bool do_bit_span, bool do_puncture,
		     unsigned char **ioutbytes,
		     unsigned int *ioutbitpos)
{
    unsigned int outbits, bits_left;
    convcode_state state = ce->enc_state;
    unsigned char *outbytes = *ioutbytes;
    unsigned int outbitpos = *ioutbitpos;
    unsigned int nbytebits = 8 - outbitpos;

    /* Next state */
    DEBUG_ASSERT(bit < 2);
    DEBUG_ASSERT(state < ce->num_states);
    ce->enc_state = ce->next_state[bit][state];

    /* Get the bits to send in the bottom bits of outbits. */
    outbits = ce->convert[bit][state];
    bits_left = ce->num_polys;

    /* Now comes the messy job of putting the bits into outbytes. */

    if (do_puncture) {
	while (bits_left > 0) {
	    bool punc = !ce->puncture[ce->enc_puncture_pos];
	    unsigned int outbit = outbits & 1;

	    ce->enc_puncture_pos++;
	    if (ce->enc_puncture_pos >= ce->puncture_len)
		ce->enc_puncture_pos = 0;
	    bits_left--;
	    outbits >>= 1;
	    if (punc)
		continue;
	    *outbytes |= outbit << outbitpos;
	    outbitpos++;
	    if (outbitpos >= 8) {
		/* Finished this byte, move to the next. */
		outbytes++;
		outbitpos = 0;
	    }
	}
	goto out;
    }

    if (do_bit_span) {
	/*
	 * If the current byte cannot hold all the bits, we have to
	 * put some of the bits in it and some into the next.
	 */
	while (bits_left > nbytebits) {
	    /* Bits going into this byte. */
	    unsigned int cbits = outbits & ((1 << nbytebits) - 1);

	    *outbytes++ |= cbits << outbitpos;
	    outbitpos = 0;
	    outbits >>= nbytebits;
	    bits_left -= nbytebits;
	    nbytebits = 8 - outbitpos;
	}
    }

    /*
     * At this point all the bits will fit into the current output
     * byte.  Stuff them in.
     */
    *outbytes |= outbits << outbitpos;
    outbitpos += bits_left;
    if (outbitpos >= 8) {
	/* Finished this byte, move to the next. */
	outbytes++;
	outbitpos = 0;
    }
 out:
    *ioutbytes = outbytes;
    *ioutbitpos = outbitpos;
}

static FORCE_INLINE void
convencode_block_partial_i(struct convcode *ce,
			   const unsigned char *bytes, unsigned int nbits,
			   bool do_bit_span, bool do_puncture,
			   unsigned char **outbytes, unsigned int *outbitpos)
{
    unsigned int nbytes = nbits / 8;
    unsigned int extra_bits = nbits % 8;
    unsigned int i, j;
    unsigned char byte;

    for (i = 0; i < nbytes; i++) {
	byte = bytes[i];
	for (j = 0; j < 8; j++) {
	    convencode_block_bit(ce, byte & 1, do_bit_span, do_puncture,
				 outbytes, outbitpos);
	    byte >>= 1;
	}
    }

    if (extra_bits > 0) {
	byte = bytes[i];
	for (j = 0; j < extra_bits; j++) {
	    convencode_block_bit(ce, byte & 1, do_bit_span, do_puncture,
				 outbytes, outbitpos);
	    byte >>= 1;
	}
    }
}

void
convencode_block_partial(struct convcode *ce,
			 const unsigned char *bytes, unsigned int nbits,
			 unsigned char **outbytes, unsigned int *outbitpos)
{
    if (ce->puncture_len > 0)
	convencode_block_partial_i(ce, bytes, nbits, true, true,
				   outbytes, outbitpos);
    else if (ce->optimize_no_span)
	convencode_block_partial_i(ce, bytes, nbits, false, false,
				   outbytes, outbitpos);
    else
	convencode_block_partial_i(ce, bytes, nbits, true, false,
				   outbytes, outbitpos);
}

void
convencode_block_final(struct convcode *ce,
		       unsigned char *outbytes, unsigned int outbitpos)
{
    unsigned int i;

    if (ce->puncture_len > 0) {
	for (i = 0; i < ce->tail_bits; i++)
	    convencode_block_bit(ce, 0, false, true, &outbytes, &outbitpos);
    } else if (ce->optimize_no_span) {
	for (i = 0; i < ce->tail_bits; i++)
	    convencode_block_bit(ce, 0, false, false, &outbytes, &outbitpos);
    } else {
	for (i = 0; i < ce->tail_bits; i++)
	    convencode_block_bit(ce, 0, true, false, &outbytes, &outbitpos);
    }
}

void
convencode_block(struct convcode *ce,
		 const unsigned char *bytes, unsigned int nbits,
		 unsigned char *outbytes, unsigned int *total_out_bits)
{
    unsigned int outbitpos = 0, i;
    unsigned char *orig_outbytes = outbytes;

    if (ce->puncture_len > 0) {
	convencode_block_partial_i(ce, bytes, nbits, false, true,
				   &outbytes, &outbitpos);
	for (i = 0; i < ce->tail_bits; i++)
	    convencode_block_bit(ce, 0, false, true, &outbytes, &outbitpos);
    } else if (ce->optimize_no_span) {
	convencode_block_partial_i(ce, bytes, nbits, false, false,
				   &outbytes, &outbitpos);
	for (i = 0; i < ce->tail_bits; i++)
	    convencode_block_bit(ce, 0, false, false, &outbytes, &outbitpos);
    } else {
	convencode_block_partial_i(ce, bytes, nbits, true, false,
				   &outbytes, &outbitpos);
	for (i = 0; i < ce->tail_bits; i++)
	    convencode_block_bit(ce, 0, true, false, &outbytes, &outbitpos);
    }
    if (total_out_bits)
	*total_out_bits = (outbytes - orig_outbytes) * 8 + outbitpos;
}

/*
 * This returns how far we think we are away from the actual value.
 *
 * When not using uncertainties, this is the number of bits that are
 * different between v1 and v2.
 *
 * When using uncertainties, if the bits are the same we use the
 * uncertainty of the bits being correct.  If the bits are different,
 * we use the uncertainty of the bits being different (which is 100% -
 * uncertainty).
 */
static FORCE_INLINE unsigned int
hamming_distance(struct convcode *ce, convcode_symsize v1, convcode_symsize v2,
		 bool do_uncertainty, const uint8_t *uncertainty)
{
    unsigned int i, rv = 0;

    if (!do_uncertainty)
	return num_bits_set(v1 ^ v2);

    for (i = 0; i < ce->num_polys; i++) {
	if ((v1 & 1) == (v2 & 1)) {
	    rv += uncertainty[i];
	} else {
	    rv += ce->uncertainty_100 - uncertainty[i];
	}
	v1 >>= 1;
	v2 >>= 1;
    }
    return rv;
}

/*
 * Return the bit that got us here from pstate (prev state) to cstate
 * (curr state).  For non-recursive mode, that's always the low bit of
 * cstate.  For recursive mode, you have to look at pstate to see what
 * it's next state is for each bit.
 */
static FORCE_INLINE int
get_prev_bit(struct convcode *ce, bool do_recursive,
	     convcode_state pstate, convcode_state cstate)
{
    if (!do_recursive)
	return cstate & 1;

    if (ce->next_state[0][pstate] == cstate)
	return 0;
#if !CONVCODE_DEBUG_STATES
    else
	return 1;
#else
    /* For debugging */
    else if (ce->next_state[1][pstate] == cstate)
	return 1;
    else {
	printf("ERR!: %x %x\n", pstate, cstate);
	DEBUG_ASSERT(0);
    }
    return 0;
#endif
}

static int
cmp_states(const void *val1, const void *val2, void *ud)
{
    struct convcode *ce = ud;
    convcode_state state1 = *((convcode_state *) val1);
    convcode_state state2 = *((convcode_state *) val2);
    convcode_state pstate1 = ce->tmptrel[state1];
    convcode_state pstate2 = ce->tmptrel[state2];
    bool invalid1, invalid2;
    unsigned int dist1, dist2;
    int rv = 0;

    pstate1 = CONVCODE_PSTATE_VAL(pstate1);
    pstate2 = CONVCODE_PSTATE_VAL(pstate2);
    invalid1 = CONVCODE_PSTATE_BIT(ce->trelmap[pstate1]);
    invalid2 = CONVCODE_PSTATE_BIT(ce->trelmap[pstate2]);
    dist1 = ce->curr_path_values[state1];
    dist2 = ce->curr_path_values[state2];

    /* Entries going back to invalid pstates are always bigger. */
    if (invalid1 && !invalid2) {
	rv = 1;
    } else if (!invalid1 && invalid2) {
	rv = -1;
    } else if (dist1 < dist2) {
	rv = -1;
    } else if (dist1 > dist2) {
	rv = 1;
#if 0 /* The below will give an exact sort order. */
    } else if (state1 < state2) {
	rv = -1;
    } else if (state1 > state2) {
	rv = 1;
#endif
    }
    return rv;
}

static void
sort_tmptrel(struct convcode *ce)
{
#if 1
    /*
     * This is an optimized selection sort.  We only care about the
     * trewl smallest values, so we only grab that many.  This is
     * generally faster than any normal sort unless trelw is very
     * large.  If trelw is large, ifdef out this section for the
     * quicksort implementation.
     */
    unsigned int i, j;

    for (i = 0; i < ce->trelw; i++) {
	unsigned int smallest = i;

	/* Find the smallest value */
	for (j = i + 1; j < ce->num_states; j++) {
	    if (cmp_states(&ce->tmptrelmap[j], &ce->tmptrelmap[smallest],
			   ce) < 0)
		smallest = j;
	}

	if (smallest != i) {
	    unsigned int tmp;

	    /* Put the smallest value into i */
	    tmp = ce->tmptrelmap[smallest];
	    ce->tmptrelmap[smallest] = ce->tmptrelmap[i];
	    ce->tmptrelmap[i] = tmp;
	}
    }
#else
    /* If you have a large trelw value, this might perform better. */
#include "qsort.h"
    convcode_state tmp;
#define LESS(i, j) (cmp_states(&ce->tmptrelmap[i], &ce->tmptrelmap[j], ce) < 0)
#define SWAP(i, j) tmp = ce->tmptrelmap[i], ce->tmptrelmap[i] = ce->tmptrelmap[j], ce->tmptrelmap[j] = tmp
    QSORT(ce->num_states, LESS, SWAP);
#endif

#if 0
    printf("\nX\n");
    for (unsigned int i = 0; i < ce->num_states; i++) {
	convcode_state pstate = ce->tmptrel[ce->tmptrelmap[i]];
	unsigned int dist = ce->curr_path_values[ce->tmptrelmap[i]];
	bool invalid;

	invalid = CONVCODE_PSTATE_BIT(ce->trelmap[pstate]);
	pstate = CONVCODE_PSTATE_VAL(pstate);
	printf("  %u %u %u %d:%u\n", i, ce->tmptrelmap[i], pstate, invalid, dist);
    }
#endif
}

static FORCE_INLINE void
decode_one_state(struct convcode *ce, unsigned int i, convcode_symsize symbol,
		 unsigned int *prevp, unsigned int *currp, convcode_state *trel,
		 bool do_uncertainty, bool do_recursive,
		 const uint8_t *uncertainty)
{
    convcode_state pstate1, pstate2;
    unsigned int bit1, bit2;
    unsigned int dist1, dist2;

    /*
     * This state could have come from two different previous
     * states, one with the top bit set (pstate2) and with with
     * the top bit clear (pstate1).  We check both of those.
     */
    pstate1 = i >> 1;
    pstate2 = pstate1 | (1 << (ce->k - 2));

    /*
     * Now calculate the distance (number of errors without
     * uncertainty, else the total uncertainty) based on each previous
     * state.
     */
    dist1 = prevp[pstate1];
    bit1 = get_prev_bit(ce, do_recursive, pstate1, i);
    DEBUG_ASSERT(bit1 < 2);
    DEBUG_ASSERT(pstate1 < ce->num_states);
    dist1 += hamming_distance(ce, ce->convert[bit1][pstate1], symbol,
			      do_uncertainty, uncertainty);
    dist2 = prevp[pstate2];
    bit2 = get_prev_bit(ce, do_recursive, pstate2, i);
    DEBUG_ASSERT(bit2 < 2);
    DEBUG_ASSERT(pstate2 < ce->num_states);
    dist2 += hamming_distance(ce, ce->convert[bit2][pstate2], symbol,
			      do_uncertainty, uncertainty);

    /*
     * Pick the previous state with the lowest error or uncertainty.
     * The top bit of trel[i] is where the actual bit value is stored.
     */
    if (dist2 < dist1) {
	trel[i] = CONVCODE_PSTATE_SET_BIT(pstate2, bit2);
	currp[i] = dist2;
    } else {
	trel[i] = CONVCODE_PSTATE_SET_BIT(pstate1, bit1);
	currp[i] = dist1;
    }
}

#if DO_SIMD
typedef unsigned int v4su __attribute__ ((vector_size (16)));
#endif

/*
 * We come here with a symbol (the number of bits is the number of
 * polynomials) The uncertainty is an array of 8-bit values, one for
 * each bit, low bit first.
 */
static FORCE_INLINE int
convdecode_symbol_i(struct convcode *ce, convcode_symsize symbol,
		    bool do_tmptrel, bool do_uncertainty, bool do_recursive,
		    const uint8_t *uncertainty)
{
    /* Previous error count/uncertainty values. */
    unsigned int *prevp = ce->prev_path_values;
    /* Error count/uncertainty values we will calculate. */
    unsigned int *currp = ce->curr_path_values;
    unsigned int i;
    /* Trellis we are working on. */
    convcode_state *trel;

#if CONVCODE_DEBUG_STATES
    DEBUG_ASSERT(ce->ctrellis + ce->num_polys < ce->trellis_size);
#endif

    /*
     * If the trellis width is less than the number of states, we have
     * a temporary trellis array that holds the number of states.
     * Otherwise we work directly in the trellis.
     */
    if (do_tmptrel)
	trel = ce->tmptrel;
    else
	trel = get_trellis_column(ce, ce->ctrellis);

#if DO_SIMD
    /*
     * This is an SIMD implementation using GCC builtins, only valid
     * for non-recursive without uncertainty.  It does 4 values at a
     * time.  See the README for details on this.
     */
    if (!do_recursive && !do_uncertainty) {
	for (i = 0; i < ce->num_states; ) {
	    convcode_state pstate1[4], pstate2[4];
	    v4su cmpv1, cmpv2;
	    v4su dist1, dist2;
	    v4su tmp;
	    unsigned int j;
#define X(v) ((v) & 1)

	    for (j = 0; j < 4; j++) {
		pstate1[j] = (i + j) >> 1;
		pstate2[j] = ((i + j) >> 1) | (1 << (ce->k - 2));
	    }

	    for (j = 0; j < 4; j++)
		cmpv1[j] = ce->convert[X(i + j)][pstate1[j]];

	    for (j = 0; j < 4; j++)
		cmpv2[j] = ce->convert[X(i + j)][pstate2[j]];

	    for (j = 0; j < 4; j++)
		dist1[j] = prevp[pstate1[j]];

	    for (j = 0; j < 4; j++)
		dist2[j] = prevp[pstate2[j]];

	    /*
	     * Two implementations of doing popcount are shown below.
	     * There's not much performance difference on my system.
	     */
	    cmpv1 ^= symbol;
	    /* Russian peasant algorithm in SIMD */
	    cmpv1 = (cmpv1 & 0x55555555) + ((cmpv1 >> 1) & 0x55555555);
	    cmpv1 = (cmpv1 & 0x33333333) + ((cmpv1 >> 2) & 0x33333333);
	    cmpv1 = (cmpv1 & 0x0f0f0f0f) + ((cmpv1 >> 4) & 0x0f0f0f0f);
	    cmpv1 = (cmpv1 & 0x00ff00ff) + ((cmpv1 >> 8) & 0x00ff00ff);
	    cmpv1 = (cmpv1 & 0x0000ffff) + ((cmpv1 >> 16) & 0x0000ffff);
	    dist1 += cmpv1;

	    cmpv2 ^= symbol;
	    /* Builtin instruction, but not vectorized */
	    for (j = 0; j < 4; j++)
		tmp[j] = __builtin_popcount(cmpv2[j]);
	    dist2 += tmp;

	    tmp = dist2 < dist1;

	    for (j = 0; j < 4; j++, i++) {
		if (tmp[j]) {
		    trel[i] = CONVCODE_PSTATE_SET_BIT(pstate2[j], X(i));
		    currp[i] = dist2[j];
		} else {
		    trel[i] = CONVCODE_PSTATE_SET_BIT(pstate1[j], X(i));
		    currp[i] = dist1[j];
		}
	    }
	}
#undef X
    } else
#endif
    {
	/*
	 * For each possible state, calculate the most probable previous
	 * state and the total error or uncertainty for that state.
	 *
	 * k must be at least 3, so num_states must be at least 4 and must
	 * be a multiple of 4.  So we can unroll the loop a bit.
	 */
	for (i = 0; i < ce->num_states; ) {
	    decode_one_state(ce, i++, symbol, prevp, currp, trel,
			     do_uncertainty, do_recursive, uncertainty);
	    decode_one_state(ce, i++, symbol, prevp, currp, trel,
			     do_uncertainty, do_recursive, uncertainty);
	    decode_one_state(ce, i++, symbol, prevp, currp, trel,
			     do_uncertainty, do_recursive, uncertainty);
	    decode_one_state(ce, i++, symbol, prevp, currp, trel,
			     do_uncertainty, do_recursive, uncertainty);
	}
    }

#if CONVCODE_DEBUG_STATES
    printf("\nT(%u) %x\n", ce->ctrellis, bits);
    for (i = 0; i < ce->num_states; i++) {
	convcode_state pstate = CONVCODE_PSTATE_VAL(trel[i]);
	int bit = CONVCODE_PSTATE_BIT(trel[i]);

	printf(" %u:%d:%4.4u", i, bit, pstate);
    }
    printf("\n");
#endif

    /*
     * If the trellis width is less than the number of states, we have
     * to find the most probable values in the temporary trellis array
     * and put them into the trellis.
     */
    if (do_tmptrel) {
	convcode_state *ntrel = get_trellis_column(ce, ce->ctrellis);

	for (i = 0; i < ce->num_states; i++)
	    ce->tmptrelmap[i] = i;

	sort_tmptrel(ce);

	for (i = 0; i < ce->trelw; i++) {
	    convcode_state v = ce->tmptrelmap[i];
	    int bit = CONVCODE_PSTATE_BIT(trel[v]);
	    convcode_state pstate = CONVCODE_PSTATE_VAL(trel[v]);

	    ntrel[i] = CONVCODE_PSTATE_SET_BIT(ce->trelmap[pstate], bit);
	}

	for (i = 0; i < ce->trelw; i++)
	    ce->trelmap[ce->tmptrelmap[i]] = i;
	for (; i < ce->num_states; i++)
	    /* mark invalid */
	    ce->trelmap[ce->tmptrelmap[i]] = CONVCODE_PSTATE_SET_BIT(0, 1);
    }

#if CONVCODE_DEBUG_STATES
    if (ce->trelmap) {
	for (i = 0; i < ce->trelw; i++) {
	    convcode_state pstate = get_trellis_entry(ce, ce->ctrellis, i);
	    int bit = CONVCODE_PSTATE_BIT(pstate);

	    pstate = CONVCODE_PSTATE_VAL(pstate);
	    printf(" %u:%d:%4.4u", i, bit, pstate);
	}
	printf("\n");
	for (i = 0; i < ce->trelw; i++)
	    printf(" %u:%4.4u", i, ce-> tmptrelmap[i]);
	printf("\n");
	for (i = 0; i < ce->num_states; i++) {
	    if (!(ce->trelmap[i] & CONVCODE_PSTATE_SET_BIT(0, 1)))
		printf(" %u:%u", i, ce->trelmap[i]);
	}
	printf("\n");
    }
    for (i = 0; i < ce->num_states; i++)
	printf(" %u:%4.4u", i, currp[i]);
    printf("\n");
#endif
    ce->ctrellis++;

    /* Swap the values so we don't have to copy curr to prev. */
    ce->curr_path_values = prevp;
    ce->prev_path_values = currp;
    return 0;
}

/*
 * Various decode symbol functions, we do this to optimize the
 * performance by having functions where checking the uncertainty and
 * the tmptrel and the do_recursive are optimized away.
 */
static int
convdecode_symbol_u_t_r(struct convcode *ce, convcode_symsize symbol,
			const uint8_t *uncertainty)
{
    return convdecode_symbol_i(ce, symbol, true, true, true, uncertainty);
}

static int
convdecode_symbol_nu_t_r(struct convcode *ce, convcode_symsize symbol,
			 const uint8_t *uncertainty)
{
    return convdecode_symbol_i(ce, symbol, true, false, true, NULL);
}

static int
convdecode_symbol_u_nt_r(struct convcode *ce, convcode_symsize symbol,
			 const uint8_t *uncertainty)
{
    return convdecode_symbol_i(ce, symbol, false, true, true, uncertainty);
}

static int
convdecode_symbol_nu_nt_r(struct convcode *ce, convcode_symsize symbol,
			  const uint8_t *uncertainty)
{
    return convdecode_symbol_i(ce, symbol, false, false, true, NULL);
}

static int
convdecode_symbol_u_t_nr(struct convcode *ce, convcode_symsize symbol,
			 const uint8_t *uncertainty)
{
    return convdecode_symbol_i(ce, symbol, true, true, false, uncertainty);
}

static int
convdecode_symbol_nu_t_nr(struct convcode *ce, convcode_symsize symbol,
			  const uint8_t *uncertainty)
{
    return convdecode_symbol_i(ce, symbol, true, false, false, NULL);
}

static int
convdecode_symbol_u_nt_nr(struct convcode *ce, convcode_symsize symbol,
			  const uint8_t *uncertainty)
{
    return convdecode_symbol_i(ce, symbol, false, true, false, uncertainty);
}

static int
convdecode_symbol_nu_nt_nr(struct convcode *ce, convcode_symsize symbol,
			   const uint8_t *uncertainty)
{
    return convdecode_symbol_i(ce, symbol, false, false, false, NULL);
}

/*
 * Extract nbits bits from bytes at offset curr.
 */
static unsigned int
extract_bits(const unsigned char *bytes, unsigned int curr, unsigned int nbits)
{
    unsigned int v = 0;
    unsigned int bits_left = nbits;
    unsigned int opos = 0;
    unsigned int pos = curr / 8;
    unsigned int bit = curr % 8;
    unsigned int byte_avail;

    byte_avail = 8 - bit;
    while (byte_avail <= bits_left) {
	v |= ((unsigned int) (bytes[pos] >> bit)) << opos;
	bits_left -= byte_avail;
	opos += byte_avail;
	bit = 0;
	byte_avail = 8;
	bytes++;
    }
    if (bits_left)
	v |= ((unsigned int) (bytes[pos] >> bit)) << opos;
    v &= (1 << nbits) - 1;
    return v;
}

/*
 * Extract symbol bits from bytes at offset curr, adding punctured bits
 * as necessary.
 *
 * The bools are for optimization, passing them in as constants should
 * cause unused portions of this code to be optimized away.
 *
 * Returns true if we got a full symbol, or false if not.
 *
 * If a full symbol is not extracted, the unused bits are stored in
 * the leftover bits.
 */
static FORCE_INLINE bool
extract_sym(struct convcode *ce,
	    bool do_leftover, bool do_puncture,
	    const unsigned char *bytes, unsigned int size,
	    unsigned int *ocurr,
	    const uint8_t *uncertainty, uint8_t *out_uncertainty,
	    convcode_symsize *out_sym)
{
    unsigned int nbits = ce->num_polys;
    unsigned int i, curr = *ocurr;
    unsigned int pos = curr / 8;
    unsigned int bit = curr % 8;
    unsigned int opos = 0;
    convcode_symsize v = 0;
    bool punc;

    if (do_leftover) {
	opos = ce->leftover_bits;
	if (uncertainty) {
	    for (i = 0; i < opos; i++)
		out_uncertainty[i] = ce->leftover_uncertainty[i];
	}
	v = ce->leftover_bits_data;
	DEBUG_ASSERT(opos < nbits);
	nbits -= opos;
	ce->leftover_bits = 0;
	ce->leftover_bits_data = 0;
    }

    punc = do_puncture && !ce->puncture[ce->dec_puncture_pos];
    while (nbits > 0 && (curr < size || punc)) {
	if (punc) {
	    /* Stuff in a punctured zero. */
	    if (uncertainty) {
		out_uncertainty[opos] = ce->uncertainty_100 / 2;
	    }
	    opos++;
	} else {
	    v |= ((bytes[pos] >> bit) & 1) << opos;
	    bit++;
	    if (uncertainty) {
		out_uncertainty[opos] = uncertainty[curr];
	    }
	    opos++;
	    if (bit >= 8) {
		bit = 0;
		pos++;
	    }
	    curr++;
	}
	if (do_puncture) {
	    ce->dec_puncture_pos++;
	    if (ce->dec_puncture_pos >= ce->puncture_len)
		ce->dec_puncture_pos = 0;
	}
	nbits--;
	punc = do_puncture && !ce->puncture[ce->dec_puncture_pos];
    }

    *ocurr = curr;

    if (opos < ce->num_polys) {
	ce->leftover_bits = opos;
	ce->leftover_bits_data = v;
	if (uncertainty) {
	    for (i = 0; i < opos; i++)
		ce->leftover_uncertainty[i] = out_uncertainty[i];
	}
	return false;
    }

    *out_sym = v;

    return true;
}

int
convdecode_data(struct convcode *ce,
		const unsigned char *bytes, unsigned int nbits)
{
    unsigned int curr_bit = 0;
    convcode_symsize sym;
    int rv;

    if (ce->puncture_len > 0) {
	/*
	 * do_leftover version.  do_leftover is set to false on the
	 * loop one so that code will be optimized away.
	 */
	if (!extract_sym(ce, true, true, bytes, nbits, &curr_bit,
			 NULL, NULL, &sym))
	    return 0;

	do {
	    rv = convdecode_symbol(ce, sym);
	    if (rv)
		return rv;
	} while (extract_sym(ce, false, true, bytes, nbits, &curr_bit,
			     NULL, NULL, &sym));
    } else {
	/*
	 * do_leftover version.  do_leftover is set to false on the
	 * loop one so that code will be optimized away.
	 */
	if (!extract_sym(ce, true, false, bytes, nbits, &curr_bit,
			 NULL, NULL, &sym))
	    return 0;

	do {
	    rv = convdecode_symbol(ce, sym);
	    if (rv)
		return rv;
	} while (extract_sym(ce, false, false, bytes, nbits, &curr_bit,
			     NULL, NULL, &sym));
    }

    return 0;
}

int
convdecode_data_u(struct convcode *ce,
		  const unsigned char *bytes, unsigned int nbits,
		  const uint8_t *uncertainty)
{
    uint8_t out_uncertainty[CONVCODE_MAX_K];
    unsigned int curr_bit = 0;
    convcode_symsize sym;
    int rv;

    if (ce->puncture_len > 0) {
	/*
	 * do_leftover version.  do_leftover is set to false on the
	 * loop one so that code will be optimized away.
	 */
	if (!extract_sym(ce, true, true, bytes, nbits, &curr_bit,
			 uncertainty, out_uncertainty, &sym))
	    return 0;

	do {
	    rv = convdecode_symbol_u(ce, sym, out_uncertainty);
	    if (rv)
		return rv;
	} while (extract_sym(ce, false, true, bytes, nbits, &curr_bit,
			     uncertainty, out_uncertainty, &sym));
    } else {
	/*
	 * do_leftover version.  do_leftover is set to false on the
	 * loop one so that code will be optimized away.
	 */
	if (!extract_sym(ce, true, false, bytes, nbits, &curr_bit,
			 uncertainty, out_uncertainty, &sym))
	    return 0;

	do {
	    rv = convdecode_symbol_u(ce, sym, out_uncertainty);
	    if (rv)
		return rv;
	} while (extract_sym(ce, false, false, bytes, nbits, &curr_bit,
			     uncertainty, out_uncertainty, &sym));
    }

    return 0;
}

int
convdecode_finish(struct convcode *ce, unsigned int *total_out_bits,
		  unsigned int *num_errs)
{
    unsigned int i, extra_bits = ce->tail_bits;
    unsigned int min_val = ce->prev_path_values[0], cstate = 0;

    if (ce->puncture_len > 0) {
	/*
	 * If puncturing, the last bits may be punctured and thus not
	 * there yet.  In that case, leftover_bits will be > 0 and we
	 * need to fill them out.  Just shove in zeros until the
	 * symbol is filled out.
	 */
	unsigned char byte = 0;
	uint8_t uncertainty = 50;

	while (ce->leftover_bits > 0) {
	    if (ce->do_uncertainty)
		convdecode_data_u(ce, &byte, 1, &uncertainty);
	    else
		convdecode_data(ce, &byte, 1);
	}
    }

    /* Find the minimum value in the final path. */
    if (ce->trelmap) {
	/* Minimum value is always at 0 because it's sorted. */
	cstate = 0;
    } else {
	for (i = 1; i < ce->num_states; i++) {
	    if (ce->prev_path_values[i] < min_val) {
		cstate = i;
		min_val = ce->prev_path_values[i];
	    }
	}
    }

    /* Go backwards through the trellis to find the full path. */
    for (i = ce->ctrellis; i > 0; ) {
	convcode_state pstate; /* Previous state */
	int bit;

	i--;
	pstate = get_trellis_entry(ce, i, cstate);
	bit = CONVCODE_PSTATE_BIT(pstate);
	pstate = CONVCODE_PSTATE_VAL(pstate);
#if CONVCODE_DEBUG_STATES
	DEBUG_ASSERT(pstate < ce->trelw);
#endif

	/*
	 * Store the bit values in position 0 so we can play it back
	 * forward easily.
	 */
	set_trellis_entry(ce, i, 0, bit);
	cstate = pstate;
    }

    /* We've stored the values in index 0 of each column, play it forward. */
    for (i = 0; i < ce->ctrellis - extra_bits; i++) {
	int rv = ce->dec_out.output_bits(ce, &ce->dec_out,
					 get_trellis_entry(ce, i, 0), 1);
	if (rv)
	    return rv;
    }
    if (ce->dec_out.out_bit_pos > 0)
	ce->dec_out.output(ce, ce->dec_out.user_data,
			   ce->dec_out.out_bits, ce->dec_out.out_bit_pos);
    if (num_errs)
	*num_errs = min_val;
    if (total_out_bits)
	*total_out_bits = ce->dec_out.total_out_bits;
    return 0;
}

/*
 * Go backwards one level on the trellis, filling in the output data.
 * The compiler should optimize away the do_output and
 * do_output_uncertainty checks since we pass in constants there.
 */
static FORCE_INLINE unsigned int
backwards_one_level(struct convcode *ce, const unsigned char *bytes,
		    const uint8_t *uncertainty, unsigned int cstate,
		    bool do_uncertainty, convcode_symsize sym,
		    unsigned int i, bool do_output,
		    unsigned int *cuncertainty,
		    unsigned char *outbytes,
		    bool do_output_uncertainty,
		    unsigned int *output_uncertainty)
{
    convcode_state pstate; /* Previous state */
    unsigned int bit;

    pstate = get_trellis_entry(ce, i, cstate);
    bit = CONVCODE_PSTATE_BIT(pstate);
    pstate = CONVCODE_PSTATE_VAL(pstate);
#if CONVCODE_DEBUG_STATES
    DEBUG_ASSERT(pstate < ce->trelw);
#endif

    /*
     * Store the bit values in the user-supplied data.
     */
    if (do_output)
	outbytes[i / 8] |= bit << (i % 8);

    if (do_output_uncertainty) {
	if (do_output)
	    output_uncertainty[i] = *cuncertainty;

	/*
	 * Subtract off the distance we had computed to here to get the
	 * previous uncertainty value.
	 */
	*cuncertainty -= hamming_distance(ce, ce->convert[bit][pstate],
					  sym, do_uncertainty,
					  uncertainty);
    }

    return pstate;
}

/*
 * This very complicated routine extracts the information for a symbol
 * as we go backwards through the trellis.  This gets the symbol and
 * the uncertainty info for the particular output bits.
 *
 * When decoding, keeping all the information around about
 * uncertainties would take a lot of memory.  Instead, we recompute it
 * as we go back through the trellis so it doesn't have to be stored.
 */
static FORCE_INLINE void
get_last_sym_info(struct convcode *ce, const unsigned char *bytes,
		  unsigned int *inpos, const uint8_t *uncertainty,
		  convcode_symsize *sym, uint8_t *tmp_uncertainty)
{
    unsigned int j;

    if (ce->puncture_len > 0) {
	/*
	 * Puncturing, we have to take into account the fact that some
	 * of the bits were not in the input and they had a specific
	 * uncertainty set.
	 */
	for (j = 0; j < ce->num_polys; j++) {
	    unsigned int pos = ce->num_polys - j - 1;

	    if (ce->dec_puncture_pos == 0)
		ce->dec_puncture_pos = ce->puncture_len - 1;
	    else
		ce->dec_puncture_pos--;

	    if (ce->puncture[ce->dec_puncture_pos]) {
		(*inpos)--;
		if (uncertainty)
		    tmp_uncertainty[pos] = uncertainty[*inpos];
		*sym |= extract_bits(bytes, *inpos, 1) << pos;
	    } else {
		if (uncertainty)
		    tmp_uncertainty[pos] = ce->uncertainty_100 / 2;
	    }
	}
    } else {
	/* Easier when not puncturing, just get the symbols and uncertainties */
	if (uncertainty) {
	    for (j = 0; j < ce->num_polys; j++)
		tmp_uncertainty[j] = uncertainty[--(*inpos)];
	} else {
	    *inpos -= ce->num_polys;
	}
	*sym = extract_bits(bytes, *inpos, ce->num_polys);
    }
}

int
convdecode_block(struct convcode *ce, const unsigned char *bytes,
		 unsigned int nbits, const uint8_t *uncertainty,
		 unsigned char *outbytes,
		 unsigned int *output_uncertainty,
		 unsigned int *num_errs)
{
    int rv;
    unsigned int i, extra_bits = ce->tail_bits;
    unsigned int min_val, cuncertainty, cstate;
    unsigned int inpos = nbits;
    uint8_t tmp_uncertainty[CONVCODE_MAX_K];

    if (uncertainty)
	rv = convdecode_data_u(ce, bytes, nbits, uncertainty);
    else
	rv = convdecode_data(ce, bytes, nbits);
    if (rv)
	return rv;

    /* Find the minimum value in the final path. */
    cstate = get_min_pos(ce);
    min_val = ce->prev_path_values[cstate];

    /* Go backwards through the trellis to find the full path. */
    cuncertainty = min_val;
    i = ce->ctrellis;

#if 0
    /*
     * Leave this in for testing, when working on this it's easier to
     * do with just one than the mess below..
     */
    /* This won't optimize away the checks in backwards_one_level(). */
    while (i > 0) {
	convcode_symsize sym = 0;

	i--;
	get_last_sym_info(ce, bytes, &inpos, uncertainty,
			  &sym, tmp_uncertainty);
	cstate = backwards_one_level(ce, bytes, tmp_uncertainty, cstate,
				     uncertainty != NULL, sym,
				     i, extra_bits == 0, &cuncertainty,
				     outbytes,
				     output_uncertainty != NULL,
				     output_uncertainty);
	if (extra_bits > 0)
	    extra_bits--;
    }
#else
    /*
     * Optimize away output, output_uncertainty and uncertainty
     * checks.  This improves performance a little bit, maybe 1%.  The
     * majority of time is spent creating the trellis.
     */
    if (output_uncertainty) {
	if (uncertainty) {
	    while (extra_bits > 0 && i > 0) {
		convcode_symsize sym = 0;

		i--;
		get_last_sym_info(ce, bytes, &inpos, uncertainty,
				  &sym, tmp_uncertainty);
		cstate = backwards_one_level(ce, bytes, tmp_uncertainty, cstate,
					     true, sym,
					     i, false, &cuncertainty, outbytes,
					     true, output_uncertainty);
		extra_bits--;
	    }

	    while (i > 0) {
		convcode_symsize sym = 0;

		i--;
		get_last_sym_info(ce, bytes, &inpos, uncertainty,
				  &sym, tmp_uncertainty);
		cstate = backwards_one_level(ce, bytes, tmp_uncertainty, cstate,
					     true, sym,
					     i, true, &cuncertainty, outbytes,
					     true, output_uncertainty);
	    }
	} else {
	    while (extra_bits > 0 && i > 0) {
		convcode_symsize sym = 0;

		i--;
		get_last_sym_info(ce, bytes, &inpos, NULL, &sym, NULL);
		cstate = backwards_one_level(ce, bytes, NULL, cstate,
					     false, sym,
					     i, false, &cuncertainty, outbytes,
					     true, output_uncertainty);
		extra_bits--;
	    }

	    while (i > 0) {
		convcode_symsize sym = 0;

		i--;
		get_last_sym_info(ce, bytes, &inpos, NULL, &sym, NULL);
		cstate = backwards_one_level(ce, bytes, NULL, cstate,
					     false, sym,
					     i, true, &cuncertainty, outbytes,
					     true, output_uncertainty);
	    }
	}
    } else {
	while (extra_bits > 0 && i > 0) {
	    convcode_symsize sym = 0;

	    i--;
	    get_last_sym_info(ce, bytes, &inpos, NULL, &sym, NULL);
	    cstate = backwards_one_level(ce, bytes, NULL, cstate,
					 false, sym,
					 i, false, &cuncertainty, outbytes,
					 false, NULL);
	    extra_bits--;
	}

	while (i > 0) {
	    convcode_symsize sym = 0;

	    i--;
	    get_last_sym_info(ce, bytes, &inpos, NULL, &sym, NULL);
	    cstate = backwards_one_level(ce, bytes, NULL, cstate,
					 false, sym,
					 i, true, &cuncertainty, outbytes,
					 false, NULL);
	}
    }
#endif

    if (num_errs)
	*num_errs = min_val;

    return 0;
}

#ifdef CONVCODE_TESTS

/*
 * Test code.
 *
 * Compile and run with -t to run tests.
 *
 * To supply your own input and output, run as:
 *
 * ./convcode [-t] [-j] [-c] [-g] [-u] [-b] [-m <size>] [-l <loops] [-x]
 *        [-w <trellis width>] [-er <rate>]
 *        [-s <start state>] [-i <init_val>]
 *        -p <poly1> [ -p <poly2> ... ] k <bits>
 *
 * where bits is a sequence of 0 or 1.

 * The -x option disables the "tail" of the encoder and expectation of
 * the tail in the decoder.  (see the convcode.h file about do_tail).
 *
 * The -t, -j, and -c option do tests, more on that later.
 *
 * The -g option output coding tables, more on that later.
 *
 * The -u, -l, -b, and -m options only work with -j, see that section below.
 *
 * The -w option sets the trellis width.  Default is 0, or 2 ^ (K - 1).
 *
 * For instance, to decode some data with the Voyager coder, do:
 *
 * $ ./convcode -p 0171 -p 0133 7 00110011
 *   0000111010000000111111100111
 *   bits = 28
 *
 * To then decode that data, do:
 *
 * $ ./convcode -p 0171 -p 0133 -d 7 0000111010000000111111100111
 *   00110011
 *   errors = 0
 *   bits = 8
 *
 * The -g option generates the convert and next_state tables that can
 * be passed into alloc_convcode().
 *
 * The -t option runs a set of built-in tests on the coder.  The following
 * options are valid with -t:
 *
 *    -w - Set the trellis width.
 *    -x - disable the tail.
 *
 * All other options are ignored.  You do not set the K when running
 * these tests.  The tests themselves are stolen from
 * https://github.com/xukmin/viterbi.git
 *
 * The -j option does a random error injection test.
 * You do something like:
 *
 *   ./convcode -p 0171 -p 0133 -j 7
 *
 * And it will run a test on a randomly filled array of data.  It will run
 * a number of loops starting at 0 injected error, then inserting 1 error
 * then 2, and so on.  It will continue to increase the number of errors
 * injected until all loops fail to decode properly.
 *
 * Options that work with this are (besides -p and setting K):
 *    -w - Set the trellis width.  Default is 0, or 2 ^ (K - 1).
 *    -l - The number of loops.  Default is 100.
 *    -x - Disable the tail.
 *    -b - Do tail biting.
 *    -r - Do recursive.
 *    -m - Set the buffer size to encode.  Defaults to 256 bits (32 bytes).
 *    -u - Do uncertainty.
 *    -er - Set the error rate.  This is float of the probability of an
 *         error per bit.  Like 1e-3 sets a 1 in 1000 chance of an error
 *         per bit (BER).
 * All other options are ignored
 *
 * The output is:
 *
 *   Inj 17000, detected_errs: 16722 (16.72), decode_errs: 31 (0.03), failures: 8 (0.80%)
 *
 * Where:
 *   Inj - the number of errors injected in each loop iteraction.
 *
 *   detected_errs - the total detected errors in all loops followed by
 *      the average per iteractionl
 *
 *   decode_errs - the total actual bits that were wrong after decode in
 *      all loops followed by the average per iteration.
 *
 *   failures - the total number of messages that were incorrect, along
 *      with a percentage of decodes that failed.
 *
 * If you enable uncertainty, it will do a semi-normal distribution of
 * uncertainty, weighted towards 0 for good data and weighted towards
 * 50 for injected errors.  Uncertainty does an amazing job of improving
 * the performance.
 *
 * The -c option enables a way to measure CPU usage, it just runs the
 * error injection with no errors injected and quits.  You can set the
 * number of loops to a large value to measure CPU usage.  It takes
 * the same parameters as -j.
 *
 * If you enable uncertainty, the detected errors is no longer a count
 * of errors, it is instead a measure of average uncertainty per decode.
 */

#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>

static bool ignore_output;

static int
handle_output(struct convcode *ce, void *output_data, unsigned char byte,
	      unsigned int nbits)
{
    unsigned int i;

    if (ignore_output)
	return 0;

    for (i = 0; i < nbits; i++) {
	if (byte & 1)
	    printf("1");
	else
	    printf("0");
	byte >>= 1;
    }
    return 0;
}

static void
do_encode_data(struct convcode *ce, const char *input)
{
    unsigned int i, nbits;
    unsigned char byte = 0;

    for (i = 0, nbits = 0; input[i]; i++) {
	if (input[i] == '1')
	    byte |= 1 << nbits;
	nbits++;
	if (nbits == 8) {
	    convencode_data(ce, &byte, 8);
	    nbits = 0;
	    byte = 0;
	}
    }
    if (nbits > 0)
	convencode_data(ce, &byte, nbits);
}

static void
do_decode_one_data(struct convcode *ce, unsigned char *bytes,
		   unsigned int nbits, uint8_t *uncertainty)
{
    if (uncertainty)
	convdecode_data_u(ce, bytes, nbits, uncertainty);
    else
	convdecode_data(ce, bytes, nbits);
}

static void
do_decode_data(struct convcode *ce, const char *input, uint8_t *uncertainty)
{
    unsigned int i, nbits;
    unsigned char byte = 0;

    for (i = 0, nbits = 0; input[i]; i++) {
	if (input[i] == '1')
	    byte |= 1 << nbits;
	nbits++;
	if (nbits == 8) {
	    do_decode_one_data(ce, &byte, 8, uncertainty);
	    nbits = 0;
	    byte = 0;
	    if (uncertainty)
		uncertainty += 8;
	}
    }
    if (nbits > 0)
	do_decode_one_data(ce, &byte, nbits, uncertainty);
}

#define RAND_TEST_SIZE (256)
#define MAX_TEST_POLYS 7
#define MAX_TAIL (MAX_TEST_POLYS * (CONVCODE_MAX_K - 1))
#define ENCODED_SIZE(size) ((size) * MAX_TEST_POLYS + MAX_TAIL)
#define RAND_TEST_MAX_DECODE_SIZE ENCODED_SIZE(RAND_TEST_SIZE)
struct test_data {
    char output[RAND_TEST_MAX_DECODE_SIZE + 1];
    unsigned char enc_bytes[RAND_TEST_MAX_DECODE_SIZE + 1];
    unsigned char dec_bytes[RAND_TEST_MAX_DECODE_SIZE + 1];
    unsigned int uncertainties[RAND_TEST_MAX_DECODE_SIZE + 1];
    unsigned int outpos;
};

static int
handle_test_output(struct convcode *ce, void *output_data, unsigned char byte,
		   unsigned int nbits)
{
    struct test_data *t = output_data;
    unsigned int i;

    for (i = 0; i < nbits; i++) {
	DEBUG_ASSERT(t->outpos < sizeof(t->output) - 1);
	if (byte & 1)
	    t->output[t->outpos++] = '1';
	else
	    t->output[t->outpos++] = '0';
	byte >>= 1;
    }
    return 0;
}

static unsigned int
run_test(unsigned int k, convcode_state *polys, unsigned int npolys,
	 bool do_tail, convcode_state trellis_width,
	 const char *encoded, const char *decoded,
	 unsigned int expected_errs, uint8_t *uncertainty,
	 unsigned int *out_uncertainties,
	 char *puncture, unsigned int puncture_len)
{
    struct test_data t;
    struct convcode *ce;
    unsigned int i, enc_nbits, dec_nbits, num_errs, rv = 0;
    unsigned int len;

    len = strlen(decoded);
    o->bytes_allocated = 0;
    ce = alloc_convcode(o, k, polys, npolys, len, trellis_width,
			do_tail, false, uncertainty != NULL, NULL, NULL);
    if (puncture)
	convcode_set_puncture(ce, puncture, puncture_len);
    convencode_set_output(ce, handle_test_output, &t);
    convdecode_set_output(ce, handle_test_output, &t);
    printf("Test k=%u %s err=%u polys={ 0%o", k, do_tail ? "tail" : "notail",
	   expected_errs, polys[0]);
    for (i = 1; i < npolys; i++)
	printf(", 0%o", polys[i]);
    printf(" } %u bits %lu bytes alloc\n", len, o->bytes_allocated);
    t.outpos = 0;
    if (expected_errs == 0) {
	do_encode_data(ce, decoded);
	convencode_finish(ce, &enc_nbits);
	t.output[t.outpos] = '\0';
	if (strcmp(encoded, t.output) != 0) {
	    printf("  encode failure, expected\n    %s\n  got\n    %s\n",
		   encoded, t.output);
	    rv = 1;
	    goto out;
	}
	if (enc_nbits != strlen(encoded)) {
	    printf("  encode failure, got %u output bits, expected %u\n",
		   enc_nbits, (unsigned int) strlen(encoded));
	    rv++;
	}
	t.outpos = 0;
    }
    do_decode_data(ce, encoded, uncertainty);
    convdecode_finish(ce, &dec_nbits, &num_errs);
    t.output[t.outpos] = '\0';
    if (strcmp(decoded, t.output) != 0) {
	printf("  decode failure, expected\n    %s\n  got\n    %s\n",
	       decoded, t.output);
	rv++;
    }
    if (num_errs != expected_errs) {
	printf("  decode failure, got %u errors, expected %u\n",
	       num_errs, expected_errs);
	rv++;
    }
    if (dec_nbits != strlen(decoded)) {
	printf("  decode failure, got %u output bits, expected %u\n",
	       dec_nbits, (unsigned int) strlen(decoded));
	rv++;
    }
    if (rv)
	goto out;

    reinit_convcode(ce);
    memset(t.enc_bytes, 0, sizeof(t.enc_bytes));
    if (expected_errs == 0) {
	memset(t.dec_bytes, 0, sizeof(t.dec_bytes));
	for (i = 0, dec_nbits = 0; decoded[i]; i++, dec_nbits++) {
	    unsigned int bit = decoded[i] == '0' ? 0 : 1;
	    t.dec_bytes[i / 8] |= bit << (i % 8);
	}

	convencode_block(ce, t.dec_bytes, dec_nbits, t.enc_bytes, &enc_nbits);
	for (i = 0; i < enc_nbits; i++) {
	    unsigned int bit = encoded[i] == '0' ? 0 : 1;

	    if (((t.enc_bytes[i / 8] >> (i % 8)) & 1) != bit) {
		printf("  block encode failure at bit %u\n", i);
		rv++;
		goto out;
	    }
	}
    } else {
	for (i = 0, enc_nbits = 0; encoded[i]; i++, enc_nbits++) {
	    unsigned int bit = encoded[i] == '0' ? 0 : 1;
	    t.enc_bytes[i / 8] |= bit << (i % 8);
	}
    }

    memset(t.dec_bytes, 0, sizeof(t.dec_bytes));
    if (convdecode_block(ce, t.enc_bytes, enc_nbits, uncertainty,
			 t.dec_bytes, t.uncertainties, &num_errs)) {
	printf("  block decode error return\n");
	rv++;
	goto out;
    }
    if (num_errs != expected_errs) {
	printf("  decode failure, got %u errors, expected %u\n",
	       num_errs, expected_errs);
	rv++;
    }
    for (i = 0; i < dec_nbits; i++) {
	unsigned int bit = decoded[i] == '0' ? 0 : 1;

	if (((t.dec_bytes[i / 8] >> (i % 8)) & 1) != bit) {
	    printf("  block decode failure at bit %u\n", i);
	    rv++;
	    goto out;
	}
	if (out_uncertainties && (t.uncertainties[i] != out_uncertainties[i])) {
	    printf("  block decode invalid uncertainty at bit %u: %u %u\n", i,
		   t.uncertainties[i], out_uncertainties[i]);
	    rv++;
	    //goto out;
	}
    }

 out:
    free_convcode(ce);
    return rv;
}

static unsigned int
rand_block_test(struct convcode *ce,
		const char *encoded, const char *decoded)
{
    struct test_data t;
    unsigned int i, dec_nbits, enc_nbits;
    unsigned int rv = 0;

    reinit_convcode(ce);
    memset(t.enc_bytes, 0, sizeof(t.enc_bytes));
    memset(t.dec_bytes, 0, sizeof(t.dec_bytes));
    for (i = 0, dec_nbits = 0; decoded[i]; i++, dec_nbits++) {
	unsigned int bit = decoded[i] == '0' ? 0 : 1;
	t.dec_bytes[i / 8] |= bit << (i % 8);
    }

    convencode_block(ce, t.dec_bytes, dec_nbits, t.enc_bytes, &enc_nbits);
    for (i = 0; i < enc_nbits; i++) {
	unsigned int bit = encoded[i] == '0' ? 0 : 1;

	if (((t.enc_bytes[i / 8] >> (i % 8)) & 1) != bit) {
	    printf("  block encode failure at bit %u\n", i);
	    rv++;
	    goto out;
	}
    }

    memset(t.dec_bytes, 0, sizeof(t.dec_bytes));
    if (convdecode_block(ce, t.enc_bytes, enc_nbits, NULL,
			 t.dec_bytes, NULL, NULL)) {
	printf("  block decode error return\n");
	rv++;
	goto out;
    }
    for (i = 0; i < dec_nbits; i++) {
	unsigned int bit = decoded[i] == '0' ? 0 : 1;

	if (((t.dec_bytes[i / 8] >> (i % 8)) & 1) != bit) {
	    printf("  block decode failure at bit %u\n", i);
	    rv++;
	    goto out;
	}
    }
 out:
    return rv;
}

static unsigned int
rand_test(unsigned int k, convcode_state *polys, unsigned int npolys,
	  bool do_tail, convcode_state trellis_width, bool recursive,
	  const convcode_symsize * const *convert,
	  const convcode_state * const *next_state,
	  char *puncture, unsigned int puncture_len)
{
    struct test_data t;
    struct convcode *ce;
    unsigned int i, j, bit, total_bits, num_errs, rv = 0;
    char decoded[RAND_TEST_SIZE + 1];
    char encoded[RAND_TEST_MAX_DECODE_SIZE + 1];
    unsigned int len;

    len = RAND_TEST_SIZE;
    o->bytes_allocated = 0;
    ce = alloc_convcode(o, k, polys, npolys, len, trellis_width,
			do_tail, recursive, false, convert, next_state);
    if (puncture)
	convcode_set_puncture(ce, puncture, puncture_len);
    convencode_set_output(ce, handle_test_output, &t);
    convdecode_set_output(ce, handle_test_output, &t);
    if (recursive)
	convencode_set_output_per_symbol(ce, true);

    printf("Random test k=%u %s%s%s polys={ 0%o", k,
	   do_tail ? " tail" : "",
	   recursive ? " recursive" : "",
	   puncture ? " puncture" : "",
	   polys[0]);
    for (i = 1; i < npolys; i++)
	printf(", 0%o", polys[i]);
    printf(" } %u bits %lu bytes alloc\n", len, o->bytes_allocated);

    for (i = 8; i < len; i++) {
	for (j = 0; j < 10; j++) {
	    for (bit = 0; bit < i; bit++)
		decoded[bit] = rand() & 1 ? '1' : '0';
	    decoded[bit] = 0;
	    t.outpos = 0;
	    reinit_convcode(ce);
	    do_encode_data(ce, decoded);
	    convencode_finish(ce, &total_bits);
	    memcpy(encoded, t.output, t.outpos);
	    encoded[t.outpos] = '\0';
	    t.outpos = 0;
	    do_decode_data(ce, encoded, NULL);
	    convdecode_finish(ce, &total_bits, &num_errs);
	    t.output[t.outpos] = '\0';
	    if (strcmp(t.output, decoded) != 0) {
		printf("  decode failure, expected\n    %s\n  got\n    %s\n",
		       decoded, t.output);
		rv++;
	    }
	    rv += rand_block_test(ce, encoded, decoded);
	}
    }
    free_convcode(ce);
    return rv;
}

/*
 * Generated from the -g option of this program with the following
 * command:
 *
 * ./convcode -p 0171 -p 0133 -g 7 >voyager_tab.h
 */
#include "voyager_tab.h"

static int
run_tests(bool do_tail, convcode_state trellis_width)
{
    unsigned int errs = 0;
    srand(time(NULL));

    {
	convcode_state polys[2] = { 5, 7 };
	static unsigned int out_uncertainties[15] = {
	    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1
	};
	if (do_tail) {
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "0011010010011011110100011100110111",
			     "010111001010001", 0, NULL, NULL,
			     NULL, 0);
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "0011010010011011110000011100110111",
			     "010111001010001", 1, NULL, out_uncertainties,
			     NULL, 0);
	} else {
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "001101001001101111010001110011",
			     "010111001010001", 0, NULL, NULL,
			     NULL, 0);
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "001101001001101111000001110011",
			     "010111001010001", 1, NULL, out_uncertainties,
			     NULL, 0);
	}
	errs += rand_test(3, polys, 2, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
    }
    {
	convcode_state polys[2] = { 3, 7 };
	if (do_tail) {
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "0111101000110000", "101100", 0, NULL, NULL,
			     NULL, 0);
	} else {
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "011110100011", "101100", 0, NULL, NULL,
			     NULL, 0);
	}
	errs += rand_test(3, polys, 2, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
    }
    {
	convcode_state polys[2] = { 5, 3 };
	static uint8_t uncertainties[18] = {
	    0, 0, 100, 0, 0, 0, 0, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    0, 0,
	};
	static unsigned int out_uncertainties1[7] = {
	    1, 1, 1, 1, 1, 2, 2
	};
	static unsigned int out_uncertainties2[7] = {
	    0, 100, 100, 100, 100, 100, 100
	};
	if (do_tail) {
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "100111101110010111", "1001101", 0, NULL, NULL,
			     NULL, 0);
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "110111101100010111", "1001101", 2, NULL,
			     out_uncertainties1,
			     NULL, 0);
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "100111101110010111", "1001101",
			     100, uncertainties, out_uncertainties2,
			     NULL, 0);
	} else {
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "10011110111001", "1001101", 0, NULL, NULL,
			     NULL, 0);
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "11011110110001", "1001101", 2, NULL,
			     out_uncertainties1,
			     NULL, 0);
	    errs += run_test(3, polys, 2, do_tail, trellis_width,
			     "10011110111001", "1001101",
			     100, uncertainties, out_uncertainties2,
			     NULL, 0);
	}
	errs += rand_test(3, polys, 2, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
    }
    { /* https://komm.dev/res/convolutional-codes/ */
	convcode_state polys[2] = { 013, 017 };
	errs += rand_test(4, polys, 2, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
    }
    { /* https://komm.dev/res/convolutional-codes/ */
	convcode_state polys[2] = { 027, 031 };
	errs += rand_test(5, polys, 2, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
    }
    { /* https://komm.dev/res/convolutional-codes/ */
	convcode_state polys[2] = { 053, 075 };
	errs += rand_test(6, polys, 2, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
    }
    { /* Voyager */
	convcode_state polys[2] = { 0171, 0133 };
	static uint8_t uncertainties[28] = {
	    0, 0, 0, 0, 100, 0, 0, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0, 0, 0, 0, 0,
	    0, 0, 0, 0
	};
	static unsigned int out_uncertainties[8] = {
	    0, 0, 100, 100, 100, 100, 100, 100
	};
	static unsigned int out_uncertainties_puncture[16] = {
	      0,  50, 150, 200, 200, 250, 250, 300,
	    300, 350, 350, 400, 400, 450, 450, 500
	};
	static char puncture[] = { 1, 1, 0, 1 };
	unsigned int puncture_len = 4;
	if (trellis_width == 0) {
	    /* Output uncertainties only work with full trellis width. */
	    if (do_tail) {
		errs += run_test(7, polys, 2, do_tail, trellis_width,
				 "0011100010011010100111011100", "01011010",
				 100, uncertainties, out_uncertainties,
				 NULL, 0);
		errs += run_test(7, polys, 2, do_tail, trellis_width,
				 "001100101100100011011100101111110",
				 "0101101001011010",
				 4, NULL, NULL,
				 puncture, puncture_len);
		errs += run_test(7, polys, 2, do_tail, trellis_width,
				 "001100101100100011011100101111110",
				 "0101101001011010",
				 650, uncertainties, out_uncertainties_puncture,
				 puncture, puncture_len);
	    } else {
		errs += run_test(7, polys, 2, do_tail, trellis_width,
				 "0011100010011010", "01011010",
				 100, uncertainties, out_uncertainties,
				 NULL, 0);
	    }
	}
	errs += rand_test(7, polys, 2, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
#if 0
	/* This test fails.  There may be issue with puncturing. */
	errs += rand_test(7, polys, 2, do_tail, trellis_width, false,
			  NULL, NULL, puncture, puncture_len);
#endif
    }
    { /* LTE */
	convcode_state polys[3] = { 0117, 0127, 0155 };
	static unsigned int out_uncertainties1[8] = {
	    2, 2, 2, 2, 2, 2, 2, 3
	};
	static unsigned int out_uncertainties2[8] = {
	    2, 2, 2, 3, 3, 4, 4, 4
	};
	if (do_tail) {
	    errs += run_test(7, polys, 3, do_tail, trellis_width,
			     "111001101011100110011101111111100110001111",
			     "10110111", 0, NULL, NULL,
			     NULL, 0);
	    if (trellis_width == 0)
		/* Output uncertainties only work with full trellis width. */
		errs += run_test(7, polys, 3, do_tail, trellis_width,
				 "001001101011100110011100111111100110001011",
				 "10110111", 4, NULL, out_uncertainties1,
				 NULL, 0);
	} else {
	    errs += run_test(7, polys, 3, do_tail, trellis_width,
			     "111001101011100110011101",
			     "10110111", 0, NULL, NULL,
			     NULL, 0);
	    if (trellis_width == 0)
		/* Output uncertainties only work with full trellis width. */
		errs += run_test(7, polys, 3, do_tail, trellis_width,
				 "001001101010100010011101",
				 "10110111", 4, NULL, out_uncertainties2,
				 NULL, 0);
	}
	errs += rand_test(7, polys, 3, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
    }
    { /* https://komm.dev/res/convolutional-codes/ */
	convcode_state polys[2] = { 0247, 0371 };
	errs += rand_test(8, polys, 2, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
    }
#if CONVCODE_MAX_K >= 9
    { /* CDMA 2000 */
	convcode_state polys[4] = { 0671, 0645, 0473, 0537 };
	errs += rand_test(9, polys, 4, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
    }
#endif
#if CONVCODE_MAX_K >= 15
    { /* Cassini / Mars Pathfinder */
	convcode_state polys[7] = { 074000, 046321, 051271, 070535,
	    063667, 073277, 076513 };
	errs += rand_test(15, polys, 7, do_tail, trellis_width, false,
			  NULL, NULL, NULL, 0);
    }
#endif
    /*
     * Recursive tests, taken from:
     * https://en.wikipedia.org/wiki/Convolutional_code#Recursive_and_non-recursive_codes.
     */
    {
	convcode_state polys[2] = { 5, 5 };
	errs += rand_test(3, polys, 2, do_tail, trellis_width, true,
			  NULL, NULL, NULL, 0);
    }
    { /* Constituent code in 3GPP 25.212 Turbo Code */
	convcode_state polys[2] = { 012, 015 };
	errs += rand_test(4, polys, 2, do_tail, trellis_width, true,
			  NULL, NULL, NULL, 0);
    }
    {
	convcode_state polys[2] = { 022, 021 };
	errs += rand_test(5, polys, 2, do_tail, trellis_width, true,
			  NULL, NULL, NULL, 0);
    }

    /* Test supplying our own state tables. */
    {
	convcode_state polys[2] = { 0171, 0133 };
	errs += rand_test(7, polys, 2, true, 0, false,
			  convcode_convert, convcode_next_state, NULL, 0);
    }

    printf("%u errors\n", errs);
    return !!errs;
}

static unsigned int
count_bit_diffs(uint8_t *data1, uint8_t *data2, unsigned int size)
{
    unsigned int i, diffs = 0;

    for (i = 0; i < size; i++)
	diffs += num_bits_set(data1[i] ^ data2[i]);
    return diffs;
}

static unsigned int
calc_normal_dist(uint8_t *data, unsigned int size)
{
    unsigned int i, curr_val = 0, curr_count = size / 17;
    int next_curr_count;

    /* A very crude normal distribution. */
    next_curr_count = curr_count - 2;
    if (next_curr_count <= 0)
	next_curr_count = 1;
    for (i = 0; curr_val <= 50 && i < size; i++) {
	data[i] = curr_val;
	curr_count--;
	if (curr_count == 0) {
	    curr_val++;
	    curr_count = next_curr_count;
	    next_curr_count -= 2;
	    if (next_curr_count <= 0)
		next_curr_count = 1;
	}
    }
#if 0
    printf("Normal distribution(%u):", i);
    for (i = 0; i < size; i++) {
	if (i % 8 == 0)
	    printf("\n%4u:", i);
	printf(" %2u", data[i]);
    }
    printf("\n");
#endif
    return i;
}

#define NORMAL_DIST_ARRAY_SIZE 1024
static uint8_t normal_dist[NORMAL_DIST_ARRAY_SIZE];
static unsigned int normal_dist_size;

static void
setup_uncertainty(uint8_t *uncertainty, unsigned int size)
{
    unsigned int i;

    for (i = 0; i < size; i++)
	uncertainty[i] = normal_dist[rand() % normal_dist_size];
}

static unsigned int
insert_random_errors(uint8_t *data, unsigned int size, unsigned int count,
		     double error_rate, uint8_t *uncertainty)
{
    unsigned int i, pos;

    if (error_rate > 0) {
	unsigned int error_rate_inv = 1 / error_rate;

	count = 0;
	for (i = 0; i < size; i++) {
	    if (rand() % error_rate_inv != 1)
		continue;
	    data[i / 8] ^= 1 << (i % 8);
	    if (uncertainty) {
		uncertainty[i] = 50 - normal_dist[rand() % normal_dist_size];
	    }
	    count++;
	}
    } else {
	bool *err_pos = calloc(size, 1);

	for (i = 0; i < count; i++) {
	    pos = rand() % size;
	    if (err_pos[pos]) /* Already put an error here. */
		continue;
	    data[pos / 8] ^= 1 << (pos % 8);
	    if (uncertainty) {
		uncertainty[pos] = 50 - normal_dist[rand() % normal_dist_size];
	    }
	    err_pos[pos] = true;
	}
	free(err_pos);
    }

    return count;
}

static int
dummy_convcode_output(struct convcode *ce, void *user_data,
		      unsigned char byte, unsigned int nbits)
{
    return 0;
}

static int
err_inj_test(unsigned int k, convcode_state *polys, unsigned int num_polys,
	     unsigned int trellis_width, bool do_tail, bool recursive,
	     bool do_uncertainty, bool do_tail_biting, bool one_loop,
	     unsigned int num_loops, unsigned int size, double error_rate,
	     char *puncture, unsigned int puncture_len)
{
    /* NOTE: size is in bits. */
    struct convcode *ce;
    uint8_t *data, *decoded, *encoded, *uncertainty = NULL;
    unsigned int i, j;
    unsigned int encoded_size, detected_errors, decode_errors, inserted_errors;
    unsigned int tmp, decode_failures;
    unsigned int byte_size; /* Byte count for data to be encoded. */
    unsigned int enc_size; /* Bits require for the encoded data. */
    unsigned int byte_enc_size; /* Byte count for encoded data. */
    unsigned int tot_inj_errs = 0;

    if (do_tail_biting)
	do_tail = false;

    if (error_rate > 0.0)
	one_loop = true;

    enc_size = convcode_encoded_size(size, num_polys, k, do_tail,
				     puncture, puncture_len);
    byte_size = CONVCODE_ROUND_UP_BYTE(size);
    byte_enc_size = CONVCODE_ROUND_UP_BYTE(enc_size);

    data = malloc(byte_size);
    decoded = malloc(byte_size);
    encoded = malloc(byte_enc_size);
    if (do_uncertainty)
	uncertainty = malloc(enc_size);

    srand(time(NULL));
    normal_dist_size = calc_normal_dist(normal_dist, NORMAL_DIST_ARRAY_SIZE);

    o->bytes_allocated = 0;
    /*
     * Set dummy_convcode_output for tail biting, so the first output
     * bits are ignored.
     */
    ce = alloc_convcode(o, k, polys, num_polys, size, trellis_width,
			do_tail, recursive, do_uncertainty, NULL, NULL);
    if (puncture)
	convcode_set_puncture(ce, puncture, puncture_len);
    convencode_set_output(ce, dummy_convcode_output, NULL);

    printf("Running injection test on %u bits (%u enc) with %u loops:%s%s%s\n",
	   size, enc_size, num_loops,
	   recursive ? " recursive" : "",
	   do_tail_biting ? " tail-biting" : do_tail ? " tail" : "",
	   do_uncertainty ? " uncertainty" : "");
    printf("  Used %lu bytes\n", o->bytes_allocated);
    for (inserted_errors = 0; ; inserted_errors++) {
	decode_errors = 0;
	detected_errors = 0;
	decode_failures = 0;
	for (i = 0; i < num_loops; i++) {
	    for (j = 0; j < byte_size; j++)
		data[j] = rand();
	    /* Make the last bits zero if size is not a multiple of 8. */
	    if (size % 8)
		data[j - 1] >>= 8 - size % 8;

	    reinit_convcode(ce);
	    memset(encoded, 0, byte_enc_size);
	    memset(decoded, 0, byte_size);
	    if (do_tail_biting) {
		/* Shove in the last k - 1 bits) */
		unsigned int opos = size - (k - 1);

		for (j = 0; j < k - 1; j++) {
		    unsigned int bit = extract_bits(data, opos, 1);

		    opos++;
		    /* Output data will be discarded. */
		    convencode_bit(ce, bit);
		}
	    }
	    convencode_block(ce, data, size, encoded, &encoded_size);
	    assert(encoded_size == enc_size);
	    if (size % 8 == 0) {
		unsigned int encoded_size2;

		/*
		 * Make sure convcode_encoded_bits_from_encoded_bytes()
		 * gets the right value.
		 */
		assert(convcode_encoded_bits_from_encoded_bytes
		       (byte_enc_size, num_polys, k,
			do_tail, &encoded_size2,
			puncture, puncture_len) == 0);
		//printf("A: %d %d\n", encoded_size, encoded_size2);
		assert(encoded_size == encoded_size2);
	    }
	    if (uncertainty)
		setup_uncertainty(uncertainty, encoded_size);
	    tot_inj_errs += insert_random_errors(encoded, encoded_size,
						 inserted_errors,
						 error_rate, uncertainty);
	    if (do_tail_biting) {
		/* Shove in the first run of the data. */
		if (uncertainty)
		    convdecode_data_u(ce, encoded, encoded_size, uncertainty);
		else
		    convdecode_data(ce, encoded, encoded_size);
		reinit_convdecode_tail_bite(ce);
	    }
	    convdecode_block(ce, encoded, encoded_size, uncertainty,
			     decoded, NULL, &tmp);
	    detected_errors += tmp;

	    tmp = count_bit_diffs(data, decoded, byte_size);
	    decode_errors += tmp;
	    if (tmp > 0)
		decode_failures++;
	}
	if (do_uncertainty) {
	    printf("Inj %u, uncertainty: %.2f, decode_errs: %u (%.2f), failures: %u (%.2f%%)\n",
		   tot_inj_errs,
		   ((float) detected_errors / (num_loops * RAND_TEST_SIZE)),
		   decode_errors,
		   ((float) decode_errors / num_loops),
		   decode_failures,
		   ((float) decode_failures * 100 / num_loops));
	} else {
	    printf("Inj %u, detected_errs: %u (%.2f), decode_errs: %u (%.2f), failures: %u (%.2f%%)\n",
		   tot_inj_errs,
		   detected_errors,
		   ((float) detected_errors / num_loops),
		   decode_errors,
		   ((float) decode_errors / num_loops),
		   decode_failures,
		   ((float) decode_failures * 100 / num_loops));
	}
	if (decode_failures >= num_loops || one_loop)
	    break;
    }

    free_convcode(ce);
    free(data);
    free(decoded);
    free(encoded);
    free(uncertainty);

    return 0;
}


static void
output_tables(struct convcode *ce)
{
    unsigned int i;

    printf("const convcode_symsize convcode_convert0[] = {");
    for (i = 0; i < ce->num_states; i++) {
	if (i % 8 == 0)
	    printf("\n   ");
	printf(" 0x%4.4x,", ce->convert[0][i]);
    }
    printf("\n};\n");
    printf("const convcode_symsize convcode_convert1[] = {");
    for (i = 0; i < ce->num_states; i++) {
	if (i % 8 == 0)
	    printf("\n   ");
	printf(" 0x%4.4x,", ce->convert[1][i]);
    }
    printf("\n};\n");
    printf("const convcode_symsize * const convcode_convert[2] = {\n");
    printf("    convcode_convert0, convcode_convert1\n");
    printf("};\n\n");

    printf("const convcode_state convcode_next_state0[] = {");
    for (i = 0; i < ce->num_states; i++) {
	if (i % 8 == 0)
	    printf("\n   ");
	printf(" 0x%4.4x,", ce->next_state[0][i]);
    }
    printf("\n};\n");
    printf("const convcode_state convcode_next_state1[] = {");
    for (i = 0; i < ce->num_states; i++) {
	if (i % 8 == 0)
	    printf("\n   ");
	printf(" 0x%4.4x,", ce->next_state[1][i]);
    }
    printf("\n};\n");
    printf("const convcode_state * const convcode_next_state[2] = {\n");
    printf("    convcode_next_state0, convcode_next_state1\n");
    printf("};\n");
}

static char puncture_code_12[] = { 1, 1 };
static char puncture_code_23[] = { 1, 1, 0, 1 };
static char puncture_code_34[] = { 1, 1, 0, 1, 1, 0 };
static char puncture_code_56[] = { 1, 1, 0, 1, 1, 0, 0, 1, 1, 0 };
static char puncture_code_78[] = { 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0 };

static struct {
    char *name;
    char *code;
    unsigned int len;
} puncture_codes[] = {
    { "1/2", puncture_code_12, 2 },
    { "2/3", puncture_code_23, 4 },
    { "3/4", puncture_code_34, 6 },
    { "5/6", puncture_code_56, 10 },
    { "7/8", puncture_code_78, 14 },
    { NULL }
};

int
main(int argc, char *argv[])
{
    convcode_state polys[CONVCODE_MAX_POLYNOMIALS];
    unsigned int i;
    unsigned int num_polys = 0;
    unsigned int k;
    unsigned int len;
    struct convcode *ce;
    unsigned int arg, total_bits, num_errs = 0;
    bool decode = false, test = false, do_tail = true, recursive = false;
    bool gen_tables = false, do_err_inj_test = false, do_uncertainty = false;
    bool do_tail_biting = false, do_cpu_usage = false;
    unsigned int err_inj_loops = 100, err_inj_size = RAND_TEST_SIZE;
    convcode_state trellis_width = 0;
    char *puncture_code = NULL;
    unsigned int puncture_code_len = 0;
    double error_rate = -1.0;

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != '-')
	    break;
	if (strcmp(argv[arg], "-d") == 0) {
	    decode = true;
	} else if (strcmp(argv[arg], "-e") == 0) {
	    decode = false;
	} else if (strcmp(argv[arg], "-t") == 0) {
	    test = true;
	} else if (strcmp(argv[arg], "-x") == 0) {
	    do_tail = false;
	} else if (strcmp(argv[arg], "-b") == 0) {
	    do_tail_biting = true;
	} else if (strcmp(argv[arg], "-r") == 0) {
	    recursive = true;
	} else if (strcmp(argv[arg], "-g") == 0) {
	    gen_tables = true;
	} else if (strcmp(argv[arg], "-j") == 0) {
	    do_err_inj_test = true;
	} else if (strcmp(argv[arg], "-u") == 0) {
	    do_uncertainty = true;
	} else if (strcmp(argv[arg], "-c") == 0) {
	    do_cpu_usage = true;
	} else if (strcmp(argv[arg], "-w") == 0) {
	    arg++;
	    if (arg >= argc) {
		fprintf(stderr, "No data supplied for -w\n");
		return 1;
	    }
	    trellis_width = strtoul(argv[arg], NULL, 0);
	} else if (strcmp(argv[arg], "-p") == 0) {
	    if (num_polys == CONVCODE_MAX_POLYNOMIALS) {
		fprintf(stderr, "Too many polynomials\n");
		return 1;
	    }
	    arg++;
	    if (arg >= argc) {
		fprintf(stderr, "No data supplied for -p\n");
		return 1;
	    }
	    polys[num_polys++] = strtoul(argv[arg], NULL, 0);
	} else if (strcmp(argv[arg], "-er") == 0) {
	    arg++;
	    if (arg >= argc) {
		fprintf(stderr, "No data supplied for -er\n");
		return 1;
	    }
	    error_rate = strtod(argv[arg], NULL);
	} else if (strcmp(argv[arg], "-l") == 0) {
	    arg++;
	    if (arg >= argc) {
		fprintf(stderr, "No data supplied for -l\n");
		return 1;
	    }
	    err_inj_loops = strtoul(argv[arg], NULL, 0);
	} else if (strcmp(argv[arg], "-m") == 0) {
	    arg++;
	    if (arg >= argc) {
		fprintf(stderr, "No data supplied for -m\n");
		return 1;
	    }
	    err_inj_size = strtoul(argv[arg], NULL, 0);
	} else if (strcmp(argv[arg], "-pc") == 0) {
	    arg++;
	    if (arg >= argc) {
		fprintf(stderr, "No data supplied for -pc\n");
		return 1;
	    }
	    for (i = 0; puncture_codes[i].name; i++) {
		if (strcmp(puncture_codes[i].name, argv[arg]) == 0)
		    break;
	    }
	    if (!puncture_codes[i].name) {
		fprintf(stderr, "Invalid puncture code name for -pc\n");
		return 1;
	    }
	    puncture_code = puncture_codes[i].code;
	    puncture_code_len = puncture_codes[i].len;
	} else {
	    fprintf(stderr, "unknown option: %s\n", argv[arg]);
	    return 1;
	}
    }

    if (test)
	return run_tests(do_tail, trellis_width);

    if (num_polys == 0) {
	fprintf(stderr, "No polynomials (-p) given\n");
	return 1;
    }

    if (arg >= argc) {
	fprintf(stderr, "No constraint (k) given\n");
	return 1;
    }

    k = strtoul(argv[arg++], NULL, 0);
    if (k < CONVCODE_MIN_K || k > CONVCODE_MAX_K) {
	fprintf(stderr, "Constraint (k) must be from %u to %u\n",
		CONVCODE_MIN_K, CONVCODE_MAX_K);
	return 1;
    }

    if (do_err_inj_test || do_cpu_usage)
	return err_inj_test(k, polys, num_polys, trellis_width,
			    do_tail, recursive, do_uncertainty, do_tail_biting,
			    do_cpu_usage,
			    err_inj_loops, err_inj_size, error_rate,
			    puncture_code, puncture_code_len);

    if (decode && arg < argc) {
	int rv;
	rv = convcode_decoded_size(strlen(argv[arg]), num_polys, k, do_tail,
				   puncture_code, puncture_code_len, &len);
	if (rv) {
	    printf("Encoded data size does not match the number of polynomials\n");
	    return 1;
	}
    } else {
	len = 0;
    }
    o->bytes_allocated = 0;
    ce = alloc_convcode(o, k, polys, num_polys, len, trellis_width,
			do_tail, recursive, false, NULL, NULL);
    if (puncture_code)
	convcode_set_puncture(ce, puncture_code, puncture_code_len);
    convencode_set_output(ce, handle_output, NULL);
    convdecode_set_output(ce, handle_output, NULL);

    if (gen_tables) {
	output_tables(ce);
	goto do_free;
    }

    if (arg >= argc) {
	fprintf(stderr, "No data given\n");
	return 1;
    }

    printf("  ");
    if (do_tail_biting) {
	if (decode) {
	    ignore_output = true;
	    do_decode_data(ce, argv[arg], NULL);
	    ignore_output = false;
	    reinit_convdecode_tail_bite(ce);
	    do_decode_data(ce, argv[arg], NULL);
	    convdecode_finish(ce, &total_bits, &num_errs);
	    printf("\n  errors = %u", num_errs);
	} else {
	    /*
	     * Feed the last k-1 bits into the encoder, but ignore the
	     * output.
	     */
	    ignore_output = true;
	    do_encode_data(ce, argv[arg] + (strlen(argv[arg]) - (k - 1)));
	    ignore_output = false;
	    do_encode_data(ce, argv[arg]);
	    convencode_finish(ce, &total_bits);
	}
    } else {
	if (decode) {
	    do_decode_data(ce, argv[arg], NULL);
	    convdecode_finish(ce, &total_bits, &num_errs);
	    printf("\n  errors = %u", num_errs);
	} else {
	    do_encode_data(ce, argv[arg]);
	    convencode_finish(ce, &total_bits);
	}
    }

    printf("\n  bits = %u\n", total_bits);
    printf("  allocated %lu bytes\n", o->bytes_allocated);

 do_free:
    free_convcode(ce);

    return 0;
}
#endif
