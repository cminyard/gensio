/*
 * Copyright 2023-2026 Corey Minyard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This is an implementation of a convolutional coder and a viterbi
 * decoder
 */

#ifndef CONVCODE_H
#define CONVCODE_H

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

#include <gensio/gensio_os_funcs.h>
#define convcode_os_funcs struct gensio_os_funcs

/*
 * Maximum number of polynomials. I've never seen one with more than
 * 8.  If larger is required, it doesn't take a lot of space to add a
 * few more.
 */
typedef uint8_t convcode_symsize;
#define CONVCODE_MAX_POLYNOMIALS 8

struct convcode;

/*
 * This is the size of the polynomials and thus the maximum state
 * machine size, and the value to hold the state.  Keep it as small as
 * possible to reduce the trellis size.  Size of K is limited by this
 * value.  We use the top bit of this to store the bit value.
 *
 * The state machine size is 2 ^ (K - 1), so a K of 8 will mean 7 bits
 * is required for the state machine.  This means you can have an
 * 7-bit state value and store the bit value in the top bit.  Or you
 * can have a max K of 16 and a 15-bit state value.  Those are the
 * most sensible values.
 *
 * As well, K must be a minimum of 3.  Less than this doesn't make
 * much sense, and it lets us loop unroll a bit for optimization.
 */
#define CONVCODE_MIN_K 3
#define CONVCODE_MAX_K 16
#if (CONVCODE_MAX_K <= 8)
typedef uint8_t convcode_state;
#elif (CONVCODE_MAX_K <= 16)
typedef uint16_t convcode_state;
#elif (CONVCODE_MAX_K <= 32)
typedef uint32_t convcode_state;
#else
#error CONVCODE_MAX_K must be <= 32.
#endif
#define CONVCODE_PSTATE_VAL(v) ((v) & ~(1 << (CONVCODE_MAX_K - 1)))
#define CONVCODE_PSTATE_BIT(v) ((v) >> (CONVCODE_MAX_K - 1))
#define CONVCODE_PSTATE_SET_BIT(v, b) ((v) | ((b) << (CONVCODE_MAX_K - 1)))

/*
 * Take the number of bits and return the number of bytes required to
 * hold it.
 */
#define CONVCODE_ROUND_UP_BYTE(size) (((size) + 7) / 8)

/*
 * Take the given parameters and the number of bits to encode and
 * compute the number of bits required to hold the given encoded
 * data.
 */
unsigned int convcode_encoded_size(unsigned int size, unsigned int num_polys,
				   unsigned int k, bool do_tail,
				   char *puncture, unsigned int puncture_len);

/*
 * Given a set of parameters and an encoded size, calculate what the
 * decoded size is.  Returns 1 (an error) if the size doesn't line up
 * with the number of polynomials.  Returns 0 otherwise.
 *
 * dsize is the number of bits that will be in the decoded output.
 */
int convcode_decoded_size(unsigned int size, unsigned int num_polys,
			  unsigned int k, bool do_tail, char *puncture,
			  unsigned int puncture_len, unsigned int *dsize);

/*
 * Helper function for handling byte-aligned messages.
 *
 * Take the a number of encoded bytes, assuming the original data was
 * byte-aligned, and calculate the actual number of encoded bits that
 * are in the message.  The encoded output may not have been a
 * multiple of 8 bits, so the end of the last byte can be partially
 * filled.
 *
 * Returns the actual encoded bit length nbits.  Return 0 on success,
 * non-zero on error.
 */
int convcode_encoded_bits_from_encoded_bytes
(unsigned int nbytes, unsigned int num_polys,
 unsigned int k, bool do_tail, unsigned int *nbits,
 char *puncture, unsigned int puncture_len);

/*
 * Allocate a convolutional coder for coding or decoding.
 *
 * k is the constraint (the size of the polynomials in bits).  The
 * maximum value is CONVCODE_MAX_K,the minimum value is CONCODE_MIN_K.
 *
 * The polynomials are given in the array.  They are coded where the
 * high bit handles the first bit fed into the state machine.  This
 * seems to be the standard used, but may be backwards from what you
 * expect.  There may be up to CONVCODE_MAX_POLYNOMIALS polynomials.
 *
 * max_decode_len_bits is the maximum number of bits that can be
 * decoded.  You can get a pretty big matrix from this.  If you say 0
 * here you can only use the coder for encoding.
 *
 * trellis_width sets the size of the trellis.  If this is zero, then
 * the width will be set to the number of states (1 << (k - 1)) and
 * all trellis paths will be kept.  If this is set to less than the
 * number of states, then the "trellis_width" most likely paths will
 * be kept and the rest of the paths discarded.  This can result in
 * poor performance, but can save a lot of data.
 *
 * If you are doing uncertainty, you must pass in true to the
 * do_uncertainty parameter, and you must use the uncertainty
 * functions and pass in the value.  Otherwise don't use uncertainty
 * functions and use NULL uncertainty to any function that takes it.
 *
 * See the discussion below on tails for what do_tail does.
 *
 * The recursive setting enables a recursive decoder.  The first
 * polynomial is the recursive one, the rest are the output
 * polynomials.  The first bit output for each symbol will be the
 * input bit, per standard recursive convolutional encoding.
 *
 * It is possible to pre-create your own convert and next_state tables
 * and pass them in to here.  This is useful for constrained
 * environments where the tables could be stored in ROM/FLASH.  They
 * must, of course, match the rest of the data.  You can use the -g
 * option of convcode command.  Otherwise pass in NULL for convert and
 * next_state.
 *
 * If outputting to functions (not doing block operations) you must
 * set the output functions using the functions described after this
 * one.
 *
 * Return NULL on an error.
 */
struct convcode *alloc_convcode(convcode_os_funcs *o,
				unsigned int k, convcode_state *polynomials,
				unsigned int num_polynomials,
				unsigned int max_decode_len_bits,
				unsigned int trellis_width,
				bool do_tail, bool recursive,
				bool do_uncertainty,
				const convcode_symsize * const *convert,
				const convcode_state * const *next_state);


/*
 * Free an allocated coder.
 */
void free_convcode(struct convcode *ce);

/*
 * Set or change the encode and decoder output functions.
 *
 * Data is normally generated to the output functions a byte at a
 * time.  You will generally get full bytes (nbits = 8) for all the
 * data except the last one, which may be smaller than 8.  Data is
 * encoded low bit first.
 *
 * If output function returns an error, the operation is stopped and
 * the error will be returned from the function that was called to
 * cause the output.
 */
typedef int (*convcode_output)(struct convcode *ce, void *user_data,
			       unsigned char byte, unsigned int nbits);

void convencode_set_output(struct convcode *ce,
			   convcode_output enc_output,
			   void *enc_out_user_data);
void convdecode_set_output(struct convcode *ce,
			   convcode_output dec_output,
			   void *dec_out_user_data);

/*
 * If set to false (the default) the output for encoding goes to the
 * output function in bytes except for possibly the last output.  If
 * set to true, the output will come out in a symbol, or
 * num_polynomial, number of bits each time, and there will not be a
 * chunk at the end that is smaller.  This is useful if you want to
 * split up the individual output streams from each polynomial, like
 * you would for a recursive decoder for turbo coding.
 */
void convencode_set_output_per_symbol(struct convcode *ce, bool val);

/*
 * Set a puncturing array to puncture on encoding and to inject zeros
 * when decoding.
 *
 * The array is an array of chars that are used as bools.  The coding
 * process goes through them one at a time when inputting or
 * outputting bits.  If a bool is set, the bit is output or input.  If
 * a bool is not set, it is dropped on output and on input a 0 bit is
 * injected.
 *
 * For instance. if the array is { 1, 1, 1, 0 } then the output will
 * drop every 4th bit.  When inputting, three bits are pulled from the
 * input and then a zero is injected then three more bits are pulled,
 * etc.
 *
 * The array can be arbitrarily long to accomplish whatever puncturing
 * you would like.
 *
 * Note that puncture arrays do not work on encoding if you set
 * output-per-symbol.  You will get whole symbols still and you will
 * have to do the puncture yourself.  They also do not work if you
 * feed the data in per symbol with convdecode_symbol().
 *
 * Note: Puncturing may have issues, it may be a bug that I'm seeing
 * in the tests, but it may be just that puncturing doesn't always
 * work well.
 */
void convcode_set_puncture(struct convcode *ce, const char *puncture_array,
			   unsigned int puncture_array_len);

/*
 * Convolutional tail
 *
 * Normally you have a "tail" of the convolutional code, where you
 * feed k - 1 zeros to clear out the state and get the end state and
 * initial state the same.  That's normally what you want, so this
 * code does that for you if you set do_tail to true.  It does output
 * an extra (num_polys * (k - 1)) bits that you must transfer to the
 * other end.  You can disable the tail, but it reduces the
 * performance of the code.
 *
 * However, there is something called "tail biting".  You initialize
 * the state with the last k - 1 bits of the data.  That way, when the
 * state machine finishes, it will be in the same state as the
 * beginning, and though it doesn't perform quite as well as a tail,
 * it's a lot better than no tail.  It requires more work on the
 * receive side.
 *
 * You have the problem on the decode side of knowing what state to
 * start at.  You solve that by running the data through the decode
 * state machine starting at zero.  The beginning bits will probably
 * be wrong, but by the end it will be aligned and in the right state
 * Then you can re-run the algorithm with the state set properly from
 * the first run of data.  I'm not 100% sure how reliable that is, but
 * it seems to work pretty well.
 *
 * If doing tail biting, set do_tail to false when you allocate the
 * coder.  Grab the last k - 1 bits of the data and put them into the
 * encoder, but throw away the output bits from this.  Then encode
 * normally.
 *
 * On the decode side, get the whole packet then feed it through once.
 * This should put the decoder into the same state the encoder was at
 * when it started transmitting data.  Do not do something that will
 * finish the decode operation, like convdecode_block() will.  Then
 * call reinit_convdecode_tail_bite(), which will re-initialize the
 * decoder but leave the states.  Then feed the entire packet through
 * to get the actual data output.  You need to finish the decode
 * operation this time.  You can feed only the end of the data through
 * on the first iteration, but that doesn't work as reliably.
 */

/*
 * Soft Decoding
 *
 * Soft decoding takes into account how certain (or, in this case,
 * uncertain) a particular bit is to be correct.  For instance, when
 * doing phase decoding, if you are right on phase, then you would be
 * 0% uncertain that the value was incorrect.  If it was half-way
 * between two expected phase values, you would be 50% uncertain the
 * value was correct.  It's easier to work with uncertainty than
 * certainty, even if the English is awkward.
 *
 * These uncertainty values by default are given in a range from 0 to
 * 100 but you would never use a value more than 50.  If you were more
 * than 50% uncertain, you would have chosen the other value, of
 * course.  You can change the max value with a function described below.
 *
 * When using soft decoding, them meaning of num_errs from
 * convdecode_finish() changes.  It is no longer a count of errors, it
 * is instead a rating of uncertainty.  You would normally divide this
 * by the number of bits to get a meaningful uncertainty number for
 * the data.
 *
 * See convdecode_block() for a way to get the full set of
 * uncertainties for each output bit, for a BCJR type algorithm.
 */

/*
 * Re-initialization handling.  Note that encoding and decoding may be
 * done simultaneously with the same structure.
 */

/*
 * Reinit the encoder.  If you want to use the encoder again
 * after and encode operation, you must reinitialize it.
 */
void reinit_convencode(struct convcode *ce);

/*
 * Re-init the decoder.  If you want to use the decoder again
 * after and decode operation, you must reinitialize it.
 *
 * Returns non-zero on error
 */
int reinit_convdecode(struct convcode *ce);

/* Like the above, but get ready for a tail bite second run. */
int reinit_convdecode_tail_bite(struct convcode *ce);

/*
 * Call both of the the above functions.
 */
void reinit_convcode(struct convcode *ce);

/*
 * By default the uncertainty ranges from 0 to 100, where 0 is 100%
 * uncertain and 100 is 0% certain.  This function allows you to set a
 * different max value to range from.  For instance, if you set it to
 * 10 then the values would range from 0 to 10.
 */
void convdecode_set_max_uncertainty(struct convcode *ce,
				    uint8_t max_uncertainty);

/*
 * Feed some data into encoder.  The size is given in bits, the data
 * goes in low bit first.  The last byte does not have to be completely
 * full, and that's fine, it will only use the low nbits % 8.
 *
 * You can feed data in with multiple calls.
 *
 * Returns nonzero on an error.
 */
int convencode_data(struct convcode *ce,
		    const unsigned char *bytes, unsigned int nbits);

/*
 * Feed a single bit into encoder.  bit must be 1 or 0.
 *
 * You can feed data in with multiple calls.
 *
 * Returns nonzero on an error.
 */
int convencode_bit(struct convcode *ce, unsigned int bit);

/*
 * Once all the data has been fed for encoding, you must call this to
 * finish the operation.  The last output will be done from here.  The
 * total number of bits generated is returned in total_out_bits;
 *
 * If the output function (see above) returns an error, that error will be
 * returned here.
 *
 * Returns nonzero on an error.
 */
int convencode_finish(struct convcode *ce, unsigned int *total_out_bits);

/*
 * If the number of polynomials is 2, 4, or 8, symbols are that size
 * and the coder will automatically set bit spanning off.  Normally
 * this is what you want; it's more efficient to put the encoded bits
 * in this way, as they will never span a byte and you can just stuff
 * them in.
 *
 * However, if the output bits are not aligned with a byte for some
 * reason, this means you must span bytes and more complicated code
 * must run to break the symbols apart and then stuff them into
 * multiple bytes.  This is here for that special case.
 *
 * Don't set this just arbitrarily, you should almost never have to
 * set this to true.  Setting it to false is safe, but it will be less
 * efficient if you don't have to span bytes.
 */
void convencode_set_byte_span(struct convcode *ce, bool do_span);

/*
 * Encode a block of data bits.  The output bits are stored in
 * outbytes, which must be large enough to hold the full encoded
 * output.  If tail is set, then this will be ((nbits + k - 1) *
 * num_polynomials).  If tail is not set, this will be (nbits *
 * num_polynomials).  The output function is not used in this case.
 *
 * This will automatically do the span optimization if it can,
 * see the comment on convencode_set_byte_span() for details.
 *
 * If total_out_bits is not NULL, the total number of bits generated
 * into outbytes will be returned there.
 *
 * Note that the outbytes buffer must be zero-ed before you call this.
 */
void convencode_block(struct convcode *ce,
		      const unsigned char *bytes, unsigned int nbits,
		      unsigned char *outbytes, unsigned int *total_out_bits);

/*
 * For multi-part block operations, you can call convencode_block
 * partial() for all blocks, and call convencode_block_final() at the
 * end to handle the tail bits (if you have that set).
 *
 * This will automatically do the span optimization if it can,
 * see the comment on convencode_set_byte_span() for details.
 *
 * Note that the outbytes buffer must be zero-ed before you call this.
 */
void convencode_block_partial(struct convcode *ce,
			      const unsigned char *bytes, unsigned int nbits,
			      unsigned char **outbytes,
			      unsigned int *outbitpos);
void convencode_block_final(struct convcode *ce,
			    unsigned char *outbytes, unsigned int outbitpos);

/*
 * Feed some data into decoder.  The size is given in bits, the data
 * goes in low bit first.  The last byte may not be completely full,
 * and that's fine, it will only use the low nbits % 8.
 *
 * If the uncertainty version is used (ending in _u), this will do
 * soft decoding.  Each uncertainty array entry will correspond to the
 * uncertainty of the given bit number, low bit first.  See the
 * discussion on soft decoding above the set_decode_max_uncertainty
 * function.
 *
 * The version without uncertainty will do hard decoding.
 *
 * The uncertainty version is separated out to avoid having to have a
 * check for a NULL uncertainty in the function, since this function
 * can be called a lot.
 *
 * You can feed data in with multiple calls.
 *
 * Returns nonzero on an error.
 */
int convdecode_data(struct convcode *ce,
		    const unsigned char *bytes, unsigned int nbits);
int convdecode_data_u(struct convcode *ce,
		      const unsigned char *bytes, unsigned int nbits,
		      const uint8_t *uncertainty);

/*
 * Push a single symbol into the decoder.  The symbol should have k
 * bits (the polynomial size) starting at bit zero.  Use the _u
 * version for uncertainty, it should be an array of k uncertainty
 * values.
 *
 * The uncertainty version is separated out to avoid having to have a
 * check for a NULL uncertainty in the function, since this function
 * can be called a lot.
 *
 * Returns nonzero on an error.
 */
#define convdecode_symbol(ce, symbol) \
    ce->decode_symbol(ce, symbol, NULL)
#define convdecode_symbol_u(ce, symbol, uncertainty) \
    ce->decode_symbol(ce, symbol, uncertainty)

/*
 * Once all the data has been fed for decoding, you must call this to
 * finish the operation.  Output will be done from here.  The total
 * number of bits generated is returned in total_out_bits;  The total
 * number of errors (or total uncertainty when doing soft decoding)
 * encountered is returned in num_errs.
 *
 * If the output function (see above) returns an error, that error
 * will be returned here.  This will also return 1 if the data exceeds
 * the available size given in max_decode_len_bits above.
 *
 * You cannot use this to get output uncertainties.  Use the
 * convdecode_block() function below for that.
 *
 * Returns nonzero on an error.
 */
int convdecode_finish(struct convcode *ce, unsigned int *total_out_bits,
		      unsigned int *num_errs);

/*
 * Much like convdecode_data() and convdecode_finish(), but does a
 * full block all at once and does not use the output function.  See
 * convdecode_data for an explaination of the first four parameters.
 *
 * Note that you can feed data into the decoder using
 * convdecode_symbol() and/or convdecode_data() before calling this
 * function.  You can also use this instead of convdecode_final() to
 * get the output in a block and get output uncertainties.
 *
 * The output data is stored in outbits, in the normal bit format
 * everything else uses.  With a tail, the output array must be at
 * least (nbits / num_polynomials - k - 1) *bits* long.  If tail is
 * off, it must be (nbits / num_polynomials) long.
 *
 * If output_uncertainty is not NULL, the uncertainty of each output
 * bit is stored in this array.  It must be the same length as the
 * number of bits in outbytes.  This is basically a full BCJR
 * algorithm; the output uncertainty can be used to compute the
 * probabilities of each output bit.  (Output uncertainties are not
 * provided in the standard output routine because that would require
 * keeping a lot of extra data in the convcode structure.  You would
 * only really use this if you were using blocks, anyway, so there's
 * no value in having it in the output routine.)
 *
 * The output uncertainty for each bit is the total uncertainty value
 * for all bits up to that point.  To convert that to an uncertainty
 * value for just that bit, you would use:
 *
 *   bit_uncertainty = ((uncertainty * num_polynomials) / bit_position)
 *
 * which should give you a value from 0 - 100.  You can, of course,
 * take that and do (100 - bit_uncertainty) to get the certainty, or
 * probability.  This is assuming the max_uncertainty is 100, of
 * course, you would need to adjust if you changed that.
 *
 * NOTE: If you have trellis_width set to < num_states, then
 * output_uncertainty will not be correct.  The previous state data is
 * lost because paths are discarding, and keeping that data around
 * would use a lot of memory.
 *
 * Note that the outbytes buffer must be zero-ed before you call this.
 *
 * Returns nonzero on an error.
 */
int convdecode_block(struct convcode *ce, const unsigned char *bytes,
		     unsigned int nbits, const uint8_t *uncertainty,
		     unsigned char *outbytes, unsigned int *output_uncertainty,
		     unsigned int *num_errs);

    
/***********************************************************************
 * Here and below is more internal stuff.  You can sort of use this,
 * but it may be subject to change.
 */

/*
 * Both the decoder and encoder use the following structure to report
 * output bits.
 */
struct convcode_outdata {
    /*
     * Used to report output bytes as they are collected.  The last
     * time this is called from the finish function nbits may be < 8.
     */
    convcode_output output;
    void *user_data;

    int (*output_bits)(struct convcode *ce, struct convcode_outdata *of,
		       unsigned int bits, unsigned int len);

    /*
     * Output bit processing.  Bits are collected in out_bits until we
     * get 8, then we send it to the output.
     */
    unsigned char out_bits;
    unsigned int out_bit_pos;

    /* Total number of output bits we have generated. */
    unsigned int total_out_bits;
};

/*
 * The data structure for encoding and decoding.  Note that if you use
 * alloc_convcode(), you don't need to mess with this.  But you can
 * change output and output_data if you like in enc_out and dec_out.
 * But don't mess with anything else if you use alloc_convcode().
 * output and output_data will always be first so you can change them
 * even if the structure changes underneath.
 */
struct convcode {
    struct convcode_outdata enc_out;
    struct convcode_outdata dec_out;

    /*
     * Used to report output bytes as they are collected after encoding
     * or decoding.  The last time this is called from convencode_finish()
     * or convdecode_finish() nbits may be < 8.
     */
    convcode_output enc_output;
    void *enc_user_data;

    /* The constraint, or polynomial size in bits.  Max is 16. */
    unsigned int k;

    /* Polynomials. */
    convcode_state polys[CONVCODE_MAX_POLYNOMIALS];
    unsigned int num_polys;

    /*
     * Set if num_polys is 2, 4, or 8.  This lets us optimize putting
     * the bits into the output bytes when encoding as the bits will
     * never span a byte.
     */
    bool optimize_no_span;

    unsigned int tail_bits; /* Number of tail bits, 0 if no tail. */
    bool recursive;

    /* Current state. */
    convcode_state enc_state;

    /* Puncture array. */
    unsigned int puncture_len;
    unsigned int enc_puncture_pos;
    unsigned int dec_puncture_pos;
    const char *puncture;

    /*
     * For the given state, what is the encoded output?  Indexed first
     * by the bit, then by the state.
     */
    const convcode_symsize *convert[2];

    /*
     * 2D Array indexed first by bit then by current state.
     */
    const convcode_state *next_state[2];

    /*
     * Were the above allocated by us or passed in?
     */
    bool states_alloced;

    /*
     * Number of states in the state machine, 1 << (k - 1).
     */
    unsigned int num_states;

    /*
     * The bit trellis matrix.  The first array is an array of
     * pointers to arrays of convcode_state, one for each possible
     * output bit on decoding.  It is trellis_size elements.  Each
     * array in that is individually allocated and contains the state
     * for a specific input.  Each of these is trelw elements wide.
     * If trelw < num_states, the values are computed into tmptrel
     * and then sorted into this array to get the top trelw values.
     */
    convcode_state *trellis;
    unsigned int trellis_size; /* Length of the trellis */
    unsigned int ctrellis; /* Current trellis position */
    unsigned int trelw; /* Width of the trellises we compute */

    /* Are we doing uncertainty calculations? */
    bool do_uncertainty;

    /*
     * A temporary trellis entry, only set/used if trelw < num_states.
     * We calculate the full set of state values into this and then
     * compress it into the trellis.  Also a map that is used for
     * sorting, after the sort tmptrelmap will index into the sorted
     * tmptrel.
     */
    convcode_state *tmptrel;
    convcode_state *tmptrelmap;

    /*
     * A map from the previous state to the previous entry in the
     * trellis, only set/used if trelw < num_states.  If the top bit
     * is set then the entry is invalid.
     */
    convcode_state *trelmap;

    /*
     * You don't need the whole path value matrix, you only need the
     * previous one and the current one (the one you are working on).
     * Each of these is num_states elements.
     */
    unsigned int *prev_path_values;
    unsigned int *curr_path_values;

    /*
     * Symbol decoding function, set here to remove a lot of checks
     * for partial trellis or uncertainty.  It's set based up on data
     * at allocation.
     */
    int (*decode_symbol)(struct convcode *ce, convcode_symsize symbol,
			 const uint8_t *uncertainty);

    /*
     * The uncertainty that maps to 100% uncertain for soft decoding.
     * See the discussion on soft decoding above the
     * set_decode_max_uncertainty function.
     */
    uint8_t uncertainty_100;

    /*
     * When reading bits for decoding, there may be some left over if
     * there weren't enough bits for the whole operation.  Store those
     * here for use in the next decode call.
     */
    convcode_symsize leftover_bits;
    convcode_state leftover_bits_data;
    uint8_t leftover_uncertainty[CONVCODE_MAX_POLYNOMIALS];

    convcode_os_funcs *o;
};

/*
 * If you want to manage all the memory yourself, then do the following:
 *  * Get your own copy of struct convcode.
 *  * Call setup_convcode1.  This will set up various data items you will
 *    need for allocation.
 *  * Set ce->output, ce->output_data
 *  * Allocate the following:
 *    ce->convert - sizeof(*ce->convert) * ce->convert_size
 *  * If you are doing decoding, allocate the following:
 *    ce->trellis - sizeof(*ce->trellis) * ce->trellis_size * ce->trelw
 *    ce->prev_paths_value - sizeof(*ce->prev_path_values) * ce->num_states
 *    ce->curr_paths_value - sizeof(*ce->curr_path_values) * ce->num_states
 *    if trelw < num_states
 *      ce->tmptrel - sizeof(*ce->tmptrel) * ce->trelw
 *      ce->tmptrelmap - sizeof(*ce->tmptrelmap) * ce->trelw
 *      ce->trelmap - sizeof(*ce->trelmap) * ce->trelw
 *  * Call setup_convcode2(ce)
 *  * Call reinit_convcode(ce)
 *
 * You can look at the code for the various size calculations if you want
 * to statically allocate the various entries.
 *
 * Note that if you use this technique, you will not be binary
 * compatible with newer libraries of this code.  But that's probably
 * not an issue.
 */

/*
 * See the above discussion and alloc_convcode for the meaning of the values.
 */
int setup_convcode1(struct convcode *ce, unsigned int k,
		    convcode_state *polynomials, unsigned int num_polynomials,
		    unsigned int max_decode_len_bits,
		    unsigned int trellis_width,
		    bool do_tail, bool recursive, bool do_uncertainty);

/* See the above discussion for how to use this. */
void setup_convcode2(struct convcode *ce);

#endif /* CONVCODE_H */
