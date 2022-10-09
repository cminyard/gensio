/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2022  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>

#include <gensio/gensio.h>
#include <gensio/gensio_time.h>
#include "gensio_ll_sound.h"

#ifdef _WIN32
/* Assume this for Windows. */
#define IS_BIG_ENDIAN 0
#define IS_LITTLE_ENDIAN 1
#define bswap_16 _byteswap_ushort
#define bswap_32 _byteswap_ulong
#define bswap_64 _byteswap_uint64

#elif defined(linux)
#include <byteswap.h>
#include <endian.h>
#define IS_BIG_ENDIAN (__BYTE_ORDER == __BIG_ENDIAN)
#define IS_LITTLE_ENDIAN (__BYTE_ORDER != __BIG_ENDIAN)

#else /* BSD and others? */
#if defined(__APPLE__)
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#else
#include <sys/endian.h>
#define bswap_16 bswap16
#define bswap_32 bswap32
#define bswap_64 bswap64
#endif
#define IS_BIG_ENDIAN (BYTE_ORDER == BIG_ENDIAN)
#define IS_LITTLE_ENDIAN (BYTE_ORDER != BIG_ENDIAN)
#endif

enum gensio_sound_ll_state {
    GENSIO_SOUND_LL_CLOSED,
    GENSIO_SOUND_LL_IN_OPEN,
    GENSIO_SOUND_LL_OPEN,
    GENSIO_SOUND_LL_IN_CLOSE,
    GENSIO_SOUND_LL_IN_OPEN_CLOSE
};

struct sound_ll;
struct sound_info;

enum gensio_sound_fmt_type {
    GENSIO_SOUND_FMT_UNKNOWN = -1,

    GENSIO_SOUND_FMT_DOUBLE = 0,
    GENSIO_SOUND_FMT_MIN_USER = GENSIO_SOUND_FMT_DOUBLE,

    GENSIO_SOUND_FMT_FLOAT = 1,
    GENSIO_SOUND_FMT_S32 = 2,
    GENSIO_SOUND_FMT_S24 = 3,
    GENSIO_SOUND_FMT_S16 = 4,
    GENSIO_SOUND_FMT_S8 = 5,

    /*
     * All the ones above this are supported on the user side.  The
     * ones below are only supported on the PCM side, and only if the
     * hardware supports it.
     */
    GENSIO_SOUND_FMT_MAX_USER = GENSIO_SOUND_FMT_S8,

    GENSIO_SOUND_FMT_U32,
    GENSIO_SOUND_FMT_U24,
    GENSIO_SOUND_FMT_U16,
    GENSIO_SOUND_FMT_U8,
#if IS_BIG_ENDIAN
    GENSIO_SOUND_FMT_DOUBLE_BE = GENSIO_SOUND_FMT_DOUBLE,
    GENSIO_SOUND_FMT_FLOAT_BE = GENSIO_SOUND_FMT_FLOAT,
    GENSIO_SOUND_FMT_S32_BE = GENSIO_SOUND_FMT_S32,
    GENSIO_SOUND_FMT_U32_BE = GENSIO_SOUND_FMT_U32,
    GENSIO_SOUND_FMT_S24_BE = GENSIO_SOUND_FMT_S24,
    GENSIO_SOUND_FMT_U24_BE = GENSIO_SOUND_FMT_U24,
    GENSIO_SOUND_FMT_S16_BE = GENSIO_SOUND_FMT_S16,
    GENSIO_SOUND_FMT_U16_BE = GENSIO_SOUND_FMT_U16,
    GENSIO_SOUND_FMT_DOUBLE_LE,
    GENSIO_SOUND_FMT_FLOAT_LE,
    GENSIO_SOUND_FMT_S32_LE,
    GENSIO_SOUND_FMT_U32_LE,
    GENSIO_SOUND_FMT_S24_LE,
    GENSIO_SOUND_FMT_U24_LE,
    GENSIO_SOUND_FMT_S16_LE,
    GENSIO_SOUND_FMT_U16_LE,
    GENSIO_SOUND_FMT_DOUBLE_ALT = GENSIO_SOUND_FMT_DOUBLE_LE,
    GENSIO_SOUND_FMT_FLOAT_ALT = GENSIO_SOUND_FMT_FLOAT_LE,
    GENSIO_SOUND_FMT_S32_ALT = GENSIO_SOUND_FMT_S32_LE,
    GENSIO_SOUND_FMT_U32_ALT = GENSIO_SOUND_FMT_U32_LE,
    GENSIO_SOUND_FMT_S24_ALT = GENSIO_SOUND_FMT_S24_LE,
    GENSIO_SOUND_FMT_U24_ALT = GENSIO_SOUND_FMT_U24_LE,
    GENSIO_SOUND_FMT_S16_ALT = GENSIO_SOUND_FMT_S16_LE,
    GENSIO_SOUND_FMT_U16_ALT = GENSIO_SOUND_FMT_U16_LE,
#else
    GENSIO_SOUND_FMT_DOUBLE_BE,
    GENSIO_SOUND_FMT_FLOAT_BE,
    GENSIO_SOUND_FMT_S32_BE,
    GENSIO_SOUND_FMT_U32_BE,
    GENSIO_SOUND_FMT_S24_BE,
    GENSIO_SOUND_FMT_U24_BE,
    GENSIO_SOUND_FMT_S16_BE,
    GENSIO_SOUND_FMT_U16_BE,
    GENSIO_SOUND_FMT_DOUBLE_ALT = GENSIO_SOUND_FMT_DOUBLE_BE,
    GENSIO_SOUND_FMT_FLOAT_ALT = GENSIO_SOUND_FMT_FLOAT_BE,
    GENSIO_SOUND_FMT_S32_ALT = GENSIO_SOUND_FMT_S32_BE,
    GENSIO_SOUND_FMT_U32_ALT = GENSIO_SOUND_FMT_U32_BE,
    GENSIO_SOUND_FMT_S24_ALT = GENSIO_SOUND_FMT_S24_BE,
    GENSIO_SOUND_FMT_U24_ALT = GENSIO_SOUND_FMT_U24_BE,
    GENSIO_SOUND_FMT_S16_ALT = GENSIO_SOUND_FMT_S16_BE,
    GENSIO_SOUND_FMT_U16_ALT = GENSIO_SOUND_FMT_U16_BE,
    GENSIO_SOUND_FMT_DOUBLE_LE = GENSIO_SOUND_FMT_DOUBLE,
    GENSIO_SOUND_FMT_FLOAT_LE = GENSIO_SOUND_FMT_FLOAT,
    GENSIO_SOUND_FMT_S32_LE = GENSIO_SOUND_FMT_S32,
    GENSIO_SOUND_FMT_U32_LE = GENSIO_SOUND_FMT_U32,
    GENSIO_SOUND_FMT_S24_LE = GENSIO_SOUND_FMT_S24,
    GENSIO_SOUND_FMT_U24_LE = GENSIO_SOUND_FMT_U24,
    GENSIO_SOUND_FMT_S16_LE = GENSIO_SOUND_FMT_S16,
    GENSIO_SOUND_FMT_U16_LE = GENSIO_SOUND_FMT_U16,
#endif

    GENSIO_SOUND_FMT_COUNT
};

struct sound_format_names {
    const char *name;
    enum gensio_sound_fmt_type format;
};

/* Used to convert from a string to a format enum value. */
static struct sound_format_names sound_format_names[] = {
    { "float64",	GENSIO_SOUND_FMT_DOUBLE },
    { "float",		GENSIO_SOUND_FMT_FLOAT },
    { "s32",		GENSIO_SOUND_FMT_S32 },
    { "s24",		GENSIO_SOUND_FMT_S24 },
    { "s16",		GENSIO_SOUND_FMT_S16 },
    { "s8",		GENSIO_SOUND_FMT_S8 },
    { "u32",		GENSIO_SOUND_FMT_U32 },
    { "u24",		GENSIO_SOUND_FMT_U24 },
    { "u16",		GENSIO_SOUND_FMT_U16 },
    { "u8",		GENSIO_SOUND_FMT_U8 },
    { "float64_be",	GENSIO_SOUND_FMT_DOUBLE_BE },
    { "float_be",	GENSIO_SOUND_FMT_FLOAT_BE },
    { "int32_be",	GENSIO_SOUND_FMT_S32_BE },
    { "int24_be",	GENSIO_SOUND_FMT_S24_BE },
    { "int16_be",	GENSIO_SOUND_FMT_S16_BE },
    { "u32_be",		GENSIO_SOUND_FMT_U32_BE },
    { "u24_be",		GENSIO_SOUND_FMT_U24_BE },
    { "u16_be",		GENSIO_SOUND_FMT_U16_BE },
    { "float64_le",	GENSIO_SOUND_FMT_DOUBLE_LE },
    { "float_le",	GENSIO_SOUND_FMT_FLOAT_LE },
    { "int32_le",	GENSIO_SOUND_FMT_S32_LE },
    { "int24_le",	GENSIO_SOUND_FMT_S24_LE },
    { "int16_le",	GENSIO_SOUND_FMT_S16_LE },
    { "u32_le",		GENSIO_SOUND_FMT_U32_LE },
    { "u24_le",		GENSIO_SOUND_FMT_U24_LE },
    { "u16_le",		GENSIO_SOUND_FMT_U16_LE },
    { "FLOAT64",	GENSIO_SOUND_FMT_DOUBLE },
    { "FLOAT",		GENSIO_SOUND_FMT_FLOAT },
    { "S32",		GENSIO_SOUND_FMT_S32 },
    { "S24",		GENSIO_SOUND_FMT_S24 },
    { "S16",		GENSIO_SOUND_FMT_S16 },
    { "S8",		GENSIO_SOUND_FMT_S8 },
    { "U32",		GENSIO_SOUND_FMT_U32 },
    { "U24",		GENSIO_SOUND_FMT_U24 },
    { "U16",		GENSIO_SOUND_FMT_U16 },
    { "U8",		GENSIO_SOUND_FMT_U8 },
    { "FLOAT64_BE",	GENSIO_SOUND_FMT_DOUBLE_BE },
    { "FLOAT_BE",	GENSIO_SOUND_FMT_FLOAT_BE },
    { "INT32_BE",	GENSIO_SOUND_FMT_S32_BE },
    { "INT24_BE",	GENSIO_SOUND_FMT_S24_BE },
    { "INT16_BE",	GENSIO_SOUND_FMT_S16_BE },
    { "U32_BE",		GENSIO_SOUND_FMT_U32_BE },
    { "U24_BE",		GENSIO_SOUND_FMT_U24_BE },
    { "U16_BE",		GENSIO_SOUND_FMT_U16_BE },
    { "FLOAT64_LE",	GENSIO_SOUND_FMT_DOUBLE_LE },
    { "FLOAT_LE",	GENSIO_SOUND_FMT_FLOAT_LE },
    { "INT32_LE",	GENSIO_SOUND_FMT_S32_LE },
    { "INT24_LE",	GENSIO_SOUND_FMT_S24_LE },
    { "INT16_LE",	GENSIO_SOUND_FMT_S16_LE },
    { "U32_LE",		GENSIO_SOUND_FMT_U32_LE },
    { "U24_LE",		GENSIO_SOUND_FMT_U24_LE },
    { "U16_LE",		GENSIO_SOUND_FMT_U16_LE },
    {}
};

struct sound_fmt_info {
    unsigned int size; /* Size, in bytes, of the sample. */
    bool host_bswap; /* Is this byte-swapped with respect to the host? */
    bool isfloat;
    uint32_t offset; /* If unsigned, convert to signed by subtracting this. */
    float scale; /* Scale between offset value and float. */
};

static struct sound_fmt_info sound_fmt_info[] = {
    [ GENSIO_SOUND_FMT_DOUBLE_BE ]	= { .size = sizeof(double),
					    .host_bswap = IS_LITTLE_ENDIAN,
					    .isfloat = true },
    [ GENSIO_SOUND_FMT_FLOAT_BE ]	= { .size = sizeof(float),
					    .host_bswap = IS_LITTLE_ENDIAN,
					    .isfloat = true },
    [ GENSIO_SOUND_FMT_S32_BE ]		= { .size = 4,
					    .host_bswap = IS_LITTLE_ENDIAN,
					    .scale = 2147483648. },
    [ GENSIO_SOUND_FMT_S24_BE ]		= { .size = 3,
					    .host_bswap = IS_LITTLE_ENDIAN,
					    .scale = 8388608. },
    [ GENSIO_SOUND_FMT_S16_BE ]		= { .size = 2,
					    .host_bswap = IS_LITTLE_ENDIAN,
					    .scale = 32768. },
    [ GENSIO_SOUND_FMT_U32_BE ]		= { .size = 4,
					    .host_bswap = IS_LITTLE_ENDIAN,
					    .offset = 2147483648,
					    .scale = 2147483648. },
    [ GENSIO_SOUND_FMT_U24_BE ]		= { .size = 3,
					    .host_bswap = IS_LITTLE_ENDIAN,
					    .offset = 8388608,
					    .scale = 8388608. },
    [ GENSIO_SOUND_FMT_U16_BE ]		= { .size = 2,
					    .host_bswap = IS_LITTLE_ENDIAN,
					    .offset = 32768,
					    .scale = 32768. },
    [ GENSIO_SOUND_FMT_S8 ]		= { .size = 1,
					    .scale = 128. },
    [ GENSIO_SOUND_FMT_U8 ]		= { .size = 1, .offset = 128,
					    .scale = 128. },
    [ GENSIO_SOUND_FMT_DOUBLE_LE ]	= { .size = sizeof(double),
					    .host_bswap = IS_BIG_ENDIAN,
					    .isfloat = true },
    [ GENSIO_SOUND_FMT_FLOAT_LE ]	= { .size = sizeof(float),
					    .host_bswap = IS_BIG_ENDIAN,
					    .isfloat = true },
    [ GENSIO_SOUND_FMT_S32_LE ]		= { .size = 4,
					    .host_bswap = IS_BIG_ENDIAN,
					    .scale = 2147483648. },
    [ GENSIO_SOUND_FMT_S24_LE ]		= { .size = 3,
					    .host_bswap = IS_BIG_ENDIAN,
					    .scale = 8388608. },
    [ GENSIO_SOUND_FMT_S16_LE ]		= { .size = 2,
					    .host_bswap = IS_BIG_ENDIAN,
					    .scale = 32768. },
    [ GENSIO_SOUND_FMT_U32_LE ]		= { .size = 4,
					    .host_bswap = IS_BIG_ENDIAN,
					    .offset = 2147483648,
					    .scale = 2147483648. },
    [ GENSIO_SOUND_FMT_U24_LE ]		= { .size = 3,
					    .host_bswap = IS_BIG_ENDIAN,
					    .offset = 8388608,
					    .scale = 8388608. },
    [ GENSIO_SOUND_FMT_U16_LE ]		= { .size = 2,
					    .host_bswap = IS_BIG_ENDIAN,
					    .offset = 32768,
					    .scale = 32768. }
};

static int32_t
get_int24(const unsigned char **in, unsigned int offset, bool host_bswap)
{
    int32_t v = 0;
    bool big_endian = IS_BIG_ENDIAN ? !host_bswap : host_bswap;

    if (big_endian) {
	v = *(*in)++ << 16;
	v |= *(*in)++ << 8;
	v |= *(*in)++;
    } else {
	v = *(*in)++;
	v |= *(*in)++ << 8;
	v |= *(*in)++ << 16;
    }

    /* If offset is zero, that means the value is signed. */
    if ((v & 0x800000) && !offset)
	v |= 0xff << 24;

    return v;
}

static int32_t
get_int(const unsigned char **in, unsigned int size,
	unsigned int offset, bool host_bswap)
{
    int32_t v = 0;

    switch(size) {
    case 4:
	v = *((int32_t *) *in);
	if (host_bswap)
	    v = bswap_32(v);
	(*in) += 4;
	break;

    case 3:
	v = get_int24(in, offset, host_bswap);
	break;

    case 2:
	v = *((int16_t *) *in);
	if (host_bswap)
	    v = bswap_16(v);
	(*in) += 2;
	break;

    case 1:
	v = *((int8_t *) *in);
	(*in) += 1;
	break;

    default:
	assert(0);
    }

    v -= offset;

    return v;
}

static void
put_int24(int32_t v, unsigned char **out, bool host_bswap)
{
    bool big_endian = IS_BIG_ENDIAN ? !host_bswap : host_bswap;

    if (big_endian) {
	*(*out)++ = v >> 16;
	*(*out)++ = v >> 8;
	*(*out)++ = v;
    } else {
	*(*out)++ = v;
	*(*out)++ = v >> 8;
	*(*out)++ = v >> 16;
    }
}

static void
put_int(int32_t v,
	unsigned char **out, unsigned int size,
	unsigned int offset, bool host_bswap)
{
    v += offset;

    switch(size) {
    case 4:
	if (host_bswap)
	    v = bswap_32(v);
	*((int32_t *) *out) = v;
	(*out) += 4;
	break;

    case 3:
	put_int24(v, out, host_bswap);
	break;

    case 2:
	if (host_bswap)
	    v = bswap_16(v);
	*((int16_t *) *out) = v;
	(*out) += 2;
	break;

    case 1:
	*((int8_t *) *out) = v;
	(*out) += 1;
	break;

    default:
	assert(0);
    }
}

static void
put_float(double v, unsigned char **out,
	  unsigned int size, bool host_bswap)
{
    const void *data = *out;

    if (size == 4) {
	*((float *) data) = v;
	if (host_bswap) {
	    int32_t *iv = ((int32_t *) data);
	    *iv = bswap_32(*((int32_t *) data));
	}
    } else if (size == 8) {
	*((double *) data) = v;
	if (host_bswap) {
	    int64_t *iv = ((int64_t *) data);
	    *iv = bswap_64(*((int64_t *) data));
	}
    } else {
	assert(0);
    }
    *out += size;
}

static double
get_float(const unsigned char **in, unsigned int size, bool host_bswap)
{
    double v = 0;

    if (size == 4) {
	float fv = *((float *) (*in));
	if (host_bswap) {
	    int32_t *iv = ((int32_t *) &fv);
	    *iv = bswap_32(*((int32_t *) &fv));
	}
	v = fv;
    } else if (size == 8) {
	v = *((double *) (*in));
	if (host_bswap) {
	    int64_t *iv = ((int64_t *) &v);
	    *iv = bswap_64(*((int64_t *) &v));
	}
    } else {
	assert(0);
    }
    *in += size;

    return v;
}

/*
 * This is used to convert between the user format and the format used
 * by the pcm side.
 */
struct sound_cnv_info {
    bool enabled;
    /* PCM format.  Will be UNKNOWN if not set by user. */
    enum gensio_sound_fmt_type pfmt;
    enum gensio_sound_fmt_type ufmt;
    gensiods pframesize; /* Size of a frame on the PCM side, in bytes. */
    unsigned int usize; /* Sample size (in bytes) on the user side */

    /* Above values are always set.  Values below are only set if enabled. */

    bool host_bswap;
    unsigned int psize; /* Sample size on the PCM side, in bytes */
    uint32_t offset; /* Subtract/add this from/to the pcm/user to convert. */
    float scale_in; /* Multiply by this to scale to -1.0 - 1.0 float, before offset. */
    float scale_out; /* Multiply by this to scale from -1.0 - 1.0 float, after offset. */
    void (*convin)(const unsigned char **in, unsigned char **out,
		   struct sound_cnv_info *info);
    void (*convout)(const unsigned char **in, unsigned char **out,
		    struct sound_cnv_info *info);
    unsigned char *buf; /* PCM buffer(s) */
};

static void
conv_int_to_float_in(const unsigned char **in, unsigned char **out,
		     struct sound_cnv_info *info)
{
    double v = get_int(in, info->psize, info->offset, info->host_bswap);

    v *= info->scale_in;

    put_float(v, out, info->usize, false);
}

static void
conv_float_to_int_out(const unsigned char **in, unsigned char **out,
		      struct sound_cnv_info *info)
{
    double v = get_float(in, info->usize, false);

    v *= info->scale_out;

    put_int(v + .5, out, info->psize, info->offset, info->host_bswap);
}

static void
conv_float_to_int_in(const unsigned char **in, unsigned char **out,
		     struct sound_cnv_info *info)
{
    double v = get_float(in, info->psize, info->host_bswap);

    v *= info->scale_in;

    put_int(v + .5, out, info->usize, 0, false);
}

static void
conv_int_to_float_out(const unsigned char **in, unsigned char **out,
		      struct sound_cnv_info *info)
{
    double v = get_float(in, info->usize, false);

    v *= info->scale_out;

    put_int(v, out, info->psize, info->offset, info->host_bswap);
}

static void
conv_int_to_int_in(const unsigned char **in, unsigned char **out,
		   struct sound_cnv_info *info)
{
    int32_t v = get_int(in, info->psize, info->offset, info->host_bswap);

    put_int(v, out, info->usize, 0, false);
}

static void
conv_int_to_int_out(const unsigned char **in, unsigned char **out,
		   struct sound_cnv_info *info)
{
    int32_t v = get_int(in, info->usize, 0, false);

    put_int(v, out, info->psize, info->offset, info->host_bswap);
}

static void
conv_float_to_float_in(const unsigned char **in, unsigned char **out,
		       struct sound_cnv_info *info)
{
    double v = get_float(in, info->psize, info->host_bswap);

    put_float(v, out, info->usize, false);
}

static void
conv_float_to_float_out(const unsigned char **in, unsigned char **out,
			struct sound_cnv_info *info)
{
    double v = get_float(in, info->usize, false);

    put_float(v, out, info->psize, info->host_bswap);
}

struct sound_type {
    const char *name;
    int (*setup)(struct sound_info *si, struct gensio_sound_info *io);
    void (*cleanup)(struct sound_info *si);
    int (*open_dev)(struct sound_info *si);
    void (*close_dev)(struct sound_info *si);
    int (*sub_write)(struct sound_info *si, const unsigned char *buf,
		     gensiods buflen, gensiods *nr_written);
    int (*write)(struct sound_info *si, gensiods *rcount,
		 const struct gensio_sg *sg, gensiods sglen);
    void (*next_read)(struct sound_info *si);
    void (*set_write_enable)(struct sound_info *si, bool enable);
    void (*set_read_enable)(struct sound_info *si, bool enable);
    unsigned int (*start_close)(struct sound_info *si);
    /* Return number of frames left to send. */
    unsigned long (*drain_count)(struct sound_info *si);
    int (*devices)(char ***rnames, char ***rspecs, gensiods *rcount);
};

struct sound_info {
    struct sound_ll *soundll;

    struct sound_type *type;
    char *devname;
    bool is_input;

    unsigned int samplerate; /* Frames per second. */
    unsigned int framesize; /* User side sample size * number of chans, bytes */
    gensiods num_bufs; /* Number of buffers on the PCM size. */
    unsigned int chans; /* Number of channels, Will be 0 if disabled. */

    bool ready; /* Is a frame ready to send to user, or is write ready? */

    gensiods readpos; /* frame offset into buf. */
    gensiods len; /* Input only, the number of frames in buf. */
    gensiods bufsize; /* Size in frames of buf. */
    unsigned char *buf; /* User side buffer. */

    /*
     * The conversion buffer info.  This is the pcm side of the data.
     * If cnv.enabled is false, don't use most of this.  A few fields
     * are always set, see the struct definition for details.
     */
    struct sound_cnv_info cnv;

    void *pinfo; /* Info for the specific I/O type (alsa, file, etc.). */
};

static void
setup_convv(struct sound_info *si, enum gensio_sound_fmt_type pfmt)
{
    enum gensio_sound_fmt_type ufmt = si->cnv.ufmt;
    struct sound_fmt_info *uinfo, *pinfo;

    si->cnv.pfmt = pfmt;

    uinfo = &sound_fmt_info[ufmt];
    pinfo = &sound_fmt_info[pfmt];

    si->cnv.usize = uinfo->size;
    si->cnv.psize = pinfo->size;
    si->cnv.offset = pinfo->offset;
    si->cnv.host_bswap = pinfo->host_bswap;

    si->cnv.pframesize = (gensiods) pinfo->size * si->chans;

    if (pinfo->isfloat && uinfo->isfloat) {
	si->cnv.convin = conv_float_to_float_in;
	si->cnv.convout = conv_float_to_float_out;
    } else if (pinfo->isfloat) {
	si->cnv.scale_out = 1 / pinfo->scale;
	si->cnv.scale_in = pinfo->scale;
	si->cnv.convin = conv_float_to_int_in;
	si->cnv.convout = conv_int_to_float_out;
    } else if (uinfo->isfloat) {
	si->cnv.scale_in = 1 / pinfo->scale;
	si->cnv.scale_out = pinfo->scale;
	si->cnv.convin = conv_int_to_float_in;
	si->cnv.convout = conv_float_to_int_out;
    } else {
	si->cnv.convin = conv_int_to_int_in;
	si->cnv.convout = conv_int_to_int_out;
    }

    si->cnv.enabled = true;
}

static int
setup_conv(const char *ufmt, const char *pfmt, struct sound_info *si)
{
    enum gensio_sound_fmt_type pfmtv;
    enum gensio_sound_fmt_type i;

    if (si->cnv.ufmt == GENSIO_SOUND_FMT_UNKNOWN) {
	/* Only do this if it hasn't been done. */
	for (i = GENSIO_SOUND_FMT_MIN_USER;
	     i <= GENSIO_SOUND_FMT_MAX_USER; i++) {
	    if (strcmp(sound_format_names[i].name, ufmt) == 0)
		break;
	}
	if (i > GENSIO_SOUND_FMT_MAX_USER || i < GENSIO_SOUND_FMT_MIN_USER)
	    return GE_INVAL;

	si->cnv.usize = sound_fmt_info[i].size;
	si->framesize = si->cnv.usize * si->chans;

	/* Will be overridden if pfmt is set. */
	si->cnv.pframesize = si->framesize;

	si->cnv.ufmt = i;
    }

    if (!pfmt)
	return 0;

    for (i = 0; i < GENSIO_SOUND_FMT_COUNT; i++) {
	if (strcmp(sound_format_names[i].name, pfmt) == 0)
	    break;
    }
    if (i >= GENSIO_SOUND_FMT_COUNT)
	return GE_INVAL;
    pfmtv = i;

    if (si->cnv.ufmt == pfmtv)
	return 0;

    setup_convv(si, pfmtv);
    return 0;
}

struct sound_ll {
    struct gensio_os_funcs *o;
    struct gensio_lock *lock;
    struct gensio_runner *runner;
    bool deferred_op_pending;

    unsigned int refcount;

    struct gensio_ll *ll;
    gensio_ll_cb cb;
    void *cb_data;

    enum gensio_sound_ll_state state;

    gensio_ll_open_done open_done;
    void *open_done_data;
    gensio_ll_close_done close_done;
    void *close_done_data;
    unsigned int nr_waiting_close;
    bool do_close_now;

    bool stream_running;

    bool read_enabled;
    bool write_enabled;

    bool in_read;
    bool in_write;

    int err;

    struct sound_info in;
    struct sound_info out;

    unsigned int overflows;
    unsigned int underflows;
};

#define ll_to_sound(v) ((struct sound_ll *) gensio_ll_get_user_data(v))

static void gensio_sound_sched_deferred_op(struct sound_ll *soundll);
static void gensio_sound_ll_check_read(struct sound_ll *soundll);
static void gensio_sound_ll_check_write(struct sound_ll *soundll);

static void
gensio_sound_ll_free(struct sound_ll *soundll)
{
    struct gensio_os_funcs *o = soundll->o;

    if (soundll->in.type) {
	soundll->in.type->close_dev(&soundll->in);
	soundll->in.type->cleanup(&soundll->in);
    }
    if (soundll->out.type) {
	soundll->out.type->close_dev(&soundll->out);
	soundll->out.type->cleanup(&soundll->out);
    }
    if (soundll->in.devname)
	o->free(o, soundll->in.devname);
    if (soundll->out.devname)
	o->free(o, soundll->out.devname);
    if (soundll->in.buf)
	o->free(o, soundll->in.buf);
    if (soundll->in.cnv.buf)
	o->free(o, soundll->in.cnv.buf);
    if (soundll->out.buf)
	o->free(o, soundll->out.buf);
    if (soundll->out.cnv.buf)
	o->free(o, soundll->out.cnv.buf);
    if (soundll->ll)
	gensio_ll_free_data(soundll->ll);
    if (soundll->lock)
	o->free_lock(soundll->lock);
    if (soundll->runner)
	o->free_runner(soundll->runner);
    o->free(o, soundll);
}

static void
gensio_sound_ll_lock(struct sound_ll *soundll)
{
    soundll->o->lock(soundll->lock);
}

static void
gensio_sound_ll_unlock(struct sound_ll *soundll)
{
    soundll->o->unlock(soundll->lock);
}

static void
gensio_sound_ll_ref(struct sound_ll *soundll)
{
    soundll->refcount++;
}

static void
gensio_sound_ll_deref(struct sound_ll *soundll)
{
    assert(soundll->refcount > 1);
    soundll->refcount--;
}

static void
gensio_sound_ll_deref_and_unlock(struct sound_ll *soundll)
{
    unsigned int refcount;

    assert(soundll->refcount > 0);
    refcount = --soundll->refcount;
    gensio_sound_ll_unlock(soundll);
    if (refcount == 0)
	gensio_sound_ll_free(soundll);
}

static int
extend_sound_devs(char ***names, char ***specs, gensiods *size)
{
    gensiods nsize = *size + 10;
    char **nnames, **nspecs;

    nnames = calloc(sizeof(*nnames), nsize);
    if (!nnames)
	return GE_NOMEM;

    nspecs = calloc(sizeof(*nspecs), nsize);
    if (!nspecs) {
	free(nnames);
	return GE_NOMEM;
    }

    if (*names) {
	memcpy(nnames, *names, *size * sizeof(*nnames));
	free(*names);
    }
    if (*specs) {
	memcpy(nspecs, *specs, *size * sizeof(*nspecs));
	free(*specs);
    }
    *names = nnames;
    *specs = nspecs;
    *size = nsize;
    return 0;
}

static int gensio_sound_api_default_write(struct sound_info *out,
					  gensiods *rcount,
					  const struct gensio_sg *sg,
					  gensiods sglen);

#if HAVE_ALSA
#include "alsa_sound.h"
#else
#define ALSA_INIT
#endif

#ifdef _WIN32
#include "win_sound.h"
#else
#define WIN_INIT
#endif

#include "file_sound.h"

static void
gensio_sound_ll_check_read(struct sound_ll *soundll)
{
    struct sound_info *si = &soundll->in;

    if (soundll->in_read)
	return;
    if (soundll->read_enabled && (si->ready || soundll->err)) {
	unsigned int len;
	gensiods count;

	if (soundll->err) {
	    soundll->in_read = true;
	    gensio_sound_ll_unlock(soundll);
	    count = soundll->cb(soundll->cb_data, GENSIO_LL_CB_READ,
				soundll->err, NULL, 0, NULL);
	    gensio_sound_ll_lock(soundll);
	    soundll->in_read = false;
	    goto out;
	}

	if (si->readpos + si->len > si->bufsize)
	    len = si->bufsize - si->readpos;
	else
	    len = si->len;
	soundll->in_read = true;
	gensio_sound_ll_unlock(soundll);
	count = soundll->cb(soundll->cb_data, GENSIO_LL_CB_READ, 0,
			    si->buf + si->readpos * si->framesize,
			    (gensiods) len * si->framesize, NULL);
	gensio_sound_ll_lock(soundll);
	soundll->in_read = false;
	if (soundll->state != GENSIO_SOUND_LL_OPEN)
	    goto out;
	si->readpos += count / si->framesize;
	si->len -= count / si->framesize;
	if (si->len == 0) {
	    si->readpos = 0;
	    si->ready = false;
	    if (si->type->next_read)
		si->type->next_read(&soundll->in);
	}
    }
 out:
    if (soundll->read_enabled && (si->ready || soundll->err))
	gensio_sound_sched_deferred_op(soundll);
}

static void
gensio_sound_ll_check_write(struct sound_ll *soundll)
{
    struct sound_info *si = &soundll->out;

    if (soundll->in_write)
	return;
    if (soundll->write_enabled && si->ready) {
	soundll->in_write = true;
	gensio_sound_ll_unlock(soundll);
	soundll->cb(soundll->cb_data, GENSIO_LL_CB_WRITE_READY, 0,
		    NULL, 0, NULL);
	gensio_sound_ll_lock(soundll);
	soundll->in_write = false;
    }
    if (soundll->write_enabled && si->ready)
	gensio_sound_sched_deferred_op(soundll);
}

static void
gensio_sound_ll_do_close(struct sound_ll *soundll)
{
    gensio_ll_close_done close_done = soundll->close_done;
    void *close_done_data = soundll->close_done_data;

    soundll->close_done = NULL;
    gensio_sound_ll_unlock(soundll);
    close_done(soundll->cb_data, close_done_data);
    gensio_sound_ll_lock(soundll);
}

static void
gensio_sound_ll_do_open(struct sound_ll *soundll, int err)
{
    gensio_ll_open_done open_done = soundll->open_done;
    void *open_done_data = soundll->open_done_data;

    soundll->open_done = NULL;
    gensio_sound_ll_unlock(soundll);
    open_done(soundll->cb_data, err, open_done_data);
    gensio_sound_ll_lock(soundll);
}

static void
gensio_sound_do_read_enable(struct sound_ll *soundll)
{
    soundll->in.type->set_read_enable(&soundll->in, true);
    if (soundll->in.ready || soundll->err) {
	gensio_sound_sched_deferred_op(soundll);
    } else {
	if (soundll->in.ready || soundll->err)
	    gensio_sound_sched_deferred_op(soundll);
    }
}

static void
gensio_sound_ll_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct sound_ll *soundll = cbdata;

    gensio_sound_ll_lock(soundll);
    soundll->deferred_op_pending = false;
    switch(soundll->state) {
    case GENSIO_SOUND_LL_CLOSED:
	break;

    case GENSIO_SOUND_LL_IN_OPEN: {
	bool oldread = soundll->read_enabled, oldwrite = soundll->write_enabled;

	soundll->state = GENSIO_SOUND_LL_OPEN;
	gensio_sound_ll_do_open(soundll, 0);
	if (soundll->state != GENSIO_SOUND_LL_OPEN)
	    break;
	/*
	 * These won't be activated if they were enabled before the
	 * open callback, handle that.
	 */
	if (oldread && soundll->read_enabled)
	    gensio_sound_do_read_enable(soundll);
	if (oldwrite && soundll->write_enabled)
	    soundll->out.type->set_write_enable(&soundll->out, true);
	break;
    }

    case GENSIO_SOUND_LL_OPEN:
	gensio_sound_ll_check_read(soundll);
	gensio_sound_ll_check_write(soundll);
	break;

    case GENSIO_SOUND_LL_IN_OPEN_CLOSE:
	if (soundll->do_close_now)
	    gensio_sound_ll_do_open(soundll, GE_LOCALCLOSED);
	/* Fallthrough */
    case GENSIO_SOUND_LL_IN_CLOSE:
	if (soundll->do_close_now) {
	    soundll->do_close_now = false;
	    soundll->state = GENSIO_SOUND_LL_CLOSED;
	    gensio_sound_ll_do_close(soundll);
	    gensio_sound_ll_deref(soundll);
	}
	break;

    default:
	break;
    }
    gensio_sound_ll_deref_and_unlock(soundll);
}

/* Must be called with the lock held. */
static void
gensio_sound_sched_deferred_op(struct sound_ll *soundll)
{
    if (!soundll->deferred_op_pending) {
	gensio_sound_ll_ref(soundll);
	soundll->deferred_op_pending = true;
	soundll->o->run(soundll->runner);
    }
}

static int
gensio_sound_api_default_write(struct sound_info *out, gensiods *rcount,
			       const struct gensio_sg *sg, gensiods sglen)
{
    int err = 0;
    gensiods count = 0, i, nr_written = 0;

    for (i = 0; i < sglen; i++) {
	const unsigned char *buf, *ibuf = NULL;
	unsigned char *tbuf;
	gensiods buflen, ibuflen = 0, j; /* Size in frames. */

	if (!sg[i].buflen)
	    continue;

	if (out->cnv.enabled) {
	    ibuf = sg[i].buf;
	    ibuflen = sg[i].buflen / out->framesize;
	moredata:
	    tbuf = out->cnv.buf;
	    for (j = 0; j < ibuflen && j < out->bufsize; j++) {
		gensiods k;

		for (k = 0; k < out->chans; k++)
		    out->cnv.convout(&ibuf, &tbuf, &out->cnv);
	    }
	    if (j == ibuflen)
		ibuf = NULL;
	    else
		ibuflen -= j;
	    buf = out->cnv.buf;
	    buflen = j;
	} else {
	    buf = sg[i].buf;
	    buflen = sg[i].buflen / out->framesize;
	}
	err = out->type->sub_write(out, buf, buflen, &nr_written);
	if (err)
	    break;
	count += nr_written * out->framesize;
	if (nr_written < buflen)
	    /* Didn't write the whole buffer. */
	    break;
	if (ibuf)
	    goto moredata;
    }
    if (!err && rcount)
	*rcount = count;
    return err;
}

static int
gensio_sound_ll_write(struct sound_ll *soundll, gensiods *rcount,
		      const struct gensio_sg *sg, gensiods sglen)
{
    int err = 0;
    gensiods i = 0;

    if (soundll->out.chans == 0)
	return GE_NOTSUP;

    gensio_sound_ll_lock(soundll);
    if (soundll->err) {
	err = soundll->err;
	goto out_unlock;
    }
    if (soundll->state != GENSIO_SOUND_LL_OPEN) {
	err = GE_NOTREADY;
	goto out_unlock;
    }
    for (i = 0; i < sglen; i++) {
	if (sg[i].buflen % soundll->out.framesize != 0) {
	    err = GE_INVAL;
	    goto out_unlock;
	}
    }
    err = soundll->out.type->write(&soundll->out, rcount, sg, sglen);
 out_unlock:
    gensio_sound_ll_unlock(soundll);
    return err;
}

static int
gensio_sound_ll_open(struct sound_ll *soundll,
		     gensio_ll_open_done open_done, void *open_data)
{
    int err = 0;

    gensio_sound_ll_lock(soundll);
    if (soundll->state != GENSIO_SOUND_LL_CLOSED) {
	err = GE_INUSE;
	goto out_unlock;
    }

    if (soundll->in.chans) {
	err = soundll->in.type->open_dev(&soundll->in);
	if (err)
	    goto out_unlock;
    }
    if (soundll->out.chans) {
	err = soundll->out.type->open_dev(&soundll->out);
	if (err) {
	    if (soundll->in.chans)
		soundll->in.type->close_dev(&soundll->in);
	    goto out_unlock;
	}
    }
    soundll->state = GENSIO_SOUND_LL_IN_OPEN;
    soundll->open_done = open_done;
    soundll->open_done_data = open_data;
    soundll->stream_running = true;
    gensio_sound_sched_deferred_op(soundll);

 out_unlock:
    gensio_sound_ll_unlock(soundll);
    return err;
}

static int
gensio_sound_ll_close(struct sound_ll *soundll,
		      gensio_ll_close_done close_done, void *close_data)
{
    int err = 0;

    gensio_sound_ll_lock(soundll);
    if (soundll->state == GENSIO_SOUND_LL_IN_OPEN)
	soundll->state = GENSIO_SOUND_LL_IN_OPEN_CLOSE;
    else if (soundll->state == GENSIO_SOUND_LL_OPEN)
	soundll->state = GENSIO_SOUND_LL_IN_CLOSE;
    else
	err = GE_INUSE;
    if (!err) {
	gensio_sound_ll_ref(soundll); /* For the close */
	soundll->close_done = close_done;
	soundll->close_done_data = close_data;

	soundll->nr_waiting_close = 0;
	if (soundll->in.chans)
	    soundll->nr_waiting_close +=
		soundll->in.type->start_close(&soundll->in);
	if (soundll->out.chans)
	    soundll->nr_waiting_close +=
		soundll->out.type->start_close(&soundll->out);
	if (soundll->nr_waiting_close == 0) {
	    soundll->stream_running = false;
	    soundll->do_close_now = true;
	    gensio_sound_sched_deferred_op(soundll);
	}
    }
    gensio_sound_ll_unlock(soundll);
    return err;
}

static int
gensio_sound_ll_control(struct sound_ll *soundll, bool get, unsigned int option,
			char *data, gensiods *datalen)
{
    unsigned int i;
    struct sound_info *si;
    const char *s;

    switch(option) {
    case GENSIO_CONTROL_RADDR:
	if (!get)
	    return GE_NOTSUP;
	if (strtoul(data, NULL, 0) > 0)
	    return GE_NOTFOUND;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "sound");
	return 0;

    case GENSIO_CONTROL_IN_RATE:
	if (!get)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%u",
				       soundll->in.samplerate);
	return 0;

    case GENSIO_CONTROL_OUT_RATE:
	if (!get)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%u",
				       soundll->out.samplerate);
	return 0;

    case GENSIO_CONTROL_IN_BUFSIZE:
	if (!get)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%lu",
				       (unsigned long) soundll->in.bufsize);
	return 0;

    case GENSIO_CONTROL_OUT_BUFSIZE:
	if (!get)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%lu",
				       (unsigned long) soundll->out.bufsize);
	return 0;

    case GENSIO_CONTROL_IN_NR_CHANS:
	if (!get)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%u",
				       soundll->in.chans);
	return 0;

    case GENSIO_CONTROL_OUT_NR_CHANS:
	if (!get)
	    return GE_NOTSUP;
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%u",
				       soundll->out.chans);
	return 0;

    case GENSIO_CONTROL_IN_FORMAT:
	if (!get)
	    return GE_NOTSUP;
	si = &soundll->in;
	goto get_si_format;

    case GENSIO_CONTROL_OUT_FORMAT:
	if (!get)
	    return GE_NOTSUP;
	si = &soundll->out;
    get_si_format:
	s = "unknown";
	for (i = 0; sound_format_names[i].name; i++) {
	    if (sound_format_names[i].format == si->cnv.ufmt) {
		s = sound_format_names[i].name;
		break;
	    }
	}
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%s", s);
	return 0;

    case GENSIO_CONTROL_DRAIN_COUNT: {
	unsigned long frames_left = 0;

	if (!get)
	    return GE_NOTSUP;
	si = &soundll->out;
	if (!si->type)
	    return GE_NOTSUP;
	if (si->type->drain_count)
	    frames_left = si->type->drain_count(si);
	*datalen = gensio_pos_snprintf(data, *datalen, NULL, "%lu", frames_left);
	return 0;
    }

    default:
	return GE_NOTSUP;
    }
}

static int
gensio_sound_ll_do_free(struct sound_ll *soundll)
{
    gensio_sound_ll_lock(soundll);
    switch (soundll->state) {
    case GENSIO_SOUND_LL_IN_OPEN:
    case GENSIO_SOUND_LL_OPEN:
	gensio_sound_ll_close(soundll, NULL, NULL);
	break;

    default:
	break;
    }
    gensio_sound_ll_deref_and_unlock(soundll);
    return 0;
}

static int
gensio_sound_ll_func(struct gensio_ll *ll, int op,
		     gensiods *count,
		     void *buf, const void *cbuf,
		     gensiods buflen,
		     const char *const *auxdata)
{
    struct sound_ll *soundll = ll_to_sound(ll);

    switch (op) {
    case GENSIO_LL_FUNC_SET_CALLBACK:
	soundll->cb = (gensio_ll_cb) cbuf;
	soundll->cb_data = buf;
	return 0;

    case GENSIO_LL_FUNC_WRITE_SG:
	return gensio_sound_ll_write(soundll, count, cbuf, buflen);

    case GENSIO_LL_FUNC_OPEN:
	return gensio_sound_ll_open(soundll, (gensio_ll_open_done) cbuf, buf);

    case GENSIO_LL_FUNC_CLOSE:
	return gensio_sound_ll_close(soundll, (gensio_ll_close_done) cbuf, buf);

    case GENSIO_LL_FUNC_SET_READ_CALLBACK: {
	bool enable = !!buflen;

	/* Output only, just ignore. */
	if (!soundll->in.type)
	    return 0;

	gensio_sound_ll_lock(soundll);
	if (soundll->read_enabled != enable) {
	    soundll->read_enabled = enable;
	    if (soundll->state == GENSIO_SOUND_LL_OPEN) {
		if (enable)
		    gensio_sound_do_read_enable(soundll);
		else
		    soundll->in.type->set_read_enable(&soundll->in, false);
	    }
	}
	gensio_sound_ll_unlock(soundll);
	return 0;
    }

    case GENSIO_LL_FUNC_SET_WRITE_CALLBACK: {
	bool enable = !!buflen;

	/* Input only, just ignore. */
	if (!soundll->out.type)
	    return 0;

	gensio_sound_ll_lock(soundll);
	if (soundll->write_enabled != enable) {
	    soundll->write_enabled = enable;
	    if (soundll->state == GENSIO_SOUND_LL_OPEN) {
		soundll->out.type->set_write_enable(&soundll->out, enable);
		if (soundll->out.ready)
		    gensio_sound_sched_deferred_op(soundll);
	    }
	}
	gensio_sound_ll_unlock(soundll);
	return 0;
    }

    case GENSIO_LL_FUNC_FREE:
	return gensio_sound_ll_do_free(soundll);

    case GENSIO_LL_FUNC_DISABLE:
	soundll->stream_running = false;
	soundll->in.type->close_dev(&soundll->in);
	soundll->in.type->close_dev(&soundll->out);
	soundll->state = GENSIO_SOUND_LL_CLOSED;
	return 0;

    case GENSIO_LL_FUNC_CONTROL:
	return gensio_sound_ll_control(soundll, *((bool *) cbuf), buflen, buf,
				       count);

    }

    return GE_NOTSUP;
}

static struct sound_type *sound_types[] = {
    ALSA_INIT
    WIN_INIT
    FILE_INIT
    NULL
};

static int
setup_sound_info(struct gensio_os_funcs *o,
		 struct sound_info *si, struct gensio_sound_info *io,
		 bool isinput)
{
    unsigned int i = 0;
    int err;

    if (io->type) {
	for (; sound_types[i]; i++) {
	    if (strcmp(io->type, sound_types[i]->name) == 0)
		break;
	}
    }
    if (!sound_types[i])
	return GE_INVAL;

    si->type = sound_types[i];
    if (!io->devname || io->samplerate == 0 || io->chans == 0)
	return GE_INVAL;
    if (!io->format || io->bufsize == 0 || io->num_bufs == 0)
	return GE_INVAL;

    si->cnv.pfmt = GENSIO_SOUND_FMT_UNKNOWN;
    si->cnv.ufmt = GENSIO_SOUND_FMT_UNKNOWN;
    si->bufsize = io->bufsize;
    si->num_bufs = io->num_bufs;
    si->chans = io->chans;
    si->samplerate = io->samplerate;

    err = setup_conv(io->format, io->pformat, si);
    if (err)
	return err;

    err = si->type->setup(si, io);
    if (err)
	return err;

    si->devname = gensio_strdup(o, io->devname);
    if (!si->devname)
	return GE_NOMEM;

    if (isinput) {
	/* One buffer for sending to the user. */
	si->buf = o->zalloc(o, io->bufsize * si->framesize);
	if (!si->buf)
	    return GE_NOMEM;
    }

    return 0;
}

int
gensio_sound_ll_alloc(struct gensio_os_funcs *o,
		      struct gensio_sound_info *in,
		      struct gensio_sound_info *out,
		      struct gensio_ll **newll)
{
    int err;
    struct sound_ll *soundll;

    if (in && in->chans == 0)
	in = NULL;
    if (out && out->chans == 0)
	out = NULL;

    if (!in && !out)
	return GE_INVAL;

    soundll = o->zalloc(o, sizeof(*soundll));
    if (!soundll)
	return GE_NOMEM;

    soundll->refcount = 1;
    soundll->o = o;

    if (in) {
	soundll->in.is_input = true;
	soundll->in.soundll = soundll;
	err = setup_sound_info(o, &soundll->in, in, true);
	if (err)
	    goto out_err;
    }

    if (out) {
	soundll->out.is_input = false;
	soundll->out.soundll = soundll;
	err = setup_sound_info(o, &soundll->out, out, false);
	if (err)
	    goto out_err;
    }

    soundll->runner = o->alloc_runner(o, gensio_sound_ll_deferred_op, soundll);
    if (!soundll->runner)
	goto out_nomem;

    soundll->lock = o->alloc_lock(o);
    if (!soundll->lock)
	goto out_nomem;

    soundll->ll = gensio_ll_alloc_data(o, gensio_sound_ll_func, soundll);
    if (!soundll->ll)
	goto out_nomem;

    *newll = soundll->ll;

    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    gensio_sound_ll_free(soundll);
    return err;
}

void
gensio_sound_devices_free(char **names, char **specs, gensiods count)
{
    gensiods i;

    if (names) {
	for (i = 0; i < count; i++) {
	    if (names[i])
		free(names[i]);
	}
	free(names);
    }
    if (specs) {
	for (i = 0; i < count; i++) {
	    if (specs[i])
		free(specs[i]);
	}
	free(specs);
    }
}

int
gensio_sound_devices(const char *type,
		     char ***rnames, char ***rspecs, gensiods *rcount)
{
    unsigned int i = 0;

    if (type) {
	for (; sound_types[i]; i++) {
	    if (strcmp(type, sound_types[i]->name) == 0)
		break;
	}
    }
    if (!sound_types[i])
	return GE_INVAL;
    return sound_types[i]->devices(rnames, rspecs, rcount);
}
