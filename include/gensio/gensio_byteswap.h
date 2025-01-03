/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2025  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Basic byte-swapping definitions.
 */

#ifndef GENSIO_BYTESWAP_H
#define GENSIO_BYTESWAP_H

#ifdef _WIN32
/* Assume this for Windows. */
#define GENSIO_IS_BIG_ENDIAN 0
#define GENSIO_IS_LITTLE_ENDIAN 1
#define gensio_bswap_16 _byteswap_ushort
#define gensio_bswap_32 _byteswap_ulong
#define gensio_bswap_64 _byteswap_uint64

#elif defined(linux)
#include <byteswap.h>
#include <endian.h>
#define GENSIO_IS_BIG_ENDIAN (__BYTE_ORDER == __BIG_ENDIAN)
#define GENSIO_IS_LITTLE_ENDIAN (__BYTE_ORDER != __BIG_ENDIAN)
#define gensio_bswap_16 bswap_16
#define gensio_bswap_32 bswap_32
#define gensio_bswap_64 bswap_64

#else /* BSD and others? */
#if defined(__APPLE__)
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define gensio_bswap_16 OSSwapInt16
#define gensio_bswap_32 OSSwapInt32
#define gensio_bswap_64 OSSwapInt64
#else
#include <sys/endian.h>
#define gensio_bswap_16 bswap16
#define gensio_bswap_32 bswap32
#define gensio_bswap_64 bswap64
#endif
#define GENSIO_IS_BIG_ENDIAN (BYTE_ORDER == BIG_ENDIAN)
#define GENSIO_IS_LITTLE_ENDIAN (BYTE_ORDER != BIG_ENDIAN)
#endif

#if GENSIO_IS_BIG_ENDIAN
#define gensio_bswap_16_from_be(x) (x)
#define gensio_bswap_32_from_be(x) (x)
#define gensio_bswap_64_from_be(x) (x)
#define gensio_bswap_16_to_be(x) (x)
#define gensio_bswap_32_to_be(x) (x)
#define gensio_bswap_64_to_be(x) (x)
#define gensio_bswap_16_from_le(x) gensio_bswap_16(x)
#define gensio_bswap_32_from_le(x) gensio_bswap_32(x)
#define gensio_bswap_64_from_le(x) gensio_bswap_164(x)
#define gensio_bswap_16_to_le(x) gensio_bswap_16(x)
#define gensio_bswap_32_to_le(x) gensio_bswap_32(x)
#define gensio_bswap_64_to_le(x) gensio_bswap_64(x)
#else
#define gensio_bswap_16_from_be(x) gensio_bswap_16(x)
#define gensio_bswap_32_from_be(x) gensio_bswap_32(x)
#define gensio_bswap_64_from_be(x) gensio_bswap_64(x)
#define gensio_bswap_16_to_be(x) gensio_bswap_16(x)
#define gensio_bswap_32_to_be(x) gensio_bswap_32(x)
#define gensio_bswap_64_to_be(x) gensio_bswap_64(x)
#define gensio_bswap_16_from_le(x) (x)
#define gensio_bswap_32_from_le(x) (x)
#define gensio_bswap_64_from_le(x) (x)
#define gensio_bswap_16_to_le(x) (x)
#define gensio_bswap_32_to_le(x) (x)
#define gensio_bswap_64_to_le(x) (x)
#endif

#endif /* GENSIO_BYTESWAP_H */
