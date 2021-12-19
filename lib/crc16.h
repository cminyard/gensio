/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_CRC16_H
#define GENSIO_CRC16_H

#include <stdint.h>

/* Initialize crc with zero. */
void crc16(const unsigned char *buf, unsigned int len, uint16_t *icrc);

/* Initialize crc with 0xffff, xor it with 0xffff when done. */
void crc16_ccitt(const unsigned char *buf, unsigned int len, uint16_t *icrc);

#endif /* GENSIO_CRC16_H */
