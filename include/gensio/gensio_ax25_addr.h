/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_AX25_ADDR_H
#define GENSIO_AX25_ADDR_H

#include <gensio/gensio_dllvisibility.h>
#include <stdint.h>
#include <gensio/gensio_addr.h>

struct gensio_ax25_subaddr {
    char addr[7]; /* Only 6 bytes, but nil terminate for convenience. */
    uint8_t ssid : 4;
    uint8_t ch : 1; /* The command/response (dest/src) or h bit (extra). */

    /* Reserved bits, set to one, don't use. */
    uint8_t r1 : 1;
    uint8_t r2 : 1;
    uint8_t r3 : 1;
};

GENSIO_DLL_PUBLIC
bool ax25_subaddr_equal(const struct gensio_ax25_subaddr *a1,
			const struct gensio_ax25_subaddr *a2);

/* Doesn't include terminating '\0' */
#define GENSIO_AX25_MAX_SUBADDR_STR_LEN 10

/* Convert a string to/from a subaddress. */
GENSIO_DLL_PUBLIC
int ax25_str_to_subaddr(const char *s, struct gensio_ax25_subaddr *a,
			bool is_cr);
GENSIO_DLL_PUBLIC
int ax25_subaddr_to_str(const struct gensio_ax25_subaddr *addr,
			char *buf, gensiods *pos, gensiods buflen,
			bool do_cr);

#define GENSIO_AX25_ADDR_MAX_EXTRA 8
struct gensio_ax25_addr {
    struct gensio_addr r;
    struct gensio_os_funcs *o;
    uint8_t tnc_port;
    uint8_t nr_extra;
    struct gensio_ax25_subaddr dest;
    struct gensio_ax25_subaddr src;
    struct gensio_ax25_subaddr extra[GENSIO_AX25_ADDR_MAX_EXTRA];
};

/*
 * Doesn't include terminating '\0'. 10 subaddresses plus a colon
 * between each plus the "ax25:<tnc>," at the beginning.
 */
#define GENSIO_AX25_MAX_ADDR_STR_LEN \
    ((GENSIO_AX25_MAX_SUBADDR_STR_LEN * (GENSIO_AX25_ADDR_MAX_EXTRA + 2)) + \
      (GENSIO_AX25_ADDR_MAX_EXTRA + 1 + 8))

#define addr_to_ax25(a) gensio_container_of(a, struct gensio_ax25_addr, r)

/*
 * The address fields are all of the form "callsign-<n>[:c|r|h]" where
 * callsign consists of upper-case letters and numbers.  If lower-case
 * letters are provided, they are converted to upper case.  <n> is
 * 0-15, if -<n> is not provided it is set to zero.  The c/r/h given
 * is the command/response (for src and dest) or "h" bit (for extras).
 * If not given, h is zero and c/r is assumed to be "r".
 */
GENSIO_DLL_PUBLIC
int gensio_ax25_addr_alloc(struct gensio_os_funcs *o,
			   uint8_t tnc_port, const char *dest, const char *src,
			   uint8_t nr_extra, const char *extras[],
			   struct gensio_addr **raddr);

/*
 * string is in the form:
 *
 *   [ax25:]tncport,dest[:c|r],src[:c|r][,extra1[:h][,extra2[:h][..]]]
 *
 * if ":c|r" is not given on a source/dest, then it is assumed to be
 * response (0).
 */
GENSIO_DLL_PUBLIC
int gensio_ax25_str_to_addr(struct gensio_os_funcs *o,
			    const char *s, struct gensio_addr **raddr);

/* Maximum memory an encoded message can take. */
#define AX25_ADDR_MAX_ENCODED_LEN ((2 + GENSIO_AX25_ADDR_MAX_EXTRA) * 7)
/*
 * data is an incoming packet, pos is the current position in the
 * packet, len is the total length of the packet, port is the tnc it
 * came from.  Data is decoded into the given address and pos is
 * updated to the first byte after the address.
 */
GENSIO_DLL_PUBLIC
int decode_ax25_addr(struct gensio_os_funcs *o,
		     unsigned char *data, gensiods *pos, gensiods len,
		     uint16_t port, struct gensio_ax25_addr *addr);

/* Return the length of the encoded address. */
GENSIO_DLL_PUBLIC
unsigned int ax25_addr_encode_len(struct gensio_addr *iaddr);

/* Encode the address in the buffer, returns the number of bytes. */
GENSIO_DLL_PUBLIC
unsigned int ax25_addr_encode(unsigned char *buf, struct gensio_addr *iaddr);

#endif /* GENSIO_AX25_ADDR_H */
