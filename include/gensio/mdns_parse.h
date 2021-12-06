/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_MDNS_PARSE_H
#define GENSIO_MDNS_PARSE_H

#include <stdint.h>
#include <gensio/gensio_dllvisibility.h>

/* Defined in RFC 1035 */
struct mdns_header {
    uint16_t id;

/*
 * Defined in RFC 1035 (QUERY, OPCODE, and RCODE, AA, TC, RD, RA and
 * RFC 2535 (AD and CD),
 */
#define DNS_FLAG_QUERY	(1 << 15)
#define DNS_FLAG_OPCODE_SHIFT 14
#define DNS_FLAG_OPCODE_MASK (0xf << DNS_FLAG_OPCODE_SHIFT)
#define DNS_FLAG_OPCODE_GET(f) (((f) & DNS_FLAG_OPCODE_MASK) >> \
				DNS_FLAG_OPCODE_SHIFT)
#define DNS_FLAG_OPCODE_SET(f, v) f = ((f) & ~DNS_FLAG_OPCODE_MASK) |	\
				       (v << DNS_FLAG_OPCODE_SHIFT))
#define DNS_FLAG_AA	(1 << 10)
#define DNS_FLAG_TC	(1 << 9)
#define DNS_FLAG_RD	(1 << 8)
#define DNS_FLAG_RA	(1 << 7)
#define DNS_FLAG_AD	(1 << 5)
#define DNS_FLAG_CD	(1 << 4)
#define DNS_FLAG_RCODE_SHIFT 0
#define DNS_FLAG_RCODE_MASK (0xf << DNS_FLAG_RCODE_SHIFT)
#define DNS_FLAG_RCODE_GET(f) (((f) & DNS_FLAG_RCODE_MASK) >> \
				DNS_FLAG_RCODE_SHIFT)
#define DNS_FLAG_RCODE_SET(f, v) f = ((f) & ~DNS_FLAG_RCODE_MASK) |	\
				      (v << DNS_FLAG_RCODE_SHIFT))
    uint16_t flags;

    uint16_t nr_queries;
    uint16_t nr_answers;
    uint16_t nr_ns;
    uint16_t nr_ar;
};

enum dns_opcodes {
    DNS_OPCODE_QUERY = 0,
    DNS_OPCODE_INVERSE_QUERY = 1,
    DNS_OPCODE_STATUS = 2,
    DNS_OPCODE_NOTIFY = 4,
    DNS_OPCODE_UPDATE = 5
};

enum dns_rcodes {
    DNS_RCODE_NO_ERROR		= 0,
    DNS_RCODE_FORMAT_ERROR	= 1,
    DNS_RCODE_SERVER_FAILURE	= 2,
    DNS_RCODE_NONEXISTANTDOMAIN	= 3,
    DNS_RCODE_NOTIMPLEMENTED	= 4,
    DNS_RCODE_REFUSED		= 5,
    DNS_RCODE_YXDOMAIN		= 6,
    DNS_RCODE_YXRRSET		= 7,
    DNS_RCODE_NXRRSET		= 8,
    DNS_RCODE_NOTAUTH		= 9,
    DNS_RCODE_NOTINZONE		= 10
};

enum dns_rr_types {
    DNS_RR_TYPE_A = 1,
    DNS_RR_TYPE_PTR = 12,
    DNS_RR_TYPE_TXT = 16,
    DNS_RR_TYPE_AAAA = 28,
    DNS_RR_TYPE_SRV = 33,
    DNS_RR_TYPE_ANY = 255 /* ANY is only for queries. */
};

enum dns_classes {
    DNS_CLASS_IN = 1,
    DNS_CLASS_ANY = 255, /* ANY is only for queries. */
    DNS_CLASS_CACHE_FLUSH = 0x8000U, /* For modifying data. */
    DNS_CLASS_UNICAST_RESPONSE = 0x8000U, /* Request a unicast response. */
};

struct mdns_name {
    unsigned int nstrs;
    const char **strs;
    unsigned int *pos; /* Holds the position in the output buffer. */
};

struct mdns_query {
    struct mdns_name name;
    uint16_t type;
    uint16_t class;
};

struct mdns_rr_a {
    unsigned char addr[4];
};

struct mdns_rr_ptr {
    struct mdns_name name;
};

struct mdns_rr_txt {
    char **items;
};

struct mdns_rr_aaaa {
    unsigned char addr[16];
};

struct mdns_rr_srv {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    struct mdns_name name;
};

struct mdns_rr {
    struct mdns_name name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdata_len;
    unsigned char *rdata;
    union {
	struct mdns_rr_a a;
	struct mdns_rr_ptr ptr;
	struct mdns_rr_txt txt;
	struct mdns_rr_aaaa aaaa;
	struct mdns_rr_srv srv;
    };
};

/*
 * A received message, or a message to be sent.  For messages
 * allocated with mdns_alloc_msg(), the user may modify h.id, h.flags,
 * max_size, and curr_size.  Leave everything else alone.  For
 * messages from mdns_parse_msg(), there should be no need to modify
 * anything.
 */
struct mdns_msg {
    struct gensio_os_funcs *o;
    unsigned int max_size;
    unsigned int curr_size;
    unsigned int ctrls; /* See MDNS_MSG_CTRL_xxx below. */
    struct mdns_header h;
    unsigned int query_len;
    unsigned int answer_len;
    unsigned int ns_len;
    unsigned int ar_len;
    struct mdns_query **queries;
    struct mdns_rr **answers;
    struct mdns_rr **ns;
    struct mdns_rr **ar;
};

/* A bitmask of controls for handling the output of the mdns packet. */
enum {
    /* Do not compress the strings. */
      MDNS_MSG_CTRL_NOCOMPRESS = (1 << 0)
};

/* Free an mdns message allocated by the below functions. */
GENSIO_DLL_PUBLIC
void mdns_free_msg(struct mdns_msg *m);

/*
 * Parse a block of data holding an mdns message and return a pointer
 * to a message.  Returns:
 *
 * GE_NOMEM - Could not allocate memory
 * GE_INVAL - Invalid data items in the data
 * GE_OUTOFRANGE - The length was too short for the message
 */
GENSIO_DLL_PUBLIC
int mdns_parse_msg(struct gensio_os_funcs *o,
		   unsigned char *buf, gensiods len,
		   struct mdns_msg **rmsg);

/*
 * Convert an MDNS message to bytes in the buffer.  Note that this
 * will *not* return an error if buflen is not long enough to hold the
 * message, but *pos will be > buflen.  You must check this, and you
 * can use it to know how large a buffer to dynamically allocate to
 * hold the message.
 *
 * Note that you must initialize pos to zero (or wherever you want to
 * start in buf) before calling this.
 *
 * Returns:
 * GE_INVAL - Something in the message was invalid.
 */
GENSIO_DLL_PUBLIC
int mdns_output(struct mdns_msg *m,
		unsigned char *buf, unsigned int buflen, unsigned int *pos);

/*
 * Allocate an empty mdns message for adding things to.
 *
 * Note that you must add fields in the following order: queries, answers,
 * ns, and ar.
 *
 * The max_size fields specifies the maximum output size of the
 * message.  If set to zero, it is disabled.
 *
 * The current output (on the network) size of the message is tracked
 * in the curr_size field, it is updated as you add elements.  If
 * max_size is non-zero and adding an element would cause the
 * curr_size to exceed max_size, GE_OUTOFRANGE is returned from the
 * add operation.
 *
 * If you want to allocate the message after the fact, you can set
 * max_size to zero (or some maximum number) and add your data.  Then
 * you can use curr_size to allocate the buffer, set curr_size back to
 * zero, and re-output the message
 */
GENSIO_DLL_PUBLIC
struct mdns_msg *mdns_alloc_msg(struct gensio_os_funcs *o,
				uint16_t id, uint16_t flags,
				unsigned int max_size);

/*
 * Add a query to an MDNS message.
 *
 * Returns:
 * GE_INVAL - A field in the name was too long (63 byte limit).
 * GE_NOMEM - Could not allocate memory.
 */
GENSIO_DLL_PUBLIC
int mdns_add_query(struct mdns_msg *m, const struct mdns_name *name,
		   uint16_t type, uint16_t class);

enum mdns_rr_location {
    MDNS_RR_ANSWER,
    MDNS_RR_NS,
    MDNS_RR_AR
};

/*
 * Add an "a" field to an MDNS message.  "where" says which list to
 * put the message in, per the above enum.  ipv4_addr must be 4 bytes
 * long in network order.
 *
 * Returns:
 * GE_INVAL - A field in the name was too long (63 byte limit) or
 *	      where is wrong.
 * GE_NOMEM - Could not allocate memory.
 */
GENSIO_DLL_PUBLIC
int mdns_add_rr_a(struct mdns_msg *m,
		  enum mdns_rr_location where, const struct mdns_name *name,
		  uint16_t class, uint32_t ttl, unsigned char *ipv4_addr);

/*
 * Add an "aaaa" field to an MDNS message.  "where" says which list to
 * put the message in, per the above enum.  ipv6_addr must be 16 bytes
 * long in network order.
 *
 * Returns:
 * GE_INVAL - A field in the name was too long (63 byte limit) or
 *	      where is wrong.
 * GE_NOMEM - Could not allocate memory.
 */
GENSIO_DLL_PUBLIC
int mdns_add_rr_aaaa(struct mdns_msg *m,
		     enum mdns_rr_location where, const struct mdns_name *name,
		     uint16_t class, uint32_t ttl, unsigned char *ipv6_addr);

/*
 * Add a "ptr" field to an MDNS message.  "where" says which list to
 * put the message in, per the above enum.
 *
 * Returns:
 * GE_INVAL - A field in the name was too long (63 byte limit) or
 *	      where is wrong.
 * GE_NOMEM - Could not allocate memory.
 */
GENSIO_DLL_PUBLIC
int mdns_add_rr_ptr(struct mdns_msg *m,
		    enum mdns_rr_location where, const struct mdns_name *name,
		    uint16_t class, uint32_t ttl,
		    const struct mdns_name *subname);

/*
 * Add a "srv" field to an MDNS message.  "where" says which list to
 * put the message in, per the above enum.
 *
 * Returns:
 * GE_INVAL - A field in the name was too long (63 byte limit) or
 *	      where is wrong.
 * GE_NOMEM - Could not allocate memory.
 */
GENSIO_DLL_PUBLIC
int mdns_add_rr_srv(struct mdns_msg *m,
		    enum mdns_rr_location where, const struct mdns_name *name,
		    uint16_t class, uint32_t ttl,
		    uint16_t priority, uint16_t weight, uint16_t port,
		    const struct mdns_name *subname);

/*
 * Add an "txt" field to an MDNS message.  "where" says which list to
 * put the message in, per the above enum.  txt is an array of pointers
 * to characters terminated by a NULL.
 *
 * Returns:
 * GE_INVAL - A field in the name was too long (63 byte limit) or
 *	      where is wrong, or a txt field is >255 bytes.
 * GE_NOMEM - Could not allocate memory.
 */
GENSIO_DLL_PUBLIC
int mdns_add_rr_txt(struct mdns_msg *m,
		    enum mdns_rr_location where, const struct mdns_name *name,
		    uint16_t class, uint32_t ttl, const char **txt);

/*
 * Compare two messages.  Returns -1 if m1 < m2, 0 if they are the
 * same, and 1 if m1 > m2.  The comparison is somewhat arbitrary, but
 * is consistent, so it's good for building trees and such.
 *
 * This can only be used with messages returned by mdns_parse_msg(),
 * it cannot be used on messages returned by mdns_alloc_msg().
 */
GENSIO_DLL_PUBLIC
int mdns_cmp(struct mdns_msg *m1, struct mdns_msg *m2);

/* Compare two names like strcmp. */
GENSIO_DLL_PUBLIC
int mdns_name_cmp(struct mdns_name *n1, struct mdns_name *n2);

#endif /* GENSIO_MDNS_PARSE_H */
