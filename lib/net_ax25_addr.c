/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <gensio/gensio.h>
#include <gensio/gensio_ax25_addr.h>

bool
ax25_subaddr_equal(const struct gensio_ax25_subaddr *a1,
		   const struct gensio_ax25_subaddr *a2)
{
    if (strcmp(a1->addr, a2->addr) != 0)
	return false;
    if (a1->ssid != a2->ssid)
	return false;
    return true;
}

static bool ax25_addr_equal(const struct gensio_addr *ia1,
			    const struct gensio_addr *ia2,
			    bool compare_ports, bool compare_all)
{
    struct gensio_ax25_addr *a1 = addr_to_ax25(ia1), *a2 = addr_to_ax25(ia2);
    unsigned int i;

    if (compare_ports && a1->tnc_port != a2->tnc_port)
	return false;
    if (!ax25_subaddr_equal(&a1->dest, &a2->dest))
	return false;
    if (!ax25_subaddr_equal(&a1->src, &a2->src))
	return false;
    if (!compare_all)
	return true;
    if (a1->nr_extra != a2->nr_extra)
	return false;
    for (i = 0; i < a1->nr_extra; i++) {
	if (strcmp(a1->extra[i].addr, a2->extra[i].addr) != 0)
	    return false;
	if (a1->extra[i].ssid != a2->extra[i].ssid)
	    return false;
    }
    return true;
}

int
ax25_subaddr_to_str(const struct gensio_ax25_subaddr *a,
		    char *buf, gensiods *pos, gensiods buflen,
		    bool do_cr)
{
    if (a->ssid)
	gensio_pos_snprintf(buf, buflen, pos, "%s-%d", a->addr, a->ssid);
    else
	gensio_pos_snprintf(buf, buflen, pos, "%s", a->addr);
    if (do_cr)
	gensio_pos_snprintf(buf, buflen, pos, ":%c", a->ch ? 'c' : 'r');
    return 0;
}

static int
ax25_addr_to_str(const struct gensio_addr *addr,
		 char *buf, gensiods *pos, gensiods buflen)
{
    struct gensio_ax25_addr *a = addr_to_ax25(addr);
    unsigned int i;

    gensio_pos_snprintf(buf, buflen, pos, "ax25:%d,", a->tnc_port);
    ax25_subaddr_to_str(&a->dest, buf, pos, buflen, false);
    gensio_pos_snprintf(buf, buflen, pos, ",");
    ax25_subaddr_to_str(&a->src, buf, pos, buflen, false);
    for (i = 0; i < a->nr_extra; i++) {
	gensio_pos_snprintf(buf, buflen, pos, ",");
	ax25_subaddr_to_str(&a->extra[i], buf, pos, buflen, false);
	if (a->extra[i].ch)
	    gensio_pos_snprintf(buf, buflen, pos, ":h");
    }

    return 0;
}

static struct gensio_addr *
ax25_addr_dup(const struct gensio_addr *iaddr)
{
    struct gensio_ax25_addr *a = addr_to_ax25(iaddr), *ra;

    ra = a->o->zalloc(a->o, sizeof(*ra));
    if (!ra)
	return NULL;
    memcpy(ra, a, sizeof(*ra));
    return &ra->r;
}

static struct gensio_addr *
ax25_addr_cat(const struct gensio_addr *addr1,
	      const struct gensio_addr *addr2)
{
    return NULL;
}

static bool
ax25_addr_addr_present(const struct gensio_addr *gai,
		       const void *addr, gensiods addrlen,
		       bool compare_ports)
{
    /* FIXME ? */
    return false;
}

static void
ax25_addr_free(struct gensio_addr *addr)
{
    struct gensio_ax25_addr *a = addr_to_ax25(addr);

    a->o->free(a->o, a);
}

static bool
ax25_addr_next(struct gensio_addr *addr)
{
    return false;
}

static void
ax25_addr_rewind(struct gensio_addr *addr)
{
}

static int
ax25_addr_get_nettype(const struct gensio_addr *addr)
{
    return GENSIO_NETTYPE_AX25;
}

static bool
ax25_addr_family_supports(const struct gensio_addr *addr, int family, int flags)
{
    return family == GENSIO_NETTYPE_AX25;
}

static void
ax25_addr_getaddr(const struct gensio_addr *addr, void *oaddr, gensiods *rlen)
{
    gensiods len = *rlen;

    if (len > sizeof(struct gensio_ax25_addr))
	len = sizeof(struct gensio_ax25_addr);
    memcpy(oaddr, addr, len);
    *rlen = sizeof(struct gensio_ax25_addr);
}

const static struct gensio_addr_funcs ax25_addr_funcs = {
    .addr_equal = ax25_addr_equal,
    .addr_to_str = ax25_addr_to_str,
    .addr_to_str_all = ax25_addr_to_str,
    .addr_dup = ax25_addr_dup,
    .addr_cat = ax25_addr_cat,
    .addr_addr_present = ax25_addr_addr_present,
    .addr_free = ax25_addr_free,
    .addr_next = ax25_addr_next,
    .addr_rewind = ax25_addr_rewind,
    .addr_get_nettype = ax25_addr_get_nettype,
    .addr_family_supports = ax25_addr_family_supports,
    .addr_getaddr = ax25_addr_getaddr
};

int
ax25_str_to_subaddr(const char *s, struct gensio_ax25_subaddr *a, bool is_cr)
{
    unsigned int i, j;
    char *end;

    if (!*s)
	/* Reject empty strings. */
	return GE_INVAL;

    for (i = 0; i < 6; i++) {
	if (!s[i])
	    break;
	else if (isupper(s[i]) || isdigit(s[i]))
	    a->addr[i] = s[i];
	else if (islower(s[i]))
	    a->addr[i] = toupper(s[i]);
	else if (s[i] == '-')
	    break;
	else
	    return GE_INVAL;
    }
    if (s[i] == '\0') {
	a->ssid = 0;
	return 0;
    }
    if (s[i] != '-')
	return GE_INVAL;

    for (j = i; j < 6; j++)
	a->addr[j] = '\0';
    a->addr[j] = '\0';

    a->ch = 0;
    i++;
    j = strtoul(s + i, &end, 10);
    if (*end == ':') {
	if (!is_cr && strcmp(end, ":h") == 0)
	    a->ch = 1;
	else
	    return GE_INVAL;
    } else if (*end != '\0') {
	return GE_INVAL;
    }
    if (j >= 16)
	return GE_INVAL;
    a->ssid = j;
    a->r1 = 1;
    a->r2 = 1;
    a->r3 = 1;

    return 0;
}

int
gensio_ax25_addr_alloc(struct gensio_os_funcs *o,
		       uint8_t tnc_port, const char *dest, const char *src,
		       uint8_t nr_extra, const char *extras[],
		       struct gensio_addr **raddr)
{
    struct gensio_ax25_addr *a;
    unsigned int i;
    int rv;

    if (nr_extra > GENSIO_AX25_ADDR_MAX_EXTRA)
	return GE_INVAL;

    a = o->zalloc(o, sizeof(*a));
    if (!a)
	return GE_NOMEM;

    a->o = o;
    a->r.funcs = &ax25_addr_funcs;
    rv = ax25_str_to_subaddr(dest, &a->dest, true);
    if (rv)
	goto out_err;
    rv = ax25_str_to_subaddr(src, &a->src, true);
    if (rv)
	goto out_err;
    for (i = 0; i < nr_extra; i++) {
	rv = ax25_str_to_subaddr(extras[i], &(a->extra[i]), false);
	if (rv)
	    goto out_err;
    }
    a->nr_extra = nr_extra;

    *raddr = &a->r;
    return 0;

 out_err:
    o->free(o, a);
    return rv;
}

int
gensio_ax25_str_to_addr(struct gensio_os_funcs *o,
			const char *instr, struct gensio_addr **raddr)
{
    char *s, *dest, *src, *end;
    const char*extras[GENSIO_AX25_ADDR_MAX_EXTRA + 1];
    uint8_t tnc_port;
    unsigned int i;
    int rv;

    if (strncmp(instr, "ax25:", 5) == 0)
	instr += 5;

    if (!isdigit(*instr)) /* Must be a number to start. */
	return GE_INVAL;
    tnc_port = strtoul(instr, &end, 10);
    if (*end != ',')
	return GE_INVAL;

    s = gensio_strdup(o, end + 1);
    if (!s)
	return GE_NOMEM;
    dest = s;
    src = strchr(dest, ',');
    if (!src)
	goto out_inval;
    *src++ = '\0';
    end = strchr(src, ',');
    for (i = 0; end && i < GENSIO_AX25_ADDR_MAX_EXTRA; i++) {
	*end++ = '\0';
	extras[i] = end;
	end = strchr(extras[i], ',');
    }
    if (end)
	/* Too many extra fields. */
	goto out_inval;
    rv = gensio_ax25_addr_alloc(o, tnc_port, dest, src, i, extras, raddr);
    o->free(o, s);
    return rv;

 out_inval:
    o->free(o, s);
    return GE_INVAL;
}

static int
decode_ax25_subaddr(unsigned char *data, gensiods *ipos, gensiods len,
		    struct gensio_ax25_subaddr *addr)
{
    gensiods pos = *ipos;
    unsigned int i;

    if (len - *ipos < 7)
	return GE_INVAL;
    memset(addr, 0, sizeof(*addr));
    for (i = 0; i < 6; i++) {
	if (data[i + pos] & 1)
	    return GE_INVAL;
	addr->addr[i] = data[i + pos] >> 1;
	if (addr->addr[i] == ' ') /* Spaces are at the end and not used. */
	    addr->addr[i] = '\0';
    }
    addr->ssid = (data[i + pos] >> 1) & 0xf;
    addr->ch = (data[i + pos] >> 7) & 1;
    addr->r1 = (data[i + pos] >> 5) & 1;
    addr->r2 = (data[i + pos] >> 6) & 1;
    addr->r3 = 1;
    *ipos += 7;
    if (data[i + pos] & 1)
	return GE_REMCLOSE;
    return 0;
}

int
decode_ax25_addr(struct gensio_os_funcs *o,
		 unsigned char *data, gensiods *ipos, gensiods len,
		 uint16_t tnc_port, struct gensio_ax25_addr *addr)
{
    int rv;

    addr->tnc_port = tnc_port;
    addr->r.funcs = &ax25_addr_funcs;
    addr->o = o;
    rv = decode_ax25_subaddr(data, ipos, len, &addr->dest);
    if (rv)
	return rv;
    rv = decode_ax25_subaddr(data, ipos, len, &addr->src);
    addr->nr_extra = 0;
    if (rv == GE_REMCLOSE)
	return 0;
    if (rv)
	return rv;
    do {
	if (addr->nr_extra >= GENSIO_AX25_ADDR_MAX_EXTRA)
	    return GE_INVAL;
	rv = decode_ax25_subaddr(data, ipos, len,
				 &(addr->extra[addr->nr_extra]));
	if (rv == GE_INVAL)
	    return rv;
	addr->nr_extra++;
    } while (rv == 0);

    return 0;
}

unsigned int
ax25_addr_encode_len(struct gensio_addr *iaddr)
{
    struct gensio_ax25_addr *addr = addr_to_ax25(iaddr);

    assert(addr->nr_extra <= GENSIO_AX25_ADDR_MAX_EXTRA);
    return 7 * (2 + addr->nr_extra);
}

static void
encode_ax25_subaddr(unsigned char *data, struct gensio_ax25_subaddr *addr)
{
    unsigned int i;

    for (i = 0; i < 6; i++) {
	if (!addr->addr[i])
	    break;
	data[i] = addr->addr[i] << 1;
    }
    for (; i < 6; i++) /* Fill the end with spaces. */
	data[i] = ' ' << 1;
    data[i] = (addr->ssid << 1) | addr->ch << 7;
}

unsigned int
ax25_addr_encode(unsigned char *buf, struct gensio_addr *iaddr)
{
    struct gensio_ax25_addr *addr = addr_to_ax25(iaddr);
    unsigned int len, i;

    assert(addr->r.funcs == &ax25_addr_funcs);
    assert(addr->nr_extra <= GENSIO_AX25_ADDR_MAX_EXTRA);

    encode_ax25_subaddr(buf, &addr->dest);
    encode_ax25_subaddr(buf + 7, &addr->src);
    len = 14;
    for (i = 0; i < addr->nr_extra; i++) {
	encode_ax25_subaddr(buf + len, &addr->extra[i]);
	len += 7;
    }

    buf[len - 1] |= 1; /* Mark the end of the address. */

    return len;
}
