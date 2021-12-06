/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <string.h>
#include <arpa/inet.h>
#include <gensio/gensio.h>
#include <gensio/mdns_parse.h>

static uint16_t
get_u16(unsigned char *buf)
{
    return (buf[0] << 8) | buf[1];
}

static uint32_t
get_u32(unsigned char *buf)
{
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}

static int
mdns_parse_header(unsigned char *buf, gensiods *pos,
		  gensiods len, struct mdns_header *h)
{
    unsigned char *p = buf + *pos;

    if (*pos + len < 12)
	return GE_OUTOFRANGE;

    h->id = get_u16(p + 0);
    h->flags = get_u16(p + 2);
    h->nr_queries = get_u16(p + 4);
    h->nr_answers = get_u16(p + 6);
    h->nr_ns = get_u16(p + 8);
    h->nr_ar = get_u16(p + 10);
    *pos += 12;

    return 0;
}

static int
mdns_name_elems(unsigned char *buf, gensiods *pos,
		gensiods len, gensiods *op)
{
    unsigned char *p;
    gensiods ip, offset; /* input position, output position */
    unsigned int size;
    int rv;

    if (*pos >= len)
	return GE_OUTOFRANGE;

    ip = *pos;
    p = buf + ip;
    while (*p) {
	size = *p;
	if ((size & 0xc0) != 0) {
	    /* It's a pointer, */
	    if ((size & 0xc0) != 0xc0)
		/* Other combinations are not valid. */
		return GE_INVAL;
	    if (ip + 1 >= len)
		return GE_OUTOFRANGE;
	    offset = get_u16(p) & 0x3fff;
	    if (offset >= *pos) /* We can only refer backwards. */
		return GE_INVAL;
	    rv = mdns_name_elems(buf, &offset, len, op);
	    if (rv)
		return rv;
	    ip += 2;
	    p += 2;
	    break;
	} else {
	    ip++;
	    p++;
	    /*
	     * We do >= here because another byte must follow this for the
	     * next size.
	     */
	    if (size + ip >= len)
		return GE_OUTOFRANGE;
	    ip += size;
	    p += size;
	    (*op)++;
	}
    }
    return 0;
}

static void
mdns_free_name(struct gensio_os_funcs *o, struct mdns_name *s)
{
    unsigned int i = 0;

    if (s->strs) {
	for (i = 0; s->strs[i]; i++)
	    gensio_os_funcs_zfree(o, (char *) (s->strs[i]));
	gensio_os_funcs_zfree(o, s->strs);
    }
    if (s->pos) {
	gensio_os_funcs_zfree(o, s->pos);
    }
}

static int
mdns_name(struct gensio_os_funcs *o, unsigned char *buf,
	  gensiods *pos, gensiods *op, const char **name, unsigned int *posoff)
{
    unsigned char *p;
    unsigned int size;
    gensiods offset;
    int rv;

    p = buf + *pos;
    while (*p) {
	size = *p;
	if ((size & 0xc0) != 0) {
	    /* It's a pointer, */
	    offset = get_u16(p) & 0x3fff;
	    rv = mdns_name(o, buf, &offset, op, name, NULL);
	    if (rv)
		return rv;
	    p += 2;
	    *pos += 1;
	    break;
	} else {
	    p++;
	    if (posoff)
		posoff[*op] = *pos;
	    *pos += 1;
	    name[*op] = gensio_os_funcs_zalloc(o, size + 1);
	    if (!name[*op])
		return GE_NOMEM;
	    memcpy((char *) (name[*op]), p, size);
	    p += size;
	    (*op)++;
	    *pos += size;
	}
    }
    *pos += 1;
    return 0;
}

static int
mdns_parse_name(struct gensio_os_funcs *o,
		unsigned char *buf, gensiods *pos,
		gensiods len, struct mdns_name *name)
{
    gensiods op = 0;
    struct mdns_name s;
    int rv;

    rv = mdns_name_elems(buf, pos, len, &op);
    if (rv)
	return rv;
    s.strs = gensio_os_funcs_zalloc(o, (op + 1) * sizeof(char *));
    if (!s.strs)
	return GE_NOMEM;
    s.pos = gensio_os_funcs_zalloc(o, op * sizeof(unsigned int));
    if (!s.pos) {
	mdns_free_name(o, &s);
	return GE_NOMEM;
    }
    op = 0;
    rv = mdns_name(o, buf, pos, &op, s.strs, s.pos);
    if (rv) {
	mdns_free_name(o, &s);
	return rv;
    }
    name->nstrs = op;
    name->strs = s.strs;
    name->pos = s.pos;
    return 0;
}

static int
mdns_parse_query(struct gensio_os_funcs *o,
		 unsigned char *buf, gensiods *pos,
		 gensiods len, struct mdns_query **rq)
{
    unsigned char *p;
    struct mdns_query *q;
    int rv;

    q = gensio_os_funcs_zalloc(o, sizeof(*q));
    if (!q)
	return GE_NOMEM;

    rv = mdns_parse_name(o, buf, pos, len, &q->name);
    if (rv) {
	gensio_os_funcs_zfree(o, q);
	return rv;
    }
    if (*pos + 4 > len) {
	mdns_free_name(o, &q->name);
	gensio_os_funcs_zfree(o, q);
	return GE_OUTOFRANGE;
    }
    p = buf + *pos;
    q->type = get_u16(p + 0);
    q->class = get_u16(p + 2);
    *pos += 4;
    *rq = q;

    return 0;
}

static void
mdns_free_query(struct gensio_os_funcs *o, struct mdns_query *q)
{
    if (!q)
	return;
    mdns_free_name(o, &q->name);
    gensio_os_funcs_zfree(o, q);
}

static void
mdns_free_rr(struct gensio_os_funcs *o, struct mdns_rr *r)
{
    unsigned int i;

    if (!r)
	return;

    switch (r->type) {
    case DNS_RR_TYPE_A:
    case DNS_RR_TYPE_AAAA:
	break;

    case DNS_RR_TYPE_PTR:
	mdns_free_name(o, &r->ptr.name);
	break;

    case DNS_RR_TYPE_TXT:
	if (r->txt.items) {
	    for (i = 0; r->txt.items[i]; i++)
		gensio_os_funcs_zfree(o, r->txt.items[i]);
	    gensio_os_funcs_zfree(o, r->txt.items);
	}
	break;

    case DNS_RR_TYPE_SRV:
	mdns_free_name(o, &r->srv.name);
	break;

    default:
	break;
    }
    if (r->rdata)
	gensio_os_funcs_zfree(o, r->rdata);
    mdns_free_name(o, &r->name);
    gensio_os_funcs_zfree(o, r);
}

static int
mdns_parse_txt(struct gensio_os_funcs *o,
	       unsigned char *buf, gensiods *pos,
	       gensiods len, struct mdns_rr_txt *v)
{
    gensiods ip = *pos;
    unsigned int size, count = 0;
    char **items;

    while (ip < len) {
	size = buf[ip++];
	if (size + ip > len)
	    return GE_OUTOFRANGE;
	count++;
	ip += size;
    }
    items = gensio_os_funcs_zalloc(o, sizeof(*items) * (count + 1));
    if (!items)
	return GE_NOMEM;
    count = 0;
    ip = *pos;
    while (ip < len) {
	size = buf[ip++];
	items[count] = gensio_os_funcs_zalloc(o, size + 1);
	if (!items[count]) {
	    while (count > 0)
		gensio_os_funcs_zfree(o, items[--count]);
	    gensio_os_funcs_zfree(o, items);
	    return GE_NOMEM;
	}
	memcpy(items[count], buf + ip, size);
	count++;
	ip += size;
    }
    v->items = items;
    return 0;
}

static int
mdns_parse_rr(struct gensio_os_funcs *o,
	      unsigned char *buf, gensiods *pos,
	      gensiods len, struct mdns_rr **rr)
{
    unsigned char *p;
    struct mdns_rr *r;
    int rv;
    gensiods ip;

    r = gensio_os_funcs_zalloc(o, sizeof(*r));
    if (!r)
	return GE_NOMEM;

    rv = mdns_parse_name(o, buf, pos, len, &r->name);
    if (rv)
	goto out_err;
    rv = GE_OUTOFRANGE;
    if (*pos + 10 > len)
	goto out_err;
    p = buf + *pos;
    r->type = get_u16(p + 0);
    r->class = get_u16(p + 2);
    r->ttl = get_u32(p + 4);
    r->rdata_len = get_u16(p + 8);
    *pos += 10;
    if (*pos + r->rdata_len > len)
	goto out_err;

    p = buf + *pos;
    r->rdata = gensio_os_funcs_zalloc(o, r->rdata_len);
    if (!r->rdata) {
	rv = GE_NOMEM;
	goto out_err;
    }
    memcpy(r->rdata, p, r->rdata_len);

    ip = *pos;
    rv = GE_INVAL;
    switch (r->type) {
    case DNS_RR_TYPE_A:
	if (r->rdata_len < 4)
	    goto out_err;
	memcpy(r->a.addr, p, 4);
	break;

    case DNS_RR_TYPE_PTR:
	rv = mdns_parse_name(o, buf, &ip, ip + r->rdata_len, &r->ptr.name);
	if (rv)
	    goto out_err;
	break;

    case DNS_RR_TYPE_TXT:
	rv = mdns_parse_txt(o, buf, &ip, ip + r->rdata_len, &r->txt);
	if (rv)
	    goto out_err;
	break;

    case DNS_RR_TYPE_AAAA:
	if (r->rdata_len < 16)
	    goto out_err;
	memcpy(r->a.addr, p, 16);
	break;

    case DNS_RR_TYPE_SRV:
	if (r->rdata_len < 7)
	    goto out_err;
	r->srv.priority = get_u16(p + 0);
	r->srv.weight = get_u16(p + 2);
	r->srv.port = get_u16(p + 4);
	ip += 6;
	rv = mdns_parse_name(o, buf, &ip, ip + r->rdata_len - 6,
			     &r->srv.name);
	if (rv)
	    goto out_err;
	break;
    }
    *pos += r->rdata_len;
    *rr = r;

    return 0;

 out_err:
    mdns_free_rr(o, r);
    return rv;
}

void
mdns_free_msg(struct mdns_msg *m)
{
    struct gensio_os_funcs *o = m->o;
    unsigned int i;

    if (m->queries) {
	for (i = 0; i < m->h.nr_queries; i++)
	    mdns_free_query(o, m->queries[i]);
	gensio_os_funcs_zfree(o, m->queries);
    }
    if (m->answers) {
	for (i = 0; i < m->h.nr_answers; i++)
	    mdns_free_rr(o, m->answers[i]);
	gensio_os_funcs_zfree(o, m->answers);
    }
    if (m->ns) {
	for (i = 0; i < m->h.nr_ns; i++)
	    mdns_free_rr(o, m->ns[i]);
	gensio_os_funcs_zfree(o, m->ns);
    }
    if (m->ar) {
	for (i = 0; i < m->h.nr_ar; i++)
	    mdns_free_rr(o, m->ar[i]);
	gensio_os_funcs_zfree(o, m->ar);
    }
    gensio_os_funcs_zfree(o, m);
}

static int
mdns_alloc_data(struct gensio_os_funcs *o, struct mdns_msg *m)
{
    if (m->query_len) {
	m->queries = gensio_os_funcs_zalloc(o, m->query_len *
					    sizeof(struct mdns_query *));
	if (!m->queries)
	    return GE_NOMEM;
    }
    if (m->answer_len) {
	m->answers = gensio_os_funcs_zalloc(o, m->answer_len *
					    sizeof(struct mdns_rr *));
	if (!m->answers)
	    return GE_NOMEM;
    }
    if (m->ns_len) {
	m->ns = gensio_os_funcs_zalloc(o, m->ns_len *
				       sizeof(struct mdns_rr *));
	if (!m->ns)
	    return GE_NOMEM;
    }
    if (m->ar_len) {
	m->ar = gensio_os_funcs_zalloc(o, m->ar_len *
				       sizeof(struct mdns_rr *));
	if (!m->ar)
	    return GE_NOMEM;
    }

    return 0;
}

int
mdns_parse_msg(struct gensio_os_funcs *o,
	       unsigned char *buf, gensiods len,
	       struct mdns_msg **rmsg)
{
    struct mdns_msg *m;
    gensiods pos = 0;
    int rv;
    unsigned int i;

    m = gensio_os_funcs_zalloc(o, sizeof(*m));
    if (!m)
	return GE_NOMEM;
    m->o = o;

    rv = mdns_parse_header(buf, &pos, len, &m->h);
    if (rv)
	goto out_err;
    m->query_len = m->h.nr_queries;
    m->answer_len = m->h.nr_answers;
    m->ns_len = m->h.nr_ns;
    m->ar_len = m->h.nr_ar;
    rv = mdns_alloc_data(o, m);
    if (rv)
	goto out_err;
    for (i = 0; i < m->h.nr_queries; i++) {
	rv = mdns_parse_query(o, buf, &pos, len, &(m->queries[i]));
	if (rv)
	    goto out_err;
    }
    for (i = 0; i < m->h.nr_answers; i++) {
	rv = mdns_parse_rr(o, buf, &pos, len, &(m->answers[i]));
	if (rv)
	    goto out_err;
    }
    for (i = 0; i < m->h.nr_ns; i++) {
	rv = mdns_parse_rr(o, buf, &pos, len, &(m->ns[i]));
	if (rv)
	    goto out_err;
    }
    for (i = 0; i < m->h.nr_ar; i++) {
	rv = mdns_parse_rr(o, buf, &pos, len, &(m->ar[i]));
	if (rv)
	    goto out_err;
    }
    *rmsg = m;
    return 0;

 out_err:
    mdns_free_msg(m);
    return rv;
}

struct mdns_msg *
mdns_alloc_msg(struct gensio_os_funcs *o, uint16_t id, uint16_t flags,
	       unsigned int max_size)
{
    struct mdns_msg *m;

    if (max_size && max_size < 12)
	return NULL;

    m = gensio_os_funcs_zalloc(o, sizeof(*m));
    if (!m)
	return NULL;

    m->o = o;
    m->max_size = max_size;
    m->h.id = id;
    m->h.flags = flags;

    return m;
}

static int
dup_mdns_name(struct gensio_os_funcs *o, const struct mdns_name *src,
	      struct mdns_name *dest)
{
    unsigned int i;
    const char **nstr;
    unsigned int *pos;

    for (i = 0; i < src->nstrs; i++) {
	if (strlen(src->strs[i]) >= 64)
	    return GE_INVAL;
    }
    nstr = gensio_os_funcs_zalloc(o, (src->nstrs + 1) * sizeof(char *));
    if (!nstr)
	return GE_NOMEM;
    pos = gensio_os_funcs_zalloc(o, src->nstrs * sizeof(unsigned int));
    if (!pos) {
	gensio_os_funcs_zfree(o, nstr);
	return GE_NOMEM;
    }
    for (i = 0; i < src->nstrs; i++) {
	nstr[i] = gensio_strdup(o, src->strs[i]);
	if (!nstr[i]) {
	    while (i > 0)
		gensio_os_funcs_zfree(o, (char *) (nstr[--i]));
	    gensio_os_funcs_zfree(o, nstr);
	    gensio_os_funcs_zfree(o, pos);
	    return GE_NOMEM;
	}
    }
    dest->strs = nstr;
    dest->pos = pos;
    dest->nstrs = src->nstrs;;
    return 0;
}

static void
put_u16(uint16_t v, unsigned char *buf, unsigned int buflen,
	unsigned int *pos)
{
    if (*pos + 2 <= buflen) {
	buf[*pos] = v >> 8;
	buf[(*pos) + 1] = v & 0xff;
    }
    *pos += 2;
}

static void
put_u32(uint32_t v, unsigned char *buf, unsigned int buflen,
	unsigned int *pos)
{
    if (*pos + 4 <= buflen) {
	buf[*pos] = v >> 24;
	buf[(*pos) + 1] = (v >> 16) & 0xff;
	buf[(*pos) + 2] = (v >> 8) & 0xff;
	buf[(*pos) + 3] = v & 0xff;
    }
    *pos += 4;
}

static void
put_bytes(unsigned char *b, unsigned int len,
	  unsigned char *buf, unsigned int buflen, unsigned int *pos)
{
    if (*pos + len <= buflen)
	memcpy(buf + *pos, b, len);
    *pos += len;
}

/*
 * Returns 0 if not found, 1 if found, -1 if we are past where we can
 * search.
 */
static int
find_substr_in_name(struct mdns_name *n, const char **strs,
		    unsigned int *substr)
{
    unsigned int i, j;

    if (n->pos[0] == 0)
	return -1;
    for (i = 0; n->strs[i]; i++) {
	for (j = 0; n->strs[i + j] && strs[j]; j++) {
	    if (strcmp(n->strs[i + j], strs[j]) != 0)
		goto next;
	}
	/* Found one. */
	*substr = n->pos[i];
	return 1;
    next:
	continue;
    }
    return 0;
}

static int
find_substr_in_rr(struct mdns_rr *r, const char **strs, unsigned int *substr)
{
    int rv;

    rv = find_substr_in_name(&r->name, strs, substr);
    if (rv)
	return rv;
    switch(r->type) {
    case DNS_RR_TYPE_A:
    case DNS_RR_TYPE_AAAA:
    case DNS_RR_TYPE_TXT:
    default:
	break;

    case DNS_RR_TYPE_PTR:
	rv = find_substr_in_name(&r->ptr.name, strs, substr);
	if (rv)
	    return rv;
	break;

    case DNS_RR_TYPE_SRV:
	rv = find_substr_in_name(&r->srv.name, strs, substr);
	if (rv)
	    return rv;
	break;
    }

    return 0;
}

static bool
find_substr(struct mdns_msg *m, const char **strs, unsigned int *substr)
{
    unsigned int i;
    int rv;

    for (i = 0; i < m->h.nr_queries; i++) {
	rv = find_substr_in_name(&m->queries[i]->name, strs, substr);
	if (rv < 0)
	    return false;
	else if (rv > 0)
	    return true;
    }
    for (i = 0; i < m->h.nr_answers; i++) {
	rv = find_substr_in_rr(m->answers[i], strs, substr);
	if (rv < 0)
	    return false;
	else if (rv > 0)
	    return true;
    }
    for (i = 0; i < m->h.nr_ns; i++) {
	rv = find_substr_in_rr(m->ns[i], strs, substr);
	if (rv < 0)
	    return false;
	else if (rv > 0)
	    return true;
    }
    for (i = 0; i < m->h.nr_ar; i++) {
	rv = find_substr_in_rr(m->ar[i], strs, substr);
	if (rv < 0)
	    return false;
	else if (rv > 0)
	    return true;
    }

    return false;
}

static int
mdns_output_name(struct mdns_msg *m,
		 struct mdns_name *n, unsigned char *buf, unsigned int buflen,
		 unsigned int *pos)
{
    unsigned int len, i, j, substr = 0;
    bool do_compress = !(m->ctrls & MDNS_MSG_CTRL_NOCOMPRESS);

    /*
     * Set the positions to zero so when we run into this name in
     * find_substr we know to abort.
     */
    for (j = 0; j < n->nstrs; j++) {
	n->pos[j] = 0;
    }

    /*
     * Compare the whole name, then remove the first element, then the
     * second element, etc, looking for a match.
     */
    for (j = 0; do_compress && j < n->nstrs; j++) {
	if (find_substr(m, n->strs + j, &substr))
	    break;
    }
    if (substr > 0x3fff)
	/* We can only reference the first part of a message. */
	substr = 0;

    /* Now output all the strings we didn't compress. */
    for (i = 0; i < j; i++) {
	len = strlen(n->strs[i]);
	if (len >= 64)
	    return GE_INVAL;
	if (*pos + len + 1 <= buflen) {
	    buf[*pos] = len;
	    memcpy(buf + *pos + 1, n->strs[i], len);
	}
	n->pos[i] = *pos;
	*pos += len + 1;
    }
    /* Output either the compress information or the final '0'. */
    if (substr) {
	put_u16(0xc000 | substr, buf, buflen, pos);
    } else {
	if (*pos + 1 <= buflen)
	    buf[*pos] = 0; /* End marker. */
	*pos += 1;
    }
    return 0;
}

static int
mdns_output_query(struct mdns_msg *m,
		  struct mdns_query *q, unsigned char *buf, unsigned int buflen,
		  unsigned int *pos)
{
    int rv;

    rv = mdns_output_name(m, &q->name, buf, buflen, pos);
    if (rv)
	return rv;
    put_u16(q->type, buf, buflen, pos);
    put_u16(q->class, buf, buflen, pos);
    return 0;
}

static int
mdns_output_txt(char **elems, unsigned char *buf, unsigned int buflen,
		unsigned int *pos)
{
    unsigned int i;

    for (i = 0; elems[i]; i++) {
	unsigned int len = strlen(elems[i]);

	if (len > 255)
	    return GE_INVAL;
	if (*pos + len + 1 <= buflen) {
	    buf[*pos] = len;
	    memcpy(buf + *pos + 1, elems[i], len);
	}
	*pos += len + 1;
    }

    return 0;
}

static int
mdns_output_rr(struct mdns_msg *m,
	       struct mdns_rr *r, unsigned char *buf, unsigned int buflen,
	       unsigned int *pos)
{
    unsigned int rdata_len_pos;
    int rv;

    rv = mdns_output_name(m, &r->name, buf, buflen, pos);
    if (rv)
	return rv;
    put_u16(r->type, buf, buflen, pos);
    put_u16(r->class, buf, buflen, pos);
    put_u32(r->ttl, buf, buflen, pos);
    rdata_len_pos = *pos;
    put_u16(0, buf, buflen, pos); /* Well fix this up later. */
    switch (r->type) {
    case DNS_RR_TYPE_A:
	put_bytes(r->a.addr, 4, buf, buflen, pos);
	break;

    case DNS_RR_TYPE_PTR:
	rv = mdns_output_name(m, &r->ptr.name, buf, buflen, pos);
	if (rv)
	    return rv;
	break;

    case DNS_RR_TYPE_TXT:
	rv = mdns_output_txt(r->txt.items, buf, buflen, pos);
	if (rv)
	    return rv;
	break;

    case DNS_RR_TYPE_AAAA:
	put_bytes(r->aaaa.addr, 16, buf, buflen, pos);
	break;

    case DNS_RR_TYPE_SRV:
	put_u16(r->srv.priority, buf, buflen, pos);
	put_u16(r->srv.weight, buf, buflen, pos);
	put_u16(r->srv.port, buf, buflen, pos);
	rv = mdns_output_name(m, &r->srv.name, buf, buflen, pos);
	if (rv)
	    return rv;
	break;

    default:
	return GE_INVAL;
    }

    put_u16(*pos - rdata_len_pos - 2, buf, buflen, &rdata_len_pos);
    return 0;
}

int
mdns_output(struct mdns_msg *m,
	    unsigned char *buf, unsigned int buflen, unsigned int *pos)
{
    unsigned int i;
    int rv;

    put_u16(m->h.id, buf, buflen, pos);
    put_u16(m->h.flags, buf, buflen, pos);
    put_u16(m->h.nr_queries, buf, buflen, pos);
    put_u16(m->h.nr_answers, buf, buflen, pos);
    put_u16(m->h.nr_ns, buf, buflen, pos);
    put_u16(m->h.nr_ar, buf, buflen, pos);
    for (i = 0; i < m->h.nr_queries; i++) {
	rv = mdns_output_query(m, m->queries[i], buf, buflen, pos);
	if (rv)
	    return rv;
    }
    for (i = 0; i < m->h.nr_answers; i++) {
	rv = mdns_output_rr(m, m->answers[i], buf, buflen, pos);
	if (rv)
	    return rv;
    }
    for (i = 0; i < m->h.nr_ns; i++) {
	rv = mdns_output_rr(m, m->ns[i], buf, buflen, pos);
	if (rv)
	    return rv;
    }
    for (i = 0; i < m->h.nr_ar; i++) {
	rv = mdns_output_rr(m, m->ar[i], buf, buflen, pos);
	if (rv)
	    return rv;
    }
    return 0;
}

int
mdns_add_query(struct mdns_msg *m, const struct mdns_name *name,
	       uint16_t type, uint16_t class)
{
    struct gensio_os_funcs *o = m->o;
    struct mdns_query *q;
    unsigned int size = 0;
    int rv;

    if (m->h.nr_answers || m->h.nr_ns || m->h.nr_ar)
	return GE_NOTREADY; /* Have to add fields in order. */

    if (m->h.nr_queries >= m->query_len) {
	struct mdns_query **new_set;

	new_set = gensio_os_funcs_zalloc(o, ((m->query_len + 10) *
					     sizeof(struct mdns_query *)));
	if (!new_set)
	    return GE_NOMEM;
	if (m->queries) {
	    memcpy(new_set, m->queries,
		   m->query_len * sizeof(struct mdns_query *));
	    gensio_os_funcs_zfree(o, m->queries);
	}
	m->queries = new_set;
	m->query_len += 10;
    }
    q = gensio_os_funcs_zalloc(o, sizeof(*q));
    if (!q)
	return GE_NOMEM;
    q->type = type;
    q->class = class;
    rv = dup_mdns_name(o, name, &q->name);
    if (rv)
	goto out_err;

    rv = mdns_output_query(m, q, NULL, 0, &size);
    if (rv)
	goto out_err;
    if (m->max_size && (m->curr_size + size > m->max_size)) {
	rv = GE_OUTOFRANGE;
	goto out_err;
    }
    m->curr_size += size;

    m->queries[(m->h.nr_queries)++] = q;
    return 0;

 out_err:
    mdns_free_query(o, q);
    return rv;
}

static int
mdns_alloc_rr(struct gensio_os_funcs *o, const struct mdns_name *name,
	      uint16_t type, uint16_t class, uint32_t ttl,
	      struct mdns_rr **rr)
{
    struct mdns_rr *r;
    int rv;

    r = gensio_os_funcs_zalloc(o, sizeof(*r));
    if (!r)
	return GE_NOMEM;
    r->type = type;
    r->class = class;
    r->ttl = ttl;
    rv = dup_mdns_name(o, name, &r->name);
    if (rv) {
	mdns_free_rr(o, r);
	return rv;
    }
    *rr = r;
    return 0;
}

static int
extend_rr(struct gensio_os_funcs *o,
	  uint16_t *len, unsigned int *nitems, struct mdns_rr ***items,
	  struct mdns_rr *r)
{
    if (*len >= *nitems) {
	struct mdns_rr **newset;

	newset = gensio_os_funcs_zalloc(o, ((*nitems + 10) *
					    sizeof(struct mdns_rr *)));
	if (!newset) {
	    mdns_free_rr(o, r);
	    return GE_NOMEM;
	}
	if (*items) {
	    memcpy(newset, *items, *len * sizeof(struct mdns_rr *));
	    gensio_os_funcs_zfree(o, *items);
	}
	*nitems += 10;
	*items = newset;
    }
    (*items)[(*len)++] = r;
    return 0;
}

static int
mdns_add_rr(struct gensio_os_funcs *o,
	    struct mdns_msg *m, enum mdns_rr_location where,
	    struct mdns_rr *r)
{
    unsigned int size = 0;
    int rv;

    rv = mdns_output_rr(m, r, NULL, 0, &size);
    if (rv) {
	mdns_free_rr(o, r);
	return rv;
    }
    if (m->max_size && (m->curr_size + size > m->max_size)) {
	mdns_free_rr(o, r);
	return GE_OUTOFRANGE;
    }
    m->curr_size += size;

    switch (where) {
    case MDNS_RR_ANSWER:
	if (m->h.nr_ns || m->h.nr_ar)
	    goto out_not_ready;
	return extend_rr(o, &m->h.nr_answers, &m->answer_len, &m->answers, r);

    case MDNS_RR_NS:
	if (m->h.nr_ar)
	    goto out_not_ready;
	return extend_rr(o, &m->h.nr_ns, &m->ns_len, &m->ns, r);

    case MDNS_RR_AR:
	return extend_rr(o, &m->h.nr_ar, &m->ar_len, &m->ar, r);

    default:
	return GE_INVAL;
    }

 out_not_ready:
    mdns_free_rr(o, r);
    return GE_NOTREADY; /* Have to add fields in order. */
}

int
mdns_add_rr_a(struct mdns_msg *m,
	      enum mdns_rr_location where, const struct mdns_name *name,
	      uint16_t class, uint32_t ttl, unsigned char *ipv4_addr)
{
    struct gensio_os_funcs *o = m->o;
    struct mdns_rr *r;
    int rv;

    rv = mdns_alloc_rr(o, name, DNS_RR_TYPE_A, class, ttl, &r);
    if (rv)
	return rv;
    memcpy(r->a.addr, ipv4_addr, 4);
    return mdns_add_rr(o, m, where, r);
}

int
mdns_add_rr_aaaa(struct mdns_msg *m,
		 enum mdns_rr_location where, const struct mdns_name *name,
		 uint16_t class, uint32_t ttl, unsigned char *ipv6_addr)
{
    struct gensio_os_funcs *o = m->o;
    struct mdns_rr *r;
    int rv;

    rv = mdns_alloc_rr(o, name, DNS_RR_TYPE_AAAA, class, ttl, &r);
    if (rv)
	return rv;
    memcpy(r->aaaa.addr, ipv6_addr, 16);
    return mdns_add_rr(o, m, where, r);
}

int
mdns_add_rr_ptr(struct mdns_msg *m,
		enum mdns_rr_location where, const struct mdns_name *name,
		uint16_t class, uint32_t ttl, const struct mdns_name *subname)
{
    struct gensio_os_funcs *o = m->o;
    struct mdns_rr *r;
    int rv;

    rv = mdns_alloc_rr(o, name, DNS_RR_TYPE_PTR, class, ttl, &r);
    if (rv)
	return rv;
    rv = dup_mdns_name(o, subname, &r->ptr.name);
    if (rv) {
	mdns_free_rr(o, r);
	return rv;
    }
    return mdns_add_rr(o, m, where, r);
}

int
mdns_add_rr_srv(struct mdns_msg *m,
		enum mdns_rr_location where, const struct mdns_name *name,
		uint16_t class, uint32_t ttl,
		uint16_t priority, uint16_t weight, uint16_t port,
		const struct mdns_name *subname)
{
    struct gensio_os_funcs *o = m->o;
    struct mdns_rr *r;
    int rv;

    rv = mdns_alloc_rr(o, name, DNS_RR_TYPE_SRV, class, ttl, &r);
    if (rv)
	return rv;
    r->srv.priority = priority;
    r->srv.weight = weight;
    r->srv.port = port;
    rv = dup_mdns_name(o, subname, &r->srv.name);
    if (rv) {
	mdns_free_rr(o, r);
	return rv;
    }
    return mdns_add_rr(o, m, where, r);
}

int
mdns_add_rr_txt(struct mdns_msg *m,
		enum mdns_rr_location where, const struct mdns_name *name,
		uint16_t class, uint32_t ttl, const char **itxt)
{
    struct gensio_os_funcs *o = m->o;
    struct mdns_rr *r;
    int rv = GE_NOMEM;;
    char **txt;
    unsigned int i;

    for (i = 0; itxt[i]; i++) {
	if (strlen(itxt[i]) > 255)
	    return GE_INVAL;
    }
    if (i == 0)
	return GE_INVAL;
    txt = gensio_os_funcs_zalloc(o, (i + 1) * sizeof(char *));
    if (!txt)
	return GE_NOMEM;
    for (i = 0; itxt[i]; i++) {
	txt[i] = gensio_strdup(o, itxt[i]);
	if (!txt[i])
	    goto out_err;
    }

    rv = mdns_alloc_rr(o, name, DNS_RR_TYPE_TXT, class, ttl, &r);
    if (rv)
	goto out_err;
    r->txt.items = txt;
    return mdns_add_rr(o, m, where, r);

 out_err:
    for (i = 0; txt[i]; i++)
	gensio_os_funcs_zfree(o, txt[i]);
    gensio_os_funcs_zfree(o, txt);
    return rv;
}

#define cmp_int(a, b) \
    do {						\
	if ((a) > (b))					\
	    return 1;					\
	if ((a) < (b))					\
	    return -1;					\
    } while(0)

static int
mdns_cmp_name(struct mdns_name *n1, struct mdns_name *n2)
{
    unsigned int i;
    int rv;

    cmp_int(n1->nstrs, n2->nstrs);
    for (i = 0; i < n1->nstrs; i++) {
	rv = strcmp(n1->strs[i], n2->strs[i]);
	if (rv)
	    return rv;
    }
    return 0;
}

static int
mdns_cmp_query(struct mdns_query *q1, struct mdns_query *q2)
{
    int rv = mdns_cmp_name(&q1->name, &q2->name);

    if (rv)
	return rv;
    cmp_int(q1->type, q2->type);
    cmp_int(q1->class, q2->class);
    return 0;
}

static int
mdns_cmp_rr(struct mdns_rr *r1, struct mdns_rr *r2)
{
    unsigned int i;
    int rv = mdns_cmp_name(&r1->name, &r2->name);

    if (rv)
	return rv;
    cmp_int(r1->type, r2->type);
    cmp_int(r1->class, r2->class);
    cmp_int(r1->ttl, r2->ttl);
    switch(r1->type) {
    case DNS_RR_TYPE_A:
	return memcmp(r1->a.addr, r2->a.addr, 4);

    case DNS_RR_TYPE_AAAA:
	return memcmp(r1->aaaa.addr, r2->aaaa.addr, 16);

    case DNS_RR_TYPE_PTR:
	return mdns_cmp_name(&r1->ptr.name, &r2->ptr.name);

    case DNS_RR_TYPE_SRV:
	cmp_int(r1->srv.priority, r2->srv.priority);
	cmp_int(r1->srv.weight, r2->srv.weight);
	cmp_int(r1->srv.port, r2->srv.port);
	return mdns_cmp_name(&r1->srv.name, &r2->srv.name);

    case DNS_RR_TYPE_TXT:
	for (i = 0; r1->txt.items[i] && r2->txt.items[i]; i++) {
	    rv = strcmp(r1->txt.items[i], r2->txt.items[i]);
	    if (rv)
		return rv;
	}
	if (r1->txt.items[i] > r2->txt.items[i])
	    return 1;
	if (r1->txt.items[i] < r2->txt.items[i])
	    return -1;
	return 0;

    default:
	cmp_int(r1->rdata_len, r2->rdata_len);
	return memcmp(r1->rdata, r2->rdata, r1->rdata_len);
    }
}

int
mdns_cmp(struct mdns_msg *m1, struct mdns_msg *m2)
{
    int rv;
    unsigned int i;

    cmp_int(m1->h.id, m2->h.id);
    cmp_int(m1->h.flags, m2->h.flags);
    cmp_int(m1->h.nr_queries, m2->h.nr_queries);
    cmp_int(m1->h.nr_answers, m2->h.nr_answers);
    cmp_int(m1->h.nr_ns, m2->h.nr_ns);
    cmp_int(m1->h.nr_ar, m2->h.nr_ar);
    for (i = 0; i < m1->h.nr_queries; i++) {
	rv = mdns_cmp_query(m1->queries[i], m2->queries[i]);
	if (rv)
	    return rv;
    }
    for (i = 0; i < m1->h.nr_answers; i++) {
	rv = mdns_cmp_rr(m1->answers[i], m2->answers[i]);
	if (rv)
	    return rv;
    }
    for (i = 0; i < m1->h.nr_ns; i++) {
	rv = mdns_cmp_rr(m1->ns[i], m2->ns[i]);
	if (rv)
	    return rv;
    }
    for (i = 0; i < m1->h.nr_ar; i++) {
	rv = mdns_cmp_rr(m1->ar[i], m2->ar[i]);
	if (rv)
	    return rv;
    }
    return 0;
}

int
mdns_name_cmp(struct mdns_name *n1, struct mdns_name *n2)
{
    unsigned int i;

    for (i = 0; i < n1->nstrs && i < n2->nstrs; i++) {
	int rv = strcmp(n1->strs[i], n2->strs[i]);

	if (rv)
	    return rv;
    }
    if (i < n1->nstrs)
	return 1;
    if (i < n2->nstrs)
	return -1;
    return 0;
}
