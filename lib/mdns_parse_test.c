
#include <stdio.h>
#include <arpa/inet.h>
#include <gensio/gensio.h>
#include <gensio/gensio_osops_env.h>
#include <gensio/mdns_parse.h>

static void
print_mdns_name(FILE *f, struct mdns_name *n)
{
    unsigned int i;
    const char *p;

    if (!n->strs)
	return;
    for (i = 0; n->strs[i]; i++) {
	for (p = n->strs[i]; *p; p++) {
	    if (*p == '.' || *p == '\\')
		fputc('\\', f);
	    fputc(*p, f);
	}
	if (n->strs[i + 1])
	    fputc('.', f);
    }
}

static void
print_mdns_query(FILE *f, struct mdns_query *q)
{
    fprintf(f, "Query (%d, %d): ", q->type, q->class);
    print_mdns_name(f, &q->name);
    fprintf(f, "\n");
}

static void
print_mdns_rr(FILE *f, const char *type, struct mdns_rr *r)
{
    unsigned int i;
    char buf[100];

    fprintf(f, "%s RR (%d, %d, %d): ", type, r->type, r->class, r->ttl);
    print_mdns_name(f, &r->name);
    fprintf(f, "\n");
    if (r->rdata_len) {
	struct gensio_fdump h;

	gensio_fdump_init(&h);
	gensio_fdump_buf(f, r->rdata, r->rdata_len, &h);
	gensio_fdump_buf_finish(f, &h);
    }
    switch (r->type) {
    case DNS_RR_TYPE_A:
	fprintf(f, "  A: %s\n", inet_ntop(AF_INET, r->a.addr, buf, sizeof(buf)));
	break;

    case DNS_RR_TYPE_PTR:
	fprintf(f, "  PTR: ");
	print_mdns_name(f, &r->ptr.name);
	fprintf(f, "\n");
	break;

    case DNS_RR_TYPE_TXT:
	fprintf(f, "  TXT:\n");
	for (i = 0; r->txt.items && r->txt.items[i]; i++)
	    fprintf(f, "    %s\n", r->txt.items[i]);
	break;

    case DNS_RR_TYPE_AAAA:
	fprintf(f, "  AAAA: %s\n", inet_ntop(AF_INET6, r->a.addr,
					 buf, sizeof(buf)));
	break;

    case DNS_RR_TYPE_SRV:
	fprintf(f, "  SRV:\n");
	fprintf(f, "    priority: %u\n", r->srv.priority);
	fprintf(f, "    weight: %u\n", r->srv.weight);
	fprintf(f, "    port: %u\n", r->srv.port);
	fprintf(f, "    name: ");
	print_mdns_name(f, &r->srv.name);
	fprintf(f, "\n");
	break;
    }
}

static void
print_mdns_msg(FILE *f, struct mdns_msg *m)
{
    unsigned int i;

    fprintf(f, "Msg: id=%d, flags=0x%4.4x\n", m->h.id, m->h.flags);
    for (i = 0; i < m->h.nr_queries; i++)
	print_mdns_query(f, m->queries[i]);
    for (i = 0; i < m->h.nr_answers; i++)
	print_mdns_rr(f, "Answer", m->answers[i]);
    for (i = 0; i < m->h.nr_ns; i++)
	print_mdns_rr(f, "NS", m->ns[i]);
    for (i = 0; i < m->h.nr_ar; i++)
	print_mdns_rr(f, "AR", m->ar[i]);
}

static int
check_msg(struct gensio_os_funcs *o, struct mdns_msg *m, const char *name)
{
    unsigned int len, pos;
    unsigned char *buf;
    struct mdns_msg *m2;
    int rv;

    fprintf(stderr, "***Checking %s\n", name);
    len = 0;
    m->curr_size = 0;
    rv = mdns_output(m, NULL, 0, &len);
    if (rv) {
	fprintf(stderr, "Error outputting %s message: %s\n", name,
		gensio_err_to_str(rv));
	return 1;
    }
    buf = gensio_os_funcs_zalloc(o, len);
    pos = 0;
    rv = mdns_output(m, buf, len, &pos);
    if (rv) {
	gensio_os_funcs_zfree(o, buf);
	fprintf(stderr, "Error outputting %s message(2): %s\n", name,
		gensio_err_to_str(rv));
	return 1;
    }
    rv = mdns_parse_msg(o, buf, len, &m2);
    if (rv) {
	gensio_os_funcs_zfree(o, buf);
	fprintf(stderr, "Error parsing %s message(2): %s\n", name,
		gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_zfree(o, buf);

    if (mdns_cmp(m, m2) != 0) {
	fprintf(stderr, "Message compare fail on %s\n", name);
	fprintf(stderr, "Msg1:\n");
	print_mdns_msg(stderr, m);
	fprintf(stderr, "Msg2:\n");
	print_mdns_msg(stderr, m2);
	mdns_free_msg(m2);
	return 1;
    }

    mdns_free_msg(m2);
    return 0;
}

int
main(int argc, char *argv[])
{
    struct gensio_os_funcs *o;
    struct mdns_msg *m;
    int rv;
    const char *names[20];
    struct mdns_name name, name2;
    unsigned char ipaddr[16] = { 0x93, 0x39, 0x45, 0x23,
				 0x43, 0x68, 0x87, 0x22,
				 0x53, 0x68, 0x87, 0x62,
				 0x49, 0x67, 0x89, 0x82};
    const char *txt[4];

    rv = gensio_os_env_set("GENSIO_MEMTRACK", "abort");
    if (rv) {
	fprintf(stderr, "Unable to set GENSIO_MEMTRACK: %s",
		gensio_err_to_str(rv));
	return 1;
    }

    rv = gensio_default_os_hnd(0, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate os funcs: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    m = mdns_alloc_msg(o, 0x1234, 0x8765, 0);
    if (check_msg(o, m, "empty"))
	return 1;

    names[0] = "asdf1";
    names[1] = "test1234";
    names[2] = "local";
    name.strs = names + 2;
    name.nstrs = 1;
    rv = mdns_add_query(m, &name, 0x3874, 0x9432);
    if (rv) {
	fprintf(stderr, "Could not add mdns query: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    if (check_msg(o, m, "query1"))
	return 1;

    name.strs = names + 1;
    name.nstrs = 2;
    rv = mdns_add_query(m, &name, 0x2903, 0x7503);
    if (rv) {
	fprintf(stderr, "Could not add mdns query1: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    if (check_msg(o, m, "query2"))
	return 1;

    name.strs = names;
    name.nstrs = 3;
    rv = mdns_add_query(m, &name, 0x3489, 0x8392);
    if (rv) {
	fprintf(stderr, "Could not add mdns query2: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    if (check_msg(o, m, "query3"))
	return 1;

    names[0] = "Hel.lo";
    names[1] = "Th\\ere";
    names[2] = "local";
    name.strs = names + 1;
    name.nstrs = 2;
    rv = mdns_add_rr_a(m, MDNS_RR_ANSWER, &name, DNS_CLASS_IN, 60, ipaddr);
    if (rv) {
	fprintf(stderr, "Could not add mdns answer1: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    if (check_msg(o, m, "answer1"))
	return 1;

    name.strs = names;
    name.nstrs = 3;
    rv = mdns_add_rr_aaaa(m, MDNS_RR_ANSWER, &name, DNS_CLASS_IN, 100, ipaddr);
    if (rv) {
	fprintf(stderr, "Could not add mdns answer2: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    if (check_msg(o, m, "answer2"))
	return 1;

    names[0] = "A"; names[1] = "B"; names[2] = "C"; names[3] = "D";
    names[4] = "E"; names[5] = "F"; names[6] = "G"; names[7] = "H";
    names[8] = "I"; names[9] = "J";
    names[10] = "K"; names[11] = "L"; names[12] = "M"; names[13] = "N";
    names[14] = "O"; names[15] = "P"; names[16] = "Q"; names[17] = "R";
    names[18] = "S"; names[19] = "T";
    name.strs = names + 10;
    name.nstrs = 10;
    name2.strs = names;
    name2.nstrs = 20;
    rv = mdns_add_rr_ptr(m, MDNS_RR_NS, &name, DNS_CLASS_IN, 200, &name2);
    if (rv) {
	fprintf(stderr, "Could not add mdns ns1: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    if (check_msg(o, m, "ns1"))
	return 1;

    name.strs = names + 13;
    name.nstrs = 7;
    name2.strs = names + 7;
    name2.nstrs = 13;
    rv = mdns_add_rr_srv(m, MDNS_RR_AR, &name,
			 DNS_CLASS_IN, 99, 0x8934, 0x8229, 0x7483, &name2);
    if (rv) {
	fprintf(stderr, "Could not add mdns ar1: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    if (check_msg(o, m, "ar1"))
	return 1;

    txt[0] = "jsdlfsldfjks";
    txt[1] = "90asdfjasdf;js";
    txt[2] = "w90ee [s9.90324\\asd";
    txt[3] = NULL;
    name.strs = names + 13;
    name.nstrs = 7;
    rv = mdns_add_rr_txt(m, MDNS_RR_AR, &name, DNS_CLASS_IN, 99, txt);
    if (rv) {
	fprintf(stderr, "Could not add mdns ar2: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    if (check_msg(o, m, "ar2"))
	return 1;

    mdns_free_msg(m);

    gensio_cleanup_mem(o);
    gensio_os_funcs_free(o);
    return 0;
}
