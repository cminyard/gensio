/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

#include <gensio/gensio.h>
#include <gensio/gensio_list.h>
#include <gensio/gensio_ax25_addr.h>

#define AGWPE_TOO_SMALL		1

#define AGWPE_HEADER_SIZE	36
#define AGWPE_MAX_MSG_SIZE	(2048 + AGWPE_HEADER_SIZE)

struct agwpe_packet {
    uint8_t port;
    char kind;
    uint8_t pid;
    char callfrom[10];
    char callto[10];
    uint32_t len;
    uint32_t user;
    unsigned char *data;
};

static uint32_t
agwpe_fetch32(unsigned char *data)

{
    return data[0] | data[1] << 8 | data[2] << 16 | data[3] << 24;
}

static void
agwpe_set32(unsigned char *data, uint32_t val)

{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
    data[2] = (val >> 16) & 0xff;
    data[3] = (val >> 24) & 0xff;
}

static void
agwpe_fix_call(char *call)
{
    call[9] = '\0';
    while (*call) {
	*call = toupper(*call);
	call++;
    }
}

int
agwpe_decode_packet(unsigned char *data, gensiods len,
		    struct agwpe_packet *packet)
{
    if (len < AGWPE_HEADER_SIZE)
	return GE_TOOBIG;
    packet->port = data[0];
    packet->kind = data[4];
    packet->pid = data[6];
    memcpy(packet->callfrom, data + 8, 10);
    agwpe_fix_call(packet->callfrom);
    memcpy(packet->callto, data + 18, 10);
    agwpe_fix_call(packet->callto);
    packet->len = agwpe_fetch32(data + 28);
    packet->user = agwpe_fetch32(data + 32);
    packet->data = data + 36;
    return 0;
}

int
agwpe_encode_packet2(unsigned char *data, gensiods len,
		     struct agwpe_packet *packet, gensiods *outlen,
		     unsigned char *extra, unsigned int extra_len)
{
    if (len < AGWPE_HEADER_SIZE + packet->len)
	return GE_TOOBIG;
    data[0] = packet->port;
    data[4] = packet->kind;
    data[6] = packet->pid;
    memcpy(data + 8, packet->callfrom, 10);
    memcpy(data + 18, packet->callto, 10);
    agwpe_set32(data + 32, packet->user);
    memcpy(data + 36, packet->data, packet->len);
    if (extra) {
	packet->data = data + 36;
	memcpy(packet->data + packet->len, extra, extra_len);
	packet->len += extra_len;
    }
    agwpe_set32(data + 28, packet->len);
    *outlen = AGWPE_HEADER_SIZE + packet->len;
    return 0;
}

int
agwpe_encode_packet(unsigned char *data, gensiods len,
		    struct agwpe_packet *packet, gensiods *outlen)
{
    return agwpe_encode_packet2(data, len, packet, outlen, NULL, 0);
}

struct ax25_reg_addr {
    struct gensio_link link;
    char addr[10];
};
#define to_reg_addr(l) gensio_container_of(l, struct ax25_reg_addr, link)

struct agwpe_inst;

struct agwpe_ax25_conn {
    struct gensio_link link;
    struct gensio_link xmit_link;
    bool in_xmit;
    bool in_close;
    bool report_open;
    bool was_connection; /* true if we initiated the connection. */
    bool report_close;
    bool timeout; /* Report timeout or disconnect close. */
    bool flow_controlled; /* We have stopped net recv data. */
    int err;
    bool free_on_send; /* Free the connection after the last send. */

    struct agwpe_inst *inst;

    struct gensio *ax25_io;

    char local_addr[10];
    char dest_addr[10];

    /* Data from ax25 to net. */
    unsigned char inbuf[AGWPE_MAX_MSG_SIZE];
    gensiods inpos;
    gensiods inlen;

    /* Overflow data from net to ax25. */
    unsigned char outbuf[AGWPE_MAX_MSG_SIZE];
    gensiods outlen;
};
#define to_ax25_conn(l) \
    gensio_container_of(l, struct agwpe_ax25_conn, link)
#define to_ax25_conn_xmit(l) \
    gensio_container_of(l, struct agwpe_ax25_conn, xmit_link)

#define NUM_OOB_PACKETS	32

struct agwpe_inst {
    struct gensio_link link;

    unsigned char inbuf[AGWPE_MAX_MSG_SIZE];
    gensiods inpos;
    struct agwpe_packet inpacket;
    gensiods inpacketpos;
    bool pending_recv_packet;

    unsigned char outbuf[AGWPE_MAX_MSG_SIZE];
    gensiods outpos;
    gensiods outlen;

    struct gensio *io;
    struct accinfo *ai;
    bool in_close;
    unsigned int ax25_waiting_close;

    bool monitoring;
    bool handle_raw;

    struct gensio_list addrs; /* struct ax25_reg_addr */
    struct gensio_list conns; /* struct agqpe_ax25_conn */

    struct gensio_list xmitq; /* struct agqpe_ax25_conn, xmit_link */

    enum {
	SENDING_OUTBUF = 0,
	SENDING_CONN,
	SENDING_OOB
    } send_state;

    unsigned char oob_packets[NUM_OOB_PACKETS][AGWPE_MAX_MSG_SIZE];
    gensiods oob_packet_len[NUM_OOB_PACKETS];
    unsigned int oob_data_pos;
    unsigned int oob_pos;
    unsigned int oob_len;
};

struct accinfo {
    struct gensio_os_funcs *o;
    struct gensio_accepter *acc;

    /* Main ax25 connection, UI and raw packets come in here. */
    struct gensio *tnc;

    struct gensio_list ios; /* struct agwpe_inst */

    unsigned int num_monitoring;
    unsigned int num_raw;

    bool shutting_down;
};
#define to_inst(l) gensio_container_of(l, struct agwpe_inst, link)

static void handle_net_close(struct gensio *unused, void *user_data);
static int handle_new_ax25_channel(struct accinfo *ai, struct gensio *io,
				   const char *const *auxdata);

static void
conn_add_xmitq(struct agwpe_ax25_conn *conn)
{
    if (!conn->in_xmit) {
	conn->in_xmit = true;
	gensio_list_add_tail(&conn->inst->xmitq, &conn->xmit_link);
	gensio_set_write_callback_enable(conn->inst->io, true);
    }
}

static struct agwpe_ax25_conn *
find_conn(struct agwpe_inst *inst, struct agwpe_packet *p)
{
    struct gensio_link *l;

    gensio_list_for_each(&inst->conns, l) {
	struct agwpe_ax25_conn *conn = to_ax25_conn(l);

	if (strcmp(conn->local_addr, p->callfrom) == 0 &&
		strcmp(conn->dest_addr, p->callto) == 0) {
	    return conn;
	}
    }
    return NULL;
}

static void
handle_ax25_close(struct gensio *unused, void *user_data)
{
    struct agwpe_ax25_conn *conn = user_data;
    struct agwpe_inst *inst = conn->inst;

    if (inst->in_close) {
	/* The whole instance is being shut down, nothing to report. */
	if (conn->in_xmit)
	    gensio_list_rm(&inst->xmitq, &conn->xmit_link);
	gensio_list_rm(&inst->conns, &conn->link);
	gensio_free(conn->ax25_io);
	free(conn);

	assert(inst->ax25_waiting_close > 0);
	inst->ax25_waiting_close--;
	if (inst->ax25_waiting_close == 0) {
	    int rv = gensio_close(inst->io, handle_net_close, inst);
	    if (rv)
		handle_net_close(NULL, inst);
	}
    } else {
	conn->report_close = true;
	conn_add_xmitq(conn);
    }
}

static void
start_ax25_close(struct agwpe_ax25_conn *conn)
{
    int rv;

    if (conn->in_close)
	return;

    if (conn->flow_controlled)
	gensio_set_read_callback_enable(conn->inst->io, true);
    conn->in_close = true;
    rv = gensio_close(conn->ax25_io, handle_ax25_close, conn);
    if (rv)
	handle_ax25_close(NULL, conn);
}

static int
io_conn_event(struct gensio *io, void *user_data, int event, int err,
	      unsigned char *buf, gensiods *buflen,
	      const char *const *auxdata)
{
    struct agwpe_ax25_conn *conn = user_data;
    struct agwpe_packet op;
    gensiods count;
    int rv;

    switch (event) {
    case GENSIO_EVENT_READ:
	if (err)
	    goto out_fail;
	if (conn->inpos) {
	    *buflen = 0;
	    gensio_set_read_callback_enable(conn->ax25_io, false);
	    return 0;
	}
	if (*buflen > AGWPE_MAX_MSG_SIZE)
	    goto out_fail;

	memset(&op, 0, sizeof(op));
	op.kind = 'D'; /* Data */
	/* These are swapped for data packets. */
	strncpy(op.callfrom, conn->dest_addr, 10);
	op.callfrom[9] = '\0';
	strncpy(op.callto, conn->local_addr, 10);
	op.callto[9] = '\0';
	op.data = buf;
	op.len = *buflen;
	conn->inpos = 0;
	agwpe_encode_packet(conn->inbuf, sizeof(conn->inbuf),
			    &op, &conn->inlen);
	conn_add_xmitq(conn);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	if (!conn->outlen) {
	    gensio_set_write_callback_enable(conn->ax25_io, false);
	    return 0;
	}
	rv = gensio_write(conn->ax25_io, &count, conn->outbuf, conn->outlen,
			  NULL);
	if (rv)
	    goto out_fail;
	if (count > 0) {
	    conn->outlen = 0;
	    if (conn->flow_controlled) {
		conn->flow_controlled = false;
		conn->inst->pending_recv_packet = false;
		gensio_set_read_callback_enable(conn->inst->io, true);
	    }
	    gensio_set_write_callback_enable(conn->ax25_io, false);
	}
	return 0;

    case GENSIO_EVENT_NEW_CHANNEL:
	return handle_new_ax25_channel(conn->inst->ai, (struct gensio *) buf,
				       auxdata);

    default:
	return GE_NOTSUP;
    }

 out_fail:
    start_ax25_close(conn);
    return 0;
}

static bool
check_output_ready(struct agwpe_inst *inst)
{
    if (inst->outlen) {
	gensio_set_read_callback_enable(inst->io, false);
	inst->pending_recv_packet = true;
	return false;
    }
    return true;
}

static struct ax25_reg_addr *
find_inst_addr(struct agwpe_inst *inst, char *addr)
{
    struct gensio_link *l;

    gensio_list_for_each(&inst->addrs, l) {
	struct ax25_reg_addr *regaddr = to_reg_addr(l);

	if (strcmp(regaddr->addr, addr) == 0)
	    return regaddr;
    }
    return NULL;
}

static int
process_register_callsign(struct agwpe_inst *inst, struct agwpe_packet *p)
{
    gensiods len;
    struct ax25_reg_addr *regaddr = NULL;
    struct agwpe_packet op;
    unsigned char data[1];
    int rv;

    if (!check_output_ready(inst))
	return 0;

    if (find_inst_addr(inst, p->callfrom))
	goto already_present;	

    regaddr = calloc(1, sizeof(*regaddr));
    if (!regaddr)
	goto out_err;

    memset(&op, 0, sizeof(op));

    memcpy(regaddr->addr, p->callfrom, 10);
    len = 10;
    rv = gensio_control(inst->ai->tnc,
			GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_SET,
			GENSIO_CONTROL_ADD_LADDR,
			regaddr->addr, &len);
    if (rv)
	goto out_err;
    gensio_list_add_tail(&inst->addrs, &regaddr->link);
    data[0] = 1;
    goto send_response;

 out_err:
    if (regaddr)
	free(regaddr);
 already_present:
    data[0] = 0;

 send_response:
    memset(&op, 0, sizeof(op));
    op.kind = 'X';
    op.len = 1;
    op.data = data;
    strncpy(op.callfrom, p->callfrom, 10);
    op.callfrom[9] = '\0';
    agwpe_encode_packet(inst->outbuf, sizeof(inst->outbuf),
			&op, &inst->outlen);
    gensio_set_write_callback_enable(inst->io, true);
    return 0;
}

static int
process_unregister_callsign(struct agwpe_inst *inst, struct agwpe_packet *p)
{
    gensiods len;
    struct gensio_link *l, *l2;

    gensio_list_for_each_safe(&inst->addrs, l, l2) {
	struct ax25_reg_addr *regaddr = to_reg_addr(l);

	if (strcasecmp(regaddr->addr, p->callfrom) == 0) {
	    len = 10;
	    gensio_control(inst->ai->tnc,
			   GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_SET,
			   GENSIO_CONTROL_DEL_LADDR,
			   regaddr->addr, &len);
	    gensio_list_rm(&inst->addrs, l);
	    break;
	}
    }
    return 0;
}

static int
process_ask_port_information(struct agwpe_inst *inst, struct agwpe_packet *p)
{
    struct agwpe_packet op;
    char data[100];

    if (!check_output_ready(inst))
	return 0;

    memset(&op, 0, sizeof(op));

    snprintf(data, sizeof(data), "1;AX25 port");

    op.kind = 'G';
    op.len = strlen(data) + 1;
    op.data = (unsigned char *) data;
    agwpe_encode_packet(inst->outbuf, sizeof(inst->outbuf),
			&op, &inst->outlen);
    gensio_set_write_callback_enable(inst->io, true);
    return 0;
}

static int
process_version_info(struct agwpe_inst *inst, struct agwpe_packet *p)
{
    struct agwpe_packet op;
    unsigned char data[8];

    if (!check_output_ready(inst))
	return 0;

    memset(&op, 0, sizeof(op));

    memset(data, 0, sizeof(data));
    data[0] = 1; /* Version 1.0 */

    op.kind = 'R';
    op.len = 8;
    op.data = data;
    agwpe_encode_packet(inst->outbuf, sizeof(inst->outbuf),
			&op, &inst->outlen);
    gensio_set_write_callback_enable(inst->io, true);

    return 0;
}

static int
process_ask_port_capabilities(struct agwpe_inst *inst, struct agwpe_packet *p)
{
    struct agwpe_packet op;
    unsigned char data[12];
    struct gensio_link *l;
    unsigned int i = 0;

    if (!check_output_ready(inst))
	return 0;

    memset(&op, 0, sizeof(op));

    memset(data, 0, sizeof(data));

    /* Fake values for just about everything. */
    data[0] = 0;
    data[1] = 1;
    data[2] = 0x19;
    data[3] = 4;
    data[4] = 0xc8;
    data[5] = 4;
    data[6] = 7;

    gensio_list_for_each(&inst->ai->ios, l)
	i++;
    data[7] = i;

    /*
     * FIXME - data[8-11] is num byte received in the last 2 minutes.
     * Really not very useful, but it could be calculated.
     */

    op.port = p->port;
    op.kind = 'g';
    op.len = 8;
    op.data = data;
    agwpe_encode_packet(inst->outbuf, sizeof(inst->outbuf),
			&op, &inst->outlen);
    gensio_set_write_callback_enable(inst->io, true);

    return 0;
}

static int
process_ask_port_outstanding(struct agwpe_inst *inst, struct agwpe_packet *p)
{
    struct agwpe_packet op;
    unsigned char data[4];
    char buf[20];
    gensiods len;
    unsigned int val;
    int rv;

    if (!check_output_ready(inst))
	return 0;

    memset(&op, 0, sizeof(op));

    memset(data, 0, sizeof(data));

    strcpy(buf, "1"); /* Fetch for the whole thing. */
    len = sizeof(buf);
    rv = gensio_control(inst->ai->tnc,
			GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_GET,
			GENSIO_CONTROL_DRAIN_COUNT,
			buf, &len);
    if (!rv) {
	val = strtoul(buf, NULL, 0);
	data[0] = val & 0xff;
	data[1] = (val >> 8) & 0xff;
	data[2] = (val >> 16) & 0xff;
	data[3] = (val >> 24) & 0xff;
    }

    op.port = p->port;
    op.kind = 'y';
    op.len = 4;
    op.data = data;
    agwpe_encode_packet(inst->outbuf, sizeof(inst->outbuf),
			&op, &inst->outlen);
    gensio_set_write_callback_enable(inst->io, true);

    return 0;
}

static int
process_ask_conn_outstanding(struct agwpe_inst *inst, struct agwpe_packet *p)
{
    struct agwpe_packet op;
    unsigned char data[4];
    char buf[20];
    unsigned int val;
    int rv;
    struct agwpe_ax25_conn *conn;
    gensiods len;

    if (!check_output_ready(inst))
	return 0;

    memset(&op, 0, sizeof(op));

    memset(data, 0, sizeof(data));

    conn = find_conn(inst, p);
    if (!conn)
	goto skip;

    strcpy(buf, "0");
    len = sizeof(buf);
    rv = gensio_control(conn->ax25_io,
			GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_GET,
			GENSIO_CONTROL_DRAIN_COUNT,
			buf, &len);
    if (!rv) {
	val = strtoul(buf, NULL, 0);
	data[0] = val & 0xff;
	data[1] = (val >> 8) & 0xff;
	data[2] = (val >> 16) & 0xff;
	data[3] = (val >> 24) & 0xff;
    }

 skip:
    memset(&op, 0, sizeof(op));
    op.port = p->port;
    op.kind = 'Y';
    op.len = 4;
    op.data = data;
    strncpy(op.callfrom, p->callto, 10);
    op.callfrom[9] = '\0';
    strncpy(op.callto, p->callfrom, 10);
    op.callto[9] = '\0';
    agwpe_encode_packet(inst->outbuf, sizeof(inst->outbuf),
			&op, &inst->outlen);
    gensio_set_write_callback_enable(inst->io, true);

    return 0;
}

static bool
packet_to_addr(struct agwpe_packet *p, bool via, char *addr, unsigned int len,
	       unsigned int *dataoffset)
{
    unsigned int pos, i;
    char *s;

    pos = snprintf(addr, len, "addr=%d,%s,%s",
		   p->port, p->callto, p->callfrom);
    if (pos > len)
	return false;
    if (via) {
	if (p->len < 1 || p->len < (p->data[0] * 10 + 1))
	    return false;
	if (p->data[0] > GENSIO_AX25_ADDR_MAX_EXTRA)
	    return false;
	s = (char *) p->data + 1;
	for (i = 0; i < p->data[0]; i++, s += 10) {
	    s[9] = '\0';
	    pos += snprintf(addr + pos, len - pos, ",%s", s);
	    if (pos > len)
		return false;
	}
	if (dataoffset)
	    *dataoffset = p->data[0] * 10 + 1;
    }
    return true;
}

static int
process_send_ui(struct agwpe_inst *inst, struct agwpe_packet *p, bool via)
{
    char addr[GENSIO_AX25_MAX_ADDR_STR_LEN + 1];
    char pidstr[10];
    const char *auxdata[4] = { addr, pidstr, "oob", NULL };
    unsigned int offset;

    if (p->port != 0)
	return 0;

    if (!packet_to_addr(p, via, addr, sizeof(addr), &offset))
	return 0;
    snprintf(pidstr, sizeof(pidstr), "%d", p->pid);
    gensio_write(inst->ai->tnc, NULL, p->data + offset, p->len - offset,
		 auxdata);

    return 0;
}

static void
encode_report_open(struct agwpe_ax25_conn *conn)
{
    struct agwpe_packet op;
    char data[100];

    memset(&op, 0, sizeof(op));
    op.kind = 'C'; /* Connected */
    strncpy(op.callfrom, conn->local_addr, 10);
    op.callfrom[9] = '\0';
    strncpy(op.callto, conn->dest_addr, 10);
    op.callto[9] = '\0';
    if (conn->was_connection)
	op.len = snprintf(data, sizeof(data),
			  "*** CONNECTED With %s\r",
			  conn->dest_addr);
    else
	op.len = snprintf(data, sizeof(data),
			  "*** CONNECTED To Station %s\r",
			  conn->dest_addr);
    op.data = (unsigned char *) data;
    conn->inpos = 0;
    agwpe_encode_packet(conn->inbuf, sizeof(conn->inbuf),
			&op, &conn->inlen);
}

static void
encode_report_disconnected(struct agwpe_ax25_conn *conn)
{
    struct agwpe_packet op;
    char data[100];

    memset(&op, 0, sizeof(op));
    op.kind = 'd'; /* Disconnected */
    strncpy(op.callfrom, conn->local_addr, 10);
    strncpy(op.callto, conn->dest_addr, 10);
    if (conn->timeout)
	op.len = snprintf(data, sizeof(data),
			  "*** DISCONNECTED RETRYOUT With %s\r",
			  conn->dest_addr);
    else
	op.len = snprintf(data, sizeof(data),
			  "*** DISCONNECTED From Station %s\r",
			  conn->dest_addr);
    op.data = (unsigned char *) data;
    conn->inpos = 0;
    agwpe_encode_packet(conn->inbuf, sizeof(conn->inbuf),
			&op, &conn->inlen);
}

static void
conn_opened(struct gensio *io, int err, void *user_data)
{
    struct agwpe_ax25_conn *conn = user_data;

    if (err) {
	conn->report_close = true;
	conn->timeout = true;
    } else {
	conn->report_open = true;
	gensio_set_read_callback_enable(conn->ax25_io, true);
    }

    conn_add_xmitq(conn);
}

static int
process_connect(struct agwpe_inst *inst, struct agwpe_packet *p,
		bool via, unsigned int pid)
{
    char addr[GENSIO_AX25_MAX_ADDR_STR_LEN + 1];
    const char *args[3] = { addr, NULL };
    struct agwpe_packet op;
    char data[100];
    struct agwpe_ax25_conn *conn;
    int rv;

    if (p->port != 0)
	goto out_fail_noconn;

    if (find_conn(inst, p))
	/* Duplicate connection. */
	goto out_fail_noconn;

    if (!find_inst_addr(inst, p->callfrom))
	/* We don't own the source address. */
	goto out_fail_noconn;

    conn = calloc(1, sizeof(*conn));
    if (!conn)
	goto out_fail_noconn;

    conn->was_connection = true;
    strcpy(conn->local_addr, p->callfrom);
    strcpy(conn->dest_addr, p->callto);
    conn->inst = inst;
    if (!packet_to_addr(p, via, addr, sizeof(addr), NULL))
	goto out_fail;
    rv = gensio_alloc_channel(inst->ai->tnc, args, io_conn_event, conn,
			      &conn->ax25_io);
    if (rv) {
	conn->timeout = true; /* For lack of a better error */
	goto out_fail;
    }
    rv = gensio_open(conn->ax25_io, conn_opened, conn);
    if (rv) {
	conn->timeout = true; /* For lack of a better error */
	goto out_fail;
    }
    gensio_list_add_tail(&inst->conns, &conn->link);

    return 0;

 out_fail:
    encode_report_disconnected(conn);
    conn->free_on_send = true;
    conn_add_xmitq(conn);
    return 0;

 out_fail_noconn:
    if (!check_output_ready(inst))
	return 0;

    memset(&op, 0, sizeof(op));
    op.kind = 'd'; /* Disconnected */
    op.pid = pid;
    strcpy(op.callfrom, p->callfrom);
    op.callfrom[9] = '\0';
    strcpy(op.callto, p->callto);
    op.callto[9] = '\0';
    op.len = snprintf(data, sizeof(data),
		      "*** DISCONNECTED RETRYOUT With %s\r",
		      p->callto);
    op.data = (unsigned char *) data;
    /* No connection available, encode it into tue inst outbuf. */
    agwpe_encode_packet(inst->outbuf, sizeof(inst->outbuf),
			&op, &inst->outlen);
    gensio_set_write_callback_enable(inst->io, true);
    return 0;
}

static int
process_send_connected(struct agwpe_inst *inst, struct agwpe_packet *p)
{
    struct agwpe_ax25_conn *conn = find_conn(inst, p);
    gensiods count;
    int rv;

    if (!conn)
	return 0;

    if (p->len > AGWPE_MAX_MSG_SIZE)
	goto out_fail;

    if (conn->outlen) {
	/* No place to put the data, flow control. */
	conn->flow_controlled = true;
	inst->pending_recv_packet = true;
	gensio_set_read_callback_enable(inst->io, false);
	return 0;
    }

    rv = gensio_write(conn->ax25_io, &count, p->data, p->len, NULL);
    if (rv)
	goto out_fail;

    if (count == 0) {
	memcpy(conn->outbuf, p->data, p->len);
	conn->outlen = p->len;
	gensio_set_write_callback_enable(conn->ax25_io, true);
    }
    return 0;

 out_fail:
    start_ax25_close(conn);
    return 0;
}

static int
process_disconnect(struct agwpe_inst *inst, struct agwpe_packet *p)
{
    struct agwpe_ax25_conn *conn = find_conn(inst, p);

    if (!conn || conn->in_close)
	return 0;

    start_ax25_close(conn);
    return 0;
}

static int
process_net_packet(struct agwpe_inst *inst)
{
    struct agwpe_packet *p = &inst->inpacket;
    int rv = 0;

    agwpe_fix_call(p->callfrom);
    agwpe_fix_call(p->callto);

    switch (p->kind) {
    case 'P':
	/* Just ignore this. */
	break;

    case 'X':
	rv = process_register_callsign(inst, p);
	break;

    case 'x':
	rv = process_unregister_callsign(inst, p);
	break;

    case 'G':
	rv = process_ask_port_information(inst, p);
	break;

    case 'm':
	inst->monitoring = !inst->monitoring;
	inst->ai->num_monitoring += inst->monitoring ? 1 : -1;
	break;
	
    case 'R':
	rv = process_version_info(inst, p);
	break;

    case 'g':
	rv = process_ask_port_capabilities(inst, p);
	break;

    case 'H':
	/* FIXME - we can get heard information, could provide it. */
	break;

    case 'y':
	rv = process_ask_port_outstanding(inst, p);
	break;

    case 'Y':
	rv = process_ask_conn_outstanding(inst, p);
	break;

    case 'M':
	rv = process_send_ui(inst, p, false);
	break;

    case 'C':
	rv = process_connect(inst, p, false, 0xf0);
	break;

    case 'D':
	rv = process_send_connected(inst, p);
	break;

    case 'd':
	rv = process_disconnect(inst, p);
	break;

    case 'v':
	rv = process_connect(inst, p, true, 0xf0);
	break;

    case 'V':
	rv = process_send_ui(inst, p, true);
	break;

    case 'c':
	rv = process_connect(inst, p, false, p->pid);
	break;

    case 'K': {
	const char *auxdata[2] = { "raw", NULL };
	if (p->port == 0)
	    gensio_write(inst->ai->tnc, NULL, p->data, p->len, auxdata);
	break;
    }

    case 'k':
	inst->handle_raw = !inst->handle_raw;
	inst->ai->num_raw += inst->handle_raw ? 1 : -1;
	break;

    default:
	rv = GE_INVAL;
    }
    return rv;
}

static void
handle_net_close(struct gensio *unused, void *user_data)
{
    struct agwpe_inst *inst = user_data;
    struct gensio_link *l, *l2;

    if (inst->io)
	gensio_free(inst->io);

    gensio_list_for_each_safe(&inst->ai->ios, l, l2) {
	if (&inst->link == l) {
	    gensio_list_rm(&inst->ai->ios, l);
	    break;
	}
    }
    free(inst);
}

static void
close_inst(struct agwpe_inst *inst)
{
    int rv;
    struct gensio_link *l, *l2;

    inst->in_close = true;
    gensio_list_for_each_safe(&inst->addrs, l, l2) {
	struct ax25_reg_addr *regaddr = to_reg_addr(l);
	gensiods len = 10;

	gensio_control(inst->ai->tnc,
		       GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_SET,
		       GENSIO_CONTROL_DEL_LADDR,
		       regaddr->addr, &len);
	gensio_list_rm(&inst->addrs, l);
	free(regaddr);
    }

    gensio_list_for_each(&inst->conns, l)
	inst->ax25_waiting_close++;
    gensio_list_for_each_safe(&inst->conns, l, l2) {
	struct agwpe_ax25_conn *conn = to_ax25_conn(l);

	if (!conn->in_close) {
	    conn->in_close = true;
	    rv = gensio_close(conn->ax25_io, handle_ax25_close, conn);
	    if (!rv)
		handle_ax25_close(NULL, conn);
	}
    }
}

static int
io_net_event(struct gensio *io, void *user_data, int event, int err,
	     unsigned char *buf, gensiods *buflen,
	     const char *const *auxdata)
{
    struct agwpe_inst *inst = user_data;
    gensiods len, used = 0, left;
    int rv;

    if (err)
	goto protocol_err;

    switch (event) {
    case GENSIO_EVENT_READ:
	left = *buflen;
	if (inst->pending_recv_packet) {
	    used = 0;
	    gensio_set_read_callback_enable(inst->io, false);
	    goto out_read;
	}
	if (inst->inpos < AGWPE_HEADER_SIZE) {
	    len = left;
	    if (inst->inpos + len > AGWPE_HEADER_SIZE)
		len = AGWPE_HEADER_SIZE - inst->inpos;
	    memcpy(inst->inbuf + inst->inpos, buf + used, len);
	    used += len;
	    left -= len;
	    inst->inpos += len;
	    if (inst->inpos >= AGWPE_HEADER_SIZE) {
		agwpe_decode_packet(inst->inbuf, inst->inpos, &inst->inpacket);
		if (inst->inpacket.len == 0)
		    goto process_packet;
		if (inst->inpacket.len > AGWPE_MAX_MSG_SIZE)
		    goto protocol_err;
		inst->inpacketpos = 0;
	    } else {
		goto out_read;
	    }
	}
	len = left;
	if (len > inst->inpacket.len)
	    len = inst->inpacket.len;
	memcpy(inst->inpacket.data + inst->inpacketpos, buf + used, len);
	used += len;
	left -= len;
	inst->inpacketpos += len;
	if (inst->inpacketpos < inst->inpacket.len)
	    goto out_read;
    process_packet:
	err = process_net_packet(inst);
	if (err)
	    goto protocol_err;
	inst->inpos = 0;
    out_read:
	*buflen = used;
	break;

    case GENSIO_EVENT_WRITE_READY:
	if (!inst->outlen && gensio_list_empty(&inst->xmitq)) {
	    gensio_set_write_callback_enable(inst->io, false);
	    goto out_write;
	}
	switch(inst->send_state) {
	case SENDING_OUTBUF:
	    break;
	case SENDING_CONN:
	    goto send_conn;
	case SENDING_OOB:
	    goto send_oob;
	}
	if (inst->outlen) {
	    rv = gensio_write(inst->io, &len, inst->outbuf + inst->outpos,
			      inst->outlen, NULL);
	    if (rv)
		goto protocol_err;
	    inst->outlen -= len;
	    if (inst->outlen > 0) {
		inst->outpos += len;
		goto out_write;
	    }
	    inst->outlen = 0;
	    inst->outpos = 0;
	    inst->pending_recv_packet = false;
	}
    send_conn:
	if (!gensio_list_empty(&inst->xmitq)) {
	    struct gensio_link *l, *l2;

	    gensio_list_for_each_safe(&inst->xmitq, l, l2) {
		struct agwpe_ax25_conn *conn = to_ax25_conn_xmit(l);

	    restart_send:
		if (conn->inlen) {
		    rv = gensio_write(inst->io, &len,
				      conn->inbuf + conn->inpos,
				      conn->inlen, NULL);
		    if (rv)
			goto protocol_err;
		    conn->inlen -= len;
		    if (conn->inlen > 0) {
			conn->inpos += len;
			inst->send_state = SENDING_CONN;
			goto out_write;
		    }
		    conn->inlen = 0;
		    conn->inpos = 0;
		}
		inst->send_state = SENDING_OUTBUF;

		if (conn->report_open) {
		    encode_report_open(conn);
		    conn->report_open = false;
		    goto restart_send;
		}
		if (conn->report_close) {
		    encode_report_disconnected(conn);
		    conn->report_close = false;
		    conn->free_on_send = true;
		    goto restart_send;
		}

		conn->in_xmit = false;
		gensio_list_rm(&inst->xmitq, l);
		if (conn->free_on_send) {
		    if (conn->ax25_io)
			gensio_free(conn->ax25_io);
		    gensio_list_rm(&conn->inst->conns, &conn->link);
		    free(conn);
		}
	    }
	}
    send_oob:
	while (inst->oob_len) {
	    rv = gensio_write(inst->io, &len,
		inst->oob_packets[inst->oob_pos] + inst->oob_data_pos,
		inst->oob_packet_len[inst->oob_pos], NULL);
	    if (rv)
		goto protocol_err;
	    inst->oob_packet_len[inst->oob_pos] -= len;
	    if (inst->oob_packet_len[inst->oob_pos] > 0) {
		inst->oob_data_pos += len;
		inst->send_state = SENDING_OOB;
		goto out_write;
	    }
	    inst->oob_data_pos = 0;
	    inst->oob_pos = (inst->oob_pos + 1) % NUM_OOB_PACKETS;
	    inst->oob_len--;
	    inst->send_state = SENDING_OUTBUF;
	}
	/* Wrote all the data. */
	gensio_set_write_callback_enable(inst->io, false);
    out_write:
	break;

    default:
	return GE_NOTSUP;
    }
    return 0;

 protocol_err:
    gensio_set_read_callback_enable(inst->io, false);
    gensio_set_write_callback_enable(inst->io, false);
    close_inst(inst);
    return 0;
}

static int
io_acc_event(struct gensio_accepter *accepter, void *user_data,
	     int event, void *data)
{
    struct accinfo *ai = user_data;
    struct agwpe_inst *inst;

    if (event == GENSIO_ACC_EVENT_LOG) {
	struct gensio_loginfo *li = data;

	vfprintf(stderr, li->str, li->args);
	fprintf(stderr, "\n");
	return 0;
    }

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return GE_NOTSUP;

    if (ai->shutting_down) {
	gensio_free(data);
	return 0;
    }

    inst = calloc(1, sizeof(*inst));
    if (!inst) {
	fprintf(stderr, "Could not allocate info for new io\n");
	gensio_free(data);
	return 0;
    }
    gensio_list_init(&inst->addrs);
    gensio_list_init(&inst->conns);
    gensio_list_init(&inst->xmitq);
    inst->io = data;
    inst->ai = ai;
    gensio_list_add_tail(&ai->ios, &inst->link);
    gensio_set_callback(inst->io, io_net_event, inst);
    gensio_set_read_callback_enable(inst->io, true);

    return 0;
}

static void
gensio_ax25_subaddr_to_addr(struct gensio_ax25_subaddr *xaddr, char *addr)
{
    unsigned int pos;

    strncpy(addr, xaddr->addr, 7);
    addr[6] = '\0';
    pos = strlen(addr);
    addr[pos++] = '-';
    if (xaddr->ssid >= 10) {
	addr[pos++] = '1';
	addr[pos++] = xaddr->ssid + '0' - 10;
    } else {
	addr[pos++] = xaddr->ssid + '0';
    }
    addr[pos] = '\0';
}

static int
handle_new_ax25_channel(struct accinfo *ai, struct gensio *io,
			const char *const *auxdata)
{
    struct agwpe_ax25_conn *conn;
    struct agwpe_inst *inst = NULL;
    struct gensio_link *l;
    char destaddr[10], srcaddr[10];
    unsigned int i;
    struct gensio_addr *gaddr = NULL;
    struct gensio_ax25_addr *xaddr;
    int rv = GE_INVAL;

    for (i = 0; auxdata && auxdata[i]; i++) {
	if (strncmp(auxdata[i], "addr:", 5)) {
	    rv = gensio_ax25_str_to_addr(ai->o, auxdata[i] + 5, &gaddr);
	    if (rv)
		goto out_err;
	    xaddr = addr_to_ax25(gaddr);
	    gensio_ax25_subaddr_to_addr(&xaddr->dest, destaddr);
	    gensio_ax25_subaddr_to_addr(&xaddr->src, srcaddr);
	}
    }
    if (rv) /* Didn't find the addr: entry. */
	goto out_err;

    gensio_list_for_each(&ai->ios, l) {
	inst = to_inst(l);
	if (find_inst_addr(inst, srcaddr))
	    break;
	inst = NULL;
    }
    if (!inst) {
	rv = GE_NOTFOUND;
	goto out_err;
    }

    conn = calloc(1, sizeof(*conn));
    if (!conn) {
	rv = GE_NOMEM;
	goto out_err;
    }

    strcpy(conn->local_addr, srcaddr);
    strcpy(conn->dest_addr, destaddr);
    conn->inst = inst;
    gensio_list_add_tail(&inst->conns, &conn->link);

    encode_report_disconnected(conn);
    conn->free_on_send = true;
    conn_add_xmitq(conn);

 out_err:
    if (gaddr)
	gensio_addr_free(gaddr);
    return rv;
}

static unsigned int
addr_to_UIS_header(const char *addr, unsigned int pid, unsigned int datalen,
		   char *src, char *dest,
		   char *header, unsigned int header_len)
{
    unsigned int port;
    char *end;
    time_t t;
    struct tm tm;

    if (strncmp(addr, "ax25:", 5) == 0)
	addr += 5;
    port = strtoul(addr, &end, 10);
    if (*end != ',')
	return 0;
    addr = end + 1;
    end = strchr(addr, ',');
    if (!end)
	return 0;
    if (end - addr > 11)
	return 0;
    memcpy(dest, addr, end - addr);
    dest[11] = '\0';
    addr = end + 1;
    end = strchr(dest, ':');
    if (end)
	*end = '\0'; /* Chop off ':c/h'. */
    end = strchr(addr, ',');
    if (!end)
	end = (char *) addr + strlen(addr);
    if (end - addr > 11)
	return 0;
    memcpy(src, addr, end - addr);
    src[11] = '\0';
    end = strchr(src, ':');
    if (end)
	*end = '\0'; /* Chop off ':c/h'. */
    time(&t);
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    return snprintf(header, header_len,
		    "%u:Fm %s To %s <UI PID=%2.2x Len=%u >"
		    "[%2.2d:%2.2d:%2.2d]\r",
		    port + 1, src, dest, pid, datalen,
		    tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int
io_tnc_event(struct gensio *io, void *user_data, int event, int err,
	     unsigned char *buf, gensiods *buflen,
	     const char *const *auxdata)
{
    struct accinfo *ai = user_data;
    bool is_raw = false, is_oob = false;
    const char *addr = NULL;
    int pid = -1;
    unsigned int i;
    struct gensio_link *l;
    char dest[12], src[12], fmtstr[100], *fmt = NULL;
    unsigned int fmtlen, pos;
    struct agwpe_packet op;

    /*
     * FIXME - There is no handling of 'T' frames (frames send for 'M'
     * packets.  To do it right would require some ax25 layer changes.
     * I'm not sure it matters at this point.  Also, the raw data
     * doesn't contain anything we sent, which seems to be the intent
     * for some of this.
     */

    switch (event) {
    case GENSIO_EVENT_READ:
	for (i = 0; auxdata && auxdata[i]; i++) {
	    if (strcmp(auxdata[i], "raw"))
		is_raw = true;
	    else if (strcmp(auxdata[i], "oob"))
		is_oob = true;
	    else if (strncmp(auxdata[i], "addr:", 5) == 0)
		addr = auxdata[i] + 5;
	    else if (strncmp(auxdata[i], "pid:", 4) == 0)
		pid = strtoul(auxdata[i] + 4, NULL, 0);
	}
	if (is_raw) {
	    gensio_list_for_each(&ai->ios, l) {
		struct agwpe_inst *inst = to_inst(l);

		if (!inst->handle_raw)
		    continue;
	    
		if (inst->oob_len >= NUM_OOB_PACKETS)
		    continue;

		memset(&op, 0, sizeof(op));
		op.kind = 'K';
		op.data = (unsigned char *) buf;
		op.len = *buflen;
		pos = (inst->oob_pos + inst->oob_len) % NUM_OOB_PACKETS;
		agwpe_encode_packet(inst->oob_packets[pos],
				    AGWPE_MAX_MSG_SIZE,
				    &op, &(inst->oob_packet_len[pos]));
		inst->oob_len++;
		gensio_set_write_callback_enable(inst->io, true);
	    }
	    /*
	     * FIXME - finish handling S and I packets.
	     *
	     * This is hard, maybe impossible, because there is no way
	     * to know if a connection is extended (S and I are two
	     * bytes) or not (S and I frames are one byte).  Direwolf
	     * has some hacks around this, but they are hacks.
	     *
	     * I don't see any value in this, anyway.  U frames are
	     * all you need.
	     *
	     * For now, just report U packets (done below) and raw data.
	     */
	    /* U packets are handled in the OOB section below. */
	} else if (is_oob) {
	    if (ai->num_monitoring == 0 || !addr || pid == -1)
		return 0;

	    gensio_list_for_each(&ai->ios, l) {
		struct agwpe_inst *inst = to_inst(l);

		if (!inst->monitoring)
		    continue;

		if (inst->oob_len >= NUM_OOB_PACKETS)
		    continue;

		if (!fmt) {
		    fmtlen = addr_to_UIS_header(addr, pid,
						(unsigned int) *buflen,
						src, dest,
						fmtstr, sizeof(fmtstr));
		    if (fmtlen == 0)
			return 0;
		    if (fmtlen + *buflen > AGWPE_MAX_MSG_SIZE)
			return 0;
		    fmt = fmtstr;
		}

		memset(&op, 0, sizeof(op));
		op.kind = 'U';
		memcpy(op.callfrom, src, 10);
		memcpy(op.callto, dest, 10);
		op.data = (unsigned char *) fmt;
		op.len = fmtlen;
		pos = (inst->oob_pos + inst->oob_len) % NUM_OOB_PACKETS;
		agwpe_encode_packet2(inst->oob_packets[pos],
				     AGWPE_MAX_MSG_SIZE,
				     &op, &(inst->oob_packet_len[pos]),
				     buf, *buflen);
		inst->oob_len++;
		gensio_set_write_callback_enable(inst->io, true);
	    }
	}
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	/* Should never happen. */
	gensio_set_write_callback_enable(io, false);
	return 0;

    case GENSIO_EVENT_NEW_CHANNEL:
	return handle_new_ax25_channel(ai, (struct gensio *) buf, auxdata);

    case GENSIO_EVENT_PARMLOG: {
	struct gensio_parmlog_data *p = (struct gensio_parmlog_data *) buf;
	vfprintf(stderr, p->log, p->args);
	putc('\n', stderr);
	return 0;
    }

    default:
	return GE_NOTSUP;
    }
}

static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
    fprintf(stderr, "\n");
}

static void
help(char *progname, int err)
{
    printf("%s [options] io2\n", progname);
    printf("\nA program to allow network connections to AX25\n");
    printf("\noptions are:\n");
    printf("  -p, --listenport <gensio> - Set the listening port, default\n"
	   "    is tcp,7001\n");
    printf("  --version - Print the version number and exit.\n");
    printf("  -h, --help - This help\n");
    exit(err);
}

int
main(int argc, char *argv[])
{
    char *agwpe_gensio = "tcp,7001";
    char *tnc_gensio;
    unsigned int i;
    int rv;
    struct gensio_os_proc_data *proc_data = NULL;
    struct accinfo ai_data, *ai = &ai_data;
    gensiods len;

    memset(ai, 0, sizeof(*ai));
    gensio_list_init(&ai->ios);

    for (i = 1; i < argc; i++) {
	char *a = argv[i];

	if (a[0] != '-')
	    break;
	if (strcmp(a, "--") == 0)
	    break;
	if (strcmp(a, "-p") == 0 || strcmp(a, "--listenport") == 0) {
	    if (i + 1 == argc) {
		fprintf(stderr, "No parameter given for %s\n", a);
		return 1;
	    }
	    i++;
	    agwpe_gensio = argv[i];
	} else if (strcmp(a, "--version") == 0) {
	    printf("Version %s\n", gensio_version_string);
	    exit(0);
	} else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
	    help(argv[2], 0);
	} else {
	    fprintf(stderr, "Unknown option %s\n", a);
	    return 1;
	}
    }
    if (i == argc) {
	fprintf(stderr, "No tnc gensio given\n");
	return 1;
    }

    rv = gensio_alloc_os_funcs(GENSIO_DEF_WAKE_SIG, &ai->o, 0);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_set_vlog(ai->o, do_vlog);
    
    rv = gensio_os_proc_setup(ai->o, &proc_data);
    if (rv) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    tnc_gensio = gensio_alloc_sprintf(ai->o, "ax25(heard,raw),%s", argv[i]);
    if (!tnc_gensio) {
	fprintf(stderr, "Could not allocate string for tnc gensio.\n");
	return 1;
    }

    rv = str_to_gensio(tnc_gensio, ai->o, io_tnc_event, ai, &ai->tnc);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", tnc_gensio,
		gensio_err_to_str(rv));
	return 1;
    }
    rv = gensio_open_s(ai->tnc);
    if (rv) {
	fprintf(stderr, "Could not open %s: %s\n", tnc_gensio,
		gensio_err_to_str(rv));
	goto out_err;
    }
    len = 1;
    rv = gensio_control(ai->tnc,
			GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_SET,
			GENSIO_CONTROL_ENABLE_OOB,
			"1", &len);
    if (rv) {
	fprintf(stderr, "Could not enable oob on %s: %s\n", tnc_gensio,
		gensio_err_to_str(rv));
	goto out_err;
    }
    gensio_os_funcs_zfree(ai->o, tnc_gensio);
    tnc_gensio = NULL;

    rv = str_to_gensio_accepter(agwpe_gensio, ai->o, io_acc_event,
				ai, &ai->acc);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", agwpe_gensio,
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_acc_startup(ai->acc);
    if (rv) {
	fprintf(stderr, "Could not start %s: %s\n", agwpe_gensio,
		gensio_err_to_str(rv));
	goto out_err;
    }

    while (true) {
	rv = gensio_os_funcs_service(ai->o, NULL);
	if (rv) {
	    if (rv == GE_INTERRUPTED)
		continue;
	    fprintf(stderr, "Error from service: %s\n",
		    gensio_err_to_str(rv));
	    goto out_err;
	}
    }

 out_err:
    return 1;
}
