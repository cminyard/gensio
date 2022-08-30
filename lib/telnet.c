/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <stdlib.h>
#include <string.h>

#include "telnet.h"

static struct telnet_cmd *
find_cmd(struct telnet_cmd *array, unsigned char option)
{
    int i;

    for (i = 0; array[i].option != TELNET_CMD_END_OPTION; i++) {
	if (array[i].option == option)
	    return &array[i];
    }
    return NULL;
}

void
telnet_cmd_send(telnet_data_t *td, const unsigned char *cmd, int len)
{
    if (gensio_buffer_output(&td->out_telnet_cmd, cmd, len) < len) {
	/* Out of data, abort the connection.  This really shouldn't
	   happen.*/
	td->error = 1;
	return;
    }

    td->output_ready(td->cb_data);
}

static void
send_i(telnet_data_t *td, unsigned char type, unsigned char option)
{
    unsigned char i[3];
    i[0] = TN_IAC;
    i[1] = type;
    i[2] = option;
    telnet_cmd_send(td, i, 3);
}

static void
handle_telnet_cmd(telnet_data_t *td, unsigned int size)
{
    unsigned char *cmd_str = td->telnet_cmd;
    struct telnet_cmd *cmd;
    int rv;
    unsigned char option;

    if (size < 2)
	return;

    if (cmd_str[1] < TN_SB) { /* A one-byte command. */
	td->cmd_handler(td->cb_data, cmd_str[1]);
	return;
    }

    /* Everything else is at least 3 bytes. */
    if (size < 3)
	return;

    if (cmd_str[1] == TN_SB) { /* Option */
	cmd = find_cmd(td->cmds, cmd_str[2]);
	if (!cmd || !cmd->option_handler)
	    return;
	cmd->option_handler(td->cb_data, cmd_str + 2, size - 2);
    } else if (cmd_str[1] == TN_WILL) {
	option = cmd_str[2];
	cmd = find_cmd(td->cmds, option);
	if (!cmd) {
	    send_i(td, TN_DONT, option);
	} else {
	    rv = cmd->i_do;
	    if (!rv && cmd->will_do_handler) {
		rv = cmd->will_do_handler(td->cb_data, TN_WILL);
		cmd->i_do = rv;
	    }
	    if (!rv || !cmd->sent_do) {
		send_i(td, rv ? TN_DO : TN_DONT, option);
		cmd->sent_do = 1;
	    }
	    cmd->rem_will = rv;
	}
    } else if (cmd_str[1] == TN_WONT) {
	option = cmd_str[2];
	cmd = find_cmd(td->cmds, option);
	if (cmd) {
	    if (cmd->will_do_handler)
		cmd->will_do_handler(td->cb_data, TN_WONT);
	    if (cmd->rem_will || !cmd->sent_do) {
		send_i(td, TN_DONT, option);
		cmd->sent_do = 1;
	    }
	    cmd->rem_will = 0;
	}
    } else if (cmd_str[1] == TN_DO) {
	option = cmd_str[2];
	cmd = find_cmd(td->cmds, option);
	if (!cmd) {
	    send_i(td, TN_WONT, option);
	} else {
	    rv = cmd->i_will;
	    if (cmd->will_do_handler) {
		rv = cmd->will_do_handler(td->cb_data, TN_DO);
		cmd->i_will = rv;
	    }
	    if (!rv || !cmd->sent_will) {
		send_i(td, rv ? TN_WILL : TN_WONT, option);
		cmd->sent_will = 1;
	    }
	    cmd->rem_do = rv;
	}
    } else if (cmd_str[1] == TN_DONT) {
	option = cmd_str[2];
	cmd = find_cmd(td->cmds, option);
	if (cmd) {
	    if (cmd->will_do_handler)
		cmd->will_do_handler(td->cb_data, TN_DONT);
	    if (cmd->rem_do || !cmd->sent_will) {
		send_i(td, TN_WONT, option);
		cmd->sent_will = 1;
	    }
	    cmd->rem_do = 0;
	}
    }
}

void
telnet_send_option(telnet_data_t *td, const unsigned char *option,
		   unsigned int len)
{
    unsigned int real_len;
    unsigned int i;

    /* Make sure to account for any duplicate 255s. */
    for (real_len = 0, i = 0; i < len; i++, real_len++) {
	if (option[i] == TN_IAC)
	    real_len++;
    }

    real_len += 4; /* Add the initial and end markers. */

    if (real_len > gensio_buffer_left(&td->out_telnet_cmd)) {
	/* Out of data, abort the connection.  This really shouldn't
	   happen.*/
	td->error = 1;
	return;
    }

    gensio_buffer_outchar(&td->out_telnet_cmd, TN_IAC);
    gensio_buffer_outchar(&td->out_telnet_cmd, TN_SB);
    for (i = 0; i < len; i++) {
	gensio_buffer_outchar(&td->out_telnet_cmd, option[i]);
	if (option[i] == TN_IAC)
	    gensio_buffer_outchar(&td->out_telnet_cmd, option[i]);
    }
    gensio_buffer_outchar(&td->out_telnet_cmd, TN_IAC);
    gensio_buffer_outchar(&td->out_telnet_cmd, TN_SE);

    td->output_ready(td->cb_data);
}

unsigned int
process_telnet_data(unsigned char *outdata, unsigned int outlen,
		    unsigned char **r_indata, unsigned int *inlen,
		    telnet_data_t *td)
{
    unsigned int i, j;
    unsigned char *indata = *r_indata;

    /* If it's a telnet port, get the commands out of the stream. */
    for (i = 0, j = 0; i < *inlen && j < outlen; i++) {
	if (td->telnet_cmd_pos != 0) {
	    unsigned char tn_byte;

	    tn_byte = indata[i];

	    if ((td->telnet_cmd_pos == 1) && (tn_byte == TN_IAC)) {
		/* Two IACs in a row causes one IAC to be sent, so
		   just let this one go through. */
		outdata[j++] = tn_byte;
		td->telnet_cmd_pos = 0;
		continue;
	    }

	    if (td->telnet_cmd_pos == 1) {
		/* These are two byte commands, so we have
		   everything we need to handle the command. */
		td->telnet_cmd[td->telnet_cmd_pos++] = tn_byte;
		if (tn_byte < TN_SB) {
		    handle_telnet_cmd(td, td->telnet_cmd_pos);
		    td->telnet_cmd_pos = 0;
		}
	    } else if (td->telnet_cmd_pos == 2) {
		td->telnet_cmd[td->telnet_cmd_pos++] = tn_byte;
		if (td->telnet_cmd[1] == TN_SE) {
		    /* SE is never valid except after an SE. */
		    td->telnet_cmd_pos = 0;
		    continue;
		}
		if (td->telnet_cmd[1] != TN_SB) {
		    /* It's a will/won't/do/don't */
		    handle_telnet_cmd(td, td->telnet_cmd_pos);
		    td->telnet_cmd_pos = 0;
		}
	    } else {
		/* It's in a suboption, look for the end and IACs. */
	      if (td->suboption_iac) {
		    if (tn_byte == TN_SE) {
			/* Remove the IAC 240 from the end. */
			td->telnet_cmd_pos--;
			handle_telnet_cmd(td, td->telnet_cmd_pos);
			td->telnet_cmd_pos = 0;
		    } else if (tn_byte == TN_IAC) {
			/* Don't do anything, a double 255 means
			   we leave on 255 in. */
		    } else {
			/* If we have an IAC and an invalid
			   character, delete them both */
			td->telnet_cmd_pos--;
		    }
		    td->suboption_iac = 0;
		} else {
		    if (td->telnet_cmd_pos > MAX_TELNET_CMD_SIZE)
			/* Always store the last character
			   received in the final postition (the
			   array is one bigger than the max size)
			   so we can detect the end of the
			   suboption. */
			td->telnet_cmd_pos = MAX_TELNET_CMD_SIZE;

		    td->telnet_cmd[td->telnet_cmd_pos++] = tn_byte;
		    if (tn_byte == TN_IAC)
			td->suboption_iac = 1;
		}
	    }
	} else if (indata[i] == TN_IAC) {
	    td->telnet_cmd[td->telnet_cmd_pos++] = TN_IAC;
	    td->suboption_iac = 0;
	} else {
	    outdata[j++] = indata[i];
	}
    }

    *inlen -= i;
    *r_indata = indata + i;

    return j;
}

unsigned int
process_telnet_xmit(unsigned char *outdata, unsigned int outlen,
		    const unsigned char **indata, size_t *r_inlen)
{
    unsigned int i, j = 0;
    unsigned int inlen = *r_inlen;
    const unsigned char *ibuf = *indata;

    /* Double the IACs on a telnet transmit stream. */
    for (i = 0; i < inlen; i++) {
	if (ibuf[i] == TN_IAC) {
	    if (outlen < 2)
		    break;
	    outdata[j++] = TN_IAC;
	    outdata[j++] = TN_IAC;
	    outlen -= 2;
	} else {
	    if (outlen < 1)
		break;
	    outdata[j++] = ibuf[i];
	    outlen--;
	}
    }

    *indata = ibuf + i;
    *r_inlen = inlen - i;

    return j;
}

void
telnet_init(telnet_data_t *td,
	    void *cb_data,
	    void (*output_ready)(void *cb_data),
	    void (*cmd_handler)(void *cb_data, unsigned char cmd),
	    struct telnet_cmd *cmds,
	    const unsigned char *init_seq,
	    int init_seq_len)
{
    memset(td, 0, sizeof(*td));
    gensio_buffer_init(&td->out_telnet_cmd, td->out_telnet_cmdbuf,
		       sizeof(td->out_telnet_cmdbuf));
    td->cb_data = cb_data;
    td->output_ready = output_ready;
    td->cmd_handler = cmd_handler;
    td->cmds = cmds;

    telnet_cmd_send(td, init_seq, init_seq_len);
}

void
telnet_cleanup(telnet_data_t *td)
{
    td->cmds = NULL;
}
