/*
 * Copyright 2020 Corey Minyard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * A basic client that talks to the basic server.  It sends the string
 * given in argv[2] and waits for three lines from the server, printing
 * them all out.
 *
 * To use this, run:
 *   basic_server telnet,tcp,3023 <string>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gensio/gensio.h>
#include <gensio/gensio_list.h>

static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
    fprintf(stderr, "\n");
}

struct coninfo {
    struct gensio_os_funcs *o;
    struct gensio *io;
    struct gensio_waiter *waiter;
    int err;
    bool closing;
    unsigned int incount; /* Counts read line. */
    char *outbuf; /* Holds write data */
    unsigned int outbuf_len;
    unsigned int outbuf_pos;
};

static void
close_done(struct gensio *io, void *close_data)
{
    struct coninfo *ci = close_data;

    gensio_os_funcs_wake(ci->o, ci->waiter);
}

static void
start_close(struct coninfo *ci)
{
    int rv;

    ci->closing = true;
    rv = gensio_close(ci->io, close_done, ci);
    if (rv) {
	/* Should be impossible, but just in case... */
	ci->err = rv;
	fprintf(stderr, "Error closing io: %s\n", gensio_err_to_str(rv));
	close_done(ci->io, ci);
    }
}

static int
io_event(struct gensio *io, void *user_data, int event, int err,
	 unsigned char *buf, gensiods *buflen,
	 const char *const *auxdata)
{
    struct coninfo *ci = user_data;
    gensiods len, i;
    int rv;

    switch (event) {
    case GENSIO_EVENT_READ:
	if (ci->closing) {
	    gensio_set_read_callback_enable(ci->io, false);
	    return 0;
	}

	if (err) {
	    fprintf(stderr, "Error from io: %s\n", gensio_err_to_str(err));
	    if (err != GE_REMCLOSE)
		ci->err = err;
	    start_close(ci);
	    return 0;
	}

	len = *buflen;
	for (i = 0; i < len; i++) {
	    if (buf[i] == '\n') {
		ci->incount++;
		if (ci->incount >= 3) {
		    gensio_set_read_callback_enable(ci->io, false);
		    start_close(ci);
		}
		i++;
		break;
	    }
	}
	*buflen = i; /* We processed the characters up to the new line. */
	fwrite(buf, 1, i, stdout);
	fflush(stdout);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	if (ci->closing) {
	    gensio_set_write_callback_enable(ci->io, false);
	    return 0;
	}

	if (ci->outbuf_pos < ci->outbuf_len) {
	    rv = gensio_write(ci->io, &i, ci->outbuf + ci->outbuf_pos,
			      ci->outbuf_len - ci->outbuf_pos, NULL);
	    if (rv) {
		if (rv != GE_REMCLOSE)
		    fprintf(stderr, "Error writing to io: %s\n",
			    gensio_err_to_str(rv));
		ci->err = rv;
		start_close(ci);
	    }
	    ci->outbuf_pos += i;
	}
	if (ci->outbuf_pos >= ci->outbuf_len) {
	    gensio_set_read_callback_enable(ci->io, true);
	    gensio_set_write_callback_enable(ci->io, false);
	}
	return 0;

    default:
	return GE_NOTSUP;
    }
}

int
main(int argc, char *argv[])
{
    struct coninfo ci;
    int rv;
    struct gensio_os_proc_data *proc_data;

    if (argc < 2) {
	fprintf(stderr, "No gensio given\n");
	return 1;
    }

    if (argc < 3) {
	fprintf(stderr, "No string given\n");
	return 1;
    }

    memset(&ci, 0, sizeof(ci));
    rv = gensio_default_os_hnd(0, &ci.o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_set_vlog(ci.o, do_vlog);

    rv = gensio_os_proc_setup(ci.o, &proc_data);
    if (rv) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    ci.outbuf_len = strlen(argv[2]);
    ci.outbuf = calloc(1, ci.outbuf_len + 1);
    if (!ci.outbuf) {
	fprintf(stderr, "Out of memory\n");
	return 1;
    }
    memcpy(ci.outbuf, argv[2], ci.outbuf_len);
    ci.outbuf[ci.outbuf_len++] = '\n';

    ci.waiter = gensio_os_funcs_alloc_waiter(ci.o);
    if (!ci.waiter) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not waiter, out of memory\n");
	goto out_err;
    }

    rv = str_to_gensio(argv[1], ci.o, io_event, &ci, &ci.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_open_s(ci.io);
    if (rv) {
	fprintf(stderr, "Could not open %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    gensio_set_write_callback_enable(ci.io, true);
    rv = gensio_os_funcs_wait(ci.o, ci.waiter, 1, NULL);

    if (ci.err)
	rv = ci.err;

 out_err:
    free(ci.outbuf);
    if (ci.io)
	gensio_free(ci.io);
    if (ci.waiter)
	gensio_os_funcs_free_waiter(ci.o, ci.waiter);
    gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(ci.o);

    return !!rv;
}
