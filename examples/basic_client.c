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

/* This should be the only include you need to do most things with gensio. */
#include <gensio/gensio.h>

/*
 * The gensio library logs internal issues that it finds to the
 * function set by gensio_os_funcs_set_vlog().  Though it's not
 * strictly necessary to have this, it's a good idea because it's
 * useful for tracking down issues.
 */
static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
    fprintf(stderr, "\n");
}

/*
 * The main data structure for the program.  It holds all connection
 * information.
 */
struct coninfo {
    struct gensio_os_funcs *o;

    /* The gensio for the connection. */
    struct gensio *io;

    /* Use to wait for the program to shut down. */
    struct gensio_waiter *waiter;

    /* If an error occurs, it is stored here. */
    int err;

    /* Are we in the process of closing the connection? */
    bool closing;

    unsigned int incount; /* Counts the number of lines read. */

    /*
     * The write buffer, and it's current length and position.  Note
     * that the data left to write is (outbuf_len - outbuf_pos), the
     * length is not changed as data is written.  Only the position is
     * changed.
     */
    char *outbuf;
    unsigned int outbuf_len;
    unsigned int outbuf_pos;
};

/*
 * Close is done asynchronously, this tells us that a connection has
 * finished closing.  We can just stop the program.  When this is
 * called, it is guaranteed that no callbacks are being done or will
 * be done on this gensio.
 */
static void
close_done(struct gensio *io, void *close_data)
{
    struct coninfo *ci = close_data;

    gensio_os_funcs_wake(ci->o, ci->waiter);
}

/*
 * Start the connection close.
 */
static void
start_close(struct coninfo *ci)
{
    int rv;

    if (ci->closing)
	return;

    ci->closing = true;
    rv = gensio_close(ci->io, close_done, ci);
    if (rv) {
	/* Should be impossible, but just in case... */
	ci->err = rv;
	fprintf(stderr, "Error closing io: %s\n", gensio_err_to_str(rv));
	close_done(ci->io, ci);
    }
}

/*
 * This is called when there is read data ready on the gensio or if a
 * write can be done on the gensio.
 */
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
	/* Data has come in from the server. */
	if (ci->closing) {
	    /* Closing, I don't want any more data. */
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

	/*
	 * Basically we just count newlines on read data.  When we see
	 * three we start the close process.
	 */
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

	/*
	 * Note that we could continue to process data from the
	 * buffer, but it simpler to just handle up to a newline and
	 * tell gensio we only handled that many characters.  It will
	 * call us again with the rest of the data.  Let it do the
	 * buffer handling.
	 */

	/* Print out the data we received. */
	fwrite(buf, 1, i, stdout);
	fflush(stdout);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	/* We can write data. */

	if (ci->closing) {
	    /*
	     * If we get called after close, make sure we don't get
	     * called again.
	     */
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
	    /*
	     * We only write one buffer in this program, once the
	     * write is complete just turn on the read and disable the
	     * write.
	     */
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

    /* We are single-threaded, no need for a signal here. */
    rv = gensio_alloc_os_funcs(0, &ci.o, 0);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    /* Send internal logs here. */
    gensio_os_funcs_set_vlog(ci.o, do_vlog);

    /*
     * Do basic process setup and save the data for restoration later.
     * This isn't strictly necessary, but using this and
     * gensio_os_proc_cleanup() will properly restore signal handlers,
     * masks, and other basic OS setup.
     */
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

    /*
     * Allocate the gensio to connect to the server.  When it is ready
     * to write data or data has been read io_event will be called.
     */
    rv = str_to_gensio(argv[1], ci.o, io_event, &ci, &ci.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    /*
     * The gensio is closed after being allocation.  We need to open
     * it so it will make the connection.  This is an example of a
     * synchronous open, when this function returns the gensio will be
     * opened (if no error is returned).  You can do an asynchronous
     * open, but there's not much point as there's nothing else do to
     * in this program at this point.
     */
    rv = gensio_open_s(ci.io);
    if (rv) {
	fprintf(stderr, "Could not open %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    /* Call the io_event with write ready when we can write. */
    gensio_set_write_callback_enable(ci.io, true);

    /*
     * This is the main operation loop for the program.  The waiter is
     * used so this can be woken up when the program is ready to shut
     * down.
     */
    rv = gensio_os_funcs_wait(ci.o, ci.waiter, 1, NULL);

    /* We stored the error in the main data structure, get it. */
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
