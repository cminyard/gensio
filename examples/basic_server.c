/*
 * Copyright 2020 Corey Minyard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * A basic server that receives connections and handles certain strings
 * when it sees them.  It also demonstrates basic thread support.
 *
 * To use this, run:
 *   basic_server telnet,tcp,3023
 * then telnet to it.
 *
 * If you type in "hello" is reponds with "bonjour".
 *
 * If you type in "goodbye" it responds with "au revior" and closes
 * the connection.
 *
 * If you type in "shutdown" it reponds with "adieu pour toujours" and
 * shuts down the server.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* This should be the only include you need to do most things with gensio. */
#include <gensio/gensio.h>

/* We use the gensio list code. */
#include <gensio/gensio_list.h>

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
 * This structure describes a single connection that has come in to
 * the server.  The server can serve multiple connections at the same
 * time and it keeps these in the list.
 */
struct ioinfo {
    /* The accepter info for the accepter that got this connection. */
    struct accinfo *ai;

    /* The gensio object for this connection. */
    struct gensio *io;

    /*
     * This lock protects the close operation and it protects the
     * output buffer.  Input is single-threaded so no need to protect
     * that.
     */
    struct gensio_lock *lock;

    /* The link for this object for gensio_list. */
    struct gensio_link link;

    /* Read data is collected in this array until an end of line. */
    char inbuf[100];
    unsigned int inbuf_len;

    /* Write data is held in this array. */
    char outbuf[200];
    unsigned int outbuf_len;

    bool closing; /* We have started a close, but it's not done. */

    bool close_on_write; /* Start a close when the current write completes. */
};

/*
 * This structure is the main structure for the program, it holds general
 * information for the operation and a list of ioinfo structures for the
 * current connections.
 */
struct accinfo {
    struct gensio_os_funcs *o;

    /* Accepter for this program, receives connection requests. */
    struct gensio_accepter *acc;

    /* Used to wait for the program to shut down. */
    struct gensio_waiter *waiter;

    struct gensio_list ios; /* List of current connections. */
    struct gensio_lock *ios_lock; /* Protect the list. */

    /* We start a second thread, that thread uses this waiter */
    struct gensio_waiter *thread2_waiter;

    /*
     * We are currently shutting down the program.  Don't accept
     * new connections.
     */ 
    bool shutting_down;

    bool shutdown_called; /* gensio_acc_shutdown() has been called. */
};

/*
 * The accepter shutdown is not synchronous, when the shutdown is
 * started it is given this function to call when the shutdown
 * completes.  It just wakes up the main waiter to terminate
 * the program.
 */
static void
shutdown_done(struct gensio_accepter *acc, void *shutdown_data)
{
    struct accinfo *ai = shutdown_data;

    gensio_os_funcs_wake(ai->o, ai->waiter);
}

/*
 * Check to see if we need to start the accepter shutdown.  We do this
 * when shutting down if there are no more connections.  This is called
 * through the code wherever a shutdown might be ready to be done.
 */
static void
check_shutdown(struct accinfo *ai)
{
    int rv = 0;

    gensio_os_funcs_lock(ai->o, ai->ios_lock);
    if (ai->shutting_down && gensio_list_empty(&ai->ios) &&
		!ai->shutdown_called) {
	/* We are ready to shut down and there are no connections. */
	ai->shutdown_called = true;
	rv = gensio_acc_shutdown(ai->acc, shutdown_done, ai);
    }
    gensio_os_funcs_unlock(ai->o, ai->ios_lock);

    if (rv) {
	fprintf(stderr, "Error shutting down accepter: %s\n",
		gensio_err_to_str(rv));
	shutdown_done(NULL, ai);
    }
}

/*
 * Close is done asynchronously, this tells us that a connection has
 * finished closing.  We can just free the data.  When this is called,
 * it is guaranteed that no callbacks are being done or will be done
 * on this gensio.
 */
static void
close_done(struct gensio *io, void *close_data)
{
    struct ioinfo *ii = close_data;
    struct accinfo *ai = ii->ai;

    gensio_os_funcs_lock(ai->o, ai->ios_lock);
    gensio_list_rm(&ai->ios, &ii->link);
    gensio_os_funcs_unlock(ai->o, ai->ios_lock);

    gensio_free(io);
    gensio_os_funcs_free_lock(ai->o, ii->lock);
    free(ii);
    check_shutdown(ai);
}

/*
 * Add some data to the output buffer.  It converts all newline characters
 * to \r\n.
 */
static void
add_output_buf_len(struct ioinfo *ii, char *str, gensiods ilen)
{
    gensiods i, j, len = 0;

    /*
     * Calculate the full length of the output data, adding an extra
     * character for each newline.
     */
    for (i = 0; i < ilen; i++) {
	if (str[i] == '\n')
	    len++;
	if (str[i] == '\r')
	    len++;
	len++;
    }

    gensio_os_funcs_lock(ii->ai->o, ii->lock);
    if (len + (gensiods) ii->outbuf_len >= sizeof(ii->outbuf))
	/* Not enough room. */
	goto out;

    /*
     * Now add the data to the output buffer, converting all newlines
     * to \r\n.
     */
    for (i = 0, j = ii->outbuf_len; i < ilen; i++) {
	if (str[i] == '\n')
	    ii->outbuf[j++] = '\r';
	ii->outbuf[j++] = str[i];
	if (str[i] == '\r')
	    ii->outbuf[j++] = '\n';
    }
    ii->outbuf_len += len;

    /* We have data to write, wake up the write operation to write it. */
    gensio_set_write_callback_enable(ii->io, true);
 out:
    gensio_os_funcs_unlock(ii->ai->o, ii->lock);
}

/*
 * Add a string to the output buffer.
 */
static void
add_output_buf(struct ioinfo *ii, char *str)
{
    add_output_buf_len(ii, str, strlen(str));
}

/*
 * Initiate the close of a connection.
 */
static void
start_close(struct ioinfo *ii)
{
    int rv = 0;

    gensio_os_funcs_lock(ii->ai->o, ii->lock);
    if (!ii->closing) {
	ii->closing = true;
	rv = gensio_close(ii->io, close_done, ii);
    }
    gensio_os_funcs_unlock(ii->ai->o, ii->lock);

    if (rv) {
	/* Should be impossible, but just in case... */
	fprintf(stderr, "Error closing io: %s\n", gensio_err_to_str(rv));
	close_done(ii->io, ii);
    }
}

/*
 * This is called when a full input line is received.  Depending on the
 * input string it performs different operations.
 */
static void
handle_input_line(struct ioinfo *ii)
{
    if (ii->closing)
	return;

    if (strcmp(ii->inbuf, "hello") == 0) {
	add_output_buf(ii, "bonjour\n");
    } else if (strcmp(ii->inbuf, "goodbye") == 0) {
	add_output_buf(ii, "au revior\n");
	ii->close_on_write = true; /* Close when the final write is complete. */
    } else if (strcmp(ii->inbuf, "shutdown") == 0) {
	struct accinfo *ai = ii->ai;
	struct gensio_link *l, *l2;

	/* Start a full shutdown.  Initiate a close on each connection. */
	add_output_buf(ii, "adieu pour toujours\n");
	ai->shutting_down = true;

	gensio_os_funcs_lock(ai->o, ai->ios_lock);
	gensio_list_for_each_safe(&ai->ios, l, l2) {
	    struct ioinfo *wii = gensio_container_of(l, struct ioinfo, link);

	    if (wii->outbuf_len > 0)
		/* Data is being written, close after the final write. */
		wii->close_on_write = true;
	    else
		/* No data to write, can start closing immediately. */
		start_close(wii);
	}
	gensio_os_funcs_unlock(ai->o, ai->ios_lock);
	check_shutdown(ai);
    } else {
	add_output_buf(ii, "Eh?\n");
    }
}

/*
 * Called when there is read data in the I/O handler.  This stores the
 * data into the read buffer, echos it, and calls the line handler
 * once it has a full line.
 */
static int
handle_read_buffer(struct ioinfo *ii, int err,
		   unsigned char *buf, gensiods *buflen)
{
    gensiods len, i;
    bool handle_it = false; /* Did we get an end of line char? */

    if (ii->closing)
	return 0;

    if (err) {
	/* Don't log GE_REMCLOSE, that means it was a normal close. */
	if (err != GE_REMCLOSE)
	    fprintf(stderr, "Error from io: %s\n", gensio_err_to_str(err));
	start_close(ii);
	return 0;
    }

    /*
     * Process the input data.  Note that the read callback is
     * guaranteed to be single-threaded, so there is no need to lock
     * when handling input data.
     */

    len = *buflen;
    for (i = 0; i < len; i++) {
	if (buf[i] == '\n' || buf[i] == '\r') {
	    ii->inbuf[ii->inbuf_len] = '\0';
	    ii->inbuf_len = 0;
	    /*
	     * Note that you could continue to process characters
	     * but this demonstrates that you can process partial
	     * buffers, which can sometimes simplify code.
	     */
	    handle_it = true;
	    i++;
	    break;
	}
	if (ii->inbuf_len >= sizeof(ii->inbuf) - 1)
	    continue;
	ii->inbuf[ii->inbuf_len++] = buf[i];
    }
    *buflen = i; /* We processed the characters up to the new line. */

    /* Echo to user */
    add_output_buf_len(ii, (char *) buf, i);

    /* Do the response after the echo, if it's ready. */
    if (handle_it)
	handle_input_line(ii);

    return 0;
}

/*
 * This is called when the gensio is able to write.  This will write
 * data to the gensio.  Once all the data is written, write ready is
 * disabled and a close is done if necessary.
 */
static int
handle_write_ready(struct ioinfo *ii)
{
    int rv;
    gensiods i;
    struct accinfo *ai = ii->ai;
    bool do_close = false;

    gensio_os_funcs_lock(ai->o, ii->lock);
    if (ii->closing) {
	/* If we get called after close, make sure we don't get called again. */
	gensio_set_write_callback_enable(ii->io, false);
	goto out;
    }

    if (ii->outbuf_len > 0) {
	rv = gensio_write(ii->io, &i, ii->outbuf, ii->outbuf_len, NULL);
	if (rv) {
	    if (rv != GE_REMCLOSE)
		fprintf(stderr, "Error writing to io: %s\n",
			gensio_err_to_str(rv));
	    gensio_set_write_callback_enable(ii->io, false);
	    do_close = true;
	    goto out;
	}
	if (i >= ii->outbuf_len) {
	    ii->outbuf_len = 0;
	} else {
	    ii->outbuf_len -= i;
	    memmove(ii->outbuf, ii->outbuf + i, ii->outbuf_len);
	}
    }
    if (ii->outbuf_len == 0) {
	/*
	 * All output data is written.  Disable the write callback and
	 * check to see if we should close.
	 */
	gensio_set_write_callback_enable(ii->io, false);
	do_close = ii->close_on_write;
    }
 out:
    gensio_os_funcs_unlock(ai->o, ii->lock);

    /* Close has to be done outside the lock, because it claims that lock. */
    if (do_close)
	start_close(ii);
    return 0;
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
    struct ioinfo *ii = user_data;

    switch (event) {
    case GENSIO_EVENT_READ:
	return handle_read_buffer(ii, err, buf, buflen);

    case GENSIO_EVENT_WRITE_READY:
	return handle_write_ready(ii);

    default:
	return GE_NOTSUP;
    }
}

/*
 * This is called when a new connection comes in on the accepter.  It
 * is also called on log events from the accepter, like if a
 * connection comes in but something in the stack refused the
 * connection.
 */
static int
io_acc_event(struct gensio_accepter *accepter, void *user_data,
	     int event, void *idata)
{
    struct accinfo *ai = user_data;
    struct gensio *io;
    struct ioinfo *ii;
    char str[100];
    gensiods size = sizeof(str);
    int rv;

    if (event == GENSIO_ACC_EVENT_LOG) {
	struct gensio_loginfo *li = idata;

	vfprintf(stderr, li->str, li->args);
	fprintf(stderr, "\n");
	return 0;
    }

    if (event != GENSIO_ACC_EVENT_NEW_CONNECTION)
	return GE_NOTSUP;

    /* In a new connection the data is the gensio pointer. */
    io = idata;

    printf("Got connection from the following address:\n");
    /* Only fetch the first address, on SCTP there can be multiple ones. */
    snprintf(str, sizeof(str), "%u", 0);
    rv = gensio_control(io,
			GENSIO_CONTROL_DEPTH_FIRST,
			GENSIO_CONTROL_GET,
			GENSIO_CONTROL_RADDR,
			str, &size);
    if (!rv)
	printf("  %s\n", str);

    if (ai->shutting_down) {
	/* We are shutting down, just refuse the connection. */
	gensio_free(io);
	return 0;
    }

    /* We will take this connection, allocate data for it. */
    ii = calloc(1, sizeof(*ii));
    if (!ii) {
	fprintf(stderr, "Could not allocate info for new io\n");
	gensio_free(io);
	return 0;
    }
    ii->lock = gensio_os_funcs_alloc_lock(ai->o);
    if (!ii->lock) {
	fprintf(stderr, "Could not allocate lock for new io\n");
	gensio_free(io);
	free(ii);
	return 0;
    }

    ii->io = io;
    ii->ai = ai;
    gensio_os_funcs_lock(ai->o, ai->ios_lock);
    gensio_list_add_tail(&ai->ios, &ii->link);
    gensio_os_funcs_unlock(ai->o, ai->ios_lock);

    /*
     * Call io_event with this connection when data comes is or write
     * is ready.
     */
    gensio_set_callback(ii->io, io_event, ii);

    /*
     * We are set up, enable the read data callback and write a prompt.
     */
    gensio_set_read_callback_enable(ii->io, true);
    add_output_buf(ii, "Ready\n");

    return 0;
}

/*
 * As a demo we start a second thread.  It just waits for shutdown, thus
 * it is processing gensio operations.
 */
static void
thread2(void *data)
{
    struct accinfo *ai = data;

    gensio_os_funcs_wait(ai->o, ai->thread2_waiter, 1, NULL);
}

int
main(int argc, char *argv[])
{
    struct accinfo ai;
    int rv;
    struct gensio_os_proc_data *proc_data = NULL;
    struct gensio_thread *tid2 = NULL;
    unsigned int i;

    if (argc < 2) {
	fprintf(stderr, "No gensio accepter given\n");
	return 1;
    }

    memset(&ai, 0, sizeof(ai));
    gensio_list_init(&ai.ios);

    /*
     * Allocate a default OS function handlers.  Since we are
     * multi-threaded, we have to pass in a signal to use for
     * inter-thread waking.  Just use the default one.
     */
    rv = gensio_alloc_os_funcs(GENSIO_DEF_WAKE_SIG, &ai.o, 0);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    /* Send internal logs here. */
    gensio_os_funcs_set_vlog(ai.o, do_vlog);

    /*
     * Do basic process setup and save the data for restoration later.
     * This isn't strictly necessary, but using this and
     * gensio_os_proc_cleanup() will properly restore signal handlers,
     * masks, and other basic OS setup.
     */
    rv = gensio_os_proc_setup(ai.o, &proc_data);
    if (rv) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    ai.ios_lock = gensio_os_funcs_alloc_lock(ai.o);
    if (!ai.ios_lock) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not allocate lock, out of memory\n");
	goto out_err;
    }

    ai.waiter = gensio_os_funcs_alloc_waiter(ai.o);
    if (!ai.waiter) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not allocate waiter, out of memory\n");
	goto out_err;
    }

    ai.thread2_waiter = gensio_os_funcs_alloc_waiter(ai.o);
    if (!ai.thread2_waiter) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not thread2 waiter, out of memory\n");
	goto out_err;
    }

    rv = gensio_os_new_thread(ai.o, thread2, &ai, &tid2);
    if (rv == GE_NOTSUP) {
	/* No thread support */
    } else if (rv) {
	fprintf(stderr, "Could not allocate thread 2: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }

    /*
     * Create the accepter to watch for incoming connections.  When
     * connections come it io_acc_event will be called.
     */
    rv = str_to_gensio_accepter(argv[1], ai.o, io_acc_event, &ai, &ai.acc);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    /* By default accepters are not started upon creation.  So start it. */
    rv = gensio_acc_startup(ai.acc);
    if (rv) {
	fprintf(stderr, "Could not start %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    printf("Listening on the following addresses:\n");
    for (i = 0; ; i++) {
	char str[100];
	gensiods size = sizeof(str);

	snprintf(str, sizeof(str), "%u", i);
	rv = gensio_acc_control(ai.acc,
				GENSIO_CONTROL_DEPTH_FIRST,
				GENSIO_CONTROL_GET,
				GENSIO_ACC_CONTROL_LADDR,
				str, &size);
	if (rv)
	    break;
	printf("  %s\n", str);
    }

    /*
     * This (and the one in thread2) is the main operation loop for
     * the program.  The waiter is used so this can be woken up when
     * the program is ready to shut down.
     */
    rv = gensio_os_funcs_wait(ai.o, ai.waiter, 1, NULL);

 out_err:
    if (tid2) {
	gensio_os_funcs_wake(ai.o, ai.thread2_waiter);
	gensio_os_wait_thread(tid2);
    }
    if (ai.acc)
	gensio_acc_free(ai.acc);
    if (ai.waiter)
	gensio_os_funcs_free_waiter(ai.o, ai.waiter);
    if (ai.thread2_waiter)
	gensio_os_funcs_free_waiter(ai.o, ai.thread2_waiter);
    if (ai.ios_lock)
	gensio_os_funcs_free_lock(ai.o, ai.ios_lock);
    gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(ai.o);

    return !!rv;
}
