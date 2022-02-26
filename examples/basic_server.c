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

struct ioinfo {
    struct accinfo *ai;
    struct gensio *io;
    struct gensio_link link;
    char inbuf[100]; /* Holds read data */
    unsigned int inbuf_len;
    char outbuf[200]; /* Holds write data */
    unsigned int outbuf_len;
    bool closing; /* We have started a close */
    bool close_on_write;
};

struct accinfo {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    struct gensio_accepter *acc;
    struct gensio_list ios; /* List of ioinfo */
    struct gensio_waiter *thread2_waiter;
    bool shutting_down;
};

static void
shutdown_done(struct gensio_accepter *acc, void *shutdown_data)
{
    struct accinfo *ai = shutdown_data;

    gensio_os_funcs_wake(ai->o, ai->waiter);
}

static void
check_shutdown(struct accinfo *ai)
{
    int rv;

    if (!ai->shutting_down || !gensio_list_empty(&ai->ios))
	return;

    rv = gensio_acc_shutdown(ai->acc, shutdown_done, ai);
    if (rv) {
	fprintf(stderr, "Error shutting down accepter: %s\n",
		gensio_err_to_str(rv));
	shutdown_done(NULL, ai);
    }
}

static void
close_done(struct gensio *io, void *close_data)
{
    struct ioinfo *ii = close_data;
    struct accinfo *ai = ii->ai;

    gensio_free(io);
    gensio_list_rm(&ai->ios, &ii->link);
    free(ii);
    check_shutdown(ai);
}

static void
add_output_buf_len(struct ioinfo *ii, char *str, gensiods ilen)
{
    gensiods i, j, len = 0;

    for (i = 0; i < ilen; i++) {
	if (str[i] == '\n')
	    len++;
	if (str[i] == '\r')
	    len++;
	len++;
    }

    if (len + (gensiods) ii->outbuf_len >= sizeof(ii->outbuf))
	return;

    for (i = 0, j = ii->outbuf_len; i < ilen; i++) {
	if (str[i] == '\n')
	    ii->outbuf[j++] = '\r';
	ii->outbuf[j++] = str[i];
	if (str[i] == '\r')
	    ii->outbuf[j++] = '\n';
    }

    ii->outbuf_len += len;
    gensio_set_write_callback_enable(ii->io, true);
}

static void
add_output_buf(struct ioinfo *ii, char *str)
{
    add_output_buf_len(ii, str, strlen(str));
}

static void
start_close(struct ioinfo *ii)
{
    int rv;

    ii->closing = true;
    rv = gensio_close(ii->io, close_done, ii);
    if (rv) {
	/* Should be impossible, but just in case... */
	fprintf(stderr, "Error closing io: %s\n", gensio_err_to_str(rv));
	gensio_free(ii->io);
	free(ii);
    }
}

static void
handle_buf(struct ioinfo *ii)
{
    if (ii->closing)
	return;

    if (strcmp(ii->inbuf, "hello") == 0) {
	add_output_buf(ii, "bonjour\n");
    } else if (strcmp(ii->inbuf, "goodbye") == 0) {
	add_output_buf(ii, "au revior\n");
	ii->close_on_write = true;
    } else if (strcmp(ii->inbuf, "shutdown") == 0) {
	struct accinfo *ai = ii->ai;
	struct gensio_link *l;

	add_output_buf(ii, "adieu pour toujours\n");
	ai->shutting_down = true;
	gensio_list_for_each(&ai->ios, l) {
	    struct ioinfo *wii = gensio_container_of(l, struct ioinfo, link);

	    if (wii == ii) /* Close on the final write. */
		ii->close_on_write = true;
	    else
		start_close(wii);
	}
    } else {
	add_output_buf(ii, "Eh?\n");
    }
}

static int
io_event(struct gensio *io, void *user_data, int event, int err,
	 unsigned char *buf, gensiods *buflen,
	 const char *const *auxdata)
{
    struct ioinfo *ii = user_data;
    gensiods len, i;
    int rv;
    bool handle_it = false;

    switch (event) {
    case GENSIO_EVENT_READ:
	if (ii->closing)
	    return 0;

	if (err) {
	    if (err != GE_REMCLOSE)
		fprintf(stderr, "Error from io: %s\n", gensio_err_to_str(err));
	    start_close(ii);
	    return 0;
	}

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
	    handle_buf(ii);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	if (ii->closing) {
	    gensio_set_write_callback_enable(ii->io, false);
	    return 0;
	}

	if (ii->outbuf_len > 0) {
	    rv = gensio_write(ii->io, &i, ii->outbuf, ii->outbuf_len, NULL);
	    if (rv) {
		if (rv != GE_REMCLOSE)
		    fprintf(stderr, "Error writing to io: %s\n",
			    gensio_err_to_str(rv));
		gensio_set_write_callback_enable(ii->io, false);
		start_close(ii);
		return 0;
	    }
	    if (i >= ii->outbuf_len) {
		ii->outbuf_len = 0;
	    } else {
		ii->outbuf_len -= i;
		memmove(ii->outbuf, ii->outbuf + i, ii->outbuf_len);
	    }
	}
	if (ii->outbuf_len == 0) {
	    gensio_set_write_callback_enable(ii->io, false);
	    if (ii->close_on_write && !ii->closing)
		start_close(ii);
	}
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
io_acc_event(struct gensio_accepter *accepter, void *user_data,
	     int event, void *data)
{
    struct accinfo *ai = user_data;
    struct ioinfo *ii;

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

    ii = calloc(1, sizeof(*ii));
    if (!ii) {
	fprintf(stderr, "Could not allocate info for new io\n");
	gensio_free(data);
	return 0;
    }
    ii->io = data;
    ii->ai = ai;
    gensio_list_add_tail(&ai->ios, &ii->link);
    gensio_set_callback(ii->io, io_event, ii);
    gensio_set_read_callback_enable(ii->io, true);
    add_output_buf(ii, "Ready\n");

    return 0;
}

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

    if (argc < 2) {
	fprintf(stderr, "No gensio accepter given\n");
	return 1;
    }

    memset(&ai, 0, sizeof(ai));
    gensio_list_init(&ai.ios);

    rv = gensio_default_os_hnd(GENSIO_DEF_WAKE_SIG, &ai.o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_set_vlog(ai.o, do_vlog);

    rv = gensio_os_proc_setup(ai.o, &proc_data);
    if (rv) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    ai.waiter = gensio_os_funcs_alloc_waiter(ai.o);
    if (!ai.waiter) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not waiter, out of memory\n");
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

    rv = str_to_gensio_accepter(argv[1], ai.o, io_acc_event, &ai, &ai.acc);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_acc_startup(ai.acc);
    if (rv) {
	fprintf(stderr, "Could not start %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

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
    gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(ai.o);

    return !!rv;
}
