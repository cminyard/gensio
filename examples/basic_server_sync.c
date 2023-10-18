/*
 * Copyright 2020 Corey Minyard
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * A basic server that receives connections and handles certain
 * strings when it sees them.  It only uses synchronous I/O and can
 * only handle one connection at a time.
 *
 * To use this, run:
 *   basic_server telnet,tcp,3023
 * then telnet to it.
 *
 * If you type in "hello" is reponse with "bonjour".
 *
 * If you type in "goodbye" it responds with "au revior" and closes
 * the connection.
 *
 * If you type in "shutdown" it reponds with "adieu pour toujours" and
 * shuts down the server.
 *
 * !!!!!!!!!!!DANGER!!!!!!!!!!!!!!
 *
 * This program may look simpler than the asynchronous version, but it
 * has some significant drawbacks:
 *
 *   It can only handle one connection at a time.  You could do forks
 *   and all the handling associated with that, but then it would be
 *   larger than the asynchronous version.
 *
 *   It is susceptible to deadlocks.  This is *intrinsic* in designs
 *   like this.  If the write gets blocked and the thing on the other
 *   end of the io is waiting on a read in this program to complete,
 *   you are stuck.
 *
 * This kind of programming is not really recommended except for some
 * very special situations or very simple programs.  There is no
 * "poll()" type call for gensio.  If you are going to do that, just
 * use async I/O.
 *
 * Note that you can use gensio_open_s(), gensio_close_s(), and
 * gensio_acc_accept_s() safely in a simple program and use
 * asynchronous I/O for the data handling.
 */

#include <stdio.h>
#include <string.h>
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

static int
handle_buffer(struct gensio *io, char *buf)
{
    char *out = "Eh?\r\n";
    int shutdown = 0;
    int rv;

    if (strcmp(buf, "hello") == 0) {
	out = "bonjour\r\n";
    } else if (strcmp(buf, "goodbye") == 0) {
	out = "au revior\r\n";
	shutdown = 1;
    } else if (strcmp(buf, "shutdown") == 0) {
	out = "adieu pour toujours\r\n";
	shutdown = 2;
    }

    rv = gensio_write_s(io, NULL, out, strlen(out), NULL);
    if (rv) {
	if (rv != GE_REMCLOSE)
	    fprintf(stderr, "Error on io: %s\n", gensio_err_to_str(rv));
	if (!shutdown)
	    shutdown = 1;
    }

    return shutdown;
}

static int
process_data(struct gensio *io)
{
    gensiods i;
    int rv;
    char inbuf[100], *buf;
    char dummy[10];
    gensiods inpos = 0, count;
    int shutdown;

    rv = gensio_write_s(io, NULL, "Ready\r\n", 7, NULL);
    if (rv)
	goto out_err;

    for (;;) {
	if (inpos < sizeof(inbuf)) {
	    rv = gensio_read_s(io, &count, inbuf + inpos,
			       sizeof(inbuf) - inpos - 1, NULL);
	    if (rv)
		goto out_err;
	    rv = gensio_write_s(io, NULL, inbuf + inpos, count, NULL);
	    if (rv)
		goto out_err;
	    buf = inbuf + inpos;
	    inpos += count;
	    buf[inpos] = '\0';
	} else {
	    rv = gensio_read_s(io, &count, dummy, sizeof(dummy), NULL);
	    if (rv)
		goto out_err;
	    rv = gensio_write_s(io, NULL, dummy, count, NULL);
	    if (rv)
		goto out_err;
	    buf = dummy;
	}
	for (i = 0; i < count; i++) {
	    if (buf[i] == '\r' || buf[i] == '\n') {
		if (buf[i] == '\r') {
		    rv = gensio_write_s(io, NULL, "\n", 1, NULL);
		    if (rv)
			goto out_err;
		}
		if (buf[i] == '\n') {
		    rv = gensio_write_s(io, NULL, "\r", 1, NULL);
		    if (rv)
			goto out_err;
		}
		buf[i++] = '\0';
		shutdown = handle_buffer(io, inbuf);
		if (shutdown)
		    goto out;
		inpos = count - i;
		memmove(inbuf, buf + i, inpos);
		buf = inbuf;
		i = 0;
	    }
	}
    }
 out:
    rv = gensio_close_s(io);
    if (rv)
	fprintf(stderr, "Error closing io: %s\n", gensio_err_to_str(rv));
    gensio_free(io);

    if (shutdown == 2)
	return true;
    return false;

 out_err:
    if (rv != GE_REMCLOSE)
	fprintf(stderr, "Error on io: %s\n", gensio_err_to_str(rv));
    return false;
}

static int
io_acc_event(struct gensio_accepter *accepter, void *user_data,
	     int event, void *data)
{
    if (event == GENSIO_ACC_EVENT_LOG) {
	struct gensio_loginfo *li = data;

	vfprintf(stderr, li->str, li->args);
	fprintf(stderr, "\n");
	return 0;
    }

    return GE_NOTSUP;
}

int
main(int argc, char *argv[])
{
    struct gensio_os_funcs *o;
    struct gensio_accepter *acc = NULL;
    struct gensio *io = NULL;
    int rv;
    struct gensio_os_proc_data *proc_data;

    if (argc < 2) {
	fprintf(stderr, "No gensio accepter given\n");
	return 1;
    }

    rv = gensio_alloc_os_funcs(0, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    gensio_os_funcs_set_vlog(o, do_vlog);

    rv = gensio_os_proc_setup(o, &proc_data);
    if (rv) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    rv = str_to_gensio_accepter(argv[1], o, io_acc_event, NULL, &acc);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_acc_set_sync(acc);
    if (rv) {
	fprintf(stderr, "Could not set acceptor %s sync: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_acc_startup(acc);
    if (rv) {
	fprintf(stderr, "Could not start %s: %s\n", argv[1],
		gensio_err_to_str(rv));
	goto out_err;
    }

    for (;;) {
	rv = gensio_acc_accept_s(acc, NULL, &io);
	if (rv) {
	    fprintf(stderr, "Could not accept %s: %s\n", argv[1],
		    gensio_err_to_str(rv));
	    goto out_err;
	}

	rv = gensio_set_sync(io);
	if (rv) {
	    fprintf(stderr, "Could not set io sync: %s\n",
		    gensio_err_to_str(rv));
	    goto out_err;
	}

	if (process_data(io)) {
	    io = NULL;
	    break;
	}

	io = NULL;
    }

 out_err:
    if (io) {
	gensio_close_s(io);
	gensio_free(io);
    }
    if (acc) {
	gensio_acc_shutdown_s(acc);
	gensio_acc_free(acc);
    }
    gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(o);

    return !!rv;
}
