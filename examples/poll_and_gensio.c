/*
 * Copyright 2023 Corey Minyard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This example shows using poll() along with gensio in separate
 * threads.  This will echo whatever you type.  It does not put stdio
 * into raw mode, you can just type ^D (^Z on Windows) to exit.
 *
 * This program create a pipe and a thread to handle the pipe that
 * interacts with the gensio data. write, and then opens a stdio
 * gensio.  When data comes in stdio, it will be written to the pipe.
 * It will then read the data from the read side of the pipe and write
 * it to stdout.
 *
 * This is a threaded program, and has mutexes to protect the data
 * structures that are shared.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gensio/gensio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#endif

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

    /* The gensio for stdio. */
    struct gensio *io;

    /* Used to wake up the main thread when the close is complete. */
    struct gensio_waiter *waiter;

#ifdef _WIN32
    HANDLE readpipe, writepipe;
    HANDLE wakepipe_in, wakepipe_out;
#else
    int readpipe, writepipe;
    int wakepipe_in, wakepipe_out;
#endif

    /* Used to transfer data from stdin to the pipe. */
    struct gensio_lock *to_pipe_lock;
    unsigned char to_pipe[128];
    gensiods to_pipe_pos;
    gensiods to_pipe_len;

    /* Used to transfer data from the pipe to stdout. */
    struct gensio_lock *to_stdout_lock;
    unsigned char to_stdout[128];
    gensiods to_stdout_pos;
    gensiods to_stdout_len;

    /* Various things to make shutdown clean. */
    struct gensio_lock *close_lock;
    bool closing;
    unsigned int close_count;
    int err;
};

/* Must be called with close_lock held. */
static void
i_close_done(struct coninfo *ci)
{
    ci->close_count--;
    if (ci->close_count == 0)
	gensio_os_funcs_wake(ci->o, ci->waiter);
}

static void
close_done(struct gensio *io, void *close_data)
{
    struct coninfo *ci = close_data;

    gensio_os_funcs_lock(ci->o, ci->close_lock);
    i_close_done(ci);
    gensio_os_funcs_unlock(ci->o, ci->close_lock);
}

static void start_close(struct coninfo *ci, int err)
{
    int rv;

    gensio_os_funcs_lock(ci->o, ci->close_lock);
    if (ci->closing)
	goto out;

    ci->closing = true;
    if (err != GE_REMCLOSE)
	ci->err = err;
    ci->close_count = 0;
    if (ci->io) {
	ci->close_count++;
	rv = gensio_close(ci->io, close_done, ci);
	if (rv) {
	    if (!ci->err)
		ci->err = rv;
	    fprintf(stderr, "Error closing io: %s\n", gensio_err_to_str(rv));
	    i_close_done(ci);
	}
    }
    if (ci->close_count == 0)
	gensio_os_funcs_wake(ci->o, ci->waiter);
 out:
    gensio_os_funcs_unlock(ci->o, ci->close_lock);
}

static void
wake_pipe_thread(struct coninfo *ci)
{
    char dummy = 0;

    write(ci->wakepipe_out, &dummy, 1);
}

static int
io_event(struct gensio *io, void *user_data, int event, int err,
	 unsigned char *buf, gensiods *buflen,
	 const char *const *auxdata)
{
    struct coninfo *ci = user_data;
    gensiods i;
    int rv;

    switch (event) {
    case GENSIO_EVENT_READ:
	if (ci->closing) {
	    gensio_set_read_callback_enable(ci->io, false);
	    return 0;
	}

	gensio_os_funcs_lock(ci->o, ci->to_pipe_lock);
	if (err) {
	    if (err != GE_REMCLOSE)
		fprintf(stderr, "Error from stdio: %s\n",
			gensio_err_to_str(err));
	    start_close(ci, err);
	    goto out_read_done;
	}

	if (ci->to_pipe_len > 0) {
	    /* Just in case */
	    gensio_set_read_callback_enable(ci->io, false);
	    *buflen = 0;
	    goto out_read_done;
	}

	/*
	 * We can only handle so much data, tell the caller what we
	 * are handling.
	 */
	if (*buflen > sizeof(ci->to_pipe))
	    *buflen = sizeof(ci->to_pipe);

	memcpy(ci->to_pipe, buf, *buflen);
	ci->to_pipe_len = *buflen;
	ci->to_pipe_pos = 0;

	/*
	 * Like the pipe_read() function, you could do the write to
	 * the pipe here, but you would need to handle if the write
	 * was incomplete.  See that function for details.  We take
	 * the simple path here.
	 */
	gensio_set_read_callback_enable(ci->io, false);
	wake_pipe_thread(ci);
    out_read_done:
	gensio_os_funcs_unlock(ci->o, ci->to_pipe_lock);
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	if (ci->closing) {
	    gensio_set_write_callback_enable(ci->io, false);
	    return 0;
	}

	gensio_os_funcs_lock(ci->o, ci->to_stdout_lock);
	if (ci->to_stdout_len == 0) {
	    /* Just in case */
	    gensio_set_write_callback_enable(ci->io, false);
	    goto out_write_done;
	}

	rv = gensio_write(ci->io, &i, ci->to_stdout + ci->to_stdout_pos,
			  ci->to_stdout_len, NULL);
	if (rv) {
	    if (rv != GE_REMCLOSE) {
		fprintf(stderr, "Error writing to io: %s\n",
			gensio_err_to_str(rv));
		gensio_set_write_callback_enable(ci->io, false);
		start_close(ci, rv);
		goto out_write_done;
	    }
	}

	ci->to_stdout_len -= i;
	ci->to_stdout_pos += i;
	if (ci->to_stdout_len == 0) {
	    gensio_set_write_callback_enable(ci->io, false);
	    wake_pipe_thread(ci);
	}
    out_write_done:
	gensio_os_funcs_unlock(ci->o, ci->to_stdout_lock);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static void
open_done(struct gensio *io, int err, void *open_data)
{
    struct coninfo *ci = open_data;

    if (err) {
	gensio_free(ci->io);
	ci->io = NULL;
	start_close(ci, err);
	return;
    }

    /*
     * Nothing else can happen until we enable this.  So no lock is
     * required.
     */
    gensio_set_read_callback_enable(ci->io, true);
}

static void pipe_read(struct coninfo *ci)
{
    gensiods i;
    ssize_t rv;

    gensio_os_funcs_lock(ci->o, ci->to_stdout_lock);
    if (ci->to_stdout_len != 0 || ci->closing)
	goto out;

    rv = read(ci->readpipe, ci->to_stdout, sizeof(ci->to_stdout));
    if (rv <= 0) {
	if (rv != 0) {
	    if (errno == EAGAIN)
		goto out;
	    fprintf(stderr, "Error from read pipe: %s\n", strerror(errno));
	}
	start_close(ci, rv);
	goto out;
    }

    ci->to_stdout_len = rv;
    ci->to_stdout_pos = 0;

    /*
     * There are two basic ways you can handle this.  You can write
     * inside this function, as shown in the ifdef below.  In that
     * case, you *must* handle a partial write.  If you get a partial
     * write, then you have to turn off the read handling, turn on the
     * write handler on the write side and let the write complete.
     */
#if 1
    rv = gensio_write(ci->io, &i, ci->to_stdout, ci->to_stdout_len, NULL);
    if (rv) {
	if (rv != GE_REMCLOSE)
	    fprintf(stderr, "Error writing to io: %s\n",
		    gensio_err_to_str(rv));
	start_close(ci, rv);
	goto out;
    }

    ci->to_stdout_len -= i;
    ci->to_stdout_pos += i;

    if (ci->to_stdout_len > 0) {
	/* All data not written, switch on the write processing. */
	gensio_set_write_callback_enable(ci->io, true);
    }
#else
    /*
     * The other way to handle this, shown here, is to just enable the
     * write handler and let it handle the output.  This is simpler
     * and leaves less code that only occasionally gets run.  But it
     * is less performant.
     */
    gensio_set_write_callback_enable(ci->io, true);
#endif

 out:
    gensio_os_funcs_unlock(ci->o, ci->to_stdout_lock);
}

static void pipe_write(struct coninfo *ci)
{
    int rv;

    gensio_os_funcs_lock(ci->o, ci->to_pipe_lock);
    if (ci->to_pipe_len == 0 || ci->closing)
	goto out;

    rv = write(ci->writepipe, ci->to_pipe + ci->to_pipe_pos, ci->to_pipe_len);
    if (rv < 0) {
	if (errno == EAGAIN)
	    goto out;
	fprintf(stderr, "Error from write pipe: %s\n", strerror(errno));
	start_close(ci, rv);
	goto out;
    }

    ci->to_pipe_len -= rv;
    ci->to_pipe_pos += rv;
    if (ci->to_pipe_len == 0)
	gensio_set_read_callback_enable(ci->io, true);
 out:
    gensio_os_funcs_unlock(ci->o, ci->to_pipe_lock);
}

static void
pipe_thread(void *data)
{
    struct coninfo *ci = data;
    struct pollfd fds[3];
    char dummy;
    int rv;

    fds[0].fd = ci->readpipe;
    fds[1].fd = ci->writepipe;
    fds[2].fd = ci->wakepipe_in;

    gensio_os_funcs_lock(ci->o, ci->close_lock); /* Needed for barriers. */
    while (!ci->closing) {
	gensio_os_funcs_unlock(ci->o, ci->close_lock);

	gensio_os_funcs_lock(ci->o, ci->to_stdout_lock);
	if (ci->to_stdout_len == 0)
	    fds[0].events = POLLIN;
	else
	    fds[0].events = 0;
	gensio_os_funcs_unlock(ci->o, ci->to_stdout_lock);
	gensio_os_funcs_lock(ci->o, ci->to_pipe_lock);
	if (ci->to_pipe_len > 0)
	    fds[1].events = POLLOUT;
	else
	    fds[1].events = 0;
	gensio_os_funcs_unlock(ci->o, ci->to_pipe_lock);

	fds[2].events = POLLIN;
	fds[0].revents = 0;
	fds[1].revents = 0;
	fds[2].revents = 0;

	rv = poll(fds, 3, -1);
	if (rv < 0) {
	    rv = errno;
	    fprintf(stderr, "Error from poll: %s\n", strerror(rv));
	    start_close(ci, gensio_os_err_to_err(ci->o, rv));
	}

	if (fds[0].events)
	    pipe_read(ci);
	if (fds[1].events)
	    pipe_write(ci);
	if (fds[2].events)
	    read(ci->wakepipe_in, &dummy, 1);

	gensio_os_funcs_lock(ci->o, ci->close_lock);
    }
    gensio_os_funcs_unlock(ci->o, ci->close_lock);
}

int
main(int argc, char *argv[])
{
    int rv;
    struct coninfo ci;
    struct gensio_os_proc_data *proc_data = NULL;
    struct gensio_thread *pipe_tid = NULL;
#ifdef _WIN32
#define INVALID_PIPE INVALID_HANDLE_VALUE
#else
#define INVALID_PIPE -1
    int pipes[2];
#endif

    memset(&ci, 0, sizeof(ci));
    ci.readpipe = INVALID_PIPE;
    ci.writepipe = INVALID_PIPE;
    ci.wakepipe_in = INVALID_PIPE;
    ci.wakepipe_out = INVALID_PIPE;

    rv = gensio_default_os_hnd(GENSIO_DEF_WAKE_SIG, &ci.o);
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

    ci.to_pipe_lock = gensio_os_funcs_alloc_lock(ci.o);
    if (!ci.to_pipe_lock) {
	rv = GE_NOMEM;
	goto out_err;
    }

    ci.to_stdout_lock = gensio_os_funcs_alloc_lock(ci.o);
    if (!ci.to_stdout_lock) {
	rv = GE_NOMEM;
	goto out_err;
    }

    ci.close_lock = gensio_os_funcs_alloc_lock(ci.o);
    if (!ci.close_lock) {
	rv = GE_NOMEM;
	goto out_err;
    }

    ci.waiter = gensio_os_funcs_alloc_waiter(ci.o);
    if (!ci.waiter) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not waiter, out of memory\n");
	goto out_err;
    }

    rv = gensio_os_new_thread(ci.o, pipe_thread, &ci, &pipe_tid);
    if (rv) {
	fprintf(stderr, "Could not allocate pipe thread: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }

#ifdef _WIN32
    #define close_pipe CloseHandle
    if (!CreatePipe(&ci.readpipe, &ci.writepipe, NULL, 0)) {
	fprintf(stderr, "Unable to create the pipes.\n");
	goto out_err;
    }
    if (!CreatePipe(&ci.wakepipe_in, &ci.wakepipe_out, NULL, 0)) {
	fprintf(stderr, "Unable to create the wake pipes.\n");
	goto out_err;
    }
#else
    #define close_pipe close
    rv = pipe(pipes);
    if (rv == -1) {
	perror("pipe");
	goto out_err;
    }
    ci.readpipe = pipes[0];
    ci.writepipe = pipes[1];

    rv = pipe(pipes);
    if (rv == -1) {
	perror("pipe");
	goto out_err;
    }
    ci.wakepipe_in = pipes[0];
    ci.wakepipe_out = pipes[1];

    if (fcntl(ci.readpipe, F_SETFL, O_NONBLOCK) == -1) {
	perror("fcntl O_NONBLOCK");
	goto out_err;
    }
    if (fcntl(ci.writepipe, F_SETFL, O_NONBLOCK) == -1) {
	perror("fcntl O_NONBLOCK");
	goto out_err;
    }
    if (fcntl(ci.wakepipe_in, F_SETFL, O_NONBLOCK) == -1) {
	perror("fcntl O_NONBLOCK");
	goto out_err;
    }
    if (fcntl(ci.wakepipe_out, F_SETFL, O_NONBLOCK) == -1) {
	perror("fcntl O_NONBLOCK");
	goto out_err;
    }
#endif

    rv = str_to_gensio("stdio(self)", ci.o, io_event, &ci, &ci.io);
    if (rv) {
	fprintf(stderr, "Could not allocate stdio: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_open(ci.io, open_done, &ci);
    if (rv) {
	fprintf(stderr, "Could not open stdio: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }

    rv = gensio_os_funcs_wait(ci.o, ci.waiter, 1, NULL);

 out_err:
    if (pipe_tid) {
	ci.closing = true;
	wake_pipe_thread(&ci);
	gensio_os_wait_thread(pipe_tid);
    }

    if (ci.wakepipe_in != INVALID_PIPE)
	close_pipe(ci.wakepipe_in);
    if (ci.wakepipe_out != INVALID_PIPE)
	close_pipe(ci.wakepipe_out);
    if (ci.readpipe != INVALID_PIPE)
	close_pipe(ci.readpipe);
    if (ci.writepipe != INVALID_PIPE)
	close_pipe(ci.writepipe);

    if (ci.io)
	gensio_free(ci.io);
    if (ci.waiter)
	gensio_os_funcs_free_waiter(ci.o, ci.waiter);
    if (ci.to_pipe_lock)
	gensio_os_funcs_free_lock(ci.o, ci.to_pipe_lock);
    if (ci.to_stdout_lock)
	gensio_os_funcs_free_lock(ci.o, ci.to_stdout_lock);
    if (ci.close_lock)
	gensio_os_funcs_free_lock(ci.o, ci.close_lock);
    gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_free(ci.o);

    if (!rv)
	rv = ci.err;

    return !!rv;
}
