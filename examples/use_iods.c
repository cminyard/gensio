/*
 * Copyright 2023 Corey Minyard
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This example shows using threads and IODs (IO Descriptors) directly
 * along with using.  This will echo whatever you type.  It does not
 * put stdio into raw mode, you can just type ^D (^Z on Windows) to
 * exit.
 *
 * This program create a pipe with IODs for the read and write, and
 * then opens a stdio gensio.  When data comes in stdio, it will be
 * written to the pipe.  It will then read the data from the read side
 * of the pipe and write it to stdout.
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

    /* Wait to stop the second thread. */
    struct gensio_waiter *thread2_waiter;

    /* IODs for the pipe. */
    struct gensio_iod *readpipe_iod;
    struct gensio_iod *writepipe_iod;

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
    ci->close_count = 2;
    ci->o->clear_fd_handlers(ci->readpipe_iod);
    ci->o->clear_fd_handlers(ci->writepipe_iod);
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
 out:
    gensio_os_funcs_unlock(ci->o, ci->close_lock);
}

static void pipe_read(struct gensio_iod *iod, void *cb_data)
{
    struct coninfo *ci = cb_data;
    gensiods len, i;
    int rv;

    gensio_os_funcs_lock(ci->o, ci->to_stdout_lock);
    if (ci->to_stdout_len > 0 || ci->closing) {
	/* Just in case. */
	ci->o->set_read_handler(iod, false);
	goto out;
    }

    rv = ci->o->read(ci->readpipe_iod, ci->to_stdout,
		     sizeof(ci->to_stdout), &len);
    if (rv) {
	if (rv != GE_REMCLOSE)
	    fprintf(stderr, "Error from read pipe: %s\n",
		    gensio_err_to_str(rv));
	start_close(ci, rv);
	goto out;
    }

    if (len == 0)
	goto out;

    ci->to_stdout_len = len;
    ci->to_stdout_pos = 0;

    /*
     * There are two basic ways you can handle this.  You can write
     * inside this function, as shown in the ifdef below.  In that
     * case, you *must* handle a partial write.  If you get a partial
     * write, then you have to turn off the read handling, turn on the
     * write handler on the write side and let the write complete.
     */
#if 1
    rv = gensio_write(ci->io, &i, ci->to_stdout, len, NULL);
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
	ci->o->set_read_handler(iod, false);
    }
#else
    /*
     * The other way to handle this, shown here, is to just enable the
     * write handler and let it handle the output.  This is simpler
     * and leaves less code that only occasionally gets run.  But it
     * is less performant.
     */
    gensio_set_write_callback_enable(ci->io, true);
    ci->o->set_read_handler(iod, false);
#endif

 out:
    gensio_os_funcs_unlock(ci->o, ci->to_stdout_lock);
}

static void pipe_write(struct gensio_iod *iod, void *cb_data)
{
    struct coninfo *ci = cb_data;
    int rv;
    struct gensio_sg sg;
    gensiods len;

    gensio_os_funcs_lock(ci->o, ci->to_pipe_lock);
    if (ci->to_pipe_len == 0 || ci->closing) {
	/* Just in case. */
	ci->o->set_write_handler(iod, false);
	goto out;
    }

    sg.buf = ci->to_pipe + ci->to_pipe_pos;
    sg.buflen = ci->to_pipe_len;
    rv = ci->o->write(ci->writepipe_iod, &sg, 1, &len);
    if (rv) {
	if (rv != GE_REMCLOSE)
	    fprintf(stderr, "Error from write pipe: %s\n",
		    gensio_err_to_str(rv));
	start_close(ci, rv);
	goto out;
    }

    ci->to_pipe_len -= len;
    ci->to_pipe_pos += len;
    if (ci->to_pipe_len == 0) {
	gensio_set_read_callback_enable(ci->io, true);
	ci->o->set_write_handler(iod, false);
    }
 out:
    gensio_os_funcs_unlock(ci->o, ci->to_pipe_lock);
}

/* Called after the pipe is shut down when all the callbacks are complete. */
static void pipe_clear(struct gensio_iod *iod, void *cb_data)
{
    struct coninfo *ci = cb_data;

    gensio_os_funcs_lock(ci->o, ci->close_lock);
    i_close_done(ci);
    gensio_os_funcs_unlock(ci->o, ci->close_lock);
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
	ci->o->set_write_handler(ci->writepipe_iod, true);
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
	    ci->o->set_read_handler(ci->readpipe_iod, true);
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

    ci->o->set_read_handler(ci->readpipe_iod, true);

    /*
     * Nothing else can happen until we enable this.  So no lock is
     * required.
     */
    gensio_set_read_callback_enable(ci->io, true);
}

static void
thread2(void *data)
{
    struct coninfo *ci = data;

    gensio_os_funcs_wait(ci->o, ci->thread2_waiter, 1, NULL);
}

int
main(int argc, char *argv[])
{
    int rv;
    struct coninfo ci;
    struct gensio_os_proc_data *proc_data = NULL;
    struct gensio_thread *tid2 = NULL;
#ifdef _WIN32
    HANDLE rpipe, wpipe;
#else
    int rpipe, wpipe;
    int pipes[2] = { -1, -1 };
#endif

    memset(&ci, 0, sizeof(ci));

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

    ci.thread2_waiter = gensio_os_funcs_alloc_waiter(ci.o);
    if (!ci.thread2_waiter) {
	rv = GE_NOMEM;
	fprintf(stderr, "Could not thread2 waiter, out of memory\n");
	goto out_err;
    }

    rv = gensio_os_new_thread(ci.o, thread2, &ci, &tid2);
    if (rv == GE_NOTSUP) {
	/* No thread support */
    } else if (rv) {
	fprintf(stderr, "Could not allocate thread 2: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }

#ifdef _WIN32
    #define close_pipe CloseHandle
    if (!CreatePipe(&rpipe, &wpipe, NULL, 0)) {
	fprintf(stderr, "Unable to create the pipes.\n");
	goto out_err;
    }
#else
    #define close_pipe close
    rv = pipe(pipes);
    if (rv == -1) {
	perror("pipe");
	goto out_err;
    }
    rpipe = pipes[0];
    wpipe = pipes[1];
#endif

    rv = ci.o->add_iod(ci.o, GENSIO_IOD_PIPE, (intptr_t) rpipe,
		       &ci.readpipe_iod, GENSIO_IOD_READABLE);
    if (rv) {
	fprintf(stderr, "Could not allocate readpipe iod: %s\n",
		gensio_err_to_str(rv));
	close_pipe(rpipe);
	close_pipe(wpipe);
	goto out_err;
    }
    /*
     * There is no need to set the except handler for this.  It's only
     * required for things that have "exceptional" data, like urgent
     * data on TCP.  If an error occurs, the read handler will be
     * called and the I/O operation will do an error.
     */
    rv = ci.o->set_fd_handlers(ci.readpipe_iod, &ci, pipe_read,
			       NULL, NULL, pipe_clear);
    if (rv) {
	fprintf(stderr, "Could not set readpipe handlers: %s\n",
		gensio_err_to_str(rv));
	close_pipe(rpipe);
	close_pipe(wpipe);
	goto out_err;
    }

    rv = ci.o->add_iod(ci.o, GENSIO_IOD_PIPE, (intptr_t) wpipe,
		       &ci.writepipe_iod, GENSIO_IOD_WRITEABLE);
    if (rv) {
	fprintf(stderr, "Could not allocate writepipe iod: %s\n",
		gensio_err_to_str(rv));
	close_pipe(wpipe);
	goto out_clear;
    }
    rv = ci.o->set_fd_handlers(ci.writepipe_iod, &ci, NULL,
			       pipe_write, NULL, pipe_clear);
    if (rv) {
	fprintf(stderr, "Could not set writepipe handlers: %s\n",
		gensio_err_to_str(rv));
	close_pipe(wpipe);
	goto out_clear;
    }

    rv = str_to_gensio("stdio(self)", ci.o, io_event, &ci, &ci.io);
    if (rv) {
	fprintf(stderr, "Could not allocate stdio: %s\n",
		gensio_err_to_str(rv));
	goto out_clear;
    }

    rv = gensio_open(ci.io, open_done, &ci);
    if (rv) {
	fprintf(stderr, "Could not open stdio: %s\n",
		gensio_err_to_str(rv));
	goto out_clear;
    }

    rv = gensio_os_funcs_wait(ci.o, ci.waiter, 1, NULL);

    goto out_err;

 out_clear:
    /*
     * The iods have their handlers set, but have not been started.
     * We can use the norpt clear to clear it since they haven't been
     * enabled.
     */
    if (ci.readpipe_iod)
	ci.o->clear_fd_handlers_norpt(ci.readpipe_iod);
    if (ci.writepipe_iod)
	ci.o->clear_fd_handlers_norpt(ci.readpipe_iod);

 out_err:
    if (tid2) {
	gensio_os_funcs_wake(ci.o, ci.thread2_waiter);
	gensio_os_wait_thread(tid2);
    }
    if (ci.readpipe_iod)
	ci.o->close(&ci.readpipe_iod);

    if (ci.writepipe_iod)
	ci.o->close(&ci.writepipe_iod);

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
