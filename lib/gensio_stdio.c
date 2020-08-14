/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/* This code handles stdio stream I/O. */

#include "config.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_builtins.h>

#include "utils.h"

static int gensio_stdio_func(struct gensio *io, int func, gensiods *count,
			     const void *cbuf, gensiods buflen, void *buf,
			     const char *const *auxdata);

struct stdiona_data;

struct stdion_channel {
    struct stdiona_data *nadata;

    int infd;
    int outfd;

    /* Are the above fds registered with set_fd_handlers()? */
    bool in_handler_set;
    bool out_handler_set;

    /* Mark if these file are regular file, needing special handling. */
    bool infd_regfile;
    bool outfd_regfile;

    unsigned int refcount;

    struct gensio *io;

    gensiods max_read_size;
    unsigned char *read_data;
    gensiods data_pending_len;
    gensiods data_pos;

    struct stdiona_data *stdiona;

    bool read_enabled;
    bool xmit_enabled;
    bool in_read;
    bool deferred_read;
    bool in_write_ready;
    bool write_pending;
    bool deferred_write;

    bool in_open;
    gensio_done_err open_done;
    void *open_data;

    /* For the client only. */
    bool in_close; /* A close is pending the running running. */
    bool deferred_close;
    bool closed;
    gensio_done close_done;
    void *close_data;

    bool in_free;

    /*
     * Used to run read callbacks from the selector to avoid running
     * it directly from user calls.
     */
    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;
};

struct stdiona_data {
    struct gensio_lock *lock;

    struct gensio_os_funcs *o;

    bool stderr_to_stdout;
    bool noredir_stderr;

    unsigned int refcount;

    int argc;
    const char **argv;
    const char **env;

    struct gensio_runner *connect_runner;
    bool in_connect_runner;

    struct gensio_timer *waitpid_timer;

    int old_flags_ostdin;
    int old_flags_ostdout;
    bool old_flags_ostdin_set;
    bool old_flags_ostdout_set;

    /* For the accepter only. */
    bool in_free;
    bool in_shutdown;
    bool enabled;
    bool in_startup;
    gensio_acc_done shutdown_done;
    void *shutdown_data;

    /* exit code from the sub-program, after close. */
    int exit_code;
    bool exit_code_set;
    unsigned int waitpid_retries;

    /*
     * If non-zero, this is the PID of the other process and we are
     * in client mode.
     */
    pid_t opid;

    struct stdion_channel io; /* stdin, stdout */
    struct stdion_channel err; /* stderr */

    /* If we are in a final close, this is the channel that did it. */
    struct stdion_channel *closing_chan;

    struct gensio_accepter *acc;
};

static void i_stdion_fd_cleared(int fd, struct stdiona_data *nadata,
				struct stdion_channel *schan);

static void
stdiona_lock(struct stdiona_data *nadata)
{
    nadata->o->lock(nadata->lock);
}

static void
stdiona_unlock(struct stdiona_data *nadata)
{
    nadata->o->unlock(nadata->lock);
}

static void
stdiona_finish_free(struct stdiona_data *nadata)
{
    if (nadata->argv)
	gensio_argv_free(nadata->o, nadata->argv);
    if (nadata->env)
	gensio_argv_free(nadata->o, nadata->env);
    if (nadata->io.deferred_op_runner)
	nadata->o->free_runner(nadata->io.deferred_op_runner);
    if (nadata->err.deferred_op_runner)
	nadata->o->free_runner(nadata->err.deferred_op_runner);
    if (nadata->connect_runner)
	nadata->o->free_runner(nadata->connect_runner);
    if (nadata->io.read_data)
	nadata->o->free(nadata->o, nadata->io.read_data);
    if (nadata->waitpid_timer)
	nadata->o->free_timer(nadata->waitpid_timer);
    if (nadata->err.read_data)
	nadata->o->free(nadata->o, nadata->err.read_data);
    if (nadata->lock)
	nadata->o->free_lock(nadata->lock);
    if (nadata->io.io)
	gensio_data_free(nadata->io.io);
    if (nadata->err.io)
	gensio_data_free(nadata->err.io);
    if (nadata->acc)
	gensio_acc_data_free(nadata->acc);
    nadata->o->free(nadata->o, nadata);
}

static void
stdiona_ref(struct stdiona_data *nadata)
{
    assert(nadata->refcount > 0);
    nadata->refcount++;
}

static void
stdiona_deref(struct stdiona_data *nadata)
{
    assert(nadata->refcount > 1);
    nadata->refcount--;
}

static void
stdiona_deref_and_unlock(struct stdiona_data *nadata)
{
    assert(nadata->refcount > 0);
    if (--nadata->refcount == 0) {
	stdiona_unlock(nadata);
	stdiona_finish_free(nadata);
    } else {
	stdiona_unlock(nadata);
    }	
}

static int
stdion_write(struct gensio *io, gensiods *count,
	     const struct gensio_sg *sg, gensiods sglen)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    return gensio_os_write(nadata->o, schan->infd, sg, sglen, count);
}

/* Must be called with nadata->lock held */
static void
stdion_finish_read(struct stdion_channel *schan, int err)
{
    struct stdiona_data *nadata = schan->nadata;
    struct gensio *io = schan->io;
    gensiods count;

    if (err) {
	/* Do this here so the user can modify it. */
	stdiona_lock(nadata);
	schan->read_enabled = false;
	if (!schan->outfd_regfile)
	    nadata->o->set_read_handler(nadata->o, schan->outfd, false);
	stdiona_unlock(nadata);
	gensio_cb(io, GENSIO_EVENT_READ, err, NULL, NULL, NULL);
    } else if (schan->data_pending_len) {
    retry:
	count = schan->data_pending_len;
	gensio_cb(io, GENSIO_EVENT_READ, err,
		  schan->read_data + schan->data_pos, &count, NULL);
	stdiona_lock(nadata);
	if (!err && count < schan->data_pending_len) {
	    /* The user didn't consume all the data. */
	    schan->data_pending_len -= count;
	    schan->data_pos += count;
	    if (!schan->closed && schan->read_enabled) {
		stdiona_unlock(nadata);
		goto retry;
	    }
	} else {
	    schan->data_pending_len = 0;
	}
    }

    schan->in_read = false;

    if (schan->read_enabled && !schan->outfd_regfile)
	nadata->o->set_read_handler(nadata->o, schan->outfd, true);
    stdiona_unlock(nadata);
}

static void
check_waitpid(struct stdion_channel *schan)
{
    struct stdiona_data *nadata = schan->nadata;

    if (nadata->closing_chan)
	schan = nadata->closing_chan;
    if (nadata->opid != -1 && !nadata->io.out_handler_set &&
		!nadata->io.in_handler_set && !nadata->err.out_handler_set) {
	pid_t rv;

	rv = waitpid(nadata->opid, &nadata->exit_code, WNOHANG);
	if (rv < 0)
	    /* FIXME = no real way to report this. */
	    ;

	if (rv == 0) {
	    gensio_time timeout = { 0, 10000000 };

	    nadata->waitpid_retries++;
	    /* The sub-process has not died, wait a bit and try again. */
	    stdiona_ref(nadata);
	    nadata->o->start_timer(nadata->waitpid_timer, &timeout);
	    nadata->closing_chan = schan;
	    return;
	}

	nadata->exit_code_set = true;
	nadata->opid = -1;
    }

    if (schan->close_done) {
	gensio_done close_done = schan->close_done;
	void *close_data = schan->close_data;

	schan->in_close = false;
	schan->close_done = NULL;

	stdiona_unlock(nadata);
	close_done(schan->io, close_data);
	stdiona_lock(nadata);

	if (schan->in_free && schan->io) {
	    gensio_data_free(schan->io);
	    schan->io = NULL;
	}
    }
}

static void
check_waitpid_timeout(struct gensio_timer *t, void *cb_data)
{
    struct stdion_channel *schan = cb_data;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    check_waitpid(schan);
    stdiona_deref_and_unlock(nadata);
}

/*
 * Note that we do callbacks from this function, it must be called
 * from a handler or deferred op and not from a user call.
 */
static void
stdion_start_close(struct stdion_channel *schan)
{
    struct stdiona_data *nadata = schan->nadata;

    schan->read_enabled = false;
    schan->xmit_enabled = false;
    if (schan->outfd_regfile)
	i_stdion_fd_cleared(schan->outfd, nadata, schan);
    else
	nadata->o->clear_fd_handlers(nadata->o, schan->outfd);

    if (schan->infd != -1) {
	if (schan->infd_regfile)
	    i_stdion_fd_cleared(schan->infd, nadata, schan);
	else
	    nadata->o->clear_fd_handlers(nadata->o, schan->infd);
    }
}

static int
stdion_do_read(struct stdiona_data *nadata, struct stdion_channel *schan)
{
    int rv;

 retry:
    rv = read(schan->outfd, schan->read_data, schan->max_read_size);
    if (rv < 0) {
	if (errno == EINTR)
	    goto retry;
	if (errno == EAGAIN || errno == EWOULDBLOCK)
	    rv = 0; /* Pretend like nothing happened. */
	else
	    rv = gensio_os_err_to_err(nadata->o, errno);
    } else if (rv == 0) {
	rv = GE_REMCLOSE;
    } else {
	schan->data_pending_len = rv;
	schan->data_pos = 0;
	rv = 0;
    }

    return rv;
}

static void
stdion_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;
    struct gensio *io = schan->io;

    stdiona_lock(nadata);
 restart:
    if (schan->in_open) {
	if (schan->open_done) {
	    stdiona_unlock(nadata);
	    schan->open_done(io, 0, schan->open_data);
	    stdiona_lock(nadata);
	}
	schan->in_open = false;
	if (schan->outfd_regfile) {
	    if (schan->read_enabled) {
		schan->in_read = true;
		schan->deferred_read = true;
	    }
	} else {
	    nadata->o->set_read_handler(nadata->o, schan->outfd,
					schan->read_enabled);
	}
	if (schan->infd_regfile) {
	    schan->deferred_write = schan->xmit_enabled;
	} else if (schan->infd != -1) {
	    nadata->o->set_write_handler(nadata->o, schan->infd,
					 schan->xmit_enabled);
	    nadata->o->set_except_handler(nadata->o, schan->infd,
					  schan->xmit_enabled);
	}
    }

    if (schan->deferred_write) {
	/* This can only happen if infd_regfile == true. */
	schan->deferred_write = false;
	while (schan->xmit_enabled) {
	    stdiona_unlock(nadata);
	    gensio_cb(schan->io, GENSIO_EVENT_WRITE_READY, 0, NULL, NULL, NULL);
	    stdiona_lock(nadata);
	}
    }

    if (schan->deferred_read) {
	int err;

	schan->deferred_read = false;
    redo_read:
	err = 0;
	if (schan->outfd_regfile && !schan->data_pending_len)
	    err = stdion_do_read(nadata, schan);
	stdiona_unlock(nadata);
	stdion_finish_read(schan, err);
	stdiona_lock(nadata);
	if (schan->outfd_regfile && schan->read_enabled)
	    goto redo_read;
    }

    if (schan->deferred_close) {
	schan->deferred_close = false;
	stdion_start_close(schan);
    }

    if (schan->deferred_read || schan->in_open || schan->deferred_write)
	goto restart;

    schan->deferred_op_pending = false;

    stdiona_deref_and_unlock(nadata);
}

static void
stdion_start_deferred_op(struct stdion_channel *schan)
{
    if (!schan->deferred_op_pending) {
	/* Call the read from the selector to avoid lock nesting issues. */
	schan->deferred_op_pending = true;
	schan->nadata->o->run(schan->deferred_op_runner);
	stdiona_ref(schan->nadata);
    }
}

static void
i_stdion_fd_cleared(int fd, struct stdiona_data *nadata,
		    struct stdion_channel *schan)
{
    if (fd == schan->infd) {
	schan->in_handler_set = false;
	schan->infd = -1;
    } else if (fd == schan->outfd) {
	schan->out_handler_set = false;
	schan->outfd = -1;
    } else {
	assert(false);
    }

    if (fd > 2) /* Don't close stdin, stdout, or stderr. */
	close(fd);

    if (schan->in_close && !schan->in_handler_set && !schan->out_handler_set) {
	if (schan == &nadata->io && !nadata->err.out_handler_set &&
		nadata->err.outfd != -1) {
	    /* The stderr channel is not open, so close the fd. */
	    close(nadata->err.outfd);
	    nadata->err.outfd = -1;
	}
	check_waitpid(schan);
    }
}

static void
stdion_fd_cleared(int fd, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    i_stdion_fd_cleared(fd, nadata, schan);
    stdiona_deref_and_unlock(nadata);
}

static void
stdion_set_read_callback_enable(struct gensio *io, bool enabled)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (schan->closed || !schan->io)
	goto out_unlock;
    schan->read_enabled = enabled;
    if (schan->in_read || schan->in_open ||
			(schan->data_pending_len && !enabled)) {
	/* Nothing to do, let the read handling wake things up. */
    } else if (schan->data_pending_len || (enabled && schan->outfd_regfile)) {
	schan->deferred_read = true;
	schan->in_read = true;
	stdion_start_deferred_op(schan);
    } else if (schan->outfd_regfile) {
	/* Nothing to do here. */
    } else {
	nadata->o->set_read_handler(nadata->o, schan->outfd, enabled);
    }
 out_unlock:
    stdiona_unlock(nadata);
}

static void
stdion_set_write_callback_enable(struct gensio *io, bool enabled)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (schan->closed || schan->infd == -1)
	goto out_unlock;
    if (schan->xmit_enabled == enabled)
	goto out_unlock;
    schan->xmit_enabled = enabled;
    if (schan->in_open)
	goto out_unlock;
    if (schan->infd_regfile) {
	if (enabled) {
	    schan->deferred_write = true;
	    stdion_start_deferred_op(schan);
	} else {
	    schan->deferred_write = false;
	}
    } else {
	    nadata->o->set_write_handler(nadata->o, schan->infd, enabled);
	    nadata->o->set_except_handler(nadata->o, schan->infd, enabled);
    }
 out_unlock:
    stdiona_unlock(nadata);
}

static void
stdion_read_ready(int fd, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (!schan->read_enabled || schan->in_read || schan->data_pending_len) {
	stdiona_unlock(nadata);
	return;
    }
    if (!schan->outfd_regfile)
	nadata->o->set_read_handler(nadata->o, schan->outfd, false);
    schan->in_read = true;
    stdiona_unlock(nadata);

    stdion_finish_read(schan, stdion_do_read(nadata, schan));
}

static void
stdion_write_ready(int fd, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (schan->in_write_ready) {
	schan->write_pending = true;
	goto out;
    }
    schan->in_write_ready = true;
 retry:
    stdiona_unlock(nadata);
    gensio_cb(schan->io, GENSIO_EVENT_WRITE_READY, 0, NULL, NULL, NULL);
    stdiona_lock(nadata);
    if (schan->write_pending) {
	schan->write_pending = false;
	if (schan->xmit_enabled)
	    goto retry;
    }
    schan->in_write_ready = false;
 out:
    stdiona_unlock(nadata);
}

static void
stdion_write_except_ready(int fd, void *cbdata)
{
    stdion_write_ready(fd, cbdata);
}

extern char **environ;

static int
setup_child_proc(struct stdiona_data *nadata)
{
    int err;
    int stdinpipe[2] = {-1, -1};
    int stdoutpipe[2] = {-1, -1};
    int stderrpipe[2] = {-1, -1};

    err = pipe(stdinpipe);
    if (err) {
	err = errno;
	goto out_err;
    }

    err = pipe(stdoutpipe);
    if (err) {
	err = errno;
	goto out_err;
    }

    nadata->io.infd = stdinpipe[1];
    nadata->io.outfd = stdoutpipe[0];
    if (fcntl(nadata->io.infd, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	goto out_err;
    }
    if (fcntl(nadata->io.outfd, F_SETFL, O_NONBLOCK) == -1) {
	err = errno;
	goto out_err;
    }

    nadata->err.infd = -1;

    if (nadata->stderr_to_stdout) {
	nadata->err.outfd = stdoutpipe[0];
	stderrpipe[0] = stdoutpipe[0];
	stderrpipe[1] = stdoutpipe[1];
    } else if (nadata->noredir_stderr) {
	nadata->err.outfd = -1;
    } else {
	err = pipe(stderrpipe);
	if (err) {
	    err = errno;
	    goto out_err;
	}
	nadata->err.outfd = stderrpipe[0];
	if (fcntl(nadata->err.outfd, F_SETFL, O_NONBLOCK) == -1) {
	    err = errno;
	    goto out_err;
	}
    }

    nadata->opid = fork();
    if (nadata->opid < 0) {
	err = errno;
	goto out_err;
    }
    if (nadata->opid == 0) {
	int i, openfiles = sysconf(_SC_OPEN_MAX);

	dup2(stdinpipe[0], 0);
	dup2(stdoutpipe[1], 1);
	if (!nadata->noredir_stderr)
	    dup2(stderrpipe[1], 2);

	/* Close everything but stdio. */
	for (i = 3; i < openfiles; i++)
	    close(i);

	err = gensio_os_setupnewprog();
	if (err) {
	    fprintf(stderr, "Unable to set groups or user: %s\r\n",
		    strerror(err));
	    exit(1);
	}

	if (nadata->env)
	    environ = (char **) nadata->env;

	execvp(nadata->argv[0], (char * const *) nadata->argv);
	fprintf(stderr, "Err: %s %s\r\n", nadata->argv[0], strerror(errno));
	exit(1); /* Only reached on error. */
    }

    close(stdinpipe[0]);
    close(stdoutpipe[1]);
    if (stdoutpipe[1] != stderrpipe[1])
	close(stderrpipe[1]);
    return 0;

 out_err:
    if (stdinpipe[0] != -1)
	close(stdinpipe[0]);
    if (stdinpipe[1] != -1)
	close(stdinpipe[1]);
    if (stdoutpipe[0] != -1)
	close(stdoutpipe[0]);
    if (stdoutpipe[1] != -1)
	close(stdoutpipe[1]);
    if (stderrpipe[0] != -1 && stderrpipe[0] != stdoutpipe[0])
	close(stderrpipe[0]);
    if (stderrpipe[1] != -1 && stderrpipe[1] != stdoutpipe[1])
	close(stderrpipe[1]);

    return gensio_os_err_to_err(nadata->o, err);
}

static int
setup_io_self(struct stdiona_data *nadata)
{
    int rv;
    struct stat statb;

    /*
     * Figure out if the files are regular files.  If they are, they
     * are handled differently.
     */
    rv = fstat(nadata->io.infd, &statb);
    if (rv == -1) {
	rv = gensio_os_err_to_err(nadata->o, errno);
	goto out_err;
    }
    nadata->io.infd_regfile = (statb.st_mode & S_IFMT) == S_IFREG;

    rv = fstat(nadata->io.outfd, &statb);
    if (rv == -1) {
	rv = gensio_os_err_to_err(nadata->o, errno);
	goto out_err;
    }
    nadata->io.outfd_regfile = (statb.st_mode & S_IFMT) == S_IFREG;

    /*
     * If these are not regular files, save off the old flags and turn
     * on non-blocking.
     */
    if (!nadata->io.infd_regfile) {
	rv = fcntl(nadata->io.infd, F_GETFL, 0);
	if (rv == -1) {
	    rv = gensio_os_err_to_err(nadata->o, errno);
	    goto out_err;
	}
	nadata->old_flags_ostdin = rv;
	if (fcntl(nadata->io.infd, F_SETFL, O_NONBLOCK) == -1) {
	    rv = gensio_os_err_to_err(nadata->o, errno);
	    goto out_err;
	}
	nadata->old_flags_ostdin_set = true;
    }

    if (!nadata->io.outfd_regfile) {
	rv = fcntl(nadata->io.outfd, F_GETFL, 0);
	if (rv == -1) {
	    rv = gensio_os_err_to_err(nadata->o, errno);
	    goto out_err;
	}
	nadata->old_flags_ostdout = rv;

	if (fcntl(nadata->io.outfd, F_SETFL, O_NONBLOCK) == -1) {
	    rv = gensio_os_err_to_err(nadata->o, errno);
	    goto out_err;
	}
	nadata->old_flags_ostdout_set = true;
    }
    rv = 0;

 out_err:
    if (rv && nadata->old_flags_ostdin_set) {
	fcntl(nadata->io.infd, F_SETFL, nadata->old_flags_ostdin);
	nadata->old_flags_ostdin_set = false;
    }
    return rv;
}

static void
cleanup_io_self(struct stdiona_data *nadata)
{
    if (nadata->old_flags_ostdin_set)
	fcntl(nadata->io.infd, F_SETFL, nadata->old_flags_ostdin);
    nadata->old_flags_ostdin_set = false;
    if (nadata->old_flags_ostdout_set)
	fcntl(nadata->io.outfd, F_SETFL, nadata->old_flags_ostdout);
    nadata->old_flags_ostdout_set = false;
    if (nadata->io.out_handler_set)
	nadata->o->clear_fd_handlers_norpt(nadata->o, nadata->io.outfd);
    nadata->io.out_handler_set = false;
    if (nadata->io.in_handler_set)
	nadata->o->clear_fd_handlers_norpt(nadata->o, nadata->io.infd);
    nadata->io.in_handler_set = false;
}

static int
stdion_open(struct gensio *io, gensio_done_err open_done, void *open_data)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    int err;

    stdiona_lock(nadata);

    if (!schan->closed || schan->in_close) {
	err = GE_NOTREADY;
	goto out_unlock;
    }

    if (schan == &nadata->io) {
	if (nadata->argv && schan == &nadata->io)
	    err = setup_child_proc(nadata);
	else
	    err = setup_io_self(nadata);
	if (err)
	    goto out_err;
    }

    if (!schan->outfd_regfile) {
	err = nadata->o->set_fd_handlers(nadata->o, schan->outfd, schan,
					 stdion_read_ready, NULL, NULL,
					 stdion_fd_cleared);
	if (err)
	    goto out_err;
	schan->out_handler_set = true;
	stdiona_ref(nadata);
    }

    if (!schan->infd_regfile && schan->infd != -1) {
	/*
	 * On the write side we send an exception to the write ready
	 * operation.
	 */
	err = nadata->o->set_fd_handlers(nadata->o, schan->infd, schan,
					 NULL, stdion_write_ready,
					 stdion_write_except_ready,
					 stdion_fd_cleared);
	if (err)
	    goto out_err_deref;
	schan->in_handler_set = true;
	stdiona_ref(nadata);
    }

    schan->closed = false;
    schan->in_open = true;
    schan->open_done = open_done;
    schan->open_data = open_data;
    stdion_start_deferred_op(schan);
    stdiona_unlock(nadata);

    return 0;

 out_err_deref:
    stdiona_deref(nadata);
 out_err:
    cleanup_io_self(nadata);
    if (nadata->io.infd != -1 && nadata->io.infd != 1)
	close(nadata->io.infd);
    nadata->io.infd = -1;
    if (nadata->io.outfd != -1 && nadata->io.outfd != 0)
	close(nadata->io.outfd);
    nadata->io.outfd = -1;
    if (nadata->err.outfd != -1 && nadata->err.outfd != 2 &&
		nadata->err.outfd != nadata->io.outfd)
	close(nadata->err.outfd);
    nadata->err.outfd = -1;
 out_unlock:
    stdiona_unlock(nadata);

    return err;
}

static int
stdion_alloc_channel(struct gensio *io, const char * const args[],
		    gensio_event cb, void *user_data,
		    struct gensio **new_io)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    int rv = 0;
    unsigned int i;
    gensiods max_read_size = nadata->io.max_read_size;

    if (nadata->stderr_to_stdout || nadata->noredir_stderr)
	return GE_INVAL;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return GE_INVAL;
    }

    stdiona_lock(nadata);
    if (io != nadata->io.io) {
	rv = GE_INVAL;
	goto out_err;
    }
    if (nadata->err.outfd == -1) {
	rv = GE_NOTFOUND;
	goto out_err;
    }
    if (nadata->err.io) {
	rv = GE_INUSE;
	goto out_err;
    }

    nadata->err.max_read_size = max_read_size;
    nadata->err.read_data = nadata->o->zalloc(nadata->o, max_read_size);
    if (!nadata->err.read_data) {
	rv = GE_NOMEM;
	goto out_err;
    }
    nadata->err.data_pending_len = 0;
    nadata->err.data_pos = 0;
    nadata->err.read_enabled = false;
    nadata->err.xmit_enabled = false;

    nadata->err.io = gensio_data_alloc(nadata->o, cb, user_data,
				       gensio_stdio_func,
				       NULL, "stderr", &nadata->err);
    if (!nadata->err.io) {
	nadata->o->free(nadata->o, nadata->err.read_data);
	nadata->err.read_data = NULL;
	rv = GE_NOMEM;
	goto out_err;
    }
    stdiona_ref(nadata);

    *new_io = nadata->err.io;

 out_err:
    stdiona_unlock(nadata);

    return rv;
}

static void
i_stdion_close(struct stdion_channel *schan,
	       gensio_done close_done, void *close_data)
{
    schan->closed = true;
    schan->in_close = true;
    schan->close_done = close_done;
    schan->close_data = close_data;

    /*
     * Always run this in the deferred handler, it simplifies issues with
     * handling regular file shutdown.
     */
    schan->deferred_close = true;
    stdion_start_deferred_op(schan);
}

static int
stdion_close(struct gensio *io, gensio_done close_done, void *close_data)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    int err = 0;

    stdiona_lock(nadata);
    if (schan->closed || schan->in_close)
	err = GE_NOTREADY;
    else
	i_stdion_close(schan, close_done, close_data);
    stdiona_unlock(nadata);

    return err;
}

static void
stdion_free(struct gensio *io)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    assert(schan->refcount > 0);
    if (--schan->refcount > 0) {
	stdiona_unlock(nadata);
	return;
    }
    schan->in_free = true;
    if (schan->in_close) {
	schan->close_done = NULL;
	stdiona_unlock(nadata);
    } else if (schan->closed) {
	gensio_data_free(schan->io);
	schan->io = NULL;
	stdiona_deref_and_unlock(nadata);
    } else {
	i_stdion_close(schan, NULL, NULL);
	stdiona_unlock(nadata);
    }
}

static void
stdion_ref(struct gensio *io)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    assert(schan->refcount > 0);
    schan->refcount++;
    stdiona_unlock(nadata);
}

static int
stdion_disable(struct gensio *io)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;

    if (!nadata->argv)
	return GE_NOTSUP;

    stdiona_lock(nadata);
    schan->closed = true;
    schan->in_close = false;
    schan->in_open = false;
    schan->close_done = NULL;
    if (nadata->io.out_handler_set) {
	nadata->o->clear_fd_handlers_norpt(nadata->o, nadata->io.outfd);
	if (nadata->io.outfd != 0)
	    close(nadata->io.outfd);
	nadata->io.outfd = -1;
    }
    if (nadata->io.in_handler_set) {
	nadata->o->clear_fd_handlers_norpt(nadata->o, nadata->io.infd);
	if (nadata->io.infd != 1)
	    close(nadata->io.infd);
	nadata->io.infd = -1;
    }
    if (nadata->err.out_handler_set) {
	nadata->o->clear_fd_handlers_norpt(nadata->o, nadata->err.outfd);
	close(nadata->err.outfd);
	nadata->err.outfd = -1;
    }
    stdiona_deref_and_unlock(nadata); /* unlocks */
    return 0;
}

static int
stdion_control(struct gensio *io, bool get, unsigned int option,
	       char *data, gensiods *datalen)
{
    struct stdion_channel *schan = gensio_get_gensio_data(io);
    struct stdiona_data *nadata = schan->nadata;
    const char **env, **argv;
    int err, status;
    gensiods pos;

    switch (option) {
    case GENSIO_CONTROL_ENVIRONMENT:
	if (get)
	    return GE_NOTSUP;
	err = gensio_argv_copy(nadata->o, (const char **) data, NULL, &env);
	if (err)
	    return err;
	if (nadata->env)
	    gensio_argv_free(nadata->o, nadata->env);
	nadata->env = env;
	return 0;

    case GENSIO_CONTROL_ARGS:
	if (get)
	    return GE_NOTSUP;
	err = gensio_argv_copy(nadata->o, (const char **) data, NULL, &argv);
	if (err)
	    return err;
	if (nadata->argv)
	    gensio_argv_free(nadata->o, nadata->argv);
	nadata->argv = argv;
	return 0;

    case GENSIO_CONTROL_EXIT_CODE:
	if (!get)
	    return GE_NOTSUP;
	if (!nadata->exit_code_set)
	    return GE_NOTREADY;
	*datalen = snprintf(data, *datalen, "%d", nadata->exit_code);
	return 0;

    case GENSIO_CONTROL_WAIT_TASK:
	if (!get)
	    return GE_NOTSUP;
	if (nadata->opid == -1)
	    return GE_NOTREADY;
	err = waitpid(nadata->opid, &status, WNOHANG | WNOWAIT);
	if (err <= 0)
	    return GE_NOTREADY;
	*datalen = snprintf(data, *datalen, "%d", status);
	return 0;

    case GENSIO_CONTROL_CLOSE_OUTPUT:
	if (get)
	    return GE_NOTSUP;
	err = 0;
	stdiona_lock(nadata);
	if (schan->infd == -1) {
	    err = GE_NOTREADY;
	} else {
	    nadata->o->clear_fd_handlers(nadata->o, schan->infd);
	    schan->infd = -1;
	}
	stdiona_unlock(nadata);
	return err;

    case GENSIO_CONTROL_RADDR:
	if (!get)
	    return GE_NOTSUP;
	pos = 0;
	if (io == nadata->io.io)
	    gensio_pos_snprintf(data, *datalen, &pos, "stdio");
	else
	    gensio_pos_snprintf(data, *datalen, &pos, "stderr");
	if (nadata->argv) {
	    gensio_pos_snprintf(data, *datalen, &pos, ",");
	    gensio_argv_snprintf(data, *datalen, &pos, nadata->argv);
	} else {
	    gensio_pos_snprintf(data, *datalen, &pos, "(self)");
	}
	*datalen = pos;
	return 0;

    case GENSIO_CONTROL_REMOTE_ID:
	if (!get)
	    return GE_NOTSUP;
	*datalen = snprintf(data, *datalen, "%d", nadata->opid);
	return 0;
    }

    return GE_NOTSUP;
}

static int
gensio_stdio_func(struct gensio *io, int func, gensiods *count,
		  const void *cbuf, gensiods buflen, void *buf,
		  const char *const *auxdata)
{
    switch (func) {
    case GENSIO_FUNC_WRITE_SG:
	return stdion_write(io, count, cbuf, buflen);

    case GENSIO_FUNC_OPEN:
	return stdion_open(io, cbuf, buf);

    case GENSIO_FUNC_CLOSE:
	return stdion_close(io, cbuf, buf);

    case GENSIO_FUNC_FREE:
	stdion_free(io);
	return 0;

    case GENSIO_FUNC_REF:
	stdion_ref(io);
	return 0;

    case GENSIO_FUNC_SET_READ_CALLBACK:
	stdion_set_read_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_SET_WRITE_CALLBACK:
	stdion_set_write_callback_enable(io, buflen);
	return 0;

    case GENSIO_FUNC_ALLOC_CHANNEL:
    {
	struct gensio_func_alloc_channel_data *d = buf;
	return stdion_alloc_channel(io, d->args, d->cb, d->user_data,
				    &d->new_io);
    }

    case GENSIO_FUNC_DISABLE:
	return stdion_disable(io);

    case GENSIO_FUNC_CONTROL:
	return stdion_control(io, *((bool *) cbuf), buflen, buf, count);

    default:
	return GE_NOTSUP;
    }
}

static int
stdio_nadata_setup(struct gensio_os_funcs *o, gensiods max_read_size,
		   struct stdiona_data **new_nadata)
{
    struct stdiona_data *nadata;

    nadata = o->zalloc(o, sizeof(*nadata));
    if (!nadata)
	return GE_NOMEM;
    nadata->o = o;
    nadata->refcount = 1;
    nadata->io.refcount = 1;
    nadata->err.refcount = 1;
    nadata->io.closed = true;
    nadata->err.closed = true;
    nadata->io.nadata = nadata;
    nadata->err.nadata = nadata;
    nadata->io.infd = -1;
    nadata->io.outfd = -1;
    nadata->io.infd = -1;
    nadata->io.outfd = -1;
    nadata->opid = -1;

    nadata->waitpid_timer = o->alloc_timer(o, check_waitpid_timeout,
					   &nadata->io);
    if (!nadata->waitpid_timer)
	goto out_nomem;

    nadata->io.max_read_size = max_read_size;
    nadata->io.read_data = o->zalloc(o, max_read_size);
    if (!nadata->io.read_data)
	goto out_nomem;

    nadata->io.deferred_op_runner = o->alloc_runner(o, stdion_deferred_op,
						    &nadata->io);
    if (!nadata->io.deferred_op_runner)
	goto out_nomem;

    nadata->err.deferred_op_runner = o->alloc_runner(o, stdion_deferred_op,
						     &nadata->err);
    if (!nadata->err.deferred_op_runner)
	goto out_nomem;

    nadata->lock = o->alloc_lock(o);
    if (!nadata->lock)
	goto out_nomem;

    *new_nadata = nadata;

    return 0;

 out_nomem:
    stdiona_finish_free(nadata);

    return GE_NOMEM;
}

int
stdio_gensio_alloc(const char * const argv[], const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **new_gensio)
{
    int err;
    struct stdiona_data *nadata = NULL;
    int i;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    bool self= false;
    bool stderr_to_stdout = false;
    bool noredir_stderr = false;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "self", &self) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "stderr-to-stdout",
				 &stderr_to_stdout) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "noredir-stderr",
				 &noredir_stderr) > 0)
	    continue;
	return GE_INVAL;
    }

    err = stdio_nadata_setup(o, max_read_size, &nadata);
    if (err)
	return err;

    nadata->stderr_to_stdout = stderr_to_stdout;
    nadata->noredir_stderr = noredir_stderr;

    if (self) {
	nadata->io.infd = 1;
	nadata->io.outfd = 0;
    } else {
	err = gensio_argv_copy(o, argv, NULL, &nadata->argv);
	if (err)
	    goto out_nomem;
    }

    nadata->io.io = gensio_data_alloc(nadata->o, cb, user_data,
				      gensio_stdio_func, NULL, "stdio",
				      &nadata->io);
    if (!nadata->io.io)
	goto out_nomem;
    gensio_set_is_client(nadata->io.io, true);
    gensio_set_is_reliable(nadata->io.io, true);

    *new_gensio = nadata->io.io;

    return 0;

 out_nomem:
    stdiona_finish_free(nadata);
    return GE_NOMEM;
}

int
str_to_stdio_gensio(const char *str, const char * const args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **new_gensio)
{
    int err;
    const char **argv;

    err = gensio_str_to_argv(o, str, NULL, &argv, NULL);
    if (!err) {
	err = stdio_gensio_alloc(argv, args, o, cb, user_data, new_gensio);
	gensio_argv_free(o, argv);
    }
    return err;
}

static void
stdiona_do_connect(struct gensio_runner *runner, void *cbdata)
{
    struct stdiona_data *nadata = cbdata;

    stdiona_lock(nadata);
 retry:
    if (nadata->in_startup) {
	nadata->in_startup = false;
	stdiona_unlock(nadata);
	gensio_acc_cb(nadata->acc, GENSIO_ACC_EVENT_NEW_CONNECTION,
		      nadata->io.io);
	stdiona_lock(nadata);
    }

    if (nadata->in_shutdown) {
	nadata->in_shutdown = false;
	stdiona_unlock(nadata);
	if (nadata->shutdown_done)
	    nadata->shutdown_done(nadata->acc, nadata->shutdown_data);
	stdiona_lock(nadata);
    }

    if (nadata->in_startup || nadata->in_shutdown)
	goto retry;

    nadata->in_connect_runner = false;
    stdiona_deref_and_unlock(nadata); /* unlocks */
}

/*
 * fd cleared for a gensio from an acceptor only.
 */
static void
stdiona_fd_cleared(int fd, void *cbdata)
{
    struct stdion_channel *schan = cbdata;
    struct stdiona_data *nadata = schan->nadata;

    stdiona_lock(nadata);
    if (fd == schan->infd)
	schan->in_handler_set = false;
    else
	schan->out_handler_set = false;

    if (!nadata->io.in_handler_set && !nadata->io.out_handler_set) {
	/* We came from an acceptor, set stdio back to original values. */
	fcntl(nadata->io.infd, F_SETFL, nadata->old_flags_ostdin);
	fcntl(nadata->io.outfd, F_SETFL, nadata->old_flags_ostdout);
    }

    if (!schan->in_handler_set && !schan->out_handler_set && schan->in_close) {
	schan->in_close = false;
	if (schan->close_done) {
	    gensio_done close_done = schan->close_done;
	    void *close_data = schan->close_data;

	    schan->close_done = NULL;

	    stdiona_unlock(nadata);
	    close_done(schan->io, close_data);
	    stdiona_lock(nadata);
	}
    }

    /* Lose the refcount we got when we added the fd handler. */
    stdiona_deref_and_unlock(nadata); /* unlocks */
}

static int
stdiona_startup(struct gensio_accepter *accepter)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    stdiona_lock(nadata);
    if (nadata->in_free || nadata->in_shutdown) {
	rv = GE_NOTREADY;
	goto out_unlock;
    }

    if (nadata->enabled) {
	rv = GE_INUSE;
	goto out_unlock;
    }

    rv = setup_io_self(nadata);
    if (rv)
	goto out_unlock;

    rv = nadata->o->set_fd_handlers(nadata->o, nadata->io.infd,
				    &nadata->io, NULL, stdion_write_ready, NULL,
				    stdiona_fd_cleared);
    if (rv)
	goto out_err;
    nadata->io.in_handler_set = true;
    stdiona_ref(nadata);

    rv = nadata->o->set_fd_handlers(nadata->o, nadata->io.outfd,
				    &nadata->io, stdion_read_ready, NULL, NULL,
				    stdiona_fd_cleared);
    if (rv)
	goto out_err;
    nadata->io.out_handler_set = true;
    stdiona_ref(nadata);

    nadata->io.closed = false;
    nadata->in_startup = true;
    nadata->enabled = true;
    if (!nadata->in_connect_runner) {
	stdiona_ref(nadata);
	nadata->in_connect_runner = true;
	nadata->o->run(nadata->connect_runner);
    }
    stdiona_ref(nadata); /* One for the gensio. */

 out_unlock:
    stdiona_unlock(nadata);
    return rv;

 out_err:
    cleanup_io_self(nadata);
    goto out_unlock;
}

static int
stdiona_shutdown(struct gensio_accepter *accepter,
		 gensio_acc_done shutdown_done, void *shutdown_data)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    stdiona_lock(nadata);
    if (nadata->in_free) {
	rv = GE_NOTREADY;
    } else if (nadata->in_shutdown || !nadata->enabled) {
	rv = GE_NOTREADY;
    } else {
	nadata->in_shutdown = true;
	nadata->enabled = false;
	nadata->shutdown_done = shutdown_done;
	nadata->shutdown_data = shutdown_data;
	if (!nadata->in_connect_runner) {
	    stdiona_ref(nadata);
	    nadata->in_connect_runner = true;
	    nadata->o->run(nadata->connect_runner);
	}
    }
    stdiona_unlock(nadata);

    return rv;
}

struct stdiona_waiters {
    struct gensio_os_funcs *o;
    struct stdiona_data *nadata;
    gensio_acc_done done;
    void *done_data;
    struct gensio_runner *runner;
};

static void
waiter_runner_cb(struct gensio_runner *runner, void *cb_data)
{
    struct stdiona_waiters *w = cb_data;

    w->done(w->nadata->acc, w->done_data);
    w->o->free_runner(w->runner);

    stdiona_lock(w->nadata);
    stdiona_deref_and_unlock(w->nadata);

    w->o->free(w->o, w);
}

static int
stdiona_set_accept_callback_enable(struct gensio_accepter *accepter,
				   bool enabled,
				   gensio_acc_done done, void *done_data)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);
    int rv = 0;

    if (done) {
	struct gensio_os_funcs *o = nadata->o;
	struct stdiona_waiters *w = o->zalloc(o, sizeof(*w));

	if (!w)
	    rv = GE_NOMEM;
	else {
	    w->o = o;
	    w->done = done;
	    w->done_data = done_data;
	    w->nadata = nadata;
	    w->runner = o->alloc_runner(o, waiter_runner_cb, w);
	    if (!w->runner) {
		o->free(o, w);
		rv = GE_NOMEM;
	    } else {
		stdiona_ref(nadata);
		o->run(w->runner);
	    }
	}
    }

    return rv;
}

static void
stdiona_free(struct gensio_accepter *accepter)
{
    struct stdiona_data *nadata = gensio_acc_get_gensio_data(accepter);

    stdiona_lock(nadata);
    nadata->in_free = true;
    stdiona_deref_and_unlock(nadata);
}

static int
gensio_acc_stdio_func(struct gensio_accepter *acc, int func, int val,
		      const char *addr, void *done, void *data,
		      const void *data2, void *ret)
{
    switch (func) {
    case GENSIO_ACC_FUNC_STARTUP:
	return stdiona_startup(acc);

    case GENSIO_ACC_FUNC_SHUTDOWN:
	return stdiona_shutdown(acc, done, data);

    case GENSIO_ACC_FUNC_SET_ACCEPT_CALLBACK:
	return stdiona_set_accept_callback_enable(acc, val, done, data);

    case GENSIO_ACC_FUNC_FREE:
	stdiona_free(acc);
	return 0;

    case GENSIO_ACC_FUNC_STR_TO_GENSIO:
    default:
	return GE_NOTSUP;
    }
}

int
stdio_gensio_accepter_alloc(const char * const args[],
			    struct gensio_os_funcs *o,
			    gensio_accepter_event cb, void *user_data,
			    struct gensio_accepter **accepter)
{
    int err;
    struct stdiona_data *nadata = NULL;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    int i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return GE_INVAL;
    }

    err = stdio_nadata_setup(o, max_read_size, &nadata);
    if (err)
	return err;

    nadata->connect_runner = o->alloc_runner(o, stdiona_do_connect, nadata);
    if (!nadata->connect_runner) {
	stdiona_finish_free(nadata);
	return GE_NOMEM;
    }

    nadata->io.infd = 1;
    nadata->io.outfd = 0;

    nadata->acc = gensio_acc_data_alloc(o, cb, user_data, gensio_acc_stdio_func,
					NULL, "stdio", nadata);
    if (!nadata->acc) {
	stdiona_finish_free(nadata);
	return GE_NOMEM;
    }
    gensio_acc_set_is_reliable(nadata->acc, true);

    nadata->io.io = gensio_data_alloc(nadata->o, NULL, NULL, gensio_stdio_func,
				      NULL, "stdio", &nadata->io);
    if (!nadata->io.io) {
	stdiona_finish_free(nadata);
	return GE_NOMEM;
    }

    *accepter = nadata->acc;
    return 0;
}

int
str_to_stdio_gensio_accepter(const char *str, const char * const args[],
			     struct gensio_os_funcs *o,
			     gensio_accepter_event cb,
			     void *user_data,
			     struct gensio_accepter **acc)
{
    return stdio_gensio_accepter_alloc(args, o, cb, user_data, acc);
}
