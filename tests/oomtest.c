/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

/*
 * This is a test program that uses the memory allocation failure
 * capabilities of the gensio_selector tool to cause allocation
 * failures over different location.
 *
 * It creates a local connection then spawns gensiot to connect
 * to/from the local connection, transfers some data, and quits.  Then
 * it shuts down the connection.  It does this while causing a memory
 * allocation failure successive times until to memory failure is
 * reached.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <sys/wait.h>
#include <gensio/gensio.h>

struct oom_tests {
    const char *connecter;
    const char *accepter;
} oom_tests[] = {
    { "ssl(CA=ca/CA.pem),tcp,localhost,",
      "ssl(key=ca/key.pem,cert=ca/cert.pem),tcp,0" },
    { "mux,sctp,localhost,", "mux,sctp,0" },
    { "serialdev,/dev/ttyEcho0,115200", NULL },
    { "udp,localhost,", "udp,0" },
    { "sctp,localhost,", "sctp,0" },
    { "telnet(rfc2217),tcp,localhost,", "telnet(rfc2217),tcp,0" },
    { "telnet,tcp,localhost,", "telnet,tcp,0" },
    { "stdio,cat", NULL },
    { "echo", NULL },
    { "tcp,localhost,", "tcp,0" },
    { NULL }
};

bool verbose;
bool debug;

static struct gensio_os_funcs *o;
static char *gensiot;
static bool got_sigchild;
static sigset_t waitsigs;

static void
handle_sigchld(int sig)
{
    got_sigchild = true;
}

static void
handle_sigusr1(int sig)
{
}

char *
alloc_vsprintf(const char *fmt, va_list va)
{
    va_list va2;
    int len;
    char c[1], *str;

    va_copy(va2, va);
    len = vsnprintf(c, 0, fmt, va);
    str = malloc(len + 1);
    if (str)
	vsnprintf(str, len + 1, fmt, va2);
    va_end(va2);
    return str;
}

char *
alloc_sprintf(const char *fmt, ...)
{
    va_list va;
    char *s;

    va_start(va, fmt);
    s = alloc_vsprintf(fmt, va);
    va_end(va);
    return s;
}

static void *
gensio_loop(void *info)
{
    struct gensio_waiter *closewaiter = info;

    o->wait(closewaiter, 1, NULL);
    return NULL;
}

static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    if (!debug)
	return;
    printf("gensio %s log: ", gensio_log_level_to_str(level));
    vprintf(log, args);
    printf("\n");
}

#define OOME_CLIENT_DIDNT_TERMINATE	GE_USER_ERR_START + 0
#define OOME_READ_OVERFLOW		GE_USER_ERR_START + 1
#define OOME_DATA_MISMATCH		GE_USER_ERR_START + 2
#define OOME_NO_PORT			GE_USER_ERR_START + 3

static const char *
oom_err_to_str(int err)
{
    switch(err) {
    case OOME_CLIENT_DIDNT_TERMINATE:
	return "client didn't terminate";

    case OOME_READ_OVERFLOW:
	return "read overflow";

    case OOME_DATA_MISMATCH:
	return "data mismatch";

    case OOME_NO_PORT:
	return "no port in gensiot output";

    default:
	return gensio_err_to_str(err);
    }
}

struct oom_test_data;

struct io_test_data {
    struct gensio *io;
    gensiods write_pos;
    gensiods read_pos;
    struct oom_test_data *od;
    bool expect_close;
    bool got_end;
    int err;
    const char *iostr;
    bool in_write;
    bool in_read;
    bool close_done;
    bool open_done;
};

struct oom_test_data {
    struct gensio_accepter *acc;
    struct io_test_data ccon;
    struct io_test_data scon;
    struct gensio_waiter *waiter;

    bool ccon_exit_code_set;
    int ccon_exit_code;
    char ccon_stderr[2048];
    gensiods ccon_stderr_pos;
    struct gensio *ccon_stderr_io;
    bool stderr_expect_close;

    bool stderr_open_done;

    pthread_mutex_t lock;

    unsigned int port;
    bool look_for_port;
    bool invalid_port_data;
};

static char *iodata = "Hello There";
static gensiods iodata_size = 11;

static void
ccon_stderr_closed(struct gensio *io, void *close_data)
{
    struct oom_test_data *od = close_data;
    int rv;
    char intstr[10];
    gensiods size = sizeof(intstr);

    rv = gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST, true,
			GENSIO_CONTROL_EXIT_CODE, intstr, &size);
    assert(!debug || !rv);
    if (rv) {
	if (debug)
	    assert(0);
	od->ccon.err = rv;
    } else {
	od->ccon_exit_code = strtoul(intstr, NULL, 0);
	od->ccon_exit_code_set = true;
    }
    pthread_mutex_lock(&od->lock);
    od->ccon_stderr_io = NULL;
    o->wake(od->waiter);
    pthread_mutex_unlock(&od->lock);
    gensio_free(io);
}

static void
con_closed(struct gensio *io, void *close_data)
{
    struct io_test_data *id = close_data;
    struct oom_test_data *od = id->od;

    pthread_mutex_lock(&od->lock);
    id->io = NULL;
    o->wake(od->waiter);
    pthread_mutex_unlock(&od->lock);
    gensio_free(io);
}

static void
acc_closed(struct gensio_accepter *acc, void *close_data)
{
    struct oom_test_data *od = close_data;

    pthread_mutex_lock(&od->lock);
    od->acc = NULL;
    o->wake(od->waiter);
    pthread_mutex_unlock(&od->lock);
    gensio_acc_free(acc);
}

static int
con_cb(struct gensio *io, void *user_data,
       int event, int err,
       unsigned char *buf, gensiods *buflen,
       const char *const *auxdata)
{
    struct io_test_data *id = user_data;
    struct oom_test_data *od = id->od;
    gensiods count;
    int rv;

    assert(id->io == io);
    if (err) {
	assert(!debug || err == GE_REMCLOSE);
	pthread_mutex_lock(&od->lock);
	gensio_set_write_callback_enable(io, false);
	gensio_set_read_callback_enable(io, false);
	if (!id->expect_close || err != GE_REMCLOSE)
	    id->err = err;
	else
	    id->got_end = true;
	o->wake(od->waiter);
	pthread_mutex_unlock(&od->lock);
	return 0;
    }

    switch(event) {
    case GENSIO_EVENT_READ:
	assert(!id->in_read);
	id->in_read = true;
	pthread_mutex_lock(&od->lock);
	if (id->read_pos + *buflen > iodata_size) {
	    gensio_set_write_callback_enable(io, false);
	    gensio_set_read_callback_enable(io, false);
	    id->err = OOME_READ_OVERFLOW;
	    printf("  readpos = %ld, buflen = %ld, read '%s'\n",
		   (long) id->read_pos, (long) *buflen, buf);
	    assert(0);
	    o->wake(od->waiter);
	    goto out_leave_read;
	}

	if (memcmp(iodata + id->read_pos, buf, *buflen) != 0) {
	    gensio_set_write_callback_enable(io, false);
	    gensio_set_read_callback_enable(io, false);
	    id->err = OOME_DATA_MISMATCH;
	    o->wake(od->waiter);
	}

	id->read_pos += *buflen;
	if (id->read_pos >= iodata_size)
	    o->wake(od->waiter);
    out_leave_read:
	pthread_mutex_unlock(&od->lock);
	id->in_read = false;
	return 0;

    case GENSIO_EVENT_WRITE_READY:
	assert(!id->in_write);
	id->in_write = true;
	pthread_mutex_lock(&od->lock);
	if (id->write_pos < iodata_size) {
	    rv = gensio_write(io, &count, iodata, iodata_size - id->write_pos,
			      NULL);
	    if (rv) {
		gensio_set_write_callback_enable(io, false);
		gensio_set_read_callback_enable(io, false);
		if (rv == GE_SHUTDOWN || rv == GE_NOTREADY) {
		    if (debug)
			printf("Write on shutdown or not ready socket\n");
		    /* System should error out elsewhere. */
		} else {
		    assert(!debug || !rv || rv == GE_REMCLOSE);
		    id->err = rv;
		    o->wake(od->waiter);
		}
	    } else {
		id->write_pos += count;
	    }
	} else {
	    gensio_set_write_callback_enable(io, false);
	    o->wake(od->waiter);
	}
	pthread_mutex_unlock(&od->lock);
	id->in_write = false;
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
acc_cb(struct gensio_accepter *accepter,
       void *user_data, int event, void *data)
{
    struct gensio_loginfo *li;
    struct oom_test_data *od = user_data;

    switch(event) {
    case GENSIO_ACC_EVENT_NEW_CONNECTION:
	od->scon.io = data;
	gensio_set_callback(od->scon.io, con_cb, &od->scon);
	gensio_set_read_callback_enable(od->scon.io, true);
	gensio_set_write_callback_enable(od->scon.io, true);
	return 0;

    case GENSIO_ACC_EVENT_LOG:
	li = data;
	do_vlog(o, li->level, li->str, li->args);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int
ccon_stderr_cb(struct gensio *io, void *user_data,
	       int event, int err,
	       unsigned char *buf, gensiods *buflen,
	       const char *const *auxdata)
{
    struct oom_test_data *od = user_data;
    gensiods size;

    if (err) {
	gensio_set_read_callback_enable(io, false);
	if (!od->stderr_expect_close || err != GE_REMCLOSE)
	    od->ccon.err = err;
	o->wake(od->waiter);
	return 0;
    }

    switch(event) {
    case GENSIO_EVENT_READ:
	if (od->ccon_stderr_pos > sizeof(od->ccon_stderr) - 1)
	    return 0;

	size = *buflen;
	if (size > sizeof(od->ccon_stderr) - od->ccon_stderr_pos - 1)
	    size = sizeof(od->ccon_stderr) - od->ccon_stderr_pos - 1;
	memcpy(od->ccon_stderr + od->ccon_stderr_pos, buf, size);
	od->ccon_stderr_pos += size;
    more_data:
	if (od->look_for_port) {
	    bool done = false;
	    char *nl, *c;

	    od->ccon_stderr[od->ccon_stderr_pos] = '\0';
	    nl = strchr(od->ccon_stderr, '\n');
	    if (nl) {
		*nl = '\0';
		if (strcmp(od->ccon_stderr, "Done") == 0) {
		    done = true;
		} else if (od->port == 0) {
		    c = strrchr(od->ccon_stderr, ',');
		    if (!c || strncmp(od->ccon_stderr, "Address", 7) != 0) {
			if (debug)
			    printf("Bad gensio port output: %s\n",
				   od->ccon_stderr);
			od->invalid_port_data = true;
			o->wake(od->waiter);
			return 0;
		    } else {
			od->port = strtoul(c + 1, NULL, 0);
		    }
		}
		size = strlen(nl + 1);
		memmove(od->ccon_stderr, nl + 1, size);
		od->ccon_stderr_pos = size;
		if (done) {
		    od->look_for_port = false;
		    o->wake(od->waiter);
		}
		if (od->ccon_stderr_pos)
		    goto more_data;
	    }
	}
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static void
ccon_stderr_open_done(struct gensio *io, int err, void *open_data)
{
    struct oom_test_data *od = open_data;

    pthread_mutex_lock(&od->lock);
    od->stderr_open_done = true;
    if (err) {
	od->ccon.err = err;
	o->wake(od->waiter);
    } else {
	gensio_set_read_callback_enable(io, true);
    }
    pthread_mutex_unlock(&od->lock);
}

static void
scon_open_done(struct gensio *io, int err, void *open_data)
{
    struct oom_test_data *od = open_data;

    pthread_mutex_lock(&od->lock);
    od->scon.open_done = true;
    if (!od->scon.io)
	/* We can race with the open and a close. */
	goto out_unlock;
    if (err) {
	od->scon.err = err;
	o->wake(od->waiter);
	gensio_free(io);
	od->scon.io = NULL;
	goto out_unlock;
    }

    gensio_set_read_callback_enable(io, true);
    gensio_set_write_callback_enable(io, true);
 out_unlock:
    pthread_mutex_unlock(&od->lock);
}

static void
ccon_open_done(struct gensio *io, int err, void *open_data)
{
    struct oom_test_data *od = open_data;
    int rv;

    pthread_mutex_lock(&od->lock);
    od->ccon.open_done = true;
    if (!od->ccon.io)
	/* We can race with the open and a close. */
	goto out_unlock;
    if (err) {
	od->ccon.err = err;
	o->wake(od->waiter);
	gensio_free(io);
	od->ccon.io = NULL;
	goto out_unlock;
    }

    rv = gensio_alloc_channel(io, NULL, ccon_stderr_cb, od,
			      &od->ccon_stderr_io);
    assert(!debug || !rv || rv == GE_REMCLOSE);
    if (rv) {
	od->ccon.err = rv;
	o->wake(od->waiter);
	goto out_unlock;
    }

    rv = gensio_open(od->ccon_stderr_io, ccon_stderr_open_done, od);
    assert(!debug || !rv || rv == GE_REMCLOSE);
    if (rv) {
	gensio_free(od->ccon_stderr_io);
	od->ccon_stderr_io = NULL;
	od->ccon.err = rv;
	o->wake(od->waiter);
	goto out_unlock;
    }

    gensio_set_read_callback_enable(io, true);
    gensio_set_write_callback_enable(io, true);
 out_unlock:
    pthread_mutex_unlock(&od->lock);
}

static int
close_con(struct io_test_data *id, struct timeval *timeout)
{
    struct oom_test_data *od = id->od;
    int rv = 0;

    pthread_mutex_lock(&od->lock);
    id->close_done = true;
    if (!id->io)
	goto out_unlock;

    rv = gensio_close(id->io, con_closed, id);
    assert(!debug || !rv || rv == GE_REMCLOSE || rv == GE_NOTREADY);
    if (rv) {
	gensio_free(id->io);
	id->io = NULL;
	goto out_unlock;
    }
    while (id->io) {
	pthread_mutex_unlock(&od->lock);
	rv = o->wait_intr_sigmask(id->od->waiter, 1, timeout, &waitsigs);
	pthread_mutex_lock(&od->lock);
	if (rv == GE_TIMEDOUT && debug) {
	    printf("Waiting on timeout err B\n");
	    assert(0);
	}
	if (rv == GE_INTERRUPTED) {
	    rv = 0;
	    continue;
	}
	if (rv)
	    break;
    }
 out_unlock:
    pthread_mutex_unlock(&od->lock);
    return rv;
}

static int
run_oom_test(struct oom_tests *test, long count, int *exitcode, bool close_acc)
{
    struct oom_test_data od;
    int rv, err = 0;
    char intstr[30], *constr;
    gensiods size;
    struct timeval timeout = { 5, 0 };

    memset(&od, 0, sizeof(od));
    od.waiter = o->alloc_waiter(o);
    if (!od.waiter)
	return GE_NOMEM;
    od.ccon.od = &od;
    od.scon.od = &od;
    od.ccon.iostr = test->connecter;
    od.scon.iostr = test->accepter;
    pthread_mutex_init(&od.lock, NULL);

    if (count < 0) {
	rv = unsetenv("GENSIO_OOM_TEST");
    } else {
	snprintf(intstr, sizeof(intstr), "%ld ", count);
	rv = setenv("GENSIO_OOM_TEST", intstr, 1);
    }
    if (rv) {
	fprintf(stderr, "Unable to set environment properly\n");
	return gensio_os_err_to_err(o, errno);
    }

    if (test->accepter) {
	rv = str_to_gensio_accepter(test->accepter, o, acc_cb, &od, &od.acc);
	assert(!debug || !rv);
	if (rv)
	    goto out_err;

	rv = gensio_acc_startup(od.acc);
	assert(!debug || !rv);
	if (rv)
	    goto out_err;

	size = sizeof(intstr);
	strcpy(intstr, "0");
	rv = gensio_acc_control(od.acc, GENSIO_CONTROL_DEPTH_FIRST, true,
				GENSIO_ACC_CONTROL_LPORT, intstr, &size);
	assert(!debug || !rv);
	if (rv)
	    goto out_err;

	constr = alloc_sprintf("stdio, %s -i 'stdio(self)' '%s%s'",
			       gensiot, test->connecter, intstr);
    } else {
	constr = alloc_sprintf("stdio, %s -i 'stdio(self)' '%s'",
			       gensiot, test->connecter);
    }
    if (!constr) {
	rv = GE_NOMEM;
	goto out_err;
    }

    rv = str_to_gensio(constr, o, con_cb, &od.ccon, &od.ccon.io);
    assert(!debug || !rv);
    free(constr);
    if (rv)
	goto out_err;

    rv = gensio_open(od.ccon.io, ccon_open_done, &od);
    assert(!debug || !rv);
    if (rv)
	goto out_err;

    pthread_mutex_lock(&od.lock);
    for (;;) {
	pthread_mutex_unlock(&od.lock);
	rv = o->wait_intr_sigmask(od.waiter, 1, &timeout, &waitsigs);
	pthread_mutex_lock(&od.lock);
	if (debug && (rv == GE_TIMEDOUT || od.scon.err == OOME_READ_OVERFLOW ||
		      od.ccon.err == OOME_READ_OVERFLOW)) {
	    printf("Waiting on err A\n");
	    assert(0);
	}
	if (rv == GE_INTERRUPTED)
	    continue;
	if (rv) {
	    err = rv;
	    break;
	}
	if (od.ccon.err) {
	    err = od.ccon.err;
	    break;
	}
	if (od.scon.err) {
	    err = od.scon.err;
	    break;
	}
	if (od.ccon.write_pos >= iodata_size &&
		od.ccon.read_pos >= iodata_size &&
		(!od.scon.io ||
		 (od.scon.write_pos >= iodata_size &&
		  od.scon.read_pos >= iodata_size))) {
	    break;
	}
    }
    pthread_mutex_unlock(&od.lock);

    if (od.acc && close_acc) {
	rv = gensio_acc_shutdown(od.acc, acc_closed, &od);
	assert(!debug || !rv || rv == GE_REMCLOSE);
	if (rv) {
	    printf("Unable to shutdown accepter: %s\n",
		    gensio_err_to_str(rv));
	    if (!err)
		err = rv;
	} else {
	    pthread_mutex_lock(&od.lock);
	    while (od.acc) {
		pthread_mutex_unlock(&od.lock);
		rv = o->wait_intr_sigmask(od.waiter, 1, &timeout, &waitsigs);
		pthread_mutex_lock(&od.lock);
		if (rv == GE_TIMEDOUT && debug) {
		    printf("Waiting on timeout err C\n");
		    assert(0);
		}
		if (rv == GE_INTERRUPTED)
		    continue;
		if (rv) {
		    if (!err)
			err = rv;
		    break;
		}
	    }
	    pthread_mutex_unlock(&od.lock);
	}
    }
    if (od.acc) {
	gensio_acc_free(od.acc);
	od.acc = NULL;
    }

    od.stderr_expect_close = true;

    if (close_acc && od.scon.io) {
	od.ccon.expect_close = true;
	rv = close_con(&od.scon, &timeout);
	if (rv) {
	    if (!err)
		err = rv;
	}
	rv = close_con(&od.ccon, &timeout);
	if (rv) {
	    if (!err)
		err = rv;
	}
    } else {
	od.scon.expect_close = true;
	rv = close_con(&od.ccon, &timeout);
	if (rv) {
	    if (!err)
		err = rv;
	}
	rv = close_con(&od.scon, &timeout);
	if (rv) {
	    if (!err)
		err = rv;
	}
    }

    if (od.ccon_stderr_io) {
	rv = gensio_close(od.ccon_stderr_io, ccon_stderr_closed, &od);
	assert(!debug || !rv || rv == GE_REMCLOSE);
	if (rv) {
	    gensio_free(od.ccon_stderr_io);
	    if (!err)
		err = rv;
	}
	pthread_mutex_lock(&od.lock);
	while (od.ccon_stderr_io) {
	    pthread_mutex_unlock(&od.lock);
	    rv = o->wait_intr_sigmask(od.waiter, 1, &timeout, &waitsigs);
	    pthread_mutex_lock(&od.lock);
	    if (rv == GE_TIMEDOUT && debug) {
		printf("Waiting on timeout err D\n");
		assert(0);
	    }
	    if (rv == GE_INTERRUPTED)
		continue;
	    if (rv) {
		if (!err)
		    err = rv;
		break;
	    }
	}
	pthread_mutex_unlock(&od.lock);
    }

    if (od.ccon_exit_code_set)
	*exitcode = od.ccon_exit_code;
    else if (!err)
	err = OOME_CLIENT_DIDNT_TERMINATE;

    if (od.ccon.io)
	gensio_free(od.ccon.io);
    if (od.scon.io)
	gensio_free(od.scon.io);
    if (od.ccon_stderr_io)
	gensio_free(od.ccon_stderr_io);
    o->free_waiter(od.waiter);
    pthread_mutex_destroy(&od.lock);

    if (od.ccon_stderr_pos && verbose) {
	od.ccon_stderr[od.ccon_stderr_pos] = '\0';
	printf("ERR out: %s", od.ccon_stderr);
    }

    return err;

 out_err:
    if (od.ccon.io)
	gensio_free(od.ccon.io);
    if (od.acc)
	gensio_acc_free(od.acc);
    o->free_waiter(od.waiter);
    pthread_mutex_destroy(&od.lock);
    return rv;
}

static int
run_oom_acc_test(struct oom_tests *test, long count, int *exitcode,
		 bool close_acc)
{
    struct oom_test_data od;
    int rv, err = 0;
    char intstr[30], *constr, *locstr;
    struct timeval timeout = { 5, 0 };

    memset(&od, 0, sizeof(od));
    od.waiter = o->alloc_waiter(o);
    if (!od.waiter)
	return GE_NOMEM;
    od.ccon.od = &od;
    od.scon.od = &od;
    od.ccon.iostr = test->connecter;
    od.scon.iostr = test->accepter;
    pthread_mutex_init(&od.lock, NULL);

    if (count < 0) {
	rv = unsetenv("GENSIO_OOM_TEST");
    } else {
	snprintf(intstr, sizeof(intstr), "%ld ", count);
	rv = setenv("GENSIO_OOM_TEST", intstr, 1);
    }
    if (rv) {
	fprintf(stderr, "Unable to set environment properly\n");
	return gensio_os_err_to_err(o, errno);
    }

    constr = alloc_sprintf("stdio, %s -v -a -p -i 'stdio(self)' '%s'",
			   gensiot, test->accepter);
    if (!constr) {
	err = GE_NOMEM;
	goto out_err;
    }

    err = str_to_gensio(constr, o, con_cb, &od.ccon, &od.ccon.io);
    assert(!debug || !err);
    free(constr);
    if (err)
	goto out_err;

    od.look_for_port = true;
    err = gensio_open(od.ccon.io, ccon_open_done, &od);
    assert(!debug || !err);
    if (err)
	goto out_err;

    for (;;) {
	rv = o->wait_intr_sigmask(od.waiter, 1, &timeout, &waitsigs);
	if (debug && rv == GE_TIMEDOUT) {
	    printf("Waiting on err E\n");
	    assert(0);
	}
	if (rv == GE_INTERRUPTED)
	    continue;
	if (rv) {
	    err = rv;
	    goto out_err;
	}
	if (od.invalid_port_data) {
	    /* Got out of memory before port, just handle it. */
	    goto finish_run;
	}
	if (od.ccon.err) {
	    err = od.ccon.err;
	    goto finish_run;
	}
	if (od.scon.err) {
	    err = od.scon.err;
	    goto finish_run;
	}
	if (!od.look_for_port)
	    break;
    }
    if (!od.port) {
	err = OOME_NO_PORT;
	goto out_err;
    }

    locstr = alloc_sprintf("%s%d", test->connecter, od.port);
    if (!locstr) {
	err = GE_NOMEM;
	goto out_err;
    }

    err = str_to_gensio(locstr, o, con_cb, &od.scon, &od.scon.io);
    assert(!debug || !err);
    free(locstr);
    if (err)
	goto out_err;

    err = gensio_open(od.scon.io, scon_open_done, &od);
    assert(!debug || !err);
    if (err)
	goto out_err;

    pthread_mutex_lock(&od.lock);
    for (;;) {
	pthread_mutex_unlock(&od.lock);
	rv = o->wait_intr_sigmask(od.waiter, 1, &timeout, &waitsigs);
	pthread_mutex_lock(&od.lock);
	if (debug && (rv == GE_TIMEDOUT || od.scon.err == OOME_READ_OVERFLOW ||
		      od.ccon.err == OOME_READ_OVERFLOW)) {
	    printf("Waiting on err F\n");
	    assert(0);
	}
	if (rv == GE_INTERRUPTED)
	    continue;
	if (rv) {
	    err = rv;
	    break;
	}
	if (od.ccon.err) {
	    err = od.ccon.err;
	    break;
	}
	if (od.scon.err) {
	    err = od.scon.err;
	    break;
	}
	if (od.ccon.write_pos >= iodata_size &&
		od.ccon.read_pos >= iodata_size &&
		(!od.scon.io ||
		 (od.scon.write_pos >= iodata_size &&
		  od.scon.read_pos >= iodata_size))) {
	    break;
	}
    }
    pthread_mutex_unlock(&od.lock);

 finish_run:
    od.stderr_expect_close = true;

    if (!close_acc && od.scon.io) {
	od.ccon.expect_close = true;
	rv = close_con(&od.scon, &timeout);
	if (rv) {
	    if (!err)
		err = rv;
	}
	rv = close_con(&od.ccon, &timeout);
	if (rv) {
	    if (!err)
		err = rv;
	}
    } else {
	od.scon.expect_close = true;
	rv = close_con(&od.ccon, &timeout);
	if (rv) {
	    if (!err)
		err = rv;
	}
	rv = close_con(&od.scon, &timeout);
	if (rv) {
	    if (!err)
		err = rv;
	}
    }

    if (od.ccon_stderr_io) {
	rv = gensio_close(od.ccon_stderr_io, ccon_stderr_closed, &od);
	assert(!debug || !rv || rv == GE_REMCLOSE);
	if (rv) {
	    gensio_free(od.ccon_stderr_io);
	    if (!err)
		err = rv;
	    goto out_err;
	}
	pthread_mutex_lock(&od.lock);
	while (od.ccon_stderr_io) {
	    pthread_mutex_unlock(&od.lock);
	    rv = o->wait_intr_sigmask(od.waiter, 1, &timeout, &waitsigs);
	    pthread_mutex_lock(&od.lock);
	    if (rv == GE_TIMEDOUT && debug) {
		printf("Waiting on timeout err G\n");
		assert(0);
	    }
	    if (rv == GE_INTERRUPTED)
		continue;
	    if (rv) {
		if (!err)
		    err = rv;
		break;
	    }
	}
	pthread_mutex_unlock(&od.lock);
    }

    if (od.ccon_exit_code_set)
	*exitcode = od.ccon_exit_code;
    else if (!err)
	err = OOME_CLIENT_DIDNT_TERMINATE;

 out_err:
    if (od.ccon.io)
	gensio_free(od.ccon.io);
    if (od.scon.io)
	gensio_free(od.scon.io);
    if (od.ccon_stderr_io)
	gensio_free(od.ccon_stderr_io);
    o->free_waiter(od.waiter);
    pthread_mutex_destroy(&od.lock);

    if (od.ccon_stderr_pos && verbose) {
	od.ccon_stderr[od.ccon_stderr_pos] = '\0';
	printf("ERR out: %s", od.ccon_stderr);
    }

    return err;
}

/* Give up after this many times. */
#define MAX_LOOPS	10000

static void
print_test(struct oom_tests *test, char *tstr, bool close_acc, long count)
{
    printf("testing(%s %s) GENSIO_OOM_TEST=%ld '%s' '%s'\n", tstr,
	   close_acc ? "sc" : "cc", count,
	   test->accepter, test->connecter);
}

static unsigned long
run_oom_tests(struct oom_tests *test, char *tstr,
	      int (*tester)(struct oom_tests *test, long count,
			    int *exitcode, bool close_acc))
{
    long count, errcount = 0;
    int rv, exit_code = 1;
    bool close_acc = false;

    /* First run (count == -1) means no memory allocation failure. */
    for (count = -1; exit_code == 1 && count < MAX_LOOPS; ) {
	if (verbose)
	    print_test(test, tstr, close_acc, count);
	rv = tester(test, count, &exit_code, close_acc);
	if (rv && rv != GE_REMCLOSE) {
	    if (!verbose)
		print_test(test, tstr, close_acc, count);
	    printf("  ***Error running %s test (%s): %s\n", tstr,
		   close_acc ? "sc" : "cc", oom_err_to_str(rv));
	    errcount++;
	    break;
	}

	if (!WIFEXITED(exit_code)) {
	    errcount++;
	    if (!verbose)
		print_test(test, tstr, close_acc, count);
	    if (WIFSIGNALED(exit_code)) {
		printf("  ***Died with signal %s\n",
			strsignal(WTERMSIG(exit_code)));
	    } else {
		printf("  ***Died for unknown reason %d\n",
			exit_code);
	    }
	    exit_code = 1;
	    goto next;
	} else {
	    exit_code = WEXITSTATUS(exit_code);
	}

	if (count == -1) {
	    /* We should always succeed if no memory allocation failure. */
	    if (exit_code != 0) {
		errcount++;
		if (!verbose)
		    print_test(test, tstr, close_acc, count);
		fprintf(stderr,
		    "  ***Error with no memory allocation failure.\n");
		/* Leave it 0 to terminate the loop, testing is pointless. */
	    } else {
		exit_code = 1;
	    }
	} else if (exit_code == 2) {
	    errcount++;
	    if (!verbose)
		print_test(test, tstr, close_acc, count);
	    printf("  ***No error on memory allocation failure.\n");
	    exit_code = 1;
	} else if (exit_code == 3) {
	    errcount++;
	    if (!verbose)
		print_test(test, tstr, close_acc, count);
	    printf("  ***Error but no memory allocation failure.\n");
	    exit_code = 0; /* No point in going on. */
	}

    next:
	if (test->accepter)
	    close_acc = !close_acc;
	if (!close_acc)
	    count++;
    }

    if (count == MAX_LOOPS) {
	errcount++;
	if (!verbose)
	    print_test(test, tstr, close_acc, count);
	printf("  ***Didn't fail in %ld loops.\n", count);
    }

    return errcount;
}

int
main(int argc, char *argv[])
{
    int rv;
    pthread_t loopth;
    struct gensio_waiter *loopwaiter;
    unsigned int i;
    unsigned long errcount = 0;
    struct sigaction sigdo;
    sigset_t sigs;

    for (i = 1; i < argc; i++) {
	if (argv[i][0] != '-')
	    break;
	if (strcmp(argv[i], "-v") == 0) {
	    verbose = true;
	    gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else if (strcmp(argv[i], "-d") == 0) {
	    debug = true;
	    gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else {
	    fprintf(stderr, "Unknown argument: '%s'\n", argv[i]);
	    exit(1);
	}
    }

    if (i >= argc) {
	gensiot = getenv("GENSIOT");
	if (!gensiot) {
	    fprintf(stderr, "No gensiot given\n");
	    exit(1);
	}
    } else {
	gensiot = argv[i];
    }

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGCHLD);
    sigaddset(&sigs, SIGPIPE); /* Ignore broken pipes. */
    rv = sigprocmask(SIG_BLOCK, &sigs, NULL);
    if (rv) {
	perror("Could not set up signal mask");
	exit(1);
    }
    rv = sigprocmask(SIG_BLOCK, NULL, &waitsigs);
    if (rv) {
	perror("Could not get signal mask");
	exit(1);
    }
    sigdelset(&waitsigs, SIGCHLD);

    memset(&sigdo, 0, sizeof(sigdo));
    sigdo.sa_handler = handle_sigchld;
    sigdo.sa_flags = SA_NOCLDSTOP;
    rv = sigaction(SIGCHLD, &sigdo, NULL);
    if (rv) {
	perror("Could not set up sigchld handler");
	exit(1);
    }

    sigdo.sa_handler = handle_sigusr1;
    sigdo.sa_flags = 0;
    rv = sigaction(SIGUSR1, &sigdo, NULL);
    if (rv) {
	perror("Could not set up siguser1 handler");
	exit(1);
    }

    rv = gensio_default_os_hnd(SIGUSR1, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }
    o->vlog = do_vlog;

    loopwaiter = o->alloc_waiter(o);
    if (!loopwaiter) {
	fprintf(stderr, "Could not allocate loop waiter\n");
	goto out_err;
    }

    rv = pthread_create(&loopth, NULL, gensio_loop, loopwaiter);
    if (rv) {
	perror("Could not allocate loop thread");
	goto out_err;
    }

    for (i = 0; oom_tests[i].connecter; i++) {
	errcount += run_oom_tests(oom_tests + i, "oom", run_oom_test);
	if (oom_tests[i].accepter)
	    errcount += run_oom_tests(oom_tests + i, "oom acc",
				      run_oom_acc_test);
    }

    o->wake(loopwaiter);
    pthread_join(loopth, NULL);
    o->free_waiter(loopwaiter);

    printf("Got %ld errors\n", errcount);
    return !!errcount;

 out_err:
    return 1;
}
