/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <gensio/gensio.h>
#include <gensio/gensio_selector.h>
#include "pthread_handler.h"

struct oom_tests {
    const char *connecter;
    const char *accepter;
    bool (*check_if_present)(struct gensio_os_funcs *o, struct oom_tests *test);
    bool check_done;
    bool check_value;
    bool allow_pass_on_oom;
};

#if HAVE_SERIALDEV
#include <sys/type.h>
#include <sys/stat.h>
#include <unistd.h>
bool
file_is_accessible_dev(const char *filename)
{
    struct stat sb;
    int rv;

    rv = stat(filename, &sb);
    if (rv == -1)
	return false;

    if (!S_ISCHR(sb.st_mode))
	return false;

    rv = open(filename, O_RDWR);
    if (rv >= 0) {
	close(rv);
	return true;
    } else {
	return false;
    }
}
#endif

static bool
check_serialdev_present(struct gensio_os_funcs *o, struct oom_tests *test)
{
#if HAVE_SERIALDEV
    const char *e = getenv("GENSIO_TEST_ECHO_DEV");

    if (e) {
	if (strlen(e) == 0) {
	    printf("Serial echo device disabled, skipping serialdev test\n");
	    return false;
	}
    } else {
	e = "/dev/ttyEcho0";
    }
    if (!file_is_accessible_dev(e)) {
	printf("Serial echo device '%s' doesn't exist or is not accessible,\n"
	       "skipping serialdev test\n", e);
	return false;
    }
    test->connecter = gensio_alloc_sprintf(o, test->connecter, e);
    if (!test->connecter) {
	printf("Unable to allocate memory for echo device '%s',\n"
	       "skipping serialdev test\n", e);
	return false;
    }
    return true;
#else
    return false;
#endif
}

static bool
check_oom_test_present(struct gensio_os_funcs *o, struct oom_tests *test)
{
    if (!test->check_done) {
	test->check_done = true;
	if (!test->check_if_present)
	    test->check_value = true;
	else
	    test->check_value = test->check_if_present(o, test);
    }
    return test->check_value;
}

struct oom_tests oom_tests[] = {
    { "relpkt,msgdelim,tcp,localhost,", "relpkt,msgdelim,tcp,0" },
    { "certauth(cert=ca/cert.pem,key=ca/key.pem,username=test1),ssl(CA=ca/CA.pem),tcp,localhost,",
      "certauth(CA=ca/CA.pem),ssl(key=ca/key.pem,cert=ca/cert.pem),tcp,0",
      .check_done = 1, .check_value = HAVE_OPENSSL },
    { "ssl(CA=ca/CA.pem),tcp,localhost,",
      "ssl(key=ca/key.pem,cert=ca/cert.pem),tcp,0",
      .check_done = 1, .check_value = HAVE_OPENSSL },
    { "echo", NULL },
    { "tcp,localhost,", "tcp,0" },
    { "sctp,localhost,", "sctp,0",
      .check_done = 1, .check_value = HAVE_LIBSCTP },
    { "udp,localhost,", "udp,0",
      .allow_pass_on_oom = true },
    { "mux,sctp,localhost,", "mux,sctp,0",
      .check_done = 1, .check_value = HAVE_LIBSCTP },
    { "telnet(rfc2217),tcp,localhost,", "telnet(rfc2217),tcp,0" },
    { "serialdev,%s,115200", NULL,
      .check_if_present = check_serialdev_present },
    { "telnet,tcp,localhost,", "telnet,tcp,0" },
    { "stdio,cat", NULL },
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

#ifdef USE_PTHREADS
static void *
gensio_loop(void *info)
{
    struct gensio_waiter *closewaiter = info;

    o->wait(closewaiter, 1, NULL);
    return NULL;
}
#endif

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
    bool closed;
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
    bool stderr_closed;

    lock_type lock;

    unsigned int port;
    bool look_for_port;
    bool invalid_port_data;

    unsigned int refcount;
};

static char *iodata = "Hello There";
static gensiods iodata_size = 11;

struct ref_trace {
    enum {
	ref_inc,
	ref_dec
    } op;
    unsigned int refcount;
    int line;
} ref_trace[512];
unsigned int ref_trace_pos;

static void
i_od_deref_and_unlock(struct oom_test_data *od, int line)
{
    unsigned int tcount;

    assert(od->refcount > 0);
    tcount = --od->refcount;
    ref_trace[ref_trace_pos].op = ref_dec;
    ref_trace[ref_trace_pos].refcount = tcount;
    ref_trace[ref_trace_pos].line = line;
    ref_trace_pos = ref_trace_pos == 511 ? 0 : ref_trace_pos + 1;
    UNLOCK(&od->lock);
    if (tcount == 0) {
	LOCK_DESTROY(&od->lock);
	if (od->ccon.io)
	    gensio_free(od->ccon.io);
	if (od->scon.io)
	    gensio_free(od->scon.io);
	if (od->ccon_stderr_io)
	    gensio_free(od->ccon_stderr_io);
	o->free_waiter(od->waiter);
	o->free(o, od);
    }
}
#define od_deref_and_unlock(od) i_od_deref_and_unlock(od, __LINE__)

static void
i_od_ref(struct oom_test_data *od, int line)
{
    assert(od->refcount > 0);
    od->refcount++;
    ref_trace[ref_trace_pos].op = ref_inc;
    ref_trace[ref_trace_pos].refcount = od->refcount;
    ref_trace[ref_trace_pos].line = line;
    ref_trace_pos = ref_trace_pos == 511 ? 0 : ref_trace_pos + 1;
}
#define od_ref(od) i_od_ref(od, __LINE__)

static void
ccon_stderr_closed(struct gensio *io, void *close_data)
{
    struct oom_test_data *od = close_data;
    int rv;
    char intstr[10];
    gensiods size = sizeof(intstr);

    od->stderr_closed = true;
    rv = gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST, true,
			GENSIO_CONTROL_EXIT_CODE, intstr, &size);
    assert(!debug || !rv);
    LOCK(&od->lock);
    if (rv) {
	if (debug)
	    assert(0);
	od->ccon.err = rv;
    } else {
	od->ccon_exit_code = strtoul(intstr, NULL, 0);
	od->ccon_exit_code_set = true;
    }
    od->ccon_stderr_io = NULL;
    o->wake(od->waiter);
    gensio_free(io);
    od_deref_and_unlock(od);
}

static void
con_closed(struct gensio *io, void *close_data)
{
    struct io_test_data *id = close_data;
    struct oom_test_data *od = id->od;

    LOCK(&od->lock);
    id->closed = true;
    gensio_free(io);
    id->io = NULL;
    o->wake(od->waiter);
    od_deref_and_unlock(od);
}

static void
acc_closed(struct gensio_accepter *acc, void *close_data)
{
    struct oom_test_data *od = close_data;

    assert(acc == od->acc);
    LOCK(&od->lock);
    od->acc = NULL;
    o->wake(od->waiter);
    gensio_acc_free(acc);
    od_deref_and_unlock(od);
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
    int rv = 0;

    LOCK(&od->lock);
    assert(id->io == io);
    if (err) {
	assert(!debug || err == GE_REMCLOSE || err == GE_NOTREADY || err == GE_LOCALCLOSED);
	gensio_set_write_callback_enable(io, false);
	gensio_set_read_callback_enable(io, false);
	if (!id->expect_close || err != GE_REMCLOSE) {
	    if (debug)
		printf("con_cb error 1: %s\n", gensio_err_to_str(err));
	    id->err = err;
	} else {
	    id->got_end = true;
	}
	o->wake(od->waiter);
	goto out;
    }

    switch(event) {
    case GENSIO_EVENT_READ:
	assert(!id->in_read);
	id->in_read = true;
	if (id->read_pos + *buflen > iodata_size) {
	    gensio_set_write_callback_enable(io, false);
	    gensio_set_read_callback_enable(io, false);
	    id->err = OOME_READ_OVERFLOW;
	    printf("  readpos = %ld, buflen = %ld, read '%s'\n",
		   (long) id->read_pos, (long) *buflen, buf);
	    assert(!debug);
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
	id->in_read = false;
	break;

    case GENSIO_EVENT_WRITE_READY:
	assert(!id->in_write);
	id->in_write = true;
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
		    if (debug)
			printf("con_cb error 2: %s\n", gensio_err_to_str(rv));
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
	id->in_write = false;
	break;

    default:
	rv = GE_NOTSUP;
    }
 out:
    UNLOCK(&od->lock);
    return rv;
}

static int
acc_cb(struct gensio_accepter *accepter,
       void *user_data, int event, void *data)
{
    struct gensio_loginfo *li;
    struct oom_test_data *od = user_data;
    int rv = 0;

    switch(event) {
    case GENSIO_ACC_EVENT_NEW_CONNECTION:
	LOCK(&od->lock);
	od->scon.io = data;
	gensio_set_callback(od->scon.io, con_cb, &od->scon);
	gensio_set_read_callback_enable(od->scon.io, true);
	gensio_set_write_callback_enable(od->scon.io, true);
	UNLOCK(&od->lock);
	break;

    case GENSIO_ACC_EVENT_LOG:
	li = data;
	do_vlog(o, li->level, li->str, li->args);
	break;

    default:
	rv = GE_NOTSUP;
    }
    return rv;
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
	LOCK(&od->lock);
	assert(!debug || err == GE_REMCLOSE);
	gensio_set_read_callback_enable(io, false);
	if (!od->stderr_expect_close || err != GE_REMCLOSE)
	    od->ccon.err = err;
	o->wake(od->waiter);
	UNLOCK(&od->lock);
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

    LOCK(&od->lock);
    if (od->stderr_closed)
	goto out_unlock;

    od->stderr_open_done = true;
    if (err) {
	assert(!debug || err == GE_REMCLOSE);
	od->ccon.err = err;
	o->wake(od->waiter);
    } else {
	gensio_set_read_callback_enable(io, true);
    }
 out_unlock:
    od_deref_and_unlock(od);
}

static void
scon_open_done(struct gensio *io, int err, void *open_data)
{
    struct oom_test_data *od = open_data;
    struct io_test_data *id = &od->scon;

    LOCK(&od->lock);
    assert(!id->open_done);
    o->wake(od->waiter);
    if (id->closed)
	goto out_unlock;

    if (err) {
	if (debug)
	    printf("scon_open_done: %s for %s\n", gensio_err_to_str(err),
		   id->iostr);
	assert(!debug || err == GE_REMCLOSE || err == GE_INVAL ||
	       err == GE_SHUTDOWN || err == GE_LOCALCLOSED ||
	       err == GE_NOTREADY);
	id->err = err;
	goto out_unlock;
    }

    gensio_set_read_callback_enable(io, true);
    gensio_set_write_callback_enable(io, true);
 out_unlock:
    id->open_done = true;
    od_deref_and_unlock(od);
}

static void
ccon_open_done(struct gensio *io, int err, void *open_data)
{
    struct oom_test_data *od = open_data;
    struct io_test_data *id = &od->ccon;
    int rv;

    LOCK(&od->lock);
    assert(!id->open_done);
    o->wake(od->waiter);
    if (id->closed)
	goto out_unlock;

    id->open_done = true;
    if (err) {
	assert(!debug || !err || err == GE_REMCLOSE || err == GE_LOCALCLOSED);
	if (debug)
	    printf("ccon_open_done error 1: %s\n", gensio_err_to_str(err));
	id->err = err;
	gensio_free(io);
	id->io = NULL;
	goto out_unlock;
    }

    rv = gensio_alloc_channel(io, NULL, ccon_stderr_cb, od,
			      &od->ccon_stderr_io);
    assert(!debug || !rv || rv == GE_REMCLOSE);
    if (rv) {
	if (debug)
	    printf("ccon_open_done error 2: %s\n", gensio_err_to_str(rv));
	id->err = rv;
	goto out_unlock;
    }

    rv = gensio_open(od->ccon_stderr_io, ccon_stderr_open_done, od);
    assert(!debug || !rv || rv == GE_REMCLOSE);
    if (rv) {
	gensio_free(od->ccon_stderr_io);
	od->ccon_stderr_io = NULL;
	if (debug)
	    printf("ccon_open_done error 3: %s\n", gensio_err_to_str(rv));
	id->err = rv;
	goto out_unlock;
    }
    od_ref(od); /* For the open */

    gensio_set_read_callback_enable(io, true);
    gensio_set_write_callback_enable(io, true);
 out_unlock:
    od_deref_and_unlock(od);
}

static struct oom_test_data *
alloc_od(struct oom_tests *test)
{
    struct oom_test_data *od;

    od = o->zalloc(o, sizeof(*od));
    if (!od)
	return NULL;
    od->refcount = 1;
    od->waiter = o->alloc_waiter(o);
    if (!od->waiter) {
	o->free(o, od);
	return NULL;
    }
    od->ccon.od = od;
    od->scon.od = od;
    od->ccon.iostr = test->connecter;
    od->scon.iostr = test->accepter;
    LOCK_INIT(&od->lock);
    return od;
}

static int
wait_for_data(struct oom_test_data *od, struct timeval *timeout)
{
    int err = 0, rv;

    for (;;) {
	UNLOCK(&od->lock);
	rv = o->wait_intr_sigmask(od->waiter, 1, timeout, &waitsigs);
	LOCK(&od->lock);
	if (debug && (rv == GE_TIMEDOUT || od->scon.err == OOME_READ_OVERFLOW ||
		      od->ccon.err == OOME_READ_OVERFLOW)) {
	    printf("Waiting on err A\n");
	    assert(0);
	}
	if (rv == GE_INTERRUPTED)
	    continue;
	if (rv) {
	    err = rv;
	    break;
	}
	if (od->ccon.err) {
	    err = od->ccon.err;
	    break;
	}
	if (od->scon.err) {
	    err = od->scon.err;
	    break;
	}
	if (od->ccon.write_pos >= iodata_size &&
		od->ccon.read_pos >= iodata_size &&
		(!od->scon.io ||
		 (od->scon.write_pos >= iodata_size &&
		  od->scon.read_pos >= iodata_size)))
	    break;
    }

    return err;
}

static int
close_con(struct io_test_data *id, struct timeval *timeout)
{
    struct oom_test_data *od = id->od;
    int rv = 0;

    if (!id->io)
	return 0;
    id->close_done = true;

    rv = gensio_close(id->io, con_closed, id);
    assert(!debug || !rv || rv == GE_REMCLOSE || rv == GE_NOTREADY);
    if (rv) {
	id->closed = true;
	/* Make sure the open completes. */
	while (!id->open_done) {
	    UNLOCK(&od->lock);
	    rv = o->wait_intr_sigmask(id->od->waiter, 1, timeout, &waitsigs);
	    LOCK(&od->lock);
	    if (rv == GE_TIMEDOUT) {
		printf("Waiting on timeout err A\n");
		assert(0);
	    }
	    if (rv == GE_INTERRUPTED) {
		rv = 0;
		continue;
	    }
	    if (rv)
		break;
	}
	goto out;
    }
    od_ref(od); /* Ref for the close */
    while (id->io) {
	UNLOCK(&od->lock);
	rv = o->wait_intr_sigmask(id->od->waiter, 1, timeout, &waitsigs);
	LOCK(&od->lock);
	if (rv == GE_TIMEDOUT) {
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
 out:
    return rv;
}

static int
close_cons(struct oom_test_data *od, bool close_acc, struct timeval *timeout)
{
    int rv, err = 0;

    if (close_acc && od->scon.io) {
	od->ccon.expect_close = true;
	rv = close_con(&od->scon, timeout);
	if (rv && !err)
	    err = rv;
	rv = close_con(&od->ccon, timeout);
	if (rv && !err)
	    err = rv;
    } else {
	od->scon.expect_close = true;
	rv = close_con(&od->ccon, timeout);
	if (rv && !err)
	    err = rv;
	rv = close_con(&od->scon, timeout);
	if (rv && !err)
	    err = rv;
    }

    return err;
}

static int
close_stderr(struct oom_test_data *od, struct timeval *timeout)
{
    int rv, err = 0;

    if (!od->ccon_stderr_io)
	return 0;

    rv = gensio_close(od->ccon_stderr_io, ccon_stderr_closed, od);
    assert(!debug || !rv || rv == GE_REMCLOSE);
    if (rv && !err) {
	od->stderr_closed = true;
	err = rv;
	goto out_err;
    }
    od_ref(od); /* Ref for the close */
    while (od->ccon_stderr_io) {
	UNLOCK(&od->lock);
	rv = o->wait_intr_sigmask(od->waiter, 1, timeout, &waitsigs);
	LOCK(&od->lock);
	if (rv == GE_TIMEDOUT) {
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
 out_err:
    return err;
}

static int
run_oom_test(struct oom_tests *test, long count, int *exitcode, bool close_acc)
{
    struct oom_test_data *od;
    int rv, err = 0;
    char intstr[30], *constr;
    gensiods size;
    struct timeval timeout = { 5, 0 };

    od = alloc_od(test);
    if (!od)
	return GE_NOMEM;

    LOCK(&od->lock);
    if (count < 0) {
	rv = unsetenv("GENSIO_OOM_TEST");
    } else {
	snprintf(intstr, sizeof(intstr), "%ld ", count);
	rv = setenv("GENSIO_OOM_TEST", intstr, 1);
    }
    if (rv) {
	fprintf(stderr, "Unable to set environment properly\n");
	od_deref_and_unlock(od);
	return gensio_os_err_to_err(o, errno);
    }

    if (test->accepter) {
	rv = str_to_gensio_accepter(test->accepter, o, acc_cb, od, &od->acc);
	assert(!debug || !rv);
	if (rv)
	    goto out_err;

	rv = gensio_acc_startup(od->acc);
	assert(!debug || !rv);
	if (rv)
	    goto out_err;

	size = sizeof(intstr);
	strcpy(intstr, "0");
	rv = gensio_acc_control(od->acc, GENSIO_CONTROL_DEPTH_FIRST, true,
				GENSIO_ACC_CONTROL_LPORT, intstr, &size);
	assert(!debug || !rv);
	if (rv)
	    goto out_err;

	constr = gensio_alloc_sprintf(o, "stdio, %s -i 'stdio(self)' '%s%s'",
				      gensiot, test->connecter, intstr);
    } else {
	constr = gensio_alloc_sprintf(o, "stdio, %s -i 'stdio(self)' '%s'",
				      gensiot, test->connecter);
    }
    if (!constr) {
	rv = GE_NOMEM;
	goto out_err;
    }

    rv = str_to_gensio(constr, o, con_cb, &od->ccon, &od->ccon.io);
    assert(!debug || !rv);
    o->free(o, constr);
    if (rv)
	goto out_err;

    rv = gensio_open(od->ccon.io, ccon_open_done, od);
    assert(!debug || !rv);
    if (rv)
	goto out_err;
    od_ref(od); /* Ref for the open */

    err = wait_for_data(od, &timeout);

    if (od->acc) {
	rv = gensio_acc_shutdown(od->acc, acc_closed, od);
	assert(!debug || !rv || rv == GE_REMCLOSE);
	if (rv) {
	    printf("Unable to shutdown accepter: %s\n",
		    gensio_err_to_str(rv));
	    if (!err)
		err = rv;
	} else {
	    od_ref(od); /* Ref for the close */
	    while (od->acc) {
		UNLOCK(&od->lock);
		rv = o->wait_intr_sigmask(od->waiter, 1, &timeout, &waitsigs);
		LOCK(&od->lock);
		if (rv == GE_TIMEDOUT) {
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
	}
    }

    od->stderr_expect_close = true;

    rv = close_cons(od, close_acc, &timeout);
    if (rv && !err)
	err = rv;

    rv = close_stderr(od, &timeout);
    if (rv && !err)
	err = rv;

    if (od->ccon_exit_code_set)
	*exitcode = od->ccon_exit_code;
    else if (!err)
	err = OOME_CLIENT_DIDNT_TERMINATE;

 out_err:
    if (od->ccon_stderr_pos && verbose) {
	od->ccon_stderr[od->ccon_stderr_pos] = '\0';
	printf("ERR out: %s", od->ccon_stderr);
    }

    assert(od->refcount == 1); /* No callbacks should be pending. */
    od_deref_and_unlock(od);

    return err;
}

static int
run_oom_acc_test(struct oom_tests *test, long count, int *exitcode,
		 bool close_acc)
{
    struct oom_test_data *od;
    int rv, err = 0;
    char intstr[30], *constr, *locstr;
    struct timeval timeout = { 5, 0 };

    od = alloc_od(test);
    if (!od)
	return GE_NOMEM;

    LOCK(&od->lock);
    if (count < 0) {
	rv = unsetenv("GENSIO_OOM_TEST");
    } else {
	snprintf(intstr, sizeof(intstr), "%ld ", count);
	rv = setenv("GENSIO_OOM_TEST", intstr, 1);
    }
    if (rv) {
	fprintf(stderr, "Unable to set environment properly\n");
	od_deref_and_unlock(od);
	return gensio_os_err_to_err(o, errno);
    }

    constr = gensio_alloc_sprintf(o, "stdio, %s -v -a -p -i 'stdio(self)' '%s'",
				  gensiot, test->accepter);
    if (!constr) {
	err = GE_NOMEM;
	goto out_err;
    }

    err = str_to_gensio(constr, o, con_cb, &od->ccon, &od->ccon.io);
    assert(!debug || !err);
    o->free(o, constr);
    if (err)
	goto out_err;

    od->look_for_port = true;
    err = gensio_open(od->ccon.io, ccon_open_done, od);
    assert(!debug || !err);
    if (err)
	goto out_err;
    od_ref(od); /* Ref for the open */

    for (;;) {
	UNLOCK(&od->lock);
	rv = o->wait_intr_sigmask(od->waiter, 1, &timeout, &waitsigs);
	LOCK(&od->lock);
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
	if (od->invalid_port_data) {
	    /* Got out of memory before port, just handle it. */
	    goto finish_run;
	}
	if (od->ccon.err) {
	    err = od->ccon.err;
	    goto finish_run;
	}
	if (od->scon.err) {
	    err = od->scon.err;
	    goto finish_run;
	}
	if (!od->look_for_port)
	    break;
    }
    if (!od->port) {
	err = OOME_NO_PORT;
	goto out_err;
    }

    locstr = gensio_alloc_sprintf(o, "%s%d", test->connecter, od->port);
    if (!locstr) {
	err = GE_NOMEM;
	goto out_err;
    }

    err = str_to_gensio(locstr, o, con_cb, &od->scon, &od->scon.io);
    assert(!debug || !err);
    o->free(o, locstr);
    if (err)
	goto out_err;

    err = gensio_open(od->scon.io, scon_open_done, od);
    assert(!debug || !err);
    if (err)
	goto out_err;
    od_ref(od); /* Ref for the open */

    err = wait_for_data(od, &timeout);

 finish_run:
    od->stderr_expect_close = true;

    rv = close_cons(od, close_acc, &timeout);
    if (rv && !err)
	err = rv;

    rv = close_stderr(od, &timeout);
    if (rv && !err)
	err = rv;

    if (od->ccon_exit_code_set)
	*exitcode = od->ccon_exit_code;
    else if (!err)
	err = OOME_CLIENT_DIDNT_TERMINATE;

 out_err:
    if (od->ccon_stderr_pos && verbose) {
	od->ccon_stderr[od->ccon_stderr_pos] = '\0';
	printf("ERR out: %s", od->ccon_stderr);
    }

    assert(od->refcount == 1); /* No callbacks should be pending. */
    od_deref_and_unlock(od);

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
			    int *exitcode, bool close_acc),
	      int start, int end)
{
    long count, errcount = 0;
    int rv, exit_code = 1;
    bool close_acc = false;

    /* First run (count == -1) means no memory allocation failure. */
    for (count = start; exit_code == 1 && count < end; ) {
	if (verbose)
	    print_test(test, tstr, close_acc, count);
	rv = tester(test, count, &exit_code, close_acc);
	if (rv && rv != GE_REMCLOSE && rv != GE_NOTREADY && rv != GE_SHUTDOWN
		&& rv != GE_LOCALCLOSED) {
	    if (!verbose)
		print_test(test, tstr, close_acc, count);
	    printf("  ***Error running %s test (%s): %s\n", tstr,
		   close_acc ? "sc" : "cc", oom_err_to_str(rv));
	    errcount++;
	    if (count < 0) /* No point in going on if the first test fails. */
		break;
	    goto next;
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
	    if (count < 0) /* No point in going on if the first test fails. */
		break;
	    goto next;
	} else {
	    exit_code = WEXITSTATUS(exit_code);
	}

	if (count < 0) {
	    /* We should always succeed if no memory allocation failure. */
	    if (exit_code != 0) {
		errcount++;
		if (!verbose)
		    print_test(test, tstr, close_acc, count);
		fprintf(stderr,
			"  ***Error with no memory allocation failure: %d.\n",
			exit_code);
		/* Leave it 0 to terminate the loop, testing is pointless. */
	    } else {
		exit_code = 1;
	    }
	} else if (exit_code == 2) {
	    if (test->allow_pass_on_oom)
		goto next;
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
#ifdef USE_PTHREADS
    pthread_t loopth[3];
    struct gensio_waiter *loopwaiter[3];
#endif
    unsigned int i, j;
    unsigned long errcount = 0;
    unsigned long skipcount = 0;
    struct sigaction sigdo;
    sigset_t sigs;
    int testnr = -1, numtests = 0, testnrstart = -1, testnrend = MAX_LOOPS;
    struct timeval zerotime = { 0, 0 };
    unsigned int num_extra_threads = 3;

#ifndef ENABLE_INTERNAL_TRACE
    fprintf(stderr, "Internal tracing disabled, cannot run oomtest\n");
    fprintf(stderr, "Configure with --enable-internal-trace to enable internal"
	    "tracing\n");
    exit(77);
#endif

    rv = gensio_default_os_hnd(SIGUSR1, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }
    o->vlog = do_vlog;

    for (j = 0; oom_tests[j].connecter; j++)
	numtests++;

    for (i = 1; i < argc; i++) {
	if (argv[i][0] != '-')
	    break;
	if (strcmp(argv[i], "-v") == 0) {
	    verbose = true;
	    gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else if (strcmp(argv[i], "-d") == 0) {
	    debug = true;
	    gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else if (strcmp(argv[i], "-l") == 0) {
	    for (j = 0; oom_tests[j].connecter; j++) {
		if (!check_oom_test_present(o, oom_tests + j))
		    continue;
		printf("%d : %s %s\n", j, oom_tests[j].connecter,
		       oom_tests[j].accepter ? oom_tests[j].accepter : "");
	    }
	    exit(0);
	} else if (strcmp(argv[i], "-t") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No test number given with -t\n");
		exit(1);
	    }
	    testnr = strtol(argv[i], NULL, 0);
	    if (testnr >= numtests) {
		fprintf(stderr, "Test number (-t) too large, max is %d\n",
			numtests);
		exit(1);
	    }
	} else if (strcmp(argv[i], "-s") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No start number given with -s\n");
		exit(1);
	    }
	    testnrstart = strtol(argv[i], NULL, 0);
	} else if (strcmp(argv[i], "-n") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No number given with -n\n");
		exit(1);
	    }
	    num_extra_threads = strtol(argv[i], NULL, 0);
	} else if (strcmp(argv[i], "-e") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No end number given with -s\n");
		exit(1);
	    }
	    testnrend = strtol(argv[i], NULL, 0) + 1;
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

#ifdef USE_PTHREADS
    for (i = 0; i < num_extra_threads; i++) {
	loopwaiter[i] = o->alloc_waiter(o);
	if (!loopwaiter[i]) {
	    fprintf(stderr, "Could not allocate loop waiter\n");
	    goto out_err;
	}

	rv = pthread_create(&loopth[i], NULL, gensio_loop, loopwaiter[i]);
	if (rv) {
	    perror("Could not allocate loop thread");
	    goto out_err;
	}
    }
#endif

    if (testnr < 0) {
	for (i = 0; oom_tests[i].connecter; i++) {
	    if (!check_oom_test_present(o, oom_tests + i)) {
		skipcount++;
		continue;
	    }
	    errcount += run_oom_tests(oom_tests + i, "oom", run_oom_test,
				      testnrstart, testnrend);
	    if (oom_tests[i].accepter)
		errcount += run_oom_tests(oom_tests + i, "oom acc",
					  run_oom_acc_test,
					  testnrstart, testnrend);
	}
    } else {
	    if (!check_oom_test_present(o, oom_tests + testnr))
		exit(77);
	    errcount += run_oom_tests(oom_tests + testnr, "oom", run_oom_test,
				      testnrstart, testnrend);
	    if (oom_tests[testnr].accepter)
		errcount += run_oom_tests(oom_tests + testnr, "oom acc",
					  run_oom_acc_test,
					  testnrstart, testnrend);
    }

#ifdef USE_PTHREADS
    for (i = 0; i < num_extra_threads; i++) {
	o->wake(loopwaiter[i]);
	pthread_join(loopth[i], NULL);
	o->free_waiter(loopwaiter[i]);
    }
#endif

    printf("Got %ld errors, skipped %ld tests\n", errcount, skipcount);
    while (o && o->service(o, &zerotime) == 0)
	;
    gensio_cleanup_mem(o);
    gensio_sel_exit(!!errcount);

 out_err:
    gensio_cleanup_mem(o);
    gensio_sel_exit(1);
    return 1;
}
