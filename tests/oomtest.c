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
#include <signal.h>
#include <gensio/gensio.h>
#include <gensio/gensio_osops.h>
#include <gensio/gensio_osops_env.h>
#include <gensio/argvutils.h>
#include <gensio/gensio_unix.h>
#ifdef HAVE_GLIB
#include <gensio/gensio_glib.h>
#endif
#ifdef HAVE_TCL
#include <gensio/gensio_tcl.h>
#endif
#include "pthread_handler.h"

struct oom_tests {
    char *connecter;
    const char *accepter;
    bool (*check_if_present)(struct gensio_os_funcs *o, struct oom_tests *test);
    void (*end_test_suite)(struct gensio_os_funcs *o, struct oom_tests *test);
    int (*start_test)(struct gensio_os_funcs *o, struct oom_tests *test);
    void (*end_test)(struct gensio_os_funcs *o, struct oom_tests *test);
    bool check_done;
    bool check_value;
    bool free_connecter;
    bool conacc;

    /* Some tests can keep going on a failure under certain circumstances. */
    bool allow_no_err_on_trig;

    /* We don't want to run some tests by default. */
    bool no_default_run;

    /* Put a limit on the I/O size that can be used. */
    gensiods max_io_size;

    /* Used for holding temporary filenames. */
    char configname[100];
    char emuname[100];
    struct gensio *io;
    struct gensio *io2;
    char *args;
    bool str_found;
    unsigned int wait_pos;
    int err;
    struct gensio_waiter *waiter;
    struct gensio_os_funcs *o;
};

static bool verbose;
static bool debug;

static unsigned int num_extra_threads = 3;
static bool use_glib = false;
static bool use_tcl = false;
static const char *os_func_str = "";

struct gensio_os_proc_data *proc_data;

#ifdef _WIN32
#include <windows.h>

#ifdef _MSC_VER
typedef int ssize_t;
#endif

#define DEFAULT_ECHO_COMMPORT "COM1"

bool
file_is_accessible_dev(const char *filename)
{
    return true; /* FIXME - what to do here? */
}

#define sleep(n) Sleep(n * 1000)

#define WIFEXITED(n) ((n) < 128)
#define WEXITSTATUS(n) (n)
#define WIFSIGNALED(n) ((n) >= 128)
#define WTERMSIG(n) (n)
const char *
strsignal(int n)
{
    if (n == STATUS_ACCESS_VIOLATION)
	return "access violation";
    if (n == STATUS_ASSERTION_FAILURE)
	return "assertion failure";
    if (n == STATUS_CONTROL_C_EXIT)
	return "control-C";
    return "unknown";
}


static FILE *
open_tempfile(char *name, unsigned int len, const char *pattern)
{
    DWORD pos;

    pos = GetTempPathA(len, name);
    if (pos == 0)
	return NULL;

    if (pos + strlen(pattern) + 7 >= len)
	return NULL;

    sprintf(name + pos, "%s%6.6ld", pattern, GetTickCount() % 1000000);
    return fopen(name, "w");
}

#else /* _WIN32 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
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

static FILE *
open_tempfile(char *name, unsigned int len, const char *pattern)
{
    int fd;
    FILE *f;

    snprintf(name, len, "/tmp/%sXXXXXX", pattern);
    fd = mkstemp(name);
    if (fd == -1)
	return NULL;
    f = fdopen(fd, "w");
    if (!f)
	close(fd);
    return f;
}

#define DEFAULT_ECHO_COMMPORT "/dev/ttyEcho0"

#endif

bool sleep_on_timeout_err;
#ifndef _WIN32
bool kill_on_timeout_err;
#endif
struct oom_test_data;

static void handle_timeout_err(struct oom_test_data *od);

static void
l_assert_or_stop(struct oom_test_data *od, bool val, char *expr, int line)
{
    if (val)
	return;
    fprintf(stderr, "Assert '%s' failed on line %d\n", expr, line);
    fflush(stderr);
    handle_timeout_err(od);
}
#define assert_or_stop(od, val) l_assert_or_stop(od, val, #val, __LINE__)

#if HAVE_LIBSCTP
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#endif
static bool
check_sctp_present(struct gensio_os_funcs *o, struct oom_tests *test)
{
#if HAVE_LIBSCTP
    int s;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (s == -1)
	return false;
    close(s);
    return true;
#else
    return false;
#endif
}

static bool
get_echo_dev(struct gensio_os_funcs *o, const char *testname,
	     const char *str, char **newstr)
{
    char *e, *te = NULL;
    int rv;

    rv = gensio_os_env_getalloc(o, "GENSIO_TEST_ECHO_DEV", &te);

    if (rv == 0) {
	if (strlen(te) == 0) {
	    printf("Serial echo device disabled, skipping serialdev test\n");
	    if (te)
		gensio_os_funcs_zfree(o, te);
	    return false;
	}
	e = te;
    } else if (rv == GE_NOTFOUND) {
	e = DEFAULT_ECHO_COMMPORT;
    } else {
	fprintf(stderr, "Unable to get GENSIO_TEST_ECHO_DEV: %s",
		gensio_err_to_str(rv));
	return false;
    }
    if (!file_is_accessible_dev(e)) {
	printf("Serial echo device '%s' doesn't exist or is not accessible,\n"
	       "skipping %s test\n", e, testname);
	if (te)
	    gensio_os_funcs_zfree(o, te);
	return false;
    }
    *newstr = gensio_alloc_sprintf(o, str, e);
    if (te)
	gensio_os_funcs_zfree(o, te);
    if (!*newstr) {
	printf("Unable to allocate memory for echo device '%s',\n"
	       "skipping %s test\n", e, testname);
	return false;
    }
    return true;
}

static char *ipmisim_emu =
    "mc_setbmc 0x20\n"
    "\n"
    "mc_add 0x20 0 no-device-sdrs 0x23 9 8 0x9f 0x1291 0xf02 persist_sdr\n"
    "sel_enable 0x20 1000 0x0a\n"
    "\n"
    "mc_enable 0x20\n";

static char *ipmisim_config =
    "name \"gensio_sim\"\n"
    "\n"
    "set_working_mc 0x20\n"
    "\n"
    "  startlan 1\n"
    "    addr localhost 9001\n"
    "\n"
    "    priv_limit admin\n"
    "\n"
    "    # Allowed IPMI 1.5 authorization types\n"
    "    allowed_auths_callback none md2 md5 straight\n"
    "    allowed_auths_user none md2 md5 straight\n"
    "    allowed_auths_operator none md2 md5 straight\n"
    "    allowed_auths_admin none md2 md5 straight\n"
    "\n"
    "    guid a123456789abcdefa123456789abcdef\n"
    "\n"
    "  endlan\n"
    "\n"
    "  sol \"%s\" 115200\n"
    "\n"
    "  startnow false\n"
    "\n"
    "  user 1 true  \"\"        \"test\" user     10 none md2 md5 straight\n"
    "  user 2 true  \"ipmiusr\" \"test\" admin    10 none md2 md5 straight\n";

static int
ipmisim_cb(struct gensio *io, void *user_data, int event, int err,
	   unsigned char *buf, gensiods *buflen, const char *const *auxdata)
{
    struct oom_tests *test = user_data;
    static const char waitstr[4] = "\x0a\x0d> ";
    gensiods pos;

    if (event != GENSIO_EVENT_READ)
	return GE_NOTSUP;

    if (err) {
	test->err = err;
	gensio_set_read_callback_enable(io, false);

	if (verbose)
	    printf("IPMISIM err: %s\n", gensio_err_to_str(err));
	gensio_os_funcs_wake(test->o, test->waiter);
	return 0;
    }

    if (verbose) {
	char *buf2;

	buf2 = malloc(*buflen + 1);
	if (buf2) {
	    memcpy(buf2, buf, *buflen);
	    buf2[*buflen] = '\0';
	    printf("IPMISIM out: %s\nIPMISIM done\n", buf2);
	    free(buf2);
	}
    }

    if (test->str_found)
	return 0;

    for (pos = 0; pos < *buflen; pos++) {
	if (buf[pos] == (unsigned char) waitstr[test->wait_pos]) {
	    test->wait_pos++;
	    if (test->wait_pos >= sizeof(waitstr)) {
		test->wait_pos = 0;
		test->str_found = true;
		gensio_os_funcs_wake(test->o, test->waiter);
		break;
	    }
	} else {
	    test->wait_pos = 0;
	}
    }

    return 0;
}

static int
ipmisim_err_cb(struct gensio *io, void *user_data, int event, int err,
	   unsigned char *buf, gensiods *buflen, const char *const *auxdata)
{
    /* FIXME - Add debug I/O. */
    if (err) {
	struct oom_tests *test = user_data;

	test->err = err;
	gensio_set_read_callback_enable(io, false);
	if (verbose)
	    printf("IPMISIM err err: %s\n", gensio_err_to_str(err));
	gensio_os_funcs_wake(test->o, test->waiter);
	return 0;
    }

    if (verbose) {
	char *buf2;

	buf2 = malloc(*buflen + 1);
	if (buf2) {
	    memcpy(buf2, buf, *buflen);
	    buf2[*buflen] = '\0';
	    printf("IPMISIM err: %s\nIPMISIM err done\n", buf2);
	    free(buf2);
	}
    }

    return 0;
}

static int
ipmisim_start(struct gensio_os_funcs *o, struct oom_tests *test)
{
    int err;
    gensio_time timeout = { 5, 0 };

    if (test->io)
	/* Started from the check present code. */
	return 0;

    test->err = 0;
    test->str_found = false;
    test->wait_pos = 0;

    err = str_to_gensio(test->args, o, ipmisim_cb, test, &test->io);
    if (err) {
	printf("Unable to alloc gensio %s: %s,\n"
	       "skipping ipmisol test\n", test->args, gensio_err_to_str(err));
	goto out_err;
    }

    err = gensio_open_s(test->io);
    if (err) {
	printf("Unable to open gensio %s: %s,\n"
	       "skipping ipmisol test\n", test->args, gensio_err_to_str(err));
	goto out_err;
    }

    err = gensio_alloc_channel(test->io, NULL, ipmisim_err_cb, test,
			       &test->io2);
    if (err) {
	printf("Unable to alloc gensio stderr channel for %s: %s,\n"
	       "skipping ipmisol test\n", test->args, gensio_err_to_str(err));
	goto out_err;
    }

    err = gensio_open_s(test->io2);
    if (err) {
	printf("Unable to open gensio stderr channel for %s: %s,\n"
	       "skipping ipmisol test\n", test->args, gensio_err_to_str(err));
	goto out_err;
    }

    gensio_set_read_callback_enable(test->io, true);
    gensio_set_read_callback_enable(test->io2, true);

 retry:
    err = gensio_os_funcs_wait_intr_sigmask(o, test->waiter,
					    1, &timeout, proc_data);
    if (err == GE_INTERRUPTED)
	goto retry;
    if (test->err)
	err = test->err;
    if (err) {
	printf("Error waiting for ipmi_sim started for %s: %s,\n"
	       "skipping ipmisol test\n", test->args, gensio_err_to_str(err));
	goto out_err;
    }

    return 0;

 out_err:
    if (test->io) {
	gensio_close_s(test->io);
	gensio_free(test->io);
	test->io = NULL;
    }
    if (test->io2) {
	gensio_close_s(test->io2);
	gensio_free(test->io2);
	test->io2 = NULL;
    }
    return err;
}

static void
ipmisim_end(struct gensio_os_funcs *o, struct oom_tests *test)
{
    int err;

    if (test->io) {
	err = gensio_close_s(test->io);
	if (err)
	    printf("ipmisim: Unable to close stdio channel for %s",
		   test->args);
	gensio_free(test->io);
	test->io = NULL;
    }
    if (test->io2) {
	err = gensio_close_s(test->io2);
	if (err)
	    printf("ipmisim: Unable to close stderr channel for %s",
		   test->args);
	gensio_free(test->io2);
	test->io2 = NULL;
    }
}

static void
ipmisim_finish(struct gensio_os_funcs *o, struct oom_tests *test)
{
    ipmisim_end(o, test);
    if (test->emuname[0]) {
	unlink(test->emuname);
	test->emuname[0] = '\0';
    }
    if (test->configname[0]) {
	unlink(test->configname);
	test->configname[0] = '\0';
    }
    if (test->args) {
	gensio_os_funcs_zfree(o, test->args);
	test->args = NULL;
    }
    if (test->waiter) {
	gensio_os_funcs_free_waiter(o, test->waiter);
	test->waiter = NULL;
    }
    test->o = NULL;
}

/* This function starts ipmi_sim for use by the ipmi tests. */
static bool
check_ipmisim_present(struct gensio_os_funcs *o, struct oom_tests *test)
{
    char *config = NULL;
    char *prog, *tprog = NULL;
    FILE *f;
    ssize_t rv, len;

    rv = gensio_os_env_getalloc(o, "IPMISIM_EXEC", &tprog);
    if (rv == GE_NOTFOUND) {
	prog = "ipmi_sim";
    } else if (rv != 0) {
	fprintf(stderr, "Unable to get IPMISIM_EXEC: %s\n",
		gensio_err_to_str(rv));
	return false;
    } else {
	prog = tprog;
    }

    if (!get_echo_dev(o, "ipmisol", ipmisim_config, &config)) {
	if (tprog)
	    gensio_os_funcs_zfree(o, tprog);
	return false;
    }

    f = open_tempfile(test->configname, sizeof(test->configname),
		      "gensio_oomtest_conf_");
    if (!f) {
	printf("Unable to open ipmisim config file '%s',\n"
	       "skipping ipmisol test\n", test->configname);
	test->configname[0] = '\0';
	goto out_err;
    }
    len = strlen(config);
    rv = fwrite(config, 1, len, f);
    gensio_os_funcs_zfree(o, config);
    config = NULL;
    fclose(f);
    if (rv != len) {
	unlink(test->configname);
	printf("Unable to write ipmisim config file '%s',\n"
	       "skipping ipmisol test\n", test->configname);
	goto out_err;
    }

    strncpy(test->emuname, "/tmp/gensio_oomtest_emu_XXXXXX",
	    sizeof(test->emuname));
    f = open_tempfile(test->emuname, sizeof(test->emuname),
		      "gensio_oomtest_emu_");
    if (!f) {
	printf("Unable to open ipmisim emu file '%s',\n"
	       "skipping ipmisol test\n", test->emuname);
	test->emuname[0] = '\0';
	goto out_err;
    }
    rv = fwrite(ipmisim_emu, 1, strlen(ipmisim_emu), f);
    fclose(f);
    if (rv != strlen(ipmisim_emu)) {
	printf("Unable to write ipmisim emu file '%s',\n"
	       "skipping ipmisol test\n", test->emuname);
	goto out_err;
    }

    test->args = gensio_alloc_sprintf(o, "stdio,%s -p -c %s -f %s",
				prog, test->configname, test->emuname);
    if (!test->args) {
	printf("Unable to allocate ipmi_sim arguments,\n"
	       "skipping ipmisol test\n");
	goto out_err;
    }

    test->waiter = gensio_os_funcs_alloc_waiter(o);
    if (!test->waiter) {
	printf("Unable to allocate ipmi_sim ewaiter,\n"
	       "skipping ipmisol test\n");
	goto out_err;
    }

    test->o = o;

    if (ipmisim_start(o, test))
	goto out_err;

    if (tprog)
	gensio_os_funcs_zfree(o, tprog);

    return true;

 out_err:
    if (tprog)
	gensio_os_funcs_zfree(o, tprog);
    if (config)
	gensio_os_funcs_zfree(o, config);
    ipmisim_end(o, test);
    ipmisim_finish(o, test);

    return false;
}

static bool
check_serialdev_present(struct gensio_os_funcs *o, struct oom_tests *test)
{
    if (!get_echo_dev(o, "serialdev", test->connecter, &test->connecter))
	return false;
    test->free_connecter = true;
    return true;
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
    { "ipmisol,lan -U ipmiusr -P test -p 9001 localhost,115200", NULL,
      /* In this test some errors will not result in a failure. */
      .allow_no_err_on_trig = true,
      .check_value = HAVE_OPENIPMI,
      .check_if_present = check_ipmisim_present,
      .end_test_suite = ipmisim_finish,
      .start_test = ipmisim_start,
      .end_test = ipmisim_end
    },
    /*
     * I would like this to run on UDP, and it works, but the relpkt
     * code has to go through it's timeout operation when gensiot
     * fails, and that takes about 5 seconds per failure.  That makes
     * the test take a long time.  So just use TCP.
     */
    { "relpkt,msgdelim,tcp,localhost,", "relpkt,msgdelim,tcp,0",
      /* In this tests some errors will not result in a failure. */
      .allow_no_err_on_trig = true,
      /*
       * The error injections cause this to take way to long with
       * large I/O sizes.  So limit it to a reasonable value.
       */
      .max_io_size = 2000 },
    { "certauth(cert=ca/cert.pem,key=ca/key.pem,username=test1),ssl(CA=ca/CA.pem),tcp,localhost,",
      "certauth(CA=ca/CA.pem),ssl(key=ca/key.pem,cert=ca/cert.pem),tcp,0",
      /* In this tests some errors will not result in a failure. */
      .allow_no_err_on_trig = true,
      .check_done = 1, .check_value = HAVE_OPENSSL },
    { "ssl(CA=ca/CA.pem),tcp,localhost,",
      "ssl(key=ca/key.pem,cert=ca/cert.pem),tcp,0",
      /* In this tests some errors will not result in a failure. */
      .allow_no_err_on_trig = true,
      .check_done = 1, .check_value = HAVE_OPENSSL },
    { "echo", NULL,
      .allow_no_err_on_trig = true,
    },
    { "tcp,localhost,", "tcp,0",
      .allow_no_err_on_trig = true,
    },
    { "sctp,localhost,", "sctp,0",
      .check_if_present = check_sctp_present, .check_value = HAVE_LIBSCTP,
      .allow_no_err_on_trig = true,
    },
    { "udp,ipv4,localhost,", "udp,ipv4,0",
      /* In this tests some errors will not result in a failure. */
      .allow_no_err_on_trig = true
    },
    { "mux,sctp,localhost,", "mux,sctp,0",
      .check_if_present = check_sctp_present, .check_value = HAVE_LIBSCTP,
      /* In this tests some errors will not result in a failure. */
      .allow_no_err_on_trig = true,
      /*
       * The error injections cause this to take way to long with
       * large I/O sizes.  So limit it to a reasonable value.
       */
      .max_io_size = 10000 },
    { "telnet(rfc2217),tcp,localhost,", "telnet(rfc2217),tcp,0",
      .allow_no_err_on_trig = true,
    },
    { "serialdev,%s,115200", NULL,
      .check_if_present = check_serialdev_present,
      .allow_no_err_on_trig = true,
      /*
       * The error injections cause this to take way to long with
       * large I/O sizes.  So limit it to a reasonable value.
       */
      .max_io_size = 1000 },
    { "telnet,tcp,localhost,", "telnet,tcp,0",
      .allow_no_err_on_trig = true,
    },
    { "stdio,cat", NULL,
      .allow_no_err_on_trig = true,
    },
    { "conacc,tcp,localhost,", "tcp,0", .conacc=true,
      .allow_no_err_on_trig = true,
    },
    { "serialdev,", "conacc,pty(raw)",
      /* In this tests some errors will not result in a failure. */
      .allow_no_err_on_trig = true,
      /*
       * This test has a few problematic things about it:
       *  * There is a Linux bug in PTYs that causes data to be dropped
       *    from the stream on a close, so you lose a chunk of data.
       *    This causes data mismatches sometimes.  Hopefully that will
       *    eventually be fixed.
       *  * If you run this tests when something else is creating PTYs
       *    (like running another of the same test at the same time, or
       *    just creating an X window or ssh login), it is possible that
       *    this gensiot program crashes, the pty is closed, the same
       *    pty number is picked up for something else creating a pty,
       *    and this test connects to the new pty.  There's nothing that
       *    can be done about this, so we don't run this test by default.
       *    It can still be run directly with the -t option.
       */
      .no_default_run = true,
      .check_value = HAVE_PTY },
    { "ax25(laddr=test-2,addr=\"0,test-1,test-2\"),kiss(writebuf=512,readbuf=512),tcp,localhost,",
      "ax25(laddr=test-1),kiss(writebuf=512,readbuf=512),tcp,0",
      /* In this tests some errors will not result in a failure. */
      .allow_no_err_on_trig = true,
    },
    { NULL }
};

static struct gensio_os_funcs *o;
static char *gensiot;

static void
gensio_loop(void *info)
{
    struct gensio_waiter *closewaiter = info;

    gensio_os_funcs_wait(o, closewaiter, 1, NULL);
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
    fflush(stdout);
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

struct io_test_data {
    struct gensio *io;
    gensiods write_pos;
    gensiods read_pos;
    gensiods max_write;
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

    gensiods io_size;

    bool ccon_exit_code_set;
    int ccon_exit_code;
    char ccon_stderr[2048];
    gensiods ccon_stderr_pos;
    struct gensio *ccon_stderr_io;
    bool stderr_expect_close;
    bool stderr_rem_closed;

    bool stderr_open_done;
    bool stderr_closed;

    lock_type lock;

    char *port;
    bool look_for_port;
    bool invalid_port_data;

    unsigned int refcount;

    bool finished;
    struct oom_test_data *next;
};

struct oom_test_data *old_ods;

/* I would like this to be larger, but there are SCTP and UDP limitations. */
#define MAX_IODATA_SIZE 65535
static unsigned char *iodata;
static gensiods iodata_size;

enum ref_trace_op { ref_inc, ref_dec, do_lock, do_unlock };
struct ref_trace {
    struct gensio_time time;
    enum ref_trace_op op;
    unsigned int refcount;
    int line;
    unsigned int data;
} ref_trace[512];
unsigned int ref_trace_pos;

static void
handle_timeout_err(struct oom_test_data *od)
{
#ifndef _WIN32
    if (kill_on_timeout_err && od->ccon_stderr_io) {
	int rv;
	char str[10];
	gensiods len = sizeof(str);

	rv = gensio_control(od->ccon_stderr_io, GENSIO_CONTROL_DEPTH_FIRST,
			    GENSIO_CONTROL_GET,
			    GENSIO_CONTROL_REMOTE_ID, str, &len);
	if (!rv) {
	    pid_t pid = strtoul(str, NULL, 0);

	    kill(pid, SIGSEGV);
	}
    }
#endif
    while (sleep_on_timeout_err)
	sleep(100);
    assert(0);
}

static void
add_ref_trace(enum ref_trace_op op, unsigned int count, int line,
	      unsigned int data)
{
    gensio_os_funcs_get_monotonic_time(o, &ref_trace[ref_trace_pos].time);
    ref_trace[ref_trace_pos].op = op;
    ref_trace[ref_trace_pos].refcount = count;
    ref_trace[ref_trace_pos].line = line;
    ref_trace[ref_trace_pos].data = data;
    ref_trace_pos = ref_trace_pos == 511 ? 0 : ref_trace_pos + 1;
}

#define OOMLOCK(lock) \
    do {						\
	LOCK(lock);					\
	add_ref_trace(do_lock, 0, __LINE__, 0);		\
    } while(0)

#define OOMUNLOCK(lock) \
    do {						\
	add_ref_trace(do_unlock, 0, __LINE__, 0);	\
	UNLOCK(lock);					\
    } while(0)

static void
i_od_deref_and_unlock(struct oom_test_data *od, int line)
{
    unsigned int tcount;

    assert(od->refcount > 0);
    tcount = --od->refcount;
    add_ref_trace(ref_dec, tcount, line, 0);
    OOMUNLOCK(&od->lock);
    if (tcount == 0) {
	LOCK_DESTROY(&od->lock);
	if (od->ccon.io)
	    gensio_free(od->ccon.io);
	if (od->scon.io)
	    gensio_free(od->scon.io);
	if (od->ccon_stderr_io)
	    gensio_free(od->ccon_stderr_io);
	gensio_os_funcs_free_waiter(o, od->waiter);
	od->finished = true;
	od->next = old_ods;
	old_ods = od;
    }
}
#define od_deref_and_unlock(od) i_od_deref_and_unlock(od, __LINE__)

static void
cleanup_ods(void)
{
    struct oom_test_data *od = old_ods, *next;

    while (od) {
	next = od->next;
	gensio_os_funcs_zfree(o, od);
	od = next;
    }
}

static void
i_od_ref(struct oom_test_data *od, int line)
{
    assert(od->refcount > 0);
    od->refcount++;
    add_ref_trace(ref_inc, od->refcount, line, 0);
}
#define od_ref(od) i_od_ref(od, __LINE__)

static void
ccon_stderr_closed(struct gensio *io, void *close_data)
{
    struct oom_test_data *od = close_data;
    int rv;
    char intstr[10];
    gensiods size = sizeof(intstr);

    assert(!od->finished);
    od->stderr_closed = true;
    rv = gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST, GENSIO_CONTROL_GET,
			GENSIO_CONTROL_EXIT_CODE, intstr, &size);
    assert(!debug || !rv);
    OOMLOCK(&od->lock);
    if (rv) {
	if (debug)
	    assert(0);
	od->ccon.err = rv;
    } else {
	od->ccon_exit_code = strtoul(intstr, NULL, 0);
	od->ccon_exit_code_set = true;
    }
    od->ccon_stderr_io = NULL;
    gensio_os_funcs_wake(o, od->waiter);
    gensio_free(io);
    od_deref_and_unlock(od);
}

static void
con_closed(struct gensio *io, void *close_data)
{
    struct io_test_data *id = close_data;
    struct oom_test_data *od = id->od;

    assert(!od->finished);

    OOMLOCK(&od->lock);
    id->closed = true;
    gensio_free(io);
    id->io = NULL;
    gensio_os_funcs_wake(o, od->waiter);
    od_deref_and_unlock(od);
}

static void
acc_closed(struct gensio_accepter *acc, void *close_data)
{
    struct oom_test_data *od = close_data;

    assert(!od->finished);
    assert(acc == od->acc);
    LOCK(&od->lock);
    od->acc = NULL;
    gensio_os_funcs_wake(o, od->waiter);
    gensio_acc_free(acc);
    od_deref_and_unlock(od);
}

int
cmp_mem(unsigned char *buf, unsigned char *buf2, gensiods *len)
{
    gensiods i;
    int rv = 0;

    for (i = 0; i < *len; i++) {
	if (buf[i] != buf2[i]) {
	    printf("Mismatch on byte %lu, expected 0x%2.2x, got 0x%2.2x\n",
		   i, buf[i], buf2[i]);
	    fflush(stdout);
	    rv = -1;
	    break;
	}
    }
    *len = i;
    return rv;
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

    assert(!od->finished);
    OOMLOCK(&od->lock);
    add_ref_trace(ref_inc, err, __LINE__, event);
    assert(id->io == io);
    if (err) {
	assert_or_stop(od, !debug || err == GE_REMCLOSE || err == GE_NOTREADY
		       || err == GE_LOCALCLOSED);
	gensio_set_write_callback_enable(io, false);
	gensio_set_read_callback_enable(io, false);
	if (!id->expect_close || err != GE_REMCLOSE) {
	    if (debug) {
		printf("con_cb error 1: %s\n", gensio_err_to_str(err));
		fflush(stdout);
	    }
	    id->err = err;
	} else {
	    id->got_end = true;
	}
	gensio_os_funcs_wake(o, od->waiter);
	goto out;
    }

    switch(event) {
    case GENSIO_EVENT_READ:
	assert(!id->in_read);
	id->in_read = true;
	if (id->read_pos + *buflen > od->io_size) {
	    gensio_set_write_callback_enable(io, false);
	    gensio_set_read_callback_enable(io, false);
	    id->err = OOME_READ_OVERFLOW;
	    printf("  readpos = %ld, buflen = %ld, read '%s'\n",
		   (long) id->read_pos, (long) *buflen, buf);
	    fflush(stdout);
	    assert(!debug);
	    gensio_os_funcs_wake(o, od->waiter);
	    goto out_leave_read;
	}

	count = *buflen;
	if (cmp_mem(iodata + id->read_pos, buf, &count) != 0) {
	    gensio_set_write_callback_enable(io, false);
	    gensio_set_read_callback_enable(io, false);
	    id->err = OOME_DATA_MISMATCH;
	    gensio_os_funcs_wake(o, od->waiter);
	}

	id->read_pos += *buflen;
	if (id->read_pos >= od->io_size)
	    gensio_os_funcs_wake(o, od->waiter);
    out_leave_read:
	id->in_read = false;
	break;

    case GENSIO_EVENT_WRITE_READY:
	assert(!id->in_write);
	id->in_write = true;
	if (id->write_pos < od->io_size) {
	    gensiods wrsize = od->io_size - id->write_pos;

	    if (id->max_write && wrsize > id->max_write)
		wrsize = id->max_write;

	    rv = gensio_write(io, &count, iodata + id->write_pos, wrsize, NULL);
	    if (rv) {
		if (rv == GE_SHUTDOWN || rv == GE_NOTREADY) {
		    if (debug) {
			printf("Write on shutdown or not ready socket\n");
			fflush(stdout);
		    }
		} else {
		    if (debug) {
			printf("con_cb error 2: %s\n", gensio_err_to_str(rv));
			fflush(stdout);
		    }
		    assert(debug || !rv || rv == GE_REMCLOSE);
		}
		gensio_set_write_callback_enable(io, false);
		gensio_set_read_callback_enable(io, false);
		id->err = rv;
		gensio_os_funcs_wake(o, od->waiter);
	    } else {
		id->write_pos += count;
	    }
	} else {
	    gensio_set_write_callback_enable(io, false);
	    gensio_os_funcs_wake(o, od->waiter);
	}
	id->in_write = false;
	break;

    default:
	rv = GE_NOTSUP;
    }
 out:
    add_ref_trace(ref_dec, rv, __LINE__, 0);
    OOMUNLOCK(&od->lock);
    return rv;
}

static void
set_max_write(struct io_test_data *id, struct gensio *io)
{
    int rv;
    char databuf[20];
    gensiods dbsize = sizeof(databuf);

    rv = gensio_control(io, 0, GENSIO_CONTROL_GET,
			GENSIO_CONTROL_MAX_WRITE_PACKET, databuf, &dbsize);
    if (!rv)
	id->max_write = strtoul(databuf, NULL, 0);
}

static int
acc_cb(struct gensio_accepter *accepter,
       void *user_data, int event, void *data)
{
    struct gensio_loginfo *li;
    struct oom_test_data *od = user_data;
    int rv = 0;

    assert(!od->finished);
    switch(event) {
    case GENSIO_ACC_EVENT_NEW_CONNECTION:
	OOMLOCK(&od->lock);
	if (od->scon.io) {
	    /*
	     * Another connection snuck in before we shut down the
	     * accepter, just shut it down.
	     */
	    gensio_free(data);
	} else {
	    /* Stop any more callbacks, avoid an infinite loop with conacc. */
	    gensio_acc_set_accept_callback_enable(od->acc, false);
	    od->scon.io = data;
	    od->scon.open_done = true;
	    gensio_set_callback(od->scon.io, con_cb, &od->scon);
	    set_max_write(&od->scon, od->scon.io);
	    gensio_set_read_callback_enable(od->scon.io, true);
	    gensio_set_write_callback_enable(od->scon.io, true);
	}
	OOMUNLOCK(&od->lock);
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

    assert(!od->finished);
    if (err) {
	OOMLOCK(&od->lock);
	assert(!debug || err == GE_REMCLOSE);
	gensio_set_read_callback_enable(io, false);
	od->stderr_rem_closed = true;
	if (!od->stderr_expect_close || err != GE_REMCLOSE)
	    od->ccon.err = err;
	gensio_os_funcs_wake(o, od->waiter);
	OOMUNLOCK(&od->lock);
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
	    char *nl, *c, *s;

	    od->ccon_stderr[od->ccon_stderr_pos] = '\0';
#ifdef _WIN32 /* Stupid Windows newlines. */
	    nl = strchr(od->ccon_stderr, '\r');
	    if (nl) {
		if (*(nl + 1) == '\n')
		    *nl++ = '\0';
		else
		    nl = NULL; /* Haven't received the whole newline yet. */
	    }
#else
	    nl = strchr(od->ccon_stderr, '\n');
#endif
	    if (nl) {
		*nl = '\0';
		if (strcmp(od->ccon_stderr, "Done") == 0) {
		    done = true;
		} else if (!od->port) {
		    if (strncmp(od->ccon_stderr, "Address", 7) != 0) {
		    bad_stderr:
			if (debug) {
			    printf("Bad gensio port output: %s\n",
				   od->ccon_stderr);
			    fflush(stdout);
			}
			od->invalid_port_data = true;
			gensio_os_funcs_wake(o, od->waiter);
			return 0;
		    }
		    s = strchr(od->ccon_stderr, ':');
		    if (!s || s[1] != ' ')
			goto bad_stderr;
		    c = strrchr(od->ccon_stderr, ',');
		    if (c)
			s = c + 1;
		    else
			s += 2;
		    od->port = strdup(s);
		    assert(od->port);
		}
		size = strlen(nl + 1);
		memmove(od->ccon_stderr, nl + 1, size);
		od->ccon_stderr_pos = size;
		if (done) {
		    od->look_for_port = false;
		    gensio_os_funcs_wake(o, od->waiter);
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

    assert(!od->finished);
    OOMLOCK(&od->lock);
    if (od->stderr_closed)
	goto out_unlock;

    od->stderr_open_done = true;
    if (err) {
	assert(!debug || err == GE_REMCLOSE);
	od->ccon.err = err;
	gensio_os_funcs_wake(o, od->waiter);
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

    assert(!od->finished);
    OOMLOCK(&od->lock);
    assert(!id->open_done);
    gensio_os_funcs_wake(o, od->waiter);
    if (id->closed)
	goto out_unlock;

    if (err) {
	if (debug) {
	    printf("scon_open_done: %s for %s\n", gensio_err_to_str(err),
		   id->iostr);
	    fflush(stdout);
	}
	assert_or_stop(od, !debug || err == GE_REMCLOSE || err == GE_INVAL ||
		       err == GE_SHUTDOWN || err == GE_LOCALCLOSED ||
		       err == GE_NOTREADY);
	if (err == GE_INVAL)
	    err = GE_REMCLOSE; /* Just translate this special case. */
	id->err = err;
	goto out_unlock;
    }

    set_max_write(id, io);

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
    struct gensio *sio;
    int rv;

    assert(!od->finished);
    OOMLOCK(&od->lock);
    assert(!id->open_done);
    gensio_os_funcs_wake(o, od->waiter);
    if (id->closed)
	goto out_unlock;

    if (err) {
	assert(!debug || !err || err == GE_REMCLOSE || err == GE_LOCALCLOSED);
	if (debug) {
	    printf("ccon_open_done error 1: %s\n", gensio_err_to_str(err));
	    fflush(stdout);
	}
	id->err = err;
	gensio_free(io);
	id->io = NULL;
	goto out_unlock;
    }

    sio = io;
    while (sio) {
	rv = gensio_alloc_channel(sio, NULL, ccon_stderr_cb, od,
				  &od->ccon_stderr_io);
	if (rv != GE_NOTSUP)
	    break;
	sio = gensio_get_child(sio, 1);
    }
    assert(!debug || !rv || rv == GE_REMCLOSE);
    if (rv) {
	if (debug) {
	    printf("ccon_open_done error 2: %s\n", gensio_err_to_str(rv));
	    fflush(stdout);
	}
	id->err = rv;
	goto out_unlock;
    }

    rv = gensio_open(od->ccon_stderr_io, ccon_stderr_open_done, od);
    assert(!debug || !rv || rv == GE_REMCLOSE);
    if (rv) {
	gensio_free(od->ccon_stderr_io);
	od->ccon_stderr_io = NULL;
	if (debug) {
	    printf("ccon_open_done error 3: %s\n", gensio_err_to_str(rv));
	    fflush(stdout);
	}
	id->err = rv;
	goto out_unlock;
    }
    od_ref(od); /* For the open */

    gensio_set_read_callback_enable(io, true);
    gensio_set_write_callback_enable(io, true);
 out_unlock:
    id->open_done = true;
    od_deref_and_unlock(od);
}

static struct oom_test_data *
alloc_od(struct oom_tests *test)
{
    struct oom_test_data *od;

    od = gensio_os_funcs_zalloc(o, sizeof(*od));
    if (!od)
	return NULL;
    od->refcount = 1;
    od->waiter = gensio_os_funcs_alloc_waiter(o);
    if (!od->waiter) {
	gensio_os_funcs_zfree(o, od);
	return NULL;
    }
    od->ccon.od = od;
    od->scon.od = od;
    od->ccon.iostr = test->connecter;
    od->scon.iostr = test->accepter;
    LOCK_INIT(&od->lock);

    if (test->max_io_size)
	od->io_size = iodata_size % test->max_io_size;
    else
	od->io_size = iodata_size;

    return od;
}

static int
wait_for_data(struct oom_test_data *od, gensio_time *timeout)
{
    int err = 0, rv;

    for (;;) {
	OOMUNLOCK(&od->lock);
	rv = gensio_os_funcs_wait_intr_sigmask(o, od->waiter,
					       1, timeout, proc_data);
	OOMLOCK(&od->lock);
	if (rv == GE_INTERRUPTED)
	    continue;
	if (rv || od->scon.err == OOME_READ_OVERFLOW ||
		      od->ccon.err == OOME_READ_OVERFLOW) {
	    printf("Waiting on err A: %s\n", gensio_err_to_str(rv));
	    fflush(stdout);
	    handle_timeout_err(od);
	}
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
	if (od->ccon.write_pos >= od->io_size &&
		od->ccon.read_pos >= od->io_size &&
		(!od->scon.io ||
		 (od->scon.write_pos >= od->io_size &&
		  od->scon.read_pos >= od->io_size)))
	    break;
    }

    return err;
}

static int
close_con(struct io_test_data *id, gensio_time *timeout)
{
    struct oom_test_data *od = id->od;
    int rv = 0;

    if (!id->io)
	return 0;

    id->close_done = true;
    /* Make sure the open completes. */
    while (!id->open_done) {
	OOMUNLOCK(&od->lock);
	rv = gensio_os_funcs_wait_intr_sigmask(o, id->od->waiter,
					       1, timeout, proc_data);
	OOMLOCK(&od->lock);
	if (rv == GE_TIMEDOUT) {
	    printf("Waiting on timeout err A\n");
	    fflush(stdout);
	    handle_timeout_err(od);
	}
	if (rv == GE_INTERRUPTED) {
	    rv = 0;
	    continue;
	}
	if (rv)
	    goto out;
    }

    rv = gensio_close(id->io, con_closed, id);
    assert(!debug || !rv || rv == GE_REMCLOSE || rv == GE_NOTREADY);
    if (rv) {
	id->closed = true;
	gensio_free(id->io);
	id->io = NULL;
	rv = 0;
	goto out;
    }
    od_ref(od); /* Ref for the close */
 out:
    return rv;
}

static int
close_stderr(struct oom_test_data *od, gensio_time *timeout)
{
    int rv, err = 0;

    if (!od->ccon_stderr_io)
	return 0;

    while (!od->stderr_rem_closed) {
	OOMUNLOCK(&od->lock);
	rv = gensio_os_funcs_wait_intr_sigmask(o, od->waiter,
					       1, timeout, proc_data);
	OOMLOCK(&od->lock);
	if (rv == GE_TIMEDOUT) {
	    printf("Waiting on timeout err G1\n");
	    fflush(stdout);
	    handle_timeout_err(od);
	}
	if (rv == GE_INTERRUPTED)
	    continue;
	if (rv) {
	    if (!err)
		err = rv;
	    break;
	}
    }
    rv = gensio_close(od->ccon_stderr_io, ccon_stderr_closed, od);
    assert(!debug || !rv || rv == GE_REMCLOSE);
    if (rv && !err) {
	od->stderr_closed = true;
	err = rv;
	goto out_err;
    }
    od_ref(od); /* Ref for the close */
    while (od->ccon_stderr_io) {
	OOMUNLOCK(&od->lock);
	rv = gensio_os_funcs_wait_intr_sigmask(o, od->waiter,
					       1, timeout, proc_data);
	OOMLOCK(&od->lock);
	if (rv == GE_TIMEDOUT) {
	    printf("Waiting on timeout err G\n");
	    fflush(stdout);
	    handle_timeout_err(od);
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
close_cons(struct oom_test_data *od, bool close_acc, gensio_time *timeout)
{
    int rv, err = 0;

    od->scon.expect_close = true;
    od->ccon.expect_close = true;
    rv = close_con(&od->ccon, timeout);
    if (rv && !err)
	err = rv;
    rv = close_con(&od->scon, timeout);
    if (rv && !err)
	err = rv;

    while (!err && (od->ccon.io || od->scon.io)) {
	OOMUNLOCK(&od->lock);
	rv = gensio_os_funcs_wait_intr_sigmask(o, od->waiter,
					       1, timeout, proc_data);
	OOMLOCK(&od->lock);
	if (rv == GE_TIMEDOUT) {
	    printf("Waiting on timeout err B\n");
	    fflush(stdout);
	    handle_timeout_err(od);
	}
	if (rv == GE_INTERRUPTED)
	    continue;
	if (rv) {
	    if (!err)
		err = rv;
	    break;
	}
    }

    rv = close_stderr(od, timeout);
    if (rv && !err)
	err = rv;

    return err;
}

struct env_info {
    const char **argv;
    gensiods args;
    gensiods argc;
};

static int
run_oom_test(struct oom_tests *test, long count, int *exitcode,
	     bool close_acc, struct env_info *env)
{
    struct oom_test_data *od;
    int rv, err = 0;
    char intstr[30], *constr;
    gensiods size;
    gensio_time timeout = { 20, 0 };

    od = alloc_od(test);
    if (!od)
	return GE_NOMEM;

    OOMLOCK(&od->lock);
    if (count < 0) {
	rv = gensio_os_argvenv_set(o, &env->argv, &env->args, &env->argc,
				   "GENSIO_ERRTRIG_TEST", NULL);
    } else {
	snprintf(intstr, sizeof(intstr), "%ld ", count);
	rv = gensio_os_argvenv_set(o, &env->argv, &env->args, &env->argc,
				   "GENSIO_ERRTRIG_TEST", intstr);
    }
    if (rv) {
	fprintf(stderr, "Unable to set environment properly: %s\n",
		gensio_err_to_str(rv));
	od_deref_and_unlock(od);
	return rv;
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

	constr = gensio_alloc_sprintf(o,
			"stdio,%s%s%s -n %u -i 'stdio(self)' '%s%s'",
			gensiot, test->conacc ? " -a" : "",
			os_func_str, num_extra_threads, test->connecter,
			intstr);
    } else {
	constr = gensio_alloc_sprintf(o,
			"stdio,%s%s -n %u -i 'stdio(self)' '%s'",
			gensiot, os_func_str, num_extra_threads,
			test->connecter);
    }
    if (!constr) {
	rv = GE_NOMEM;
	goto out_err;
    }

    rv = str_to_gensio(constr, o, con_cb, &od->ccon, &od->ccon.io);
    assert(!debug || !rv);
    gensio_os_funcs_zfree(o, constr);
    if (rv)
	goto out_err;

    rv = gensio_control(od->ccon.io, 0, GENSIO_CONTROL_SET,
			GENSIO_CONTROL_ENVIRONMENT, (char *) env->argv, NULL);
    if (rv)
	goto out_err;

    rv = gensio_open(od->ccon.io, ccon_open_done, od);
    assert(!debug || !rv);
    if (rv) {
	od->ccon.open_done = true;
	goto out_err;
    }
    od_ref(od); /* Ref for the open */

    err = wait_for_data(od, &timeout);

    if (od->acc) {
	rv = gensio_acc_shutdown(od->acc, acc_closed, od);
	assert(!debug || !rv || rv == GE_REMCLOSE);
	if (rv) {
	    printf("Unable to shutdown accepter: %s\n",
		    gensio_err_to_str(rv));
	    fflush(stdout);
	    if (!err)
		err = rv;
	} else {
	    od_ref(od); /* Ref for the close */
	    while (od->acc) {
		OOMUNLOCK(&od->lock);
		rv = gensio_os_funcs_wait_intr_sigmask(o, od->waiter,
						       1, &timeout, proc_data);
		OOMLOCK(&od->lock);
		if (rv == GE_TIMEDOUT) {
		    printf("Waiting on timeout err C\n");
		    fflush(stdout);
		    handle_timeout_err(od);
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

    if (err) {
	timeout.secs = 10;
	timeout.nsecs = 0;
    }
    rv = close_cons(od, close_acc, &timeout);
    if (rv && !err)
	err = rv;

    if (od->ccon_exit_code_set)
	*exitcode = od->ccon_exit_code;
    else if (!err)
	err = OOME_CLIENT_DIDNT_TERMINATE;

 out_err:
    if (od->ccon_stderr_pos && verbose) {
	od->ccon_stderr[od->ccon_stderr_pos] = '\0';
	printf("ERR out: %s\nERR done\n", od->ccon_stderr);
	fflush(stdout);
    }

    assert(od->refcount == 1); /* No callbacks should be pending. */
    od_deref_and_unlock(od);

    return err;
}

static int
run_oom_acc_test(struct oom_tests *test, long count, int *exitcode,
		 bool close_acc, struct env_info *env)
{
    struct oom_test_data *od;
    int rv, err = 0;
    char intstr[30], *constr, *locstr;
    gensio_time timeout = { 20, 0 };

    od = alloc_od(test);
    if (!od)
	return GE_NOMEM;

    OOMLOCK(&od->lock);
    if (count < 0) {
	rv = gensio_os_argvenv_set(o, &env->argv, &env->args, &env->argc,
				   "GENSIO_ERRTRIG_TEST", NULL);
    } else {
	snprintf(intstr, sizeof(intstr), "%ld ", count);
	rv = gensio_os_argvenv_set(o, &env->argv, &env->args, &env->argc,
				   "GENSIO_ERRTRIG_TEST", intstr);
    }
    if (rv) {
	fprintf(stderr, "Unable to set environment properly: %s\n",
		gensio_err_to_str(rv));
	od_deref_and_unlock(od);
	return rv;
    }

    constr = gensio_alloc_sprintf(o,
		"stdio,%s%s -n %d -v -a -p -i 'stdio(self)' '%s'",
		gensiot, os_func_str, num_extra_threads, test->accepter);
    if (!constr) {
	err = GE_NOMEM;
	goto out_err;
    }

    err = str_to_gensio(constr, o, con_cb, &od->ccon, &od->ccon.io);
    assert(!debug || !err);
    gensio_os_funcs_zfree(o, constr);
    if (err)
	goto out_err;

    od->look_for_port = true;
    err = gensio_open(od->ccon.io, ccon_open_done, od);
    assert(!debug || !err);
    if (err) {
	od->ccon.open_done = true;
	goto out_err;
    }
    od_ref(od); /* Ref for the open */

    for (;;) {
	OOMUNLOCK(&od->lock);
	rv = gensio_os_funcs_wait_intr_sigmask(o, od->waiter,
					       1, &timeout, proc_data);
	OOMLOCK(&od->lock);
	if (debug && rv == GE_TIMEDOUT) {
	    printf("Waiting on err E\n");
	    fflush(stdout);
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

    locstr = gensio_alloc_sprintf(o, "%s%s", test->connecter, od->port);
    if (!locstr) {
	err = GE_NOMEM;
	goto out_err;
    }

    err = str_to_gensio(locstr, o, con_cb, &od->scon, &od->scon.io);
    assert(!debug || !err);
    gensio_os_funcs_zfree(o, locstr);
    if (err)
	goto out_err;

    err = gensio_open(od->scon.io, scon_open_done, od);
    if (err == GE_NOTFOUND || err == GE_REMCLOSE) {
	/* This can happen on ptys when the other end fails. */
	od->scon.open_done = true;
	gensio_free(od->scon.io);
	od->scon.io = NULL;
	goto finish_run;
    }
    assert(!debug || !err);
    if (err) {
	od->scon.open_done = true;
	gensio_free(od->scon.io);
	od->scon.io = NULL;
	goto finish_run;
    }
    od_ref(od); /* Ref for the open */

    err = wait_for_data(od, &timeout);

 finish_run:
    od->stderr_expect_close = true;

    if (err) {
	timeout.secs = 10;
	timeout.nsecs = 0;
    }
    rv = close_cons(od, close_acc, &timeout);
    if (rv && !err)
	err = rv;

    if (od->ccon_exit_code_set)
	*exitcode = od->ccon_exit_code;
    else if (!err)
	err = OOME_CLIENT_DIDNT_TERMINATE;

 out_err:
    if (od->ccon_stderr_pos && verbose) {
	od->ccon_stderr[od->ccon_stderr_pos] = '\0';
	printf("ERR out: %s\nERR done\n", od->ccon_stderr);
	fflush(stdout);
    }

    assert(od->refcount == 1); /* No callbacks should be pending. */
    if (od->port)
	free(od->port);
    od->port = NULL;
    od_deref_and_unlock(od);

    return err;
}

/* Give up after this many times. */
#define MAX_LOOPS	10000

static void
print_test(struct oom_tests *test, char *tstr, bool close_acc, long count)
{
    printf("testing(%s %s) GENSIO_ERRTRIG_TEST=%ld GENSIO_MEMTRACK=abort '%s' '%s'\n",
	   tstr, close_acc ? "sc" : "cc", count,
	   test->accepter, test->connecter);
    fflush(stdout);
}

static unsigned long
run_oom_tests(struct oom_tests *test, char *tstr,
	      int (*tester)(struct oom_tests *test, long count,
			    int *exitcode, bool close_acc,
			    struct env_info *env),
	      int start, int end, struct env_info *env)
{
    long count, errcount = 0;
    int rv, exit_code = 1;
    bool close_acc = false;

    /* First run (count == -1) means no memory allocation failure. */
    for (count = start; exit_code == 1 && count < end; ) {
	if (verbose)
	    print_test(test, tstr, close_acc, count);
	if (test->start_test) {
	    rv = test->start_test(o, test);
	    if (rv)
		goto next;
	}
	rv = tester(test, count, &exit_code, close_acc, env);
	if (test->end_test)
	    test->end_test(o, test);
	if (rv && rv != GE_REMCLOSE && rv != GE_NOTREADY && rv != GE_SHUTDOWN
		&& rv != GE_LOCALCLOSED && rv != GE_NOTFOUND) {
	    if (!verbose)
		print_test(test, tstr, close_acc, count);
	    printf("  ***Error running %s test (%s): %s\n", tstr,
		   close_acc ? "sc" : "cc", oom_err_to_str(rv));
	    fflush(stdout);
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
		fflush(stdout);
	    } else {
		printf("  ***Died for unknown reason %d\n",
			exit_code);
		fflush(stdout);
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
			"  ***Error with no failure trigger: %d.\n",
			exit_code);
		fflush(stderr);
		/* Leave it 0 to terminate the loop, testing is pointless. */
	    } else {
		exit_code = 1;
	    }
	} else if (exit_code == 2) {
	    if (!test->allow_no_err_on_trig) {
		errcount++;
		if (!verbose)
		    print_test(test, tstr, close_acc, count);
		printf("  ***No error on failure trigger.\n");
		fflush(stdout);
		exit_code = 1;
	    }
	} else if (exit_code == 3) {
	    errcount++;
	    if (!verbose)
		print_test(test, tstr, close_acc, count);
	    printf("  ***Error but no failure trigger.\n");
	    fflush(stdout);
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
	fflush(stdout);
    }

    return errcount;
}

#ifdef HAVE_GETRANDOM_FUNC
#include <sys/random.h>
#else
static size_t
getrandom(void *ibuf, size_t buflen, unsigned int flags)
{
    size_t i;
    unsigned char *buf = ibuf;

    for (i = 0; i < buflen; i++)
	buf[i] = rand();
    return i;
}
#endif

static int
fill_random(void *buf, size_t buflen)
{
    ssize_t randsize = 0, randrv;

    while (randsize < buflen) {
	randrv = getrandom(((char *) buf) + randsize, buflen - randsize, 0);
	if (randrv < 0) {
	    perror("getrandom");
	    return -1;
	}
	randsize += randrv;
    }

    return 0;
}

static void
run_tests(struct oom_tests *test, int testnrstart, int testnrend,
	  unsigned long *skipcount, unsigned long *errcount,
	  unsigned long *testcount, struct env_info *env)
{
    if (!check_oom_test_present(o, test)) {
	(*skipcount)++;
	return;
    }
    printf("Running test %s\n", test->connecter);
    (*testcount)++;
    *errcount += run_oom_tests(test, "oom", run_oom_test,
			       testnrstart, testnrend, env);
    if (test->accepter && !test->conacc)
	*errcount += run_oom_tests(test, "oom acc",
				   run_oom_acc_test,
				   testnrstart, testnrend, env);
    if (test->end_test_suite)
	test->end_test_suite(o, test);
}

int
main(int argc, char *argv[])
{
    int rv;
    struct gensio_thread *loopth[3];
    struct gensio_waiter *loopwaiter[3];
    unsigned int i, j;
    unsigned long errcount = 0, skipcount = 0, testcount = 0;
    unsigned int repeat_count = 1;
    int testnr = -1, numtests = 0, testnrstart = -1, testnrend = MAX_LOOPS;
    gensio_time zerotime = { 0, 0 };
    struct oom_tests user_test;
    bool list_tests = false;
    char oshstr[20];
    gensiods len = sizeof(oshstr);
    char *s;
    struct env_info env;

    memset(&user_test, 0, sizeof(user_test));

    if (fill_random(&iodata_size, sizeof(iodata_size)))
	return 1;
    iodata_size %= MAX_IODATA_SIZE;

    /* This must be first so it gets picked up before any allocations. */
    rv = gensio_os_env_set("GENSIO_MEMTRACK", "abort");
    if (rv) {
	fprintf(stderr, "Unable to set GENSIO_MEMTRACK: %s",
		gensio_err_to_str(rv));
	exit(1);
    }

    rv = gensio_os_env_get("GENSIO_TEST_OS_HANDLER", oshstr, &len);
    if (rv == 0) {
	if (strcmp(oshstr, "glib") == 0) {
	    use_glib = true;
	} else if (strcmp(oshstr, "tcl") == 0) {
	    use_tcl = true;
	} else if (strcmp(oshstr, "default") == 0) {
	    /* Nothing to do. */
	} else {
	    fprintf(stderr, "Unknown OS handler fron environment: %s\n",
		    oshstr);
	    exit(1);
	}
    } else if (rv != GE_NOTFOUND) {
	fprintf(stderr, "Error getting GENSIO_TEST_OS_HANDLER: %s\n",
		gensio_err_to_str(rv));
    }
#ifndef ENABLE_INTERNAL_TRACE
    fprintf(stderr, "Internal tracing disabled, cannot run oomtest\n");
    fprintf(stderr, "Configure with --enable-internal-trace to enable internal"
	    "tracing\n");
    exit(77);
#endif

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
	} else if (strcmp(argv[i], "-b") == 0) {
	    sleep_on_timeout_err = true;
#ifndef _WIN32
	} else if (strcmp(argv[i], "-k") == 0) {
	    kill_on_timeout_err = true;
#endif
	} else if (strcmp(argv[i], "-l") == 0) {
	    list_tests = true;
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
	} else if (strcmp(argv[i], "-r") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No repeat count given with -r\n");
		exit(1);
	    }
	    repeat_count = strtol(argv[i], NULL, 0);
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
		fprintf(stderr, "No end number given with -e\n");
		exit(1);
	    }
	    testnrend = strtol(argv[i], NULL, 0) + 1;
	} else if (strcmp(argv[i], "-i") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No size given with -i\n");
		exit(1);
	    }
	    iodata_size = strtoul(argv[i], NULL, 0);
	} else if (strcmp(argv[i], "-a") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No accepter given with -a\n");
		exit(1);
	    }
	    user_test.accepter = argv[i];
	} else if (strcmp(argv[i], "-c") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No connector given with -c\n");
		exit(1);
	    }
	    user_test.connecter = argv[i];
	} else if (strcmp(argv[i], "-w") == 0) {
	    user_test.allow_no_err_on_trig = true;
	} else if (strcmp(argv[i], "--glib") == 0) {
	    use_glib = true;
	} else if (strcmp(argv[i], "--tcl") == 0) {
	    use_tcl = true;
	} else {
	    fprintf(stderr, "Unknown argument: '%s'\n", argv[i]);
	    exit(1);
	}
    }

    if (use_glib) {
#ifndef HAVE_GLIB
	fprintf(stderr, "glib specified, but glib OS handler not available.\n");
	exit(1);
#else
	os_func_str = " --glib";
	rv = gensio_glib_funcs_alloc(&o);
#endif
    } else if (use_tcl) {
#ifndef HAVE_TCL
	fprintf(stderr, "tcl specified, but tcl OS handler not available.\n");
	exit(1);
#else
	if (num_extra_threads > 0)
	    fprintf(stderr, "Number of extra threads is %u, incompatible with"
		    " TCL, forcing to 0\n", num_extra_threads);
	num_extra_threads = 0;
	os_func_str = " --tcl";
	rv = gensio_tcl_funcs_alloc(&o);
#endif
    } else {
	rv = gensio_default_os_hnd(GENSIO_DEF_WAKE_SIG, &o);
    }
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	goto out_err;
    }
    gensio_os_funcs_set_vlog(o, do_vlog);

    rv = gensio_os_proc_setup(o, &proc_data);
    if (rv) {
	fprintf(stderr, "Error setting up process data: %s\n",
		gensio_err_to_str(rv));
	exit(1);
    }

    if (list_tests) {
	for (j = 0; oom_tests[j].connecter; j++) {
	    if (!check_oom_test_present(o, oom_tests + j))
		continue;
	    printf("%d : %s %s\n", j, oom_tests[j].connecter,
		   oom_tests[j].accepter ? oom_tests[j].accepter : "");
	    if (oom_tests[j].end_test_suite)
		oom_tests[j].end_test_suite(o, oom_tests + j);
	}
	exit(0);
    }

    printf("iodata_size is %lu\n", (unsigned long) iodata_size);

    iodata = malloc(iodata_size);
    if (!iodata) {
	fprintf(stderr, "Out of memory allocation I/O data\n");
	return 1;
    }
    if (fill_random(iodata, iodata_size))
	return 1;

    if (i >= argc) {
	rv = gensio_os_env_getalloc(o, "GENSIOT", &s);
	if (rv != 0) {
	    fprintf(stderr, "Can't get GENSIOT: %s\n", gensio_err_to_str(rv));
	    exit(1);
	}
    } else {
	s = argv[i];
    }
    gensiot = gensio_quote_string(o, s);
    if (!gensiot) {
	fprintf(stderr, "Out of memory copying gensiot string\n");
	exit(1);
    }
    if (i >= argc)
	gensio_os_funcs_zfree(o, s);

    for (i = 0; i < num_extra_threads; i++) {
	loopwaiter[i] = gensio_os_funcs_alloc_waiter(o);
	if (!loopwaiter[i]) {
	    fprintf(stderr, "Could not allocate loop waiter\n");
	    goto out_err;
	}

	rv = gensio_os_new_thread(o, gensio_loop, loopwaiter[i], &loopth[i]);
	if (rv) {
	    fprintf(stderr, "Could not allocate loop thread: %s",
		    gensio_err_to_str(rv));
	    goto out_err;
	}
    }

    rv = gensio_os_argvenv_alloc(o, &env.argv, &env.args, &env.argc);
    if (rv) {
	fprintf(stderr, "Could not allocate environment array: %s",
		gensio_err_to_str(rv));
	goto out_err;
    }

    if (user_test.connecter) {
	run_tests(&user_test, testnrstart, testnrend,
		  &skipcount, &errcount, &testcount, &env);
    } else {
	for (j = 0; j < repeat_count; j++) {
	    if (testnr < 0) {
		for (i = 0; oom_tests[i].connecter; i++) {
		    if (oom_tests[i].no_default_run)
			continue;
		    run_tests(oom_tests + i, testnrstart, testnrend,
			      &skipcount, &errcount, &testcount, &env);
		}
	    } else {
		run_tests(oom_tests + testnr, testnrstart, testnrend,
			  &skipcount, &errcount, &testcount, &env);
	    }
	}
    }

    gensio_argv_free(o, env.argv);

    for (i = 0; i < num_extra_threads; i++) {
	gensio_os_funcs_wake(o, loopwaiter[i]);
	gensio_os_wait_thread(loopth[i]);
	gensio_os_funcs_free_waiter(o, loopwaiter[i]);
    }

    for (i = 0; oom_tests[i].connecter; i++) {
	if (oom_tests[i].free_connecter)
	    gensio_os_funcs_zfree(o, oom_tests[i].connecter);
    }

    printf("Got %ld errors, skipped %ld tests\n", errcount, skipcount);
    while (o && gensio_os_funcs_service(o, &zerotime) == 0)
	;
    cleanup_ods();
    gensio_cleanup_mem(o);
    if (testcount == 0)
	return 77;
    gensio_osfunc_exit(!!errcount);

 out_err:
    gensio_os_proc_cleanup(proc_data);
    gensio_os_funcs_zfree(o, gensiot);
    cleanup_ods();
    gensio_cleanup_mem(o);
    gensio_os_funcs_free(o);
    gensio_osfunc_exit(1);
    return 1;
}
