/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

%module gensio

/*
 * The gensio library can dynamically load other modules that need access
 * to the original library.  So we need to set RTLD_GLOBAL while loading.
 */
%pythonbegin %{
import sys
import os
if os.name != 'nt':
    origdlopenflags = sys.getdlopenflags()
    sys.setdlopenflags(os.RTLD_GLOBAL | os.RTLD_LAZY)
%}
%pythoncode %{
if os.name != 'nt':
    sys.setdlopenflags(origdlopenflags)
%}

%{
#include "config.h"
#include <string.h>
#include <signal.h>

#include <gensio/gensio.h>
#include <gensio/sergensio.h>
#include <gensio/gensio_selector.h>
#include <gensio/gensio_mdns.h>
#include <gensio/netif.h>
#include <gensio/gensio_swig.h>

static void wake_curr_waiter(void);
%}

%include "gensio_langinfo.i"

%{
struct waiter {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
};

static void oom_err(void);

/*
 * If an exception occurs inside a waiter, we want to stop the wait
 * operation and propagate back.  So we wake it up
 */
#ifdef USE_POSIX_THREADS
struct gensio_wait_block {
    struct waiter *curr_waiter;
};

static pthread_key_t gensio_thread_key;

static void
gensio_key_del(void *data)
{
    free(data);
}

static struct waiter *
save_waiter(struct waiter *waiter)
{
    struct gensio_wait_block *data = (struct gensio_wait_block *)
	pthread_getspecific(gensio_thread_key);
    struct waiter *prev_waiter;

    if (!data) {
	data = (struct gensio_wait_block *) malloc(sizeof(*data));
	if (!data) {
	    oom_err();
	    return NULL;
	}
	memset(data, 0, sizeof(*data));
	pthread_setspecific(gensio_thread_key, data);
    }

    prev_waiter = data->curr_waiter;
    data->curr_waiter = waiter;

    return prev_waiter;
}

static void
restore_waiter(struct waiter *prev_waiter)
{
    struct gensio_wait_block *data = (struct gensio_wait_block *)
	pthread_getspecific(gensio_thread_key);

    data->curr_waiter = prev_waiter;
}

static void
wake_curr_waiter(void)
{
    struct gensio_wait_block *data = (struct gensio_wait_block *)
	pthread_getspecific(gensio_thread_key);

    if (!data)
	return;
    if (data->curr_waiter)
	gensio_os_funcs_wake(data->curr_waiter->o, data->curr_waiter->waiter);
}

#elif defined(USE_WIN32_THREADS)
struct gensio_wait_block {
    struct waiter *curr_waiter;
};

static DWORD gensio_threadkey_idx;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    struct gensio_wait_block *b;

    switch (fdwReason)
    {
    case DLL_PROCESS_DETACH:
	b = TlsGetValue(gensio_threadkey_idx);
	if (b)
	    free(b);

	TlsFree(gensio_threadkey_idx);
	break;

    case DLL_THREAD_DETACH:
	b = TlsGetValue(gensio_threadkey_idx);
	if (b)
	    free(b);
	break;

    default:
	break;
    }

    return TRUE;
}

static struct waiter *
save_waiter(struct waiter *waiter)
{
    struct gensio_wait_block *data = TlsGetValue(gensio_threadkey_idx);
    struct waiter *prev_waiter;

    if (!data) {
	data = (struct gensio_wait_block *) malloc(sizeof(*data));
	if (!data) {
	    oom_err();
	    return NULL;
	}
	memset(data, 0, sizeof(*data));
	TlsSetValue(gensio_threadkey_idx, data);
    }

    prev_waiter = data->curr_waiter;
    data->curr_waiter = waiter;

    return prev_waiter;
}

static void
restore_waiter(struct waiter *prev_waiter)
{
    struct gensio_wait_block *data = TlsGetValue(gensio_threadkey_idx);

    data->curr_waiter = prev_waiter;
}

static void
wake_curr_waiter(void)
{
    struct gensio_wait_block *data = TlsGetValue(gensio_threadkey_idx);

    if (!data)
	return;
    if (data->curr_waiter)
	gensio_os_funcs_wake(data->curr_waiter->o, data->curr_waiter->waiter);
}

#else
static struct waiter *curr_waiter;

static struct waiter *
save_waiter(struct waiter *waiter)
{
    struct waiter *prev_waiter = curr_waiter;

    curr_waiter = waiter;
    return prev_waiter;
}

static void
restore_waiter(struct waiter *prev_waiter)
{
    curr_waiter = prev_waiter;
}

static void
wake_curr_waiter(void)
{
    if (curr_waiter)
	gensio_os_funcs_wake(curr_waiter->o, curr_waiter->waiter);
}
#endif

static void
gensio_do_wait(struct waiter *waiter, unsigned int count,
	       gensio_time *timeout)
{
    int err;
    struct waiter *prev_waiter = save_waiter(waiter);

    do {
	GENSIO_SWIG_C_BLOCK_ENTRY
	err = gensio_os_funcs_wait_intr(waiter->o,
					waiter->waiter, count, timeout);
	GENSIO_SWIG_C_BLOCK_EXIT
	if (check_for_err(err)) {
	    if (prev_waiter)
		gensio_os_funcs_wake(prev_waiter->o, prev_waiter->waiter);
	    break;
	}
	if (err == GE_INTERRUPTED)
	    continue;
	break;
    } while (1);
    restore_waiter(prev_waiter);
}

static int
gensio_do_service(struct waiter *waiter, gensio_time *timeout)
{
    int err;
    struct waiter *prev_waiter = save_waiter(waiter);

    do {
	GENSIO_SWIG_C_BLOCK_ENTRY
	err = gensio_os_funcs_service(waiter->o, timeout);
	GENSIO_SWIG_C_BLOCK_EXIT
	if (check_for_err(err)) {
	    if (prev_waiter)
		gensio_os_funcs_wake(prev_waiter->o, prev_waiter->waiter);
	    break;
	}
	if (err == GE_INTERRUPTED)
	    continue;
	break;
    } while (1);
    restore_waiter(prev_waiter);
    return err;
}

#ifdef USE_POSIX_THREADS
static void
gensio_thread_sighandler(int sig)
{
    /* Nothing to do, signal just wakes things up. */
}
#endif

struct gensio_os_funcs *alloc_gensio_os_funcs(swig_cb *log_handler)
{
    struct gensio_os_funcs *o;
    int err;
    int wake_sig;
#ifdef USE_POSIX_THREADS
    struct sigaction act;

    wake_sig = SIGUSR1;
    act.sa_handler = gensio_thread_sighandler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    err = sigaction(SIGUSR1, &act, NULL);
    if (err) {
	fprintf(stderr, "Unable to setup wake signal: %s, giving up\n",
		strerror(errno));
	exit(1);
    }
#else
    wake_sig = 0;
#endif

    err = gensio_default_os_hnd(wake_sig, &o);
    if (err) {
	fprintf(stderr, "Unable to allocate gensio os funcs: %s, giving up\n",
		gensio_err_to_str(err));
	exit(1);
    }

    err = gensio_swig_setup_os_funcs(o, log_handler);
    if (err) {
	fprintf(stderr, "Unable to set up gensio os funcs: %s, giving up\n",
		gensio_err_to_str(err));
	exit(1);
    }

    return o;
}

struct gensio_os_funcs *alloc_gensio_selector(swig_cb *log_handler)
{
    return alloc_gensio_os_funcs(log_handler);
}

static void gensio_mdns_delete_watch_done(struct gensio_mdns_watch *watch,
					  void *userdata)
{
    struct mdns_watch *w = (struct mdns_watch *) userdata;
    struct gensio_os_funcs *o = w->o;

    gensio_os_funcs_lock(o, w->lock);
    gensio_os_funcs_unlock(o, w->lock);
    gensio_os_funcs_free_lock(o, w->lock);
    deref_swig_cb_val(w->cb_val);
    gensio_os_funcs_zfree(o, w);
    check_os_funcs_free(o);
}

%}

%init %{
#ifdef USE_POSIX_THREADS
    {
	int err;

	err = pthread_key_create(&gensio_thread_key, gensio_key_del);
	if (err) {
	    fprintf(stderr, "Error creating gensio thread key: %s, giving up\n",
		    strerror(err));
	    exit(1);
	}
    }
#elif defined(USE_WIN32_THREADS)
    gensio_threadkey_idx = TlsAlloc();
    if (gensio_threadkey_idx == TLS_OUT_OF_INDEXES) {
	fprintf(stderr, "Error creating gensio thread key index\n");
	exit(1);
    }
#endif
    gensio_swig_init_lang();
%}

%include <typemaps.i>
%include <exception.i>

%nodefaultctor sergensio;
%nodefaultctor sergensio_accepter;
%nodefaultctor gensio_os_funcs;
struct gensio { };
struct sergensio { };
struct gensio_accepter { };
struct sergensio_accepter { };
struct gensio_os_funcs { };
struct waiter { };

%extend gensio_os_funcs {
    ~gensio_os_funcs() {
	check_os_funcs_free(self);
    }
}

%constant int GE_NOTSUP = GE_NOTSUP;
%constant int GE_CERTNOTFOUND = GE_CERTNOTFOUND;
%constant int GE_CERTREVOKED = GE_CERTREVOKED;
%constant int GE_CERTEXPIRED = GE_CERTEXPIRED;
%constant int GE_CERTINVALID = GE_CERTINVALID;
%constant int GE_KEYINVALID = GE_KEYINVALID;
%constant int GE_AUTHREJECT = GE_AUTHREJECT;

%constant int GENSIO_CONTROL_DEPTH_ALL = GENSIO_CONTROL_DEPTH_ALL;
%constant int GENSIO_CONTROL_DEPTH_FIRST = GENSIO_CONTROL_DEPTH_FIRST;
%constant bool GENSIO_CONTROL_GET = GENSIO_CONTROL_GET;
%constant bool GENSIO_CONTROL_SET = GENSIO_CONTROL_SET;
%constant int GENSIO_CONTROL_NODELAY = GENSIO_CONTROL_NODELAY;
%constant int GENSIO_CONTROL_STREAMS = GENSIO_CONTROL_STREAMS;
%constant int GENSIO_CONTROL_SEND_BREAK = GENSIO_CONTROL_SEND_BREAK;
%constant int GENSIO_CONTROL_GET_PEER_CERT_NAME =
    GENSIO_CONTROL_GET_PEER_CERT_NAME;
%constant int GENSIO_CONTROL_CERT_AUTH = GENSIO_CONTROL_CERT_AUTH;
%constant int GENSIO_CONTROL_USERNAME = GENSIO_CONTROL_USERNAME;
%constant int GENSIO_CONTROL_SERVICE = GENSIO_CONTROL_SERVICE;
%constant int GENSIO_CONTROL_CERT = GENSIO_CONTROL_CERT;
%constant int GENSIO_CONTROL_CERT_FINGERPRINT = GENSIO_CONTROL_CERT_FINGERPRINT;
%constant int GENSIO_CONTROL_ENVIRONMENT = GENSIO_CONTROL_ENVIRONMENT;
%constant int GENSIO_CONTROL_MAX_WRITE_PACKET = GENSIO_CONTROL_MAX_WRITE_PACKET;
%constant int GENSIO_CONTROL_ARGS = GENSIO_CONTROL_ARGS;
%constant int GENSIO_CONTROL_EXIT_CODE = GENSIO_CONTROL_EXIT_CODE;
%constant int GENSIO_CONTROL_WAIT_TASK = GENSIO_CONTROL_WAIT_TASK;
%constant int GENSIO_CONTROL_ADD_MCAST = GENSIO_CONTROL_ADD_MCAST;
%constant int GENSIO_CONTROL_DEL_MCAST = GENSIO_CONTROL_DEL_MCAST;
%constant int GENSIO_CONTROL_LADDR = GENSIO_CONTROL_LADDR;
%constant int GENSIO_CONTROL_LPORT = GENSIO_CONTROL_LPORT;
%constant int GENSIO_CONTROL_CLOSE_OUTPUT = GENSIO_CONTROL_CLOSE_OUTPUT;
%constant int GENSIO_CONTROL_CONNECT_ADDR_STR = GENSIO_CONTROL_CONNECT_ADDR_STR;
%constant int GENSIO_CONTROL_RADDR = GENSIO_CONTROL_RADDR;
%constant int GENSIO_CONTROL_RADDR_BIN = GENSIO_CONTROL_RADDR_BIN;
%constant int GENSIO_CONTROL_REMOTE_ID = GENSIO_CONTROL_REMOTE_ID;
%constant int GENSIO_CONTROL_KILL_TASK = GENSIO_CONTROL_KILL_TASK;
%constant int GENSIO_CONTROL_MCAST_LOOP = GENSIO_CONTROL_MCAST_LOOP;
%constant int GENSIO_CONTROL_MCAST_TTL = GENSIO_CONTROL_MCAST_TTL;
%constant int GENSIO_CONTROL_PASSWORD = GENSIO_CONTROL_PASSWORD;
%constant int GENSIO_CONTROL_2FA = GENSIO_CONTROL_2FA;
%constant int GENSIO_CONTROL_AUX_DATA = GENSIO_CONTROL_AUX_DATA;
%constant int GENSIO_CONTROL_REM_AUX_DATA = GENSIO_CONTROL_REM_AUX_DATA;
%constant int GENSIO_CONTROL_EXTRAINFO = GENSIO_CONTROL_EXTRAINFO;
%constant int GENSIO_CONTROL_ENABLE_OOB = GENSIO_CONTROL_ENABLE_OOB;

%constant int GENSIO_NETTYPE_UNSPEC = GENSIO_NETTYPE_UNSPEC;
%constant int GENSIO_NETTYPE_IPV4 = GENSIO_NETTYPE_IPV4;
%constant int GENSIO_NETTYPE_IPV6 = GENSIO_NETTYPE_IPV6;
%constant int GENSIO_NETTYPE_UNIX = GENSIO_NETTYPE_UNIX;

%constant int GE_NOERR = GE_NOERR;
%constant int GE_NOMEM = GE_NOMEM;
%constant int GE_NOTSUP = GE_NOTSUP;
%constant int GE_INVAL = GE_INVAL;
%constant int GE_NOTFOUND = GE_NOTFOUND;
%constant int GE_EXISTS = GE_EXISTS;
%constant int GE_OUTOFRANGE = GE_OUTOFRANGE;
%constant int GE_INCONSISTENT = GE_INCONSISTENT;
%constant int GE_NODATA = GE_NODATA;
%constant int GE_OSERR = GE_OSERR;
%constant int GE_INUSE = GE_INUSE;
%constant int GE_INPROGRESS = GE_INPROGRESS;
%constant int GE_NOTREADY = GE_NOTREADY;
%constant int GE_TOOBIG = GE_TOOBIG;
%constant int GE_TIMEDOUT = GE_TIMEDOUT;
%constant int GE_RETRY = GE_RETRY;
%constant int GE_KEYNOTFOUND = GE_KEYNOTFOUND;
%constant int GE_CERTREVOKED = GE_CERTREVOKED;
%constant int GE_CERTEXPIRED = GE_CERTEXPIRED;
%constant int GE_KEYINVALID = GE_KEYINVALID;
%constant int GE_NOCERT = GE_NOCERT;
%constant int GE_CERTINVALID = GE_CERTINVALID;
%constant int GE_PROTOERR = GE_PROTOERR;
%constant int GE_COMMERR = GE_COMMERR;
%constant int GE_IOERR = GE_IOERR;
%constant int GE_REMCLOSE = GE_REMCLOSE;
%constant int GE_HOSTDOWN = GE_HOSTDOWN;
%constant int GE_CONNREFUSE = GE_CONNREFUSE;
%constant int GE_DATAMISSING = GE_DATAMISSING;
%constant int GE_CERTNOTFOUND = GE_CERTNOTFOUND;
%constant int GE_AUTHREJECT = GE_AUTHREJECT;
%constant int GE_ADDRINUSE = GE_ADDRINUSE;
%constant int GE_INTERRUPTED = GE_INTERRUPTED;
%constant int GE_SHUTDOWN = GE_SHUTDOWN;
%constant int GE_LOCALCLOSED = GE_LOCALCLOSED;
%constant int GE_PERM = GE_PERM;
%constant int GE_APPERR = GE_APPERR;

%constant char *version = gensio_version_string;

%extend gensio {
    gensio(struct gensio_os_funcs *o, char *str, swig_cb *handler) {
	int rv;
	struct gensio_data *data;
	struct gensio *io = NULL;

	data = alloc_gensio_data(o, handler);
	if (!data)
	    return NULL;

	rv = str_to_gensio(str, o, gensio_child_event, data, &io);
	if (rv) {
	    free_gensio_data(data);
	    err_handle("gensio alloc", rv);
	}
	return io;
    }

    ~gensio()
    {
	struct gensio_data *data = (struct gensio_data *)
	    gensio_get_user_data(self);

	if (data->tmpval)
	    return;
	deref_gensio_data(data, self);
    }

    %newobject new_parent;
    struct gensio *new_parent(struct gensio_os_funcs *o, char *str,
			      swig_cb *handler) {
	int rv;
	struct gensio_data *data;
	struct gensio *io = NULL;

	data = alloc_gensio_data(o, handler);
	if (!data)
	    return NULL;

	rv = str_to_gensio_child(self, str, o, gensio_child_event, data, &io);
	if (rv) {
	    free_gensio_data(data);
	    err_handle("gensio alloc", rv);
	}
	return io;
    }

    void set_cbs(swig_cb *handler) {
	struct gensio_data *data = (struct gensio_data *)
	    gensio_get_user_data(self);

	if (data->handler_val)
	    deref_swig_cb_val(data->handler_val);
	if (handler)
	    data->handler_val = ref_swig_cb(handler, read_callback);
	else
	    data->handler_val = NULL;
    }

    %rename(open) opent;
    void opent(swig_cb *done) {
	swig_cb_val *done_val = NULL;
	void (*open_done)(struct gensio *io, int err, void *cb_data) = NULL;
	int rv;

	if (!nil_swig_cb(done)) {
	    open_done = gensio_open_done;
	    done_val = ref_swig_cb(done, open_done);
	}
	rv = gensio_open(self, open_done, done_val);
	if (rv && done_val)
	    deref_swig_cb_val(done_val);

	err_handle("open", rv);
    }

    %rename(open_nochild) open_nochildt;
    void open_nochildt(swig_cb *done) {
	swig_cb_val *done_val = NULL;
	void (*open_done)(struct gensio *io, int err, void *cb_data) = NULL;
	int rv;

	if (!nil_swig_cb(done)) {
	    open_done = gensio_open_done;
	    done_val = ref_swig_cb(done, open_done);
	}
	rv = gensio_open_nochild(self, open_done, done_val);
	if (rv && done_val)
	    deref_swig_cb_val(done_val);

	err_handle("open_nochild", rv);
    }

    %rename(open_s) open_st;
    void open_st() {
	err_handle("open_s", gensio_open_s(self));
    }

    %rename(open_nochild_s) open_nochild_st;
    void open_nochild_st() {
	err_handle("open_nochild_s", gensio_open_nochild_s(self));
    }

    %newobject alloc_channelt;
    %rename(alloc_channel) alloc_channelt;
    /*
     * Note that auxdata is really args, but we are reusing the typemap
     * for auxdata for it.
     */
    struct gensio *alloc_channelt(const char **auxdata,
				  swig_cb *handler) {
	struct gensio_data *olddata = (struct gensio_data *)
	    gensio_get_user_data(self);
	int rv = 0;
	struct gensio_data *data;
	struct gensio *io = NULL;

	data = alloc_gensio_data(olddata->o, handler);
	if (!data) {
	    err_handle("gensio alloc channel", GE_NOMEM);
	    return NULL;
	}

	rv = gensio_alloc_channel(self, auxdata, gensio_child_event, data, &io);
	if (rv) {
	    free_gensio_data(data);
	    err_handle("alloc_channel", rv);
	}

	return io;
    }

    %rename(get_type) get_typet;
    const char *get_typet(unsigned int depth) {
	return gensio_get_type(self, depth);
    }

    %rename(close) closet;
    void closet(swig_cb *done) {
	swig_cb_val *done_val = NULL;
	void (*close_done)(struct gensio *io, void *cb_data) = NULL;
	int rv;

	if (!nil_swig_cb(done)) {
	    close_done = gensio_close_done;
	    done_val = ref_swig_cb(done, close_done);
	}
	rv = gensio_close(self, close_done, done_val);
	if (rv && done_val)
	    deref_swig_cb_val(done_val);

	err_handle("close", rv);
    }

    %rename(close_s) close_st;
    void close_st() {
	err_handle("close_s", gensio_close_s(self));
    }

    %rename(write) writet;
    unsigned int writet(char *bytestr, my_ssize_t len,
			const char **auxdata) {
	gensiods wr = 0;
	int rv;

	rv = gensio_write(self, &wr, bytestr, len, auxdata);
	err_handle("write", rv);
	return wr;
    }

    void read_cb_enable(bool enable) {
	gensio_set_read_callback_enable(self, enable);
    }

    void write_cb_enable(bool enable) {
	gensio_set_write_callback_enable(self, enable);
    }

    %rename(set_sync) set_synct;
    void set_synct() {
	int rv = gensio_set_sync(self);
	err_handle("set_sync", rv);
    }

    %rename(clear_sync) clear_synct;
    void clear_synct() {
	int rv = gensio_clear_sync(self);
	err_handle("clear_sync", rv);
    }

    %rename(read_s) read_st;
    void read_st(char **rbuffer, size_t *rbuffer_len, long *r_int,
		 unsigned int reqlen, long timeout) {
	int rv;
	gensio_time tv = { timeout / 1000, (((int32_t) timeout % 1000)
					    * 1000000) };
	gensio_time *rtv = &tv;
	char *buf = (char *) malloc(reqlen);
	gensiods count = 0;

	if (!buf) {
	    rv = GE_NOMEM;
	    goto out;
	}
	if (timeout < 0)
	    rtv = NULL;
	rv = gensio_read_s(self, &count, buf, reqlen, rtv);
	if (rv) {
	    free(buf);
	} else {
	    *rbuffer = buf;
	    *rbuffer_len = count;
	}
	if (rtv)
	    *r_int = rtv->secs * 1000 + ((rtv->nsecs + 500000) / 1000000);
	else
	    *r_int = 0;
    out:
	err_handle("read_s", rv);
    }

    %rename(read_s_intr) read_s_intrt;
    void read_s_intrt(char **rbuffer, size_t *rbuffer_len, long *r_int,
		      unsigned int reqlen, long timeout) {
	int rv;
	gensio_time tv = { timeout / 1000, (((int32_t) (timeout % 1000))
					    * 1000000) };
	gensio_time *rtv = &tv;
	char *buf = (char *) malloc(reqlen);
	gensiods count = 0;

	if (!buf) {
	    rv = GE_NOMEM;
	    goto out;
	}
	if (timeout < 0)
	    rtv = NULL;
	rv = gensio_read_s_intr(self, &count, buf, reqlen, rtv);
	if (rv) {
	    free(buf);
	} else {
	    *rbuffer = buf;
	    *rbuffer_len = count;
	}
	if (rtv)
	    *r_int = rtv->secs * 1000 + ((rtv->nsecs + 500000) / 1000000);
	else
	    *r_int = 0;
    out:
	err_handle("read_s_intr", rv);
    }

    %rename(write_s) write_st;
    long write_st(long *r_int, char *bytestr, my_ssize_t len, long timeout) {
	int rv;
	gensio_time tv = { timeout / 1000, (((int32_t) (timeout % 1000))
					    * 1000000) };
	gensio_time *rtv = &tv;
	gensiods count = 0;

	if (timeout < 0)
	    rtv = NULL;
	rv = gensio_write_s(self, &count, bytestr, len, rtv);
	err_handle("write_s", rv);
	if (rtv)
	    *r_int = rtv->secs * 1000 + ((rtv->nsecs + 500000) / 1000000);
	else
	    *r_int = 0;
	return count;
    }

    %rename(write_s_intr) write_s_intrt;
    long write_s_intrt(long *r_int, char *bytestr, my_ssize_t len,
		       long timeout) {
	int rv;
	gensio_time tv = { timeout / 1000, (((int32_t) (timeout % 1000))
					    * 1000000) };
	gensio_time *rtv = &tv;
	gensiods count = 0;

	if (timeout < 0)
	    rtv = NULL;
	rv = gensio_write_s_intr(self, &count, bytestr, len, rtv);
	err_handle("write_s_intr", rv);
	if (rtv)
	    *r_int = rtv->secs * 1000 + ((rtv->nsecs + 500000) / 1000000);
	else
	    *r_int = 0;
	return count;
    }

    %rename(control) controlt;
    %newobject controlt;
    void controlt(char **rstr, size_t *rstr_len, int depth,
		  bool get, int option, char *bytestr, my_ssize_t len) {
	int rv;
	char *data = NULL;
	gensiods glen = 0, slen = len;

	if (get) {
	    /* Pass in a zero length to get the actual length. */
	    rv = gensio_control(self, depth, get, option, bytestr, &glen);
	    if (rv)
		goto out;
	    /* Allocate the larger of strlen(bytestr) and len) */
	    if (slen > glen) {
		data = (char *) malloc(slen + 1);
		glen = slen;
	    } else {
		data = (char *) malloc(glen + 1);
	    }
	    if (!data) {
		rv = GE_NOMEM;
		goto out;
	    }
	    data[glen] = '\0';
	    data[slen] = '\0';
	    glen += 1;
	    if (bytestr) {
		memcpy(data, bytestr, slen);
	    } else {
		data[0] = '\0';
	    }
	    rv = gensio_control(self, depth, get, option, data, &glen);
	    if (rv) {
		free(data);
		data = NULL;
	    }
	out:
	    if (rv == GE_NOTFOUND) /* Return None for ENOENT. */
		goto out_ret;
	} else {
	    rv = gensio_control(self, depth, get, option, bytestr, &slen);
	}

	err_handle("control", rv);
    out_ret:
	*rstr = data;
	*rstr_len = glen;
    }

    %rename(get_child) get_childt;
    %newobject get_childt;
    bool get_childt(int depth) {
	return gensio_get_child(self, depth);
    }

    %rename(is_client) is_clientt;
    bool is_clientt() {
	return gensio_is_client(self);
    }

    %rename(is_packet) is_packett;
    bool is_packett() {
	return gensio_is_packet(self);
    }

    %rename(is_reliable) is_reliablet;
    bool is_reliablet() {
	return gensio_is_reliable(self);
    }

    %rename(is_authenticated) is_authenticated;
    bool is_authenticatedt() {
	return gensio_is_authenticated(self);
    }

    %rename(is_encrypted) is_encryptedt;
    bool is_encryptedt() {
	return gensio_is_encrypted(self);
    }

    %newobject cast_to_sergensio;
    struct sergensio *cast_to_sergensio() {
	struct gensio_data *data = (struct gensio_data *)
	    gensio_get_user_data(self);
	struct sergensio *sio = gensio_to_sergensio(self);

	if (!sio)
	    cast_error("sergensio", "gensio");
	else
	    ref_gensio_data(data);
	return sio;
    }

    bool same_as(struct gensio *other) {
	return self == other;
    }
}

%define sgensio_entry(name)
    void sg_##name(int name, swig_cb *h) {
	struct sergensio_cbdata *cbdata = NULL;
	int rv;

	if (!nil_swig_cb(h)) {
	    cbdata = sergensio_cbdata(name, h);
	    if (!cbdata) {
		oom_err();
		return;
	    }
	    rv = sergensio_##name(self, name, sergensio_cb, cbdata);
	} else {
	    rv = sergensio_##name(self, name, NULL, NULL);
	}

	if (rv && cbdata)
	    cleanup_sergensio_cbdata(cbdata);
	ser_err_handle("sg_" stringify(name), rv);
    }

    int sg_##name##_s(int name) {
	struct gensio_data *data = (struct gensio_data *)
	    sergensio_get_user_data(self);
	struct sergensio_b *b = NULL;
	int rv;

	rv = sergensio_b_alloc(self, data->o, &b);
	if (!rv)
	    rv = sergensio_##name##_b(b, &name);
	if (rv)
	    ser_err_handle("sg_" stringify(name)"_s", rv);
	if (b)
	    sergensio_b_free(b);
	return name;
    }
%enddef

%constant int SERGENSIO_PARITY_NONE = SERGENSIO_PARITY_NONE;
%constant int SERGENSIO_PARITY_ODD = SERGENSIO_PARITY_ODD;
%constant int SERGENSIO_PARITY_EVEN = SERGENSIO_PARITY_EVEN;
%constant int SERGENSIO_PARITY_MARK = SERGENSIO_PARITY_MARK;
%constant int SERGENSIO_PARITY_SPACE = SERGENSIO_PARITY_SPACE;

%constant int SERGENSIO_FLOWCONTROL_NONE = SERGENSIO_FLOWCONTROL_NONE;
%constant int SERGENSIO_FLOWCONTROL_XON_XOFF = SERGENSIO_FLOWCONTROL_XON_XOFF;
%constant int SERGENSIO_FLOWCONTROL_RTS_CTS = SERGENSIO_FLOWCONTROL_RTS_CTS;
%constant int SERGENSIO_FLOWCONTROL_DCD = SERGENSIO_FLOWCONTROL_DCD;
%constant int SERGENSIO_FLOWCONTROL_DTR = SERGENSIO_FLOWCONTROL_DTR;
%constant int SERGENSIO_FLOWCONTROL_DSR = SERGENSIO_FLOWCONTROL_DSR;

%constant int SERGENSIO_BREAK_ON = SERGENSIO_BREAK_ON;
%constant int SERGENSIO_BREAK_OFF = SERGENSIO_BREAK_OFF;

%constant int SERGENSIO_DTR_ON = SERGENSIO_DTR_ON;
%constant int SERGENSIO_DTR_OFF = SERGENSIO_DTR_OFF;

%constant int SERGENSIO_RTS_ON = SERGENSIO_RTS_ON;
%constant int SERGENSIO_RTS_OFF = SERGENSIO_RTS_OFF;

%constant int SERGENSIO_CTS_AUTO = SERGENSIO_CTS_AUTO;
%constant int SERGENSIO_CTS_OFF = SERGENSIO_CTS_OFF;

%constant int SERGENSIO_DCD_DSR_ON = SERGENSIO_DCD_DSR_ON;
%constant int SERGENSIO_DCD_DSR_OFF = SERGENSIO_DCD_DSR_OFF;

%constant int SERGENSIO_RI_ON = SERGENSIO_RI_ON;
%constant int SERGENSIO_RI_OFF = SERGENSIO_RI_OFF;

%constant int SERGENSIO_LINESTATE_DATA_READY = SERGENSIO_LINESTATE_DATA_READY;
%constant int SERGENSIO_LINESTATE_OVERRUN_ERR = SERGENSIO_LINESTATE_OVERRUN_ERR;
%constant int SERGENSIO_LINESTATE_PARITY_ERR = SERGENSIO_LINESTATE_PARITY_ERR;
%constant int SERGENSIO_LINESTATE_FRAMING_ERR = SERGENSIO_LINESTATE_FRAMING_ERR;
%constant int SERGENSIO_LINESTATE_BREAK = SERGENSIO_LINESTATE_BREAK;
%constant int SERGENSIO_LINESTATE_XMIT_HOLD_EMPTY =
	SERGENSIO_LINESTATE_XMIT_HOLD_EMPTY;
%constant int SERGENSIO_LINESTATE_XMIT_SHIFT_EMPTY =
	SERGENSIO_LINESTATE_XMIT_SHIFT_EMPTY;
%constant int SERGENSIO_LINESTATE_TIMEOUT_ERR = SERGENSIO_LINESTATE_TIMEOUT_ERR;

%constant int SERGENSIO_MODEMSTATE_CTS_CHANGED = SERGENSIO_MODEMSTATE_CTS_CHANGED;
%constant int SERGENSIO_MODEMSTATE_DSR_CHANGED = SERGENSIO_MODEMSTATE_DSR_CHANGED;
%constant int SERGENSIO_MODEMSTATE_RI_CHANGED = SERGENSIO_MODEMSTATE_RI_CHANGED;
%constant int SERGENSIO_MODEMSTATE_CD_CHANGED = SERGENSIO_MODEMSTATE_CD_CHANGED;
%constant int SERGENSIO_MODEMSTATE_CTS = SERGENSIO_MODEMSTATE_CTS;
%constant int SERGENSIO_MODEMSTATE_DSR = SERGENSIO_MODEMSTATE_DSR;
%constant int SERGENSIO_MODEMSTATE_RI = SERGENSIO_MODEMSTATE_RI;
%constant int SERGENSIO_MODEMSTATE_CD = SERGENSIO_MODEMSTATE_CD;

%constant int SERGENSIO_FLUSH_RCV_BUFFER = SERGENSIO_FLUSH_RCV_BUFFER;
%constant int SERGENSIO_FLUSH_XMIT_BUFFER = SERGENSIO_FLUSH_XMIT_BUFFER;
%constant int SERGENSIO_FLUSH_RCV_XMIT_BUFFERS = SERGENSIO_FLUSH_RCV_XMIT_BUFFERS;
/* Note that the following are deprecated. */
%constant int SERGIO_FLUSH_RCV_BUFFER = SERGENSIO_FLUSH_RCV_BUFFER;
%constant int SERGIO_FLUSH_XMIT_BUFFER = SERGENSIO_FLUSH_XMIT_BUFFER;
%constant int SERGIO_FLUSH_RCV_XMIT_BUFFERS = SERGENSIO_FLUSH_RCV_XMIT_BUFFERS;


%nodefaultctor sergensio;
%extend sergensio {
    ~sergensio()
    {
	struct gensio *io = sergensio_to_gensio(self);
	struct gensio_data *data = (struct gensio_data *)
	    gensio_get_user_data(io);

	deref_gensio_data(data, io);
    }

    %newobject cast_to_gensio;
    struct gensio *cast_to_gensio() {
	struct gensio *io = sergensio_to_gensio(self);
	struct gensio_data *data = (struct gensio_data *)
	    gensio_get_user_data(io);

	ref_gensio_data(data);
	return io;
    }

    /* Standard baud rates. */
    sgensio_entry(baud);

    /* 5, 6, 7, or 8 bits. */
    sgensio_entry(datasize);

    /* SERGENSIO_PARITY_ entries */
    sgensio_entry(parity);

    /* 1 or 2 */
    sgensio_entry(stopbits);

    /* SERGENSIO_FLOWCONTROL_ entries */
    sgensio_entry(flowcontrol);

    /* SERGENSIO_FLOWCONTROL_ entries for iflowcontrol */
    sgensio_entry(iflowcontrol);

    /* SERGENSIO_BREAK_ entries */
    sgensio_entry(sbreak);

    /* SERGENSIO_DTR_ entries */
    sgensio_entry(dtr);

    /* SERGENSIO_RTS_ entries */
    sgensio_entry(rts);

    /* SERGENSIO_CTS_ entries */
    sgensio_entry(cts);

    /* SERGENSIO_DCD_DSR_ entries */
    sgensio_entry(dcd_dsr);

    /* SERGENSIO_RI_ entries */
    sgensio_entry(ri);

    int sg_modemstate(unsigned int modemstate) {
	return sergensio_modemstate(self, modemstate);
    }

    int sg_linestate(unsigned int linestate) {
	return sergensio_linestate(self, linestate);
    }

    int sg_flowcontrol_state(bool val) {
	return sergensio_flowcontrol_state(self, val);
    }

    int sg_flush(unsigned int val) {
	return sergensio_flush(self, val);
    }

    void sg_signature(char *value, swig_cb *h) {
	swig_cb_val *h_val = NULL;
	int rv;
	unsigned int len = 0;

	if (value)
	    len = strlen(value);
	if (!nil_swig_cb(h)) {
	    h_val = ref_swig_cb(h, signature);
	    rv = sergensio_signature(self, value, len, sergensio_sig_cb, h_val);
	} else {
	    rv = sergensio_signature(self, value, len, NULL, NULL);
	}

	if (rv && h_val)
	    deref_swig_cb_val(h_val);
	ser_err_handle("sg_signature", rv);
    }

    void sg_send_break() {
	ser_err_handle("sg_send_break", sergensio_send_break(self));
    }
}

%constant int GENSIO_ACC_CONTROL_LADDR = GENSIO_ACC_CONTROL_LADDR;
%constant int GENSIO_ACC_CONTROL_LPORT = GENSIO_ACC_CONTROL_LPORT;

%extend gensio_accepter {
    gensio_accepter(struct gensio_os_funcs *o, char *str, swig_cb *handler) {
	struct gensio_data *data;
	struct gensio_accepter *acc = NULL;
	int rv;

	data = alloc_gensio_data(o, handler);
	if (!data)
	    return NULL;

	rv = str_to_gensio_accepter(str, o, gensio_acc_child_event, data, &acc);
	if (rv) {
	    free_gensio_data(data);
	    err_handle("gensio_accepter constructor", rv);
	}

	return acc;
    }

    ~gensio_accepter()
    {
	struct gensio_data *data = (struct gensio_data *)
	    gensio_acc_get_user_data(self);

	deref_gensio_accepter_data(data, self);
    }

    void set_cbs(swig_cb *handler) {
	struct gensio_data *data = (struct gensio_data *)
	    gensio_acc_get_user_data(self);

	if (data->handler_val)
	    deref_swig_cb_val(data->handler_val);
	if (handler)
	    data->handler_val = ref_swig_cb(handler, read_callback);
	else
	    data->handler_val = NULL;
    }

    %newobject str_to_gensio;
    struct gensio *str_to_gensio(char *str, swig_cb *handler) {
	struct gensio_data *olddata = (struct gensio_data *)
	    gensio_acc_get_user_data(self);
	int rv;
	struct gensio_data *data;
	struct gensio *io;

	data = alloc_gensio_data(olddata->o, handler);
	if (!data)
	    return NULL;

	rv = gensio_acc_str_to_gensio(self, str, gensio_child_event, data,
				      &io);
	if (rv) {
	    free_gensio_data(data);
	    err_handle("str to gensio", rv);
	}

	return io;
    }

    void startup() {
	int rv = gensio_acc_startup(self);

	err_handle("startup", rv);
    }

    void shutdown(swig_cb *done) {
	swig_cb_val *done_val = NULL;
	int rv;

	if (!nil_swig_cb(done))
	    done_val = ref_swig_cb(done, shutdown);
	rv = gensio_acc_shutdown(self, gensio_acc_shutdown_done, done_val);
	if (rv && done_val)
	    deref_swig_cb_val(done_val);

	err_handle("shutdown", rv);
    }

    void shutdown_s() {
	int rv = gensio_acc_shutdown_s(self);

	err_handle("shutdown_s", rv);
    }

    void set_sync() {
	int rv = gensio_acc_set_sync(self);

	err_handle("set_sync", rv);
    }

    void set_accept_callback_enable(bool enabled) {
	gensio_acc_set_accept_callback_enable(self, enabled);
    }

    void set_accept_callback_enable_cb(bool enabled, swig_cb *done) {
	swig_cb_val *done_val = NULL;
	int rv;

	if (!nil_swig_cb(done))
	    done_val = ref_swig_cb(done, acc_cb_enabled);
	rv = gensio_acc_set_accept_callback_enable_cb(self, enabled,
			      gensio_acc_set_acc_cb_done, done_val);
	if (rv && done_val)
	    deref_swig_cb_val(done_val);

	err_handle("set_accept_callback_enable_cb", rv);
    }

    void set_accept_callback_enable_s(bool enabled) {
	int rv = gensio_acc_set_accept_callback_enable_s(self, enabled);

	err_handle("set_accept_callback_enable_s", rv);
    }

    /* See note in gensio_langinfo.i, int ** is really struct gensio **. */
    void accept_s_timeout(int **r_io, long *r_int,
			  struct gensio_os_funcs *o,
			  swig_cb *handler, int timeout) {
	gensio_time tv = { timeout / 1000, (((int32_t) (timeout % 1000))
					    * 1000000) };
	int rv;
	struct gensio_data *data = alloc_gensio_data(o, handler);

	*r_io = NULL;
	*r_int = 0;
	if (!data) {
	    rv = GE_NOMEM;
	    goto out_err;
	}
	rv = gensio_acc_accept_s(self, &tv, (struct gensio **) r_io);
	if (rv) {
	    free_gensio_data(data);
	    if (rv == GE_TIMEDOUT)
		return;
	    goto out_err;
	}

	*r_int = tv.secs * 1000 + ((tv.nsecs + 500000) / 1000000);
	gensio_set_callback(*((struct gensio **) r_io), gensio_child_event, data);
	return;

    out_err:
	err_handle("accept_s_timeout", rv);
    }

    %newobject accept_s;
    struct gensio *accept_s(struct gensio_os_funcs *o, swig_cb *handler) {
	struct gensio *io = NULL;
	struct gensio_data *data = alloc_gensio_data(o, handler);
	int rv;

	rv = gensio_acc_accept_s(self, NULL, &io);
	if (rv) {
	    free_gensio_data(data);
	    err_handle("accept_s", rv);
	} else {
	    gensio_set_callback(io, gensio_child_event, data);
	}

	return io;
    }

    /* See note in gensio_langinfo.i, int ** is really struct gensio **. */
    void accept_s_intr_timeout(int **r_io, long *r_int,
			       struct gensio_os_funcs *o,
			       swig_cb *handler, int timeout) {
	gensio_time tv = { timeout / 1000, (((int32_t) (timeout % 1000))
					    * 1000000) };
	int rv;
	struct gensio_data *data = alloc_gensio_data(o, handler);

	*r_io = NULL;
	*r_int = 0;
	if (!data) {
	    rv = GE_NOMEM;
	    goto out_err;
	}
	rv = gensio_acc_accept_s_intr(self, &tv, (struct gensio **) r_io);
	if (rv) {
	    free_gensio_data(data);
	    if (rv == GE_TIMEDOUT)
		return;
	    goto out_err;
	}

	*r_int = tv.secs * 1000 + ((tv.nsecs + 500000) / 1000000);
	gensio_set_callback(*((struct gensio **) r_io),
			      gensio_child_event, data);
	return;

    out_err:
	err_handle("accept_s_intr_timeout", rv);
    }

    %newobject accept_s_intr;
    struct gensio *accept_s_intr(struct gensio_os_funcs *o, swig_cb *handler) {
	struct gensio *io = NULL;
	struct gensio_data *data = alloc_gensio_data(o, handler);
	int rv;

	rv = gensio_acc_accept_s_intr(self, NULL, &io);
	if (rv) {
	    free_gensio_data(data);
	    err_handle("accept_s_intr", rv);
	} else {
	    gensio_set_callback(io, gensio_child_event, data);
	}

	return io;
    }

    char *control(int depth, bool get, int option, char *controldata) {
	int rv;
	char *data = NULL;

	if (get) {
	    gensiods len = 0, slen = strlen(controldata) + 1;

	    /* Pass in a zero length to get the actual length. */
	    rv = gensio_acc_control(self, depth, get, option, controldata,
				    &len);
	    if (rv)
		goto out;
	    len += 1;
	    /* Allocate the larger of strlen(controldata) and len) */
	    if (slen > len)
		data = (char *) malloc(slen);
	    else
		data = (char *) malloc(len);
	    if (!data) {
		rv = GE_NOMEM;
		goto out;
	    }
	    memcpy(data, controldata, slen);
	    rv = gensio_acc_control(self, depth, get, option, data, &len);
	    if (rv) {
		free(data);
		data = NULL;
	    }
	} else {
	    rv = gensio_acc_control(self, depth, get, option, controldata,
				    NULL);
	}

    out:
	err_handle("control", rv);
	return data;
    }

    bool is_packet() {
	return gensio_acc_is_packet(self);
    }

    bool is_reliable() {
	return gensio_acc_is_reliable(self);
    }

    %newobject cast_to_sergensio_acc;
    struct sergensio_accepter *cast_to_sergensio_acc() {
	struct gensio_data *data = (struct gensio_data *)
	    gensio_acc_get_user_data(self);
	struct sergensio_accepter *sacc = gensio_acc_to_sergensio_acc(self);

	if (!sacc)
	    cast_error("sergensio_accepter", "gensio_accepter");
	else
	    ref_gensio_data(data);
	return sacc;
    }
}

%extend sergensio_accepter {
    ~sergensio_accepter() {
	struct gensio_accepter *acc = sergensio_acc_to_gensio_acc(self);
	struct gensio_data *data = (struct gensio_data *)
	    gensio_acc_get_user_data(acc);

	deref_gensio_accepter_data(data, acc);
    }

    %newobject cast_to_gensio_acc;
    struct gensio_accepter *cast_to_gensio_acc() {
	struct gensio_accepter *acc = sergensio_acc_to_gensio_acc(self);
	struct gensio_data *data = (struct gensio_data *)
	    gensio_acc_get_user_data(acc);

	ref_gensio_data(data);
	return acc;
    }
}

%extend waiter {
    waiter(struct gensio_os_funcs *o) {
	struct waiter *w = (struct waiter *) malloc(sizeof(*w));

	if (w) {
	    w->o = o;
	    w->waiter = gensio_os_funcs_alloc_waiter(o);
	    if (!w->waiter) {
		free(w);
		w = NULL;
		err_handle("waiter", GE_NOMEM);
	    } else {
		os_funcs_ref(o);
	    }
	} else {
	    err_handle("waiter", GE_NOMEM);
	}

	return w;
    }

    ~waiter() {
	gensio_os_funcs_free_waiter(self->o, self->waiter);
	check_os_funcs_free(self->o);
	free(self);
    }

    long wait_timeout(unsigned int count, int timeout) {
	gensio_time tv = { timeout / 1000, (((int32_t) (timeout % 1000))
					    * 1000000) };

	gensio_do_wait(self, count, &tv);
	return tv.secs * 1000 + ((tv.nsecs + 500000) / 1000000);
    }

    void wait(unsigned int count) {
	gensio_do_wait(self, count, NULL);
    }

    void wake() {
	gensio_os_funcs_wake(self->o, self->waiter);
    }

    long service(int timeout) {
	gensio_time tv = { timeout / 1000, (((int32_t) (timeout % 1000))
					    * 1000000) };

	gensio_do_service(self, &tv);
	return tv.secs * 1000 + ((tv.nsecs + 500000) / 1000000);
    }

    long service_now() {
	gensio_time tv = { 0, 0 };

	return gensio_do_service(self, &tv);
    }
}

%nodefaultctor mdns_watch;
%nodefaultctor mdns_service;
struct mdns { };
struct mdns_watch { };
struct mdns_service { };

%extend mdns_watch {
    ~mdns_watch() {
	struct gensio_os_funcs *o = self->o;
	int rv = GE_INVAL;

	gensio_os_funcs_lock(o, self->lock);
	self->free_on_close = true;
	if (!self->closed) {
	    self->closed = true;
	    rv = gensio_mdns_remove_watch(self->watch,
					  gensio_mdns_delete_watch_done,
					  self);
	}
	gensio_os_funcs_unlock(o, self->lock);
	if (rv) {
	    gensio_os_funcs_free_lock(o, self->lock);
	    deref_swig_cb_val(self->cb_val);
	    gensio_os_funcs_zfree(o, self);
	    check_os_funcs_free(o);
	}
    }

    void close(swig_cb *done) {
	struct gensio_os_funcs *o = self->o;
	int rv;

	gensio_os_funcs_lock(o, self->lock);
	if (self->closed) {
	    rv = GE_INUSE;
	} else {
	    if (!nil_swig_cb(done))
		self->done_val = ref_swig_cb(done,
					     gensio_mdns_remove_watch_done);
	    rv = gensio_mdns_remove_watch(self->watch,
					  gensio_mdns_remove_watch_done,
					  self);
	    if (rv) {
		if (self->done_val)
		    deref_swig_cb_val(self->done_val);
	    } else {
		self->closed = true;
	    }
	}
	gensio_os_funcs_unlock(o, self->lock);
	if (rv)
	    err_handle("close", rv);
    }
}

%extend mdns_service {
    ~mdns_service() {
	gensio_mdns_remove_service(self->service);
	free(self);
    }
}

%extend mdns {
    mdns(struct gensio_os_funcs *o) {
	struct mdns *m = (struct mdns *) gensio_os_funcs_zalloc(o, sizeof(*m));
	int rv = GE_NOMEM;

	if (m) {
	    m->o = o;
	    m->lock = gensio_os_funcs_alloc_lock(o);
	    if (!m->lock) {
		gensio_os_funcs_zfree(o, m);
		m = NULL;
	    }
	}
	if (m) {
	    /* Assure m->mdns is set for other users. */
	    gensio_os_funcs_lock(o, m->lock);
	    rv = gensio_alloc_mdns(o, &m->mdns);
	    gensio_os_funcs_unlock(o, m->lock);
	    if (rv) {
		gensio_os_funcs_free_lock(o, m->lock);
		gensio_os_funcs_zfree(o, m);
		m = NULL;
	    }
	}
	if (m)
	    os_funcs_ref(o);
	else
	    err_handle("mdns", rv);

	return m;
    }

    ~mdns() {
	struct gensio_os_funcs *o = self->o;

	gensio_os_funcs_lock(o, self->lock);
	if (self->mdns && self->closed) {
	    /* Free in the close function. */
	    self->free_on_close = true;
	    gensio_os_funcs_unlock(o, self->lock);
	} else {
	    if (self->mdns)
		gensio_free_mdns(self->mdns, NULL, NULL);
	    gensio_os_funcs_unlock(o, self->lock);
	    gensio_os_funcs_free_lock(o, self->lock);
	    gensio_os_funcs_zfree(o, self);
	    check_os_funcs_free(o);
	}
    }

    void close(swig_cb *done) {
	int rv;
	struct gensio_os_funcs *o = self->o;

	gensio_os_funcs_lock(o, self->lock);
	if (self->closed) {
	    rv = GE_INUSE;
	} else {
	    if (!nil_swig_cb(done))
		self->done_val = ref_swig_cb(done, gensio_mdns_free_done);
	    rv = gensio_free_mdns(self->mdns, gensio_mdns_free_done, self);
	    if (rv) {
		if (self->done_val)
		    deref_swig_cb_val(self->done_val);
	    } else {
		self->closed = true;
	    }
	}
	gensio_os_funcs_unlock(o, self->lock);

	err_handle("close", rv);
    }

    %newobject add_service;
    struct mdns_service *add_service(int ipinterface, int ipdomain,
				     const char *name, const char *type,
				     const char *domain, const char *host,
				     int port, const char **txt)
    {
	struct mdns_service *s = (struct mdns_service *) malloc(sizeof(*s));
	int rv = GE_NOMEM;

	if (s) {
	    rv = gensio_mdns_add_service(self->mdns,
					 ipinterface, ipdomain, name, type,
					 domain, host, port, txt, &s->service);
	    if (rv) {
		free(s);
		s = NULL;
	    }
	}
	if (!s)
	    err_handle("add_service", rv);
	return s;
    }

    %newobject add_watch;
    struct mdns_watch *add_watch(int ipinterface, int ipdomain,
				 const char *name, const char *type,
				 const char *domain, const char *host,
				 swig_cb *cb)
    {
	struct gensio_os_funcs *o = self->o;
	struct mdns_watch *w;
	int rv = GE_NOMEM;

	if (nil_swig_cb(cb))
	    return NULL;
	w = (struct mdns_watch *) gensio_os_funcs_zalloc(o, sizeof(*w));
	if (w) {
	    w->o = o;
	    w->lock = gensio_os_funcs_alloc_lock(o);
	    if (!w->lock) {
		gensio_os_funcs_zfree(o, w);
		w = NULL;
	    }
	}
	if (w) {
	    w->cb_val = ref_swig_cb(cb, gensio_mdns_cb);
	    /* Assure w->watch is set for other users. */
	    gensio_os_funcs_lock(o, w->lock);
	    rv = gensio_mdns_add_watch(self->mdns,
				       ipinterface, ipdomain, name, type,
				       domain, host,
				       gensio_mdns_cb, w, &w->watch);
	    gensio_os_funcs_unlock(o, w->lock);
	    if (rv) {
		deref_swig_cb_val(w->cb_val);
		gensio_os_funcs_free_lock(o, w->lock);
		gensio_os_funcs_zfree(o, w);
		w = NULL;
	    }
	}
	if (w)
	    os_funcs_ref(o);
	else
	    err_handle("add_watch", rv);

	return w;
    }
}

%newobject alloc_gensio_selector;
struct gensio_os_funcs *alloc_gensio_selector(swig_cb *log_handler);

%newobject alloc_gensio_os_funcs;
struct gensio_os_funcs *alloc_gensio_os_funcs(swig_cb *log_handler);

unsigned long gensio_num_alloced(void);
void gensio_cleanup_mem(struct gensio_os_funcs *o);
int get_os_funcs_refcount(struct gensio_os_funcs *o);

%constant int GENSIO_LOG_FATAL = GENSIO_LOG_FATAL;
%constant int GENSIO_LOG_ERR = GENSIO_LOG_ERR;
%constant int GENSIO_LOG_WARNING = GENSIO_LOG_WARNING;
%constant int GENSIO_LOG_INFO = GENSIO_LOG_INFO;
%constant int GENSIO_LOG_DEBUG = GENSIO_LOG_DEBUG;
%constant int GENSIO_LOG_MASK_ALL = GENSIO_LOG_MASK_ALL;

void gensio_set_log_mask(unsigned int mask);

unsigned int gensio_get_log_mask(void);

%{
struct ifinfo {
    struct gensio_os_funcs *o;
    struct gensio_net_if **ifs;
    unsigned int nifs;
};
%}
struct ifinfo { };
%extend ifinfo {
    ifinfo(struct gensio_os_funcs *o) {
	struct ifinfo *ifi;
	int rv = GE_NOMEM;

	ifi = (struct ifinfo *) gensio_os_funcs_zalloc(o, sizeof(*ifi));
	if (ifi) {
	    rv = gensio_os_get_net_ifs(o, &ifi->ifs, &ifi->nifs);
	    if (rv) {
		gensio_os_funcs_zfree(o, ifi);
		ifi = NULL;
	    } else {
		ifi->o = o;
	    }
	}
	err_handle("ifinfo", rv);
	return ifi;
    }

    ~ifinfo() {
	gensio_os_free_net_ifs(self->o, self->ifs, self->nifs);
	gensio_os_funcs_zfree(self->o, self);
    }

    unsigned int get_num_ifs() {
	return self->nifs;
    }

    char *get_name(unsigned int idx) {
	char *name = NULL;

	if (idx >= self->nifs)
	    err_handle("if_is_up", GE_OUTOFRANGE);
	else
	    name = strdup(self->ifs[idx]->name);
	return name;
    }

    bool is_up(unsigned int idx) {
	bool rv = false;

	if (idx >= self->nifs)
	    err_handle("if_is_up", GE_OUTOFRANGE);
	else
	    rv = self->ifs[idx]->flags & GENSIO_NET_IF_UP;
	return rv;
    }

    bool is_loopback(unsigned int idx) {
	bool rv = false;

	if (idx >= self->nifs)
	    err_handle("if_is_loopback", GE_OUTOFRANGE);
	else
	    rv = self->ifs[idx]->flags & GENSIO_NET_IF_LOOPBACK;
	return rv;
    }

    bool is_multicast(unsigned int idx) {
	bool rv = false;

	if (idx >= self->nifs)
	    err_handle("if_is_multicast", GE_OUTOFRANGE);
	else
	    rv = self->ifs[idx]->flags & GENSIO_NET_IF_MULTICAST;
	return rv;
    }

    unsigned int get_ifindex(unsigned int idx) {
	unsigned int ifindex = 0;

	if (idx >= self->nifs)
	    err_handle("get_ifindex", GE_OUTOFRANGE);
	else
	    ifindex = self->ifs[idx]->ifindex;
	return ifindex;
    }

    unsigned int get_num_addrs(unsigned int idx) {
	unsigned int num_addrs = 0;

	if (idx >= self->nifs)
	    err_handle("get_num_addrs", GE_OUTOFRANGE);
	else
	    num_addrs = self->ifs[idx]->naddrs;
	return num_addrs;
    }

    unsigned int get_addr_netbits(unsigned int idx, unsigned int addridx) {
	unsigned int netbits = 0;

	if (idx > self->nifs || addridx >= self->ifs[idx]->naddrs)
	    err_handle("get_addr_netbits", GE_OUTOFRANGE);
	else
	    netbits = self->ifs[idx]->addrs[addridx].netbits;
	return netbits;
    }

    char *get_addr(unsigned int idx, unsigned int addridx) {
	char *addr = NULL;

	if (idx > self->nifs || addridx >= self->ifs[idx]->naddrs) {
	    err_handle("get_addr", GE_OUTOFRANGE);
	} else {
	    struct gensio_net_addr *a = &(self->ifs[idx]->addrs[addridx]);

	    addr = strdup(a->addrstr);
	    if (!addr)
		err_handle("get_addr", GE_NOMEM);
	}
	return addr;
    }
}
