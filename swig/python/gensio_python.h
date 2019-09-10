/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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

typedef PyObject swig_cb;
typedef PyObject swig_cb_val;
typedef struct swig_ref {
    PyObject *val;
} swig_ref;

#define nil_swig_cb(v) ((v) == NULL)
#define invalidate_swig_cb(v) ((v) = NULL)

#ifdef WITH_THREAD
static void gensio_swig_init_lang(void)
{
    PyEval_InitThreads();
}
#define OI_PY_STATE PyGILState_STATE
#define OI_PY_STATE_GET() PyGILState_Ensure()
#define OI_PY_STATE_PUT(s) PyGILState_Release(s)

/* We do need to work about blocking, though. */
#define GENSIO_SWIG_C_BLOCK_ENTRY Py_BEGIN_ALLOW_THREADS
#define GENSIO_SWIG_C_BLOCK_EXIT Py_END_ALLOW_THREADS
#else
static void gensio_swig_init_lang(void)
{
}
#define OI_PY_STATE int
#define OI_PY_STATE_GET() 0
#define OI_PY_STATE_PUT(s) do { } while(s)

/* No threads */
#define GENSIO_SWIG_C_BLOCK_ENTRY
#define GENSIO_SWIG_C_BLOCK_EXIT
#endif

static swig_cb_val *
ref_swig_cb_i(swig_cb *cb)
{
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    Py_INCREF(cb);
    OI_PY_STATE_PUT(gstate);
    return cb;
}
#define ref_swig_cb(cb, func) ref_swig_cb_i(cb)

static swig_ref
swig_make_ref_i(void *item, swig_type_info *class)
{
    swig_ref    rv;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    rv.val = SWIG_NewPointerObj(item, class, SWIG_POINTER_OWN);
    OI_PY_STATE_PUT(gstate);
    return rv;
}
#define swig_make_ref(item, name) \
	swig_make_ref_i(item, SWIGTYPE_p_ ## name)

static swig_cb_val *
deref_swig_cb_val(swig_cb_val *cb)
{
    OI_PY_STATE gstate;

    if (cb) {
	gstate = OI_PY_STATE_GET();
	Py_DECREF(cb);
	OI_PY_STATE_PUT(gstate);
    }
    return cb;
}

/* No way to check the refcount in Python. */
#define swig_free_ref_check(r, c) \
	do {								\
	    swig_free_ref(r);						\
	} while(0)

static PyObject *
swig_finish_call_rv(swig_cb_val *cb, const char *method_name, PyObject *args,
		    bool optional)
{
    PyObject *p, *o = NULL;

    if (PyObject_HasAttrString(cb, method_name)) {
	p = PyObject_GetAttrString(cb, method_name);
	o = PyObject_CallObject(p, args);
	Py_DECREF(p);
	if (PyErr_Occurred())
	    wake_curr_waiter();
    } else if (!optional) {
	PyObject *t = PyObject_GetAttrString(cb, "__class__");
	PyObject *c = PyObject_GetAttrString(t, "__name__");
	char *class = PyString_AsString(c);

	PyErr_Format(PyExc_RuntimeError,
		     "gensio callback: Class '%s' has no method '%s'\n",
		     class, method_name);
	wake_curr_waiter();
    }
    if (args)
	Py_DECREF(args);

    return o;
}

static gensiods
swig_finish_call_rv_gensiods(swig_cb_val *cb, const char *method_name,
			     PyObject *args, bool optional)
{
    PyObject *o;
    gensiods rv = 0;

    o = swig_finish_call_rv(cb, method_name, args, optional);
    if (o) {
	rv = PyLong_AsUnsignedLong(o);
	if (PyErr_Occurred()) {
	    PyObject *t = PyObject_GetAttrString(cb, "__class__");
	    PyObject *c = PyObject_GetAttrString(t, "__name__");
	    char *class = PyString_AsString(c);

	    PyErr_Format(PyExc_RuntimeError, "gensio callback: "
			 "Class '%s' method '%s' did not return "
			 "an integer\n", class, method_name);
	    wake_curr_waiter();
	}
	Py_DECREF(o);
    }

    return rv;
}

static int
swig_finish_call_rv_int(swig_cb_val *cb, const char *method_name,
			PyObject *args, bool optional)
{
    PyObject *o;
    int rv = GE_NOTSUP;

    o = swig_finish_call_rv(cb, method_name, args, optional);
    if (o) {
	rv = PyLong_AsUnsignedLong(o);
	if (PyErr_Occurred()) {
	    PyObject *t = PyObject_GetAttrString(cb, "__class__");
	    PyObject *c = PyObject_GetAttrString(t, "__name__");
	    char *class = PyString_AsString(c);

	    PyErr_Format(PyExc_RuntimeError, "gensio callback: "
			 "Class '%s' method '%s' did not return "
			 "an integer\n", class, method_name);
	    wake_curr_waiter();
	}
	Py_DECREF(o);
    }

    return rv;
}

static void
swig_finish_call(swig_cb_val *cb, const char *method_name, PyObject *args,
		 bool optional)
{
    PyObject *o;

    o = swig_finish_call_rv(cb, method_name, args, optional);
    if (o)
	Py_DECREF(o);
}

#define my_ssize_t Py_ssize_t
#if PY_VERSION_HEX >= 0x03000000
static int
OI_PI_BytesCheck(PyObject *o)
{
    if (PyUnicode_Check(o))
	return 1;
    if (PyBytes_Check(o))
	return 1;
    return 0;
}

static int
OI_PI_AsBytesAndSize(PyObject *o, char **buf, my_ssize_t *len)
{
    if (PyUnicode_Check(o)) {
	*buf = PyUnicode_AsUTF8AndSize(o, len);
	return 0;
    }
    return PyBytes_AsStringAndSize(o, buf, len);
}
#define OI_PI_StringCheck PyUnicode_Check
#define OI_PI_FromString PyUnicode_FromString
#define OI_PI_AsString PyUnicode_AsUTF8
#else
#define OI_PI_BytesCheck PyString_Check
#define OI_PI_AsBytesAndSize PyString_AsStringAndSize
#define OI_PI_StringCheck PyString_Check
#define OI_PI_FromString PyString_FromString
#define OI_PI_AsString PyString_AsString
#endif

struct os_funcs_data {
#ifdef USE_POSIX_THREADS
    pthread_mutex_t lock;
#endif
    unsigned int refcount;
    struct selector_s *sel;
    swig_cb_val *log_handler;
};

#ifdef USE_POSIX_THREADS
void os_funcs_lock(struct os_funcs_data *odata)
{
    pthread_mutex_lock(&odata->lock);
}
void os_funcs_unlock(struct os_funcs_data *odata)
{
    pthread_mutex_unlock(&odata->lock);
}
#else
void os_funcs_lock(struct os_funcs_data *odata)
{
}
void os_funcs_unlock(struct os_funcs_data *odata)
{
}
#endif

static void
os_funcs_ref(struct gensio_os_funcs *o)
{
    struct os_funcs_data *odata = o->other_data;

    os_funcs_lock(odata);
    odata->refcount++;
    os_funcs_unlock(odata);
}

static void
check_os_funcs_free(struct gensio_os_funcs *o)
{
    struct os_funcs_data *odata = o->other_data;

    os_funcs_lock(odata);
    if (--odata->refcount == 0) {
	os_funcs_unlock(odata);
	if (odata->log_handler)
	    deref_swig_cb_val(odata->log_handler);
	sel_free_selector(odata->sel);
	free(odata);
	o->free_funcs(o);
    } else {
	os_funcs_unlock(odata);
    }
}

struct gensio_data {
    bool tmpval; /* If true, just ignore this on destroy. */
    int refcount;
    swig_cb_val *handler_val;
    struct gensio_os_funcs *o;
};

static struct gensio_data *
alloc_gensio_data(struct gensio_os_funcs *o, swig_cb *handler)
{
    struct gensio_data *data;

    data = malloc(sizeof(*data));
    if (!data)
	return NULL;
    data->tmpval = false;
    data->refcount = 1;
    if (nil_swig_cb(handler))
	data->handler_val = NULL;
    else
	data->handler_val = ref_swig_cb(handler, read_callback);
    os_funcs_ref(o);
    data->o = o;

    return data;
}

static void
free_gensio_data(struct gensio_data *data)
{
    deref_swig_cb_val(data->handler_val);
    check_os_funcs_free(data->o);
    free(data);
}

static void
ref_gensio_data(struct gensio_data *data)
{
    struct os_funcs_data *odata = data->o->other_data;

    os_funcs_lock(odata);
    data->refcount++;
    os_funcs_unlock(odata);
}

static void
deref_gensio_data(struct gensio_data *data, struct gensio *io)
{
    struct os_funcs_data *odata = data->o->other_data;

    os_funcs_lock(odata);
    data->refcount--;
    if (data->refcount <= 0) {
	os_funcs_unlock(odata);
	gensio_free(io);
	free_gensio_data(data);
    } else {
	os_funcs_unlock(odata);
    }
}

static void
deref_gensio_accepter_data(struct gensio_data *data,
			   struct gensio_accepter *acc)
{
    struct os_funcs_data *odata = data->o->other_data;

    os_funcs_lock(odata);
    data->refcount--;
    if (data->refcount <= 0) {
	os_funcs_unlock(odata);
	gensio_acc_free(acc);
	free_gensio_data(data);
    } else {
	os_funcs_unlock(odata);
    }
}

static void
gensio_ref(struct gensio *io)
{
    struct gensio_data *data = gensio_get_user_data(io);

    ref_gensio_data(data);
}

static void
sergensio_ref(struct sergensio *sio)
{
    struct gensio_data *data = sergensio_get_user_data(sio);

    ref_gensio_data(data);
}

static void
gensio_accepter_ref(struct gensio_accepter *acc)
{
    struct gensio_data *data = gensio_acc_get_user_data(acc);

    ref_gensio_data(data);
}

static void gensio_do_vlog(struct gensio_os_funcs *o,
			   enum gensio_log_levels level,
			   const char *fmt, va_list fmtargs)
{
    struct os_funcs_data *odata = o->other_data;
    char *buf = NULL;
    unsigned int len;
    PyObject *args, *po;
    va_list tmpva;
    OI_PY_STATE gstate;

    if (!odata->log_handler)
	return;

    gstate = OI_PY_STATE_GET();

    va_copy(tmpva, fmtargs);
    len = vsnprintf(buf, 0, fmt, tmpva);
    va_end(tmpva);
    buf = o->zalloc(o, len + 1);
    if (!buf)
	goto out;
    vsnprintf(buf, len + 1, fmt, fmtargs);

    args = PyTuple_New(2);
    po = OI_PI_FromString(gensio_log_level_to_str(level));
    PyTuple_SET_ITEM(args, 0, po);
    po = OI_PI_FromString(buf);
    PyTuple_SET_ITEM(args, 1, po);
    o->free(o, buf);

    swig_finish_call(odata->log_handler, "gensio_log", args, false);
 out:
    OI_PY_STATE_PUT(gstate);
}

static void
gensio_open_done(struct gensio *io, int err, void *cb_data) {
    swig_cb_val *cb = cb_data;
    swig_ref io_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    io_ref = swig_make_ref(io, gensio);
    gensio_ref(io);
    args = PyTuple_New(2);
    PyTuple_SET_ITEM(args, 0, io_ref.val);
    if (err) {
	o = OI_PI_FromString(gensio_err_to_str(err));
    } else {
	Py_INCREF(Py_None);
	o = Py_None;
    }
    PyTuple_SET_ITEM(args, 1, o);

    swig_finish_call(cb, "open_done", args, false);

    deref_swig_cb_val(cb);
    OI_PY_STATE_PUT(gstate);
}

static void
gensio_close_done(struct gensio *io, void *cb_data) {
    swig_cb_val *cb = cb_data;
    swig_ref io_ref;
    PyObject *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    io_ref = swig_make_ref(io, gensio);
    args = PyTuple_New(1);
    gensio_ref(io);
    PyTuple_SET_ITEM(args, 0, io_ref.val);

    swig_finish_call(cb, "close_done", args, false);

    deref_swig_cb_val(cb);
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_call(struct sergensio *sio, long val, char *func)
{
    struct gensio_data *data = sergensio_get_user_data(sio);
    swig_ref sio_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val)
	goto out_put;

    sio_ref = swig_make_ref(sio, sergensio);
    args = PyTuple_New(2);
    ref_gensio_data(data);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);
    o = PyInt_FromLong(val);
    PyTuple_SET_ITEM(args, 1, o);

    swig_finish_call(data->handler_val, func, args, true);

 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_modemstate(struct sergensio *sio, unsigned int modemstate)
{
    sgensio_call(sio, modemstate, "modemstate");
}

static void
sgensio_linestate(struct sergensio *sio, unsigned int linestate)
{
    sgensio_call(sio, linestate, "linestate");
}

static void
sgensio_signature(struct sergensio *sio)
{
    /*
     * FIXME - this is wrong, it is for the client side, but this needs
     * to be the server side code that gets a signature.
     */
    struct gensio_data *data = sergensio_get_user_data(sio);
    swig_ref sio_ref;
    PyObject *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val)
	goto out_put;

    sio_ref = swig_make_ref(sio, sergensio);
    args = PyTuple_New(1);
    ref_gensio_data(data);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);

    swig_finish_call(data->handler_val, "signature", args, true);

 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_sync(struct sergensio *sio)
{
    struct gensio_data *data = sergensio_get_user_data(sio);
    swig_ref sio_ref;
    PyObject *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val)
	goto out_put;

    sio_ref = swig_make_ref(sio, sergensio);
    args = PyTuple_New(1);
    ref_gensio_data(data);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);

    swig_finish_call(data->handler_val, "sync", args, true);

 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_flowcontrol_state(struct sergensio *sio, bool val)
{
    struct gensio_data *data = sergensio_get_user_data(sio);
    swig_ref sio_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val)
	goto out_put;

    sio_ref = swig_make_ref(sio, sergensio);
    args = PyTuple_New(2);
    ref_gensio_data(data);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);
    o = PyBool_FromLong(val);
    PyTuple_SET_ITEM(args, 1, o);

    swig_finish_call(data->handler_val, "flowcontrol_state", args, true);

 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_flush(struct sergensio *sio, int val)
{
    sgensio_call(sio, val, "flush");
}

static void
sgensio_baud(struct sergensio *sio, int baud)
{
    sgensio_call(sio, baud, "sbaud");
}

static void
sgensio_datasize(struct sergensio *sio, int datasize)
{
    sgensio_call(sio, datasize, "sdatasize");
}

static void
sgensio_parity(struct sergensio *sio, int parity)
{
    sgensio_call(sio, parity, "sparity");
}

static void
sgensio_stopbits(struct sergensio *sio, int stopbits)
{
    sgensio_call(sio, stopbits, "sstopbits");
}

static void
sgensio_flowcontrol(struct sergensio *sio, int flowcontrol)
{
    sgensio_call(sio, flowcontrol, "sflowcontrol");
}

static void
sgensio_iflowcontrol(struct sergensio *sio, int iflowcontrol)
{
    sgensio_call(sio, iflowcontrol, "siflowcontrol");
}

static void
sgensio_sbreak(struct sergensio *sio, int breakv)
{
    sgensio_call(sio, breakv, "ssbreak");
}

static void
sgensio_dtr(struct sergensio *sio, int dtr)
{
    sgensio_call(sio, dtr, "sdtr");
}

static void
sgensio_rts(struct sergensio *sio, int rts)
{
    sgensio_call(sio, rts, "srts");
}

static int
gensio_child_event(struct gensio *io, void *user_data, int event, int readerr,
		   unsigned char *buf, gensiods *buflen,
		   const char *const *auxdata)
{
    struct gensio_data *data = user_data;
    swig_ref io_ref = { .val = NULL };
    PyObject *args, *o;
    OI_PY_STATE gstate;
    int rv = 0;
    gensiods rsize;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val) {
	rv = GE_NOTSUP;
	goto out_put;
    }

    switch (event) {
    case GENSIO_EVENT_READ:
	args = PyTuple_New(4);

	io_ref = swig_make_ref(io, gensio);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);

	if (readerr) {
	    o = OI_PI_FromString(gensio_err_to_str(readerr));
	} else {
	    Py_INCREF(Py_None);
	    o = Py_None;
	}
	PyTuple_SET_ITEM(args, 1, o);

	if (buf) {
	    o = PyBytes_FromStringAndSize((char *) buf, *buflen);
	} else {
	    o = Py_None;
	    Py_INCREF(Py_None);
	}
	PyTuple_SET_ITEM(args, 2, o);

	if (!auxdata || !auxdata[0]) {
	    Py_INCREF(Py_None);
	    PyTuple_SET_ITEM(args, 3, Py_None);
	} else {
	    unsigned int i, len = 0;

	    while (auxdata[len])
		len++;
	    o = PyTuple_New(len);
	    for (i = 0; i < len; i++)
		PyTuple_SetItem(o, i, PyString_FromString(auxdata[i]));
	    PyTuple_SET_ITEM(args, 3, o);
	}

	rsize = swig_finish_call_rv_gensiods(data->handler_val,
					     "read_callback", args, false);
	if (!PyErr_Occurred())
	    *buflen = rsize;
	break;

    case GENSIO_EVENT_WRITE_READY:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(1);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);

	swig_finish_call(data->handler_val, "write_callback", args, false);
	break;

    case GENSIO_EVENT_SEND_BREAK:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(1);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);

	swig_finish_call(data->handler_val, "send_break", args, true);
	break;

    case GENSIO_EVENT_AUTH_BEGIN:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(1);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);

	rv = swig_finish_call_rv_int(data->handler_val, "auth_begin",
				     args, true);
	break;

    case GENSIO_EVENT_PRECERT_VERIFY:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(1);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);

	rv = swig_finish_call_rv_int(data->handler_val, "precert_verify",
				     args, true);
	break;

    case GENSIO_EVENT_POSTCERT_VERIFY:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(3);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);
	o = PyInt_FromLong(readerr);
	PyTuple_SET_ITEM(args, 1, o);
	if (auxdata && auxdata[0]) {
	    o = OI_PI_FromString(auxdata[0]);
	} else {
	    Py_INCREF(Py_None);
	    o = Py_None;
	}
	PyTuple_SET_ITEM(args, 2, o);

	rv = swig_finish_call_rv_int(data->handler_val, "postcert_verify",
				     args, true);
	break;

    case GENSIO_EVENT_PASSWORD_VERIFY:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(2);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);
	/*
	 * FIXME - is there a way to make this a secure python string
	 * that gets wiped on free?
	 */
	o = OI_PI_FromString((const char *) buf);
	PyTuple_SET_ITEM(args, 1, o);

	rv = swig_finish_call_rv_int(data->handler_val, "password_verify",
				     args, true);
	break;

    case GENSIO_EVENT_REQUEST_PASSWORD:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(1);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);
	o = swig_finish_call_rv(data->handler_val, "request_password",
				args, true);
	rv = GE_NOTSUP;
	if (o) {
	    if (OI_PI_StringCheck(o)) {
		char *p = OI_PI_AsString(o);
		unsigned int len = strlen(p);

		if (len < *buflen)
		    *buflen = len;
		memcpy(buf, p, *buflen);
		rv = 0;
	    } else if (PyInt_Check(o)) {
		rv = PyInt_AsLong(o);
	    }
	    Py_DecRef(o);
	}
	break;

    case GENSIO_EVENT_SER_MODEMSTATE:
	sgensio_modemstate(gensio_to_sergensio(io), *((unsigned int *) buf));
	break;

    case GENSIO_EVENT_SER_LINESTATE:
	sgensio_linestate(gensio_to_sergensio(io), *((unsigned int *) buf));
	break;

    case GENSIO_EVENT_SER_SIGNATURE:
	sgensio_signature(gensio_to_sergensio(io));
	break;

    case GENSIO_EVENT_SER_FLOW_STATE:
	sgensio_flowcontrol_state(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_FLUSH:
	sgensio_flush(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_SYNC:
	sgensio_sync(gensio_to_sergensio(io));
	break;

    case GENSIO_EVENT_SER_BAUD:
	sgensio_baud(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_DATASIZE:
	sgensio_datasize(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_PARITY:
	sgensio_parity(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_STOPBITS:
	sgensio_stopbits(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_FLOWCONTROL:
	sgensio_flowcontrol(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_IFLOWCONTROL:
	sgensio_iflowcontrol(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_SBREAK:
	sgensio_sbreak(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_DTR:
	sgensio_dtr(gensio_to_sergensio(io), *((int *) buf));
	break;

    case GENSIO_EVENT_SER_RTS:
	sgensio_rts(gensio_to_sergensio(io), *((int *) buf));
	break;

    default:
	rv = GE_NOTSUP;
	break;
    }

 out_put:
    OI_PY_STATE_PUT(gstate);

    return rv;
}

static void
gensio_acc_shutdown_done(struct gensio_accepter *accepter, void *cb_data)
{
    swig_cb_val *cb = cb_data;
    swig_ref acc_ref;
    PyObject *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    acc_ref = swig_make_ref(accepter, gensio_accepter);
    args = PyTuple_New(1);
    gensio_accepter_ref(accepter);
    PyTuple_SET_ITEM(args, 0, acc_ref.val);

    swig_finish_call(cb, "shutdown_done", args, false);

    deref_swig_cb_val(cb);
    OI_PY_STATE_PUT(gstate);
}

static int
gensio_acc_io_call_cb(struct gensio_accepter *accepter, struct gensio *io,
		      const char *func, int opterr, const char *optstr,
		      bool optional)
{
    struct gensio_data *data = gensio_acc_get_user_data(accepter);
    swig_ref acc_ref, io_ref;
    PyObject *args, *o;
    int rv;
    OI_PY_STATE gstate;
    struct gensio_data tmpdata;
    void *old_user_data = gensio_get_user_data(io);

    gstate = OI_PY_STATE_GET();


    /*
     * This is a situation where the gensio has not been reported
     * to the upper layer yet and thus there is no user data.
     * Just create something to say that this isn't valid.
     */
    tmpdata.tmpval = true;
    gensio_set_user_data(io, &tmpdata);

    acc_ref = swig_make_ref(accepter, gensio_accepter);
    gensio_accepter_ref(accepter);
    io_ref = swig_make_ref(io, gensio);
    if (opterr >= 0)
	args = PyTuple_New(4);
    else if (optstr)
	args = PyTuple_New(3);
    else
	args = PyTuple_New(2);
    PyTuple_SET_ITEM(args, 0, acc_ref.val);
    PyTuple_SET_ITEM(args, 1, io_ref.val);
    if (opterr >= 0) {
	o = PyInt_FromLong(opterr);
	PyTuple_SET_ITEM(args, 2, o);
	if (optstr) {
	    o = OI_PI_FromString(optstr);
	} else {
	    Py_INCREF(Py_None);
	    o = Py_None;
	}
	PyTuple_SET_ITEM(args, 3, o);
    } else if (optstr) {
	o = OI_PI_FromString(optstr);
	PyTuple_SET_ITEM(args, 2, o);
    }

    rv = swig_finish_call_rv_int(data->handler_val, func, args, optional);
    gensio_set_user_data(io, old_user_data);

    OI_PY_STATE_PUT(gstate);
    return rv;
}

static int
gensio_acc_child_event(struct gensio_accepter *accepter, void *user_data,
		       int event, void *cdata)
{
    struct gensio_data *data = user_data;
    swig_ref acc_ref, io_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;
    struct gensio_data *iodata;
    struct gensio *io;
    struct gensio_loginfo *i = cdata;
    struct gensio_acc_password_verify_data *pwvfy;
    struct gensio_acc_postcert_verify_data *postvfy;
    char buf[256];
    struct gensio_data tmpdata;
    void *old_user_data;
    int rv;

    switch (event) {
    case GENSIO_ACC_EVENT_LOG:
	gstate = OI_PY_STATE_GET();

	acc_ref = swig_make_ref(accepter, gensio_accepter);
	args = PyTuple_New(3);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, acc_ref.val);
	o = OI_PI_FromString(gensio_log_level_to_str(i->level));
	PyTuple_SET_ITEM(args, 1, o);
	vsnprintf(buf, sizeof(buf), i->str, i->args);
	o = OI_PI_FromString(buf);
	PyTuple_SET_ITEM(args, 2, o);

	swig_finish_call(data->handler_val, "accepter_log", args, true);

	OI_PY_STATE_PUT(gstate);
	return 0;

    case GENSIO_ACC_EVENT_NEW_CONNECTION:
	io = cdata;
	iodata = alloc_gensio_data(data->o, NULL);
	gensio_set_callback(cdata /*io*/, gensio_child_event, iodata);

	gstate = OI_PY_STATE_GET();

	acc_ref = swig_make_ref(accepter, gensio_accepter);
	gensio_accepter_ref(accepter);
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(2);
	PyTuple_SET_ITEM(args, 0, acc_ref.val);
	PyTuple_SET_ITEM(args, 1, io_ref.val);

	swig_finish_call(data->handler_val, "new_connection", args, false);

	OI_PY_STATE_PUT(gstate);
	return 0;

    case GENSIO_ACC_EVENT_AUTH_BEGIN:
	return gensio_acc_io_call_cb(accepter, cdata, "auth_begin",
				     -1, NULL, true);

    case GENSIO_ACC_EVENT_PRECERT_VERIFY:
	return gensio_acc_io_call_cb(accepter, cdata, "precert_verify",
				     -1, NULL, true);

    case GENSIO_ACC_EVENT_POSTCERT_VERIFY:
	postvfy = (struct gensio_acc_postcert_verify_data *) cdata;
	return gensio_acc_io_call_cb(accepter, postvfy->io, "postcert_verify",
				     postvfy->err, postvfy->errstr, true);

    case GENSIO_ACC_EVENT_PASSWORD_VERIFY:
	pwvfy = (struct gensio_acc_password_verify_data *) cdata;
	return gensio_acc_io_call_cb(accepter, pwvfy->io, "password_verify",
				     -1, pwvfy->password, true);

    case GENSIO_ACC_EVENT_REQUEST_PASSWORD:
	pwvfy = (struct gensio_acc_password_verify_data *) cdata;
	io = pwvfy->io;

	gstate = OI_PY_STATE_GET();

	/*
	 * This is a situation where the gensio has not been reported
	 * to the upper layer yet and thus there is no user data.
	 * Just create something to say that this isn't valid.
	 */
	old_user_data = gensio_get_user_data(io);
	tmpdata.tmpval = true;
	gensio_set_user_data(io, &tmpdata);

	acc_ref = swig_make_ref(accepter, gensio_accepter);
	gensio_accepter_ref(accepter);
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(2);
	PyTuple_SET_ITEM(args, 0, acc_ref.val);
	PyTuple_SET_ITEM(args, 1, io_ref.val);

	o = swig_finish_call_rv(data->handler_val, "request_password",
				args, true);
	gensio_set_user_data(io, old_user_data);
	rv = GE_NOTSUP;
	if (o) {
	    if (OI_PI_StringCheck(o)) {
		char *p = OI_PI_AsString(o);
		unsigned int len = strlen(p);

		if (len < pwvfy->password_len)
		    pwvfy->password_len = len;
		memcpy(pwvfy->password, p, pwvfy->password_len);
		rv = 0;
	    } else if (PyInt_Check(o)) {
		rv = PyInt_AsLong(o);
	    }
	    Py_DecRef(o);
	}
	return rv;
    }

    return GE_NOTSUP;
}

struct sergensio_cbdata {
    const char *cbname;
    swig_cb_val *h_val;
};

#define stringify_1(x...)     #x
#define stringify(x...)       stringify_1(x)

#define sergensio_cbdata(name, h) \
({							\
    struct sergensio_cbdata *cbd = malloc(sizeof(*cbd));	\
    if (cbd) {						\
	cbd->cbname = stringify(name);			\
	cbd->h_val = ref_swig_cb(h, name);		\
    }							\
    cbd;						\
 })

static void
cleanup_sergensio_cbdata(struct sergensio_cbdata *cbd)
{
    deref_swig_cb_val(cbd->h_val);
    free(cbd);
}

static void
sergensio_cb(struct sergensio *sio, int err, unsigned int val, void *cb_data)
{
    struct sergensio_cbdata *cbd = cb_data;
    swig_ref sio_ref;
    PyObject *o, *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    sio_ref = swig_make_ref(sio, sergensio);
    args = PyTuple_New(3);
    sergensio_ref(sio);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);
    if (err) {
	o = OI_PI_FromString(gensio_err_to_str(err));
    } else {
	Py_INCREF(Py_None);
	o = Py_None;
    }
    PyTuple_SET_ITEM(args, 1, o);
    o = PyInt_FromLong(val);
    PyTuple_SET_ITEM(args, 2, o);

    swig_finish_call(cbd->h_val, cbd->cbname, args, true);

    cleanup_sergensio_cbdata(cbd);
    OI_PY_STATE_PUT(gstate);
}

static void
sergensio_sig_cb(struct sergensio *sio, int err,
		 const char *sig, unsigned int len, void *cb_data)
{
    swig_cb_val *h_val = cb_data;
    swig_ref sio_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    sio_ref = swig_make_ref(sio, sergensio);
    args = PyTuple_New(3);
    sergensio_ref(sio);
    PyTuple_SET_ITEM(args, 0, sio_ref.val);
    if (err) {
	o = OI_PI_FromString(gensio_err_to_str(err));
    } else {
	o = Py_None;
	Py_INCREF(o);
    }
    PyTuple_SET_ITEM(args, 1, o);

    o = PyBytes_FromStringAndSize(sig, len);
    PyTuple_SET_ITEM(args, 2, o);

    swig_finish_call(h_val, "signature", args, true);
    deref_swig_cb_val(h_val);

    OI_PY_STATE_PUT(gstate);
}

static PyObject *
add_python_result(PyObject *result, PyObject *val)
{
    if ((result == Py_None)) {
	Py_XDECREF(result);
	result = val;
    } else {
	PyObject *seq, *o2;

	if (!PyTuple_Check(result)) {
	    PyObject *tmpr = result;

	    result = PyTuple_New(1);
	    PyTuple_SetItem(result, 0, tmpr);
	}
	seq = PyTuple_New(1);
	PyTuple_SetItem(seq, 0, val);
	o2 = result;
	result = PySequence_Concat(o2, seq);
	Py_DECREF(o2);
	Py_DECREF(seq);
    }
    return result;
}

static bool check_for_err(int err)
{
    bool rv;

    if (err == GE_INTERRUPTED)
	PyErr_CheckSignals();
    rv = (bool) PyErr_Occurred();
    return rv;
};

static void err_handle(char *name, int rv)
{
    if (!rv)
	return;
    PyErr_Format(PyExc_Exception, "gensio:%s: %s", name,
		 gensio_err_to_str(rv));
}

static void ser_err_handle(char *name, int rv)
{
    if (!rv)
	return;
    PyErr_Format(PyExc_Exception, "sergensio:%s: %s", name,
		 gensio_err_to_str(rv));
}

static void cast_error(char *to, char *from)
{
    PyErr_Format(PyExc_RuntimeError, "Error casting from %s to %s", from, to);
}

static void oom_err(void)
{
    PyErr_Format(PyExc_MemoryError, "Out of memory");
}
