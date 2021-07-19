/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
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
	*buf = (char *) PyUnicode_AsUTF8AndSize(o, len);
	return 0;
    }
    return PyBytes_AsStringAndSize(o, buf, len);
}

#define OI_PI_StringCheck PyUnicode_Check
#define OI_PI_FromString PyUnicode_FromString
#define OI_PI_FromStringAndSize PyUnicode_FromStringAndSize
#define OI_PI_AsString PyUnicode_AsUTF8
#else
#define OI_PI_BytesCheck PyString_Check
#define OI_PI_AsBytesAndSize PyString_AsStringAndSize
#define OI_PI_StringCheck PyString_Check
#define OI_PI_FromString PyString_FromString
#define OI_PI_FromStringAndSize PyString_FromStringAndSize
#define OI_PI_AsString PyString_AsString
#endif

static PyObject *
OI_PI_FromStringN(const char *s)
{
    PyObject *o;

    if (s) {
	o = OI_PI_FromString(s);
    } else {
	o = Py_None;
	Py_INCREF(o);
    }
    return o;
}

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
	const char *class = OI_PI_AsString(c);

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
	    const char *class = OI_PI_AsString(c);

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
	    const char *class = OI_PI_AsString(c);

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

struct os_funcs_data {
#ifdef USE_POSIX_THREADS
    pthread_mutex_t lock;
#endif
    unsigned int refcount;
    swig_cb_val *log_handler;
};

#ifdef USE_POSIX_THREADS
static void os_funcs_lock(struct os_funcs_data *odata)
{
    pthread_mutex_lock(&odata->lock);
}
static void os_funcs_unlock(struct os_funcs_data *odata)
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
sgensio_call(struct gensio *io, long val, char *func)
{
    struct gensio_data *data = gensio_get_user_data(io);
    swig_ref io_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val)
	goto out_put;

    io_ref = swig_make_ref(io, gensio);
    args = PyTuple_New(2);
    ref_gensio_data(data);
    PyTuple_SET_ITEM(args, 0, io_ref.val);
    o = PyInt_FromLong(val);
    PyTuple_SET_ITEM(args, 1, o);

    swig_finish_call(data->handler_val, func, args, true);

 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_modemstate(struct gensio *io, unsigned int modemstate)
{
    sgensio_call(io, modemstate, "modemstate");
}

static void
sgensio_linestate(struct gensio *io, unsigned int linestate)
{
    sgensio_call(io, linestate, "linestate");
}

static void
sgensio_signature(struct gensio *io)
{
    /*
     * FIXME - this is wrong, it is for the client side, but this needs
     * to be the server side code that gets a signature.
     */
    struct gensio_data *data = gensio_get_user_data(io);
    swig_ref io_ref;
    PyObject *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val)
	goto out_put;

    io_ref = swig_make_ref(io, gensio);
    args = PyTuple_New(1);
    ref_gensio_data(data);
    PyTuple_SET_ITEM(args, 0, io_ref.val);

    swig_finish_call(data->handler_val, "signature", args, true);

 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_sync(struct gensio *io)
{
    struct gensio_data *data = gensio_get_user_data(io);
    swig_ref io_ref;
    PyObject *args;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val)
	goto out_put;

    io_ref = swig_make_ref(io, gensio);
    args = PyTuple_New(1);
    ref_gensio_data(data);
    PyTuple_SET_ITEM(args, 0, io_ref.val);

    swig_finish_call(data->handler_val, "sync", args, true);

 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_flowcontrol_state(struct gensio *io, bool val)
{
    struct gensio_data *data = gensio_get_user_data(io);
    swig_ref io_ref;
    PyObject *args, *o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    if (!data->handler_val)
	goto out_put;

    io_ref = swig_make_ref(io, gensio);
    args = PyTuple_New(2);
    ref_gensio_data(data);
    PyTuple_SET_ITEM(args, 0, io_ref.val);
    o = PyBool_FromLong(val);
    PyTuple_SET_ITEM(args, 1, o);

    swig_finish_call(data->handler_val, "flowcontrol_state", args, true);

 out_put:
    OI_PY_STATE_PUT(gstate);
}

static void
sgensio_flush(struct gensio *io, int val)
{
    sgensio_call(io, val, "flush");
}

static void
sgensio_baud(struct gensio *io, int baud)
{
    sgensio_call(io, baud, "sbaud");
}

static void
sgensio_datasize(struct gensio *io, int datasize)
{
    sgensio_call(io, datasize, "sdatasize");
}

static void
sgensio_parity(struct gensio *io, int parity)
{
    sgensio_call(io, parity, "sparity");
}

static void
sgensio_stopbits(struct gensio *io, int stopbits)
{
    sgensio_call(io, stopbits, "sstopbits");
}

static void
sgensio_flowcontrol(struct gensio *io, int flowcontrol)
{
    sgensio_call(io, flowcontrol, "sflowcontrol");
}

static void
sgensio_iflowcontrol(struct gensio *io, int iflowcontrol)
{
    sgensio_call(io, iflowcontrol, "siflowcontrol");
}

static void
sgensio_sbreak(struct gensio *io, int breakv)
{
    sgensio_call(io, breakv, "ssbreak");
}

static void
sgensio_dtr(struct gensio *io, int dtr)
{
    sgensio_call(io, dtr, "sdtr");
}

static void
sgensio_rts(struct gensio *io, int rts)
{
    sgensio_call(io, rts, "srts");
}

static PyObject *
gensio_py_handle_auxdata(const char *const *auxdata)
{
    if (!auxdata || !auxdata[0]) {
	Py_INCREF(Py_None);
	return Py_None;
    } else {
	PyObject *o;
	unsigned int i, len = 0;

	while (auxdata[len])
	    len++;
	o = PyTuple_New(len);
	for (i = 0; i < len; i++)
	    PyTuple_SetItem(o, i, PyString_FromString(auxdata[i]));
	return o;
    }
}

static int
gensio_child_event(struct gensio *io, void *user_data, int event, int readerr,
		   unsigned char *buf, gensiods *buflen,
		   const char *const *auxdata)
{
    struct gensio_data *data = user_data;
    swig_ref io_ref = { .val = NULL }, new_con = { .val = NULL };
    PyObject *args, *o;
    OI_PY_STATE gstate;
    int rv = 0;
    gensiods rsize;
    struct gensio *io2;
    struct gensio_data *iodata;

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

	PyTuple_SET_ITEM(args, 3, gensio_py_handle_auxdata(auxdata));

	rsize = swig_finish_call_rv_gensiods(data->handler_val,
					     "read_callback", args, false);
	if (!PyErr_Occurred() && buflen)
	    *buflen = rsize;
	break;

    case GENSIO_EVENT_WRITE_READY:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(1);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);

	swig_finish_call(data->handler_val, "write_callback", args, false);
	break;

    case GENSIO_EVENT_NEW_CHANNEL:
	io2 = (struct gensio *) buf;
	iodata = alloc_gensio_data(data->o, NULL);
	gensio_set_callback(io2, gensio_child_event, iodata);

	args = PyTuple_New(3);

	ref_gensio_data(data);

	io_ref = swig_make_ref(io, gensio);
	PyTuple_SET_ITEM(args, 0, io_ref.val);

	new_con = swig_make_ref(io2, gensio);
	PyTuple_SET_ITEM(args, 1, new_con.val);

	PyTuple_SET_ITEM(args, 2, gensio_py_handle_auxdata(auxdata));

	swig_finish_call(data->handler_val, "new_channel", args, false);
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
		const char *p = OI_PI_AsString(o);
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

    case GENSIO_EVENT_2FA_VERIFY:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(2);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);
	/*
	 * FIXME - is there a way to make this a secure python string
	 * that gets wiped on free?
	 */
	o = PyBytes_FromStringAndSize((const char *) buf, *buflen);
	PyTuple_SET_ITEM(args, 1, o);

	rv = swig_finish_call_rv_int(data->handler_val, "verify_2fa",
				     args, true);
	break;

    case GENSIO_EVENT_REQUEST_2FA:
	io_ref = swig_make_ref(io, gensio);
	args = PyTuple_New(1);
	ref_gensio_data(data);
	PyTuple_SET_ITEM(args, 0, io_ref.val);
	o = swig_finish_call_rv(data->handler_val, "request_2fa",
				args, true);
	rv = GE_NOTSUP;
	if (o) {
	    if (OI_PI_BytesCheck(o)) {
		char *p;
		unsigned char *p2;
		my_ssize_t len = strlen(p);

		rv = OI_PI_AsBytesAndSize(o, &p, &len);
		if (!rv) {
		    p2 = data->o->zalloc(data->o, len);
		    if (!p2) {
			rv = GE_NOMEM;
		    } else {
			memcpy(p2, p, len);
			*((unsigned char **) buf) = p2;
			*buflen = len;
		    }
		}
	    } else if (PyInt_Check(o)) {
		rv = PyInt_AsLong(o);
	    }
	    Py_DecRef(o);
	}
	break;

    case GENSIO_EVENT_SER_MODEMSTATE:
	sgensio_modemstate(io, *((unsigned int *) buf));
	break;

    case GENSIO_EVENT_SER_LINESTATE:
	sgensio_linestate(io, *((unsigned int *) buf));
	break;

    case GENSIO_EVENT_SER_SIGNATURE:
	sgensio_signature(io);
	break;

    case GENSIO_EVENT_SER_FLOW_STATE:
	sgensio_flowcontrol_state(io, *((int *) buf));
	break;

    case GENSIO_EVENT_SER_FLUSH:
	sgensio_flush(io, *((int *) buf));
	break;

    case GENSIO_EVENT_SER_SYNC:
	sgensio_sync(io);
	break;

    case GENSIO_EVENT_SER_BAUD:
	sgensio_baud(io, *((int *) buf));
	break;

    case GENSIO_EVENT_SER_DATASIZE:
	sgensio_datasize(io, *((int *) buf));
	break;

    case GENSIO_EVENT_SER_PARITY:
	sgensio_parity(io, *((int *) buf));
	break;

    case GENSIO_EVENT_SER_STOPBITS:
	sgensio_stopbits(io, *((int *) buf));
	break;

    case GENSIO_EVENT_SER_FLOWCONTROL:
	sgensio_flowcontrol(io, *((int *) buf));
	break;

    case GENSIO_EVENT_SER_IFLOWCONTROL:
	sgensio_iflowcontrol(io, *((int *) buf));
	break;

    case GENSIO_EVENT_SER_SBREAK:
	sgensio_sbreak(io, *((int *) buf));
	break;

    case GENSIO_EVENT_SER_DTR:
	sgensio_dtr(io, *((int *) buf));
	break;

    case GENSIO_EVENT_SER_RTS:
	sgensio_rts(io, *((int *) buf));
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

static void
gensio_acc_set_acc_cb_done(struct gensio_accepter *accepter, void *cb_data)
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

    swig_finish_call(cb, "set_accept_callback_done", args, false);

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
		const char *p = OI_PI_AsString(o);
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

    case GENSIO_ACC_EVENT_2FA_VERIFY:
	pwvfy = (struct gensio_acc_password_verify_data *) cdata;
	return gensio_acc_io_call_cb(accepter, pwvfy->io, "verify_2fa",
				     -1, pwvfy->password, true);

    case GENSIO_ACC_EVENT_REQUEST_2FA:
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

	o = swig_finish_call_rv(data->handler_val, "request_2fa",
				args, true);
	gensio_set_user_data(io, old_user_data);
	rv = GE_NOTSUP;
	if (o) {
	    if (OI_PI_BytesCheck(o)) {
		char *p;
		unsigned char *p2;
		my_ssize_t len = strlen(p);

		rv = OI_PI_AsBytesAndSize(o, &p, &len);
		if (!rv) {
		    p2 = data->o->zalloc(data->o, len);
		    if (!p2) {
			rv = GE_NOMEM;
		    } else {
			memcpy(p2, p, len);
			*((unsigned char **) pwvfy->password) = p2;
			pwvfy->password_len = len;
		    }
		}
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

struct mdns {
    struct gensio_os_funcs *o;
    bool closed;
    bool free_on_close;
    struct gensio_lock *lock;
    struct gensio_mdns *mdns;
    swig_cb_val *done_val;
};

struct mdns_service {
    struct gensio_mdns_service *service;
};

struct mdns_watch {
    struct gensio_os_funcs *o;
    bool closed;
    bool free_on_close;
    struct gensio_lock *lock;
    struct gensio_mdns_watch *watch;
    swig_cb_val *done_val;
    swig_cb_val *cb_val;
};

static void gensio_mdns_free_done(struct gensio_mdns *mdns, void *userdata)
{
    struct mdns *m = userdata;
    struct gensio_os_funcs *o = m->o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    swig_finish_call(m->done_val, "mdns_close_done", NULL, false);

    deref_swig_cb_val(m->done_val);
    OI_PY_STATE_PUT(gstate);

    o->lock(m->lock);
    if (m->free_on_close) {
	o->unlock(m->lock);
	o->free_lock(m->lock);
	o->free(o, m);
	check_os_funcs_free(o);
    } else {
	m->mdns = NULL;
	o->unlock(m->lock);
    }
}

static void gensio_mdns_remove_watch_done(struct gensio_mdns_watch *watch,
					  void *userdata)
{
    struct mdns_watch *w = userdata;
    struct gensio_os_funcs *o = w->o;
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();

    swig_finish_call(w->done_val, "mdns_close_watch_done", NULL, false);

    deref_swig_cb_val(w->done_val);
    OI_PY_STATE_PUT(gstate);

    o->lock(w->lock);
    if (w->free_on_close) {
	o->unlock(w->lock);
	o->free_lock(w->lock);
	o->free(o, w);
    } else {
	w->watch = NULL;
	o->unlock(w->lock);
    }
}

static void gensio_mdns_cb(struct gensio_mdns_watch *watch,
			   enum gensio_mdns_data_state state,
			   int interface, int ipdomain,
			   const char *name, const char *type,
			   const char *domain, const char *host,
			   const struct gensio_addr *addr,
			   const char *txt[], void *userdata)
{
    struct mdns_watch *w = userdata;
    PyObject *args, *a;
    OI_PY_STATE gstate;
    char *s = NULL;
    gensiods len = 0, pos = 0;
    int rv;

    gstate = OI_PY_STATE_GET();

    if (state == GENSIO_MDNS_ALL_FOR_NOW) {
	swig_finish_call(w->cb_val, "mdns_all_for_now", NULL, true);
	goto out;
    }

    args = PyTuple_New(9);
    PyTuple_SET_ITEM(args, 0, PyBool_FromLong(state == GENSIO_MDNS_NEW_DATA));
    PyTuple_SET_ITEM(args, 1, PyInt_FromLong(interface));
    PyTuple_SET_ITEM(args, 2, PyInt_FromLong(ipdomain));
    PyTuple_SET_ITEM(args, 3, OI_PI_FromStringN(name));
    PyTuple_SET_ITEM(args, 4, OI_PI_FromStringN(type));
    PyTuple_SET_ITEM(args, 5, OI_PI_FromStringN(domain));
    PyTuple_SET_ITEM(args, 6, OI_PI_FromStringN(host));

    rv = gensio_addr_to_str(addr, NULL, &len, 0);
    if (!rv) {
	s = malloc(len + 1);
	rv = gensio_addr_to_str(addr, s, &pos, len + 1);
    }
    if (rv)
	PyTuple_SET_ITEM(args, 7, OI_PI_FromStringN("unknown"));
    else
	PyTuple_SET_ITEM(args, 7, OI_PI_FromStringN(s));
    if (s)
	free(s);

    for (len = 0; txt && txt[len]; len++)
	;

    a = PyTuple_New(len);
    for (len = 0; txt && txt[len]; len++)
	PyTuple_SET_ITEM(a, len, OI_PI_FromString(txt[len]));
    PyTuple_SET_ITEM(args, 8, a);

    swig_finish_call(w->cb_val, "mdns_cb", args, false);

 out:
    OI_PY_STATE_PUT(gstate);
}

static PyObject *
add_python_result(PyObject *result, PyObject *val)
{
    if (result == Py_None) {
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
