//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

// This is the python-specific gensio wrapper

%module(directors="1") pygensio

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

%include <gensio_base.i>

%typemap(throws) gensios::gensio_error %{
    PyErr_SetString(PyExc_RuntimeError, $1.what());
    SWIG_fail;
%}


%{
static PyObject *
PI_add_result(PyObject *result, PyObject *val)
{
    PyObject *seq, *o;

    if (result == Py_None) {
	result = val;
	Py_DECREF(Py_None);
	return result;
    }

    if (!PyTuple_Check(result)) {
	PyObject *tmpr = result;

	result = PyTuple_New(1);
	PyTuple_SetItem(result, 0, tmpr);
    }

    seq = PyTuple_New(1);
    PyTuple_SetItem(seq, 0, val);
    o = result;
    result = PySequence_Concat(o, seq);
    Py_DECREF(o);
    Py_DECREF(seq);
    return result;
}

static int
PI_BytesCheck(PyObject *o)
{
    if (PyUnicode_Check(o))
	return 1;
    if (PyBytes_Check(o))
	return 1;
    return 0;
}

static int
PI_AsBytesAndSize(PyObject *o, void **buf, gensiods *ilen)
{
    Py_ssize_t len = *ilen;
    int rv = 0;

    if (PyUnicode_Check(o)) {
	*buf = (char *) PyUnicode_AsUTF8AndSize(o, &len);
    } else {
	rv = PyBytes_AsStringAndSize(o, (char **) buf, &len);
    }
    if (!rv)
	*ilen = len;
    return rv;
}

/* Not a function because it's not always used, avoid the unused warning. */
#define PI_CanBeBytes(o) \
    (o == Py_None || PI_BytesCheck(o) || PyByteArray_Check(o))

static int
PI_ToUCharVector(std::vector<unsigned char> &v, PyObject *o)
{
    void *tdata = NULL;
    gensiods len = 0;

    if (o == Py_None) {
	// Nothing to do, vector is empty
	return 0;
    }
    if (PI_BytesCheck(o)) {
	if (PI_AsBytesAndSize(o, &tdata, &len) == -1)
	    PyErr_SetString(PyExc_TypeError, "byte string conversion failed");
    } else if (PyByteArray_Check(o)) {
	tdata = PyByteArray_AsString(o);
	len = PyByteArray_Size(o);
    } else {
        PyErr_SetString(PyExc_TypeError, "Must be a byte string or array");
	return -1;
    }
    v.assign((unsigned char *) tdata, ((unsigned char *) tdata) + len);
    return 0;
}

#define PI_StringCheck PyUnicode_Check
#define PI_AsString PyUnicode_AsUTF8
#define PI_FromStringAndSize PyBytes_FromStringAndSize

static PyObject *
PI_StringArrayToTuple(const char *const *val)
{
    PyObject *o;

    if (val == NULL) {
	Py_INCREF(Py_None);
	return Py_None;
    } else {
	gensiods len, i;
	for (len = 0; val[len]; len++)
	    ;
	o = PyTuple_New(len);
	for (i = 0; i < len; i++)
	    PyTuple_SetItem(o, i, PyString_FromString(val[i]));
	return o;
    }
}

static int
PI_TupleToStringArray(char ***out, PyObject *so)
{
    unsigned int i;
    unsigned int len;
    char **temp = NULL;

    if (so == Py_None)
	goto null_auxdata;

    if (!PySequence_Check(so)) {
	PyErr_SetString(PyExc_TypeError, "Expecting a sequence");
	return -1;
    }
    len = PyObject_Length(so);
    if (len == 0)
	goto null_auxdata;

    temp = (char **) malloc(sizeof(char *) * (len + 1));
    if (!temp) {
	PyErr_SetString(PyExc_ValueError, "Out of memory");
	return -1;
    }
    memset(temp, 0, sizeof(char *) * (len + 1));
    for (i = 0; i < len; i++) {
	PyObject *o = PySequence_GetItem(so, i);

	if (!PI_StringCheck(o)) {
	    Py_XDECREF(o);
	    PyErr_SetString(PyExc_ValueError,
			    "Expecting a sequence of strings");
	    for (; i > 0; i--)
		Py_XDECREF(temp[i - 1]);
	    free(temp);
	    return -1;
	}
	temp[i] = (char *) PI_AsString(o);
	Py_DECREF(o);
    }
 null_auxdata:
    *out = temp;
    return 0;
}

#define GENSIO_SWIG_C_BLOCK_ENTRY Py_BEGIN_ALLOW_THREADS
#define GENSIO_SWIG_C_BLOCK_EXIT Py_END_ALLOW_THREADS

static bool check_for_err(int err)
{
    bool rv;

    if (err == GE_INTERRUPTED)
	PyErr_CheckSignals();
    rv = (bool) PyErr_Occurred();
    return rv;
};


%}

// We use the pure vector versions for python
%ignore gensios::Gensio::write(const SimpleUCharVector data,
			       const char *const *auxdata);
%ignore gensios::Gensio::read_s(const SimpleUCharVector data,
				gensio_time *timeout = NULL, bool intr = false);

////////////////////////////////////////////////////
// Typemaps
//

// For returning a gensiods in addition to the current return items.
%typemap(in, numinputs=0) gensiods *count (gensiods temp = 0) {
    $1 = &temp;
}
%typemap(argout) (gensiods *count) {
    $result = PI_add_result($result, SWIG_From_int(*$1));
}

// For strings returned from directors.
%typemap(directorin, numinputs=0) std::string &retval {
}
%typemap(directorargout) std::string &retval {
    char *buf = NULL;
    gensiods size = 0;

    if (PI_AsBytesAndSize($result, (void **) &buf, &size) == -1) {
	Swig::DirectorTypeMismatchException::raise(
		SWIG_ErrorType(SWIG_ArgError(swig_res)),
		"in output value of type '""std::string""'");
    } else {
	$1.assign(buf, size);
    }
}

%typemap(argout) std::string &retval {
    PyObject *o;
    o = PyUnicode_FromStringAndSize((const char *) $1->data(), $1->size());
    $result = PI_add_result($result, o);
}

// For vectors passed from target lang to C++, and passed in directors
// to target lang, and returned vectors from directors.
%typemap(typecheck, precedence=SWIG_TYPECHECK_VECTOR)
		std::vector<unsigned char> {
    $1 = PI_CanBeBytes($input);
}
%typemap(typecheck, precedence=SWIG_TYPECHECK_VECTOR)
		const std::vector<unsigned char> {
    $1 = PI_CanBeBytes($input);
}
// For values for write, write_s
%typemap(in) const std::vector<unsigned char> {
    if (PI_ToUCharVector($1, $input) == -1)
	SWIG_fail;
}
// Return value for get_addr
%typemap(out) std::vector<unsigned char> {
    $result = PI_FromStringAndSize((const char *) $1.data(), $1.size());
}
// Used for verify_2fa
%typemap(directorin) const std::vector<unsigned char> data {
    $input = PI_FromStringAndSize((const char *) $1.data(), $1.size());
}
// Used for request_2fa
%typemap(directorin, numinputs=0) std::vector<unsigned char> &retval {
}
%typemap(directorargout) std::vector<unsigned char> &retval {
    char *buf = NULL;
    gensiods size = 0;

    if (PI_AsBytesAndSize($result, (void **) &buf, &size) == -1) {
	Swig::DirectorTypeMismatchException::raise(
		SWIG_ErrorType(SWIG_ArgError(swig_res)),
		"in output value of type '""std::vector<unsigned char>""'");
    } else {
	$1.assign((unsigned char *) buf, ((unsigned char *) buf) + size);
    }
}
// Used for user_event
%typemap(directorin) std::vector<unsigned char> &userdata {
    $input = PI_FromStringAndSize((const char *) $1.data(), $1.size());
}
%typemap(directorargout) std::vector<unsigned char> &userdata {
    char *buf = NULL;
    gensiods size = 0;

    if (PI_AsBytesAndSize($result, (void **) &buf, &size) == -1) {
	Swig::DirectorTypeMismatchException::raise(
		"in output value of type '""std::vector<unsigned char>""'");
    } else {
	$1.assign((unsigned char *) buf, ((unsigned char *) buf) + size);
    }
}
// Return for read_s
%typemap(in, numinputs=0) std::vector<unsigned char> &rvec
	(std::vector<unsigned char> temp)
{
    temp.reserve(128); // FIXME - how to do this better?
    $1 = &temp;
}
%typemap(argout) std::vector<unsigned char> &rvec {
    PyObject *o;

    o = PI_FromStringAndSize((const char *) $1->data(), $1->size());
    $result = PI_add_result($result, o);
}
// For control I/O
%typemap(in) std::vector<unsigned char> &controldata
		(std::vector<unsigned char> temp) {
    $1 = &temp;
    if (PI_ToUCharVector(*$1, $input) == -1)
	SWIG_fail;
}
%typemap(argout) std::vector<unsigned char> &controldata
{
    PyObject *o;
    if ($1->size() == 0) {
	o = Py_None;
	Py_INCREF(o);
    } else {
	o = PI_FromStringAndSize((const char *) $1->data(), $1->size());
    }
    $result = PI_add_result($result, o);
}

// For non-allocating vectors passed from c++ to a direcotry target lang
%typemap(typecheck, precedence=SWIG_TYPECHECK_VECTOR) gensios::SimpleUCharVector
{
    $1 = PI_CanBeBytes($input);
}

%typemap(directorin) const gensios::SimpleUCharVector {
    $input = PI_FromStringAndSize((const char *) data.data(), data.size());
}

// auxdata and MDNS text fields
%typemap(in) const char *const * {
    if (PI_TupleToStringArray(&$1, $input) == -1)
	SWIG_fail;
}
%typemap(freearg) const char *const * {
    if ($1) {
	free($1);
    }
};
%typemap(directorin) const char *const * {
    $input = PI_StringArrayToTuple($1_name);
}

%typemap(directorin) gensios::Gensio *newg {
    // This is for reporting new gensios
    $input = SWIG_NewPointerObj(SWIG_as_voidptr($1),
				SWIGTYPE_p_gensios__Gensio, SWIG_POINTER_OWN);
}
%typemap(directorin) gensios::Gensio *tmpg {
    // Don't set SWIG_POINTER_OWN on this, we don't want python refcounts
    // managing it.
    $input = SWIG_NewPointerObj(SWIG_as_voidptr($1),
				SWIGTYPE_p_gensios__Gensio, 0);
}
%typemap(in, numinputs=0) gensios::Gensio **gret (Gensio *temp = NULL)  {
    $1 = &temp;
}
%typemap(argout) gensios::Gensio **gret {
    PyObject *val;
    if (*$1) {
	val = SWIG_NewPointerObj(SWIG_as_voidptr(*$1),
				 SWIGTYPE_p_gensios__Gensio,
				 SWIG_POINTER_OWN |  0 );
    } else {
	val = Py_None;
	Py_INCREF(Py_None);
    }
    $result = PI_add_result($result, val);
}

%typemap(in, numinputs=0) unsigned int *outval (unsigned int temp) {
    temp = 0;
    $1 = &temp;
}
%typemap(argout) unsigned int *outval {
    $result = PI_add_result($result, PyInt_FromLong(*$1));
}

// Handling of nested waiters and python callback.
%{
#include <gensio/pygensio.h>

    static thread_local Waiter *curr_waiter;

    static Waiter *
    save_waiter(Waiter *waiter)
    {
	Waiter *prev_waiter = curr_waiter;

	curr_waiter = waiter;
	return prev_waiter;
    }

    static void
    restore_waiter(Waiter *prev_waiter)
    {
	curr_waiter = prev_waiter;
    }

    class Py_Open_Done: public Gensio_Open_Done {
    public:
	Py_Open_Done(Gensio_Open_Done *iparent) : parent(iparent)
	{
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_incref(d);
	}

	void open_done(int err) override {
	    PyGILState_STATE gstate;

	    gstate = PyGILState_Ensure();
	    parent->open_done(err);
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_decref(d);
	    PyGILState_Release(gstate);
	    delete this;
	}
    private:
	// The one to call after we have done our python stuff.
	Gensio_Open_Done *parent;
    };

    class Py_Gensio_Close_Done: public Gensio_Close_Done {
    public:
	Py_Gensio_Close_Done(Gensio_Close_Done *iparent) : parent(iparent)
	{
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_incref(d);
	}

	void close_done() override {
	    PyGILState_STATE gstate;

	    gstate = PyGILState_Ensure();
	    parent->close_done();
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_decref(d);
	    PyGILState_Release(gstate);
	    delete this;
	}
    private:
	// The one to call after we have done our python stuff.
	Gensio_Close_Done *parent;
    };

    class Py_Raw_Event_Handler: public Raw_Event_Handler {
    public:
	Py_Raw_Event_Handler(Raw_Event_Handler *iparent): parent(iparent) { }
	~Py_Raw_Event_Handler() { delete parent; }

	int handle(Gensio *g, struct gensio *io,
		   int event, int err,
		   unsigned char *buf, gensiods *buflen,
		   const char *const *auxdata) override
	{
	    PyGILState_STATE gstate;
	    int rv;

	    gstate = PyGILState_Ensure();
	    rv = parent->handle(g, io, event, err, buf, buflen, auxdata);
	    PyGILState_Release(gstate);
	    return rv;
	}

	int new_channel(Event *e, Gensio *newg,
			const char *const *auxdata) override
	{
	    newg->raw_event_handler =
		new Py_Raw_Event_Handler(newg->raw_event_handler);
	    return parent->new_channel(e, newg, auxdata);
	}

	void freed(Event *e) override
	{
	    // Don't pass the event handler.  The python object is
	    // gone, we don't want this trying to report a deleted
	    // object to the freed event handler.
	    parent->freed(NULL);
	    if (e) {
		PyGILState_STATE gstate;
		gstate = PyGILState_Ensure();
		Swig::Director *d = dynamic_cast<Swig::Director *>(e);
		if (d)
		    pydirobj_decref(d);
		PyGILState_Release(gstate);
	    }
	}

    private:
	Raw_Event_Handler *parent;
    };

    class Py_Serial_Op_Done: public Serial_Op_Done {
    public:
	Py_Serial_Op_Done(Serial_Op_Done *iparent) : parent(iparent)
	{
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_incref(d);
	}

	void serial_op_done(int err, unsigned int val) override {
	    PyGILState_STATE gstate;

	    gstate = PyGILState_Ensure();
	    parent->serial_op_done(err, val);
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_decref(d);
	    PyGILState_Release(gstate);
	    delete this;
	}
    private:
	// The one to call after we have done our python stuff.
	Serial_Op_Done *parent;
    };

    class Py_Serial_Op_Sig_Done: public Serial_Op_Sig_Done {
    public:
	Py_Serial_Op_Sig_Done(Serial_Op_Sig_Done *iparent) : parent(iparent)
	{
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_incref(d);
	}

	void serial_op_sig_done(int err,
				const std::vector<unsigned char> data) override
	{
	    PyGILState_STATE gstate;

	    gstate = PyGILState_Ensure();
	    parent->serial_op_sig_done(err, data);
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_decref(d);
	    PyGILState_Release(gstate);
	    delete this;
	}
    private:
	// The one to call after we have done our python stuff.
	Serial_Op_Sig_Done *parent;
    };

    class Py_Accepter_Shutdown_Done: public Accepter_Shutdown_Done {
    public:
	Py_Accepter_Shutdown_Done(Accepter_Shutdown_Done *iparent) :
		parent(iparent)
	{
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_incref(d);
	}

	void shutdown_done() override {
	    PyGILState_STATE gstate;

	    gstate = PyGILState_Ensure();
	    parent->shutdown_done();
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_decref(d);
	    PyGILState_Release(gstate);
	    delete this;
	}
    private:
	// The one to call after we have done our python stuff.
	Accepter_Shutdown_Done *parent;
    };

    class Py_Accepter_Enable_Done: public Accepter_Enable_Done {
    public:
	Py_Accepter_Enable_Done(Accepter_Enable_Done *iparent) :
		parent(iparent)
	{
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_incref(d);
	}

	void enable_done() override {
	    PyGILState_STATE gstate;

	    gstate = PyGILState_Ensure();
	    parent->enable_done();
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_decref(d);
	    PyGILState_Release(gstate);
	    delete this;
	}
    private:
	// The one to call after we have done our python stuff.
	Accepter_Enable_Done *parent;
    };

    class Py_Raw_Acc_Event_Handler: public Raw_Accepter_Event_Handler {
    public:
	Py_Raw_Acc_Event_Handler(Raw_Accepter_Event_Handler *iparent):
	    parent(iparent) { }
	~Py_Raw_Acc_Event_Handler() { delete parent; }

	int handle(Accepter *a, int event, void *data) override
	{
	    PyGILState_STATE gstate;
	    int rv;

	    gstate = PyGILState_Ensure();
	    rv = parent->handle(a, event, data);
	    PyGILState_Release(gstate);
	    return rv;
	}

	void new_connection(Accepter_Event *e, Gensio *newg) override
	{
	    newg->raw_event_handler =
		new Py_Raw_Event_Handler(newg->raw_event_handler);
	    parent->new_connection(e, newg);
	}

	void freed(Accepter_Event *e) override
	{
	    // Don't pass the event handler.  The python object is
	    // gone, we don't want this trying to report a deleted
	    // object to the freed event handler.
	    parent->freed(NULL);
	    if (e) {
		PyGILState_STATE gstate;
		gstate = PyGILState_Ensure();
		Swig::Director *d = dynamic_cast<Swig::Director *>(e);
		if (d)
		    pydirobj_decref(d);
		PyGILState_Release(gstate);
	    }
	}

    private:
	Raw_Accepter_Event_Handler *parent;
    };

    class Py_MDNS_Free_Done: public MDNS_Free_Done {
    public:
	Py_MDNS_Free_Done(MDNS_Free_Done *iparent) : parent(iparent)
	{
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_incref(d);
	}

	void mdns_free_done() override {
	    PyGILState_STATE gstate;

	    gstate = PyGILState_Ensure();
	    parent->mdns_free_done();
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_decref(d);
	    PyGILState_Release(gstate);
	    delete this;
	}
    private:
	// The one to call after we have done our python stuff.
	MDNS_Free_Done *parent;
    };

    class Py_MDNS_Watch_Free_Done: public MDNS_Watch_Free_Done {
    public:
	Py_MDNS_Watch_Free_Done(MDNS_Watch_Free_Done *iparent) :
		parent(iparent)
	{
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_incref(d);
	}

	void mdns_watch_free_done() override {
	    PyGILState_STATE gstate;

	    gstate = PyGILState_Ensure();
	    parent->mdns_watch_free_done();
	    Swig::Director *d = dynamic_cast<Swig::Director *>(parent);
	    if (d)
		pydirobj_decref(d);
	    PyGILState_Release(gstate);
	    delete this;
	}
    private:
	// The one to call after we have done our python stuff.
	MDNS_Watch_Free_Done *parent;
    };

    class Py_Raw_MDNS_Event_Handler: public Raw_MDNS_Event_Handler {
    public:
	Py_Raw_MDNS_Event_Handler() { }
	~Py_Raw_MDNS_Event_Handler() { if (parent) delete parent; }

	void handle(MDNS_Watch_Event *e,
		    enum gensio_mdns_data_state state,
		    int interfacenum, int ipdomain,
		    const char *name, const char *type,
		    const char *domain, const char *host,
		    const struct gensio_addr *addr,
		    const char * const *txt) override
	{
	    PyGILState_STATE gstate;

	    gstate = PyGILState_Ensure();
	    parent->handle(e, state, interfacenum, ipdomain,
			   name, type, domain, host, addr, txt);
	    PyGILState_Release(gstate);
	}

	void set_parent(Raw_MDNS_Event_Handler *parent) override
	{
	    this->parent = parent;
	}

    private:
	Raw_MDNS_Event_Handler *parent = NULL;
    };

%}

// In Python there's no way to call the free handle as the python
// object has been destroyed by then.
%ignore gensios::Event::freed;

// We intercept all functions with callbacks to insert our own code.
// Python has special requirements when you block and when you call
// into python code from C/C++, we have to handle all those.
%ignore gensios::Os_Funcs::Os_Funcs;
%ignore gensios::Os_Funcs::~Os_Funcs;
%ignore gensios::Os_Funcs::set_log_handler;
%ignore gensios::Gensio::open;
%ignore gensios::Gensio::open_nochild;
%ignore gensios::Gensio::close;
%ignore gensios::Gensio::write_s;
%ignore gensios::Gensio::set_event_handler;
%ignore gensios::Gensio::alloc_channel;
%ignore gensios::Gensio::control;
%ignore gensios::gensio_alloc;
%ignore gensios::Serial_Gensio::baud;
%ignore gensios::Serial_Gensio::datasize;
%ignore gensios::Serial_Gensio::parity;
%ignore gensios::Serial_Gensio::stopbits;
%ignore gensios::Serial_Gensio::flowcontrol;
%ignore gensios::Serial_Gensio::iflowcontrol;
%ignore gensios::Serial_Gensio::sbreak;
%ignore gensios::Serial_Gensio::dtr;
%ignore gensios::Serial_Gensio::rts;
%ignore gensios::Serial_Gensio::cts;
%ignore gensios::Serial_Gensio::dcd_dsr;
%ignore gensios::Serial_Gensio::ri;
%ignore gensios::Serial_Gensio::signature;
%ignore gensios::Serial_Gensio::baud_s;
%ignore gensios::Serial_Gensio::datasize_s;
%ignore gensios::Serial_Gensio::parity_s;
%ignore gensios::Serial_Gensio::stopbits_s;
%ignore gensios::Serial_Gensio::flowcontrol_s;
%ignore gensios::Serial_Gensio::iflowcontrol_s;
%ignore gensios::Serial_Gensio::sbreak_s;
%ignore gensios::Serial_Gensio::dtr_s;
%ignore gensios::Serial_Gensio::rts_s;
%ignore gensios::Serial_Gensio::cts_s;
%ignore gensios::Serial_Gensio::dcd_dsr_s;
%ignore gensios::Serial_Gensio::ri_s;
%ignore gensios::gensio_acc_alloc;
%ignore gensios::Accepter::set_event_handler;
%ignore gensios::Accepter::shutdown;
%ignore gensios::Accepter::set_callback_enable(bool enabled,
					      Accepter_Enable_Done *done);
%ignore gensios::Accepter::str_to_gensio;
%ignore gensios::Accepter::control;

%ignore gensios::Waiter::wait;

%ignore gensios::MDNS::free;
%ignore gensios::MDNS::add_watch;
%ignore gensios::MDNS_Watch::free;
%ignore gensios::MDNS_Watch::MDNS_Watch;

#define GENSIOOSH_DLL_PUBLIC // For some reason this doesn't get set in swig
%include <gensio/gensio_err.h>
%include <gensio/gensio_control.h>
#define GENSIOOSHCPP_DLL_PUBLIC // For some reason this doesn't get set in swig
%include <gensio/gensioosh>
%include <gensio/gensio>
%include <gensio/gensiomdns>


////////////////////////////////////////////////////
// Define our own Os_Funcs functions.

%rename("") gensios::Os_Funcs::Os_Funcs;
%rename("") gensios::Os_Funcs::~Os_Funcs;
%rename("") gensios::Os_Funcs::set_log_handler;
%extend gensios::Os_Funcs {
    Os_Funcs(int wait_sig, Os_Funcs_Log_Handler *logger = NULL)
    {
	Os_Funcs_Log_Handler *int_handler = NULL;
	if (logger)
	    int_handler = new Internal_Log_Handler(logger);
	return new Os_Funcs(wait_sig, int_handler);
    }

    ~Os_Funcs()
    {
	delete self;
    }

    void set_log_handler(Os_Funcs_Log_Handler *logger) {
	Internal_Log_Handler *ilogger =
	    dynamic_cast<Internal_Log_Handler *>(self->get_log_handler());
	if (ilogger)
	    ilogger->set_handler(logger);
    }

    void cleanup_mem() {
	gensio_cleanup_mem(*self);
    }
}

////////////////////////////////////////////////////
// Define our own Gensio functins.
%rename("") gensios::Gensio::open;
%rename("") gensios::Gensio::open_nochild;
%rename("") gensios::Gensio::close;
%rename("") gensios::Gensio::write_s;
%rename("") gensios::Gensio::write_s(gensiods *count,
				const std::vector<unsigned char> data,
				gensio_time *timeout = NULL, bool intr = false);
%rename("") gensios::Gensio::set_event_handler;
%rename("") gensios::Gensio::alloc_channel;
%rename("") gensios::Gensio::control;
%catches(gensios::gensio_error) gensios::Gensio::write_s;
%extend gensios::Gensio {
    void open(Gensio_Open_Done *done)
    {
	Py_Open_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Open_Done(done);
	self->open((Gensio_Open_Done *) pydone);
    }

    void open_nochild(Gensio_Open_Done *done)
    {
	Py_Open_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Open_Done(done);
	self->open_nochild((Gensio_Open_Done *) pydone);
    }

    void close(Gensio_Close_Done *done)
    {
	Py_Gensio_Close_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Gensio_Close_Done(done);
	self->close((Gensio_Close_Done *) pydone);
    }

    int write_s(gensiods *count, const std::vector<unsigned char> data)
    {
	int rv;
	GENSIO_SWIG_C_BLOCK_ENTRY
	rv = self->write_s(count, data);
	GENSIO_SWIG_C_BLOCK_EXIT
	return rv;
    }

    Gensio *alloc_channel(const char *const *args, Event *cb)
    {
	Gensio *g = self->alloc_channel(args, cb);

	if (cb) {
	    Swig::Director *d = dynamic_cast<Swig::Director *>(cb);
	    if (d)
		pydirobj_incref(d);
	}
	if (g)
	    g->raw_event_handler =
		new Py_Raw_Event_Handler(g->raw_event_handler);
	return g;
    }

    void set_event_handler(Event *cb)
    {
	Event *old_cb = self->get_cb();

	if (cb) {
	    Swig::Director *d = dynamic_cast<Swig::Director *>(cb);
	    if (d)
		pydirobj_incref(d);
	}
	self->set_event_handler(cb);
	if (old_cb) {
	    Swig::Director *d = dynamic_cast<Swig::Director *>(old_cb);
	    if (d)
		pydirobj_decref(d);
	}
    }

    %rename(control) controlt;
    int control(int depth, bool get, unsigned int option,
		std::vector<unsigned char> &controldata)
    {
	int rv;
	char *rdata = NULL;
	gensiods glen = 0, slen = 0;

	slen = controldata.size();
	if (get) {
	    /* Pass in a zero length to get the actual length. */
	    rv = self->control(depth, get, option,
			       (char *) controldata.data(), &glen);
	    if (rv)
		goto out;
	    /* Allocate the larger of constroldata.size() and glen) */
	    if (slen > glen) {
		rdata = (char *) malloc(slen + 1);
		glen = slen;
	    } else {
		rdata = (char *) malloc(glen + 1);
	    }
	    if (!rdata) {
		rv = GE_NOMEM;
		goto out;
	    }
	    rdata[glen] = '\0';
	    rdata[slen] = '\0';
	    glen += 1;
	    memcpy(rdata, controldata.data(), slen);
	    rv = self->control(depth, get, option, rdata, &glen);
	    if (rv) {
		free(rdata);
		rdata = NULL;
		glen = 0;
	    }
	out:
	    if (!rv)
		controldata.assign(rdata, rdata + glen);
	    free(rdata);
	} else {
	    rv = self->control(depth, get, option, (char *)
			       controldata.data(), &slen);
	    controldata.resize(0);
	}
	return rv;
    }
}

%rename("") gensios::gensio_alloc;
%rename(gensio_alloc) gensio_alloct;
%newobject gensio_alloct;
%newobject cast_to_serial_gensio;
%inline %{
gensios::Gensio *gensio_alloct(std::string str, gensios::Os_Funcs &o,
			       gensios::Event *cb)
{
    Gensio *g = gensio_alloc(str, o, cb);

    if (cb) {
	Swig::Director *d = dynamic_cast<Swig::Director *>(cb);
	if (d)
	    pydirobj_incref(d);
    }
    if (g)
	g->raw_event_handler = new Py_Raw_Event_Handler(g->raw_event_handler);
    return g;
}

gensios::Gensio *gensio_alloct(gensios::Gensio *child, std::string str,
			      gensios::Os_Funcs &o, gensios::Event *cb)
{
    Gensio *g = gensio_alloc(child, str, o, cb);

    if (cb) {
	Swig::Director *d = dynamic_cast<Swig::Director *>(cb);
	if (d)
	    pydirobj_incref(d);
    }
    if (g)
	g->raw_event_handler = new Py_Raw_Event_Handler(g->raw_event_handler);
    return g;
}

gensios::Serial_Gensio *cast_to_serial_gensio(gensios::Gensio *g) {
    gensio_ref(g->get_gensio());
    return dynamic_cast<gensios::Serial_Gensio *>(g);
}
%}

%rename("") gensios::Serial_Gensio::baud;
%rename("") gensios::Serial_Gensio::datasize;
%rename("") gensios::Serial_Gensio::parity;
%rename("") gensios::Serial_Gensio::stopbits;
%rename("") gensios::Serial_Gensio::flowcontrol;
%rename("") gensios::Serial_Gensio::iflowcontrol;
%rename("") gensios::Serial_Gensio::sbreak;
%rename("") gensios::Serial_Gensio::dtr;
%rename("") gensios::Serial_Gensio::rts;
%rename("") gensios::Serial_Gensio::cts;
%rename("") gensios::Serial_Gensio::dcd_dsr;
%rename("") gensios::Serial_Gensio::ri;
%rename("") gensios::Serial_Gensio::signature;
%rename("") gensios::Serial_Gensio::baud_s;
%rename("") gensios::Serial_Gensio::datasize_s;
%rename("") gensios::Serial_Gensio::parity_s;
%rename("") gensios::Serial_Gensio::stopbits_s;
%rename("") gensios::Serial_Gensio::flowcontrol_s;
%rename("") gensios::Serial_Gensio::iflowcontrol_s;
%rename("") gensios::Serial_Gensio::sbreak_s;
%rename("") gensios::Serial_Gensio::dtr_s;
%rename("") gensios::Serial_Gensio::rts_s;
%rename("") gensios::Serial_Gensio::cts_s;
%rename("") gensios::Serial_Gensio::dcd_dsr_s;
%rename("") gensios::Serial_Gensio::ri_s;
%extend gensios::Serial_Gensio {
    void baud(unsigned int baud, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->baud(baud, (gensios::Serial_Op_Done *) pydone);
    }

    void datasize(unsigned int size, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->datasize(size, (gensios::Serial_Op_Done *) pydone);
    }

    void parity(unsigned int par, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->parity(par, (gensios::Serial_Op_Done *) pydone);
    }

    void stopbits(unsigned int bits, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->stopbits(bits, (gensios::Serial_Op_Done *) pydone);
    }

    void flowcontrol(unsigned int flow, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->flowcontrol(flow, (gensios::Serial_Op_Done *) pydone);
    }

    void iflowcontrol(unsigned int flow, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->iflowcontrol(flow, (gensios::Serial_Op_Done *) pydone);
    }

    void sbreak(unsigned int sbreak, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->sbreak(sbreak, (gensios::Serial_Op_Done *) pydone);
    }

    void dtr(unsigned int dtr, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->dtr(dtr, (gensios::Serial_Op_Done *) pydone);
    }

    void rts(unsigned int rts, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->rts(rts, (gensios::Serial_Op_Done *) pydone);
    }

    void cts(unsigned int cts, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->cts(cts, (gensios::Serial_Op_Done *) pydone);
    }

    void dcd_dsr(unsigned int dcd_dsr, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->dcd_dsr(dcd_dsr, (gensios::Serial_Op_Done *) pydone);
    }

    void ri(unsigned int ri, gensios::Serial_Op_Done *done)
    {
	Py_Serial_Op_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Done(done);
	self->ri(ri, (gensios::Serial_Op_Done *) pydone);
    }

    void signature(const std::vector<unsigned char> sig,
		   gensios::Serial_Op_Sig_Done *done)
    {
	Py_Serial_Op_Sig_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Serial_Op_Sig_Done(done);
	self->signature(sig, (gensios::Serial_Op_Sig_Done *) pydone);
    }

    int baud_s(unsigned int *outval,
	       unsigned int baud, gensio_time *timeout = NULL,
	       bool intr = false)
    {
	int rv = self->baud_s(&baud, timeout, intr);
	if (rv)
	    return rv;
	*outval = baud;
	return 0;
    }

    int datasize_s(unsigned int *outval,
		   unsigned int size, gensio_time *timeout = NULL,
		   bool intr = false)
    {
	int rv = self->datasize_s(&size, timeout, intr);
	if (rv)
	    return rv;
	*outval = size;
	return 0;
    }

    int parity_s(unsigned int *outval,
		 unsigned int par, gensio_time *timeout = NULL,
		 bool intr = false)
    {
	int rv = self->parity_s(&par, timeout, intr);
	if (rv)
	    return rv;
	*outval = par;
	return 0;
    }

    int stopbits_s(unsigned int *outval,
		   unsigned int bits, gensio_time *timeout = NULL,
		   bool intr = false)
    {
	int rv = self->stopbits_s(&bits, timeout, intr);
	if (rv)
	    return rv;
	*outval = bits;
	return 0;
    }

    int flowcontrol_s(unsigned int *outval,
		      unsigned int flow, gensio_time *timeout = NULL,
		      bool intr = false)
    {
	int rv = self->flowcontrol_s(&flow, timeout, intr);
	if (rv)
	    return rv;
	*outval = flow;
	return 0;
    }

    int iflowcontrol_s(unsigned int *outval,
		       unsigned int flow, gensio_time *timeout = NULL,
		       bool intr = false)
    {
	int rv = self->iflowcontrol_s(&flow, timeout, intr);
	if (rv)
	    return rv;
	*outval = flow;
	return 0;
    }

    int sbreak_s(unsigned int *outval,
		 unsigned int sbreak, gensio_time *timeout = NULL,
		 bool intr = false)
    {
	int rv = self->sbreak_s(&sbreak, timeout, intr);
	if (rv)
	    return rv;
	*outval = sbreak;
	return 0;
    }

    int dtr_s(unsigned int *outval,
	      unsigned int dtr, gensio_time *timeout = NULL,
	      bool intr = false)
    {
	int rv = self->dtr_s(&dtr, timeout, intr);
	if (rv)
	    return rv;
	*outval = dtr;
	return 0;
    }

    int rts_s(unsigned int *outval,
	      unsigned int rts, gensio_time *timeout = NULL,
	      bool intr = false)
    {
	int rv = self->rts_s(&rts, timeout, intr);
	if (rv)
	    return rv;
	*outval = rts;
	return 0;
    }

    int cts_s(unsigned int *outval,
	      unsigned int cts, gensio_time *timeout = NULL,
	      bool intr = false)
    {
	int rv = self->cts_s(&cts, timeout, intr);
	if (rv)
	    return rv;
	*outval = cts;
	return 0;
    }

    int dcd_dsr_s(unsigned int *outval,
		  unsigned int dcd_dsr, gensio_time *timeout = NULL,
		  bool intr = false)
    {
	int rv = self->dcd_dsr_s(&dcd_dsr, timeout, intr);
	if (rv)
	    return rv;
	*outval = dcd_dsr;
	return 0;
    }

    int ri_s(unsigned int *outval,
	     unsigned int ri, gensio_time *timeout = NULL,
	     bool intr = false)
    {
	int rv = self->ri_s(&ri, timeout, intr);
	if (rv)
	    return rv;
	*outval = ri;
	return 0;
    }
}

%rename("") gensios::gensio_acc_alloc;
%rename(gensio_acc_alloc) gensio_acc_alloct;
%newobject gensio_acc_alloct;
%inline %{
gensios::Accepter *
gensio_acc_alloct(std::string str, gensios::Os_Funcs &o,
		 gensios::Accepter_Event *cb)
{
    Accepter *a = gensio_acc_alloc(str, o, cb);

    if (cb) {
	Swig::Director *d = dynamic_cast<Swig::Director *>(cb);
	if (d)
	    pydirobj_incref(d);
    }
    if (a)
	a->raw_event_handler =
	    new Py_Raw_Acc_Event_Handler(a->raw_event_handler);
    return a;
}

gensios::Accepter *
gensio_acc_alloct(gensios::Accepter *child, std::string str, gensios::Os_Funcs &o,
		  gensios::Accepter_Event *cb)
{
    Accepter *a = gensio_acc_alloc(child, str, o, cb);

    if (cb) {
	Swig::Director *d = dynamic_cast<Swig::Director *>(cb);
	if (d)
	    pydirobj_incref(d);
    }
    if (a)
	a->raw_event_handler =
	    new Py_Raw_Acc_Event_Handler(a->raw_event_handler);
    return a;
}
%}

%rename("") gensios::Accepter::set_event_handler;
%rename("") gensios::Accepter::shutdown;
%rename("") gensios::Accepter::set_callback_enable(bool enabled,
						  Accepter_Enable_Done *done);
%rename("") gensios::Accepter::str_to_gensio;
%rename("") gensios::Accepter::control;
%extend gensios::Accepter {
    ~Accepter() {
	self->free()
    }

    void shutdown(Accepter_Shutdown_Done *done)
    {
	Py_Accepter_Shutdown_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Accepter_Shutdown_Done(done);
	self->shutdown((Accepter_Shutdown_Done *) pydone);
    }

    void set_callback_enable(bool enabled, Accepter_Enable_Done *done)
    {
	Py_Accepter_Enable_Done *pydone = NULL;
	if (done)
	    pydone = new Py_Accepter_Enable_Done(done);
	self->set_callback_enable(enabled, (Accepter_Enable_Done *) pydone);
    }

    void set_event_handler(Accepter_Event *cb)
    {
	Accepter_Event *old_cb = self->get_cb();

	if (cb) {
	    Swig::Director *d = dynamic_cast<Swig::Director *>(cb);
	    if (d)
		pydirobj_incref(d);
	}
	self->set_event_handler(cb);
	if (old_cb) {
	    Swig::Director *d = dynamic_cast<Swig::Director *>(old_cb);
	    if (d)
		pydirobj_decref(d);
	}
    }

    %newobject str_to_gensio;
    Gensio *str_to_gensio(std::string str, Event *cb)
    {
	Gensio *g = self->str_to_gensio(str, cb);

	if (cb) {
	    Swig::Director *d = dynamic_cast<Swig::Director *>(cb);
	    if (d)
		pydirobj_incref(d);
	}
	if (g)
	    g->raw_event_handler =
		new Py_Raw_Event_Handler(g->raw_event_handler);
	return g;
    }

    %rename(control) controlt;
    int control(int depth, bool get, unsigned int option,
		std::vector<unsigned char> &controldata)
    {
	int rv;
	char *rdata = NULL;
	gensiods glen = 0, slen = 0;

	slen = controldata.size();
	if (get) {
	    /* Pass in a zero length to get the actual length. */
	    rv = self->control(depth, get, option,
			       (char *) controldata.data(), &glen);
	    if (rv)
		goto out;
	    /* Allocate the larger of constroldata.size() and glen) */
	    if (slen > glen) {
		rdata = (char *) malloc(slen + 1);
		glen = slen;
	    } else {
		rdata = (char *) malloc(glen + 1);
	    }
	    if (!rdata) {
		rv = GE_NOMEM;
		goto out;
	    }
	    rdata[glen] = '\0';
	    rdata[slen] = '\0';
	    glen += 1;
	    memcpy(rdata, controldata.data(), slen);
	    rv = self->control(depth, get, option, rdata, &glen);
	    if (rv) {
		free(rdata);
		rdata = NULL;
		glen = 0;
	    }
	out:
	    if (!rv)
		controldata.assign(rdata, rdata + glen);
	    free(rdata);
	} else {
	    rv = self->control(depth, get, option, (char *)
			       controldata.data(), &slen);
	    controldata.resize(0);
	}
	return rv;
    }
}

////////////////////////////////////////////////////
// MDNS handling
%rename("") gensios::MDNS::free;
%rename("") gensios::MDNS::add_watch;
%extend gensios::MDNS {
    void free(MDNS_Free_Done *done)
    {
	Py_MDNS_Free_Done *pydone = new Py_MDNS_Free_Done(done);
	self->free((Py_MDNS_Free_Done *) pydone);
    }

    %newobject add_watch;
    MDNS_Watch *add_watch(int interfacenum, int ipdomain,
			  char *name, char *type, char *domain, char *host,
			  MDNS_Watch_Event *event)
    {
	Raw_MDNS_Event_Handler *evh = new Py_Raw_MDNS_Event_Handler;
	MDNS_Watch *w = self->add_watch(interfacenum, ipdomain, name, type,
					domain, host, event, evh);

	return w;
    }
}

%rename("") gensios::MDNS_Watch::free;
%rename("") gensios::MDNS_Watch::MDNS_Watch;
%extend gensios::MDNS_Watch {
    MDNS_Watch(MDNS *m, int interfacenum, int ipdomain,
	       char *name, char *type, char *domain, char *host,
	       MDNS_Watch_Event *event) {
	Raw_MDNS_Event_Handler *evh = new Py_Raw_MDNS_Event_Handler;
	MDNS_Watch *w = m->add_watch(interfacenum, ipdomain, name, type,
				     domain, host, event, evh);

	return w;
    }

    void free(MDNS_Watch_Free_Done *done)
    {
	Py_MDNS_Watch_Free_Done *pydone = new Py_MDNS_Watch_Free_Done(done);
	self->free((Py_MDNS_Watch_Free_Done *) pydone);
    }
}

////////////////////////////////////////////////////
// Define our own Waiter function.
%rename("") gensios::Waiter::wait;
%extend gensios::Waiter {
    int wait(unsigned int count, gensio_time *timeout)
    {
	int rv;
	Waiter *prev_waiter = save_waiter(self);

	do {
	    GENSIO_SWIG_C_BLOCK_ENTRY
	    rv = self->wait(count, timeout, true);
	    GENSIO_SWIG_C_BLOCK_EXIT
	    if (rv == GE_TIMEDOUT)
		break;
	    if (check_for_err(rv)) {
		if (prev_waiter)
		    prev_waiter->wake();
		break;
	    }
	    if (rv == GE_INTERRUPTED)
		continue;
	    break;
	} while(true);
	restore_waiter(prev_waiter);
	return rv;
    }

    int service(gensio_time *timeout) {
	int err;
	Waiter *prev_waiter = save_waiter(self);
	Os_Funcs o = self->get_os_funcs();

	do {
	    GENSIO_SWIG_C_BLOCK_ENTRY
		err = gensio_os_funcs_service(o, timeout);
	    GENSIO_SWIG_C_BLOCK_EXIT
	    if (check_for_err(err)) {
		if (prev_waiter)
		    prev_waiter->wake();
		break;
	    }
	    if (err == GE_INTERRUPTED)
		continue;
	    break;
	} while(true);
	restore_waiter(prev_waiter);
	return err;
    }
}

int gensio_num_alloced();
