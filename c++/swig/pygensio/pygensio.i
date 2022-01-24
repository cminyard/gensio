
%module(directors="1") pygensio

%{
#include <gensio/gensio>
using namespace gensio;
%}

%include <typemaps/std_string.swg>
%include <std_string.i>

%feature("director") gensio::Event;
%feature("director") gensio::Gensio_Done_Err;
%feature("director") gensio::Gensio_Done;
%feature("director") gensio::Serial_Event;
%feature("director") gensio::Serial_Op_Done;
%feature("director") gensio::Serial_Op_Sig_Done;
%feature("director") gensio::Accepter_Event;
%feature("director") gensio::Accepter_Done;
%feature("director") gensio::MDNS_Done;
%feature("director") gensio::MDNS_Watch_Done;
%feature("director") gensio::MDNS_Watch_Event;

%define GENSIOCPP_DLL_PUBLIC %enddef
%define GENSIO_DLL_PUBLIC %enddef

%ignore gensio::gensio_error;

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

static int
PI_CanBeBytes(PyObject *o)
{
    return (o == Py_None || PI_BytesCheck(o) || PyByteArray_Check(o));
}

static int
PI_ToUCharVector(std::vector<unsigned char> &v, PyObject *o)
{
    void *tdata;
    gensiods len;

    if (o == Py_None) {
	// Nothing to do, vector is empty
	return 0;
    }
    if (PI_BytesCheck(o)) {
	PI_AsBytesAndSize(o, &tdata, &len);
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
    gensiods len, i;

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
PI_TupleToStringArray(char ***out, PyObject *o)
{
    unsigned int i;
    unsigned int len;
    char **temp = NULL;

    if (o == Py_None)
	goto null_auxdata;

    if (!PySequence_Check(o)) {
	PyErr_SetString(PyExc_TypeError, "Expecting a sequence");
	return -1;
    }
    len = PyObject_Length(o);
    if (len == 0)
	goto null_auxdata;

    temp = (char **) malloc(sizeof(char *) * (len + 1));
    if (!temp) {
	PyErr_SetString(PyExc_ValueError, "Out of memory");
	return -1;
    }
    memset(temp, 0, sizeof(char *) * (len + 1));
    for (i = 0; i < len; i++) {
	PyObject *o = PySequence_GetItem(o, i);

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

%}

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

%typemap(directorout) gensiods {
    $result = PyInt_AsLong($1);
}

%typemap(out) gensiods {
    $result = PyInt_FromLong($1);
}

%typemap(typecheck, precedence=SWIG_TYPECHECK_INTEGER) gensiods {
    $1 = PyInt_Check($input) ? 1 : 0;
}

// For strings returned from directors.
%typemap(directorin, numinputs=0) std::string &retval {
}

%typemap(directorargout) std::string &retval {
    char *buf;
    gensiods size;

    if (PI_AsBytesAndSize($result, (void **) &buf, &size) == -1) {
	Swig::DirectorTypeMismatchException::raise(
		SWIG_ErrorType(SWIG_ArgError(swig_res)),
		"in output value of type '""std::string""'");
    } else {
	$1.assign(buf, size);
    }
}

// For vectors passed from target lang to C++, and passed in directors
// to target lang, and returned vectors from directors.
%typemap(typecheck, precedence=SWIG_TYPECHECK_VECTOR)
		const std::vector<unsigned char> {
    $1 = PI_CanBeBytes($input);
}

%typemap(in) const std::vector<unsigned char> {
    if (PI_ToUCharVector($1, $input) == -1)
	SWIG_fail;
}

%typemap(directorin) const std::vector<unsigned char> data {
    $input = PI_FromStringAndSize((const char *) data.data(), data.size());
}

%typemap(directorin) const std::vector<unsigned char> &retval {
    $input = PI_FromStringAndSize((const char *) data.data(), data.size());
}

%typemap(directorargout) const std::vector<unsigned char> &retval {
    char *buf;
    gensiods size;

    if (PI_AsBytesAndSize($result, (void **) &buf, &size) == -1) {
	Swig::DirectorTypeMismatchException::raise(
		SWIG_ErrorType(SWIG_ArgError(swig_res)),
		"in output value of type '""std::vector<unsigned char>""'");
    } else {
	$1.assign((unsigned char *) buf, size);
    }
}

// For non-allocating vectors passed from c++ to a direcotry target lang
%typemap(typecheck, precedence=SWIG_TYPECHECK_VECTOR) gensio::SimpleUCharVector
{
    $1 = PI_CanBeBytes($input);
}

%typemap(directorin) const gensio::SimpleUCharVector {
    $input = PI_FromStringAndSize((const char *) data.data(), data.size());
}

// auxdata
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

%typemap(directorin) gensio::Gensio * {
    if ($1->user_data) {
	$input = (PyObject *) $1->user_data;
	Py_INCREF($input);
    } else {
	$input = SWIG_NewPointerObj(SWIG_as_voidptr($1),
				  SWIGTYPE_p_gensio__Gensio,
				  SWIG_POINTER_OWN |  0 );
	$1->user_data = (void *) $input;
    }
    Py_INCREF($input);
}

%typemap(out) gensio::Gensio * {
    if ($1->user_data) {
	$result = (PyObject *) $1->user_data;
	Py_INCREF($result);
    } else {
	$result = SWIG_NewPointerObj(SWIG_as_voidptr($1),
				     SWIGTYPE_p_gensio__Gensio,
				     SWIG_POINTER_OWN |  0 );
	$1->user_data = (void *) $result;
    }
}

////////////////////////////////////////////////////
// Os_Funcs
%catches(gensio::gensio_error) gensio::Os_Funcs::Os_Funcs;
%catches(gensio::gensio_error) gensio::Os_Funcs::proc_setup;

%ignore gensio::Os_Funcs::set_vlog;
%ignore gensio::Os_Funcs::Os_Funcs(struct gensio_os_funcs *o);
%ignore gensio::Os_Funcs::operator=;
%ignore gensio::Os_Funcs::operator struct gensio_os_funcs*;

// FIXME - ignore proc_setup?
%ignore gensio::Os_Funcs::get_proc_data;

////////////////////////////////////////////////////
// Addr
%catches(gensio::gensio_error) gensio::Addr::Addr;
%catches(gensio::gensio_error) gensio::Addr::to_string;
%catches(gensio::gensio_error) gensio::Addr::to_string_all;

%ignore gensio::Addr::Addr(Os_Funcs &o, int nettype,
			   const void *iaddr, gensiods len,
			   unsigned int port);
%ignore gensio::Addr::Addr(struct gensio_addr *iaddr);
%ignore gensio::Addr::operator=;
%ignore gensio::Addr::operator struct gensio_addr*;
%ignore gensio::Addr::getaddr;


////////////////////////////////////////////////////
// Event
%ignore gensio::SimpleUCharVector;
%ignore gensio::SimpleUCharVector::operator[];

////////////////////////////////////////////////////
// Allocators

%catches(gensio::gensio_error) gensio::gensio_alloc;

////////////////////////////////////////////////////
// Gensio
// FIXME - Implement control ourself
%ignore gensio::Gensio::control;

// Custom destructor
%delobject gensio::Gensio::free;

// Only allow the vector version of write()
%ignore gensio::Gensio::write(const void *data, gensiods datalen,
			      const char *const *auxdata);
%ignore gensio::Gensio::write(const SimpleUCharVector data,
			      const char *const *auxdata);
%ignore gensio::Gensio::write_s(gensiods *count,
				const void *data, gensiods datalen,
				gensio_time *timeout = NULL);
%ignore gensio::Gensio::write_s(gensiods *count,
				const SimpleUCharVector data,
				gensio_time *timeout = NULL);
%ignore gensio::Gensio::write_s_intr(gensiods *count,
				     const void *data, gensiods datalen,
				     gensio_time *timeout = NULL);
%ignore gensio::Gensio::write_s_intr(gensiods *count,
				     const SimpleUCharVector data,
				     gensio_time *timeout = NULL);
%ignore gensio::Gensio::write(const struct gensio_sg *sg, gensiods sglen,
			      const char *const *auxdata);
%ignore gensio::Gensio::get_os_funcs();
%ignore gensio::Gensio::get_cb();
%ignore gensio::Gensio::get_gensio();

%catches(gensio::gensio_error) gensio::Gensio::open;
%catches(gensio::gensio_error) gensio::Gensio::open_s;
%catches(gensio::gensio_error) gensio::Gensio::open_nochild;
%catches(gensio::gensio_error) gensio::Gensio::open_nochild_s;
%catches(gensio::gensio_error) gensio::Gensio::write;
%catches(gensio::gensio_error) gensio::Gensio::write_s;
%catches(gensio::gensio_error) gensio::Gensio::write_s_intr;
%catches(gensio::gensio_error) gensio::Gensio::alloc_channel;
%catches(gensio::gensio_error) gensio::Gensio::close;
%catches(gensio::gensio_error) gensio::Gensio::close_s;
%catches(gensio::gensio_error) gensio::Gensio::read;
%catches(gensio::gensio_error) gensio::Gensio::read_s;
%catches(gensio::gensio_error) gensio::Gensio::read_s_intr;

%newobject gensio::Gensio::get_child;
%newobject gensio::Gensio::alloc_channel;


// FIXME - need to figure out a way to do this
%ignore gensio::Accepter_Event::log;

// FIXME - Implement control ourself
%ignore gensio::Gensio::control;

////////////////////////////////////////////////////
// gensio_err.h
%ignore gensio_i_os_err_to_err;

////////////////////////////////////////////////////
// A bunch of friend functions that we need to ignore.
%ignore gensio::gensio_alloc(struct gensio *io, Os_Funcs &o);
%ignore gensio::gensio_alloc(Gensio *child, std::string str, Os_Funcs &o,
			     Event *cb);
%ignore gensio_acc_alloc(struct gensio_accepter *acc, Os_Funcs &o);
%ignore gensio_acc_alloc(Accepter *child, std::string str, Os_Funcs &o,
			 Accepter_Event *cb);
%ignore gensio::gensio_add_class;
%ignore gensio::gensio_cpp_freed;
%ignore gensio::gensio_acc_cpp_freed;
%ignore gensio::mdns_free_done;
%ignore gensio::mdns_watch_done;
%ignore gensio::mdns_watch_event;

////////////////////////////////////////////////////
// Now our implementsion of set_vlog

%feature("director") VLog_Handler;
%inline %{
    class VLog_Handler {
    public:
	virtual void log(enum gensio_log_levels level, char *str) = 0;
	virtual ~VLog_Handler() = default;
    };
%}

%{
    void gensio_swig_vlog_handler(struct gensio_os_funcs *o,
				  enum gensio_log_levels level,
				  const char *log, va_list args)
    {
	struct VLog_Handler *h =
	    static_cast<VLog_Handler *>(gensio_os_funcs_get_data(o));
	char *str;
	va_list argcopy;
	unsigned int len;

	// This is a hack, if we get a python exception, we are going
	// to print something out but we don't want it to kill the
	// h->log() call.  This clears the python exception so h->log
	// doesn't get killed and also prints useful info.
	PyErr_Print();

	va_copy(argcopy, args);
	len = vsnprintf(NULL, 0, log, argcopy);
	va_end(argcopy);

	str = (char *) malloc(len + 1);
	vsnprintf(str, len + 1, log, args);
	h->log(level, str);
	free(str);
    }
%}

////////////////////////////////////////////////////
// Include what we need
%include <gensio/gensio_err.h>
%include <gensio/gensio>

////////////////////////////////////////////////////
// Add our logging capability
%extend gensio::Os_Funcs {
    void set_logger(struct VLog_Handler *h)
    {
	struct gensio_os_funcs *o = *self;
	gensio_os_funcs_set_data(o, h);
	gensio_os_funcs_set_vlog(o, gensio_swig_vlog_handler);
    }
}
