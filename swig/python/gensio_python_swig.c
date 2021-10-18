/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#define SWIGPYTHON

#include "config.h"
#include <malloc.h>
#include <assert.h>
#include <Python.h>
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_swig.h>
#include "python_swig_internals.h"

void (*swig_waiter_wake)(void);

swig_cb_val *
gensio_python_ref_swig_cb_i(swig_cb *cb)
{
    OI_PY_STATE gstate;

    gstate = OI_PY_STATE_GET();
    Py_INCREF(cb);
    OI_PY_STATE_PUT(gstate);
    return cb;
}

swig_cb_val *
gensio_python_deref_swig_cb_val(swig_cb_val *cb)
{
    OI_PY_STATE gstate;

    if (cb) {
	gstate = OI_PY_STATE_GET();
	Py_DECREF(cb);
	OI_PY_STATE_PUT(gstate);
    }
    return cb;
}

PyObject *
swig_finish_call_rv(swig_cb_val *cb, const char *method_name, PyObject *args,
		    bool optional)
{
    PyObject *p, *o = NULL;

    if (PyObject_HasAttrString(cb, method_name)) {
	p = PyObject_GetAttrString(cb, method_name);
	o = PyObject_CallObject(p, args);
	Py_DECREF(p);
	if (PyErr_Occurred())
	    swig_waiter_wake();
    } else if (!optional) {
	PyObject *t = PyObject_GetAttrString(cb, "__class__");
	PyObject *c = PyObject_GetAttrString(t, "__name__");
	const char *class = OI_PI_AsString(c);

	PyErr_Format(PyExc_RuntimeError,
		     "gensio callback: Class '%s' has no method '%s'\n",
		     class, method_name);
	swig_waiter_wake();
    }
    if (args)
	Py_DECREF(args);

    return o;
}

static void
gensio_do_vlog(struct gensio_os_funcs *o,
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

    po = swig_finish_call_rv(odata->log_handler, "gensio_log", args, false);
    if (po)
	Py_DECREF(po);
 out:
    OI_PY_STATE_PUT(gstate);
}

void
gensio_swig_setup_os_funcs(struct gensio_os_funcs *o,
			   swig_cb *log_handler)
{
    struct os_funcs_data *odata;

    odata = malloc(sizeof(*odata));
    assert(odata != NULL);
    odata->refcount = 1;
#ifdef USE_POSIX_THREADS
    pthread_mutex_init(&odata->lock, NULL);
#endif

    if (log_handler)
	odata->log_handler = gensio_python_ref_swig_cb_i(log_handler);
    else
	odata->log_handler = NULL;
    o->vlog = gensio_do_vlog;
    o->other_data = odata;
}

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

void
check_os_funcs_free(struct gensio_os_funcs *o)
{
    struct os_funcs_data *odata = o->other_data;

    os_funcs_lock(odata);
    if (--odata->refcount == 0) {
	os_funcs_unlock(odata);
	if (odata->log_handler)
	    gensio_python_deref_swig_cb_val(odata->log_handler);
#ifdef USE_POSIX_THREADS
	pthread_mutex_destroy(&odata->lock);
#endif
	free(odata);
	o->free_funcs(o);
    } else {
	os_funcs_unlock(odata);
    }
}

int
get_os_funcs_refcount(struct gensio_os_funcs *o)
{
    struct os_funcs_data *odata = o->other_data;

    return odata->refcount;
}
