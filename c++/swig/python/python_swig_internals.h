/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Things I had to split out into their own library so that other os
 * handlers could get to the functions they need to interact with
 * python.
 *
 * This is not a general purpose header, it is designed to be included
 * only in certain places.
 */

typedef PyObject swig_cb_val;

#if PYTHON_HAS_THREADS
#ifdef _WIN32
#include <processthreadsapi.h>
#define USE_WIN32_THREADS
#else
#include <pthread.h>
#define USE_POSIX_THREADS
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct os_funcs_data {
#ifdef USE_POSIX_THREADS
    pthread_mutex_t lock;
#endif
    unsigned int refcount;
    swig_cb_val *log_handler;
};

#define OI_PY_STATE PyGILState_STATE
#define OI_PY_STATE_GET() PyGILState_Ensure()
#define OI_PY_STATE_PUT(s) PyGILState_Release(s)

GENSIO_DLL_PUBLIC
swig_cb_val *gensio_python_ref_swig_cb_i(swig_cb *cb);

GENSIO_DLL_PUBLIC
swig_cb_val *gensio_python_deref_swig_cb_val(swig_cb_val *cb);

#if PY_VERSION_HEX >= 0x03000000
#define OI_PI_FromString PyUnicode_FromString
#define OI_PI_AsString PyUnicode_AsUTF8
#else
#define OI_PI_FromString PyString_FromString
#define OI_PI_AsString PyString_AsString
#endif

GENSIO_DLL_PUBLIC
PyObject *swig_finish_call_rv(swig_cb_val *cb, const char *method_name,
			      PyObject *args, bool optional);

GENSIO_DLL_PUBLIC
extern void (*swig_waiter_wake)(void);

#ifdef __cplusplus
}
#endif
