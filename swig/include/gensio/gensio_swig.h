/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * This is for writing os handlers to integrate with the gensio
 * swig-generated code.  It's designed to be included in swig code,
 * it's not stand-alone.
 */

#include <gensio/gensio_dllvisibility.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef SWIGPYTHON
typedef PyObject swig_cb;
#endif

GENSIO_DLL_PUBLIC
int gensio_swig_setup_os_funcs(struct gensio_os_funcs *o,
			       swig_cb *log_handler);

GENSIO_DLL_PUBLIC
void check_os_funcs_free(struct gensio_os_funcs *o);

GENSIO_DLL_PUBLIC
int get_os_funcs_refcount(struct gensio_os_funcs *o);

#ifdef __cplusplus
}
#endif
