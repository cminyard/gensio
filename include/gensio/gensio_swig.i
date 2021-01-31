/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifdef SWIGPYTHON
%typemap(in) swig_cb * {
    if ($input == Py_None)
	$1 = NULL;
    else
	$1 = $input;
}
#endif
