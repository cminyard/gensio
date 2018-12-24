/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.  These licenses are available
 *  in the root directory of this package named COPYING.LIB and
 *  COPYING.BSD, respectively.
 */

%typemap(in) swig_cb * {
    if ($input == Py_None)
	$1 = NULL;
    else
	$1 = $input;
}

%exception {
    $action
    if (PyErr_Occurred())
	SWIG_fail;
}

%typemap(in, numinputs=0) char **rbuffer (char *temp),
                          size_t *rbuffer_len (size_t temp) {
    $1 = &temp;
}

%typemap(argout) (char **rbuffer, size_t *rbuffer_len) {
    PyObject *r = OI_PI_FromStringAndSize(*$1, *$2);

    $result = add_python_result($result, r);
    free(*$1);
}

%typemap(in, numinputs=0) void *termios (struct termios temp) {
    $1 = &temp;
}

%typemap(argout) (void *termios) {
    struct termios *t = $1;
    PyObject *seq, *seq2, *o;
    int i;

    seq = PyTuple_New(7);
    o = PyInt_FromLong(t->c_iflag);
    PyTuple_SET_ITEM(seq, 0, o);
    o = PyInt_FromLong(t->c_oflag);
    PyTuple_SET_ITEM(seq, 1, o);
    o = PyInt_FromLong(t->c_cflag);
    PyTuple_SET_ITEM(seq, 2, o);
    o = PyInt_FromLong(t->c_lflag);
    PyTuple_SET_ITEM(seq, 3, o);
    o = PyInt_FromLong(cfgetispeed(t));
    PyTuple_SET_ITEM(seq, 4, o);
    o = PyInt_FromLong(cfgetospeed(t));
    PyTuple_SET_ITEM(seq, 5, o);

    seq2 = PyTuple_New(sizeof(t->c_cc));
    for (i = 0; i < sizeof(t->c_cc); i++) {
	if (i == VTIME || i == VMIN) {
	    PyTuple_SET_ITEM(seq2, i, PyInt_FromLong(t->c_cc[i]));
	} else {
	    char c[1] = { t->c_cc[i] };

	    PyTuple_SET_ITEM(seq2, i, OI_PI_FromStringAndSize(c, 1));
	}
    }
    PyTuple_SET_ITEM(seq, 6, seq2);
    $result = add_python_result($result, seq);
}

%typemap(in) const char *const *auxdata {
    unsigned int i;
    unsigned int len;
    char **temp = NULL;

    if ($input == Py_None)
	goto null_auxdata;
    if (!PySequence_Check($input)) {
	PyErr_SetString(PyExc_TypeError, "Expecting a sequence");
	SWIG_fail;
    }
    len = PyObject_Length($input);
    if (len == 0)
	goto null_auxdata;

    temp = malloc(sizeof(char *) * (len + 1));
    if (!temp) {
	PyErr_SetString(PyExc_ValueError, "Out of memory");
	SWIG_fail;
    }
    memset(temp, 0, sizeof(char *) * (len + 1));
    for (i = 0; i < len; i++) {
	PyObject *o = PySequence_GetItem($input, i);

	if (!PyString_Check(o)) {
	    Py_XDECREF(o);
	    PyErr_SetString(PyExc_ValueError,
			    "Expecting a sequence of strings");
	    SWIG_fail;
	}
	temp[i] = PyString_AsString(o);
	Py_DECREF(o);
    }
 null_auxdata:
    $1 = temp;
}

%typemap(freearg) auxdata {
    unsigned int i;

    for (i = 0; $1->val[i]; i++) {
	free($1->val[i]);
    }
    free($1->val);
};
