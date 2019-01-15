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
