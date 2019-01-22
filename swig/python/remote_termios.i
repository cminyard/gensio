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

/*
 * Functions for accessing termios through the Linux serialsim device.
 */

%module remote_termios

%{
#include <string.h>
#include <termios.h>
#include <sgtty.h>
#include <signal.h>
#include <Python.h>

#include <gensio/gensio.h>

#include "remote_termios.h"

#if PY_VERSION_HEX >= 0x03000000
#define OI_PI_FromStringAndSize PyUnicode_FromStringAndSize
#define OI_PI_FromString PyUnicode_FromString
#else
#define OI_PI_FromStringAndSize PyString_FromStringAndSize
#define OI_PI_FromString PyString_FromString
#endif

static void err_handle(char *name, int rv)
{
    if (!rv)
	return;
    PyErr_Format(PyExc_Exception, "gensio:%s: %s", name, strerror(rv));
}

/*
 * Get remote termios.  For Python, this matches what the termios
 * module does.
 */
void get_remote_termios(struct gensio *io, void *termios) {
    int fd, rv;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = remote_termios(termios, fd);

    if (rv)
	err_handle("get_remote_termios", rv);
}

/*
 * Get remote RS485 config. This is string in the format:
 *  <delay rts before send> <delay rts after send> [options]
 * where options is (in the following order):
 *  enabled, rts_on_send, rts_after_send, rx_during_tx, terminate_bus
 */
char *get_remote_rs485(struct gensio *io) {
    int fd, rv;
    char *str = NULL;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = remote_rs485(fd, &str);

    if (rv)
	err_handle("get_remote_termios", rv);
    return str;
}

void set_remote_modem_ctl(struct gensio *io, unsigned int val) {
    int fd, rv;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = sremote_mctl(val, fd);

    if (rv)
	err_handle("set_remote_modem_ctl", rv);
}

unsigned int get_remote_modem_ctl(struct gensio *io) {
    int fd, rv;
    unsigned int val;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = gremote_mctl(&val, fd);

    if (rv)
	err_handle("get_remote_modem_ctl", rv);

    return val;
}

void set_remote_serial_err(struct gensio *io, unsigned int val) {
    int fd, rv;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = sremote_sererr(val, fd);

    if (rv)
	err_handle("set_remote_serial_err", rv);
}


unsigned int get_remote_serial_err(struct gensio *io) {
    int fd, rv;
    unsigned int val;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = gremote_sererr(&val, fd);

    if (rv)
	err_handle("get_remote_serial_err", rv);

    return val;
}

void set_remote_null_modem(struct gensio *io, bool val) {
    int fd, rv;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = sremote_null_modem(val, fd);

    if (rv)
	err_handle("set_remote_null_modem", rv);
}

bool get_remote_null_modem(struct gensio *io) {
    int fd, rv, val;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = gremote_null_modem(&val, fd);

    if (rv)
	err_handle("get_remote_null_modem", rv);

    return val;
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

%}

/*
 * For get/set modem control.  You cannot set DTR or RTS, they are
 * outputs from the other side.
 */
%constant int SERGENSIO_TIOCM_CAR = TIOCM_CAR;
%constant int SERGENSIO_TIOCM_CTS = TIOCM_CTS;
%constant int SERGENSIO_TIOCM_DSR = TIOCM_DSR;
%constant int SERGENSIO_TIOCM_RNG = TIOCM_RNG;
%constant int SERGENSIO_TIOCM_DTR = TIOCM_DTR;
%constant int SERGENSIO_TIOCM_RTS = TIOCM_RTS;

/* For remote errors.  These are the kernel numbers. */
%constant int SERGENSIO_TTY_BREAK = 1 << 1;
%constant int SERGENSIO_TTY_FRAME = 1 << 2;
%constant int SERGENSIO_TTY_PARITY = 1 << 3;
%constant int SERGENSIO_TTY_OVERRUN = 1 << 4;

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

/*
 * Get remote termios.  For Python, this matches what the termios
 * module does.
 */
void get_remote_termios(struct gensio *io, void *termios);

/*
 * Get remote RS485 config. This is string in the format:
 *  <delay rts before send> <delay rts after send> [options]
 * where options is (in the following order):
 *  enabled, rts_on_send, rts_after_send, rx_during_tx, terminate_bus
 */
%newobject get_remote_rs485;
char *get_remote_rs485(struct gensio *io);

void set_remote_modem_ctl(struct gensio *io, unsigned int val);
unsigned int get_remote_modem_ctl(struct gensio *io);

void set_remote_serial_err(struct gensio *io, unsigned int val);
unsigned int get_remote_serial_err(struct gensio *io);

void set_remote_null_modem(struct gensio *io, bool val);
bool get_remote_null_modem(struct gensio *io);
