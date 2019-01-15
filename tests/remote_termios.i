
%module remote_termios

%{
#include <string.h>
#include <termios.h>
#include <sgtty.h>
#include <signal.h>

#include <gensio/gensio.h>

#include "remote_termios.h"

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
	rv = set_remote_mctl(val, fd);

    if (rv)
	err_handle("set_remote_modem_ctl", rv);
}

unsigned int get_remote_modem_ctl(struct gensio *io) {
    int fd, rv;
    unsigned int val;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = get_remote_mctl(&val, fd);

    if (rv)
	err_handle("get_remote_modem_ctl", rv);

    return val;
}

void set_remote_serial_err(struct gensio *io, unsigned int val) {
    int fd, rv;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = set_remote_sererr(val, fd);

    if (rv)
	err_handle("set_remote_serial_err", rv);
}


unsigned int get_remote_serial_err(struct gensio *io) {
    int fd, rv;
    unsigned int val;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = get_remote_sererr(&val, fd);

    if (rv)
	err_handle("get_remote_serial_err", rv);

    return val;
}

void set_remote_null_modem(struct gensio *io, bool val) {
    int fd, rv;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = set_remote_null_modem(val, fd);

    if (rv)
	err_handle("set_remote_null_modem", rv);
}

bool get_remote_null_modem(struct gensio *io) {
    int fd, rv, val;

    rv = gensio_remote_id(io, &fd);
    if (!rv)
	rv = get_remote_null_modem(&val, fd);

    if (rv)
	err_handle("get_remote_null_modem", rv);

    return val;
}
