/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdbool.h>
#if HAVE_DECL_TIOCSRS485
#include <linux/serial.h>
#endif

#ifdef HAVE_TERMIOS2
/*
 * termios2 allows the setting of custom serial port speeds.
 *
 * There is unfortunate complexity with handling termios2 on Linux.
 * You cannot include asm/termios.h and termios.h or sys/ioctl.h at
 * the same time.  So that means a lot of stuff has to be be handled
 * by hand, not with the tcxxx() functions.  The standard tcxxx()
 * function do not use the termios2 ioctls when talking to the
 * kernel (at the current time).  It's kind of a mess.
 */
#include <asm/termios.h>
int ioctl(int fd, int op, ...);

typedef struct termios2 g_termios;

static int
set_termios(int fd, struct termios2 *t)
{
    return ioctl(fd, TCSETS2, t);
}

static int
get_termios(int fd, struct termios2 *t)
{
    return ioctl(fd, TCGETS2, t);
}

static int
set_flowcontrol(int fd, bool val)
{
    return ioctl(fd, TCXONC, val ? TCOOFF : TCOON);
}

static int
do_flush(int fd, int val)
{
    return ioctl(fd, TCFLSH, val);
}

static void
do_break(int fd)
{
    ioctl(fd, TCSBRK, 0);
}

#else

#include <sys/ioctl.h>
#include <termios.h>

typedef struct termios g_termios;

static int
set_termios(int fd, struct termios *t)
{
    return tcsetattr(fd, TCSANOW, t);
}

static int
get_termios(int fd, struct termios *t)
{
    return tcgetattr(fd, t);
}

static int
set_flowcontrol(int fd, bool val)
{
    return tcflow(fd, val ? TCOOFF : TCOON);
}

static int
do_flush(int fd, int val)
{
    return tcflush(fd, val);
}

static void
do_break(int fd)
{
    tcsendbreak(fd, 0);
}

#endif

#include <gensio/sergensio_class.h>
#include <gensio/gensio_ll_fd.h>
#include <gensio/gensio_builtins.h>
#include <gensio/gensio_osops.h>

#include "uucplock.h"
#include "utils.h"

static struct baud_rates_s {
    int real_rate;
    int val;
} baud_rates[] =
{
    { 50, B50 },
    { 75, B75 },
    { 110, B110 },
    { 134, B134 },
    { 150, B150 },
    { 200, B200 },
    { 300, B300 },
    { 600, B600 },
    { 1200, B1200 },
    { 1800, B1800 },
    { 2400, B2400 },
    { 4800, B4800 },
    { 9600, B9600 },
    /* We don't support 14400 baud */
    { 19200, B19200 },
    /* We don't support 28800 baud */
    { 38400, B38400 },
    { 57600, B57600 },
    { 115200, B115200 },
#ifdef B230400
    { 230400, B230400 },
#endif
#ifdef B460800
    { 460800, B460800 },
#endif
#ifdef B500000
    { 500000, B500000 },
#endif
#ifdef B576000
    { 576000, B576000 },
#endif
#ifdef B921600
    { 921600, B921600 },
#endif
#ifdef B1000000
    { 1000000, B1000000 },
#endif
#ifdef B1152000
    { 1152000, B1152000 },
#endif
#ifdef B1500000
    { 1500000, B1500000 },
#endif
#ifdef B2000000
    { 2000000, B2000000 },
#endif
#ifdef B2500000
    { 2500000, B2500000 },
#endif
#ifdef B3000000
    { 3000000, B3000000 },
#endif
#ifdef B3500000
    { 3500000, B3500000 },
#endif
#ifdef B4000000
    { 4000000, B4000000 },
#endif
};
#define BAUD_RATES_LEN ((sizeof(baud_rates) / sizeof(struct baud_rates_s)))

static int
set_baud_rate(g_termios *t, int rate, bool custspeed)
{
    unsigned int i;

    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (rate == baud_rates[i].real_rate) {
#ifdef HAVE_TERMIOS2
	    t->c_cflag &= ~CBAUD;
	    t->c_cflag |= baud_rates[i].val;
	    t->c_ispeed = rate;
	    t->c_ospeed = rate;
#else
	    cfsetispeed(t, baud_rates[i].val);
	    cfsetospeed(t, baud_rates[i].val);
#endif
	    return 1;
	}
    }

#ifdef HAVE_TERMIOS2
    if (custspeed) {
	t->c_cflag &= ~CBAUD;
	t->c_cflag |= CBAUDEX;
	t->c_ispeed = rate;
	t->c_ospeed = rate;
	return 1;
    }
#endif

    return 0;
}

static int
get_baud_rate_val(g_termios *t)
{
    unsigned int i;
    int baud_rate;

#ifdef HAVE_TERMIOS2
    if ((t->c_cflag & CBAUD) == CBAUDEX)
	return t->c_ospeed;
    baud_rate = t->c_cflag & CBAUD;
#else
    baud_rate = cfgetospeed(t);
#endif

    for (i = 0; i < BAUD_RATES_LEN; i++) {
	if (baud_rate == baud_rates[i].val)
	    return baud_rates[i].real_rate;
    }

    return 0;
}

static void
get_rate_from_baud_rate(g_termios *t, int *val)
{
    *val = get_baud_rate_val(t);
}

static int
speedstr_to_speed(const char *speed, const char **rest)
{
    const char *end = speed;
    unsigned int len;
    int rv;

    while (*end && isdigit(*end))
	end++;
    len = end - speed;
    if (len < 1)
	return -1;

    rv = strtoul(speed, NULL, 10);
    *rest = end;

    return rv;
}

static void
set_termios_parity(g_termios *termctl, int val)
{
    switch (val) {
    default:
    case 'N': case 'n':
	termctl->c_cflag &= ~(PARENB);
	break;
    case 'E': case 'e':
    case 'S': case 's':
	termctl->c_cflag |= PARENB;
	termctl->c_cflag &= ~(PARODD);
#ifdef CMSPAR
	if (val == 'S' || val == 's')
	    termctl->c_cflag |= CMSPAR;
#endif
	break;
    case 'O': case 'o':
    case 'M': case 'm':
	termctl->c_cflag |= PARENB | PARODD;
#ifdef CMSPAR
	if (val == 'M' || val == 'm')
	    termctl->c_cflag |= CMSPAR;
#endif
	break;
    }
}


struct penum_val { char *str; int val; };
static struct penum_val parity_enums[] = {
    { "NONE", 'N' },
    { "EVEN", 'E' },
    { "ODD", 'O' },
    { "none", 'N' },
    { "even", 'E' },
    { "odd", 'O' },
    { "MARK", 'M' },
    { "SPACE", 'S' },
    { "mark", 'M' },
    { "space", 'S' },
    { NULL }
};

static int
lookup_parity_str(const char *str)
{
    unsigned int i;

    for (i = 0; parity_enums[i].str; i++) {
	if (strcmp(parity_enums[i].str, str) == 0)
	    return parity_enums[i].val;
    }
    return -1;
}

static void
set_termios_xonxoff(g_termios *termctl, int enabled)
{
    if (enabled) {
	termctl->c_iflag |= (IXON | IXOFF | IXANY);
	termctl->c_cc[VSTART] = 17;
	termctl->c_cc[VSTOP] = 19;
    } else {
	termctl->c_iflag &= ~(IXON | IXOFF | IXANY);
    }
}

static void
set_termios_rtscts(g_termios *termctl, int enabled)
{
    if (enabled)
	termctl->c_cflag |= CRTSCTS;
    else
	termctl->c_cflag &= ~CRTSCTS;
}

static void
set_termios_datasize(g_termios *termctl, int size)
{
    termctl->c_cflag &= ~CSIZE;
    switch (size) {
    case 5: termctl->c_cflag |= CS5; break;
    case 6: termctl->c_cflag |= CS6; break;
    case 7: termctl->c_cflag |= CS7; break;
    default: case 8: termctl->c_cflag |= CS8; break;
    }
}

static int
set_termios_from_speed(g_termios *termctl, int speed, const char *others,
		       bool custspeed)
{
    if (!set_baud_rate(termctl, speed, custspeed))
	return -1;

    if (*others) {
	switch (*others) {
	case 'N': case 'n':
	case 'E': case 'e':
	case 'O': case 'o':
	case 'M': case 'm':
	case 'S': case 's':
	    break;
	default:
	    return -1;
	}
	set_termios_parity(termctl, *others);
	others++;
    }

    if (*others) {
	int val;

	switch (*others) {
	case '5': val = 5; break;
	case '6': val = 6; break;
	case '7': val = 7; break;
	case '8': val = 8; break;
	default:
	    return -1;
	}
	set_termios_datasize(termctl, val);
	others++;
    }

    if (*others) {
	switch (*others) {
	case '1':
	    termctl->c_cflag &= ~(CSTOPB);
	    break;

	case '2':
	    termctl->c_cflag |= CSTOPB;
	    break;

	default:
	    return -1;
	}
	others++;
    }

    if (*others)
	return -1;

    return 0;
}

enum termio_op {
    TERMIO_OP_TERMIO,
    TERMIO_OP_MCTL,
    TERMIO_OP_BRK
};

struct sterm_data;

struct termio_op_q {
    enum termio_op op;
    int (*getset)(g_termios *termio, int *mctl, int *val, struct sterm_data *);
    void (*done)(struct sergensio *sio, int err, int val, void *cb_data);
    void *cb_data;
    struct termio_op_q *next;
};

struct sterm_data {
    struct sergensio *sio;
    struct gensio_os_funcs *o;

    struct gensio_lock *lock;

    struct gensio_timer *timer;
    bool timer_stopped;

    bool open;
    unsigned int close_timeouts_left;
    int last_close_outq_count;

    char *devname;
    char *parms;

    int fd;
    struct gensio_ll *ll;

    /*
     * Unfortunately, at least on Linux, ptys return EIO errors when
     * the remote end closes, instead of something sensible like
     * EPIPE, like all other IPC does.  So we have to have special
     * handling to detect ptys.  We still want to return GE_IOERR
     * on IO errors for real devices.
     */
    bool is_pty;

    bool write_only;		/* No termios, no read. */

    bool no_uucp_lock;

    bool allow_custspeed;

    g_termios default_termios;
    g_termios orig_termios;

    bool deferred_op_pending;
    struct gensio_runner *deferred_op_runner;
    struct termio_op_q *termio_q;
    bool break_set;
    bool disablebreak;
    unsigned int last_modemstate;
    unsigned int modemstate_mask;
    bool handling_modemstate;
    bool sent_first_modemstate;

#if HAVE_DECL_TIOCSRS485
    struct serial_rs485 rs485;
#endif
};

static void termios_process(struct sterm_data *sdata);

static void
sterm_lock(struct sterm_data *sdata)
{
    sdata->o->lock(sdata->lock);
}

static void
sterm_unlock(struct sterm_data *sdata)
{
    sdata->o->unlock(sdata->lock);
}

static void
sterm_deferred_op(struct gensio_runner *runner, void *cbdata)
{
    struct sterm_data *sdata = cbdata;

    sterm_lock(sdata);
 restart:
    termios_process(sdata);

    if (sdata->termio_q)
	/* Something was added, process it. */
	goto restart;

    sdata->deferred_op_pending = false;
    sterm_unlock(sdata);
}

static void
sterm_start_deferred_op(struct sterm_data *sdata)
{
    if (!sdata->deferred_op_pending) {
	sdata->deferred_op_pending = true;
	sdata->o->run(sdata->deferred_op_runner);
    }
}

static void
termios_process(struct sterm_data *sdata)
{
    while (sdata->termio_q) {
	struct termio_op_q *qe = sdata->termio_q;
	int val = 0, err = 0;

	sdata->termio_q = qe->next;

	if (qe->op == TERMIO_OP_TERMIO) {
	    g_termios termio;

	    if (get_termios(sdata->fd, &termio) == -1)
		err = gensio_os_err_to_err(sdata->o, errno);
	    else
		err = qe->getset(&termio, NULL, &val, sdata);
	} else if (qe->op == TERMIO_OP_MCTL) {
	    int mctl = 0;

	    if (ioctl(sdata->fd, TIOCMGET, &mctl) == -1)
		err = gensio_os_err_to_err(sdata->o, errno);
	    else
		err = qe->getset(NULL, &mctl, &val, sdata);
	} else if (qe->op == TERMIO_OP_BRK) {
	    if (sdata->break_set)
		val = SERGENSIO_BREAK_ON;
	    else
		val = SERGENSIO_BREAK_OFF;
	}

	sterm_unlock(sdata);
	qe->done(sdata->sio, err, val, qe->cb_data);
	sdata->o->free(sdata->o, qe);
	sterm_lock(sdata);
    }
}

static void
termios_clear_q(struct sterm_data *sdata)
{
    while (sdata->termio_q) {
	struct termio_op_q *qe = sdata->termio_q;

	sdata->termio_q = qe->next;
	sdata->o->free(sdata->o, qe);
    }
}

static int
termios_set_get(struct sterm_data *sdata, int val, enum termio_op op,
		int (*getset)(g_termios *termio, int *mctl, int *val,
			      struct sterm_data *sdata),
		void (*done)(struct sergensio *sio, int err,
			     int val, void *cb_data),
		void *cb_data)
{
    g_termios termio;
    struct termio_op_q *qe = NULL;
    int err = 0;

    if (sdata->write_only)
	return GE_NOTSUP;

    if (done) {
	qe = sdata->o->zalloc(sdata->o, sizeof(*qe));
	if (!qe)
	    return GE_NOMEM;
	qe->getset = getset;
	qe->done = done;
	qe->cb_data = cb_data;
	qe->op = op;
	qe->next = NULL;
    }

    sterm_lock(sdata);
    if (!sdata->open) {
	err = GE_NOTREADY;
	goto out_unlock;
    }

    if (val) {
	if (op == TERMIO_OP_TERMIO) {
	    if (get_termios(sdata->fd, &termio) == -1) {
		err = errno;
		goto out_unlock;
	    }

	    err = getset(&termio, NULL, &val, sdata);
	    if (err)
		goto out_unlock;
	    set_termios(sdata->fd, &termio);
	} else if (op == TERMIO_OP_MCTL) {
	    int mctl = 0;

	    if (ioctl(sdata->fd, TIOCMGET, &mctl) == -1) {
		err = errno;
	    } else {
		err = getset(NULL, &mctl, &val, sdata);
		if (!err) {
		    if (ioctl(sdata->fd, TIOCMSET, &mctl) == -1)
			err = errno;
		}
	    }
	    if (err)
		goto out_unlock;
	} else if (op == TERMIO_OP_BRK) {
	    int iocval;
	    bool bval;

	    if (val == SERGENSIO_BREAK_ON) {
		iocval = TIOCSBRK;
		bval = true;
	    } else if (val == SERGENSIO_BREAK_OFF) {
		iocval = TIOCCBRK;
		bval = false;
	    } else {
		err = GE_INVAL;
		goto out_unlock;
	    }
	    if (ioctl(sdata->fd, iocval) == -1) {
		err = errno;
		goto out_unlock;
	    }
	    sdata->break_set = bval;
	} else {
	    err = GE_INVAL;
	    goto out_unlock;
	}
    }

    if (qe) {
	if (!sdata->termio_q) {
	    sdata->termio_q = qe;
	    sterm_start_deferred_op(sdata);
	} else {
	    struct termio_op_q *curr = sdata->termio_q;

	    while (curr->next)
		curr = curr->next;
	    curr->next = qe;
	}
    }
 out_unlock:
    if (err && qe)
	sdata->o->free(sdata->o, qe);
    sterm_unlock(sdata);
    return err;
}

static int
termios_get_set_baud(g_termios *termio, int *mctl, int *ival,
		     struct sterm_data *sdata)
{
    int val = *ival;

    if (val) {
	if (!set_baud_rate(termio, val, sdata->allow_custspeed))
	    return GE_INVAL;
    } else {
	get_rate_from_baud_rate(termio, ival);
    }

    return 0;
}

static int
sterm_baud(struct sergensio *sio, int baud,
	   void (*done)(struct sergensio *sio, int err,
			int baud, void *cb_data),
	   void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), baud,
			   TERMIO_OP_TERMIO,
			   termios_get_set_baud, done, cb_data);
}

static int
termios_get_set_datasize(g_termios *termio, int *mctl, int *ival,
			 struct sterm_data *sdata)
{
    if (*ival) {
	int val;

	switch (*ival) {
	case 5: val = CS5; break;
	case 6: val = CS6; break;
	case 7: val = CS7; break;
	case 8: val = CS8; break;
	default:
	    return GE_INVAL;
	}
	termio->c_cflag &= ~CSIZE;
	termio->c_cflag |= val;
    } else {
	switch (termio->c_cflag & CSIZE) {
	case CS5: *ival = 5; break;
	case CS6: *ival = 6; break;
	case CS7: *ival = 7; break;
	case CS8: *ival = 8; break;
	default:
	    return GE_INVAL;
	}
    }
    return 0;
}

static int
sterm_datasize(struct sergensio *sio, int datasize,
	       void (*done)(struct sergensio *sio, int err, int datasize,
			    void *cb_data),
	       void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), datasize,
			   TERMIO_OP_TERMIO,
			   termios_get_set_datasize, done, cb_data);
}

static int
termios_get_set_parity(g_termios *termio, int *mctl, int *ival,
		       struct sterm_data *sdata)
{
    if (*ival) {
	int val;

	switch(*ival) {
	case SERGENSIO_PARITY_NONE: val = 0; break;
	case SERGENSIO_PARITY_ODD: val = PARENB | PARODD; break;
	case SERGENSIO_PARITY_EVEN: val = PARENB; break;
#ifdef CMSPAR
	case SERGENSIO_PARITY_MARK: val = PARENB | PARODD | CMSPAR; break;
	case SERGENSIO_PARITY_SPACE: val = PARENB | CMSPAR; break;
#endif
	default:
	    return GE_INVAL;
	}
	termio->c_cflag &= ~(PARENB | PARODD);
#ifdef CMSPAR
	termio->c_cflag &= ~CMSPAR;
#endif
	termio->c_cflag |= val;
    } else {
	if (!(termio->c_cflag & PARENB)) {
	    *ival = SERGENSIO_PARITY_NONE;
	} else if (termio->c_cflag & PARODD) {
#ifdef CMSPAR
	    if (termio->c_cflag & CMSPAR)
		*ival = SERGENSIO_PARITY_MARK;
	    else
#endif
		*ival = SERGENSIO_PARITY_ODD;
	} else {
#ifdef CMSPAR
	    if (termio->c_cflag & CMSPAR)
		*ival = SERGENSIO_PARITY_SPACE;
	    else
#endif
		*ival = SERGENSIO_PARITY_EVEN;
	}
    }

    return 0;
}

static int
sterm_parity(struct sergensio *sio, int parity,
	     void (*done)(struct sergensio *sio, int err, int parity,
			  void *cb_data),
	     void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), parity,
			   TERMIO_OP_TERMIO,
			   termios_get_set_parity, done, cb_data);
}

static int
termios_get_set_stopbits(g_termios *termio, int *mctl, int *ival,
			 struct sterm_data *sdata)
{
    if (*ival) {
	if (*ival == 1)
	    termio->c_cflag &= ~CSTOPB;
	else if (*ival == 2)
	    termio->c_cflag |= CSTOPB;
	else
	    return GE_INVAL;
    } else {
	if (termio->c_cflag & CSTOPB)
	    *ival = 2;
	else
	    *ival = 1;
    }

    return 0;
}

static int
sterm_stopbits(struct sergensio *sio, int stopbits,
	       void (*done)(struct sergensio *sio, int err, int stopbits,
			    void *cb_data),
	       void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), stopbits,
			   TERMIO_OP_TERMIO,
			   termios_get_set_stopbits, done, cb_data);
}

static int
termios_get_set_flowcontrol(g_termios *termio, int *mctl, int *ival,
			    struct sterm_data *sdata)
{
    if (*ival) {
        switch (*ival) {
        case SERGENSIO_FLOWCONTROL_NONE:
                termio->c_iflag &= ~(IXON | IXOFF);
                termio->c_cflag &= ~(CRTSCTS);
                break;
        case SERGENSIO_FLOWCONTROL_XON_XOFF:
                termio->c_iflag |= (IXON | IXOFF);
                termio->c_cflag &= ~(CRTSCTS);
                break;
        case SERGENSIO_FLOWCONTROL_RTS_CTS:
                termio->c_iflag &= ~(IXON | IXOFF);
                termio->c_cflag |= (CRTSCTS);
                break;
        default:
            return GE_INVAL;
        }

    } else {
	if (termio->c_cflag & CRTSCTS)
	    *ival = SERGENSIO_FLOWCONTROL_RTS_CTS;
	else if (termio->c_iflag & (IXON | IXOFF))
	    *ival = SERGENSIO_FLOWCONTROL_XON_XOFF;
	else
	    *ival = SERGENSIO_FLOWCONTROL_NONE;
    }

    return 0;
}

static int
termios_get_set_iflowcontrol(g_termios *termio, int *mctl, int *ival,
			     struct sterm_data *sdata)
{
    if (*ival) {
	int val;

	/* We can only independently set XON/XOFF. */
	switch (*ival) {
	case SERGENSIO_FLOWCONTROL_NONE: val = 0; break;
	case SERGENSIO_FLOWCONTROL_XON_XOFF: val = IXOFF; break;
	default:
	    return GE_INVAL;
	}
	termio->c_iflag &= ~IXOFF;
	termio->c_iflag |= val;
    } else {
	if (termio->c_iflag & IXOFF)
	    *ival = SERGENSIO_FLOWCONTROL_XON_XOFF;
	else
	    *ival = SERGENSIO_FLOWCONTROL_NONE;
    }

    return 0;
}

static int
sterm_flowcontrol(struct sergensio *sio, int flowcontrol,
		  void (*done)(struct sergensio *sio, int err,
			       int flowcontrol, void *cb_data),
		  void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), flowcontrol,
			   TERMIO_OP_TERMIO,
			   termios_get_set_flowcontrol, done, cb_data);
}

static int
sterm_iflowcontrol(struct sergensio *sio, int iflowcontrol,
		   void (*done)(struct sergensio *sio, int err,
				int iflowcontrol, void *cb_data),
		   void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), iflowcontrol,
			   TERMIO_OP_TERMIO,
			   termios_get_set_iflowcontrol, done, cb_data);
}

static int
sterm_sbreak(struct sergensio *sio, int breakv,
	     void (*done)(struct sergensio *sio, int err, int breakv,
			  void *cb_data),
	     void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), breakv,
			   TERMIO_OP_BRK,
			   NULL, done, cb_data);
}

static int
termios_get_set_dtr(g_termios *termio, int *mctl, int *ival,
		    struct sterm_data *sdata)
{
    if (*ival) {
	if (*ival == SERGENSIO_DTR_ON)
	    *mctl |= TIOCM_DTR;
	else if (*ival == SERGENSIO_DTR_OFF)
	    *mctl &= ~TIOCM_DTR;
	else
	    return GE_INVAL;
    } else {
	if (*mctl & TIOCM_DTR)
	    *ival = SERGENSIO_DTR_ON;
	else
	    *ival = SERGENSIO_DTR_OFF;
    }

    return 0;
}

static int
sterm_dtr(struct sergensio *sio, int dtr,
	  void (*done)(struct sergensio *sio, int err, int dtr,
		       void *cb_data),
	  void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), dtr, TERMIO_OP_MCTL,
			   termios_get_set_dtr, done, cb_data);
}

static int
termios_get_set_rts(g_termios *termio, int *mctl, int *ival,
		    struct sterm_data *sdata)
{
    if (*ival) {
	if (*ival == SERGENSIO_RTS_ON)
	    *mctl |= TIOCM_RTS;
	else if (*ival == SERGENSIO_RTS_OFF)
	    *mctl &= ~TIOCM_RTS;
	else
	    return GE_INVAL;
    } else {
	if (*mctl & TIOCM_RTS)
	    *ival = SERGENSIO_RTS_ON;
	else
	    *ival = SERGENSIO_RTS_OFF;
    }

    return 0;
}

static int
sterm_rts(struct sergensio *sio, int rts,
	  void (*done)(struct sergensio *sio, int err, int rts,
		       void *cb_data),
	  void *cb_data)
{
    return termios_set_get(sergensio_get_gensio_data(sio), rts, TERMIO_OP_MCTL,
			   termios_get_set_rts, done, cb_data);
}

static void
serialdev_timeout(struct gensio_timer *t, void *cb_data)
{
    struct sterm_data *sdata = cb_data;
    int val, rv;
    unsigned int modemstate = 0;
    bool force_send;

    sterm_lock(sdata);
    if (sdata->handling_modemstate) {
	sterm_unlock(sdata);
	return;
    }
    sdata->handling_modemstate = true;
    sterm_unlock(sdata);

    rv = ioctl(sdata->fd, TIOCMGET, &val);
    if (rv)
	goto out_restart;

    if (val & TIOCM_CD)
	modemstate |= SERGENSIO_MODEMSTATE_CD;
    if (val & TIOCM_RI)
	modemstate |= SERGENSIO_MODEMSTATE_RI;
    if (val & TIOCM_DSR)
	modemstate |= SERGENSIO_MODEMSTATE_DSR;
    if (val & TIOCM_CTS)
	modemstate |= SERGENSIO_MODEMSTATE_CTS;

    sterm_lock(sdata);
    /* Bits for things that changed. */
    modemstate |= (modemstate ^ sdata->last_modemstate) >> 4;
    sdata->last_modemstate = modemstate & sdata->modemstate_mask;
    modemstate &= sdata->last_modemstate;
    force_send = !sdata->sent_first_modemstate;
    sdata->sent_first_modemstate = true;
    sterm_unlock(sdata);

    /*
     * The bottom 4 buts of modemstate is the "changed" bits, only
     * report this if someing changed that was in the mask.
     */
    if ((force_send || modemstate & 0xf)) {
	struct gensio *io = sergensio_get_my_gensio(sdata->sio);
	gensiods vlen = sizeof(modemstate);

	gensio_cb(io, GENSIO_EVENT_SER_MODEMSTATE, 0,
		  (unsigned char *) &modemstate, &vlen, NULL);
    }

 out_restart:
    if (sdata->modemstate_mask) {
	gensio_time timeout = {1, 0};

	sdata->o->start_timer(sdata->timer, &timeout);
    }

    sterm_lock(sdata);
    sdata->handling_modemstate = false;
    sterm_unlock(sdata);
}

static int
sterm_modemstate(struct sergensio *sio, unsigned int val)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);
    gensio_time timeout = {0, 0};

    sterm_lock(sdata);
    sdata->modemstate_mask = val;
    sdata->sent_first_modemstate = false;
    sterm_unlock(sdata);

    /* Cause an immediate send of the modemstate. */
    sdata->o->stop_timer(sdata->timer);
    sdata->o->start_timer(sdata->timer, &timeout);
    return 0;
}

static int
sterm_flowcontrol_state(struct sergensio *sio, bool val)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);
    int err;

    err = set_flowcontrol(sdata->fd, val);
    if (err)
	return errno;
    return 0;
}

static int
sterm_flush(struct sergensio *sio, unsigned int val)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);
    int err;
    int tval;

    switch(val) {
    case SERGIO_FLUSH_RCV_BUFFER:	tval = TCIFLUSH; break;
    case SERGIO_FLUSH_XMIT_BUFFER:	tval = TCOFLUSH; break;
    case SERGIO_FLUSH_RCV_XMIT_BUFFERS:	tval = TCIOFLUSH; break;
    default: return GE_INVAL;
    }

    err = do_flush(sdata->fd, tval);
    if (err)
	return errno;
    return 0;
}

static int
sterm_send_break(struct sergensio *sio)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);

    do_break(sdata->fd);
    return 0;
}

static int
sergensio_sterm_func(struct sergensio *sio, int op, int val, char *buf,
		     void *done, void *cb_data)
{
    struct sterm_data *sdata = sergensio_get_gensio_data(sio);

    if (sdata->write_only)
	return GE_NOTSUP;

    switch (op) {
    case SERGENSIO_FUNC_BAUD:
	return sterm_baud(sio, val, done, cb_data);

    case SERGENSIO_FUNC_DATASIZE:
	return sterm_datasize(sio, val, done, cb_data);

    case SERGENSIO_FUNC_PARITY:
	return sterm_parity(sio, val, done, cb_data);

    case SERGENSIO_FUNC_STOPBITS:
	return sterm_stopbits(sio, val, done, cb_data);

    case SERGENSIO_FUNC_FLOWCONTROL:
	return sterm_flowcontrol(sio, val, done, cb_data);

    case SERGENSIO_FUNC_IFLOWCONTROL:
	return sterm_iflowcontrol(sio, val, done, cb_data);

    case SERGENSIO_FUNC_SBREAK:
	return sterm_sbreak(sio, val, done, cb_data);

    case SERGENSIO_FUNC_DTR:
	return sterm_dtr(sio, val, done, cb_data);

    case SERGENSIO_FUNC_RTS:
	return sterm_rts(sio, val, done, cb_data);

    case SERGENSIO_FUNC_MODEMSTATE:
	return sterm_modemstate(sio, val);

    case SERGENSIO_FUNC_FLOWCONTROL_STATE:
	return sterm_flowcontrol_state(sio, val);

    case SERGENSIO_FUNC_FLUSH:
	return sterm_flush(sio, val);

    case SERGENSIO_FUNC_SEND_BREAK:
	return sterm_send_break(sio);

    case SERGENSIO_FUNC_SIGNATURE:
    case SERGENSIO_FUNC_LINESTATE:
    default:
	return GE_NOTSUP;
    }
}

static void
sterm_timer_stopped(struct gensio_timer *timer, void *cb_data)
{
    struct sterm_data *sdata = cb_data;

    sdata->timer_stopped = true;
}

static int
sterm_check_close_drain(void *handler_data, enum gensio_ll_close_state state,
			gensio_time *next_timeout)
{
    struct sterm_data *sdata = handler_data;
    int rv, count = 0, err = 0;

    sterm_lock(sdata);
    if (state == GENSIO_LL_CLOSE_STATE_START) {
	sdata->open = false;
	rv = sdata->o->stop_timer_with_done(sdata->timer,
					    sterm_timer_stopped, sdata);
	if (rv)
	    sdata->timer_stopped = true;

	sdata->last_close_outq_count = 0;
    }

    if (state != GENSIO_LL_CLOSE_STATE_DONE)
	goto out_unlock;

    sdata->open = false;
    if (sdata->termio_q)
	goto out_einprogress;

    if (!sdata->timer_stopped)
	goto out_einprogress;

    rv = ioctl(sdata->fd, TIOCOUTQ, &count);
    if (rv || count <= 0)
	goto out_rm_uucp;
    if (sdata->last_close_outq_count == 0 ||
		count < sdata->last_close_outq_count) {
	/* First time through or some data was written, restart the timer. */
	sdata->last_close_outq_count = count;
	/*
	 * FIXME - this should be calculated, but 50 baud is 4-5 chars
	 * per second, so 1/2 a second should be plenty.
	 */
	sdata->close_timeouts_left = 50;
    }

    sdata->close_timeouts_left--;
    if (sdata->close_timeouts_left == 0)
	goto out_rm_uucp;

 out_einprogress:
    err = GE_INPROGRESS;
    next_timeout->secs = 0;
    next_timeout->nsecs = 10000000;
 out_rm_uucp:
    if (!err) {
	do_flush(sdata->fd, TCOFLUSH);
	set_termios(sdata->fd, &sdata->orig_termios);
	if (!sdata->no_uucp_lock)
	    uucp_rm_lock(sdata->devname);
    }
 out_unlock:
    sterm_unlock(sdata);
    return err;
}

#if !defined(HAVE_CFMAKERAW) || defined(HAVE_TERMIOS2)
static void s_cfmakeraw(g_termios *termios_p) {
    termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    termios_p->c_oflag &= ~OPOST;
    termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    termios_p->c_cflag &= ~(CSIZE|PARENB);
    termios_p->c_cflag |= CS8;
    termios_p->c_cc[VMIN] = 1;
}
#else
#define s_cfmakeraw cfmakeraw
#endif

static bool
is_a_pty(const char *ttyname)
{
    char buf[PATH_MAX];

    while (readlink(ttyname, buf, sizeof(buf)) > 0)
	ttyname = buf;

    if (strncmp(ttyname, "/dev/pts/", 9) == 0)
	return true;

    /*
     * According to the Linux man page, BSD slave devices are named:
     *  /dev/tty[p-za-e][0-9a-f]
     * so we have this check for them.
     */
    if (strncmp(ttyname, "/dev/tty", 8) != 0)
	return false;

    return (((ttyname[8] >= 'a' && ttyname[8] <= 'e') ||
	     (ttyname[8] >= 'p' && ttyname[8] <= 'z')) &&
	    ((ttyname[9] >= '0' && ttyname[9] <= '9') ||
	     (ttyname[9] >= 'a' && ttyname[9] <= 'f')));
}

static int
sterm_sub_open(void *handler_data, int *fd)
{
    struct sterm_data *sdata = handler_data;
    int err;
    int options;

    if (!sdata->no_uucp_lock) {
	err = uucp_mk_lock(sdata->devname);
	if (err > 0) {
	    err = GE_INUSE;
	    goto out;
	}
	if (err < 0) {
	    err = gensio_os_err_to_err(sdata->o, errno);
	    goto out;
	}
    }

    sdata->timer_stopped = false;

    options = O_NONBLOCK | O_NOCTTY;
    if (sdata->write_only)
	options |= O_WRONLY;
    else
	options |= O_RDWR;
    sdata->fd = open(sdata->devname, options);
    if (sdata->fd == -1) {
	err = errno;
	goto out_uucp;
    }

    get_termios(sdata->fd, &sdata->orig_termios);

    if (!sdata->write_only &&
		set_termios(sdata->fd, &sdata->default_termios) == -1) {
	err = errno;
	goto out_restore;
    }

    if (!sdata->write_only && !sdata->disablebreak) {
	if (ioctl(sdata->fd, TIOCCBRK) == -1) {
	    err = errno;
	    goto out_restore;
	}
    }

#if HAVE_DECL_TIOCSRS485
    if (sdata->rs485.flags & SER_RS485_ENABLED) {
	if (ioctl(sdata->fd, TIOCSRS485, &sdata->rs485) < 0) {
	    err = errno;
	    goto out_restore;
	}
    }
#endif

    sterm_lock(sdata);
    sdata->open = true;
    sdata->sent_first_modemstate = false;
    sterm_unlock(sdata);

    if (!sdata->write_only)
	sterm_modemstate(sdata->sio, 255);

    *fd = sdata->fd;

    return 0;

 out_restore:
    set_termios(sdata->fd, &sdata->orig_termios);
 out_uucp:
    if (!sdata->no_uucp_lock)
	uucp_rm_lock(sdata->devname);

    /* pty's for some reason return EIO if the remote end closes. */
    if (sdata->is_pty && err == EIO)
	err = GE_REMCLOSE;
    else
	err = gensio_os_err_to_err(sdata->o, err);
 out:
    if (sdata->fd != -1) {
	close(sdata->fd);
	sdata->fd = -1;
    }
    return err;
}

static void
sterm_free(void *handler_data)
{
    struct sterm_data *sdata = handler_data;

    termios_clear_q(sdata);
    if (sdata->lock)
	sdata->o->free_lock(sdata->lock);
    if (sdata->timer)
	sdata->o->free_timer(sdata->timer);
    if (sdata->devname)
	sdata->o->free(sdata->o, sdata->devname);
    if (sdata->deferred_op_runner)
	sdata->o->free_runner(sdata->deferred_op_runner);
    if (sdata->sio)
	sergensio_data_free(sdata->sio);
    sdata->o->free(sdata->o, sdata);
}

static int
sterm_control_raddr(struct sterm_data *sdata, char *buf, gensiods *datalen)
{
    int status = 0;
    gensiods pos = 0, buflen = *datalen;

    if (!sdata->write_only && sdata->fd != -1) {
	if (ioctl(sdata->fd, TIOCMGET, &status) == -1)
	    return gensio_os_err_to_err(sdata->o, errno);
    }

    gensio_pos_snprintf(buf, buflen, &pos, "%s", sdata->devname);

    if (!sdata->write_only) {
	g_termios itermio, *termio;
	int stopbits;
	int databits;
	int parity_enabled;
	int parity;
	int xon;
	int xoff;
	int xany;
	int flow_rtscts;
	int clocal;
	int hangup_when_done;
	char str[4];

	if (sdata->fd == -1) {
	    termio = &sdata->default_termios;
	} else {
	    if (get_termios(sdata->fd, &itermio) == -1)
		return gensio_os_err_to_err(sdata->o, errno);
	    termio = &itermio;
	}

	stopbits = termio->c_cflag & CSTOPB;
	databits = termio->c_cflag & CSIZE;
	parity_enabled = termio->c_cflag & PARENB;
	parity = termio->c_cflag & PARODD;
	xon = termio->c_iflag & IXON;
	xoff = termio->c_iflag & IXOFF;
	xany = termio->c_iflag & IXANY;
	flow_rtscts = termio->c_cflag & CRTSCTS;
	clocal = termio->c_cflag & CLOCAL;
	hangup_when_done = termio->c_cflag & HUPCL;

	memset(str, 0, sizeof(str));
	if (parity_enabled && parity)
	    str[0] = 'O';
	else if (parity_enabled)
	    str[0] = 'E';
	else
	    str[0] = 'N';

	switch (databits) {
	case CS5: str[1] = '5'; break;
	case CS6: str[1] = '6'; break;
	case CS7: str[1] = '7'; break;
	case CS8: str[1] = '8'; break;
	default: str[1] = '?';
	}

	if (stopbits)
	    str[2] = '2';
	else
	    str[2] = '1';

	gensio_pos_snprintf(buf, buflen, &pos, ",%d%s",
			    get_baud_rate_val(termio), str);

	if (xon && xoff && xany)
	    gensio_pos_snprintf(buf, buflen, &pos, ",XONXOFF");

	if (flow_rtscts)
	    gensio_pos_snprintf(buf, buflen, &pos, ",RTSCTS");

	if (clocal)
	    gensio_pos_snprintf(buf, buflen, &pos, ",CLOCAL");

	if (hangup_when_done)
	    gensio_pos_snprintf(buf, buflen, &pos, ",HANGUP_WHEN_DONE");

    }
    if (!sdata->write_only && sdata->fd != -1) {
	if (status & TIOCM_RTS)
	    gensio_pos_snprintf(buf, buflen, &pos, " RTSHI");
	else
	    gensio_pos_snprintf(buf, buflen, &pos, " RTSLO");

	if (status & TIOCM_DTR)
	    gensio_pos_snprintf(buf, buflen, &pos, " DTRHI");
	else
	    gensio_pos_snprintf(buf, buflen, &pos, " DTRLO");
    } else {
	gensio_pos_snprintf(buf, buflen, &pos, " offline");
    }

    *datalen = pos;
    return 0;
}

static int
sterm_control(void *handler_data, int fd, bool get, unsigned int option,
	      char *data, gensiods *datalen)
{
    struct sterm_data *sdata = handler_data;

    switch (option) {
    case GENSIO_CONTROL_SEND_BREAK:
	if (get)
	    break;
	do_break(fd);
	return 0;

    case GENSIO_CONTROL_RADDR:
	if (!get)
	    break;
	if (strtoul(data, NULL, 0) > 0)
	    return GE_NOTFOUND;
	return sterm_control_raddr(sdata, data, datalen);

    case GENSIO_CONTROL_REMOTE_ID:
	if (!get)
	    return GE_NOTSUP;
	*datalen = snprintf(data, *datalen, "%d", sdata->fd);
	return 0;

    default:
	break;
    }

    return GE_NOTSUP;
}

static int
sterm_write(void *handler_data, int fd, gensiods *rcount,
	    const struct gensio_sg *sg, gensiods sglen,
	    const char *const *auxdata)
{
    struct sterm_data *sdata = handler_data;
    int rv = gensio_os_write(sdata->o, fd, sg, sglen, rcount);

    if (rv && sdata->is_pty && rv == GE_IOERR)
	return GE_REMCLOSE; /* We don't seem to get EPIPE from ptys */
    return rv;
}

static int
sterm_do_read(int fd, void *data, gensiods count, gensiods *rcount,
	      const char ***auxdata, void *cb_data)
{
    struct sterm_data *sdata = cb_data;
    int rv = gensio_os_read(sdata->o, fd, data, count, rcount);

    if (rv && sdata->is_pty && rv == GE_IOERR)
	return GE_REMCLOSE; /* We don't seem to get EPIPE from ptys */
    return rv;
}

static void
sterm_read_ready(void *handler_data, int fd)
{
    struct sterm_data *sdata = handler_data;

    gensio_fd_ll_handle_incoming(sdata->ll, sterm_do_read, NULL, sdata);
}

static const struct gensio_fd_ll_ops sterm_fd_ll_ops = {
    .sub_open = sterm_sub_open,
    .check_close = sterm_check_close_drain,
    .free = sterm_free,
    .write = sterm_write,
    .read_ready = sterm_read_ready,
    .control = sterm_control
};

static int
handle_speedstr(g_termios *termio, const char *str, bool custspeed)
{
    int val;
    const char *rest = "";

    val = speedstr_to_speed(str, &rest);
    if (val == -1)
	return GE_INVAL;
    if (set_termios_from_speed(termio, val, rest, custspeed) == -1)
	return GE_INVAL;
    return 0;
}

static int
process_termios_parm(g_termios *termio, const char *parm, bool custspeed)
{
    int rv = 0, val;
    const char *str;
    bool bval;

    if (gensio_check_keyvalue(parm, "speed", &str) > 0) {
	rv = handle_speedstr(termio, str, custspeed);
    } else if (handle_speedstr(termio, parm, custspeed) == 0) {
	;
    } else if (gensio_check_keybool(parm, "xonxoff", &bval) > 0) {
	set_termios_xonxoff(termio, bval);
    } else if (gensio_check_keybool(parm, "rtscts", &bval) > 0) {
	set_termios_rtscts(termio, bval);
    } else if (gensio_check_keybool(parm, "local", &bval) > 0) {
	if (bval)
	    termio->c_cflag |= CLOCAL;
	else
	    termio->c_cflag &= ~CLOCAL;
    } else if (gensio_check_keybool(parm, "hangup-when-done", &bval) > 0) {
	if (bval)
	    termio->c_cflag |= HUPCL;
	else
	    termio->c_cflag &= ~HUPCL;

    /* Everything below is deprecated. */
    } else if (strcasecmp(parm, "1STOPBIT") == 0) {
	termio->c_cflag &= ~(CSTOPB);
    } else if (strcasecmp(parm, "2STOPBITS") == 0) {
	termio->c_cflag |= CSTOPB;
    } else if (strcasecmp(parm, "5DATABITS") == 0) {
	set_termios_datasize(termio, 5);
    } else if (strcasecmp(parm, "6DATABITS") == 0) {
	set_termios_datasize(termio, 6);
    } else if (strcasecmp(parm, "7DATABITS") == 0) {
	set_termios_datasize(termio, 7);
    } else if (strcasecmp(parm, "8DATABITS") == 0) {
	set_termios_datasize(termio, 8);
    } else if ((val = lookup_parity_str(parm)) != -1) {
	set_termios_parity(termio, val);
    } else if (strcasecmp(parm, "-XONXOFF") == 0) {
	set_termios_xonxoff(termio, 0);
    } else if (strcasecmp(parm, "-RTSCTS") == 0) {
	set_termios_rtscts(termio, 0);
    } else if (strcasecmp(parm, "-LOCAL") == 0) {
	termio->c_cflag &= ~CLOCAL;
    } else if (strcasecmp(parm, "HANGUP_WHEN_DONE") == 0) {
	termio->c_cflag |= HUPCL;
    } else if (strcasecmp(parm, "-HANGUP_WHEN_DONE") == 0) {
	termio->c_cflag &= ~HUPCL;
    } else {
	rv = GE_INVAL;
    }

    return rv;
}

static int
process_rs485(struct sterm_data *sdata, const char *str)
{
#if HAVE_DECL_TIOCSRS485
    int argc, i;
    const char **argv;
    char *end;
    int err;

    if (!str || strcasecmp(str, "off") == 0) {
	sdata->rs485.flags &= ~SER_RS485_ENABLED;
	return 0;
    }

    err = gensio_str_to_argv(sdata->o, str, &argc, &argv, ":");

    if (err)
	return err;
    if (argc < 2)
	return GE_INVAL;

    sdata->rs485.delay_rts_before_send = strtoul(argv[0], &end, 10);
    if (end == argv[0] || *end != '\0')
	goto out_inval;

    sdata->rs485.delay_rts_after_send = strtoul(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0')
	goto out_inval;

    for (i = 2; i < argc; i++) {
	if (strcmp(argv[i], "rts_on_send") == 0) {
	    sdata->rs485.flags |= SER_RS485_RTS_ON_SEND;
	} else if (strcmp(argv[i], "rts_after_send") == 0) {
	    sdata->rs485.flags |= SER_RS485_RTS_AFTER_SEND;
	} else if (strcmp(argv[i], "rx_during_tx") == 0) {
	    sdata->rs485.flags |= SER_RS485_RX_DURING_TX;
#ifdef SER_RS485_TERMINATE_BUS
	} else if (strcmp(argv[i], "terminate_bus") == 0) {
	    sdata->rs485.flags |= SER_RS485_TERMINATE_BUS;
#endif
	} else {
	    goto out_inval;
	}
    }

    sdata->rs485.flags |= SER_RS485_ENABLED;

 out:
    gensio_argv_free(sdata->o, argv);
    return err;

 out_inval:
    err = GE_INVAL;
    goto out;
#else
    return GE_NOTSUP;
#endif
}

static int
sergensio_process_parms(struct sterm_data *sdata)
{
    int argc, i;
    const char **argv;
    int err = gensio_str_to_argv(sdata->o, sdata->parms, &argc, &argv,
				 " \f\t\n\r\v,");
    const char *str;

    if (err)
	return err;

    for (i = 0; i < argc; i++) {
	if (gensio_check_keybool(argv[i], "wronly", &sdata->write_only) > 0) {
	    continue;
	} else if (gensio_check_keybool(argv[i], "nobreak",
					&sdata->disablebreak) > 0) {
	    continue;
	} else if (gensio_check_keyvalue(argv[i], "rs485", &str) > 0) {
	    err = process_rs485(sdata, str);
	    if (err)
		break;
	    continue;

	/* The following is deprecated. */
	} else if (strcasecmp(argv[i], "-NOBREAK") == 0) {
	    sdata->disablebreak = false;
	    continue;
	}
	err = process_termios_parm(&sdata->default_termios, argv[i],
				   sdata->allow_custspeed);
	if (err)
	    break;
    }

    gensio_argv_free(sdata->o, argv);
    return err;
}

static int
sergensio_setup_defaults(struct gensio_os_funcs *o, struct sterm_data *sdata)
{
    int val, err;
    g_termios *termctl = &sdata->default_termios;
    char *str;

    s_cfmakeraw(termctl);

    err = gensio_get_default(o, "serialdev", "speed", false,
			     GENSIO_DEFAULT_STR, &str, NULL);
    if (err) {
	gensio_log(o, GENSIO_LOG_ERR, "Failed getting default serialdev speed:"
		   " %s\n", gensio_err_to_str(err));
	return err;
    }
    if (str) {
	if (handle_speedstr(termctl, str, sdata->allow_custspeed)) {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Default speed settings (%s) are invalid,"
		       " defaulting to 9600N81", str);
	    set_baud_rate(termctl, 9600, false);
	    set_termios_parity(termctl, 'N');
	    set_termios_datasize(termctl, 8);
	    termctl->c_cflag &= ~(CSTOPB); /* 1 stopbit */
	}
	o->free(o, str);
    }

    sdata->default_termios.c_cflag |= CREAD;
    sdata->default_termios.c_cc[VSTART] = 17;
    sdata->default_termios.c_cc[VSTOP] = 19;
    sdata->default_termios.c_iflag |= IGNBRK;

    val = 0;
    err = gensio_get_default(o, "serialdev", "xonxoff", false,
			     GENSIO_DEFAULT_BOOL, NULL, &val);
    if (err)
	return err;
    set_termios_xonxoff(termctl, val);

    val = 0;
    err = gensio_get_default(o, "serialdev", "rtscts", false,
			     GENSIO_DEFAULT_BOOL, NULL, &val);
    if (err)
	return err;
    set_termios_rtscts(termctl, val);

    val = 0;
    err = gensio_get_default(o, "serialdev", "local", false,
			     GENSIO_DEFAULT_BOOL, NULL, &val);
    if (err)
	return err;
    if (val)
	termctl->c_cflag |= CLOCAL;

    val = 0;
    err = gensio_get_default(o, "serialdev", "hangup_when_done", false,
			     GENSIO_DEFAULT_BOOL, NULL, &val);
    if (err)
	return err;
    if (val)
	termctl->c_cflag |= HUPCL;

    err = gensio_get_default(o, "serialdev", "rs485", false, GENSIO_DEFAULT_STR,
			     &str, NULL);
    if (err) {
	gensio_log(o, GENSIO_LOG_ERR, "Failed getting default serialdev rs485:"
		   " %s\n", gensio_err_to_str(err));
	return err;
    }
    if (str) {
	if (process_rs485(sdata, str))
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Default rs485 settings (%s) are invalid, ignoring",
		       str);
	o->free(0, str);
    }

    return 0;
}

int
serialdev_gensio_alloc(const char *devname, const char * const args[],
		       struct gensio_os_funcs *o,
		       gensio_event cb, void *user_data,
		       struct gensio **rio)
{
    struct sterm_data *sdata = o->zalloc(o, sizeof(*sdata));
    struct gensio *io;
    int err;
    char *comma;
    gensiods max_read_size = GENSIO_DEFAULT_BUF_SIZE;
    int i;
    bool nouucplock_set = false;

    if (!sdata)
	return GE_NOMEM;

    sdata->o = o;

    i = 0;
    err = gensio_get_default(o, "serialdev", "custspeed", false,
			     GENSIO_DEFAULT_BOOL, NULL, &i);
    if (err)
	goto out_err;
    sdata->allow_custspeed = i;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "nouucplock",
				 &sdata->no_uucp_lock) > 0) {
	    nouucplock_set = true;
	    continue;
	}
	if (gensio_check_keybool(args[i], "custspeed",
				 &sdata->allow_custspeed) > 0)
	    continue;
	err = GE_INVAL;
	goto out_err;
    }

    sdata->fd = -1;

    sdata->timer = o->alloc_timer(o, serialdev_timeout, sdata);
    if (!sdata->timer)
	goto out_nomem;

    sdata->devname = gensio_strdup(o, devname);
    if (!sdata->devname)
	goto out_nomem;

    sdata->is_pty = is_a_pty(sdata->devname);

    comma = strchr(sdata->devname, ',');
    if (comma)
	*comma++ = '\0';

    if (!nouucplock_set) {
	const char *slash = strrchr(devname, '/');

	/*
	 * If the user didn't force it, don't do uucp locking if the
	 * devname is "tty", as in "/dev/tty".  That does all sorts
	 * of bad things...
	 */
	if (slash)
	    slash++;
	else
	    slash = devname;

	/* Don't do uucp locking on /dev/tty or ptys */
	sdata->no_uucp_lock = strcmp(slash, "tty") == 0 || sdata->is_pty;
    }

    err = sergensio_setup_defaults(o, sdata);
    if (err)
	goto out_err;

    if (comma) {
	sdata->parms = comma;
	err = sergensio_process_parms(sdata);
	if (err)
	    goto out_err;
    }
    sdata->deferred_op_runner = o->alloc_runner(o, sterm_deferred_op, sdata);
    if (!sdata->deferred_op_runner)
	goto out_nomem;

    sdata->lock = o->alloc_lock(o);
    if (!sdata->lock)
	goto out_nomem;

    sdata->ll = fd_gensio_ll_alloc(o, -1, &sterm_fd_ll_ops, sdata,
				   max_read_size, sdata->write_only);
    if (!sdata->ll)
	goto out_nomem;

    /*
     * After this point, freeing the ll or io will free sdata through
     * the free callbacks.
     */

    io = base_gensio_alloc(o, sdata->ll, NULL, NULL, "serialdev",
			   cb, user_data);
    if (!io) {
	gensio_ll_free(sdata->ll);
	return GE_NOMEM;
    }

    sdata->sio = sergensio_data_alloc(o, io, sergensio_sterm_func, sdata);
    if (!sdata->sio) {
	gensio_free(io);
	return GE_NOMEM;
    }

    err = gensio_addclass(io, "sergensio", sdata->sio);
    if (err) {
	gensio_free(io);
	return err;
    }

    *rio = io;
    return 0;

 out_nomem:
    err = GE_NOMEM;
 out_err:
    sterm_free(sdata);
    return err;
}

int
str_to_serialdev_gensio(const char *str, const char * const args[],
		      struct gensio_os_funcs *o,
		      gensio_event cb, void *user_data,
		      struct gensio **new_gensio)
{
    return serialdev_gensio_alloc(str, args, o, cb, user_data, new_gensio);
}
