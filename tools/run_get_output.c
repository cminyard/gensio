/*
 *  gensiotools - General tools using gensio
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  gensio give you permission to combine gensio with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for gensio and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of gensio are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gensio/gensio.h>

struct run_data {
    struct gensio_os_funcs *o;
    int err;
    struct gensio_waiter *w;
    bool close_stdin;
    unsigned char *closestr;
    gensiods closestr_pos;
    gensiods closestr_len;
    char *indata;
    gensiods indata_pos;
    gensiods indata_len;
    char *outdata;
    gensiods outdata_pos;
    gensiods outdata_len;
    char *errdata;
    gensiods errdata_pos;
    gensiods errdata_len;
};

static int
run_io_event(struct gensio *io, void *user_data,
	     int event, int err,
	     unsigned char *buf, gensiods *buflen,
	     const char *const *auxdata)
{
    gensiods i;
    struct run_data *d = user_data;

    if (err) {
    out_err:
	if (err != GE_REMCLOSE && !d->err) {
	    fprintf(stderr, "Error from stdio: %s\n", gensio_err_to_str(err));
	    d->err = err;
	}
	gensio_os_funcs_wake(d->o, d->w);
	return 0;
    }

    if (event == GENSIO_EVENT_WRITE_READY) {
	gensiods left = d->indata_len - d->indata_pos;

	if (left) {
	    gensiods count = 0;
	    err = gensio_write(io, &count, d->indata + d->indata_pos, left,
			       NULL);
	    if (err)
		goto out_err;
	    d->indata_pos += count;
	}
	if (d->indata_pos >= d->indata_len) {
	    gensio_set_write_callback_enable(io, false);
	    if (d->close_stdin) {
		err = gensio_control(io, 0, GENSIO_CONTROL_SET,
				     GENSIO_CONTROL_CLOSE_OUTPUT, NULL, NULL);
		if (err)
		    goto out_err;
	    }
	}
	return 0;
    }

    if (event != GENSIO_EVENT_READ)
	return GE_NOTSUP;

    if (d->closestr && d->closestr_len) {
	for (i = 0; i < *buflen; i++) {
	    if (buf[i] == d->closestr[d->closestr_pos]) {
		d->closestr_pos++;
		if (d->closestr_pos == d->closestr_len) {
		    d->closestr_len = 0;
		    gensio_os_funcs_wake(d->o, d->w);
		}
	    } else {
		d->closestr_pos = 0;
	    }
	}
    }

    if (!d->outdata) {
	fwrite(buf, 1, *buflen, stdout);
	return 0;
    }

    if (d->outdata_pos + *buflen + 1 > d->outdata_len) {
	char *old = d->outdata;
	gensiods new_len = d->outdata_len + *buflen + 256;

	d->outdata = malloc(new_len);
	if (!d->outdata) {
	    d->outdata = old;
	    d->err = GE_NOMEM;
	    fprintf(stderr, "Error allocating output data\n");
	    return 0;
	}
	d->outdata_len = new_len;
	memcpy(d->outdata, old, d->outdata_pos);
	free(old);
    }
    memcpy(d->outdata + d->outdata_pos, buf, *buflen);
    d->outdata_pos += *buflen;
    d->outdata[d->outdata_pos] = '\0';
    return 0;
}

static int
run_errio_event(struct gensio *io, void *user_data,
		int event, int err,
		unsigned char *buf, gensiods *buflen,
		const char *const *auxdata)
{
    struct run_data *d = user_data;

    if (err) {
	if (err != GE_REMCLOSE && !d->err) {
	    fprintf(stderr, "Error from stdio: %s\n", gensio_err_to_str(err));
	    d->err = err;
	}
	gensio_os_funcs_wake(d->o, d->w);
	return 0;
    }

    if (event != GENSIO_EVENT_READ)
	return GE_NOTSUP;

    if (!d->errdata) {
	fwrite(buf, 1, *buflen, stderr);
	return 0;
    }

    if (d->errdata_pos + *buflen + 1 > d->errdata_len) {
	char *old = d->errdata;
	gensiods new_len = d->errdata_len + *buflen + 256;

	d->errdata = malloc(new_len);
	if (!d->errdata) {
	    d->errdata = old;
	    d->err = GE_NOMEM;
	    fprintf(stderr, "Error allocating error data\n");
	    return 0;
	}
	d->errdata_len = new_len;
	memcpy(d->errdata, old, d->errdata_pos);
	free(old);
    }
    memcpy(d->errdata + d->errdata_pos, buf, *buflen);
    d->errdata_pos += *buflen;
    d->errdata[d->errdata_pos] = '\0';
    return 0;
}

int
run_get_output(const char *argv[],
	       bool close_stdin,
	       char *closestr, unsigned long closestrlen,
	       char *in, unsigned long inlen,
	       char **out, unsigned long *outlen,
	       char **errout, unsigned long *erroutlen,
	       int *rc)
{
    struct run_data d;
    struct gensio *io = NULL, *errio = NULL;
    bool io_open = false, errio_open = false;

    memset(&d, 0, sizeof(d));
    d.close_stdin = close_stdin;
    d.closestr = (unsigned char *) closestr;
    d.closestr_len = closestrlen;

    d.err = gensio_default_os_hnd(0, &d.o);
    if (d.err) {
	fprintf(stderr, "Error allocating os handler: %s\n",
		gensio_err_to_str(d.err));
	goto out;
    }

    if (in && inlen) {
	d.indata = in;
	d.indata_len = inlen;
	d.indata_pos = 0;
    }

    if (out) {
	d.outdata = malloc(256);
	if (!d.outdata) {
	    d.err = GE_NOMEM;
	    fprintf(stderr, "Error allocating output data: %s\n",
		    gensio_err_to_str(d.err));
	    goto out;
	}
	d.outdata_pos = 0;
	d.outdata_len = 256;
	d.outdata[0] = '\0';
    }

    if (errout) {
	d.errdata = malloc(256);
	if (!d.errdata) {
	    d.err = GE_NOMEM;
	    fprintf(stderr, "Error allocating output data: %s\n",
		    gensio_err_to_str(d.err));
	    goto out;
	}
	d.errdata_pos = 0;
	d.errdata_len = 256;
	d.errdata[0] = '\0';
    }

    d.w = gensio_os_funcs_alloc_waiter(d.o);
    if (!d.w) {
	d.err = GE_NOMEM;
	fprintf(stderr, "Error allocating os waiter: %s\n",
		gensio_err_to_str(d.err));
	goto out;
    }

    d.err = gensio_terminal_alloc("stdio", argv, NULL, d.o, run_io_event, &d,
				  &io);
    if (d.err) {
	fprintf(stderr, "Error allocating os stdio: %s\n",
		gensio_err_to_str(d.err));
	goto out;
    }

    d.err = gensio_open_s(io);
    if (d.err) {
	fprintf(stderr, "Error opening stdio: %s\n",
		gensio_err_to_str(d.err));
	goto out;
    }
    io_open = true;

    d.err = gensio_alloc_channel(io, NULL, run_errio_event, &d, &errio);
    if (d.err) {
	fprintf(stderr, "Error allocating stderr: %s\n",
		gensio_err_to_str(d.err));
	goto out;
    }

    d.err = gensio_open_s(errio);
    if (d.err) {
	fprintf(stderr, "Error opening stderr: %s\n",
		gensio_err_to_str(d.err));
	goto out;
    }
    errio_open = true;

    if (d.indata) {
	gensio_set_write_callback_enable(io, true);
    } else if (close_stdin) {
	d.err = gensio_control(io, 0, GENSIO_CONTROL_SET,
			       GENSIO_CONTROL_CLOSE_OUTPUT, NULL, NULL);
	if (d.err) {
	    fprintf(stderr, "Error closing stdin: %s\n",
		    gensio_err_to_str(d.err));
	    goto out;
	}
    }
    gensio_set_read_callback_enable(io, true);
    gensio_set_read_callback_enable(errio, true);

    gensio_os_funcs_wait(d.o, d.w, 1, NULL);

 out:
    if (errio) {
	if (errio_open)
	    gensio_close_s(errio);
	gensio_free(errio);
    }
    if (io) {
	if (io_open)
	    gensio_close_s(io);
	if (!d.err && rc) {
	    char intstr[10];
	    gensiods size = sizeof(intstr);

	    d.err = gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST,
				   GENSIO_CONTROL_GET,
				   GENSIO_CONTROL_EXIT_CODE, intstr, &size);
	    if (d.err)
		fprintf(stderr, "Error getting return code: %s\n",
			gensio_err_to_str(d.err));
	    *rc = strtol(intstr, NULL, 0);
	}
	gensio_free(io);
    }
    if (d.w)
	gensio_os_funcs_free_waiter(d.o, d.w);
    if (d.o)
	gensio_os_funcs_free(d.o);

    if (d.err) {
	if (d.outdata)
	    free(d.outdata);
	if (d.errdata)
	    free(d.errdata);
    } else {
	if (out)
	    *out = d.outdata;
	else
	    free(d.outdata);
	if (outlen)
	    *outlen = d.outdata_pos;
	if (errout)
	    *errout = d.errdata;
	else
	    free(d.errdata);
	if (erroutlen)
	    *erroutlen = d.errdata_pos;
    }

    return d.err;
}
