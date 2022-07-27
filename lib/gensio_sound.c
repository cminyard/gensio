/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>

#include <gensio/sergensio_class.h>
#include <gensio/gensio_builtins.h>

#include "gensio_ll_sound.h"

int
sound_gensio_alloc(const char *devname, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **rio)
{
    int err;
    struct gensio_sound_info in, out;
    struct gensio_ll *ll;
    struct gensio *io;
    gensiods dsval;
    unsigned int uival;
    int i;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.devname = devname;
    out.devname = devname;

    in.bufsize = 2048;
    in.num_bufs = 4;

    out.bufsize = 2048;
    out.num_bufs = 4;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyds(args[i], "inbufsize", &in.bufsize) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "outbufsize", &out.bufsize) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "bufsize", &dsval) > 0) {
	    in.bufsize = dsval;
	    out.bufsize = dsval;
	    continue;
	}
	if (gensio_check_keyuint(args[i], "innbufs", &in.num_bufs) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "outnbufs", &out.num_bufs) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "nbufs", &uival) > 0) {
	    in.num_bufs = uival;
	    out.num_bufs = uival;
	    continue;
	}
	if (gensio_check_keyuint(args[i], "inchans", &in.chans) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "outchans", &out.chans) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "inrate", &in.samplerate) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "outrate", &out.samplerate) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "rate", &uival) > 0) {
	    in.samplerate = uival;
	    out.samplerate = uival;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "intype", &in.type) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "outtype", &out.type) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "type", &out.type) > 0) {
	    in.type = out.type;
	    continue;
	}

	if (gensio_check_keyvalue(args[i], "outdev", &out.devname) > 0)
	    continue;

	if (gensio_check_keyvalue(args[i], "informat", &in.format) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "outformat", &out.format) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "format", &out.format) > 0) {
	    in.format = out.format;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "inpformat", &in.pformat) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "outpformat", &out.pformat) > 0)
	    continue;
	if (gensio_check_keyvalue(args[i], "pformat", &out.pformat) > 0) {
	    in.pformat = out.pformat;
	    continue;
	}
	return GE_INVAL;
    }

    err = gensio_sound_ll_alloc(o, &in, &out, &ll);
    if (err)
	goto out_err;

    io = base_gensio_alloc(o, ll, NULL, NULL, "sound", cb, user_data);
    if (!io) {
	gensio_ll_free(ll);
	return GE_NOMEM;
    }

    *rio = io;
    return 0;

 out_err:
    return err;
}

int
str_to_sound_gensio(const char *str, const char * const args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **new_gensio)
{
    return sound_gensio_alloc(str, args, o, cb, user_data, new_gensio);
}
