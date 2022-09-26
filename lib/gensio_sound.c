/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <gensio/sergensio_class.h>

#include "gensio_ll_sound.h"


static int
alloc_sound_list(struct gensio_os_funcs *o, const char *type,
		 gensio_event cb, void *user_data,
		 struct gensio **rio)
{
    char **names, **specs;
    gensiods i, count, len = 1;
    int err;
    const char *argv[3];
    char *data;

    err = gensio_sound_devices(type, &names, &specs, &count);
    if (err)
	return err;

    for (i = 0; i < count; i++)
	len += strlen(names[i]) + strlen(specs[i]) + 2;

    data = o->zalloc(o, 5 + len);
    if (!data) {
	err = GE_NOMEM;
	goto out;
    }
    memcpy(data, "data=", 5);
    len = 5;
    for (i = 0; i < count; i++) {
	gensiods cpysize = strlen(names[i]);

	memcpy(data + len, names[i], cpysize);
	len += cpysize;
	data[len++] = '\t';
	cpysize = strlen(specs[i]);
	memcpy(data + len, specs[i], cpysize);
	len += cpysize;
	data[len++] = '\n';
    }
    data[len] = '\0';

    argv[0] = "noecho";
    argv[1] = data;
    argv[2] = NULL;

    err = gensio_terminal_alloc("echo", NULL, argv, o, cb, user_data, rio);
 out:
    if (data)
	o->free(o, data);
    gensio_sound_devices_free(names, specs, count);
    return err;
}

static int
sound_gensio_alloc(const void *gdata, const char * const args[],
		   struct gensio_os_funcs *o,
		   gensio_event cb, void *user_data,
		   struct gensio **rio)
{
    const char *devname = gdata;
    int err;
    struct gensio_sound_info in, out;
    struct gensio_ll *ll;
    struct gensio *io;
    gensiods dsval;
    unsigned int uival;
    bool list = false;
    int i;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.devname = devname;
    out.devname = devname;

    in.bufsize = 1024;
    in.num_bufs = 100;

    out.bufsize = 1024;
    out.num_bufs = 100;

    for (i = 0; args && args[i]; i++) {
	if (isdigit(args[i][0])) {
	    const char *s = args[i];
	    char *n;

	    in.samplerate = strtoul(s, &n, 0);
	    if (n[0] != '-' || n[1] == '\0')
		return GE_INVAL;
	    s = n + 1;
	    in.chans = strtoul(s, &n, 0);
	    if (n[0] != '-' || n[1] == '\0')
		return GE_INVAL;
	    in.format = n + 1;
	    out.samplerate = in.samplerate;
	    out.chans = in.chans;
	    out.format = in.format;
	    continue;
	}
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
	if (gensio_check_keyuint(args[i], "chans", &in.chans) > 0) {
	    out.chans = in.chans;
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
	if (gensio_check_keybool(args[i], "list", &list) > 0)
	    continue;
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

    if (list)
	return alloc_sound_list(o, in.type, cb, user_data, rio);

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

static int
str_to_sound_gensio(const char *str, const char * const args[],
		    struct gensio_os_funcs *o,
		    gensio_event cb, void *user_data,
		    struct gensio **new_gensio)
{
    return sound_gensio_alloc(str, args, o, cb, user_data, new_gensio);
}

int
gensio_init_sound(struct gensio_os_funcs *o)
{
    int rv;

    rv = register_gensio(o, "sound", str_to_sound_gensio, sound_gensio_alloc);
    if (rv)
	return rv;
    return 0;
}
