/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2022  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_LL_SOUND_H
#define GENSIO_LL_SOUND_H

#include <gensio/gensio_base.h>

struct gensio_sound_info {
    const char *type; /* alsa, port, file, etc. */
    const char *devname;
    unsigned int chans;
    unsigned int samplerate;
    gensiods bufsize;
    unsigned int num_bufs;
    const char *format;
    const char *pformat; /* Format on the PCM side. */
};

int gensio_sound_ll_alloc(struct gensio_os_funcs *o,
			  struct gensio_sound_info *in,
			  struct gensio_sound_info *out,
			  struct gensio_ll **newll);

void gensio_sound_devices_free(char **names, char **specs, gensiods count);

int gensio_sound_devices(const char *type,
			 char ***names, char ***specs, gensiods *count);

#endif /* GENSIO_LL_SOUND_H */
