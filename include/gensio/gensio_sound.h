/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_SOUND_H
#define GENSIO_SOUND_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gensio/gensio_dllvisibility.h>
#include <gensio/gensio_types.h>

GENSIO_DLL_PUBLIC
void gensio_sound_devices_free(char **names, char **specs, gensiods count);

GENSIO_DLL_PUBLIC
int gensio_sound_devices(const char *type,
			 char ***names, char ***specs, gensiods *count);

#ifdef __cplusplus
}
#endif

#endif /* MDNS_H */

