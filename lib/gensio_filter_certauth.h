/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_FILTER_CERTAUTH_H
#define GENSIO_FILTER_CERTAUTH_H

#include <gensio/gensio_base.h>

struct gensio_certauth_filter_data;

int gensio_certauth_filter_config(struct gensio_os_funcs *o,
				  const char * const args[],
				  bool default_is_client,
				  struct gensio_certauth_filter_data **rdata);

void
gensio_certauth_filter_config_free(struct gensio_certauth_filter_data *data);

bool gensio_certauth_filter_config_allow_unencrypted(
	     struct gensio_certauth_filter_data *data);

bool gensio_certauth_filter_config_is_client(
	     struct gensio_certauth_filter_data *data);

int gensio_certauth_filter_alloc(struct gensio_certauth_filter_data *data,
				 struct gensio_filter **rfilter);

#endif /* GENSIO_FILTER_CERTAUTH_H */
