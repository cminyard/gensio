/*
 *  gensiotools - General tools using gensio
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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

#ifndef GTLSSH_H
#define GTLSSH_H
#include <stdbool.h>
#include <stdint.h>
#include <gensio/gensio.h>

int checkout_file(const char *filename, bool expect_dir, bool check_private);
bool file_is_readable(const char *filename);
int write_file_to_gensio(const char *filename, struct gensio *io,
			 struct gensio_os_funcs *o, gensio_time *timeout,
			 bool xlatnl);
int write_buf_to_gensio(const char *buf, gensiods len, struct gensio *io,
			gensio_time *timeout, bool xlatnl);
int write_str_to_gensio(const char *str, struct gensio *io,
			gensio_time *timeout, bool xlatnl);
int read_rsp_from_gensio(char *buf, gensiods *len, struct gensio *io,
			 gensio_time *timeout, bool echo);

/* Transferred over the aux data. */
struct gtlssh_aux_data {
    uint32_t flags; /* Flag fields in network order. */
};
#define GTLSSH_AUX_FLAG_NO_INTERACTIVE		(1 << 0)

#endif /* GENSIOTOOL_UTILS_H */
