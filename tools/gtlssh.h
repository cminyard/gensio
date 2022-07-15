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
#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include <gensio/gensio.h>

typedef void (*gtlssh_logger)(void *cbdata, const char *format, ...);

int checkout_file(gtlssh_logger logger, void *cbdata,
		  const char *filename, bool expect_dir, bool check_private);
bool file_is_readable(const char *filename);
char *get_homedir(gtlssh_logger logger, void *cbdata,
		  const char *username, const char *extra);
char *get_tlsshdir(gtlssh_logger logger, void *cbdata,
		   const char *username, const char *extra);
char *get_my_username(gtlssh_logger logger, void *cbdata);
char *get_my_hostname(gtlssh_logger logger, void *cbdata);
bool check_dir_exists(gtlssh_logger logger, void *cbdata,
		      const char *dir, bool check_private);
bool check_file_exists(const char *file);
void make_dir(gtlssh_logger logger, void *cbdata,
	      const char *dir, bool make_private);

/* Only used on Windows. */
int make_file(gtlssh_logger logger, void *cbdata,
	      const char *filename,
	      const void *contents, size_t len,
	      bool make_private);
int read_file(gtlssh_logger logger, void *cbdata,
	      const char *filename, void *contents, size_t *len);

#define LINK_ERROR  1
#define LINK_EXISTS 2
int make_link(gtlssh_logger logger, void *cbdata,
	      const char *link, const char *file, const char *name);
int move_file(gtlssh_logger logger, void *cbdata,
	      const char *src, const char *dest);
int delete_file(gtlssh_logger logger, void *cbdata,
		const char *filename);

int run_get_output(const char *argv[],
		   bool close_stdin,
		   char *closestr, unsigned long closestrlen,
		   char *in, unsigned long inlen,
		   char **out, unsigned long *outlen,
		   char **errout, unsigned long *erroutlen,
		   int *rc);

#ifdef _WIN32
#define DIRSEP '\\'
#define DIRSEPS "\\"
#else
#define DIRSEP '/'
#define DIRSEPS "/"
#endif

/* Transferred over the aux data. */
struct gtlssh_aux_data {
    uint32_t flags; /* Flag fields in network order. */
};
/* Do not do interactive querying of passwords and 2fa. */
#define GTLSSH_AUX_FLAG_NO_INTERACTIVE		(1 << 0)

/* On windows, Don't drop the privileges on a privileged user. */
#define GTLSSH_AUX_FLAG_PRIVILEGED		(1 << 1)

#endif /* GENSIOTOOL_UTILS_H */
