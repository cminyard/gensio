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
#include <gensio/gensio.h>

int checkout_file(const char *filename, bool expect_dir, bool check_private);
bool file_is_readable(const char *filename);
char *get_tlsshdir(void);
char *get_my_username(void);
char *get_my_hostname(void);
bool check_dir_exists(const char *dir, bool check_private);
bool check_file_exists(const char *file);
void make_dir(const char *dir, bool make_private);
#define LINK_ERROR  1
#define LINK_EXISTS 2
int make_link(const char *link, const char *file, const char *name);
int move_file(const char *src, const char *dest);
int delete_file(const char *filename);

int run_get_output(const char *argv[], char *in, unsigned long inlen,
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

#endif /* GENSIOTOOL_UTILS_H */
