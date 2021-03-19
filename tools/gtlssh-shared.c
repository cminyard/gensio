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

#include "gtlssh.h"
#include "utils.h"
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <Windows.h>
#include <Lmcons.h>

#define HOST_NAME_MAX 256

char *
get_tlsshdir(void)
{
    char homedrive[200];
    char homepath[200];
    char *dir;

    if (GetEnvironmentVariable("HOMEDRIVE", homedrive, sizeof(homedrive)) == 0)
    {
	fprintf(stderr, "No HOMEDRIVE set\n");
	return NULL;
    }

    if (GetEnvironmentVariable("HOMEPATH", homepath, sizeof(homepath)) == 0) {
	fprintf(stderr, "No HOMEPATH set\n");
	return NULL;
    }

    dir = alloc_sprintf("%s%s\\.gtlssh", homedrive, homepath);
    if (!dir) {
	fprintf(stderr, "Out of memory allocating gtlssh dir\n");
	return NULL;
    }

    return dir;
}

char *
get_my_username(void)
{
    char *username = malloc(UNLEN + 1);
    DWORD len = UNLEN + 1;

    if (!username) {
	fprintf(stderr, "out of memory allocating username\n");
	return NULL;
    }

    if (!GetUserNameA(username, &len)) {
	DWORD err = GetLastError();
	char errbuf[128];

	free(username);
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	fprintf(stderr, "Could not get username: %s\n", errbuf);
	return NULL;
    }

    return username;
}

#else

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <limits.h>

char *
get_tlsshdir(void)
{
    const char *home = getenv("HOME");
    char *dir;

    if (!home) {
	fprintf(stderr, "No home directory set\n");
	return NULL;
    }

    dir = alloc_sprintf("%s/.gtlssh", home);
    if (!dir) {
	fprintf(stderr, "Out of memory allocating gtlssh dir\n");
	return NULL;
    }

    return dir;
}

char *
get_my_username(void)
{
    struct passwd *pw = getpwuid(getuid());
    char *username;

    if (!pw) {
	fprintf(stderr, "no username given, and can't look up UID\n");
	return NULL;
    }
    username = strdup(pw->pw_name);
    if (!username) {
	fprintf(stderr, "out of memory allocating username\n");
	return NULL;
    }

    return username;
}

#endif /* _WIN32 */

char *
get_my_hostname(void)
{
    char hostname[HOST_NAME_MAX + 1];

    if (gethostname(hostname, sizeof(hostname)) != 0)
	return NULL;
    return strdup(hostname);
}

