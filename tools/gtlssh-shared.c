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
#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>
#include <aclapi.h>

static int
check_sid(const char *filename, const PSID osid, const PSID sid)
{
    if (!(EqualSid(sid, osid) ||
	  IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
	  IsWellKnownSid(sid, WinLocalSystemSid))) {
	fprintf(stderr, "%s is accessible by others, giving up\n",
		filename);
	return 1;
    }
    return 0;
}

int
checkout_file(const char *filename, bool expect_dir, bool check_private)
{
    DWORD attr;
    SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION;
    PSID osid = NULL, psid = NULL;
    ACL *dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL, sd2 = NULL;
    DWORD err = 0;
    char errbuf[128];

    attr = GetFileAttributesA(filename);

    if (attr == INVALID_FILE_ATTRIBUTES) {
	err = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	fprintf(stderr, "Unable to examine %s: %s\n",
		filename, errbuf);
	goto out_err;
    }

    if (expect_dir) {
	if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
	    fprintf(stderr, "%s is not a directory\n", filename);
	    goto out_err;
	}
    } else {
	if (attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) {
	    fprintf(stderr, "%s is not a regular file\n", filename);
	    goto out_err;
	}
    }

    if (GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
			OWNER_SECURITY_INFORMATION, &psid,
			NULL, NULL, NULL, &sd2)) {
	err = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	fprintf(stderr, "Unable to get my process security info: %s\n",
		errbuf);
	goto out_err;
    }

    if (check_private)
	si |= DACL_SECURITY_INFORMATION;
    if (GetNamedSecurityInfoA(filename, SE_FILE_OBJECT, si,
			      &osid, NULL, &dacl, NULL, &sd)) {
	err = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	fprintf(stderr, "Unable to get my security info for %s: %s\n",
		filename, errbuf);
	goto out_err;
    }

    if (!EqualSid(psid, osid)) {
	fprintf(stderr, "You do not own %s, giving up\n", filename);
	goto out_err;
    }

    if (check_private) {
	WORD i;

	for (i = 0; i < dacl->AceCount; i++) {
	    ACE_HEADER *a;

	    if (!GetAce(dacl, i, (void **) &a)) {
		err = GetLastError();
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
			      err, 0, errbuf, sizeof(errbuf), NULL);
		fprintf(stderr, "Unable to get ACE %d for %s: %s\n",
			i, filename, errbuf);
		goto out_err;
	    }
	    switch (a->AceType) {
	    case ACCESS_ALLOWED_ACE_TYPE: {
		ACCESS_ALLOWED_ACE *aa = (void *) a;
		if (check_sid(filename, psid, (SID *) &aa->SidStart))
		    goto out_err;
		break;
	    }
	    case ACCESS_ALLOWED_CALLBACK_ACE_TYPE: {
		ACCESS_ALLOWED_CALLBACK_ACE *aa = (void *) a;
		if (check_sid(filename, psid, (SID *) &aa->SidStart))
		    goto out_err;
		break;
	    }
	    case ACCESS_ALLOWED_OBJECT_ACE_TYPE: {
		ACCESS_ALLOWED_OBJECT_ACE *aa = (void *) a;
		if (check_sid(filename, psid, (SID *) &aa->SidStart))
		    goto out_err;
		break;
	    }
	    case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: {
		ACCESS_ALLOWED_CALLBACK_OBJECT_ACE *aa = (void *) a;
		if (check_sid(filename, psid, (SID *) &aa->SidStart))
		    goto out_err;
		break;
	    }
	    case ACCESS_DENIED_ACE_TYPE:
	    case ACCESS_DENIED_CALLBACK_ACE_TYPE:
	    case ACCESS_DENIED_OBJECT_ACE_TYPE:
	    case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
		/* Denies are ok. */
		break;
	    default:
		fprintf(stderr, "%s is accessible by others, giving up\n",
			filename);
		goto out_err;
	    }
	}
    }

 out:
    if (sd)
	LocalFree(sd);
    if (sd2)
	LocalFree(sd2);
    return err;

 out_err:
    err = 1;
    goto out;
}

bool
file_is_readable(const char *filename)
{
    PSID osid = NULL, psid = NULL;
    PSECURITY_DESCRIPTOR sd = NULL, sd2 = NULL;
    bool rv = false;

    /*
     * From what I can tell, if you are the owner you have read
     * access.  Nothing else matters.
     */
    if (GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT,
			OWNER_SECURITY_INFORMATION, &psid,
			NULL, NULL, NULL, &sd2))
	goto out_false;

    if (GetNamedSecurityInfoA(filename, SE_FILE_OBJECT,
			      OWNER_SECURITY_INFORMATION,
			      &osid, NULL, NULL, NULL, &sd))
	goto out_false;

    if (!EqualSid(psid, osid))
	goto out_false;

    rv = true;
 out_false:
    return rv;
}

#else

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int
checkout_file(const char *filename, bool expect_dir, bool check_private)
{
    struct stat sb;
    int rv;

    rv = stat(filename, &sb);
    if (rv == -1) {
	fprintf(stderr, "Unable to examine %s: %s\n",
		filename, strerror(errno));
	return errno;
    }

    if (sb.st_uid != getuid()) {
	fprintf(stderr, "You do not own %s, giving up\n", filename);
	return EPERM;
    }

    if (check_private && sb.st_mode & 077) {
	fprintf(stderr, "%s is accessible by others, giving up\n", filename);
	return EPERM;
    }

    if (expect_dir) {
	if (!S_ISDIR(sb.st_mode)) {
	    fprintf(stderr, "%s is not a directory\n", filename);
	    return EINVAL;
	}
    } else {
	if (!S_ISREG(sb.st_mode)) {
	    fprintf(stderr, "%s is not a regular file\n", filename);
	    return EINVAL;
	}
    }

    return 0;
}

bool
file_is_readable(const char *filename)
{
    struct stat sb;
    int rv;

    rv = stat(filename, &sb);
    if (rv == -1)
	return false;

    if (!S_ISREG(sb.st_mode))
	return false;

    if (sb.st_uid == getuid()) {
	if (sb.st_mode & 0400)
	    return true;
    }
    if (sb.st_gid == getgid()) {
	if (sb.st_mode & 0040)
	    return true;
    }
    if (sb.st_mode & 0004)
	return true;

    return false;
}

#endif /* _WIN32 */
