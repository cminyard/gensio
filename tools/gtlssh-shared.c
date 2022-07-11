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

#include "config.h"
#ifdef _WIN32
#include <winsock2.h>
#include <Windows.h>
#include <Lmcons.h>
#include <ntsecapi.h>
#include <userenv.h>
#endif

#include "gtlssh.h"
#include "utils.h"
#include <stdio.h>

/* Should use sysconf to get this eventually. */
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

#define GTLSSHDIR DIRSEPS ".gtlssh"

#ifdef _WIN32

static void
set_lsa_string(LSA_STRING *a, const char *b)
{
    a->Length = (USHORT) strlen(b);
    a->MaximumLength = (USHORT)(a->Length + sizeof(*b));
    a->Buffer = (char *) b;
}

static void
add_unicode_str(UNICODE_STRING *ustr, const char *str, unsigned int len,
		char **pos)
{
    unsigned int blen = len * sizeof(wchar_t);

    ustr->Buffer = (wchar_t *) *pos;
    mbstowcs(ustr->Buffer, str, len);
    ustr->Length = blen;
    ustr->MaximumLength = blen;
    *pos += blen;
}

int
win_get_user(gtlssh_logger logger, void *cbdata,
	     const char *user, const char *src_module,
	     bool interactive, TOKEN_GROUPS *extra_groups, HANDLE *userh)
{
    HANDLE lsah;
    NTSTATUS rv;
    DWORD err = 0;
    void *login_info= NULL;
    LSA_STRING package_name;
    ULONG package_auth;
    DWORD user_chars = mbstowcs(NULL, user, strlen(user));
    DWORD user_bytes = user_chars * sizeof(wchar_t);
    wchar_t *wuser = NULL;
    bool domain_user;
    DWORD logon_len;
    char *pos;
    TOKEN_SOURCE token_source;
    LSA_STRING origin_name;
    void *profile = NULL;
    DWORD profile_len = 0;
    LUID logon_id;
    HANDLE htok;
    QUOTA_LIMITS quota_limits;
    NTSTATUS sub_status;
    PROFILEINFOW profile_info = { 0 };
    SECURITY_LOGON_TYPE logon_type;

    if (interactive) {
	LSA_STRING name;
	LSA_OPERATIONAL_MODE dummy1;

	/* Interactive, get a token we can use for that. */
	set_lsa_string(&name, src_module);
	rv = LsaRegisterLogonProcess(&name, &lsah, &dummy1);
    } else {
	/* Just getting information, no need for a token requiring auth. */
	rv = LsaConnectUntrusted(&lsah);
    }
    if (rv)
	return LsaNtStatusToWinError(rv);

    domain_user = strchr(user, '\\');

    if (domain_user)
	set_lsa_string(&package_name, MICROSOFT_KERBEROS_NAME_A);
    else
	set_lsa_string(&package_name, MSV1_0_PACKAGE_NAME);
    rv = LsaLookupAuthenticationPackage(lsah, &package_name, &package_auth);
    if (rv) {
	err = LsaNtStatusToWinError(rv);
	goto out_err;
    }

    if (domain_user) {
	/* look up the Kerb authentication provider's index */
	KERB_S4U_LOGON *s4u_logon;

	/*
	 * KERB_S4U_LOGON must be passed as a single contiguous buffer
	 * that includes all strings, otherwise LsaLogonUser will
	 * complain.  Add an extra char for the termination, just in
	 * case.
	 */
	logon_len = sizeof(KERB_S4U_LOGON) + user_bytes;
	s4u_logon = calloc(logon_len + sizeof(wchar_t), 1);
	if (!s4u_logon) {
	    err = STATUS_NO_MEMORY;
	    goto out_err;
	}
	s4u_logon->MessageType = KerbS4ULogon;
	if (interactive)
	    s4u_logon->Flags = KERB_S4U_LOGON_FLAG_IDENTIFY;
	pos = (char *) (s4u_logon + 1);
	add_unicode_str(&s4u_logon->ClientUpn, user, user_chars, &pos);
	login_info = s4u_logon;
	logon_type = Network;
    } else {
	MSV1_0_S4U_LOGON *s4u_logon;

	/*
	 * MSV1_o_S4U_LOGON must be passed as a single contiguous
	 * buffer that includes all strings, otherwise LsaLogonUser
	 * will complain.  Add an extra char for the termination, just
	 * in case.
	 */
	logon_len = sizeof(MSV1_0_S4U_LOGON) + user_bytes + sizeof(wchar_t);
	s4u_logon = (MSV1_0_S4U_LOGON *) calloc(logon_len +
						sizeof(wchar_t), 1);
	if (!s4u_logon) {
	    err = STATUS_NO_MEMORY;
	    goto out_err;
	}
	s4u_logon->MessageType = MsV1_0S4ULogon;
	pos = (char *) (s4u_logon + 1);

	add_unicode_str(&s4u_logon->UserPrincipalName, user, user_chars, &pos);
	add_unicode_str(&s4u_logon->DomainName, ".", 1, &pos);

	login_info = s4u_logon;
	logon_type = Network;
    }

    /*
     * This information is copied into the resulting token.  Note that
     * SourceName is an 8 character ASCII buffer.
     */
    AllocateLocallyUniqueId(&token_source.SourceIdentifier);
    strncpy(token_source.SourceName, src_module, 7);
    token_source.SourceName[7] = 0;

    set_lsa_string(&origin_name, src_module);

    rv = LsaLogonUser(lsah, &origin_name, logon_type, package_auth,
		      login_info, logon_len, extra_groups, &token_source,
		      &profile, &profile_len, &logon_id, &htok,
		      &quota_limits, &sub_status);
    if (rv) {
	err = LsaNtStatusToWinError(rv);
	goto out_err;
    }

    if (interactive) {
	MSV1_0_INTERACTIVE_PROFILE *iprofile;

	iprofile = (MSV1_0_INTERACTIVE_PROFILE *) profile;
	if (iprofile->MessageType == MsV1_0InteractiveProfile)
	    profile_info.lpServerName = iprofile->LogonServer.Buffer;

	profile_info.dwSize = sizeof(profile_info);
	profile_info.dwFlags = PI_NOUI;
	wuser = calloc(user_bytes + sizeof(wchar_t), 1);
	if (!wuser) {
	    err = STATUS_NO_MEMORY;
	    goto out_err;
	}
	mbstowcs(wuser, user, user_chars);
	profile_info.lpUserName = wuser;
	if (!LoadUserProfileW(htok, &profile_info)) {
	    err = GetLastError();
	    goto out_err;
	}
    }

    *userh = htok;

 out_err:
    if (profile_info.hProfile)
	UnloadUserProfile(htok, profile_info.hProfile);
    if (wuser)
	free(wuser);
    if (login_info)
	free(login_info);
    if (profile)
	LsaFreeReturnBuffer(profile);
    if (lsah)
	LsaDeregisterLogonProcess (lsah);
    LsaClose(lsah);

    return err;
}

char *
get_homedir(gtlssh_logger logger, void *cbdata,
	    const char *username, const char *extra)
{
    DWORD extra_len = 0;
    char *dir;

    if (!extra)
	extra = "";
    extra_len = strlen(extra);

    if (!username) {
	DWORD drive_len = 0, path_len, rv;
	bool have_userprofile = false;

	path_len = GetEnvironmentVariable("USERPROFILE", NULL, 0);
	if (path_len != 0) {
	    path_len--;
	    have_userprofile = true;
	} else {
	    drive_len = GetEnvironmentVariable("HOMEDRIVE", NULL, 0);
	    if (drive_len == 0) {
		logger(cbdata, "No HOMEDRIVE or USERPROFILE set\n");
		return NULL;
	    }
	    /* Docs say return value includes the nil terminator. */
	    drive_len--;
	    path_len = GetEnvironmentVariable("HOMEPATH", NULL, 0);
	    if (path_len == 0) {
		logger(cbdata, "No HOMEPATH or USERPROFILE set\n");
		return NULL;
	    }
	    path_len--;
	}

	dir = malloc(drive_len + path_len + extra_len + 1);
	if (!dir) {
	    logger(cbdata, "Out of memory allocating home dir\n");
	    return NULL;
	}

	if (have_userprofile) {
	    rv = GetEnvironmentVariable("USERPROFILE", dir, path_len + 1);
	    if (rv != path_len) {
		logger(cbdata, "No USERPROFILE set\n");
		return NULL;
	    }
	} else {
	    rv = GetEnvironmentVariable("HOMEDRIVE", dir, drive_len + 1);
	    if (rv != drive_len) {
		logger(cbdata, "No HOMEDRIVE set\n");
		return NULL;
	    }
	    rv = GetEnvironmentVariable("HOMEPATH", dir + drive_len,
					path_len + 1);
	    if (rv != path_len) {
		logger(cbdata, "No HOMEPATH set\n");
		return NULL;
	    }
	}
	strncpy(dir + drive_len + path_len, extra, extra_len + 1);
    } else {
	HANDLE userh = NULL;
	DWORD err, len;
	char dummy[1];

	err = win_get_user(logger, cbdata, username, "gtlssh", false, NULL,
			   &userh);
	if (err) {
	    char errbuf[128];

	    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
			  err, 0, errbuf, sizeof(errbuf), NULL);
	    logger(cbdata, "Could not get user: %s\n", errbuf);
	    return NULL;
	}

	len = 0;
	if (!GetUserProfileDirectoryA(userh, dummy, &len) &&
		(GetLastError() != ERROR_INSUFFICIENT_BUFFER)) {
	    char errbuf[128];

	    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
			  GetLastError(), 0, errbuf, sizeof(errbuf), NULL);
	    logger(cbdata, "GetUserProfileDirectory: %s\n", errbuf);
	    CloseHandle(userh);
	    return NULL;
	}
	dir = malloc(len + extra_len);
	if (!dir) {
	    logger(cbdata, "Out of memory allocating home dir\n");
	    CloseHandle(userh);
	    return NULL;
	}
	GetUserProfileDirectoryA(userh, dir, &len);
	CloseHandle(userh);
	strncpy(dir + len - 1, extra, extra_len + 1);
    }

    return dir;
}

char *
get_my_username(gtlssh_logger logger, void *cbdata)
{
    char *username = malloc(UNLEN + 1);
    DWORD len = UNLEN + 1;

    if (!username) {
	logger(cbdata, "out of memory allocating username\n");
	return NULL;
    }

    if (!GetUserNameA(username, &len)) {
	DWORD err = GetLastError();
	char errbuf[128];

	free(username);
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	logger(cbdata, "Could not get username: %s\n", errbuf);
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
#include <errno.h>

char *
get_homedir(gtlssh_logger logger, void *cbdata,
	    const char *username, const char *extra)
{
    char *dir;

    if (!extra)
	extra = "";

    if (!username) {
	const char *home = getenv("HOME");

	if (!home) {
	    logger(cbdata, "No home directory set\n");
	    return NULL;
	}

	dir = alloc_sprintf("%s%s", home, extra);
    } else {
	struct passwd *pw = getpwnam(username);
	
	dir = alloc_sprintf("%s%s", pw->pw_dir, extra);
    }

    if (!dir) {
	logger(cbdata, "Out of memory allocating gtlssh dir\n");
	return NULL;
    }

    return dir;
}

char *
get_my_username(gtlssh_logger logger, void *cbdata)
{
    struct passwd *pw = getpwuid(getuid());
    char *username;

    if (!pw) {
	logger(cbdata, "no username given, and can't look up UID\n");
	return NULL;
    }
    username = strdup(pw->pw_name);
    if (!username) {
	logger(cbdata, "out of memory allocating username\n");
	return NULL;
    }

    return username;
}

#endif /* _WIN32 */

char *
get_tlsshdir(gtlssh_logger logger, void *cbdata,
	     const char *username, const char *extra)
{
    char *hextra = GTLSSHDIR;
    bool hextra_alloced = false;
    char *dir;

    if (extra) {
	hextra = alloc_sprintf("%s%s", GTLSSHDIR, extra);
	if (!hextra) {
	    logger(cbdata, "Could not allocate tlsshdir\n");
	    return NULL;
	}
	hextra_alloced = true;
    }
    dir = get_homedir(logger, cbdata, username, hextra);
    if (hextra_alloced)
	free(hextra);
    return dir;
}

char *
get_my_hostname(gtlssh_logger logger, void *cbdata)
{
    char hostname[HOST_NAME_MAX + 1];

#ifdef _WIN32
    struct gensio_os_funcs *o;
    gensio_default_os_hnd(0, &o);
#endif

    if (gethostname(hostname, sizeof(hostname)) != 0) {
#ifdef _WIN32
	int err = WSAGetLastError();
	char errbuf[128];

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	logger(cbdata, "Could not get hostname: %s\n", errbuf);
#else
	logger(cbdata, "Could not get hostname: %s\n", strerror(errno));
#endif
	return NULL;
    }
    return strdup(hostname);
}

