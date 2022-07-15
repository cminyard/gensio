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
#include <wtsapi32.h>
#include <sddl.h>
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

static DWORD
read_token_info(HANDLE h, TOKEN_INFORMATION_CLASS type, void **rval,
		DWORD *rlen)
{
    DWORD err, len = 0;
    void *val;

    if (GetTokenInformation(h, type, NULL, 0, &len))
	/* This should fail. */
	return ERROR_INVALID_DATA;
    err = GetLastError();
    if (err != ERROR_INSUFFICIENT_BUFFER)
	return err;
    val = malloc(len);
    if (!val)
	return STATUS_NO_MEMORY;
    if (!GetTokenInformation(h, type, val, len, &len)) {
	free(val);
	return GetLastError();
    }
    *rval = val;
    if (rlen)
	*rlen = len;
    return 0;
}

static DWORD
get_logon_sid_from_token(HANDLE h, SID **logon_sid, bool *found)
{
    DWORD err;
    unsigned int i;
    TOKEN_GROUPS *grps = NULL;
    SID *sid;

    err = read_token_info(h, TokenGroups, (void **) &grps, NULL);
    if (err) {
	/* Not an error if the token doesn't have groups. */
	err = 0;
	goto out_err;
    }

    /* Now scan for a logon id SID. */
    for (i = 0; i < grps->GroupCount; i++) {
	if ((grps->Groups[i].Attributes & SE_GROUP_LOGON_ID) ==
	    SE_GROUP_LOGON_ID) {
	    int len = GetLengthSid(grps->Groups[i].Sid);

	    sid = (SID *) malloc(len);
	    if (!sid) {
		err = STATUS_NO_MEMORY;
		goto out_err;
	    }
	    if (!CopySid(len, sid, grps->Groups[i].Sid)) {
		err = GetLastError();
		goto out_err;
	    }
	    *logon_sid = sid;
	    sid = NULL;
	    *found = true;
	    break;
	}
    }

 out_err:
    if (grps)
	free(grps);
    if (sid)
	free(sid);

    return err;
}

static DWORD
get_logon_sid(SID *user, SID **logon_sid, bool *rfound)
{
    DWORD err;
    unsigned int i;
    bool found = false;
    WTS_SESSION_INFOA *sesinfo = NULL;
    DWORD sescount;
    TOKEN_USER *usid = NULL;
    HANDLE h = NULL;

    /*
     * Find a session with the same user SID as the passed in user.
     */
    if (!WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1,
			       &sesinfo, &sescount)) {
	err = GetLastError();
	goto out_err;
    }

    for (i = 0; !found && i < sescount; i++) {
	if (!WTSQueryUserToken(sesinfo[i].SessionId, &h))
	    continue;

	/* Check to make sure it's our user. */
	err = read_token_info(h, TokenUser, (void **) &usid, NULL);
	if (err)
	    goto continue_scan;
	if (!EqualSid(usid->User.Sid, user))
	    goto continue_scan;

	err = get_logon_sid_from_token(h, logon_sid, &found);
	if (err)
	    goto out_err;

    continue_scan:
	if (h) {
	    CloseHandle(h);
	    h = NULL;
	}
	if (usid) {
	    free(usid);
	    usid = NULL;
	}
    }

    /* Not finding is not an error, we just report it. */
    *rfound = found;
    err = 0;

 out_err:
    if (h)
	CloseHandle(h);
    if (sesinfo)
	WTSFreeMemory(sesinfo);
    if (usid)
	free(usid);
    return err;
}

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

static DWORD
get_kerb_logon(const char *user, const char *password, bool interactive,
	       void **logon_info, DWORD *logon_info_len,
	       SECURITY_LOGON_TYPE *logon_type)
{
    DWORD user_chars = mbstowcs(NULL, user, strlen(user));
    DWORD user_bytes = user_chars * sizeof(wchar_t);
    DWORD domain_chars = strchr(user, '\\') - user;
    DWORD real_user_chars = strlen(user + domain_chars + 1);
    DWORD logon_len;
    char *pos;

    if (password) {
	DWORD pw_chars = mbstowcs(NULL, password, strlen(password));
	DWORD pw_bytes = pw_chars * sizeof(wchar_t);
	KERB_INTERACTIVE_LOGON *int_logon;

	/*
	 * KERB_S4U_LOGON must be passed as a single contiguous buffer
	 * that includes all strings, otherwise LsaLogonUser will
	 * complain.  Add an extra char for the termination, just in
	 * case.
	 */
	logon_len = sizeof(KERB_INTERACTIVE_LOGON) + user_bytes + pw_bytes;
	int_logon = calloc(logon_len + sizeof(wchar_t), 1);
	if (!int_logon)
	    return STATUS_NO_MEMORY;
	int_logon->MessageType = KerbInteractiveLogon;
	pos = (char *) (int_logon + 1);
	add_unicode_str(&int_logon->LogonDomainName, user, domain_chars, &pos);
	user += domain_chars + 1; /* SKip over domain\ */
	add_unicode_str(&int_logon->UserName, user, real_user_chars, &pos);
	add_unicode_str(&int_logon->Password, password, pw_chars, &pos);
	*logon_info = int_logon;
	*logon_type = Interactive;
    } else {
	/* look up the Kerb authentication provider's index */
	KERB_S4U_LOGON *s4u_logon;
	char *tmpstr, *upnstr;

	upnstr = malloc(user_chars + 1);
	if (!upnstr)
	    return STATUS_NO_MEMORY;
	tmpstr = upnstr;
	memcpy(tmpstr, user + domain_chars + 1, real_user_chars);
	tmpstr += real_user_chars;
	*tmpstr++ = '@';
	memcpy(tmpstr, user, domain_chars);
	tmpstr += domain_chars;
	*tmpstr = '\0';

	/*
	 * KERB_S4U_LOGON must be passed as a single contiguous buffer
	 * that includes all strings, otherwise LsaLogonUser will
	 * complain.  Add an extra char for the termination, just in
	 * case.
	 */
	logon_len = sizeof(KERB_S4U_LOGON) + user_bytes;
	s4u_logon = calloc(logon_len + sizeof(wchar_t), 1);
	if (!s4u_logon) {
	    free(upnstr);
	    return STATUS_NO_MEMORY;
	}
	s4u_logon->MessageType = KerbS4ULogon;
	if (interactive)
	    s4u_logon->Flags = KERB_S4U_LOGON_FLAG_IDENTIFY;
	pos = (char *) (s4u_logon + 1);
	add_unicode_str(&s4u_logon->ClientUpn, upnstr, user_chars, &pos);
	free(upnstr);
	*logon_info = s4u_logon;
	*logon_type = Network;
    }
    *logon_info_len = logon_len;
    return 0;
}

static DWORD
get_local_logon(const char *user, const char *password,
		void **logon_info, DWORD *logon_info_len,
		SECURITY_LOGON_TYPE *logon_type)
{
    DWORD user_chars = mbstowcs(NULL, user, strlen(user));
    DWORD user_bytes = user_chars * sizeof(wchar_t);
    DWORD logon_len;
    char *pos;

    if (password) {
	DWORD pw_chars = mbstowcs(NULL, password, strlen(password));
	DWORD pw_bytes = pw_chars * sizeof(wchar_t);
	MSV1_0_INTERACTIVE_LOGON *mi_logon;

	/*
	 * MSV1_0_INTERACTIVE_LOGON must be passed as a single
	 * contiguous buffer that includes all strings, otherwise
	 * LsaLogonUser will complain.  Add an extra char for the
	 * termination, just in case.
	 */
	logon_len = (sizeof(*mi_logon) + user_bytes + pw_bytes +
		     sizeof(wchar_t));
	mi_logon = (MSV1_0_INTERACTIVE_LOGON *) malloc(logon_len);
	if (!mi_logon)
	    return STATUS_NO_MEMORY;
	mi_logon->MessageType = MsV1_0InteractiveLogon;

	pos = (char *) (mi_logon + 1);
	add_unicode_str(&mi_logon->LogonDomainName, ".", 1, &pos);
	add_unicode_str(&mi_logon->UserName, user, user_chars, &pos);
	add_unicode_str(&mi_logon->Password, password, pw_chars, &pos);

	*logon_info = mi_logon;
	*logon_type = Interactive;
    } else {
	MSV1_0_S4U_LOGON *s4u_logon;

	/*
	 * MSV1_0_S4U_LOGON must be passed as a single contiguous
	 * buffer that includes all strings, otherwise LsaLogonUser
	 * will complain.  Add an extra char for the termination, just
	 * in case.
	 */
	logon_len = sizeof(MSV1_0_S4U_LOGON) + user_bytes + sizeof(wchar_t);
	s4u_logon = (MSV1_0_S4U_LOGON *) calloc(logon_len +
						sizeof(wchar_t), 1);
	if (!s4u_logon)
	    return STATUS_NO_MEMORY;
	s4u_logon->MessageType = MsV1_0S4ULogon;
	pos = (char *) (s4u_logon + 1);

	add_unicode_str(&s4u_logon->UserPrincipalName, user, user_chars, &pos);
	add_unicode_str(&s4u_logon->DomainName, ".", 1, &pos);

	*logon_info = s4u_logon;
	*logon_type = Network;
    }
    *logon_info_len = logon_len;
    return 0;
}

struct group_list {
    const LPTSTR name;
};
static struct group_list add_groups[] = {
    { .name = TEXT("S-1-5-32-559") }, /* BUILTIN\Performance Log Users */
    { .name = TEXT("S-1-5-14") }, /* NT AUTHORITY\REMOTE INTERACTIVE LOGON */
    { .name = TEXT("S-1-5-4") }, /* NT AUTHORITY\INTERACTIVE */
    { .name = TEXT("S-1-2-0") }, /* LOCAL */
    { .name = TEXT("S-1-5-64-36") }, /* NT AUTHORITY\Cloud Account Authentication */
    { .name = TEXT("S-1-5-64-10") }, /* NT AUTHORITY\NTLM Authentication */
};
static unsigned int add_groups_len = (sizeof(add_groups) /
				      sizeof(struct group_list));

/* Supply either isid or sidstr, not both. */
static DWORD
append_group(TOKEN_GROUPS *grps, SID *sid, const LPTSTR sidstr, DWORD attrs)
{
    SID *new_sid, *free_sid = NULL;
    size_t len;
    unsigned int i = grps->GroupCount;
    int err = 0;

    if (sidstr) {
	if (!ConvertStringSidToSid(sidstr, (void **) &free_sid))
	    return GetLastError();
	/* Can't use free_sid directly, it's allocated with LocalAlloc(). */
	sid = free_sid;
    }

    len = GetLengthSid(sid);
    new_sid = malloc(len);
    if (!new_sid) {
	err = STATUS_NO_MEMORY;
	goto out_err;
    }
    if (!CopySid(len, new_sid, sid)) {
	err = GetLastError();
	free(new_sid);
	goto out_err;
    }

    grps->Groups[i].Attributes = attrs;
    grps->Groups[i].Sid = new_sid;
    grps->GroupCount++;
 out_err:
    if (free_sid)
	LocalFree(free_sid);
    return err;
}

static void
free_groups(TOKEN_GROUPS *grps)
{
    unsigned int i;

    for (i = 0; i < grps->GroupCount; i++)
	free(grps->Groups[i].Sid);
    free(grps);
}

#if 0
static void
pr_sid(int indent, const char *str, SID *sid)
{
    char *sidstr;

    if (!sid) {
	printf("%*s%s: NULL Sid\n", indent, "", str);
    } else if (ConvertSidToStringSidA(sid, &sidstr)) {
	printf("%*s%s: %s\n", indent, "", str, sidstr);
	LocalFree(sidstr);
    } else {
	printf("%*s%s: Bad Sid\n", indent, "", str);
    }
}

static void
print_sid(const char *str, SID *sid)
{
    pr_sid(0, str, sid);
}
#endif

int
win_get_user(gtlssh_logger logger, void *cbdata,
	     const char *user, const char *password, const char *src_module,
	     bool interactive, HANDLE *userh)
{
    HANDLE lsah;
    NTSTATUS rv;
    DWORD err = 0;
    void *logon_info = NULL;
    LSA_STRING package_name;
    ULONG package_auth;
    DWORD user_chars = mbstowcs(NULL, user, strlen(user));
    DWORD user_bytes = user_chars * sizeof(wchar_t);
    wchar_t *wuser = NULL;
    bool domain_user;
    DWORD logon_len;
    TOKEN_SOURCE token_source;
    LSA_STRING origin_name;
    void *profile = NULL;
    DWORD profile_len = 0;
    LUID logon_id;
    HANDLE htok = NULL, tmptok;
    QUOTA_LIMITS quota_limits;
    NTSTATUS sub_status;
    PROFILEINFOW profile_info = { 0 };
    SECURITY_LOGON_TYPE logon_type;
    TOKEN_USER *usersid = NULL;
    SID *logon_sid = NULL;
    TOKEN_GROUPS *extra_groups = NULL;
    MSV1_0_INTERACTIVE_PROFILE *iprofile;
    bool found;
    DWORD len, i;

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

    if (domain_user)
	err = get_kerb_logon(user, password, interactive,
			     &logon_info, &logon_len, &logon_type);
    else
	err = get_local_logon(user, password, &logon_info, &logon_len,
			      &logon_type);
    if (err)
	goto out_err;

    /*
     * This information is copied into the resulting token.  Note that
     * SourceName is an 8 character ASCII buffer.
     */
    AllocateLocallyUniqueId(&token_source.SourceIdentifier);
    strncpy(token_source.SourceName, src_module, 7);
    token_source.SourceName[7] = 0;

    set_lsa_string(&origin_name, src_module);

    /*
     * Do a first run.  For just query request (not interactive) this
     * is all we need, but for interactive, we use this to pull
     * information from for the real logon.
     *
     * Pass in NULL for groups so this will generate a new logon sid,
     * which we may or may not use.
     */
    rv = LsaLogonUser(lsah, &origin_name, logon_type, package_auth,
		      logon_info, logon_len, NULL, &token_source,
		      &profile, &profile_len, &logon_id, &htok,
		      &quota_limits, &sub_status);
    if (rv) {
	err = LsaNtStatusToWinError(rv);
	goto out_err;
    }
    if (profile)
	LsaFreeReturnBuffer(profile);

    if (!interactive)
	/* We have all we need, no setup is necessary. */
	goto out_finish;

    /*
     * For interactive, the created handle does not have a proper
     * logon SID (maybe) and doesn't have the extra groups.  So we
     * will need to find the right SID and use that.  If the user is
     * currently logged on, we will pull that logon sid.  If they are
     * not, we will use the logon SID from the token we just created.
     */

    /* First find the proper logon sid. */
    err = read_token_info(htok, TokenUser, (void **) &usersid, NULL);
    if (err)
	goto out_err;
    err = get_logon_sid(usersid->User.Sid, &logon_sid, &found);
    if (err)
	goto out_err;
    if (!found) {
	/*
	 * The user isn't logged on, use the logon sid from the token.
	 * we just created.
	 */
	err = get_logon_sid_from_token(htok, &logon_sid, &found);
	if (err)
	    goto out_err;
	if (!found) {
	    err = ERROR_INVALID_DATA;
	    goto out_err;
	}
    }

    /*
     * Now add the logon sid to the extra groups.  If it's a network
     * logon, convert it to interactive by adding the proper sids.
     */
    len = sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES);
    if (logon_type == Network)
	len += add_groups_len * sizeof(SID_AND_ATTRIBUTES);
    extra_groups = (TOKEN_GROUPS *) malloc(len);
    if (!extra_groups) {
	err = STATUS_NO_MEMORY;
	goto out_err;
    }
    memset(extra_groups, 0, len);
    append_group(extra_groups, logon_sid, NULL,
		 (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT |
		  SE_GROUP_MANDATORY | SE_GROUP_LOGON_ID));
    if (logon_type == Network) {
	for (i = 0; i < add_groups_len; i++) {
	    err = append_group(extra_groups, NULL, add_groups[i].name,
			       (SE_GROUP_ENABLED |
				SE_GROUP_ENABLED_BY_DEFAULT |
				SE_GROUP_MANDATORY));
	    if (err)
		goto out_err;
	}
    }

    /* Now get the actual token. */
    rv = LsaLogonUser(lsah, &origin_name, logon_type, package_auth,
		      logon_info, logon_len, extra_groups, &token_source,
		      &profile, &profile_len, &logon_id, &tmptok,
		      &quota_limits, &sub_status);
    if (rv) {
	err = LsaNtStatusToWinError(rv);
	goto out_err;
    }
    CloseHandle(htok);
    htok = tmptok;

    /* Interactive logons should have the profile loaded. */
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

 out_finish:
    if (logon_type != Network) {
	/*
	 * We want an impersonation token.  Network tokens do that,
	 * but others do not.
	 */
	if (!DuplicateToken(htok, SecurityImpersonation, &tmptok))
	    err = GetLastError();
	CloseHandle(htok);
	htok = tmptok;
    }

    *userh = htok;
    htok = NULL;

 out_err:
    if (extra_groups)
	free_groups(extra_groups);
    if (htok)
	CloseHandle(htok);
    if (usersid)
	free(usersid);
    if (wuser)
	free(wuser);
    if (logon_info)
	free(logon_info);
    if (profile_info.hProfile)
	UnloadUserProfile(htok, profile_info.hProfile);
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

	err = win_get_user(logger, cbdata, username, NULL,
			   "gtlssh", false, &userh);
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

