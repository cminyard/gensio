/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <winsock2.h>
#include <windows.h>

const char *
gensio_os_check_tcpd_ok(struct gensio_iod *iod, const char *iprogname)
{
    return NULL;
}

#include <bcrypt.h>
#include <ntstatus.h>

int
gensio_os_get_random(struct gensio_os_funcs *o,
		     void *data, unsigned int len)
{
    NTSTATUS rv;
    BCRYPT_ALG_HANDLE alg;
    int err = 0;

    rv = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM,
				     MS_PRIMITIVE_PROVIDER, 0);
    if (rv != STATUS_SUCCESS)
	return gensio_os_err_to_err(o, rv);
    rv = BCryptGenRandom(alg, data, len, 0);
    if (rv)
	err = gensio_os_err_to_err(o, rv);
    BCryptCloseAlgorithmProvider(alg, 0);
    return err;
}

int
gensio_i_os_err_to_err(struct gensio_os_funcs *o,
		       int oserr, const char *caller, const char *file,
		       unsigned int lineno)
{
    int err;

    if (oserr == 0)
	return 0;

    switch(oserr) {
    case WSAEINVAL:		err = GE_INVAL; break;
    case WSAEINPROGRESS:	err = GE_INPROGRESS; break;
    case WSAETIMEDOUT:		err = GE_TIMEDOUT; break;
    case WSAECONNRESET:		err = GE_REMCLOSE; break;
    case WSAEHOSTUNREACH:	err = GE_HOSTDOWN; break;
    case WSAECONNREFUSED:	err = GE_CONNREFUSE; break;
    case WSAEADDRINUSE:		err = GE_ADDRINUSE; break;
    case WSAEINTR:		err = GE_INTERRUPTED; break;
    case WSAESHUTDOWN:		err = GE_SHUTDOWN; break;
    case WSAEMSGSIZE:		err = GE_TOOBIG; break;
    case WSAEACCES:		err = GE_PERM; break;
    case WSAEWOULDBLOCK:	err = GE_INPROGRESS; break;

    case STATUS_NOT_FOUND:	err = GE_NOTFOUND; break;
    case STATUS_INVALID_PARAMETER: err = GE_INVAL; break;
    case STATUS_NO_MEMORY:	err = GE_NOMEM; break;

    case ERROR_NOT_ENOUGH_MEMORY: err = GE_NOMEM; break;
    case ERROR_BROKEN_PIPE:	err = GE_REMCLOSE; break;
    case ERROR_FILE_NOT_FOUND:	err = GE_NOTFOUND; break;
    case ERROR_NOT_FOUND:	err = GE_NOTFOUND; break;
    default:			err = GE_OSERR;
    }

    if (err == GE_OSERR) {
	char errbuf[128];

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      oserr, 0, errbuf, sizeof(errbuf), NULL);
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled OS error in %s:%d: %s (%d)", caller, lineno,
		   errbuf, oserr);
    }

    return err;
}
