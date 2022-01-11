/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GENSIO_ERR_H
#define GENSIO_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

struct gensio_os_funcs;
#include <gensio/gensio_dllvisibility.h>

#define GE_NOERR		0
#define GE_NOMEM		1
#define GE_NOTSUP		2
#define GE_INVAL		3
#define GE_NOTFOUND		4
#define GE_EXISTS		5
#define GE_OUTOFRANGE		6
#define GE_INCONSISTENT		7
#define GE_NODATA		8
#define GE_OSERR		9
#define GE_INUSE		10
#define GE_INPROGRESS		11
#define GE_NOTREADY		12
#define GE_TOOBIG		13
#define GE_TIMEDOUT		14
#define GE_RETRY		15
#define GE_errblank_xxx		16
#define GE_KEYNOTFOUND		17
#define GE_CERTREVOKED		18
#define GE_CERTEXPIRED		19
#define GE_KEYINVALID		20
#define GE_NOCERT		21
#define GE_CERTINVALID		22
#define GE_PROTOERR		23
#define GE_COMMERR		24
#define GE_IOERR		25
#define GE_REMCLOSE		26
#define GE_HOSTDOWN		27
#define GE_CONNREFUSE		28
#define GE_DATAMISSING		29
#define GE_CERTNOTFOUND		30
#define GE_AUTHREJECT		31
#define GE_ADDRINUSE		32
#define GE_INTERRUPTED		33
#define GE_SHUTDOWN		34
#define GE_LOCALCLOSED		35
#define GE_PERM			36
#define GE_APPERR		37
#define GE_UNKNOWN_NAME_ERROR	38
#define GE_NAME_ERROR		39
#define GE_NAME_SERVER_FAILURE	40
#define GE_NAME_INVALID		41
#define GE_NAME_NET_NOT_UP	42

/*
 * Gensio mux has the ability to return an arbitrary error from the
 * new channel event that is passed back to the open_channel() return
 * error.  This range can be used to pass back an arbitrary error or
 * information.
 */
#define GE_USER_CHAN_ERR_BASE	10000
#define GE_USER_CHAN_ERR_END	10999

/*
 * Users can define their own error code, but they must be >= the
 * following value.  gensio will never return an error in that range.
 */
#define GE_USER_ERR_START	1000000

#ifndef __func__ /* Just in case */
# if __STDC_VERSION__ < 199901L
#  if __GNUC__ >= 2
#   define __func__ __FUNCTION__
#  else
#   define __func__ "<unknown>"
#  endif
# endif
#endif

#define gensio_os_err_to_err(o, oserr)					\
    gensio_i_os_err_to_err(o, oserr, __func__, __FILE__, __LINE__)

GENSIO_DLL_PUBLIC
const char *gensio_err_to_str(int err);

GENSIO_DLL_PUBLIC
int gensio_i_os_err_to_err(struct gensio_os_funcs *o,
			   int oserr, const char *caller,
			   const char *file, unsigned int lineno);

#ifdef __cplusplus
}
#endif

#endif /* GENSIO_ERR_H */
