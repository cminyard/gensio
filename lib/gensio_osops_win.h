/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#define ERRHANDLE()			\
do {								\
    int err = 0;						\
    if (rv < 0) {						\
	if (errno == WSAEINTR)					\
	    goto retry;						\
	if (errno == WSAEWOULDBLOCK)				\
	    rv = 0; /* Handle like a zero-byte write. */	\
	else {							\
	    err = errno;					\
	    assert(err);					\
	}							\
    } else if (rv == 0) {					\
	err = WSAECONNRESET;					\
    }								\
    if (!err && rcount)						\
	*rcount = rv;						\
    rv = gensio_os_err_to_err(o, err);				\
} while(0)

int
gensio_os_close_socket(struct gensio_os_funcs *o, int *fd)
{
    int err;

    /* Don't do errtrig on close, it can fail and not cause any issues. */

    assert(*fd != -1);
    err = closesocket(*fd);
#ifdef ENABLE_INTERNAL_TRACE
    /* Close should never fail, but don't crash in production builds. */
    if (err) {
	err = errno;
	assert(0);
    }
#endif
    *fd = -1;

    if (err == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_set_non_blocking(struct gensio_os_funcs *o, int fd)
{
    unsigned long flags = 1;
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    rv = ioctlsocket(fd, FIONBIO, &flags);
    if (rv)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

const char *
gensio_os_check_tcpd_ok(int new_fd, const char *iprogname)
{
    return NULL;
}

int
gensio_os_get_random(struct gensio_os_funcs *o,
		     void *data, unsigned int len)
{
    return 0; /* FIXME */
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
    default:			err = GE_OSERR;
    }

    if (err == GE_OSERR) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled OS error in %s:%d: %s (%d)", caller, lineno,
		   strerror(oserr), oserr);
    }

    return err;
}

int
gensio_os_close(struct gensio_os_funcs *o, int *fd)
{
    return gensio_os_close_socket(o, fd);
}

int
gensio_os_write(struct gensio_os_funcs *o,
		int fd, const struct gensio_sg *sg, gensiods sglen,
		gensiods *rcount)
{
    return GE_NOTSUP;
}

int
gensio_os_read(struct gensio_os_funcs *o,
	       int fd, void *buf, gensiods buflen, gensiods *rcount)
{
    return GE_NOTSUP;
}
