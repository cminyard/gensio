/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include <sys/uio.h>
#ifdef HAVE_TCPD_H
#include <tcpd.h>
#endif /* HAVE_TCPD_H */
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#define ERRHANDLE()			\
do {								\
    int err = 0;						\
    if (rv < 0) {						\
	if (errno == EINTR)					\
	    goto retry;						\
	if (errno == EWOULDBLOCK || errno == EAGAIN)		\
	    rv = 0; /* Handle like a zero-byte write. */	\
	else {							\
	    err = errno;					\
	    assert(err);					\
	}							\
    } else if (rv == 0) {					\
	err = EPIPE;						\
    }								\
    if (!err && rcount)						\
	*rcount = rv;						\
    rv = gensio_os_err_to_err(o, err);				\
} while(0)

int
gensio_os_write(struct gensio_iod *iod,
		const struct gensio_sg *sg, gensiods sglen,
		gensiods *rcount)
{
    struct gensio_os_funcs *o = iod->f;
    ssize_t rv;

    if (do_errtrig())
	return GE_NOMEM;

    if (sglen == 0) {
	if (rcount)
	    *rcount = 0;
	return 0;
    }
 retry:
    rv = writev(iod->fd, (struct iovec *) sg, sglen);
    ERRHANDLE();
    return rv;
}

int
gensio_os_read(struct gensio_iod *iod,
	       void *buf, gensiods buflen, gensiods *rcount)
{
    struct gensio_os_funcs *o = iod->f;
    ssize_t rv;

    if (do_errtrig())
	return GE_NOMEM;

    if (buflen == 0) {
	if (rcount)
	    *rcount = 0;
	return 0;
    }
 retry:
    rv = read(iod->fd, buf, buflen);
    ERRHANDLE();
    return rv;
}

static int
close_socket(struct gensio_os_funcs *o, int fd)
{
    int err;

    /* Don't do errtrig on close, it can fail and not cause any issues. */

    assert(fd != -1);
    err = close(fd);
#ifdef ENABLE_INTERNAL_TRACE
    /* Close should never fail, but don't crash in production builds. */
    if (err) {
	err = errno;
	assert(0);
    }
#endif

    if (err == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_close(struct gensio_iod **iodp)
{
    struct gensio_iod *iod = *iodp;
    struct gensio_os_funcs *o = iod->f;
    int err;

    /* Don't do errtrig on close, it can fail and not cause any issues. */

    assert(iodp);
    assert(!iod->handlers_set);
    err = close(iod->fd);
#ifdef ENABLE_INTERNAL_TRACE
    /* Close should never fail, but don't crash in production builds. */
    if (err) {
	err = errno;
	assert(0);
    }
#endif
    o->release_iod(iod);
    *iodp = NULL;

    if (err == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_setupnewprog(void)
{
    struct passwd *pw;
    int err;
    uid_t uid = geteuid();
    gid_t *groups = NULL;
    int ngroup = 0;

    if (do_errtrig())
	return GE_NOMEM;

    if (uid == getuid())
	return 0;

    err = seteuid(getuid());
    if (err)
	return errno;

    pw = getpwuid(uid);
    if (!pw)
	return errno;

    getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroup);
    if (ngroup > 0) {
	groups = malloc(sizeof(gid_t) * ngroup);
	if (!groups)
	    return ENOMEM;

	err = getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroup);
	if (err == -1) {
	    err = errno;
	    free(groups);
	    return err;
	}

	err = setgroups(err, groups);
	if (err) {
	    err = errno;
	    free(groups);
	    return err;
	}
	free(groups);
    }

    err = setgid(getegid());
    if (err)
	return errno;

    err = setuid(uid);
    if (err)
	return errno;
    return 0;
}

static int
set_non_blocking(struct gensio_os_funcs *o, int fd)
{
    if (do_errtrig())
	return GE_NOMEM;

    if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
	return gensio_os_err_to_err(o, errno);
    return 0;
}

int
gensio_os_set_non_blocking(struct gensio_iod *iod)
{
    return set_non_blocking(iod->f, iod->fd);
}

const char *
gensio_os_check_tcpd_ok(struct gensio_iod *iod, const char *iprogname)
{
#ifdef HAVE_TCPD_H
    struct request_info req;

    if (!iprogname)
	iprogname = progname;
    request_init(&req, RQ_DAEMON, iprogname, RQ_FILE, iod->fd, NULL);
    fromhost(&req);

    if (!hosts_access(&req))
	return "Access denied\r\n";
#endif

    return NULL;
}

int
gensio_os_get_random(struct gensio_os_funcs *o,
		     void *data, unsigned int len)
{
    int fd;
    int rv;

    if (do_errtrig())
	return GE_NOMEM;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1)
	return gensio_os_err_to_err(o, errno);

    while (len > 0) {
	rv = read(fd, data, len);
	if (rv < 0) {
	    rv = errno;
	    goto out;
	}
	len -= rv;
	data += rv;
    }

    rv = 0;

 out:
    close(fd);
    return gensio_os_err_to_err(o, rv);
}

int
gensio_os_is_regfile(struct gensio_iod *iod, bool *isfile)
{
    int err;
    struct stat statb;

    err = fstat(iod->fd, &statb);
    if (err == -1) {
	err = gensio_os_err_to_err(iod->f, errno);
	return err;
    }
    *isfile = (statb.st_mode & S_IFMT) == S_IFREG;
    return 0;
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
    case ENOMEM:	err = GE_NOMEM; break;
    case EINVAL:	err = GE_INVAL; break;
    case ENOENT:	err = GE_NOTFOUND; break;
    case EEXIST:	err = GE_EXISTS; break;
    case EBUSY:		err = GE_INUSE; break;
    case EINPROGRESS:	err = GE_INPROGRESS; break;
    case ETIMEDOUT:	err = GE_TIMEDOUT; break;
    case EPIPE:		err = GE_REMCLOSE; break;
    case ECONNRESET:	err = GE_REMCLOSE; break;
    case EHOSTUNREACH:	err = GE_HOSTDOWN; break;
    case ECONNREFUSED:	err = GE_CONNREFUSE; break;
    case EIO:		err = GE_IOERR; break;
    case EADDRINUSE:	err = GE_ADDRINUSE; break;
    case EINTR:		err = GE_INTERRUPTED; break;
    case ESHUTDOWN:     err = GE_SHUTDOWN; break;
    case EMSGSIZE:      err = GE_TOOBIG; break;
    case EPERM:         err = GE_PERM; break;
    case EACCES:        err = GE_PERM; break;
    default:		err = GE_OSERR;
    }

    if (err == GE_OSERR) {
	gensio_log(o, GENSIO_LOG_INFO,
		   "Unhandled OS error in %s:%d: %s (%d)", caller, lineno,
		   strerror(oserr), oserr);
    }

    return err;
}
