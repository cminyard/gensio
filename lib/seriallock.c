/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include "seriallock.h"

#if USE_UUCP_LOCKING

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <signal.h>
#include <gensio/gensio.h>

static char *uucp_lck_dir = UUCP_LOCK_DIR;
static char *dev_prefix = "/dev/";

static int
uucp_fname_lock(struct gensio_os_funcs *o, const char *devname,
		char **rname)
{
    size_t dev_prefix_len = strlen(dev_prefix), len, i;
    char *name;

    if (strncmp(dev_prefix, devname, dev_prefix_len) == 0)
	devname += dev_prefix_len;

    /*
     * Format is "/var/lock/LCK..<devname>".  The 7 is for
     * the "/LCK.." and the final nil char.
     */
    len = 7 + strlen(uucp_lck_dir) + strlen(devname);

    name = o->zalloc(o, len);
    if (!name)
	return GE_NOMEM;

    snprintf(name, len, "%s/LCK..%s", uucp_lck_dir, devname);
    for (i = strlen(uucp_lck_dir) + 1; name[i]; i++) {
	if (name[i] == '/')
	    name[i] = '_';
    }

    *rname = name;
    return 0;
}

static int
uucp_svr4_lock(struct gensio_os_funcs *o, int fd, char **rname)
{
    struct stat stat;
    size_t len;
    int maj, min;
    char *name;

    if (fstat(fd, &stat) == -1)
	return gensio_os_err_to_err(o, errno);

#if 0
    /* Should we do this? */
    if (!S_ISCHR(stat.st_mode))
	return GE_INCONSISTENT;
#endif

    maj = major(stat.st_rdev);
    min = minor(stat.st_rdev);

    if (maj > 999 || min > 999)
	return GE_INVAL;

    /*
     * Format is "/var/lock/LCK.mmm.iii" where mmm is the major number
     * and iii is the minor number.  The 13 is for the "/LCK.mmm.iii"
     * and the final nil char.
     */
    len = strlen(uucp_lck_dir) + 13;
    name = o->zalloc(o, len);
    if (!name)
	return GE_NOMEM;

    snprintf(name, len, "%s/LCK.%3.3d.%3.3d", uucp_lck_dir, maj, min);

    *rname = name;
    return 0;
}

static int
alloc_lock_names(struct gensio_os_funcs *o,
		 int fd, const char *devname, char **rname1, char **rname2)
{
    char *name1 = NULL, *name2 = NULL;
    int err;

    err = uucp_fname_lock(o, devname, &name1);
    if (!err)
	err = uucp_svr4_lock(o, fd, &name2);
    if (err) {
	if (name2)
	    o->free(o, name2);
    } else {
	*rname1 = name1;
	*rname2 = name2;
    }
    return err;
}

static void
uucp_rm_lock(struct gensio_os_funcs *o, int fd, const char *devname)
{
    char *lck_file1, *lck_file2;
    int err;

    if (!gensio_uucp_locking_enabled) return;

    err = alloc_lock_names(o, fd, devname, &lck_file1, &lck_file2);
    if (err)
	return;

    unlink(lck_file1);
    unlink(lck_file2);
    o->free(o, lck_file1);
    o->free(o, lck_file2);
}

static int
write_full(int fd, char *data, size_t count)
{
    ssize_t written;

 restart:
    while ((written = write(fd, data, count)) > 0) {
	data += written;
	count -= written;
    }
    if (written < 0) {
	if (errno == EAGAIN)
	    goto restart;
	return -1;
    }
    return 0;
}

static int
check_lock_file(const char *lck_file)
{
    int n, fd, pid = 0;
    union {
	uint32_t ival;
	char     str[64];
    } buf;

    if ((fd = open(lck_file, O_RDONLY)) >= 0) {
	n = read(fd, &buf, sizeof(buf) - 1);
	close(fd);
	if (n == 4) 		/* Kermit-style lockfile. */
	    pid = buf.ival;
	else if (n > 0) {		/* Ascii lockfile. */
	    buf.str[n] = '\0';
	    sscanf(buf.str, "%10d", &pid);
	}

	if (pid > 0 && kill((pid_t)pid, 0) < 0 && errno == ESRCH) {
	    /* death lockfile - remove it */
	    unlink(lck_file);
	    pid = 0;
	}
    }

    return pid;
}

static int
uucp_mk_lock(struct gensio_os_funcs *o, int fd, const char *devname)
{
    struct stat stt;
    int pid = -1, err;

    if (!gensio_uucp_locking_enabled)
	return 0;

    if (stat(uucp_lck_dir, &stt) == 0) { /* is lock file directory present? */
	char *lck_file1, *lck_file2;
	union {
	    uint32_t ival;
	    char     str[64];
	} buf;
	int lockfd;

	err = alloc_lock_names(o, fd, devname, &lck_file1, &lck_file2);
	if (err)
	    return err;

	pid = check_lock_file(lck_file1);
	if (pid == 0)
	    pid = check_lock_file(lck_file2);

	if (pid == 0) {
	    int mask;

	    mask = umask(022);
	    lockfd = open(lck_file1, O_WRONLY | O_CREAT | O_EXCL, 0666);
	    umask(mask);
	    if (lockfd >= 0) {
	        ssize_t rv;

		snprintf(buf.str, sizeof(buf), "%10ld\n",
			 (long)getpid());
		rv = write_full(lockfd, buf.str, strlen(buf.str));
		close(lockfd);
		if (rv < 0) {
		    pid = -1;
		    unlink(lck_file1);
		} else {
		    link(lck_file1, lck_file2);
		}
	    } else {
		pid = -1;
	    }
	}

	o->free(o, lck_file1);
	o->free(o, lck_file2);
    }

    if (pid < 0) {
	gensio_log(o, GENSIO_LOG_ERR, "Error accessing locks in %s: %s",
		   uucp_lck_dir, strerror(errno));
	return GE_NOTFOUND;
    } else if (pid > 0) {
	gensio_log(o, GENSIO_LOG_ERR, "Port in use by pid %d", pid);
	return GE_INUSE;
    }
    return 0;
}

#else

static void
uucp_rm_lock(struct gensio_os_funcs *o, int fd, const char *devname)
{
}

static int
uucp_mk_lock(struct gensio_os_funcs *o, int fd, const char *devname)
{
    return 0;
}

#endif /* USE_UUCP_LOCKING */

#if USE_FLOCK_LOCKING
#include <stdio.h>
#include <sys/file.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <gensio/gensio.h>

static void
flock_rm_lock(struct gensio_os_funcs *o, int fd)
{
    flock(fd, LOCK_UN);
    ioctl(fd, TIOCNXCL);
}

static int
flock_mk_lock(struct gensio_os_funcs *o, int fd)
{
    int rv;

    rv = flock(fd, LOCK_EX | LOCK_NB);
    if (rv != 0) {
	if (errno == EWOULDBLOCK)
	    rv = GE_INUSE;
	else
	    rv = gensio_os_err_to_err(o, errno);
    }
    if (rv == 0) {
	rv = ioctl(fd, TIOCEXCL);
	if (rv != 0)
	    rv = gensio_os_err_to_err(o, errno);
    }
    return rv;
}

#else

static void
flock_rm_lock(struct gensio_os_funcs *o, int fd)
{
}

static int
flock_mk_lock(struct gensio_os_funcs *o, int fd)
{
    return 0;
}

#endif

void
serial_rm_lock(struct gensio_os_funcs *o,
	       bool do_uucp_lock, bool do_flock,
	       int fd, const char *devname)
{
    if (do_uucp_lock)
	uucp_rm_lock(o, fd, devname);
    if (do_flock)
	flock_rm_lock(o, fd);
}

int
serial_mk_lock(struct gensio_os_funcs *o,
	       bool do_uucp_lock, bool do_flock,
	       int fd, const char *devname)
{
    int err = 0;

    if (do_uucp_lock)
	err = uucp_mk_lock(o, fd, devname);
    if (!err && do_flock) {
	err = flock_mk_lock(o, fd);
	if (err)
	    uucp_rm_lock(o, fd, devname);
    }

    return err;
}
