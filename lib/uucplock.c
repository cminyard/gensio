/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"
#include "uucplock.h"

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
#include <signal.h>
#include <gensio/gensio_os_funcs.h>

static char *uucp_lck_dir = UUCP_LOCK_DIR;
static char *dev_prefix = "/dev/";

static size_t
uucp_fname_lock_size(char *devname)
{
    size_t dev_prefix_len = strlen(dev_prefix);

    if (strncmp(dev_prefix, devname, dev_prefix_len) == 0)
	devname += dev_prefix_len;

    /*
     * Format is "/var/lock/LCK..<devname>".  The 7 is for
     * the "/LCK.." and the final nil char.
     */
    return 7 + strlen(uucp_lck_dir) + strlen(devname);
}

static void
uucp_fname_lock(char *buf, char *devname)
{
    size_t i, dev_prefix_len = strlen(dev_prefix);

    if (strncmp(dev_prefix, devname, dev_prefix_len) == 0)
	devname += dev_prefix_len;

    sprintf(buf, "%s/LCK..%s", uucp_lck_dir, devname);
    for (i = strlen(uucp_lck_dir) + 1; buf[i]; i++) {
	if (buf[i] == '/')
	    buf[i] = '_';
    }
}

void
uucp_rm_lock(char *devname)
{
    char *lck_file;

    if (!gensio_uucp_locking_enabled) return;

    lck_file = malloc(uucp_fname_lock_size(devname));
    if (lck_file == NULL) {
	return;
    }
    uucp_fname_lock(lck_file, devname);
    unlink(lck_file);
    free(lck_file);
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

int
uucp_mk_lock(struct gensio_os_funcs *o, char *devname)
{
    struct stat stt;
    int pid = -1;

    if (!gensio_uucp_locking_enabled)
	return 0;

    if (stat(uucp_lck_dir, &stt) == 0) { /* is lock file directory present? */
	char *lck_file;
	union {
	    uint32_t ival;
	    char     str[64];
	} buf;
	int fd;

	lck_file = malloc(uucp_fname_lock_size(devname));
	if (lck_file == NULL)
	    return gensio_os_err_to_err(o, errno);

	uucp_fname_lock(lck_file, devname);

	pid = 0;
	if ((fd = open(lck_file, O_RDONLY)) >= 0) {
	    int n;

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

	if (pid == 0) {
	    int mask;

	    mask = umask(022);
	    fd = open(lck_file, O_WRONLY | O_CREAT | O_EXCL, 0666);
	    umask(mask);
	    if (fd >= 0) {
	        ssize_t rv;

		snprintf(buf.str, sizeof(buf), "%10ld\n",
			 (long)getpid());
		rv = write_full(fd, buf.str, strlen(buf.str));
		close(fd);
		if (rv < 0) {
		    pid = -1;
		    unlink(lck_file);
		}
	    } else {
		pid = -1;
	    }
	}

	free(lck_file);
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

void
uucp_rm_lock(char *devname)
{
}

int
uucp_mk_lock(struct gensio_os_funcs *o, char *devname)
{
    return 0;
}

#endif /* USE_UUCP_LOCKING */
