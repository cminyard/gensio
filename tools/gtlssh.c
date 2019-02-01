/*
 *  gtlssh - A program for shell over TLS with gensios
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <termios.h>
#include <gensio/gensio.h>
#include <pwd.h>

#include "ioinfo.h"
#include "ser_ioinfo.h"
#include "utils.h"

unsigned int debug;

struct gdata {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    struct gensio *user_io;
    struct gensio *io;
    const char *ios;
    bool can_close;
};

static void
gshutdown(struct ioinfo *ioinfo)
{
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    ginfo->o->wake(ginfo->waiter);
}

static void
gerr(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    fprintf(stderr, "Error on %s: \n", ginfo->ios);
    vfprintf(stderr, fmt, ap);
}

static void
gout(struct ioinfo *ioinfo, char *fmt, va_list ap)
{
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    char str[200];

    vsnprintf(str, sizeof(str), fmt, ap);
    gensio_write(ginfo->user_io, NULL, str, strlen(str), NULL);
}

static int
getpassword(char *pw, gensiods *len)
{
    int fd = open("/dev/tty", O_RDWR);
    struct termios old_termios, new_termios;
    int err = 0;
    gensiods pos = 0;
    char c = 0;
    static char *prompt = "Password: ";

    if (fd == -1) {
	err = errno;
	fprintf(stderr, "Unable to open controlling terminal: %s\n",
		strerror(err));
	return err;
    }

    err = tcgetattr(fd, &old_termios);
    if (err == -1) {
	err = errno;
	fprintf(stderr, "Unable to get terminal information: %s\n",
		strerror(err));
	return err;
    }

    new_termios = old_termios;
    new_termios.c_lflag &= ~ECHO;

    err = tcsetattr(fd, TCSANOW, &new_termios);
    if (err == -1) {
	err = errno;
	fprintf(stderr, "Unable to set terminal information: %s\n",
		strerror(err));
	return err;
    }

    write(fd, prompt, strlen(prompt));
    while (true) {
	err = read(fd, &c, 1);
	if (err) {
	    err = errno;
	    fprintf(stderr, "Error reading password: %s\n", strerror(err));
	    goto out;
	}
	if (c != '\r' && c != '\n')
	    break;
	if (pos < *len)
	    pw[pos++] = c;
    }
    if (pos < *len)
	pw[pos++] = '\0';
    *len = pos;
    
 out:
    tcsetattr(fd, TCSANOW, &old_termios);
    return err;
}

static int
gevent(struct ioinfo *ioinfo, struct gensio *io, int event,
       int err, unsigned char *buf, gensiods *buflen,
       const char *const *auxdata)
{
    switch (event) {
    case GENSIO_EVENT_REQUEST_PASSWORD:
	return getpassword((char *) buf, buflen);

    default:
	return ENOTSUP;
    }
}

static struct ioinfo_user_handlers guh = {
    .shutdown = gshutdown,
    .err = gerr,
    .out = gout,
    .event = gevent
};

static void
io_open(struct gensio *io, int err, void *open_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    if (err) {
	ginfo->can_close = false;
	fprintf(stderr, "open error on %s: %s", ginfo->ios, strerror(err));
	gshutdown(ioinfo);
    } else {
	ioinfo_set_ready(ioinfo, io);
    }
}

static void
io_close(struct gensio *io, void *close_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    struct gensio_waiter *closewaiter = close_data;

    ginfo->o->wake(closewaiter);
}

static const char *progname;
static const char *io1_default_tty = "serialdev,/dev/tty";
static const char *io1_default_notty = "stdio(self)";

static void
help(int err)
{
    printf("%s [options] io2\n", progname);
    printf("\nA program to connect gensios together.  This programs has two\n");
    printf("gensios, io1 (default is local terminal) and io2 (must be set).\n");
    printf("\noptions are:\n");
    printf("  -i, --input <gensio) - Set the io1 device, default is\n"
	   "    %s for tty or %s for non-tty stdin\n",
	   io1_default_tty, io1_default_notty);
    printf("  -d, --debug - Enable debug.  Specify more than once to increase\n"
	   "    the debug level\n");
    printf("  -a, --accepter - Accept a connection on io2 instead of"
	   " initiating a connection\n");
    printf("  --signature <sig> - Set the RFC2217 server signature to <sig>\n");
    printf("  -e, --escchar - Set the local terminal escape character.\n"
	   "    Set to 0 to disable the escape character\n"
	   "    Default is ^\\ for tty stdin and disabled for non-tty stdin\n");
    printf("  -h, --help - This help\n");
    exit(err);
}

static void
do_vlog(struct gensio_os_funcs *f, enum gensio_log_levels level,
	const char *log, va_list args)
{
    if (!debug)
	return;
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
}

static int
lookup_certfiles(const char *tlssh_dir, const char *username,
		 const char *hostname, int port,
		 char **rCAdir, char **rcertfile, char **rkeyfile)
{
    char *CAdir = NULL, *certfile = NULL, *keyfile = NULL;
    int err = ENOMEM;

    CAdir = alloc_sprintf("%s/server_certs", tlssh_dir);
    if (!CAdir) {
	fprintf(stderr, "Error allocating memory for CAdir\n");
	return ENOMEM;
    }

    certfile = alloc_sprintf("%s/default.cert", tlssh_dir);
    if (!certfile) {
	fprintf(stderr, "Error allocating memory for certificate file\n");
	goto out_err;
    }

    keyfile = alloc_sprintf("%s/default.key", tlssh_dir);
    if (!keyfile) {
	fprintf(stderr, "Error allocating memory for private key file\n");
	goto out_err;
    }

    err = checkout_file(CAdir, true);
    if (err)
	goto out_err;

    err = checkout_file(certfile, false);
    if (err)
	goto out_err;

    err = checkout_file(keyfile, false);
    if (err)
	goto out_err;

    err = ENOMEM;
    *rCAdir = alloc_sprintf("CA=%s/", CAdir);
    if (!*rCAdir)
	goto out_err;
    *rcertfile = alloc_sprintf(",cert=%s", certfile);
    if (!*rcertfile) {
	free(*rCAdir);
	*rCAdir = NULL;
	goto out_err;
    }
    *rkeyfile = alloc_sprintf(",key=%s", keyfile);
    if (!*rkeyfile) {
	free(*rcertfile);
	*rcertfile = NULL;
	free(*rCAdir);
	*rCAdir = NULL;
	goto out_err;
    }

    err = 0;

 out_err:
    if (CAdir)
	free(CAdir);
    if (certfile)
	free(certfile);
    if (keyfile)
	free(keyfile);
    return err;
}

int
main(int argc, char *argv[])
{
    int arg, rv;
    struct gensio_waiter *closewaiter;
    unsigned int closecount = 0;
    int escape_char = -1;
    struct gensio_os_funcs *o;
    struct ioinfo_sub_handlers *sh1 = NULL, *sh2 = NULL;
    void *subdata1 = NULL, *subdata2 = NULL;
    struct ioinfo *ioinfo1, *ioinfo2;
    struct gdata userdata1, userdata2;
    char *s, *username, *hostname, *keyfile, *certfile, *CAdir;
    char *tlssh_dir = NULL;
    int port = 2190, err;
    char *do_telnet = "";

    memset(&userdata1, 0, sizeof(userdata1));
    memset(&userdata2, 0, sizeof(userdata2));

    progname = argv[0];

    if (isatty(0)) {
	escape_char = 0x1c; /* ^\ */
	userdata1.ios = io1_default_tty;
    } else {
	userdata1.ios = io1_default_notty;
    }

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != '-')
	    break;
	if (strcmp(argv[arg], "--") == 0) {
	    arg++;
	    break;
	}
	if ((rv = cmparg_int(argc, argv, &arg, "-e", "--escchar",
			     &escape_char))) {
	    ;
	} else if ((rv = cmparg(argc, argv, &arg, "-r", "--telnet", NULL))) {
	    do_telnet = "telnet(rfc2217)";
	} else if ((rv = cmparg(argc, argv, &arg, "-d", "--debug", NULL))) {
	    debug++;
	    if (debug > 1)
		gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else if ((rv = cmparg(argc, argv, &arg, "-h", "--help", NULL)))
	    help(0);
	else {
	    fprintf(stderr, "Unknown argument: %s\n", argv[arg]);
	    help(1);
	}
	if (rv < 0)
	    return 1;
    }

    if (arg >= argc) {
	fprintf(stderr, "No string given to connect to\n");
	help(1);
    }

    s = strrchr(argv[arg], '@');
    if (s) {
	*s++ = '\0';
	username = argv[arg];
	hostname = s;
    } else {
	struct passwd *pw = getpwuid(getuid());

	if (!pw) {
	    fprintf(stderr, "no usename given, and can't look up UID\n");
	    return 1;
	}
	username = strdup(pw->pw_name);
	if (!username) {
	    fprintf(stderr, "out of memory allocating username\n");
	    return 1;
	}
	hostname = argv[arg];
    }

    if (!tlssh_dir) {
	const char *home = getenv("HOME");

	if (!home) {
	    fprintf(stderr, "No home directory set\n");
	    return 1;
	}

	tlssh_dir = alloc_sprintf("%s/.gtlssh", home);
	if (!tlssh_dir) {
	    fprintf(stderr, "Out of memory allocating gtlssh dir\n");
	    return 1;
	}
    }

    err = checkout_file(tlssh_dir, true);
    if (err)
	return 1;

    err = lookup_certfiles(tlssh_dir, username, hostname, port,
			   &CAdir, &certfile, &keyfile);
    if (err)
	return 1;

    s = alloc_sprintf("%scertauth(username=%s%s%s),ssl(%s),tcp,%s,%p",
		      do_telnet, username, certfile, keyfile,
		      CAdir, hostname, port);
    if (!s) {
	fprintf(stderr, "out of memory allocating IO string\n");
	return 1;
    }
    userdata2.ios = s;

    rv = gensio_default_os_hnd(0, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n", strerror(rv));
	return 1;
    }
    o->vlog = do_vlog;

    userdata1.o = o;
    userdata2.o = o;

    userdata1.waiter = o->alloc_waiter(o);
    if (!userdata1.waiter) {
	fprintf(stderr, "Could not allocate OS waiter: %s\n", strerror(rv));
	return 1;
    }
    userdata2.waiter = userdata1.waiter;

    closewaiter = o->alloc_waiter(o);
    if (!closewaiter) {
	fprintf(stderr, "Could not allocate close waiter: %s\n", strerror(rv));
	return 1;
    }

    subdata1 = alloc_ser_ioinfo(0, "", &sh1);
    if (!subdata1) {
	fprintf(stderr, "Could not allocate subdata 1\n");
	return 1;
    }
    subdata2 = alloc_ser_ioinfo(0, "", &sh2);
    if (!subdata2) {
	fprintf(stderr, "Could not allocate subdata 2\n");
	return 1;
    }

    ioinfo1 = alloc_ioinfo(o, escape_char, sh1, subdata1, &guh, &userdata1);
    if (!ioinfo1) {
	fprintf(stderr, "Could not allocate ioinfo 1\n");
	return 1;
    }

    ioinfo2 = alloc_ioinfo(o, 0, sh2, subdata1, &guh, &userdata2);
    if (!ioinfo2) {
	fprintf(stderr, "Could not allocate ioinfo 2\n");
	return 1;
    }

    ioinfo_set_otherioinfo(ioinfo1, ioinfo2);

    rv = str_to_gensio(userdata1.ios, o, NULL, ioinfo1, &userdata1.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n",
		userdata1.ios, strerror(rv));
	return 1;
    }

    userdata1.user_io = userdata1.io;
    userdata2.user_io = userdata1.io;

    rv = str_to_gensio(userdata2.ios, o, NULL, ioinfo2, &userdata2.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", userdata2.ios,
		strerror(rv));
	return 1;
    }

    userdata1.can_close = true;
    rv = gensio_open(userdata1.io, io_open, NULL);
    if (rv) {
	userdata1.can_close = false;
	fprintf(stderr, "Could not open %s: %s\n", userdata1.ios, strerror(rv));
	return 1;
    }

    userdata2.can_close = true;
    rv = gensio_open(userdata2.io, io_open, NULL);
    if (rv) {
	userdata2.can_close = false;
	fprintf(stderr, "Could not open %s: %s\n", userdata2.ios,
		strerror(rv));
	goto close1;
    }

    o->wait(userdata1.waiter, 1, NULL);

    if (userdata2.can_close) {
	rv = gensio_close(userdata2.io, io_close, closewaiter);
	if (rv)
	    printf("Unable to close %s: %s\n", userdata2.ios, strerror(rv));
	else
	    closecount++;
    }

 close1:
    if (userdata1.can_close) {
	rv = gensio_close(userdata1.io, io_close, closewaiter);
	if (rv)
	    printf("Unable to close %s: %s\n", userdata1.ios, strerror(rv));
	else
	    closecount++;
    }

    if (closecount > 0) {
	o->wait(closewaiter, closecount, NULL);
    }

    gensio_free(userdata1.io);
    if (userdata2.io)
	gensio_free(userdata2.io);

    o->free_waiter(closewaiter);
    o->free_waiter(userdata1.waiter);

    free_ioinfo(ioinfo1);
    free_ioinfo(ioinfo2);
    free_ser_ioinfo(subdata1);
    free_ser_ioinfo(subdata2);

    return 0;
}
