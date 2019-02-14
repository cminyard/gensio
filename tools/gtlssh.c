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
    char *ios;
    bool can_close;
};

char *username, *hostname, *keyfile, *certfile, *CAdir;
char *tlssh_dir = NULL;
int port = 852;

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
    fprintf(stderr, "\n");
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
	goto out_close;
    }

    new_termios = old_termios;
    new_termios.c_lflag &= ~ECHO;

    err = tcsetattr(fd, TCSANOW, &new_termios);
    if (err == -1) {
	err = errno;
	fprintf(stderr, "Unable to set terminal information: %s\n",
		strerror(err));
	goto out_close;
    }

    err = write(fd, prompt, strlen(prompt));
    if (err == -1) {
	fprintf(stderr, "Error writing password prompt, giving up: %s\n",
		strerror(errno));
	exit(1);
    }
    while (true) {
	err = read(fd, &c, 1);
	if (err < 0) {
	    err = errno;
	    fprintf(stderr, "Error reading password: %s\n", strerror(err));
	    goto out;
	}
	if (c == '\r' || c == '\n')
	    break;
	if (pos < *len)
	    pw[pos++] = c;
    }
    err = 0;
    printf("\n");
    if (pos < *len)
	pw[pos++] = '\0';
    *len = pos;

 out:
    tcsetattr(fd, TCSANOW, &old_termios);
 out_close:
    close(fd);
    return err;
}

static struct ioinfo_user_handlers guh = {
    .shutdown = gshutdown,
    .err = gerr,
    .out = gout
};

static void
io_close(struct gensio *io, void *close_data)
{
    struct ioinfo *ioinfo = gensio_get_user_data(io);
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    struct gensio_waiter *closewaiter = close_data;

    ginfo->o->wake(closewaiter);
}

static const char *progname;
static char *io1_default_tty = "serialdev,/dev/tty";
static char *io1_default_notty = "stdio(self)";

static void
help(int err)
{
    printf("%s [options] hostname [program]\n", progname);
    printf("\nA program to connect to a remote system over TLS.  The\n");
    printf("hostname is the remote system.  If no program is given and\n");
    printf("if stdin is a tty, the connection is interactive.  Otherwise\n");
    printf("the connection is not interactive and buffered.\n");
    printf("\noptions are:\n");
    printf("  -p, --port <port> - Use the given port instead of the default.");
    printf("  -i, --keyfile <file> - Use the given file for the key instead\n"
	   "    of the default.  The certificate will default to the same\n"
	   "    name ending in .crt");
    printf("  --certfile <file> - Set the certificate to use.\n");
    printf("  -r, --telnet - Do telnet processing with RFC2217 handling.\n");
    printf("  -e, --escchar - Set the local terminal escape character.\n"
	   "    Set to -1 to disable the escape character\n"
	   "    Default is ^\\ for tty stdin and disabled for non-tty stdin\n");
    printf("  --nosctp - Disable SCTP support.\n");
    printf("  --notcp - Disable TCP support.\n");
    printf("  -d, --debug - Enable debug.  Specify more than once to increase\n"
	   "    the debug level\n");
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
    fprintf(stderr, "\r\n");
}

static int
lookup_certfiles(const char *tlssh_dir, const char *username,
		 const char *hostname, int port,
		 char **rCAdir, char **rcertfile, char **rkeyfile)
{
    int err = GE_NOMEM;

    if (!CAdir) {
	CAdir = alloc_sprintf("%s/server_certs", tlssh_dir);
	if (!CAdir) {
	    fprintf(stderr, "Error allocating memory for CAdir\n");
	    return GE_NOMEM;
	}
    }

    if (!certfile) {
	certfile = alloc_sprintf("%s/keycerts/%s,%d.crt", tlssh_dir,
				 hostname, port);
	if (!certfile)
	    goto cert_nomem;
	if (file_is_readable(certfile)) {
	    keyfile = alloc_sprintf("%s/keycerts/%s,%d.key", tlssh_dir,
				    hostname, port);
	    goto found_cert;
	}
	free(certfile);
	certfile = alloc_sprintf("%s/keycerts/%s.crt", tlssh_dir, hostname);
	if (!certfile)
	    goto cert_nomem;
	if (file_is_readable(certfile)) {
	    keyfile = alloc_sprintf("%s/keycerts/%s.key", tlssh_dir, hostname);
	    goto found_cert;
	}
	free(certfile);

	certfile = alloc_sprintf("%s/default.crt", tlssh_dir);
	if (!certfile) {
	cert_nomem:
	    fprintf(stderr, "Error allocating memory for certificate file\n");
	    goto out_err;
	}
	keyfile = alloc_sprintf("%s/default.key", tlssh_dir);
    found_cert:
	if (!keyfile) {
	    fprintf(stderr, "Error allocating memory for private key file\n");
	    goto out_err;
	}
    }

    err = checkout_file(CAdir, true, false);
    if (err)
	goto out_err;

    err = checkout_file(certfile, false, false);
    if (err)
	goto out_err;

    err = checkout_file(keyfile, false, true);
    if (err)
	goto out_err;

    err = GE_NOMEM;
    *rCAdir = alloc_sprintf("CA=%s/", CAdir);
    if (!*rCAdir)
	goto out_err;
    *rcertfile = alloc_sprintf(",cert=%s", certfile);
    if (!*rcertfile) {
	*rCAdir = NULL;
	goto out_err;
    }
    *rkeyfile = alloc_sprintf(",key=%s", keyfile);
    if (!*rkeyfile) {
	*rcertfile = NULL;
	*rCAdir = NULL;
	goto out_err;
    }

    err = 0;

 out_err:
    return err;
}

static int
add_certfile(struct gensio_os_funcs *o, const char *cert, const char *fmt, ...)
{
    int rv;
    va_list va;
    char *filename;

    va_start(va, fmt);
    filename = alloc_vsprintf(fmt, va);
    va_end(va);
    if (!filename) {
	fprintf(stderr, "Out of memory allocating filename");
	return GE_NOMEM;
    }

    rv = open(filename, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (rv == -1 && errno == EEXIST) {
	fprintf(stderr,
		"Certificate file %s already exists, this means the\n"
		"certificate has changed.  Someone may be trying to\n"
		"intercept your communications.  Giving up, remove the\n"
		"file if it is incorrect and try again\n", filename);
	rv = GE_KEYINVALID;
    } else if (rv == -1) {
	rv = errno;
	fprintf(stderr, "Error opening '%s', could not save certificate: %s\n",
		filename, strerror(rv));
	rv = gensio_os_err_to_err(o, rv);
    } else {
	int fd = rv, len = strlen(cert);

    retry:
	rv = write(fd, cert, len);
	if (rv == -1) {
	    rv = errno;
	    fprintf(stderr, "Error writing '%s', could not save certificate:"
		    " %s\n", filename, strerror(rv));
	    rv = gensio_os_err_to_err(o, rv);
	    goto out;
	} else if (rv != len) {
	    len -= rv;
	    cert += rv;
	    goto retry;
	}
	rv = 0;

    out:
	close(fd);
    }

    free(filename);
    return rv;
}

static int
verify_certfile(struct gensio_os_funcs *o,
		const char *cert, const char *fmt, ...)
{
    int rv;
    va_list va;
    char *filename;
    char cmpcert[16384];

    va_start(va, fmt);
    filename = alloc_vsprintf(fmt, va);
    va_end(va);
    if (!filename) {
	fprintf(stderr, "Out of memory allocating filename");
	return GE_NOMEM;
    }

    rv = open(filename, O_RDONLY);
    if (rv == -1) {
	fprintf(stderr,
		"Unable to open certificate file at %s: %s\n", filename,
		strerror(errno));
	rv = GE_CERTNOTFOUND;
    } else {
	int fd = rv, len = strlen(cert);

	rv = read(fd, cmpcert, sizeof(cmpcert));
	if (rv == -1) {
	    rv = errno;
	    fprintf(stderr, "Error reading '%s', could not verify certificate:"
		    " %s\n", filename, strerror(rv));
	    rv = gensio_os_err_to_err(o, rv);
	    goto out;
	} else if (rv != len) {
	    fprintf(stderr, "Certificate at '%s': length mismatch\n", filename);
	    rv = GE_CERTINVALID;
	    goto out;
	} else if (memcmp(cert, cmpcert, len) != 0) {
	    fprintf(stderr, "Certificate at '%s': compare failure\n", filename);
	    rv = GE_CERTINVALID;
	    goto out;
	}
	rv = 0;

    out:
	close(fd);
    }

    free(filename);
    return rv;
}

static int
auth_event(struct gensio *io, void *user_data, int event, int ierr,
	   unsigned char *ibuf, gensiods *buflen,
	   const char *const *auxdata)
{
    struct ioinfo *ioinfo = user_data;
    struct gdata *ginfo = ioinfo_userdata(ioinfo);
    struct gensio *ssl_io;
    char raddr[256];
    char fingerprint[256];
    char cert[16384];
    char buf[100];
    char *cmd;
    gensiods len;
    int err;

    switch (event) {
    case GENSIO_EVENT_POSTCERT_VERIFY:
	ssl_io = io;
	while (ssl_io) {
	    if (strcmp(gensio_get_type(ssl_io, 0), "ssl") == 0)
		break;
	    ssl_io = gensio_get_child(ssl_io, 1);
	}
	if (!ssl_io) {
	    fprintf(stderr, "SSL was not in the gensio stack?\n");
	    return GE_INVAL;
	}

	len = sizeof(cert);
	err = gensio_control(ssl_io, 0, true, GENSIO_CONTROL_CERT,
			     cert, &len);
	if (err) {
	    fprintf(stderr, "Error getting certificate: %s\n",
		    gensio_err_to_str(err));
	    return GE_NOMEM;
	}
	if (len >= sizeof(cert)) {
	    fprintf(stderr, "certificate is too large");
	    return GE_NOMEM;
	}

	gensio_raddr_to_str(ssl_io, NULL, raddr, sizeof(raddr));

	if (!ierr) {
	    /* Found a certificate, make sure it's the right one. */
	    err = verify_certfile(ginfo->o,
				  cert, "%s/%s,%d.crt", CAdir, hostname, port);
	    if (!err)
		err = verify_certfile(ginfo->o,
				      cert, "%s/%s.crt", CAdir, raddr);
	    if (err == GE_CERTNOTFOUND) {
		printf("\nCertificate for %s found and correct, but"
		       " address file was\nmissing for it an/or\n  %s\n",
		       hostname, raddr);
		printf("It is possible that the same key is used for"
		       " different connections,\n but"
		       " there may also be aman in the middle\n");
		printf("Verify carefully, add if it is ok.\n");
		do {
		    char *s;

		    printf("Add this certificate? (y/n): ");
		    s = fgets(buf, sizeof(buf), stdin);
		    if (s == NULL) {
			printf("Error reading input, giving up\n");
			exit(1);
		    }
		    if (buf[0] == 'y') {
			err = 0;
			break;
		    } else if (buf[0] == 'n') {
			err = GE_AUTHREJECT;
			break;
		    } else {
			printf("Invalid input: %s", buf);
		    }
		} while (true);
		if (!err) {
		    err = add_certfile(ginfo->o, cert,
				       "%s/%s,%d.crt", CAdir, hostname, port);
		    if (!err)
			err = add_certfile(ginfo->o, cert,
					   "%s/%s.crt", CAdir, raddr);
		}
	    }
	    return err;
	}

	/*
	 * Called from the SSL layer if the certificate provided by
	 * the server didn't have a match.
	 */
	if (ierr != GE_CERTNOTFOUND) {
	    const char *errstr = "probably didn't match host certificate.";
	    if (ierr == GE_CERTREVOKED)
		errstr = "is revoked";
	    else if (ierr == GE_CERTEXPIRED)
		errstr = "is expired";
	    fprintf(stderr, "Certificate for %s failed validation: %s\n",
		    hostname, auxdata[0]);
	    fprintf(stderr,
		    "Certificate from remote, and possibly in\n"
		    "  %s/%s,%d.crt\n"
		    "or\n"
		    "  %s/%s.crt\n"
		    "%s\n",
		    CAdir, hostname, port, CAdir, raddr, errstr);
	    return ierr;
	}

	/* Key was not present, ask the user if that is ok. */
	len = sizeof(fingerprint);
	err = gensio_control(ssl_io, 0, true, GENSIO_CONTROL_CERT_FINGERPRINT,
			     fingerprint, &len);
	if (err) {
	    fprintf(stderr, "Error getting fingerprint: %s\n",
		    gensio_err_to_str(err));
	    return GE_CERTINVALID;
	}
	if (len >= sizeof(fingerprint)) {
	    fprintf(stderr, "fingerprint is too large\n");
	    return GE_CERTINVALID;
	}

	printf("Certificate for %s", hostname);
	if (strcmp(hostname, raddr) != 0)
	    printf(" %s\n", raddr);
	printf(" is not present, fingerprint is:\n%s\n", fingerprint);
	printf("Please validate the fingerprint and verify if you want it\n"
	       "added to the set of valid servers.\n");
	do {
	    char *s;

	    printf("Add this certificate? (y/n): ");
	    s = fgets(buf, sizeof(buf), stdin);
	    if (s == NULL) {
		printf("Error reading input, giving up\n");
		exit(1);
	    }
	    if (buf[0] == 'y') {
		err = 0;
		break;
	    } else if (buf[0] == 'n') {
		err = GE_AUTHREJECT;
		break;
	    } else {
		printf("Invalid input: %s", buf);
	    }
	} while (true);

	if (err)
	    return err;

	len = sizeof(cert);
	err = gensio_control(ssl_io, 0, true, GENSIO_CONTROL_CERT,
			     cert, &len);
	if (err) {
	    fprintf(stderr, "Error getting certificate: %s\n",
		    gensio_err_to_str(err));
	    return GE_NOMEM;
	}
	if (len >= sizeof(cert)) {
	    fprintf(stderr, "certificate is too large");
	    return GE_NOMEM;
	}

	err = add_certfile(ginfo->o,
			   cert, "%s/%s,%d.crt", CAdir, hostname, port);
	if (!err)
	    err = add_certfile(ginfo->o, cert, "%s/%s.crt", CAdir, raddr);

	cmd = alloc_sprintf("gtlssh-keygen rehash %s", CAdir);
	if (!cmd) {
	    fprintf(stderr, "Could not allocate memory for rehash, skipping\n");
	} else {
	    int rv = system(cmd);

	    if (rv != 0)
		fprintf(stderr, "Error from %s, rehash skipped\n", cmd);

	    free(cmd);
	}

	return err;

    case GENSIO_EVENT_REQUEST_PASSWORD:
	return getpassword((char *) ibuf, buflen);

    default:
	return GE_NOTSUP;
    }
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
    char *s;
    int err;
    char *do_telnet = "";
    char *CAdirspec = NULL, *certfilespec = NULL, *keyfilespec = NULL;
    const char *service = "login:";
    char *free_service = NULL;
    bool interactive = true;
    const char *transport = "sctp";
    bool notcp = false, nosctp = false;

    memset(&userdata1, 0, sizeof(userdata1));
    memset(&userdata2, 0, sizeof(userdata2));

    progname = argv[0];

    if (isatty(0)) {
	escape_char = 0x1c; /* ^\ */
	userdata1.ios = io1_default_tty;
    } else {
	userdata1.ios = io1_default_notty;
	interactive = false;
    }

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != '-')
	    break;
	if (strcmp(argv[arg], "--") == 0) {
	    arg++;
	    break;
	}
	if ((rv = cmparg(argc, argv, &arg, "-i", "--keyfile", &keyfile))) {
	    if (!certfile) {
		char *dotpos = strrchr(keyfile, '.');

		if (dotpos)
		    *dotpos = '\0';
		certfile = alloc_sprintf("%s.crt", keyfile);
		if (dotpos)
		    *dotpos = '.';
		if (!certfile) {
		    fprintf(stderr, "Unable to allocate memory for certfile\n");
		    exit(1);
		}
	    }
	} else if ((rv = cmparg_int(argc, argv, &arg, "-p", "--port",
				    &port))) {
	    ;
	} else if ((rv = cmparg(argc, argv, &arg, NULL, "--certfile",
				&certfile))) {
	    ;
	} else if ((rv = cmparg_int(argc, argv, &arg, "-e", "--escchar",
			     &escape_char))) {
	    ;
	} else if ((rv = cmparg(argc, argv, &arg, NULL, "--notcp", NULL))) {
	    notcp = true;
	} else if ((rv = cmparg(argc, argv, &arg, NULL, "--nosctp", NULL))) {
	    nosctp = true;
	} else if ((rv = cmparg(argc, argv, &arg, "-r", "--telnet", NULL))) {
	    do_telnet = "telnet(rfc2217),";
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

    if (nosctp && notcp) {
	fprintf(stderr, "You cannot disable both TCP and SCTP\n");
	exit(1);
    }

    if (nosctp)
	transport = "tcp";

    if (!!certfile != !!keyfile) {
	fprintf(stderr,
		"If you specify a certfile, you must specify a keyfile\n");
	exit(1);
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

    arg++;
    if (arg < argc) {
	/* User gave us a remote program. */
	free_service = alloc_sprintf("program:%s", argv[arg]);
	if (!free_service) {
	    fprintf(stderr, "Unable to allocate remote program request\n");
	    return 1;
	}
	service = free_service;
	userdata1.ios = io1_default_notty;
	interactive = false;
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

    err = checkout_file(tlssh_dir, true, true);
    if (err)
	return 1;

    rv = gensio_default_os_hnd(0, &o);
    if (rv) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    o->vlog = do_vlog;

    userdata1.o = o;
    userdata2.o = o;

    userdata1.waiter = o->alloc_waiter(o);
    if (!userdata1.waiter) {
	fprintf(stderr, "Could not allocate OS waiter\n");
	return 1;
    }
    userdata2.waiter = userdata1.waiter;

    closewaiter = o->alloc_waiter(o);
    if (!closewaiter) {
	fprintf(stderr, "Could not allocate close waiter\n");
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

    ioinfo2 = alloc_ioinfo(o, 0, sh2, subdata2, &guh, &userdata2);
    if (!ioinfo2) {
	fprintf(stderr, "Could not allocate ioinfo 2\n");
	return 1;
    }

    ioinfo_set_otherioinfo(ioinfo1, ioinfo2);

    rv = str_to_gensio(userdata1.ios, o, NULL, ioinfo1, &userdata1.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n",
		userdata1.ios, gensio_err_to_str(rv));
	return 1;
    }

    userdata1.user_io = userdata1.io;
    userdata2.user_io = userdata1.io;

    err = lookup_certfiles(tlssh_dir, username, hostname, port,
			   &CAdirspec, &certfilespec, &keyfilespec);
    if (err)
	return 1;

 retry:
    s = alloc_sprintf("%scertauth(username=%s,service=%s%s%s,),"
		      "ssl(%s),%s,%s,%d",
		      do_telnet, username, service, certfilespec, keyfilespec,
		      CAdirspec, transport, hostname, port);
    if (!s) {
	fprintf(stderr, "out of memory allocating IO string\n");
	return 1;
    }
    userdata2.ios = s;

    rv = str_to_gensio(userdata2.ios, o, auth_event, ioinfo2, &userdata2.io);
    if (rv) {
	fprintf(stderr, "Could not allocate %s: %s\n", userdata2.ios,
		gensio_err_to_str(rv));
	return 1;
    }

    if (interactive) {
	rv = gensio_control(userdata2.io, GENSIO_CONTROL_DEPTH_ALL, false,
			    GENSIO_CONTROL_NODELAY, "1", NULL);
	if (rv) {
	    fprintf(stderr, "Could not set nodelay on %s: %s\n", userdata2.ios,
		    gensio_err_to_str(rv));
	    return 1;
	}
    }

    userdata2.can_close = true;
    rv = gensio_open_s(userdata2.io);
    if (rv) {
	userdata2.can_close = false;
	fprintf(stderr, "Could not open %s: %s\n", userdata2.ios,
		gensio_err_to_str(rv));
	if (strcmp(transport, "sctp") == 0 && !notcp) {
	    fprintf(stderr, "Falling back to tcp\n");
	    free(userdata2.ios);
	    userdata2.ios = NULL;
	    transport = "tcp";
	    goto retry;
	}
	goto closeit;
    }

    ioinfo_set_ready(ioinfo2, userdata2.io);

    userdata1.can_close = true;
    rv = gensio_open_s(userdata1.io);
    if (rv) {
	userdata1.can_close = false;
	fprintf(stderr, "Could not open %s: %s\n",
		userdata1.ios, gensio_err_to_str(rv));
	goto closeit;
    }
    ioinfo_set_ready(ioinfo1, userdata1.io);

    o->wait(userdata1.waiter, 1, NULL);

 closeit:
    if (userdata2.can_close) {
	rv = gensio_close(userdata2.io, io_close, closewaiter);
	if (rv)
	    printf("Unable to close %s: %s\n", userdata2.ios,
		   gensio_err_to_str(rv));
	else
	    closecount++;
    }

    if (userdata1.can_close) {
	rv = gensio_close(userdata1.io, io_close, closewaiter);
	if (rv)
	    printf("Unable to close %s: %s\n", userdata1.ios,
		   gensio_err_to_str(rv));
	else
	    closecount++;
    }

    if (closecount > 0) {
	o->wait(closewaiter, closecount, NULL);
    }

    if (CAdirspec)
	free(CAdirspec);
    if (certfilespec)
	free(certfilespec);
    if (keyfilespec)
	free(keyfilespec);

    gensio_free(userdata1.io);
    gensio_free(userdata2.io);

    if (userdata2.ios)
	free(userdata2.ios);
    o->free_waiter(closewaiter);
    o->free_waiter(userdata1.waiter);

    free_ioinfo(ioinfo1);
    free_ioinfo(ioinfo2);
    free_ser_ioinfo(subdata1);
    free_ser_ioinfo(subdata2);

    return 0;
}
