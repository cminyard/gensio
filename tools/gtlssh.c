/*
 *  gtlssh - A program for shell over TLS with gensios
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gensio/gensio.h>
#include <gensio/gensio_mdns.h>
#ifdef HAVE_PRCTL
#include <sys/prctl.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif

#include "ioinfo.h"
#include "localports.h"
#include "ser_ioinfo.h"
#include "utils.h"
#include "gtlssh.h"

unsigned int debug;

struct gdata {
    struct gensio_os_funcs *o;
    struct gensio_waiter *waiter;
    struct gensio *user_io;
    struct gensio *io;
    char *ios;
    bool can_close;

    /* The following are only used on ioinfo2. */
    bool interactive;
    bool got_oob;
};

static void
gshutdown(struct ioinfo *ioinfo, bool user_req)
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

static void handle_rem_req(struct gensio *io, const char *service);

static int gevent(struct ioinfo *ioinfo, struct gensio *io, int event,
		  int ierr, unsigned char *buf, gensiods *buflen,
		  const char *const *auxdata)
{
    if (event != GENSIO_EVENT_NEW_CHANNEL)
	return GE_NOTSUP;
    handle_rem_req((struct gensio *) buf, auxdata[0]);
    return 0;
}

static void winch_ready(struct gensio_iod *iod, void *cb_data);

/*
 * We wait until the other end has signalled us to say that it is
 * ready before sending the winch.  Otherwise the winch will mess up
 * the password login process.
 */
static void
goobdata(struct ioinfo *ioinfo, unsigned char *buf, gensiods *buflen)
{
    struct gdata *ginfo = ioinfo_userdata(ioinfo);

    if (ginfo->got_oob)
	return;

    ginfo->got_oob = true;
    if (ginfo->interactive)
	winch_ready(NULL, ioinfo);
}

static struct ioinfo_user_handlers guh = {
    .shutdown = gshutdown,
    .err = gerr,
    .event = gevent,
    .out = gout,
    .oobdata = goobdata
};

static char *username, *hostname;
static char *certname, *CAname, *keyname;
static char *tlssh_dir = NULL;
static unsigned int port = 852;

static int
getpassword(struct gdata *ginfo, char *pw, gensiods *len)
{
    struct gensio *tty;
    int err = 0;
    gensiods pos = 0;
    char c = 0;
    static char *prompt = "Password: ";
    const char *constr = "stdio(console,raw)";

    err = str_to_gensio(constr, ginfo->o, NULL, NULL, &tty);
    if (err) {
	fprintf(stderr, "Unable to allocate gensio for %s: %s\n", constr,
		gensio_err_to_str(err));
	return err;
    }

    err = gensio_open_s(tty);
    if (err) {
	gensio_free(tty);
	fprintf(stderr, "Unable to open console %s: %s\n", constr,
		gensio_err_to_str(err));
	return err;
    }

    err = gensio_set_sync(tty);
    if (err) {
	fprintf(stderr, "Unable to set %s synchronous: %s\n", constr,
		gensio_err_to_str(err));
	goto out;
    }

    err = gensio_write_s(tty, NULL, prompt, strlen(prompt), NULL);
    if (err) {
	fprintf(stderr, "Error writing password prompt, giving up: %s\n",
		gensio_err_to_str(err));
	exit(1);
    }
    while (true) {
	gensiods count = 0;

	err = gensio_read_s(tty, &count, &c, 1, NULL);
	if (err) {
	    fprintf(stderr, "Error reading password: %s\n",
		    gensio_err_to_str(err));
	    goto out;
	}
	if (count != 1) {
	    fprintf(stderr,
		    "Error reading password: read didn't return data\n");
	    err = GE_IOERR;
	    goto out;
	}
	if (c == '\r' || c == '\n')
	    break;
	if (pos < *len)
	    pw[pos++] = c;
    }
    err = 0;
    gensio_write_s(tty, NULL, "\r\n", 2, NULL);
    if (pos < *len)
	pw[pos++] = '\0';
    *len = pos;

 out:
    gensio_clear_sync(tty);
    gensio_close_s(tty);
    gensio_free(tty);
    return err;
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
static char *io1_default_tty = "stdio(self,raw)";
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
    printf("  -p, --port <port> - Use the given port instead of the\n"
	   "    default.\n");
    printf("  -i, --keyname <file> - Use the given file for the key instead\n"
	   "    of the default.  The certificate will default to the same\n"
	   "    name ending in .crt\n");
    printf("  --certname <file> - Set the certificate to use.\n");
    printf("  --caname <directory> - Set the cert authority directory.\n");
    printf("  -r, --telnet - Do telnet processing with RFC2217 handling.\n");
    printf("  -e, --escchar - Set the local terminal escape character.\n"
	   "    Set to -1 to disable the escape character\n"
	   "    Default is ^\\ for tty stdin and disabled for non-tty stdin\n");
    printf("  --nosctp - Disable SCTP support (default).\n");
    printf("  --sctp - Disable SCTP support.\n");
    printf("  --notcp - Disable TCP support.\n");
    printf("  --transport - Use the given gensio instead of TCP or SCTP.\n");
    printf("    hostname is ignored in this case, except for the username\n");
    printf("    part, but is required.\n");
    printf("  -m, --mdns - Look up the name using mDNS.  This will fetch\n");
    printf("    then IP address, IPv4 or IPv6, the port number and whether\n");
    printf("    telnet is required and make the connection.\n");
    printf("  --mdns-type - Set the type used for the lookup.  See\n");
    printf("    the gmdns(1) man page under 'STRING VALUES FOR QUERIES'\n");
    printf("    for detail on how to do regex, glob, etc.\n");
    printf("  -d, --debug - Enable debug.  Specify more than once to increase\n"
	   "    the debug level\n");
    printf("  -L <accept addr>:<connect addr> - Listen at the <accept addr>\n"
	   "    on the local machine, and if a connection comes in forward it\n"
	   "    to the <connect addr> from the remote machine on the gtlssh\n"
	   "    connection.  A local address is in the form:\n"
	   "      [<bind addr>:][sctp|tcp,]port\n"
	   "    or:\n"
	   "      <unix socket path>\n"
	   "    Remote addresses are in the form:\n"
	   "      <hostname>:[sctp|tcp,]port\n"
	   "    or:\n"
	   "      <unix socket path>\n"
	   "    If a name begins with '/' it is a unix socket path.  hostname\n"
	   "    and bind addr are standard internet names or addresses.\n");
    printf("  -R <accept addr>:<connect addr> - Like -L, except the\n"
	   "    <accept addr> is on the remote machine and <connect addr> is\n"
	   "    done from the local machine\n");
    printf("  -4 - Do IPv4 only.\n");
    printf("  -6 - Do IPv6 only.\n");
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

#if HAVE_OPENSSL
#include <openssl/x509.h>
#include <openssl/pem.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_get0_notAfter(x) X509_get_notAfter(x)
#endif

#if OPENSSL_VERSION_NUMBER < 0x10002000L || defined(LIBRESSL_VERSION_NUMBER)
/* We need to provide our own backport of the ASN1_TIME_diff() function. */
#include "openssl_compat.h"
#endif

static void
translate_filename(char *filename)
{
#ifdef _WIN32
    unsigned int i;

    for (i = 0; filename[i]; i++) {
	if (i > 2 && filename[i] == ':')
	    filename[i] = '!';
    }
#endif
}

static int
check_cert_expiry(const char *name, const char *filename,
		  const char *cert, gensiods certlen)
{
    X509 *x = NULL;
    const ASN1_TIME *t = NULL;
    int days, seconds, err = 0;

    if (filename) {
	FILE *fp = fopen(filename, "r");

	if (!fp) {
	    fprintf(stderr,
		    "Unable to open %s certificate file for "
		    "expiry verification\n", name);
	    return GE_NOTFOUND;
	}
	x = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
    } else {
	BIO *cert_bio = BIO_new_mem_buf(cert, certlen);

	if (!cert_bio) {
	    fprintf(stderr, "Unable to create %s certificate BIO\n", name);
	    return GE_IOERR;
	}

	x = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
	BIO_free(cert_bio);
    }
    if (!x) {
	fprintf(stderr,
		"Unable to load %s certificate for expiry verification\n",
		name);
	return GE_IOERR;
    }

    t = X509_get0_notAfter(x);
    if (!t) {
	fprintf(stderr, "Unable to get certificate expiry time\n");
	err = GE_IOERR;
	goto out;
    }

    if (!ASN1_TIME_diff(&days, &seconds, NULL, t)) {
	fprintf(stderr, "Unable to compare certificate expiry time\n");
	err = GE_IOERR;
	goto out;
    }

    if (days < 0 || seconds < 0) {
	fprintf(stderr, "***Error: %s certificate has expired\n", name);
	err = GE_CERTEXPIRED;
	goto out;
    }

    if (days < 30)
	fprintf(stderr, "***WARNING: %s certificate will expire in %d days\n",
		name, days);

 out:
    if (x)
	X509_free(x);

    return err;
}

static int
lookup_certinfo(struct gensio_os_funcs *o,
		const char *tlssh_dir, const char *username,
		const char *hostname, int port,
		char **rCAspec, char **rcertspec, char **rkeyspec)
{
    int err = GE_NOMEM;
    char *tcertname, *tkeyname, *tmp;

    if (!CAname) {
	CAname = alloc_sprintf("%s%cserver_certs", tlssh_dir, DIRSEP);
	if (!CAname) {
	    fprintf(stderr, "Error allocating memory for CAname\n");
	    return GE_NOMEM;
	}
    }

    if (!certname) {
	tcertname = alloc_sprintf("%s%ckeycerts%c%s,%d.crt", tlssh_dir, DIRSEP,
				  DIRSEP, hostname, port);
	if (!tcertname)
	    goto cert_nomem;
	if (file_is_readable(tcertname)) {
	    tkeyname = alloc_sprintf("%s%ckeycerts%c%s,%d.key", tlssh_dir,
				     DIRSEP, DIRSEP, hostname, port);
	    goto found_cert;
	}
	free(tcertname);
	tcertname = alloc_sprintf("%s%ckeycerts%c%s.crt", tlssh_dir, DIRSEP,
				  DIRSEP, hostname);
	if (!tcertname)
	    goto cert_nomem;
	if (file_is_readable(tcertname)) {
	    tkeyname = alloc_sprintf("%s%ckeycerts%c%s.key", tlssh_dir, DIRSEP,
				     DIRSEP,hostname);
	    goto found_cert;
	}
	free(tcertname);

	tcertname = alloc_sprintf("%s%cdefault.crt", tlssh_dir, DIRSEP);
	if (!tcertname) {
	cert_nomem:
	    fprintf(stderr, "Error allocating memory for certificate file\n");
	    goto out_err;
	}
	tkeyname = alloc_sprintf("%s%cdefault.key", tlssh_dir, DIRSEP);
    found_cert:
	if (!tkeyname) {
	    fprintf(stderr, "Error allocating memory for private key file\n");
	    free(tcertname);
	    tcertname = NULL;
	    goto out_err;
	}
	certname = tcertname;
	keyname = tkeyname;
    }

    err = checkout_file(CAname, true, false);
    if (err)
	goto out_err;

    err = checkout_file(certname, false, false);
    if (err)
	goto out_err;

    err = checkout_file(keyname, false, true);
    if (err)
	goto out_err;

    check_cert_expiry("local", certname, NULL, 0);

    err = GE_NOMEM;
    tmp = alloc_sprintf("CA=%s%c", CAname, DIRSEP);
    if (!tmp)
	goto out_err;
    *rCAspec = gensio_quote_string(o, tmp);
    free(tmp);
    if (!*rCAspec)
	goto out_err;
    tmp = alloc_sprintf("cert=%s", certname);
    if (!tmp)
	goto out_err1;
    *rcertspec = gensio_quote_string(o, tmp);
    free(tmp);
    if (!*rcertspec) {
    out_err1:
	o->free(o, *rCAspec);
	*rCAspec = NULL;
	goto out_err;
    }
    tmp = alloc_sprintf("key=%s", keyname);
    if (!tmp)
	goto out_err2;
    *rkeyspec = gensio_quote_string(o, tmp);
    free(tmp);
    if (!*rkeyspec) {
    out_err2:
	o->free(o, *rcertspec);
	*rcertspec = NULL;
	o->free(o, *rCAspec);
	*rCAspec = NULL;
	goto out_err;
    }

    err = 0;

 out_err:
    return err;
}

static int
verify_cert(struct gensio_os_funcs *o,
	    const char *cert, const char *dir,
	    const char *name, unsigned int port)
{
    size_t rv;
    FILE *f;
    char *filename;
    char cmpcert[16384];

    if (port)
	filename = alloc_sprintf("%s%c%s,%d.crt", dir, DIRSEP, name, port);
    else
	filename = alloc_sprintf("%s%c%s.crt", dir, DIRSEP, name);
    if (!filename) {
	fprintf(stderr, "Out of memory allocating filename");
	return GE_NOMEM;
    }
    translate_filename(filename);

    f = fopen(filename, "r");
    if (!f) {
	fprintf(stderr,
		"Unable to open certificate file at %s\n", filename);
	rv = GE_CERTNOTFOUND;
    } else {
	size_t len = strlen(cert);

	rv = fread(cmpcert, 1, sizeof(cmpcert), f);
	if (rv == 0) {
	    fprintf(stderr,
		    "Error reading '%s', could not verify certificate\n",
		    filename);
	    rv = GE_IOERR;
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
	fclose(f);
    }

    free(filename);
    return rv;
}

#ifdef _WIN32

static int
add_cert2(struct gensio_os_funcs *o, const char *cert, const char *filename)
{
    HANDLE h;
    DWORD written;
    unsigned int len = strlen(cert);

    /* Default security attributes is user-only, so we stick with that. */
    h = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_NEW,
		    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
	DWORD err = GetLastError();

	if (err == ERROR_FILE_EXISTS) {
	    fprintf(stderr,
		    "Certificate file %s already exists, this means the\n"
		    "certificate has changed.  Someone may be trying to\n"
		    "intercept your communications.  Giving up, remove the\n"
		    "file if it is incorrect and try again\n", filename);
	    return GE_KEYINVALID;
	} else {
	    char errbuf[128];

	    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
			  err, 0, errbuf, sizeof(errbuf), NULL);
	    fprintf(stderr, "Could not get open new certificate: %s\n", errbuf);
	    return gensio_os_err_to_err(o, err);
	}
    }

    if (!WriteFile(h, cert, len, &written, NULL)) {
	DWORD err = GetLastError();
	char errbuf[128];

	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		      err, 0, errbuf, sizeof(errbuf), NULL);
	fprintf(stderr, "Could not write certificate file %s: %s\n",
		filename, errbuf);
	CloseHandle(h);
	return gensio_os_err_to_err(o, err);
    }
    CloseHandle(h);
    if (len != written) {
	fprintf(stderr, "Incomplete write on certificate file %s: wrote %u,"
		" expected %u\n", filename, (unsigned int) written, len);
	return GE_IOERR;
    }

    return 0;
}

#else

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static int
add_cert2(struct gensio_os_funcs *o, const char *cert, const char *filename)
{
    int rv = open(filename, O_CREAT | O_EXCL | O_WRONLY, 0600);

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

    return rv;
}
#endif

static int
add_cert(struct gensio_os_funcs *o, const char *cert, const char *dir,
	 const char *name, unsigned int port)
{
    int rv;
    char *filename;

    if (port)
	filename = alloc_sprintf("%s%c%s,%d.crt", dir, DIRSEP, name, port);
    else
	filename = alloc_sprintf("%s%c%s.crt", dir, DIRSEP, name);
    if (!filename) {
	fprintf(stderr, "Out of memory allocating filename");
	return GE_NOMEM;
    }
    translate_filename(filename);

    rv = add_cert2(o, cert, filename);

    free(filename);
    return rv;
}

#else

static int
check_cert_expiry(const char *name, const char *filename,
		  const char *cert, gensiods certlen)
{
    return GE_NOTFOUND;
}

static int
lookup_certinfo(struct gensio_os_funcs *o,
		const char *tlssh_dir, const char *username,
		const char *hostname, int port,
		char **rCAspec, char **rcertspec, char **rkeyspec)
{
    return GE_NOTFOUND;
}

static int
add_cert(struct gensio_os_funcs *o, const char *cert, const char *fmt, ...)
{
    return GE_NOTFOUND;
}

static int
verify_cert(struct gensio_os_funcs *o,
	    const char *cert, const char *name, unsigned int port)
{
    return GE_NOTFOUND;
}
#endif

static void
translate_raddr(char *raddr)
{
    while (*raddr) {
	if (*raddr == '/')
	    *raddr = '-';
	raddr++;
    }
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
    gensiods len, certlen;
    int err, err1, err2;

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

	certlen = sizeof(cert);
	err = gensio_control(ssl_io, 0, true, GENSIO_CONTROL_CERT,
			     cert, &certlen);
	if (err) {
	    fprintf(stderr, "Error getting certificate: %s\n",
		    gensio_err_to_str(err));
	    return GE_NOMEM;
	}
	if (certlen >= sizeof(cert)) {
	    fprintf(stderr, "certificate is too large");
	    return GE_NOMEM;
	}

	strcpy(raddr, "0");
	len = sizeof(raddr);
	err = gensio_control(ssl_io, GENSIO_CONTROL_DEPTH_FIRST, true,
			     GENSIO_CONTROL_CONNECT_ADDR_STR, raddr, &len);
	if (err) {
	    strcpy(raddr, "0");
	    len = sizeof(raddr);
	    err = gensio_control(ssl_io, GENSIO_CONTROL_DEPTH_FIRST, true,
				 GENSIO_CONTROL_RADDR, raddr, &len);
	}
	if (err) {
	    fprintf(stderr, "Could not get connections remote address: %s\n",
		    gensio_err_to_str(err));
	    return err;
	}
	translate_raddr(raddr);

	if (!ierr) {
	    /* Found a certificate, make sure it's the right one. */
	    err1 = verify_cert(ginfo->o, cert, CAname, hostname, port);
	    err2 = verify_cert(ginfo->o, cert, CAname, raddr, 0);
	    if ((err1 == GE_CERTNOTFOUND && err1 == err2) ||
			(err1 == GE_CERTNOTFOUND && !err2) ||
			(err2 == GE_CERTNOTFOUND && !err1)) {
		if (err1)
		    printf("\nCertificate for %s found and correct, but"
			   " address file was\nmissing for it.\n", hostname);
		if (err2)
		    printf("\nCertificate for %s found and correct, but"
			   " address file was\nmissing for\n  %s\n",
			   hostname, raddr);
		printf("It is possible that the same key is used for"
		       " different connections,\nbut"
		       " there may also be a man in the middle\n");
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
		    if (err1)
			err = add_cert(ginfo->o, cert, CAname, hostname, port);
		    if (!err && err2)
			err = add_cert(ginfo->o, cert, CAname, raddr, 0);
		}
	    }

	    goto postcert_done;
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
		    CAname, hostname, port, CAname, raddr, errstr);
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

	err = add_cert(ginfo->o, cert, CAname, hostname, port);
	if (!err)
	    err = add_cert(ginfo->o, cert, CAname, raddr, 0);

	cmd = alloc_sprintf("gtlssh-keygen rehash %s", CAname);
	if (!cmd) {
	    fprintf(stderr, "Could not allocate memory for rehash, skipping\n");
	} else {
	    int rv = system(cmd);

	    if (rv != 0)
		fprintf(stderr, "Error from %s, rehash skipped\n", cmd);

	    free(cmd);
	}

    postcert_done:
	if (!err)
	    err = check_cert_expiry("remote host", NULL, cert, certlen);
	return err;

    case GENSIO_EVENT_REQUEST_PASSWORD:
	return getpassword(ginfo, (char *) ibuf, buflen);

    default:
	return GE_NOTSUP;
    }
}

#if HAVE_DECL_SIGWINCH
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>

static void winch_sent(void *cb_data);

static int winch_pipe[2];
static struct gensio_iod *winch_iod;
static unsigned char winch_buf[11];
static struct ioinfo_oob winch_oob = { .buf = winch_buf };
static bool winch_oob_sending;
static bool winch_oob_pending;

static void
send_winch(struct ioinfo *ioinfo)
{
    struct winsize win;
    int rv;

    rv = ioctl(0, TIOCGWINSZ, &win);
    if (rv == -1)
	return;

    /* See goobdata() comment for message format. */
    winch_oob.buf[0] = 'w';
    gensio_u16_to_buf(winch_oob.buf + 1, 8); /* Number of following bytes. */
    gensio_u16_to_buf(winch_oob.buf + 3, win.ws_row);
    gensio_u16_to_buf(winch_oob.buf + 5, win.ws_col);
    gensio_u16_to_buf(winch_oob.buf + 7, win.ws_xpixel);
    gensio_u16_to_buf(winch_oob.buf + 9, win.ws_ypixel);
    winch_oob.len = 11;
    winch_oob.cb_data = ioinfo;
    winch_oob.send_done = winch_sent;
    ioinfo_sendoob(ioinfo, &winch_oob);
    winch_oob_sending = true;
}

static void
winch_sent(void *cb_data)
{
    struct ioinfo *ioinfo = cb_data;

    winch_oob_sending = false;
    if (winch_oob_pending) {
	winch_oob_pending = false;
	send_winch(ioinfo);
    }
}

static void
winch_ready(struct gensio_iod *iod, void *cb_data)
{
    struct ioinfo *ioinfo = cb_data;
    char dummy;
    int rv = 1;

    /* Clear out the pipe. */
    while (rv == 1)
	rv = read(winch_pipe[0], &dummy, 1);
    /* errno should be EAGAIN here. */

    if (!isatty(0))
	return;

    if (winch_oob_sending)
	winch_oob_pending = true;
    else
	send_winch(ioinfo);
}

static void
handle_sigwinch(int signum)
{
    int rv;

    rv = write(winch_pipe[1], "w", 1);
    if (rv != 1) {
	/* What can be done here? */
    }
}

static int
setup_window_change(void)
{
    struct sigaction sigact;

    if (pipe(winch_pipe) == -1) {
	perror("Unable to allocate SIGWINCH pipe");
	return 1;
    }
    if (fcntl(winch_pipe[0], F_SETFL, O_NONBLOCK) == -1) {
	perror("Unable to set nonblock on SIGWINCH pipe[0]");
	return 1;
    }
    if (fcntl(winch_pipe[1], F_SETFL, O_NONBLOCK) == -1) {
	perror("Unable to set nonblock on SIGWINCH pipe[1]");
	return 1;
    }

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = handle_sigwinch;
    if (sigaction(SIGWINCH, &sigact, NULL)) {
	perror("Unable to setup SIGWINCH");
	return 1;
    }

    return 0;
}

static int
setup_window_change2(struct gensio_os_funcs *o, struct ioinfo *ioinfo)
{
    int rv;

    rv = o->add_iod(o, GENSIO_IOD_PIPE, winch_pipe[0], &winch_iod);
    if (rv) {
	fprintf(stderr, "Could not add SIGWINCH fd iod: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }

    rv = o->set_fd_handlers(winch_iod, ioinfo, winch_ready,
			    NULL, NULL, NULL);
    if (rv) {
	fprintf(stderr, "Could not set SIGWINCH fd handler: %s\n",
		gensio_err_to_str(rv));
	return 1;
    }
    o->set_read_handler(winch_iod, true);

    return 0;
}

#else

static void
winch_ready(struct gensio_iod *iod, void *cb_data)
{
}

static int
setup_window_change(void)
{
    return 0;
}

static int
setup_window_change2(struct gensio_os_funcs *o, struct ioinfo *ioinfo)
{
    return 0;
}

#endif /* HAVE_DECL_SIGWINCH */

static void
pr_localport(const char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
}

struct remote_portinfo {
    char *accepter_str;
    char *connecter_str;
    char *id_str;

    char service[5];

    struct ioinfo_oob oob;

    struct gensio_os_funcs *o;

    struct remote_portinfo *next;
};

static unsigned int curr_service;
static struct remote_portinfo *remote_ports;

static void
handle_rem_req(struct gensio *io, const char *service)
{
    struct remote_portinfo *pi = remote_ports;

    for (; pi; pi = pi->next) {
	if (strcmp(pi->service, service) == 0)
	    break;
    }
    if (!pi) {
	fprintf(stderr, "Unknown remote service request: %s\n", service);
	gensio_free(io);
	return;
    }

    remote_port_new_con(pi->o, io, pi->connecter_str, pi->id_str);
}

static int
add_remote_port(struct gensio_os_funcs *o,
		const char *accepter_str, const char *connecter_str,
		const char *id_str)
{
    struct remote_portinfo *np = NULL;
    int err = GE_NOMEM;

    np = malloc(sizeof(*np));
    if (!np) {
	fprintf(stderr, "Out of memory allocating port info\n");
	goto out_err;
    }
    memset(np, 0, sizeof(*np));
    np->o = o;
    snprintf(np->service, sizeof(np->service), "%4.4d", curr_service++);

    np->accepter_str = alloc_sprintf("r  %s%s", np->service, accepter_str);
    if (!np->accepter_str) {
	fprintf(stderr, "Out of memory allocating accept string: %s\n",
		accepter_str);
	goto out_err;
    }
    np->oob.buf = (unsigned char *) np->accepter_str;
    np->oob.len = strlen(np->accepter_str) + 1; /* Send the nil, too. */
    if (np->oob.len > 65535) {
	fprintf(stderr, "Accepter string to long: %s\n", accepter_str);
	goto out_err;
    }
    np->oob.buf[1] = (np->oob.len - 3) >> 8;
    np->oob.buf[2] = (np->oob.len - 3) & 0xff;

    np->connecter_str = strdup(connecter_str);
    if (!np->connecter_str) {
	fprintf(stderr, "Out of memory allocating connecter string: %s\n",
		connecter_str);
	goto out_err;
    }

    np->id_str = strdup(id_str);
    if (!np->id_str) {
	fprintf(stderr, "Out of memory allocating id string: %s\n", id_str);
	goto out_err;
    }
    np->next = remote_ports;
    remote_ports = np;
    np = NULL;
    err = 0;

 out_err:
    if (np) {
	if (np->accepter_str)
	    free(np->accepter_str);
	if (np->connecter_str)
	    free(np->connecter_str);
	if (np->id_str)
	    free(np->id_str);
	free(np);
    }
    return err;
}

static void
start_remote_ports(struct ioinfo *ioinfo)
{
    struct remote_portinfo *pi = remote_ports;

    for (; pi; pi = pi->next)
	ioinfo_sendoob(ioinfo, &pi->oob);
}

static bool
validate_port(const char *host, const char *port, const char **rtype,
	      const char *addr)
{
    const char *type = "tcp";
    unsigned long val;
    char *end;

    if (strncmp(port, "tcp,", 4) == 0)
	port += 4;
    if (strncmp(port, "sctp,", 5) == 0) {
	port += 5;
	type = "sctp";
    }

    if (host && *host == '\0') {
	fprintf(stderr, "No host given in '%s'\n", addr);
	return false;
    }

    val = strtoul(port, &end, 10);
    if (*port == '\0' || *end != '\0' || val > 65535) {
	fprintf(stderr, "Invalid port given in '%s'\n", addr);
	return false;
    }

    *rtype = type;
    return true;
}

static int
handle_port(struct gensio_os_funcs *o, bool remote, const char *iaddr)
{
    char *s[4];
    const char *type = NULL;
    unsigned int num_s = 0, pos = 0;
    char *connecter_str = NULL, *accepter_str = NULL;
    char *addr = strdup(iaddr);
    int err = -1;
    bool has_bind = false;

    if (!addr) {
	fprintf(stderr, "Out of memory duplicating port '%s'\n", iaddr);
	goto out_err;
    }

    while (num_s < 4) {
	s[num_s++] = addr;
	addr = strchr(addr, ':');
	if (addr)
	    *addr++ = '\0';
	else
	    break;
    }

    if (num_s < 2)
	goto out_not_enough_fields;
    if (num_s > 4)
	goto out_too_many_fields;

    if (s[num_s - 1][0] == '/') { /* remote is a unix socket. */
	if (s[0][0] == '/') { /* local is a unix socket */
	    if (num_s > 2)
		goto out_too_many_fields;
	} else if (num_s > 3) {
	    goto out_too_many_fields;
	} else if (num_s == 3) {
	    has_bind = true;
	}
    } else if (s[0][0] == '/') { /* local is a unix socket */
	if (num_s > 3)
	    goto out_too_many_fields;
    } else if (num_s < 3) {
	goto out_not_enough_fields;
    } else if (num_s == 4) {
	has_bind = true;
    }

    if (has_bind) {
	if (!validate_port(s[pos], s[pos + 1], &type, iaddr))
	    goto out_err;
	accepter_str = alloc_sprintf("%s,%s,%s", type, s[pos], s[pos + 1]);
	pos += 2;
    } else if (s[pos][0] == '/') { /* accepter is a unix socket */
	accepter_str = alloc_sprintf("unix,%s", s[pos]);
	pos++;
    } else {
	if (!validate_port(NULL, s[pos], &type, iaddr))
	    goto out_err;
	accepter_str = alloc_sprintf("%s,%s", type, s[pos]);
	pos++;
    }

    if (s[pos][0] == '/') { /* remote is a unix socket */
	connecter_str = alloc_sprintf("unix,%s", s[pos]);
    } else {
	if (!validate_port(s[pos], s[pos + 1], &type, iaddr))
	    goto out_err;
	connecter_str = alloc_sprintf("%s,%s,%s", type, s[pos], s[pos + 1]);
    }

    if (remote)
	err = add_remote_port(o, accepter_str, connecter_str, iaddr);
    else
	err = add_local_port(o, accepter_str, connecter_str, iaddr);
    goto out_err;

 out_not_enough_fields:
    fprintf(stderr, "Not enough fields in port info '%s'\n", iaddr);
    goto out_err;
 out_too_many_fields:
    fprintf(stderr, "Too many fields in port info '%s'\n", iaddr);
    goto out_err;

 out_err:
    if (accepter_str)
	free(accepter_str);
    if (connecter_str)
	free(connecter_str);
    if (addr)
	free(addr);

    return err;
}

struct mdns_cb_data {
    bool done;
    int err;
    bool telnet;
    char *transport;
    struct gensio_os_funcs *o;
    struct gensio_waiter *wait;
};

static void
mdns_cb(struct gensio_mdns_watch *w,
	enum gensio_mdns_data_state state,
	int iface, int ipdomain,
	const char *name, const char *type,
	const char *domain, const char *host,
	const struct gensio_addr *addr, const char *txt[],
	void *userdata)
{
    struct mdns_cb_data *cb_data = userdata;
    struct gensio_os_funcs *o = cb_data->o;
    char *addrstr = NULL, *s;
    gensiods addrstrlen = 0, pos = 0;
    const char *protocol;
    static const char *stackstr = "gensiostack=";
    unsigned int i;

    if (cb_data->done)
	return;

    if (state == GENSIO_MDNS_ALL_FOR_NOW)
	goto out_wake;

    if (state != GENSIO_MDNS_NEW_DATA)
	return;

    /* Found it. */

    /* Look for the trailing protocol type. */
    s = strrchr(type, '.');
    if (!s)
	goto out_wake;
    s++;
    if (strcmp(s, "_tcp") == 0) {
	protocol = "tcp";
    } else if (strcmp(s, "_udp") == 0) {
	protocol = "udp";
    } else if (strcmp(s, "_sctp") == 0) {
	protocol = "sctp";
    } else {
	goto out_wake;
    }

    cb_data->err = gensio_addr_to_str(addr, NULL, &addrstrlen, 0);
    if (cb_data->err)
	goto out_wake;
    addrstr = o->zalloc(o, addrstrlen + 1);
    cb_data->err = gensio_addr_to_str(addr, addrstr, &pos, addrstrlen + 1);
    if (cb_data->err) {
	o->free(o, addrstr);
	goto out_wake;
    }

    cb_data->transport = gensio_alloc_sprintf(o, "%s,%s", protocol, addrstr);
    if (!cb_data->transport) {
	cb_data->err = GE_NOMEM;
	goto out_wake;
    }

    for (i = 0; txt && txt[i]; i++) {
	if (strncmp(txt[i], stackstr, strlen(stackstr)) == 0) {
	    if (strstr(txt[i], "telnet"))
		cb_data->telnet = true;
	    break;
	}
    }

 out_wake:
    if (addrstr)
	o->free(o, addrstr);
    cb_data->done = true;
    o->wake(cb_data->wait);
}

static void
mdns_freed(struct gensio_mdns *m, void *userdata)
{
    struct mdns_cb_data *cb_data = userdata;

    cb_data->o->wake(cb_data->wait);
}

static int
lookup_mdns_transport(struct gensio_os_funcs *o, const char *name,
		      const char *type, const char *iptypestr,
		      const char **transport, bool *telnet)
{
    struct gensio_mdns *mdns;
    struct gensio_mdns_watch *mdns_watch;
    int nettype = GENSIO_NETTYPE_UNSPEC;
    int err;
    struct mdns_cb_data cb_data;
    struct gensio_time timeout = { 30, 0 };

    memset(&cb_data, 0, sizeof(cb_data));
    cb_data.err = GE_NOTFOUND;
    cb_data.o = o;
    cb_data.wait = o->alloc_waiter(o);
    if (!cb_data.wait) {
	fprintf(stderr, "Unable to allocate wait: out of memory\n");
	return 1;
    }

    if (strcmp(iptypestr, "ipv4,") == 0)
	nettype = GENSIO_NETTYPE_IPV4;
    else if (strcmp(iptypestr, "ipv6,") == 0)
	nettype = GENSIO_NETTYPE_IPV6;

    err = gensio_alloc_mdns(o, &mdns);
    if (err) {
	o->free_waiter(cb_data.wait);
	fprintf(stderr, "Unable to allocate mdns data: %s\n",
		gensio_err_to_str(err));
	return 1;
    }

    err = gensio_mdns_add_watch(mdns, -1, nettype, name, type, NULL, NULL,
				mdns_cb, &cb_data, &mdns_watch);
    if (err) {
	o->free_waiter(cb_data.wait);
	gensio_free_mdns(mdns, NULL, NULL);
	fprintf(stderr, "Unable to add mdns watch: %s\n",
		gensio_err_to_str(err));
	return 1;
    }

    o->wait(cb_data.wait, 1, &timeout);

    gensio_mdns_remove_watch(mdns_watch, NULL, NULL);
    gensio_free_mdns(mdns, mdns_freed, &cb_data);

    o->wait(cb_data.wait, 1, NULL);

    if (cb_data.err) {
	fprintf(stderr, "Error looking up %s with mdns: %s\n",
		name, gensio_err_to_str(cb_data.err));
	return cb_data.err;
    }

    *transport = cb_data.transport;
    *telnet = cb_data.telnet;
    return 0;
}

int
main(int argc, char *argv[])
{
    int arg, rv = 0;
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
    unsigned int use_telnet = 0;
    char *CAspec = NULL, *certspec = NULL, *keyspec = NULL;
    char *service;
    gensiods service_len, len;
    const char *transport = "sctp";
    bool user_transport = false, mdns_transport = false;
    bool notcp = false, nosctp = true;
    const char *muxstr = "mux,";
    bool use_mux = true;
    const char *addr, *cstr;
    const char *iptype = ""; /* Try both IPv4 and IPv6 by default. */
    const char *mdns_type = NULL;
    struct gensio_os_proc_data *proc_data;

    localport_err = pr_localport;

    memset(&userdata1, 0, sizeof(userdata1));
    memset(&userdata2, 0, sizeof(userdata2));
    userdata2.interactive = true;

    err = gensio_default_os_hnd(0, &o);
    if (err) {
	fprintf(stderr, "Could not allocate OS handler: %s\n",
		gensio_err_to_str(err));
	return 1;
    }
    o->vlog = do_vlog;

    err = gensio_os_proc_setup(o, &proc_data);
    if (err) {
	fprintf(stderr, "Could not setup process data: %s\n",
		gensio_err_to_str(err));
	o->free_funcs(o);
	return 1;
    }

    if (setup_window_change())
	return 1;

    progname = argv[0];

    if (can_do_raw()) {
	escape_char = 0x1c; /* ^\ */
	userdata1.ios = io1_default_tty;
    } else {
	userdata1.ios = io1_default_notty;
	userdata2.interactive = false;
    }

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != '-')
	    break;
	if (strcmp(argv[arg], "--") == 0) {
	    arg++;
	    break;
	}
	if (((err = cmparg(argc, argv, &arg, "-i", "--keyname", &cstr))) ||
		((err = cmparg(argc, argv, &arg, "-i", "--keyfile", &cstr)))) {
	    if (keyname)
		free(keyname);
	    keyname = strdup(cstr);
	    if (!keyname) {
		fprintf(stderr, "Unable to allocate memory for keyname\n");
		exit(1);
	    }
	    if (!certname) {
		char *dotpos = strrchr(keyname, '.');

		if (dotpos)
		    *dotpos = '\0';
		s = alloc_sprintf("%s.crt", keyname);
		if (dotpos)
		    *dotpos = '.';
		if (!s) {
		    fprintf(stderr, "Unable to allocate memory for certname\n");
		    exit(1);
		}
		if (certname)
		    free(certname);
		certname = s;
	    }
	} else if ((err = cmparg_uint(argc, argv, &arg, "-p", "--port",
				      &port))) {
	    ;
	} else if (((err = cmparg(argc, argv, &arg, NULL, "--certname",
				  &cstr))) ||
		   ((err = cmparg(argc, argv, &arg, NULL, "--certfile",
				  &cstr)))) {
	    if (certname)
		free(certname);
	    certname = strdup(cstr);
	    if (!certname) {
		fprintf(stderr, "Unable to allocate memory for certname\n");
		exit(1);
	    }
	} else if (((err = cmparg(argc, argv, &arg, NULL, "--caname",
				  &cstr))) ||
		   ((err = cmparg(argc, argv, &arg, NULL, "--cadir",
				  &cstr)))) {
	    if (CAname)
		free(CAname);
	    CAname = strdup(cstr);
	    if (!CAname) {
		fprintf(stderr, "Unable to allocate memory for cadir\n");
		exit(1);
	    }
	} else if ((err = cmparg_int(argc, argv, &arg, "-e", "--escchar",
				     &escape_char))) {
	    ;
	} else if ((err = cmparg(argc, argv, &arg, NULL, "--nomux", NULL))) {
	    muxstr = "";
	    use_mux = false;
	} else if ((err = cmparg(argc, argv, &arg, NULL, "--notcp", NULL))) {
	    notcp = true;
	} else if ((err = cmparg(argc, argv, &arg, NULL, "--nosctp", NULL))) {
	    nosctp = true;
	} else if ((err = cmparg(argc, argv, &arg, NULL, "--sctp", NULL))) {
	    nosctp = false;
	} else if ((err = cmparg(argc, argv, &arg, "-r", "--telnet", NULL))) {
	    do_telnet = "telnet(rfc2217),";
	    use_telnet = 1;
	} else if ((err = cmparg(argc, argv, &arg, "", "--transport",
				 &transport))) {
	    user_transport = true;
	    nosctp = true;
	    notcp = true;
	} else if ((err = cmparg(argc, argv, &arg, "-m", "--mdns", NULL))) {
	    mdns_transport = true;
	    user_transport = true;
	    nosctp = true;
	    notcp = true;
	} else if ((err = cmparg(argc, argv, &arg, NULL, "--mdns-type",
				 &mdns_type))) {
	    ;
	} else if ((err = cmparg(argc, argv, &arg, "-L", NULL, &addr))) {
	    err = handle_port(o, false, addr);
	} else if ((err = cmparg(argc, argv, &arg, "-R", NULL, &addr))) {
	    err = handle_port(o, true, addr);
	} else if ((err = cmparg(argc, argv, &arg, "-4", NULL, NULL))) {
	    iptype = "ipv4,";
	} else if ((err = cmparg(argc, argv, &arg, "-6", NULL, NULL))) {
	    iptype = "ipv6,";
	} else if ((err = cmparg(argc, argv, &arg, "-d", "--debug", NULL))) {
	    debug++;
	    if (debug > 1)
		gensio_set_log_mask(GENSIO_LOG_MASK_ALL);
	} else if ((err = cmparg(argc, argv, &arg, "-h", "--help", NULL))) {
	    help(0);
	} else {
	    fprintf(stderr, "Unknown argument: %s\n", argv[arg]);
	    help(1);
	}
	if (err < 0)
	    return 1;
    }

    if (nosctp && notcp && !user_transport) {
	fprintf(stderr, "You cannot disable both TCP and SCTP\n");
	exit(1);
    }

    if (nosctp && !user_transport)
	transport = "tcp";

    if (!!certname != !!keyname) {
	fprintf(stderr,
		"If you specify a certname, you must specify a keyname\n");
	exit(1);
    }

    if (arg >= argc) {
	fprintf(stderr, "No string given to connect to\n");
	help(1);
    }

#if defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
    if (!debug) {
	if (prctl(PR_SET_DUMPABLE, 0) != 0) {
	    fprintf(stderr,
		    "Unable to disable ptrace attach, giving up.\n");
	    exit(1);
	}
    }
#endif

    s = strrchr(argv[arg], '@');
    if (s) {
	*s++ = '\0';
	username = strdup(argv[arg]);
	if (!username) {
	    fprintf(stderr, "out of memory allocating username\n");
	    return 1;
	}
	hostname = s;
    } else {
	username = get_my_username();
	if (!username)
	    return 1;
	hostname = argv[arg];
    }

    arg++;
    if (arg < argc) {
	int i;
	unsigned int len = 0;

	/* User gave us a remote program. */
	for (i = arg; i < argc; i++)
	    len += strlen(argv[i]) + 1; /* Extra space for nil at end */
	len += 9; /* Space for "program:" and final nil. */
	/* Note that ending '\0' is handled by final space. */

	service = malloc(len);
	if (!service) {
	    fprintf(stderr, "Unable to allocate remote program request\n");
	    return 1;
	}
	strcpy(service, "program:");
	len = 8;
	for (i = arg; i < argc; i++) {
	    len += sprintf(service + len, "%s", argv[i]);
	    service[len++] = '\0';
	}
	service[len++] = '\0';

	userdata1.ios = io1_default_notty;
	userdata2.interactive = false;
	service_len = len;
    } else {
	char *termvar = getenv("TERM");
	unsigned int len = 0;

	if (termvar) {
	    len = 6 + 5 + strlen(termvar) + 2;
	    service = malloc(len);
	    if (!service) {
		fprintf(stderr, "Unable to allocate remote login request\n");
		return 1;
	    }
	    len = sprintf(service, "login:TERM=%s", termvar);
	    service[len++] = '\0';
	    service[len++] = '\0';
	} else {
	    service = malloc(6 + 1);
	    if (!service) {
		fprintf(stderr, "Unable to allocate remote login request\n");
		return 1;
	    }
	    len = sprintf(service, "login:");
	    service[len++] = '\0';
	}
	service_len = len;
    }

    if (!tlssh_dir) {
	tlssh_dir = get_tlsshdir();
	if (!tlssh_dir)
	    return 1;
    }

    err = checkout_file(tlssh_dir, true, true);
    if (err)
	return 1;

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

    ioinfo2 = alloc_ioinfo(o, -1, sh2, subdata2, &guh, &userdata2);
    if (!ioinfo2) {
	fprintf(stderr, "Could not allocate ioinfo 2\n");
	return 1;
    }

    ioinfo_set_otherioinfo(ioinfo1, ioinfo2);

    err = str_to_gensio(userdata1.ios, o, NULL, ioinfo1, &userdata1.io);
    if (err) {
	fprintf(stderr, "Could not allocate %s: %s\n",
		userdata1.ios, gensio_err_to_str(err));
	return 1;
    }

    userdata1.user_io = userdata1.io;
    userdata2.user_io = userdata1.io;

    err = lookup_certinfo(o, tlssh_dir, username, hostname, port,
			  &CAspec, &certspec, &keyspec);
    if (err)
	return 1;

    if (mdns_transport) {
	bool ltelnet = false;
	err = lookup_mdns_transport(o, hostname, mdns_type, iptype,
				    &transport, &ltelnet);
	if (err)
	    return 1;
	if (ltelnet) {
	    do_telnet = "telnet(rfc2217),";
	    use_telnet = 1;
	}
    }

 retry:
    if (user_transport)
	s = alloc_sprintf("%s%scertauth(enable-password,username=%s,%s,%s),"
			  "ssl(%s),%s",
			  do_telnet, muxstr, username, certspec,
			  keyspec, CAspec, transport);
    else
	s = alloc_sprintf("%s%scertauth(enable-password,username=%s,%s,%s),"
			  "ssl(%s),%s,%s%s,%d",
			  do_telnet, muxstr, username, certspec,
			  keyspec, CAspec,
			  transport, iptype, hostname, port);
    if (!s) {
	fprintf(stderr, "out of memory allocating IO string\n");
	return 1;
    }
    userdata2.ios = s;

    err = str_to_gensio(userdata2.ios, o, auth_event, ioinfo2, &userdata2.io);
    if (err) {
	fprintf(stderr, "Could not allocate %s: %s\n", userdata2.ios,
		gensio_err_to_str(err));
	return 1;
    }

    if (use_mux) {
	len = 4;
	err = gensio_control(userdata2.io, 1 + use_telnet, false,
			     GENSIO_CONTROL_SERVICE, "mux", &len);
	if (err) {
	    fprintf(stderr, "Could not set mux service %s: %s\n",
		    userdata2.ios, gensio_err_to_str(err));
	    return 1;
	}
    }

    err = gensio_control(userdata2.io, 0 + use_telnet, false,
			 GENSIO_CONTROL_SERVICE, service, &service_len);
    if (err) {
	fprintf(stderr, "Could not set service %s: %s\n", userdata2.ios,
		gensio_err_to_str(err));
	return 1;
    }

    if (userdata2.interactive) {
	err = gensio_control(userdata2.io, GENSIO_CONTROL_DEPTH_ALL, false,
			     GENSIO_CONTROL_NODELAY, "1", NULL);
	if (err) {
	    fprintf(stderr, "Could not set nodelay on %s: %s\n", userdata2.ios,
		    gensio_err_to_str(err));
	    return 1;
	}
    }

    userdata2.can_close = true;
    err = gensio_open_s(userdata2.io);
    if (err) {
	rv = 1;
	userdata2.can_close = false;
	fprintf(stderr, "Could not open %s: %s\n", userdata2.ios,
		gensio_err_to_str(err));
	if (!notcp && !user_transport && strcmp(transport, "sctp") == 0) {
	    fprintf(stderr, "Falling back to tcp\n");
	    free(userdata2.ios);
	    userdata2.ios = NULL;
	    transport = "tcp";
	    goto retry;
	}
	goto closeit;
    }

    if (mdns_transport)
	o->free(o, (char *) transport);

    userdata1.can_close = true;
    err = gensio_open_s(userdata1.io);
    if (err) {
	rv = 1;
	userdata1.can_close = false;
	fprintf(stderr, "Could not open %s: %s\n",
		userdata1.ios, gensio_err_to_str(err));
	goto closeit;
    }

    ioinfo_set_ready(ioinfo1, userdata1.io);
    ioinfo_set_ready(ioinfo2, userdata2.io);

    if (setup_window_change2(o, ioinfo2))
	return 1;

    start_local_ports(userdata2.io);
    start_remote_ports(ioinfo2);

    o->wait(userdata1.waiter, 1, NULL);

 closeit:
    free(service);

    if (userdata2.can_close) {
	err = gensio_close(userdata2.io, io_close, closewaiter);
	if (err)
	    printf("Unable to close %s: %s\n", userdata2.ios,
		   gensio_err_to_str(err));
	else
	    closecount++;
    }

    if (userdata1.can_close) {
	err = gensio_close(userdata1.io, io_close, closewaiter);
	if (err)
	    printf("Unable to close %s: %s\n", userdata1.ios,
		   gensio_err_to_str(err));
	else
	    closecount++;
    }

    if (closecount > 0)
	o->wait(closewaiter, closecount, NULL);

    if (CAspec)
	o->free(o, CAspec);
    if (certspec)
	o->free(o, certspec);
    if (keyspec)
	o->free(o, keyspec);

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

    gensio_os_proc_cleanup(proc_data);
    o->free_funcs(o);
    if (keyname)
	free(keyname);
    if (certname)
	free(certname);
    if (CAname)
	free(CAname);

    return rv;
}
