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

#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "utils.h"
#include "gtlssh.h"

int debug;

#define DEFAULT_KEYSIZE 2048
static unsigned int keysize = DEFAULT_KEYSIZE;

static char *default_gtlsshdir;
static const char *gtlsshdir;

static char *default_keydir;
static const char *keydir;
static bool keydir_set = false;

#define DEFAULT_KEYDAYS 365
static unsigned int keydays = DEFAULT_KEYDAYS;

#ifdef SYSCONFDIR
#define DEFAULT_CONFDIR SYSCONFDIR DIRSEPS "gtlssh"
static const char *confdir = DEFAULT_CONFDIR;
#endif

static char *alloc_commonname = NULL;
static const char *commonname = NULL;
static bool commonname_set = false;

static bool force = false;

static void
help(const char *progname)
{
#define P printf
    P("Key handling tool for gtlssh.  Format is:\n");
    P("%s [<option> [<option> [...]]] command <command options>\n", progname);
    P("Options are:\n");
    P("  --keysize <size> - Create an RSA key with the given number of bits.\n");
    P("        default is %u\n", DEFAULT_KEYSIZE);
    P("  --keydays <days> - Create a key that expires in the given number\n");
    P("        of days.  Default is %u\n", DEFAULT_KEYDAYS);
    P("  --basedir <dir> - Location where keys are stored.\n");
    P("        Default is %s\n", default_gtlsshdir);
    P("  --keydir <dir> - Location to put the non-default generated keys.\n");
    P("        Default is %s for normal certificates.\n", keydir);
#ifdef DEFAULT_CONFDIR
    P("        %s for server certificates.\n", DEFAULT_CONFDIR);
#endif
    P("  --commonname <name> - Set the common name in the certificate.\n");
    P("        The default is your username for normal certificates and\n");
    P("        the fully qualified domain name for server certificates.\n");
    P("  --force, -f - Don't ask questions, just do the operation.  This\n");
    P("        may overwrite data without asking.\n");
    P("\n");
    P("Commands are:\n");
    P("  setup\n");
    P("    Create the directory structure for gtlssh and create the\n");
    P("    default keys.\n");
    P("\n");
    P("  keygen [-p <port>] [<hostname>] [[-p <port>] <hostname> [...]]\n");
    P("    Generate a keys for the given hostnames, optionally at the given\n");
    P("    port.  If no hostname is given, the default key/cert is generated\n");
    P("    in\n");
    P("      %s/default.key\n", default_gtlsshdir);
    P("    and\n");
    P("      %s/default.crt\n", default_gtlsshdir);
    P("    Otherwise the key is generated in\n");
    P("      %s/<hostname>[,<port>].key/crt.\n", default_keydir);
    P("    When gtlssh makes a connection, it will look for the hostname\n");
    P("    with the port, then just the hostname, then the default key in\n");
    P("    that order for the key to use for the connection.\n");
    P("    If there are any old keys, they will be renamed with a '.1'\n");
    P("    appended to the name.\n");
    P("\n");
    P("  rehash [<dir> [<dir> [...]]]\n");
    P("    Redo the hash entries in the given directories.  If you put\n");
    P("    certificates into those directories but do not rehash them,\n");
    P("    the tools will not be able to find the new certificates.\n");
    P("    If you don't enter any directories, it will rehash the following:\n");
    P("      %s/allowed_certs\n", default_gtlsshdir);
    P("      %s/server_certs\n", default_gtlsshdir);
    P("    Certificates that have expired are automatically removed.\n");
    P("\n");
    P("  addallow [-i] <hostname> <file>\n");
    P("    Add the given file as an allowed public certificate for the given\n");
    P("    hostname.  It will install this file in the directory:\n");
    P("      %s/allowed_certs\n", default_gtlsshdir);
    P("    with the name 'hostname.crt'.  It will also rehash the\n");
    P("    directory.  If -i is specified, input comes from stdin and the\n");
    P("    file is not required or used.  If the destination file already\n");
    P("    exists, it will rename it 'hostname.crt.1.crt'.\n");
    P("\n");
    P("  pushcert [-n <name>] [-p <port>] <hostname> [[-p <port>] <hostname> [...]]\n");
    P("    Put the local certificate for the given host onto the remote\n");
    P("    host so it can be used for login.  It uses old credentials\n");
    P("    (credentials with .1 appended to the name, per keygen) if\n");
    P("    they are there.  This is useful if you have upated your\n");
    P("    certificate and need to send a new one to some remote hosts.\n");
    P("    It finds the certificate name as described in the keygen\n");
    P("    command.  If old credentials exist, it will use those to\n");
    P("    connect with gtlssh and send the certificate.  Otherwise it\n");
    P("    will use default credentials and hope for the best, probably\n");
    P("    only useful if passwords are accepcted.  This only works\n");
    P("    one keygen back, if you have run the keygen command twice\n");
    P("    for the host, you will need to transfer the certificate\n");
    P("    manually.  By default the credential on the remote host is\n");
    P("    named the output of 'hostname -f' on the local machine,\n");
    P("    -n overrides this.\n");
#ifdef DEFAULT_CONFDIR
    P("\n");
    P("  serverkey [name]\n");
    P("    Create keys for the gtlsshd server.  Probably requires root.\n");
    P("    The name is a prefix for they filenames generated which will\n");
    P("    be name.crt and name.key.  The default name is 'default'.\n");
#endif
#undef P
    exit(0);
}

static int
copy_to_file(FILE *f, const char *dest, char *endstr)
{
    char buf[1024];
    FILE *out;
    size_t count;
    size_t pos = 0;

    out = fopen(dest, "w");
    if (!out) {
	fprintf(stderr, "Unable to open %s\n", dest);
	return 1;
    }
    while ((count = fread(buf, 1, sizeof(buf), f))) {
	if (endstr) {
	    gensiods i;

	    for (i = 0; i < count; i++) {
		if (buf[i] == endstr[pos]) {
		    pos++;
		    if (!endstr[pos]) {
			fwrite(buf, 1, i + 1, out);
			fputc('\n', out);
			goto done;
		    }
		} else {
		    pos = 0;
		}
	    }
	}
	fwrite(buf, 1, count, out);
    }
 done:
    fclose(out);
    return 0;
}

static bool
promptyn(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintf(fmt, args);
    printf(" (y/n): ");
    va_end(args);
    while (true) {
	char rsp[100];

	if (fgets(rsp, sizeof(rsp), stdin) == NULL) {
	    fprintf(stderr, "Error getting response, aborting\n");
	    exit(1);
	}
	if (rsp[0] == 'y')
	    return true;
	if (rsp[0] == 'n')
	    return false;

	printf("Unknown response, please enter y or n: ");
    }
}

static void
check_dir(bool created, bool check_private, const char *fmt, ...)
{
    char *dir;
    va_list args;

    va_start(args, fmt);
    dir = alloc_vsprintf(fmt, args);
    va_end(args);

    if (!dir) {
	fprintf(stderr,
		"check_dir: Unable to allocate directory string, giving up\n");
	exit(1);
    }

    if (!check_dir_exists(dir, check_private)) {
	if (created) {
	    make_dir(dir, check_private);
	} else {
	    if (force || promptyn("%s does not exist.  Create it?", dir)) {
		make_dir(dir, check_private);
	    } else {
		printf("Not creating %s, giving up\n", dir);
		exit(1);
	    }
	}
    }
    free(dir);
}

static void
check_dirstruct(void)
{
    bool created = false;

    if (!check_dir_exists(gtlsshdir, true)) {
	if (force || promptyn("%s does not exist.  Do you want to create it?",
			      gtlsshdir)) {
	    make_dir(gtlsshdir, true);
	    created = true;
	} else {
	    printf("Not modifying %s, giving up\n", gtlsshdir);
	    exit(1);
	}
    }

    check_dir(created, true, "%s%ckeycerts", gtlsshdir, DIRSEP);
    check_dir(created, true, "%s%callowed_certs", gtlsshdir, DIRSEP);
    check_dir(created, true, "%s%cserver_certs", gtlsshdir, DIRSEP);
}

#define ITERATE_DIR_ERR 2
#define ITERATE_DIR_STOP 1
#define ITERATE_DIR_CONTINUE 0
static int
iterate_dir(const char *dir,
	    int (*op)(const char *dir, const char *name, void *cbdata),
	    void *cbdata)
{
    DIR *d;
    struct dirent *e;
    int rv;

    d = opendir(dir);
    if (d == NULL) {
	fprintf(stderr, "Unable to open dir %s: %s\n", dir, strerror(errno));
	return 1;
    }

    while ((e = readdir(d))) {
	rv = op(dir, e->d_name, cbdata);
	if (rv == ITERATE_DIR_ERR)
	    return 1;
	if (rv == ITERATE_DIR_STOP)
	    break;
    }

    return 0;
}

int
check_for_certfile(const char *dir, const char *name, void *cbdata)
{
    const char *s = strrchr(name, '.');

    if (strcmp(s, ".crt") == 0) {
	bool *certpresent = cbdata;

	*certpresent = true;
	/* Only need 1. */
	return ITERATE_DIR_STOP;
    }
    return ITERATE_DIR_CONTINUE;
}

int
remove_links(const char *dir, const char *name, void *cbdata)
{
    const char *s;
    char *fname;
    int rv;

    for (s = name; *s && *s != '.'; s++) {
	/* Before the '.' must be all hex digits. */
	if (!isxdigit(*s))
	    return ITERATE_DIR_CONTINUE;
    }
    if (*s != '.')
	return ITERATE_DIR_CONTINUE;
    s++;
    /* After the '.' is a decimal number. */
    if (!isdigit(*s))
	return ITERATE_DIR_CONTINUE;
    s++;
    for (; *s; s++) {
	/* Before the '.' must be all decimal digits. */
	if (!isdigit(*s))
	    return ITERATE_DIR_CONTINUE;
    }

    /* It's a link, remove it. */
    fname = alloc_sprintf("%s%c%s", dir, DIRSEP, name);
    if (!fname) {
	fprintf(stderr, "Out of memory allocating for %s%c%s",
		dir, DIRSEP, name);
	return ITERATE_DIR_ERR;
    }
    rv = delete_file(fname);
    free(fname);
    if (rv) {
	fprintf(stderr, "Unable to remove %s%c%s: %s", dir, DIRSEP, name,
		strerror(errno));
	return ITERATE_DIR_ERR;
    }
    return ITERATE_DIR_CONTINUE;
}

struct datalist {
    void *data;
    unsigned int len;
    struct datalist *next;
};

static bool
data_in_list(void *data, unsigned int len, struct datalist *list,
	     bool (*cmp)(void *d1, unsigned int len1,
			 void *d2, unsigned int len2, void *cbdata),
	     void *cbdata)
{
    for (; list; list = list->next) {
	if (cmp(data, len, list->data, list->len, cbdata))
	    return true;
    }
    return false;
}

static void
data_list_free(struct datalist *list,
	       void (*freeit)(void *d, unsigned int len, void *cbdata),
	       void *cbdata)
{
    struct datalist *next;

    for (; list; list = next) {
	next = list->next;
	freeit(list->data, list->len, cbdata);
    }
}

static int
add_data_to_list(void *data, unsigned int len, struct datalist **list)
{
    struct datalist *new_link;

    new_link = malloc(sizeof(*new_link));
    if (!new_link)
	return 1;
    new_link->data = data;
    new_link->len = len;
    new_link->next = *list;
    *list = new_link;
    return 0;
}

typedef X509 Cert;

static Cert *
load_cert(const char *file)
{
    BIO *in;
    X509 *cert;

    in = BIO_new_file(file, "r");
    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    BIO_free(in);
    if (!cert) {
	fprintf(stderr, "Unable to load PEM X509 cert at %s: ", file);
	ERR_print_errors_fp(stderr);
    }
    return cert;
}

static void
free_cert(Cert *cert)
{
    X509_free(cert);
}

static bool
cmp_certs(Cert *cert1, Cert *cert2)
{
    return X509_cmp(cert1, cert2) == 0;
}

static bool
hash_cert_cmp(void *data1, unsigned int data1len,
	      void *data2, unsigned int data2len, void *cbdata)
{
    return cmp_certs(data1, data2);
}

static void
hash_cert_free(void *data, unsigned int datalen, void *cbdata)
{
    free_cert(data);
}

struct hash_dir_info {
    struct datalist *certs;
};

static int
hash_file(const char *dir, const char *name, void *cbdata)
{
    struct hash_dir_info *info = cbdata;
    Cert *cert = NULL;
    char *s = NULL;
    unsigned long hash;
    unsigned int i;
    int rv = ITERATE_DIR_CONTINUE;
    const ASN1_TIME *notafter;
    const char *endstr = strrchr(name, '.');

    if (strcmp(endstr, ".crt") != 0)
	return ITERATE_DIR_CONTINUE;

    s = alloc_sprintf("%s%c%s", dir, DIRSEP, name);
    if (!s) {
	fprintf(stderr, "Out of memory allocating %s%c%s", dir, DIRSEP, name);
	return ITERATE_DIR_ERR;
    }
    
    cert = load_cert(s);
    if (!cert)
	goto out_err;

    notafter = X509_get0_notAfter(cert);
    if (X509_cmp_current_time(notafter) < 0) {
	printf("Removing expired certificate %s\n", s);
	delete_file(s);
	free(s);
	free_cert(cert);
	return ITERATE_DIR_CONTINUE;
    }

    if (data_in_list(cert, 0, info->certs, hash_cert_cmp, NULL)) {
	/* Duplicate */
	free(s);
	free_cert(cert);
	return ITERATE_DIR_CONTINUE;
    }

    if (add_data_to_list(cert, 0, &info->certs)) {
	fprintf(stderr, "Unable to add certificate to list\n");
	free_cert(cert);
	goto out_err;
    }

    hash = X509_subject_name_hash(cert);
    for (i = 0; i < 100; i++) {
	int err;
	char *l = alloc_sprintf("%s%c%08lx.%d", dir, DIRSEP, hash, i);

	if (!l) {
	    fprintf(stderr, "Out of memory allocating %s%c%08lx.%d",
		    dir, DIRSEP, hash, i);
	    goto out_err;
	}

	err = make_link(l, s, name);
	free(l);
	if (err == 0)
	    goto out;
	if (err != LINK_EXISTS)
	    goto out_err;
    }
    fprintf(stderr, "Unable to make a link for %s, too many tries\n", s);
    goto out_err;

 out:
    if (s)
	free(s);
    return rv;

 out_err:
    rv = ITERATE_DIR_ERR;
    goto out;
}

static void
hash_dir(const char *fmt, ...)
{
    bool certpresent;
    int err;
    char *dir;
    va_list args;
    struct hash_dir_info info;

    va_start(args, fmt);
    dir = alloc_vsprintf(fmt, args);
    va_end(args);

    if (!dir) {
	fprintf(stderr,
		"hash_dir: Unable to allocate directory string, giving up\n");
	exit(1);
    }

    memset(&info, 0, sizeof(info));

    err = iterate_dir(dir, check_for_certfile, &certpresent);
    if (err) {
	fprintf(stderr, "Unable to iterate %s, not hashing that dir\n", dir);
	goto out;
    }
    if (!certpresent) {
	printf("No certificates in %s, not rehashing\n", dir);
	goto out;
    }

    err = iterate_dir(dir, remove_links, NULL);
    if (err) {
	fprintf(stderr, "Unable to iterate(2) %s, not hashing that dir\n", dir);
	goto out;
    }

    err = iterate_dir(dir, hash_file, &info);
    if (err) {
	fprintf(stderr, "Unable to iterate(3) %s, not hashing that dir\n", dir);
	goto out;
    }

 out:
    data_list_free(info.certs, hash_cert_free, NULL);
    free(dir);
}

static int
rehash(int argc, char *argv[])
{
    int i;

    if (argc == 0) {
	hash_dir("%s%callowed_certs", gtlsshdir, DIRSEP);
	hash_dir("%s%cserver_certs", gtlsshdir, DIRSEP);
    } else {
	for (i = 0; i < argc; i++) {
	    if (!check_dir_exists(argv[i], false))
		fprintf(stderr, "%s is not a directory", argv[i]);
	    else
		hash_dir(argv[i]);
	}
    }

    return 0;
}

static int
addallow(int argc, char **argv)
{
    bool do_stdin = false;
    int i;
    char *dest = NULL;

    for (i = 0; i < argc; i++) {
	if (argv[i][0] != '-')
	    break;
	if (strcmp(argv[i], "--") == 0) {
	    i++;
	    break;
	}
	if (cmparg(argc, argv, &i, "-i", NULL, NULL)) {
	    do_stdin = true;
	    continue;
	}

	fprintf(stderr, "Unknown parameter: %s\n", argv[i]);
	return 1;
    }

    argc -= i;
    argv += i;

    if (argc < 1) {
	fprintf(stderr, "Missing hostname for addallow, see help\n");
	return 1;
    }
    if (!do_stdin && argc < 2) {
	fprintf(stderr, "Missing certificate file for addallow, see help\n");
	return 1;
    }

    dest = alloc_sprintf("%s%callowed_certs%c%s.crt", gtlsshdir, DIRSEP,
			 DIRSEP, argv[0]);
    if (!dest) {
	fprintf(stderr, "Can't allocate memory for %s/allowed_certs/%s.crt\n",
		gtlsshdir, argv[0]);
	return 1;
    }

    if (check_file_exists(dest)) {
	if (force || promptyn("File %s already exists, do you want to overwrite it?", dest)) {
	    delete_file(dest);
	} else {
	    printf("Not installing certificate at %s\n", dest);
	    goto out_err;
	}
    }
    if (do_stdin) {
	if (copy_to_file(stdin, dest, "-----END CERTIFICATE-----"))
	    goto out_err;
    } else {
	FILE *f = fopen(argv[1], "r");

	if (!f) {
	    fprintf(stderr, "Unable to open %s\n", argv[1]);
	    goto out_err;
	}
	if (copy_to_file(f, dest, NULL)) {
	    fclose(f);
	    goto out_err;
	}
	fclose(f);
    }
    hash_dir("%s%callowed_certs", gtlsshdir, DIRSEP);
    return 0;

 out_err:
    free(dest);
    return 1;
}

static int
keygen_one(const char *name, const char *key, const char *cert)
{
    const char *argv[15];
    char *out, *errout, *keyval, *days, *cn, *s;
    int err, rc;

    if (check_file_exists(key) || check_file_exists(cert)) {
	if (force || promptyn("Files %s or %s already exist, do you want to overwrite them?", key, cert)) {
	    /* Move the key and certificate to backup files. */
	    s = alloc_sprintf("%s.1", key);
	    if (s) {
		move_file(key, s);
		free(s);
	    }
	    s = alloc_sprintf("%s.1", cert);
	    if (s) {
		move_file(key, s);
		free(s);
	    }
	    delete_file(key);
	    delete_file(cert);
	} else {
	    printf("Not generating key for %s", name);
	    return 1;
	}
    }

    argv[0] = "openssl";
    argv[1] = "req";
    argv[2] = "-newkey";
    keyval = alloc_sprintf("rsa:%u", keysize);
    if (!keyval) {
	fprintf(stderr, "Out of memory allocating key settings\n");
	return 1;
    }
    argv[3] = keyval;
    argv[4] = "-nodes";
    argv[5] = "-keyout";
    argv[6] = key;
    argv[7] = "-x509";
    argv[8] = "-days";
    days = alloc_sprintf("%u", keydays);
    if (!days) {
	free(keyval);
	fprintf(stderr, "Out of memory allocating days settings\n");
	return 1;
    }
    argv[9] = days;
    argv[10] = "-out";
    argv[11] = cert;
    argv[12] = "-subj";
    cn = alloc_sprintf("/CN=%s", commonname);;
    if (!cn) {
	free(days);
	free(keyval);
	fprintf(stderr, "Out of memory allocating commonname settings\n");
	return 1;
    }
    argv[13] = cn;
    argv[14] = NULL;

    err = run_get_output(argv, true, NULL, 0,
			 NULL, 0, &out, NULL, &errout, NULL, &rc);
    free(keyval);
    free(days);
    free(cn);
    if (err)
	return 1;

    if (rc) {
	fprintf(stderr, "Error running openssl: %s\n", errout);
    } else {
	printf("Key created.  Put %s into:\n", cert);
	printf("  .gtlssh/allowed_certs\n");
	printf("on remote systems you want to log into without a password.\n");
    }

    free(out);
    free(errout);
    return 0;
}

static int
keygen(int argc, char *argv[])
{
    char *key, *cert, port[128];
    int err, i;

    if (argc == 0) {
	key = alloc_sprintf("%s%cdefault.key", gtlsshdir, DIRSEP);
	if (!key) {
	    fprintf(stderr, "Out of memory allocating key\n");
	    return 1;
	}
	cert = alloc_sprintf("%s%cdefault.crt", gtlsshdir, DIRSEP);
	if (!cert) {
	    free(key);
	    fprintf(stderr, "Out of memory allocating cert\n");
	    return 1;
	}
	err = keygen_one("default", key, cert);
	free(key);
	free(cert);
	return err;
    }

    port[0] = '\0';
    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "-p") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No port given with -p");
		return err;
	    }
	    if (strlen(argv[i]) == 0)
		port[9] = '\0';
	    else
		snprintf(port, sizeof(port), ",%s", argv[i]);
	} else {
	    key = alloc_sprintf("%s%c%s%s.key", keydir, DIRSEP, argv[i], port);
	    if (!key) {
		fprintf(stderr, "Out of memory allocating key\n");
		return 1;
	    }
	    cert = alloc_sprintf("%s%c%s%s.crt", keydir, DIRSEP, argv[i], port);
	    if (!cert) {
		free(key);
		fprintf(stderr, "Out of memory allocating cert\n");
		return 1;
	    }
	    err = keygen_one(argv[i], key, cert);
	    free(key);
	    free(cert);
	    if (err)
		return 1;
	}
    }
    return 0;
}

#ifdef DEFAULT_CONFDIR
static int
serverkey(int inargc, char *inargv[])
{
    const char *keyname = "gtlsshd";
    const char *argv[15];
    char *serverkey = NULL, *servercert = NULL, *s;
    char *keyval = NULL, *days = NULL, *cn = NULL;
    char *out = NULL, *errout = NULL;
    int rv = 0, rc, err;

    if (inargc > 0)
	keyname = inargv[0];

    serverkey = alloc_sprintf("%s%c%s.key", confdir, DIRSEP, keyname);
    if (!serverkey) {
	fprintf(stderr, "Out of memory allocating server key\n");
	rv = 1;
	goto out;
    }
    servercert = alloc_sprintf("%s%c%s.crt", confdir, DIRSEP, keyname);
    if (!servercert) {
	fprintf(stderr, "Out of memory allocating server certificate\n");
	rv = 1;
	goto out;
    }

    if (check_file_exists(serverkey) || check_file_exists(servercert)) {
	if (force || promptyn("Files %s or %s already exist, do you want to overwrite them?", serverkey, servercert)) {
	    /* Move the key and certificate to backup files. */
	    s = alloc_sprintf("%s.1", serverkey);
	    if (s) {
		move_file(serverkey, s);
		free(s);
	    }
	    s = alloc_sprintf("%s.1", servercert);
	    if (s) {
		move_file(servercert, s);
		free(s);
	    }
	    delete_file(serverkey);
	    delete_file(servercert);
	} else {
	    printf("Not generating server keys");
	    rv = 1;
	    goto out;
	}
    }

    if (!check_dir_exists(confdir, false))
	make_dir(confdir, false);

    argv[0] = "openssl";
    argv[1] = "req";
    argv[2] = "-newkey";
    keyval = alloc_sprintf("rsa:%u", keysize);
    if (!keyval) {
	fprintf(stderr, "Out of memory allocating key settings\n");
	rv = 1;
	goto out;
    }
    argv[3] = keyval;
    argv[4] = "-nodes";
    argv[5] = "-keyout";
    argv[6] = serverkey;
    argv[7] = "-x509";
    argv[8]= "-days";
    days = alloc_sprintf("%u", keydays);
    if (!days) {
	fprintf(stderr, "Out of memory allocating days settings\n");
	rv = 1;
	goto out;
    }
    argv[9] = days;
    argv[10] = "-out";
    argv[11] = servercert;
    argv[12] = "-subj";
    cn = alloc_sprintf("/CN=%s", commonname);;
    if (!cn) {
	fprintf(stderr, "Out of memory allocating commonname settings\n");
	rv = 1;
	goto out;
    }
    argv[13] = cn;
    argv[14] = NULL;

    err = run_get_output(argv, true, NULL, 0,
			 NULL, 0, &out, NULL, &errout, NULL, &rc);

    if (err) {
	/* Error has already been printed. */
    } else if (rc) {
	fprintf(stderr, "Error running openssl for serverkey: %s\n", errout);
    } else {
	printf("Key created.  Put %s into:\n", servercert);
    }

 out:
    if (keyval)
	free(keyval);
    if (days)
	free(days);
    if (cn)
	free(cn);
    if (serverkey)
	free(serverkey);
    if (servercert)
	free(servercert);
    if (out)
	free(out);
    if (errout)
	free(errout);
    return rv;
}
#endif

static int
pushcert_one(const char *host, const char *port, const char *name)
{
    const char *argv[14];
    char *upcert = NULL, *cert = NULL, *key = NULL;
    char *out = NULL, *errout = NULL;
    char upcertstr[32768];
    int rv = 0, rc, i = 0, err;
    ssize_t upcertstr_len;
    FILE *f;

    /* Find the certificate we want to send. */
    upcert = alloc_sprintf("%s%c%s%s.crt", keydir, DIRSEP, host, port);
    if (upcert && !check_file_exists(upcert)) {
	free(upcert);
	upcert = alloc_sprintf("%s%cdefault.crt", gtlsshdir, DIRSEP);
    }
    if (!upcert) {
	fprintf(stderr, "Out of memory allocating cert info\n");
	rv = 1;
	goto out;
    }
    f = fopen(upcert, "r");
    if (!f) {
	fprintf(stderr, "Unable to open %s\n", upcert);
	rv = 1;
	goto out;
    }
    upcertstr_len = fread(upcertstr, 1, sizeof(upcertstr), f);
    fclose(f);
    if (upcertstr_len == 0) {
	fprintf(stderr, "No certificate in %s\n", upcert);
	rv = 1;
	goto out;
    } else if (upcertstr_len == sizeof(upcertstr)) {
	fprintf(stderr, "Certificate in %s is too large\n", upcert);
	rv = 1;
	goto out;
    }

    /* Now find the old credentials. */
    cert = alloc_sprintf("%s%c%s%s.crt.1", keydir, DIRSEP, host, port);
    if (cert && !check_file_exists(cert)) {
	free(cert);
	cert = alloc_sprintf("%s%cdefault.crt.1", gtlsshdir, DIRSEP);
	if (cert && !check_file_exists(cert)) {
	    printf("Could not find an old certificate for ${HOST}${PORT}.\n");
	    printf("Just trying to send it without old credentials.\n");
	    free(cert);
	    cert = NULL;
	    goto no_cert;
	}
    }
    if (cert) {
	key = strdup(cert);
	if (key)
	    strcpy(key + strlen(key) - 5, "key.1");
    }
    if (!cert || !key) {
	fprintf(stderr, "Out of memory allocating key settings\n");
	rv = 1;
	goto out;
    }

 no_cert:
    argv[i++] = "gtlssh";
    if (key) {
	argv[i++] = "--keyname";
	argv[i++] = key;
    }
    if (cert) {
	argv[i++] = "--certname";
	argv[i++] = cert;
    }
    if (strlen(port) > 0) {
	argv[i++] = "-p";
	argv[i++] = port;
    }
    argv[i++] = host;
    argv[i++] = "gtlssh-keygen";
    argv[i++] = "-f";
    argv[i++] = "addallow";
    argv[i++] = "-i";
    argv[i++] = name;
    argv[i++] = NULL;

    err = run_get_output(argv, true, NULL, 0, upcertstr, upcertstr_len,
			 &out, NULL, &errout, NULL, &rc);

    if (err) {
	/* Error has already been printed. */
    } else if (rc) {
	fprintf(stderr, "Error pushing key %s to %s: %s %s\n", upcert, host,
		out, errout);
    } else {
	printf("Certificate %s pushed to %s\n", upcert, host);
	if (debug)
	    printf("%s%s", out, errout);
    }

 out:
    if (out)
	free(out);
    if (errout)
	free(errout);
    if (upcert)
	free(upcert);
    if (key)
	free(key);
    if (cert)
	free(cert);
    return rv;
}

static int
pushcert(int argc, char *argv[])
{
    char *port, *name;
    char *defport = "";
    char *hostname;
    int rv, i;

    if (argc == 0) {
	fprintf(stderr, "No remote system given to update\n");
	return 1;
    }

    hostname = get_my_hostname();
    if (!hostname) {
	fprintf(stderr, "Out of memory allocating hostname\n");
	return 1;
    }

    port = defport;
    name = hostname;

    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "-p") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No port given with -p\n");
		rv = 1;
		goto out;
	    }
	    if (port != defport)
		free(port);
	    if (strlen(argv[i]) == 0) {
		port = defport;
	    } else {
		port = alloc_sprintf(",%s", argv[i]);
		if (!port) {
		    fprintf(stderr, "Out of memory allocating port\n");
		    rv = 1;
		    goto out;
		}
	    }
	} else if (strcmp(argv[i], "-p") == 0) {
	    i++;
	    if (i >= argc) {
		fprintf(stderr, "No name given with -n\n");
		rv = 1;
		goto out;
	    }
	    if (strlen(argv[i]) == 0) {
		name = hostname;
	    } else {
		name = argv[i];
	    }
	} else {
	    rv = pushcert_one(argv[i], port, name);
	    if (rv)
		goto out;
	}
    }

 out:
    if (hostname)
	free(hostname);
    if (port != defport)
	free(port);
    return 0;
}

int
main(int argc, char **argv)
{
    int i, rv = 1;

    default_gtlsshdir = get_tlsshdir();
    if (!default_gtlsshdir)
	exit(1);
    default_keydir = alloc_sprintf("%s%ckeycerts", gtlsshdir, DIRSEP);
    if (!default_keydir) {
	fprintf(stderr, "Could not allocate memory for keydir\n");
	exit(1);
    }

    for (i = 1; i < argc; i++) {
	if (argv[i][0] != '-')
	    break;
	if (strcmp(argv[i], "--") == 0) {
	    i++;
	    break;
	}
	if (cmparg(argc, argv, &i, "-d", "--debug", NULL)) {
	    debug++;
	    continue;
	}
	if (cmparg_uint(argc, argv, &i, NULL, "--keysize", &keysize))
	    continue;
	if (cmparg_uint(argc, argv, &i, NULL, "--keydays", &keydays))
	    continue;
	if (cmparg(argc, argv, &i, NULL, "--basedir", &gtlsshdir))
	    continue;
	if (cmparg(argc, argv, &i, NULL, "--keydir", &keydir)) {
	    keydir_set = true;
	    continue;
	}
	if (cmparg(argc, argv, &i, NULL, "--commonname", &commonname)) {
	    commonname_set = true;
	    continue;
	}
	if (cmparg(argc, argv, &i, NULL, "--force", NULL)) {
	    force = true;
	    continue;
	}
	if (cmparg(argc, argv, &i, NULL, "--help", NULL)) {
	    help(argv[0]);
	    continue;
	}

	fprintf(stderr, "Unknown option '%s'\n", argv[i]);
	exit(1);
    }

    if (!gtlsshdir)
	gtlsshdir = default_gtlsshdir;
    if (!keydir)
	keydir = default_keydir;

    argc -= i;
    argv += i;
    if (argc == 0) {
	fprintf(stderr, "No command given, use --help for help\n");
	exit(1);
    }

    if (strcmp(argv[0], "rehash") == 0)
	rv = rehash(argc - 1, argv + 1);
    else if (strcmp(argv[0], "addallow") == 0)
	rv = addallow(argc - 1, argv + 1);
    else if (strcmp(argv[0], "keygen") == 0) {
	if (!keydir_set)
	    check_dirstruct();
	if (!commonname_set) {
	    alloc_commonname = get_my_username();
	    if (!alloc_commonname) {
		fprintf(stderr, "Error allocating username\n");
		exit(1);
	    }
	    commonname = alloc_commonname;
	}
	rv = keygen(argc - 1, argv + 1);
	if (alloc_commonname)
	    free(alloc_commonname);
    } else if (strcmp(argv[0], "setup") == 0) {
	check_dirstruct();
	if (!commonname_set) {
	    alloc_commonname = get_my_username();
	    if (!alloc_commonname) {
		fprintf(stderr, "Error allocating username\n");
		exit(1);
	    }
	    commonname = alloc_commonname;
	}
	rv = keygen(0, NULL);
	if (alloc_commonname)
	    free(alloc_commonname);
#ifdef DEFAULT_CONFDIR
    } else if (strcmp(argv[0], "serverkey") == 0) {
	if (keydir_set)
	    confdir = keydir;
	if (!commonname_set) {
	    alloc_commonname = get_my_hostname();
	    if (!alloc_commonname) {
		fprintf(stderr, "Error allocating hostname\n");
		exit(1);
	    }
	    commonname = alloc_commonname;
	}
	rv = serverkey(argc - 1, argv + 1);
	if (alloc_commonname)
	    free(alloc_commonname);
#endif
    } else if (strcmp(argv[0], "pushcert") == 0) {
	rv = pushcert(argc - 1, argv + 1);
    } else {
	fprintf(stderr, "Unknown command %s, use --help for help\n", argv[i]);
	exit(1);
    }

    return rv;
}
