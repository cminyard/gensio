/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include "gensio_filter_certauth.h"
#include <gensio/gensio_err.h>

#ifdef _WIN32
#define DIRSEP '\\'
#else
#define DIRSEP '/'
#endif

struct gensio_certauth_filter_data {
    struct gensio_os_funcs *o;
    bool is_client;
    char *CAfilepath;
    char *keyfile;
    char *certfile;
    char *username;
    char *password;
    char *service;
    char *val_2fa;
    unsigned int len_2fa;
    bool allow_authfail;
    bool use_child_auth;
    bool enable_password;
    bool do_2fa; /* Ask for two-factor authentication, version 2+ */

    /*
     * The following is only used for testing. so certauth can be run
     * over stdio for fuzz testing.  Do not document.
     */
    bool allow_unencrypted;
};

#include <assert.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <gensio/gensio.h>
#include <gensio/gensio_class.h>
#include <gensio/gensio_os_funcs.h>

/* Also in gensio_filter_ssl.c. */
static int
gensio_cert_get_name(X509 *cert, char *data, gensiods *datalen)
{
    char *nidstr = NULL, *end;
    int index = -1, len, tlen, nid;
    int datasize;
    X509_NAME *nm;
    X509_NAME_ENTRY *e;
    ASN1_STRING *as;
    unsigned char *strobj;
    int strobjlen;
    ASN1_OBJECT *obj;

    if (!cert)
	return GE_NOCERT;
    datasize = *datalen;
    index = strtol(data, &end, 0);
    if (*end == ',')
	nidstr = end + 1;
    else if (*end)
	return GE_CERTINVALID;
    nm = X509_get_subject_name(cert);
    if (nidstr) {
	nid = OBJ_sn2nid(nidstr);
	if (nid == NID_undef) {
	    nid = OBJ_ln2nid(data);
	    if (nid == NID_undef)
		return GE_CERTINVALID;
	}
	index = X509_NAME_get_index_by_NID(nm, nid, index);
	if (index < 0)
	    return GE_NOTFOUND;
    }
    e = X509_NAME_get_entry(nm, index);
    if (!e)
	return GE_NOTFOUND;
    obj = X509_NAME_ENTRY_get_object(e);
    nid = OBJ_obj2nid(obj);
    len = snprintf(data, datasize, "%d,%s,", index, OBJ_nid2sn(nid));
    as = X509_NAME_ENTRY_get_data(e);
    strobjlen = ASN1_STRING_to_UTF8(&strobj, as);
    if (strobjlen < 0)
	return GE_NOMEM;
    tlen = strobjlen;
    if (len + 1 < datasize) {
	if (strobjlen > datasize - len - 1)
	    strobjlen = datasize - len - 1;
	memcpy(data + len, strobj, strobjlen);
	data[strobjlen + len] = '\0';
    }
    len += tlen;
    OPENSSL_free(strobj);
    *datalen = len;
    return 0;
}

/* Also in gensio_filter_ssl.c. */
static int
gensio_cert_to_buf(X509 *cert, char *buf, gensiods *buflen)
{
    BIO *mbio;
    BUF_MEM *bptr;
    gensiods len = *buflen, copylen;

    mbio = BIO_new(BIO_s_mem());
    if (!mbio)
	return GE_NOMEM;

    if (PEM_write_bio_X509(mbio, cert) == 0) {
	BIO_free(mbio);
	return GE_IOERR;
    }

    BIO_get_mem_ptr(mbio, &bptr);
    *buflen = bptr->length;
    copylen = len;
    if (copylen > bptr->length)
	copylen = bptr->length;
    memcpy(buf, bptr->data, copylen);
    if (len > copylen)
	buf[copylen] = '\0';
    BIO_free(mbio);
    return 0;
}

/* Also in gensio_filter_ssl.c. */
static int
gensio_cert_fingerprint(X509 *cert, char *buf, gensiods *buflen)
{
    gensiods len = *buflen, clen;
    unsigned int i, n, l;
    unsigned char md[EVP_MAX_MD_SIZE];

    if (X509_digest(cert, EVP_sha1(), md, &n) == 0)
	return GE_NOMEM;

    clen = snprintf(buf, len, "%2.2X", md[0]);
    for (i = 1; i < n; i++) {
	if (clen >= len)
	    l = 0;
	else
	    l = len - clen;

	clen += snprintf(buf + clen, l, ":%2.2X", md[i]);
    }
    *buflen = clen;
    return 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_up_ref(x) CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509)
static EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    EVP_MD_CTX *c = OPENSSL_malloc(sizeof(*c));

    if (c)
	memset(c, 0, sizeof(*c));
    return c;
}
static void EVP_MD_CTX_free(EVP_MD_CTX *c)
{
    OPENSSL_free(c);
}
#endif

#define GENSIO_CERTAUTH_DATA_SIZE	2048
#define GENSIO_CERTAUTH_CHALLENGE_SIZE	32
#define GENSIO_CERTAUTH_VERSION		4

/*
 * Passwords are always sent in this size buffer to keep an attacker
 * from getting the actual password length.
 */
#define GENSIO_CERTAUTH_PASSWORD_LEN	100

/*
 * A message consists of the following:
 *
 * <message number> [ <element number> <element length> <element data>
 *	[ <element number> ...] <end element>
 *
 * The message number is the same as the states below, it is one byte
 * long.  Message elements may come in any order.  The element number
 * is one byte and the element length is a two byte network order
 * unsigned integer, giving the maximum element data length of 65535
 * bytes.
 */

/*
 * State machines for both the client and the server, also message
 * numbers (except for CLIENT_START).
 */
enum certauth_state {
    /*
     * Client first sends the hello (containing the version, username,
     * and optional service and options) and goes into SERVERHELLO.
     */
    CERTAUTH_CLIENT_START = 0,

    /*
     * Server waits for CLIENTHELLO.
     *
     * The app is called to check the username.  If the app says
     * verification is done, send a SERVERDONE with error result
     * from the app.
     *
     * If apps says to continue verification, send the SERVERHELLO
     * (containing the version, random challenge, and optional
     * options) and goes into CHALLENGE_RESPONSE.
     *
     * Message contains a VERSION element, an optional USERNAME
     * element, and an optional SERVICE element.
     */
    CERTAUTH_CLIENTHELLO = 1,

    /*
     * Client waits for SERVERHELLO and uses the random challenge to
     * generate a challenge response and sends challenge response
     * (containing certificate and challenge response) and goes into
     * PASSWORD_REQUEST.
     *
     * Client may also receive a SERVERDONE in this state if the
     * authorization is rejected or authorized on username alone.
     *
     * Message contains a VERSION element, a CHALLENGE_DATA element,
     * and an optional AUX_DATA element.  AUX_DATA is version 2 or
     * later.
     */
    CERTAUTH_SERVERHELLO = 2,

    /*
     * Server receives the challenge response verifies the reponse and
     * the certificate against the CA.
     *
     * The app is called before the verification so it can do things
     * based on certificate data.  If the app says
     * verification is done, send a SERVERDONE with error result
     * from the app.
     *
     * Otherwise the certificate is verified and the challenge
     * response is checked.  If the certificate verifies but the
     * challenge response fails, fail the connection.  If both pass
     * verification, send a SERVERDONE giving the result and go into
     * passthrough mode.  If the certificate does not verify, send
     * a PASSWORD_REQUEST (no data) and go into PASSWORD mode.
     *
     * Message contains a CERTIFICATE element, a CHALLENGE_RSP
     * element, and an optional AUX_DATA element.  AUX_DATA is version
     * 2 or later.  AUX_DATA has to be here, and not in CLIENTHELLO,
     * because the client doesn't know the remote version when sending
     * a CLIENTHELLO.
     */
    CERTAUTH_CHALLENGE_RESPONSE = 3,

    /*
     * Client waits for PASSWORD_REQUEST.
     *
     * Client may also receive a SERVERDONE in this state if the
     * authorization is rejected or authorized by the certificate.
     *
     * Message contains a PASSWORD_TYPE element to tell how to handle
     * the request.
     */
    CERTAUTH_PASSWORD_REQUEST = 4,

    /*
     * Server waits for a password.  When received. the application is
     * notified of the password.  Send a SERVERDONE with error result
     * from the app.
     *
     * Message contains either a PASSWORD_DATA element or a DUMMY_DATA
     * element and then an optional 2FA_DATA element.
     */
    CERTAUTH_PASSWORD = 5,

    /*
     * Client waits for SERVERDONE and goes into passthrough mode if
     * successful, contains the result.
     *
     * Message contains a RESULT element.
     */
    CERTAUTH_SERVERDONE = 6,

    /*
     * We are done, just waiting for the data to be written from the
     * buffer before reporting so.
     */
    CERTAUTH_WAIT_WRITE_DONE = 107,

    /*
     * Just pass all the data through.
     */
    CERTAUTH_PASSTHROUGH = 108,

    /*
     * Something went wrong, abort.
     */
    CERTAUTH_ERR = 109
};
#define CERTAUTH_STATE_MAX CERTAUTH_SERVERDONE

/*
 * Various message components.
 *
 * The contents are given for each one.
 */
enum certauth_elements {
    /*
     *  100 2 <2 byte version number>
     */
    CERTAUTH_VERSION		= 100,

    /*
     * 101 <n> <n byte string>
     */
    CERTAUTH_USERNAME		= 101,

    /*
     * Currently not used.
     */
    CERTAUTH_OPTIONS		= 102,

    /*
     * 103 32 <32 bytes of random data>
     */
    CERTAUTH_CHALLENGE_DATA	= 103,

    /*
     * 104 <n> <signature of random data plus service id signed by the
     *          client private key>
     */
    CERTAUTH_CHALLENGE_RSP	= 104,

    /*
     * 105 <n> <X509 certificate in PEM format>
     */
    CERTAUTH_CERTIFICATE	= 105,

    /*
     * 106 2 1|2
     *
     * The challenge response is verified, 1 is for success, 2 is for
     * failure.
     */
    CERTAUTH_RESULT		= 106,

    /*
     * 107 <n> <n-byte string with service name>
     *
     * The service is used to tell the server what service the client
     * wishes to run.  It is optional and may be ignored.
     */
    CERTAUTH_SERVICE		= 107,

    /*
     * 108 100 <100-byte string with password>
     *
     * The service is used to transfer a password.
     */
    CERTAUTH_PASSWORD_DATA	= 108,

    /* 109 n <n zeros>
     *
     * Dummy data to mask the fact that we are not sending certs or
     * passwords.
     */
    CERTAUTH_DUMMY_DATA		= 109,

    /*
     * 110 2 <val>
     * The bottom two bits is what password data we are asking for, either
     * send the password (1) or send a dummy (2).  Bit 8 requests that a
     * 2FA_DATA element be sent, also.
     */
    CERTAUTH_PASSWORD_TYPE	= 110,

    /*
     * 111 <n> <2fa data length n>
     *
     * The service is used to transfer 2-factor auth data.  Added in version 2.
     */
    CERTAUTH_2FA_DATA		= 111,

    /*
     * 112 <n> <data>
     *
     * Holds a block of generic data.  It has no meaning to certauth,
     * it is used to transfer useful information to the other end.
     */
    CERTAUTH_AUX_DATA		= 112,

    /*
     * 200
     *
     * This is the last thing in the message.
     */
    CERTAUTH_END		= 200
};
#define CERTAUTH_MIN_ELEMENT CERTAUTH_VERSION
#define CERTAUTH_MAX_ELEMENT CERTAUTH_AUX_DATA

#define CERTAUTH_RESULT_SUCCESS	1
#define CERTAUTH_RESULT_FAILURE	2
#define CERTAUTH_RESULT_ERR	3

/* Request a password. */
#define CERTAUTH_PASSWORD_TYPE_REQ	1
/* Don't send a password, just send dummy data. */
#define CERTAUTH_PASSWORD_TYPE_DUMMY	2
#define CERTAUTH_PASSWORD_TYPE_MASK	0xff
/*
 * Request 2 factor authentication data on top of password or dummy data.
 * Added in version 2.
 */
#define CERTAUTH_PASSWORD_TYPE_BIT_2FA	(1 << 8)

struct certauth_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;
    bool is_client;
    enum certauth_state state;
    struct gensio_lock *lock;

    /*
     * If we get an error while reading, hold it here until the try
     * connect is called.
     */
    int pending_err;

    /* Version number from the remote end. */
    unsigned int version;

    /* My version number, may be lowered due to openssl capabilities. */
    unsigned int my_version;

    /* Result from the server or local verification. */
    unsigned int result;

    /* Result from the response check. */
    unsigned int response_result;

    /* Certificate verification result, server only. */
    bool verified;

    /* Use authenticated from the child gensio to skip this layer. */
    bool use_child_auth;

    /* Enable password authentication. */
    bool enable_password;

    /* Enable 2-factor authentication. */
    bool do_2fa;

    char *username;
    size_t username_len;

    unsigned int password_req_val;
    char *password;
    size_t password_len;

    bool req_2fa_val;
    unsigned char *val_2fa;
    gensiods len_2fa;

    /* Aux data locally and from the remote end. */
    unsigned char *val_aux;
    gensiods len_aux;
    unsigned char *val_rem_aux;
    gensiods len_rem_aux;

    char *service;
    size_t service_len;

    unsigned char *challenge_data;
    gensiods challenge_data_size;

    X509 *cert;
    STACK_OF(X509) *sk_ca;
    EVP_PKEY *pkey;
    X509_STORE *verify_store;

    bool allow_authfail;

    BUF_MEM cert_buf_mem;
    BIO *cert_bio;
    const EVP_MD *rsa_md5;
    const EVP_MD *sha3_512;
    const EVP_MD *digest;

    unsigned char *read_buf;
    gensiods read_buf_len;
    gensiods max_read_size;

    unsigned char *write_buf;
    gensiods write_buf_len;
    gensiods write_buf_pos;
    gensiods max_write_size;

    /*
     * Processing for incoming messages.
     */
    unsigned char curr_msg_type;
    unsigned char curr_elem;
    unsigned int curr_elem_len;
    bool curr_elem_len_b1;
    bool curr_elem_len_b2;
    bool got_msg;
};

#define filter_to_certauth(v) ((struct certauth_filter *) \
			       gensio_filter_get_user_data(v))

static void
gca_vlog(struct certauth_filter *f, enum gensio_log_levels l,
	 bool do_ssl_err, char *fmt, va_list ap)
{
    if (do_ssl_err) {
	char buf[256], buf2[200];
	unsigned long ssl_err = ERR_get_error();

	if (!ssl_err)
	    goto no_ssl_err;

	ERR_error_string_n(ssl_err, buf2, sizeof(buf2));
	snprintf(buf, sizeof(buf), "certauth: %s: %s", fmt, buf2);
	gensio_vlog(f->o, l, buf, ap);
    } else {
    no_ssl_err:
	gensio_vlog(f->o, l, fmt, ap);
    }
}


static void
gca_log_info(struct certauth_filter *f, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gca_vlog(f, GENSIO_LOG_INFO, false, fmt, ap);
    va_end(ap);
}

static void
gca_log_err(struct certauth_filter *f, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gca_vlog(f, GENSIO_LOG_ERR, false, fmt, ap);
    va_end(ap);
}

static void
gca_logs_info(struct certauth_filter *f, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gca_vlog(f, GENSIO_LOG_INFO, true, fmt, ap);
    va_end(ap);
}

static void
gca_logs_err(struct certauth_filter *f, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gca_vlog(f, GENSIO_LOG_ERR, true, fmt, ap);
    va_end(ap);
}

static void
certauth_lock(struct certauth_filter *sfilter)
{
    sfilter->o->lock(sfilter->lock);
}

static void
certauth_unlock(struct certauth_filter *sfilter)
{
    sfilter->o->unlock(sfilter->lock);
}

static void
certauth_set_callbacks(struct gensio_filter *filter,
		  gensio_filter_cb cb, void *cb_data)
{
    /* We don't currently use callbacks. */
}

static bool
certauth_ul_read_pending(struct gensio_filter *filter)
{
    return false; /* We never have data pending to the upper layer. */
}

static bool
certauth_ll_write_pending(struct gensio_filter *filter)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);

    return sfilter->write_buf_len > 0;
}

static bool
certauth_ll_read_needed(struct gensio_filter *filter)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);

    /*
     * Turn off read when we have a message to process.
     */
    return !sfilter->got_msg;
}

static int
certauth_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);
    int rv = 0;

    certauth_lock(sfilter);
    if (!sfilter->result)
	sfilter->result = CERTAUTH_RESULT_FAILURE;

    if (sfilter->result == CERTAUTH_RESULT_SUCCESS)
	gensio_set_is_authenticated(io, true);
    else if (sfilter->result == CERTAUTH_RESULT_ERR)
	rv = GE_AUTHREJECT;
    else if (sfilter->is_client || !sfilter->allow_authfail)
	rv = GE_AUTHREJECT;

    certauth_unlock(sfilter);
    return rv;
}

static void
certauth_write(struct certauth_filter *sfilter, void *data, unsigned int len)
{
    if (len + sfilter->write_buf_len > sfilter->max_write_size) {
	gca_log_err(sfilter, "Unable to write data to network");
	sfilter->pending_err = GE_TOOBIG;
	return;
    }
    memcpy(sfilter->write_buf + sfilter->write_buf_len, data, len);
    sfilter->write_buf_len += len;
}

static void
certauth_write_zeros(struct certauth_filter *sfilter, unsigned int len)
{
    if (len + sfilter->write_buf_len > sfilter->max_write_size) {
	gca_log_err(sfilter, "Unable to write data to network");
	sfilter->pending_err = GE_TOOBIG;
	return;
    }
    memset(sfilter->write_buf + sfilter->write_buf_len, 0, len);
    sfilter->write_buf_len += len;
}

static void
certauth_u16_to_buf(unsigned char *buf, unsigned int v)
{
    buf[0] = (v >> 8) & 0xff;
    buf[1] = v & 0xff;
}

static unsigned int
certauth_buf_to_u16(unsigned char *buf)
{
    return (((unsigned int) buf[0]) << 8) | buf[1];
}

static void
certauth_write_byte(struct certauth_filter *sfilter, unsigned char b)
{
    certauth_write(sfilter, &b, 1);
}

static void
certauth_write_u16(struct certauth_filter *sfilter, unsigned int v)
{
    unsigned char d[2];

    certauth_u16_to_buf(d, v);
    certauth_write(sfilter, d, 2);
}

static gensiods
certauth_writeleft(struct certauth_filter *sfilter)
{
    return sfilter->max_write_size - sfilter->write_buf_len;
}

static void *
certauth_writepos(struct certauth_filter *sfilter)
{
    return sfilter->write_buf + sfilter->write_buf_len;
}

static int
certauth_verify_cert(struct certauth_filter *sfilter)
{
    X509_STORE_CTX *cert_store_ctx = NULL;
    int rv = 0, verify_err;
    const char *auxdata[] = { NULL, NULL };

    cert_store_ctx = X509_STORE_CTX_new();
    if (!cert_store_ctx) {
	rv = GE_NOMEM;
	goto out_err;
    }

    if (!X509_STORE_CTX_init(cert_store_ctx, sfilter->verify_store,
			     sfilter->cert, sfilter->sk_ca)) {
	rv = GE_NOMEM;
	goto out_err;
    }

    verify_err = X509_verify_cert(cert_store_ctx);
    if (verify_err <= 0) {
	verify_err = X509_STORE_CTX_get_error(cert_store_ctx);
	if (verify_err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
	    verify_err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	    rv = GE_CERTNOTFOUND;
	else if (verify_err == X509_V_ERR_CERT_REVOKED)
	    rv = GE_CERTREVOKED;
	else if (verify_err == X509_V_ERR_CERT_HAS_EXPIRED ||
		 verify_err == X509_V_ERR_CRL_HAS_EXPIRED)
	    rv = GE_CERTEXPIRED;
	else
	    rv = GE_CERTINVALID;
    } else {
	verify_err = X509_V_OK;
    }

    certauth_unlock(sfilter);
    if (rv)
	auxdata[0] = X509_verify_cert_error_string(verify_err);
    rv = gensio_filter_do_event(sfilter->filter, GENSIO_EVENT_POSTCERT_VERIFY,
				rv, NULL, NULL, auxdata);
    certauth_lock(sfilter);
    if (rv == GE_NOTSUP) {
	if (verify_err != X509_V_OK) {
	    gca_logs_info(sfilter,
			  "Remote peer certificate verify failed: %s",
			  X509_verify_cert_error_string(verify_err));
	    rv = GE_NOTSUP;
	} else {
	    rv = 0;
	}
    }
    if (rv == 0)
	sfilter->verified = true;

 out_err:
    if (cert_store_ctx)
	X509_STORE_CTX_free(cert_store_ctx);

    return rv;
}

static int
certauth_add_cert(struct certauth_filter *sfilter)
{
    unsigned int lenpos;

    certauth_write_byte(sfilter, CERTAUTH_CERTIFICATE);
    lenpos = sfilter->write_buf_len;
    sfilter->write_buf_len += 2;
    sfilter->cert_buf_mem.length = 0;
    sfilter->cert_buf_mem.data = certauth_writepos(sfilter);
    sfilter->cert_buf_mem.max = certauth_writeleft(sfilter);
    BIO_set_mem_buf(sfilter->cert_bio, &sfilter->cert_buf_mem, BIO_NOCLOSE);
    BIO_set_flags(sfilter->cert_bio, 0);
    if (PEM_write_bio_X509(sfilter->cert_bio, sfilter->cert) == 0) {
	gca_logs_err(sfilter, "Failure writing cert to network");
	return GE_TOOBIG;
    }
    sfilter->write_buf_len += sfilter->cert_buf_mem.length;
    certauth_u16_to_buf(sfilter->write_buf + lenpos,
			sfilter->cert_buf_mem.length);

    return 0;
}

static int
certauth_get_cert(struct certauth_filter *sfilter)
{
    sfilter->cert_buf_mem.length = sfilter->read_buf_len;
    sfilter->cert_buf_mem.data = (char *) sfilter->read_buf;
    sfilter->cert_buf_mem.max = sfilter->read_buf_len;
    BIO_set_mem_buf(sfilter->cert_bio, &sfilter->cert_buf_mem,
		    BIO_NOCLOSE);
    BIO_set_flags(sfilter->cert_bio, BIO_FLAGS_MEM_RDONLY);
    sfilter->cert = PEM_read_bio_X509(sfilter->cert_bio, NULL, NULL, NULL);
    if (!sfilter->cert) {
	gca_logs_err(sfilter, "Failure reading cert from network");
	return GE_NOCERT;
    }

    sfilter->sk_ca = sk_X509_new_null();
    if (!sfilter->sk_ca) {
	gca_log_err(sfilter, "Failure allocating CA stack");
	return GE_NOMEM;
    }
    if (!sk_X509_push(sfilter->sk_ca, sfilter->cert)) {
	gca_log_err(sfilter, "Failure pushing to CA stack");
	return GE_NOMEM;
    }
    /* cert is in the stack and held by the user. */
    X509_up_ref(sfilter->cert);

    return 0;
}

static int
v3_certauth_add_challenge_rsp(struct certauth_filter *sfilter)
{
    EVP_MD_CTX *sign_ctx;
    unsigned int lenpos, len;
    int rv = 0;

#ifdef EVP_PKEY_ED25519
    if (EVP_PKEY_base_id(sfilter->pkey) == EVP_PKEY_ED25519) {
	gca_log_err(sfilter,
		    "Remote end or SSL too old to support ed25519 key");
	return GE_KEYINVALID;
    }
#endif

    certauth_write_byte(sfilter, CERTAUTH_CHALLENGE_RSP);
    lenpos = sfilter->write_buf_len;
    sfilter->write_buf_len += 2;
    if (certauth_writeleft(sfilter) < EVP_PKEY_size(sfilter->pkey)) {
	gca_log_err(sfilter, "Key too large to fit in the data");
	return GE_TOOBIG;
    }

    sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx) {
	gca_log_err(sfilter, "Unable to allocate signature context");
	return GE_NOMEM;
    }
    if (!EVP_SignInit(sign_ctx, sfilter->digest)) {
	gca_logs_err(sfilter, "Signature init failed");
	goto out_nomem;
    }
    if (!EVP_SignUpdate(sign_ctx, sfilter->challenge_data,
			sfilter->challenge_data_size)) {
	gca_logs_err(sfilter, "Signature update failed");
	goto out_nomem;
    }
    if (!EVP_SignUpdate(sign_ctx, sfilter->service, sfilter->service_len)) {
	gca_logs_err(sfilter, "Signature update (service) failed");
	goto out_nomem;
    }
    if (!EVP_SignFinal(sign_ctx, certauth_writepos(sfilter), &len,
		       sfilter->pkey)) {
	gca_logs_err(sfilter, "Signature final failed");
	goto out_nomem;
    }
    sfilter->write_buf_len += len;
    certauth_u16_to_buf(sfilter->write_buf + lenpos, len);

 out:
    EVP_MD_CTX_free(sign_ctx);
    return rv;

 out_nomem:
    rv = GE_NOMEM;
    goto out;
}

static int
certauth_add_challenge_rsp(struct certauth_filter *sfilter)
{
    struct gensio_os_funcs *o = sfilter->o;
    EVP_MD_CTX *sign_ctx;
    size_t lenpos, len;
    int rv = 0;
    unsigned char *to_sign = NULL;
    gensiods to_sign_size;
    const EVP_MD *digest = sfilter->digest;

    if (sfilter->version < 4 || sfilter->my_version < 4)
	return v3_certauth_add_challenge_rsp(sfilter);

#ifdef EVP_PKEY_ED25519
    if (EVP_PKEY_base_id(sfilter->pkey) == EVP_PKEY_ED25519)
	digest = NULL;
#endif

    certauth_write_byte(sfilter, CERTAUTH_CHALLENGE_RSP);
    lenpos = sfilter->write_buf_len;
    sfilter->write_buf_len += 2;

    sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx) {
	gca_log_err(sfilter, "Unable to allocate signature context");
	return GE_NOMEM;
    }

    to_sign_size = sfilter->challenge_data_size + sfilter->service_len;
    to_sign = o->zalloc(o, to_sign_size);
    if (!to_sign) {
	gca_logs_err(sfilter, "challeng data allocation failed");
	goto out_nomem;
    }
    memcpy(to_sign, sfilter->challenge_data, sfilter->challenge_data_size);
    memcpy(to_sign + sfilter->challenge_data_size,
	   sfilter->service, sfilter->service_len);

    if (!EVP_DigestSignInit(sign_ctx, NULL, digest, NULL, sfilter->pkey)) {
	gca_logs_err(sfilter, "Digest signature init failed");
	goto out_nomem;
    }
    if (!EVP_DigestSign(sign_ctx, NULL, &len,
			to_sign, to_sign_size)) {
	gca_logs_err(sfilter, "Digest Signature sign failed");
	goto out_nomem;
    }
    if (certauth_writeleft(sfilter) < len) {
	gca_log_err(sfilter, "Signature too large to fit in the data");
	return GE_TOOBIG;
    }
    if (!EVP_DigestSign(sign_ctx, certauth_writepos(sfilter), &len,
			to_sign, to_sign_size)) {
	gca_logs_err(sfilter, "Digest Signature sign(2) failed");
	goto out_nomem;
    }
    sfilter->write_buf_len += len;
    certauth_u16_to_buf(sfilter->write_buf + lenpos, len);

 out:
    if (to_sign)
	o->free(o, to_sign);
    EVP_MD_CTX_free(sign_ctx);
    return rv;

 out_nomem:
    rv = GE_NOMEM;
    goto out;
}

static int
v3_certauth_check_challenge(struct certauth_filter *sfilter)
{
    EVP_MD_CTX *sign_ctx;
    int rv = 0;
    EVP_PKEY *pkey;

    sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx) {
	gca_log_err(sfilter, "Unable to allocate verify context");
	return GE_NOMEM;
    }
    if (!EVP_VerifyInit(sign_ctx, sfilter->digest)) {
	gca_logs_err(sfilter, "Verify init failed");
	goto out_nomem;
    }
    if (!EVP_VerifyUpdate(sign_ctx, sfilter->challenge_data,
			  sfilter->challenge_data_size)) {
	gca_logs_err(sfilter, "Verify update failed");
	goto out_nomem;
    }
    if (!EVP_VerifyUpdate(sign_ctx, sfilter->service, sfilter->service_len)) {
	gca_logs_err(sfilter, "Verify update (service) failed");
	goto out_nomem;
    }
    pkey = X509_get_pubkey(sfilter->cert);
    if (!pkey) {
	gca_logs_err(sfilter, "Getting public key failed");
	goto out_nomem;
    }
    rv = EVP_VerifyFinal(sign_ctx, sfilter->read_buf, sfilter->read_buf_len,
			 pkey);
    EVP_PKEY_free(pkey);
    if (rv < 0) {
	gca_logs_err(sfilter, "Verify final failed");
	goto out_nomem;
    }

    if (rv) {
	sfilter->response_result = CERTAUTH_RESULT_SUCCESS;
    } else {
	sfilter->response_result = CERTAUTH_RESULT_FAILURE;
	gca_logs_info(sfilter, "Challenge verify failed");
    }

    rv = 0;

 out:
    EVP_MD_CTX_free(sign_ctx);
    return rv;

 out_nomem:
    rv = GE_NOMEM;
    goto out;
}

static int
certauth_check_challenge(struct certauth_filter *sfilter)
{
    struct gensio_os_funcs *o = sfilter->o;
    EVP_MD_CTX *sign_ctx;
    int rv = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *to_sign = NULL;
    gensiods to_sign_size;
    const EVP_MD *digest = sfilter->digest;

    if (sfilter->version < 4 || sfilter->my_version < 4)
	return v3_certauth_check_challenge(sfilter);

    sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx) {
	gca_log_err(sfilter, "Unable to allocate verify context");
	return GE_NOMEM;
    }

    to_sign_size = sfilter->challenge_data_size + sfilter->service_len;
    to_sign = o->zalloc(o, to_sign_size);
    if (!to_sign) {
	gca_logs_err(sfilter, "challeng data allocation failed");
	goto out_nomem;
    }
    memcpy(to_sign, sfilter->challenge_data, sfilter->challenge_data_size);
    memcpy(to_sign + sfilter->challenge_data_size,
	   sfilter->service, sfilter->service_len);

    pkey = X509_get_pubkey(sfilter->cert);
    if (!pkey) {
	gca_logs_err(sfilter, "Getting public key failed");
	goto out_nomem;
    }

#ifdef EVP_PKEY_ED25519
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_ED25519)
	digest = NULL;
#endif

    if (!EVP_DigestVerifyInit(sign_ctx, NULL, digest, NULL, pkey)) {
	gca_logs_err(sfilter, "Digest verify init failed");
	goto out_nomem;
    }
    rv = EVP_DigestVerify(sign_ctx, sfilter->read_buf, sfilter->read_buf_len,
			  to_sign, to_sign_size);
    if (rv != 0 && rv != 1) {
	gca_logs_err(sfilter, "Verify final failed");
	goto out_nomem;
    }

    if (rv) {
	sfilter->response_result = CERTAUTH_RESULT_SUCCESS;
    } else {
	sfilter->response_result = CERTAUTH_RESULT_FAILURE;
	gca_logs_info(sfilter, "Challenge verify failed");
    }

    rv = 0;

 out:
    if (pkey)
	EVP_PKEY_free(pkey);
    if (to_sign)
	o->free(o, to_sign);
    EVP_MD_CTX_free(sign_ctx);
    return rv;

 out_nomem:
    rv = GE_NOMEM;
    goto out;
}

static void
certauth_add_dummy(struct certauth_filter *sfilter, unsigned int len)
{
    certauth_write_byte(sfilter, CERTAUTH_DUMMY_DATA);
    certauth_write_u16(sfilter, len);
    certauth_write_zeros(sfilter, len);
}

static void
certauth_send_server_done(struct certauth_filter *sfilter)
{
    int result = CERTAUTH_RESULT_SUCCESS;

    if (!sfilter->result)
	sfilter->result = CERTAUTH_RESULT_FAILURE;
    if (!sfilter->allow_authfail)
	result = sfilter->result;
    if (sfilter->result == CERTAUTH_RESULT_ERR)
	result = CERTAUTH_RESULT_FAILURE;

    sfilter->write_buf_len = 0;
    certauth_write_byte(sfilter, CERTAUTH_SERVERDONE);
    certauth_write_byte(sfilter, CERTAUTH_RESULT);
    certauth_write_u16(sfilter, 2);
    certauth_write_u16(sfilter, result);
    certauth_write_byte(sfilter, CERTAUTH_END);
}

static void
set_digest(struct certauth_filter *sfilter)
{
    if (sfilter->version >= 3 && sfilter->my_version >= 3)
	sfilter->digest = sfilter->sha3_512;
    else
	sfilter->digest = sfilter->rsa_md5;
}

static int
certauth_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);
    struct gensio *io;
    gensiods len;
    bool password_requested = false;
    int err, rv;
    unsigned int req;

    certauth_lock(sfilter);
    if (sfilter->pending_err)
	goto out_finish;
    if (!sfilter->got_msg)
	goto out_inprogress;

    switch (sfilter->state) {
    case CERTAUTH_CLIENT_START:
	sfilter->write_buf_len = 0;
	certauth_write_byte(sfilter, CERTAUTH_CLIENTHELLO);
	certauth_write_byte(sfilter, CERTAUTH_VERSION);
	certauth_write_u16(sfilter, 2);
	certauth_write_u16(sfilter, sfilter->my_version);
	if (sfilter->username && sfilter->username_len) {
	    certauth_write_byte(sfilter, CERTAUTH_USERNAME);
	    certauth_write_u16(sfilter, sfilter->username_len);
	    certauth_write(sfilter, sfilter->username, sfilter->username_len);
	}
	if (sfilter->service && sfilter->service_len) {
	    certauth_write_byte(sfilter, CERTAUTH_SERVICE);
	    certauth_write_u16(sfilter, sfilter->service_len);
	    certauth_write(sfilter, sfilter->service, sfilter->service_len);
	}

	certauth_write_byte(sfilter, CERTAUTH_END);

	sfilter->state = CERTAUTH_SERVERHELLO;
	break;

    case CERTAUTH_CLIENTHELLO:
	if (!sfilter->version) {
	    /* Remote end didn't send version. */
	    gca_log_err(sfilter,
			   "Remote client didn't send version");
	    sfilter->pending_err = GE_DATAMISSING;
	    break;
	}

	/* Verify support for things requested. */
	if (sfilter->do_2fa && sfilter->version < 2) {
	    gca_log_err(sfilter,
		"2-factor auth requested but other end doesn't have it");
	    sfilter->pending_err = GE_INVAL;
	    break;
	}
	set_digest(sfilter);

	io = gensio_filter_get_gensio(filter);
	if (sfilter->use_child_auth) {
	    if (gensio_is_authenticated(io)) {
		/*
		 * A lower layer has already authenticated, just skip this.
		 */
		gca_log_info(sfilter, "Using lower layer authentication");
		sfilter->result = CERTAUTH_RESULT_SUCCESS;
		/* Go ahead and go through the motions. */
	    }
	} else {
	    /* Override child setting. */
	    gensio_set_is_authenticated(io, false);
	}

	certauth_unlock(sfilter);
	err = gensio_filter_do_event(sfilter->filter,
				     GENSIO_EVENT_AUTH_BEGIN, 0,
				     NULL, NULL, NULL);
	certauth_lock(sfilter);
	if (!err)
	    /*
	     * Note that we go ahead and do the rest of the messages
	     * even though they may fail, because otherwise we are
	     * broadcasting to the world that we have a login with
	     * no credentials.
	     */
	    sfilter->result = CERTAUTH_RESULT_SUCCESS;
	else if (err == GE_AUTHREJECT) {
	    sfilter->result = CERTAUTH_RESULT_ERR;
	    gca_log_err(sfilter, "auth begin rejected connection");
	} else if (err != GE_NOTSUP) {
	    gca_log_err(sfilter, "Error from application at auth begin: %s",
			gensio_err_to_str(err));
	    sfilter->pending_err = err;
	    goto finish_result;
	}

	sfilter->write_buf_len = 0;
	certauth_write_byte(sfilter, CERTAUTH_SERVERHELLO);
	certauth_write_byte(sfilter, CERTAUTH_VERSION);
	certauth_write_u16(sfilter, 2);
	certauth_write_u16(sfilter, sfilter->my_version);
	certauth_write_byte(sfilter, CERTAUTH_CHALLENGE_DATA);
	certauth_write_u16(sfilter, sfilter->challenge_data_size);
	if (!RAND_bytes(sfilter->challenge_data,
			sfilter->challenge_data_size)) {
	    gca_log_err(sfilter, "Unable to get random data");
	    sfilter->pending_err = GE_IOERR;
	    break;
	}
	certauth_write(sfilter, sfilter->challenge_data,
		       sfilter->challenge_data_size);
	if (sfilter->version >= 2 && sfilter->len_aux && sfilter->val_aux) {
	    certauth_write_byte(sfilter, CERTAUTH_AUX_DATA);
	    certauth_write_u16(sfilter, sfilter->len_aux);
	    certauth_write(sfilter, sfilter->val_aux, sfilter->len_aux);
	}

	certauth_write_byte(sfilter, CERTAUTH_END);

	sfilter->state = CERTAUTH_CHALLENGE_RESPONSE;
	break;

    case CERTAUTH_SERVERHELLO:
	if (sfilter->result)
	    /* We got a server done with result, just go on. */
	    goto handle_server_done;

	if (!sfilter->challenge_data || !sfilter->version) {
	    gca_log_err(sfilter,
			"Remote server didn't send challenge data or version");
	    sfilter->pending_err = GE_DATAMISSING;
	    break;
	}
	set_digest(sfilter);
	sfilter->write_buf_len = 0;
	certauth_write_byte(sfilter, CERTAUTH_CHALLENGE_RESPONSE);

	if (sfilter->cert) {
	    sfilter->pending_err = certauth_add_cert(sfilter);
	    if (sfilter->pending_err)
		goto finish_result;
	} else {
	    /* Mask the fact we are not sending a cert. */
	    certauth_add_dummy(sfilter, 1265);
	}

	if (sfilter->pkey) {
	    sfilter->pending_err = certauth_add_challenge_rsp(sfilter);
	    if (sfilter->pending_err)
		goto finish_result;
	} else {
	    /* Mask the fact we are not sending a response. */
	    certauth_add_dummy(sfilter, 256);
	}
	if (sfilter->version >= 2 && sfilter->len_aux && sfilter->val_aux) {
	    certauth_write_byte(sfilter, CERTAUTH_AUX_DATA);
	    certauth_write_u16(sfilter, sfilter->len_aux);
	    certauth_write(sfilter, sfilter->val_aux, sfilter->len_aux);
	}

	certauth_write_byte(sfilter, CERTAUTH_END);

	sfilter->state = CERTAUTH_PASSWORD_REQUEST;
	break;

    case CERTAUTH_CHALLENGE_RESPONSE:
	if (sfilter->result == CERTAUTH_RESULT_SUCCESS)
	    /* Already authenticated, just do the dummy password. */
	    goto try_password;
	if (!sfilter->cert) {
	    if (!sfilter->enable_password) {
		sfilter->pending_err = GE_AUTHREJECT;
		goto finish_result;
	    }

	    /*
	     * Remote end didn't send certificate and/or challenge
	     * response, or the challenge response failed, try
	     * password.
	     */
	    goto try_password;
	}

	if (!!sfilter->cert != !!sfilter->response_result) {
	    gca_log_err(sfilter, "Remote end did not send cert and response");
	    sfilter->pending_err = GE_PROTOERR;
	    goto finish_result;
	}

	if (!sfilter->result) {
	    certauth_unlock(sfilter);
	    err = gensio_filter_do_event(sfilter->filter,
					 GENSIO_EVENT_PRECERT_VERIFY, 0,
					 NULL, NULL, NULL);
	    certauth_lock(sfilter);
	    if (!err) {
		sfilter->result = CERTAUTH_RESULT_SUCCESS;
	    } else if (err == GE_AUTHREJECT) {
		gca_log_err(sfilter, "precert verify rejected connection");
		sfilter->result = CERTAUTH_RESULT_ERR;
	    } else if (err != GE_NOTSUP) {
		gca_log_err(sfilter, "Error from application at precert: %s",
			    gensio_err_to_str(err));
		sfilter->pending_err = err;
		goto finish_result;
	    }
	}
	err = certauth_verify_cert(sfilter);
	if (!sfilter->result) {
	    if (err == GE_AUTHREJECT) {
		gca_log_err(sfilter, "precert verify rejected connection");
		sfilter->result = CERTAUTH_RESULT_ERR;
	    } else if (err && err != GE_NOTSUP) {
		gca_log_err(sfilter, "Error from application at precert: %s",
			    gensio_err_to_str(err));
		sfilter->pending_err = err;
		goto finish_result;
	    }

	    if (sfilter->verified &&
			sfilter->response_result == CERTAUTH_RESULT_SUCCESS) {
		sfilter->result = CERTAUTH_RESULT_SUCCESS;
	    }
	}

	/*
	 * We may mark it as authenticated, but go through the
	 * password request so an attacker can't tell how the
	 * authentication was done.
	 */

    try_password:
	if (!sfilter->result && sfilter->enable_password)
	    req = CERTAUTH_PASSWORD_TYPE_REQ;
	else
	    req = CERTAUTH_PASSWORD_TYPE_DUMMY;
	/* Request 2 factor authentication data. */
	if (sfilter->do_2fa)
	    req |= CERTAUTH_PASSWORD_TYPE_BIT_2FA;
	sfilter->write_buf_len = 0;
	certauth_write_byte(sfilter, CERTAUTH_PASSWORD_REQUEST);
	certauth_write_byte(sfilter, CERTAUTH_PASSWORD_TYPE);
	certauth_write_u16(sfilter, 2);
	certauth_write_u16(sfilter, req);
	certauth_write_byte(sfilter, CERTAUTH_END);
	sfilter->state = CERTAUTH_PASSWORD;
	break;

    case CERTAUTH_PASSWORD_REQUEST:
	if (!sfilter->password_req_val) {
	    gca_log_err(sfilter, "Remote client didn't send request value");
	    sfilter->pending_err = GE_DATAMISSING;
	    goto finish_result;
	}

	sfilter->write_buf_len = 0;
	if (sfilter->password_req_val != CERTAUTH_PASSWORD_TYPE_REQ) {
	    certauth_write_byte(sfilter, CERTAUTH_PASSWORD);
	    certauth_add_dummy(sfilter, sfilter->password_len);
	    goto password_done;
	}

	if (!sfilter->enable_password) {
	    /*
	     * If we don't have passwords enabled but the other end
	     * requests, send all zeros.
	     */
	    certauth_write_byte(sfilter, CERTAUTH_PASSWORD);
	    certauth_write_byte(sfilter, CERTAUTH_PASSWORD_DATA);
	    certauth_write_u16(sfilter, sfilter->password_len);
	    if (sfilter->password_len)
		certauth_write_zeros(sfilter, sfilter->password_len);
	    goto password_done;
	}

	if (!*sfilter->password) {
	    /* Empty password, ask the user. */
	    gensiods dummy_len = sfilter->password_len;

	    certauth_unlock(sfilter);
	    err = gensio_filter_do_event(sfilter->filter,
					 GENSIO_EVENT_REQUEST_PASSWORD, 0,
					 (unsigned char *) sfilter->password,
					 &dummy_len, NULL);
	    certauth_lock(sfilter);
	    if (err) {
		memset(sfilter->password, 0, sfilter->password_len);
		if (err != GE_NOTSUP) {
		    gca_log_err(sfilter, "Error fetching password: %s",
				gensio_err_to_str(err));
		    sfilter->pending_err = err;
		    goto finish_result;
		}
	    }
	    password_requested = true;
	}

	certauth_write_byte(sfilter, CERTAUTH_PASSWORD);
	certauth_write_byte(sfilter, CERTAUTH_PASSWORD_DATA);
	certauth_write_u16(sfilter, sfilter->password_len);
	if (sfilter->password_len)
	    certauth_write(sfilter, sfilter->password, sfilter->password_len);
	if (password_requested)
	    memset(sfilter->password, 0, sfilter->password_len);

    password_done:
	if (sfilter->val_2fa) {
	    if (sfilter->version < 2) {
		gca_log_err(sfilter,
		    "2-factor auth given, but server doesn't support it");
		sfilter->pending_err = GE_INVAL;
		goto finish_result;
	    }
	    goto send_2fa;
	}
	if (!sfilter->req_2fa_val)
	    goto password_end;

	password_requested = false;
	if (!sfilter->val_2fa) {
	    /* Empty 2fa data, ask the user. */
	    certauth_unlock(sfilter);
	    err = gensio_filter_do_event(sfilter->filter,
					 GENSIO_EVENT_REQUEST_2FA, 0,
					 (unsigned char *) &sfilter->val_2fa,
					 &sfilter->len_2fa,
					 NULL);
	    certauth_lock(sfilter);
	    if (err) {
		if (err != GE_NOTSUP) {
		    gca_log_err(sfilter, "Error fetching 2-factor auth: %s",
				gensio_err_to_str(err));
		    sfilter->pending_err = err;
		    goto finish_result;
		}
	    }
	    password_requested = true;
	    if (sfilter->len_2fa > 65535 || sfilter->len_2fa < 1) {
		gca_log_err(sfilter, "2-factor auth data bad size: %lld",
			    (unsigned long long) sfilter->len_2fa);
		sfilter->pending_err = GE_TOOBIG;
		goto clear_2fa;
	    }
	}

    send_2fa:
	certauth_write_byte(sfilter, CERTAUTH_2FA_DATA);
	certauth_write_u16(sfilter, sfilter->len_2fa);
	if (sfilter->len_2fa)
	    certauth_write(sfilter, sfilter->val_2fa, sfilter->len_2fa);
    clear_2fa:
	if (password_requested) {
	    memset(sfilter->val_2fa, 0, sfilter->len_2fa);
	    sfilter->o->free(sfilter->o, sfilter->val_2fa);
	    sfilter->val_2fa = NULL;
	    sfilter->len_2fa = 0;
	}
	if (sfilter->pending_err)
	    goto finish_result;
    password_end:
	certauth_write_byte(sfilter, CERTAUTH_END);

	sfilter->state = CERTAUTH_SERVERDONE;
	break;

    case CERTAUTH_PASSWORD:
	if (sfilter->do_2fa && !sfilter->val_2fa) {
	    /* Remote end didn't send a password and we requested one. */
	    gca_log_err(sfilter, "Remote client didn't send 2fa data");
	    sfilter->pending_err = GE_DATAMISSING;
	    goto finish_result;
	}

	if (sfilter->result) {
	    /* Already verified by certificate, the password was for show. */
	    if (sfilter->val_2fa
			&& sfilter->result == CERTAUTH_RESULT_SUCCESS) {
		sfilter->result = 0;
		goto check_2fa;
	    }
	    goto finish_result;
	}

	if (sfilter->enable_password && !sfilter->password) {
	    /* Remote end didn't send a password and we requested one. */
	    gca_log_err(sfilter, "Remote client didn't send password");
	    sfilter->pending_err = GE_DATAMISSING;
	    goto finish_result;
	}

	if (!sfilter->password || !*sfilter->password)
	    goto finish_result;

	len = sfilter->password_len;
	certauth_unlock(sfilter);
	err = gensio_filter_do_event(sfilter->filter,
				     GENSIO_EVENT_PASSWORD_VERIFY, 0,
				     (unsigned char *) sfilter->password,
				     &len, NULL);
	certauth_lock(sfilter);
	if (sfilter->state != CERTAUTH_PASSWORD)
	    /*
	     * Either something went wrong, or the user called
	     * GENSIO_CONTROL_FINISH_INIT.  We just exit in either
	     * case.
	     */
	    goto out_finish;
	memset(sfilter->password, 0, sfilter->password_len);
	if (!err) {
	    sfilter->result = CERTAUTH_RESULT_SUCCESS;
	} else if (err == GE_CERTINVALID) {
	    gca_log_err(sfilter, "Application rejected password");
	} else if (err != GE_NOTSUP) {
	    gca_log_err(sfilter, "Error from application at password: %s",
			gensio_err_to_str(err));
	    sfilter->pending_err = err;
	}
	if (!sfilter->do_2fa)
	    goto finish_result;

    check_2fa:
	len = sfilter->len_2fa;
	certauth_unlock(sfilter);
	err = gensio_filter_do_event(sfilter->filter,
				     GENSIO_EVENT_2FA_VERIFY, 0,
				     (unsigned char *) sfilter->val_2fa,
				     &len, NULL);
	certauth_lock(sfilter);
	if (sfilter->state != CERTAUTH_PASSWORD)
	    /*
	     * Either something went wrong, or the user called
	     * GENSIO_CONTROL_FINISH_INIT.  We just exit in either
	     * case.
	     */
	    goto out_finish;
	memset(sfilter->val_2fa, 0, sfilter->len_2fa);
	sfilter->o->free(sfilter->o, sfilter->val_2fa);
	sfilter->val_2fa = NULL;
	sfilter->len_2fa = 0;
	if (!err) {
	    sfilter->result = CERTAUTH_RESULT_SUCCESS;
	} else if (err == GE_CERTINVALID) {
	    gca_log_err(sfilter, "Application rejected 2-factor auth");
	} else if (err != GE_NOTSUP) {
	    gca_log_err(sfilter, "Error from application at 2-factor auth: %s",
			gensio_err_to_str(err));
	    sfilter->pending_err = err;
	}

    finish_result:
	certauth_send_server_done(sfilter);
	if (sfilter->pending_err) {
	    sfilter->state = CERTAUTH_ERR;
	    goto out_finish;
	}
	sfilter->state = CERTAUTH_WAIT_WRITE_DONE;
	/*
	 * Leave got_msg enabled so we won't read any more until we go
	 * to passthrough state.
	 */
	goto out_inprogress;

    case CERTAUTH_SERVERDONE:
	if (!sfilter->result) {
	    /* Remote end didn't send result. */
	    gca_log_err(sfilter, "Remote server didn't send result");
	    sfilter->pending_err = GE_DATAMISSING;
	    goto out_finish;
	}

    handle_server_done:
	if (sfilter->result != CERTAUTH_RESULT_SUCCESS) {
	    sfilter->pending_err = GE_AUTHREJECT;
	    goto out_finish;
	}

	sfilter->state = CERTAUTH_PASSTHROUGH;
	goto out_finish;

    case CERTAUTH_WAIT_WRITE_DONE:
	if (sfilter->write_buf_len == 0) {
	    sfilter->state = CERTAUTH_PASSTHROUGH;
	    goto out_finish;
	}
	goto out_inprogress;

    default:
	assert(false);
    }

    sfilter->got_msg = false;
 out_inprogress:
    rv = GE_INPROGRESS;
    goto out;
 out_finish:
    rv = sfilter->pending_err;
 out:
    certauth_unlock(sfilter);
    return rv;
}

static int
certauth_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    return 0;
}

static int
certauth_ul_write(struct gensio_filter *filter,
		  gensio_ul_filter_data_handler handler, void *cb_data,
		  gensiods *rcount,
		  const struct gensio_sg *sg, gensiods sglen,
		  const char *const *auxdata)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);
    int rv = 0;

    certauth_lock(sfilter);
    if (sg) {
	if (sfilter->state != CERTAUTH_PASSTHROUGH || sfilter->pending_err)
	    rv = GE_NOTREADY;
	else
	    rv = handler(cb_data, rcount, sg, sglen, auxdata);
	if (rv)
	    goto out_unlock;
    }

    if (sfilter->write_buf_len) {
	gensiods count = 0;
	struct gensio_sg sg = { sfilter->write_buf + sfilter->write_buf_pos,
			      sfilter->write_buf_len - sfilter->write_buf_pos };

	rv = handler(cb_data, &count, &sg, 1, auxdata);
	if (rv)
	    goto out_unlock;
	if (count + sfilter->write_buf_pos >= sfilter->write_buf_len) {
	    sfilter->write_buf_len = 0;
	    sfilter->write_buf_pos = 0;
	} else {
	    sfilter->write_buf_pos += count;
	}
    }

 out_unlock:
    certauth_unlock(sfilter);
    return rv;
}

static unsigned int
limited_strlen(const char *str, unsigned int max)
{
    unsigned int i;

    for (i = 0; i < max; i++) {
	if (!*str)
	    return i;
    }
    return i;
}

static void
certauth_handle_new_element(struct certauth_filter *sfilter)
{
    struct gensio_os_funcs *o = sfilter->o;

    switch (sfilter->curr_elem) {
    case CERTAUTH_VERSION:
	if (sfilter->version) {
	    gca_log_err(sfilter, "Version received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	if (sfilter->curr_elem_len != 2) {
	    gca_log_err(sfilter, "Version size not 2");
	    sfilter->pending_err = GE_PROTOERR;
	} else {
	    sfilter->version = certauth_buf_to_u16(sfilter->read_buf);
	    if (!sfilter->version) {
		gca_log_err(sfilter, "Version was zero");
		sfilter->pending_err = GE_PROTOERR;
	    }
	}
	break;

    case CERTAUTH_USERNAME:
	if (sfilter->username) {
	    gca_log_err(sfilter, "Username received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	sfilter->username = o->zalloc(o, sfilter->curr_elem_len + 1);
	sfilter->username_len = sfilter->curr_elem_len;
	if (!sfilter->username) {
	    gca_log_err(sfilter, "Unable to allocate memory for username");
	    sfilter->pending_err = GE_NOMEM;
	} else {
	    memcpy(sfilter->username, sfilter->read_buf,
		   sfilter->curr_elem_len);
	}
	break;

    case CERTAUTH_SERVICE:
	if (sfilter->service) {
	    gca_log_err(sfilter, "Service received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	sfilter->service = o->zalloc(o, sfilter->curr_elem_len + 1);
	sfilter->service_len = sfilter->curr_elem_len;
	if (!sfilter->service) {
	    gca_log_err(sfilter, "Unable to allocate memory for service");
	    sfilter->pending_err = GE_NOMEM;
	} else {
	    memcpy(sfilter->service, sfilter->read_buf,
		   sfilter->curr_elem_len);
	}
	break;

    case CERTAUTH_PASSWORD_TYPE:
	if (sfilter->password_req_val) {
	    gca_log_err(sfilter, "password req received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	if (sfilter->curr_elem_len != 2) {
	    gca_log_err(sfilter, "password req size not 2");
	    sfilter->pending_err = GE_PROTOERR;
	} else {
	    sfilter->password_req_val = certauth_buf_to_u16(sfilter->read_buf);
	    sfilter->req_2fa_val = (sfilter->password_req_val &
				    CERTAUTH_PASSWORD_TYPE_BIT_2FA);
	    sfilter->password_req_val &= CERTAUTH_PASSWORD_TYPE_MASK;
	    if (!sfilter->password_req_val) {
		gca_log_err(sfilter, "password req was zero");
		sfilter->pending_err = GE_PROTOERR;
	    }
	}
	break;

    case CERTAUTH_PASSWORD_DATA:
	if (sfilter->password) {
	    gca_log_err(sfilter, "Password received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	sfilter->password_len = limited_strlen((char *) sfilter->read_buf,
					       sfilter->curr_elem_len);
	sfilter->password = o->zalloc(o, sfilter->password_len + 1);
	if (!sfilter->password) {
	    gca_log_err(sfilter, "Unable to allocate memory for password");
	    sfilter->pending_err = GE_NOMEM;
	} else {
	    memcpy(sfilter->password, sfilter->read_buf,
		   sfilter->password_len);
	}
	break;

    case CERTAUTH_2FA_DATA:
	if (sfilter->len_2fa) {
	    gca_log_err(sfilter, "2-factor auth received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	sfilter->len_2fa = sfilter->curr_elem_len;
	sfilter->val_2fa = o->zalloc(o, sfilter->len_2fa + 1);
	if (!sfilter->val_2fa) {
	    gca_log_err(sfilter, "Unable to allocate memory for 2-factor auth");
	    sfilter->pending_err = GE_NOMEM;
	} else {
	    memcpy(sfilter->val_2fa, sfilter->read_buf, sfilter->len_2fa);
	}
	break;

    case CERTAUTH_AUX_DATA:
	if (sfilter->len_rem_aux) {
	    gca_log_err(sfilter, "Remote aux data received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	sfilter->len_rem_aux = sfilter->curr_elem_len;
	sfilter->val_rem_aux = o->zalloc(o, sfilter->len_rem_aux + 1);
	if (!sfilter->val_rem_aux) {
	    gca_log_err(sfilter, "Unable to allocate memory for remote aux");
	    sfilter->pending_err = GE_NOMEM;
	} else {
	    memcpy(sfilter->val_rem_aux, sfilter->read_buf,
		   sfilter->len_rem_aux);
	}
	break;

    case CERTAUTH_OPTIONS:
	break;

    case CERTAUTH_CHALLENGE_DATA:
	if (sfilter->challenge_data) {
	    gca_log_err(sfilter, "Challenge data received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	sfilter->challenge_data = o->zalloc(o, sfilter->curr_elem_len);
	sfilter->challenge_data_size = sfilter->curr_elem_len;
	if (!sfilter->challenge_data) {
	    gca_log_err(sfilter, "Unable to allocate memory for challenge");
	    sfilter->pending_err = GE_NOMEM;
	} else {
	    memcpy(sfilter->challenge_data, sfilter->read_buf,
		   sfilter->curr_elem_len);
	}
	break;

    case CERTAUTH_CHALLENGE_RSP:
	if (sfilter->response_result) {
	    gca_log_err(sfilter,
			"Challenge response received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	sfilter->pending_err = certauth_check_challenge(sfilter);
	break;

    case CERTAUTH_CERTIFICATE:
	if (sfilter->cert) {
	    gca_log_err(sfilter, "Certificate received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	sfilter->pending_err = certauth_get_cert(sfilter);
	break;

    case CERTAUTH_RESULT:
	if (sfilter->result) {
	    gca_log_err(sfilter, "Result received when already set");
	    sfilter->pending_err = GE_PROTOERR;
	    break;
	}
	if (sfilter->curr_elem_len != 2) {
	    gca_log_err(sfilter, "Result size not 2");
	    sfilter->pending_err = GE_PROTOERR;
	} else {
	    sfilter->result = certauth_buf_to_u16(sfilter->read_buf);
	    if (!sfilter->result) {
		gca_log_err(sfilter, "Result value was zero");
		sfilter->pending_err = GE_PROTOERR;
	    }
	}
	break;

    case CERTAUTH_DUMMY_DATA:
	/* Just ignore it. */
	break;

    default:
	break;
    }
}

static int
certauth_ll_write(struct gensio_filter *filter,
		  gensio_ll_filter_data_handler handler, void *cb_data,
		  gensiods *rcount,
		  unsigned char *buf, gensiods buflen,
		  const char *const *auxdata)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);
    int err = 0;
    unsigned char *obuf = buf;
    gensiods elemleft;

    if (buflen == 0)
	goto out;

    certauth_lock(sfilter);
    if (sfilter->state == CERTAUTH_PASSTHROUGH) {
	certauth_unlock(sfilter);
	err = gensio_filter_do_event(sfilter->filter, GENSIO_EVENT_READ, 0,
				     buf, &buflen, auxdata);
	if (rcount)
	    *rcount = buflen;
	return err;
    }

    if (gensio_str_in_auxdata(auxdata, "oob")) {
	/* Ignore oob data. */
	if (rcount)
	    *rcount = buflen;
	goto out_unlock;
    }

    if (sfilter->pending_err) {
	if (rcount)
	    *rcount = buflen;
	goto out_unlock;
    }
    if (!sfilter->curr_msg_type) {
	sfilter->curr_msg_type = *buf;
	buf++;
	buflen--;
	if (sfilter->curr_msg_type > CERTAUTH_STATE_MAX) {
	    gca_log_err(sfilter, "Invalid message type: %d",
			sfilter->curr_msg_type);
	    sfilter->pending_err = GE_PROTOERR;
	    goto out_unlock;
	}
	sfilter->curr_elem = 0;
	sfilter->curr_elem_len_b1 = false;
	sfilter->curr_elem_len_b2 = false;
	sfilter->read_buf_len = 0;
	if (sfilter->is_client &&
			sfilter->curr_msg_type == CERTAUTH_SERVERDONE) {
	    /* We allow server done in any state. */
	    sfilter->state = CERTAUTH_SERVERDONE;
	} else if (sfilter->curr_msg_type != sfilter->state) {
	    gca_log_err(sfilter, "Expected message type %d, got %d",
			sfilter->state, sfilter->curr_msg_type);
	    sfilter->pending_err = GE_PROTOERR;
	    goto out_unlock;
	}
    }
    if (buflen == 0)
	goto out_unlock;
 restart:
    if (!sfilter->curr_elem) {
	sfilter->curr_elem = *buf;
	buf++;
	buflen--;
	if (sfilter->curr_elem == CERTAUTH_END) {
	    sfilter->curr_msg_type = 0;
	    sfilter->got_msg = true;
	    goto out_unlock;
	}
	if (sfilter->curr_elem > CERTAUTH_MAX_ELEMENT ||
			sfilter->curr_elem < CERTAUTH_MIN_ELEMENT) {
	    gca_log_err(sfilter, "Invalid message element: %d",
			sfilter->curr_elem);
	    sfilter->pending_err = GE_PROTOERR;
	    goto out_unlock;
	}
    }
    if (buflen == 0)
	goto out_unlock;
    if (!sfilter->curr_elem_len_b1) {
	sfilter->curr_elem_len_b1 = true;
	sfilter->curr_elem_len = ((unsigned int) (*buf)) << 8;
	buf++;
	buflen--;
    }
    if (buflen == 0)
	goto out_unlock;
    if (!sfilter->curr_elem_len_b2) {
	sfilter->curr_elem_len_b2 = true;
	sfilter->curr_elem_len |= *buf;
	if (!sfilter->curr_elem_len ||
		sfilter->curr_elem_len > sfilter->max_read_size) {
	    gca_log_err(sfilter, "Element type %d was too large: %d",
			sfilter->curr_elem, sfilter->curr_elem_len);
	    sfilter->pending_err = GE_PROTOERR;
	    goto out_unlock;
	}
	buf++;
	buflen--;
    }
    elemleft = sfilter->curr_elem_len - sfilter->read_buf_len;
    if (buflen >= elemleft) {
	memcpy(sfilter->read_buf + sfilter->read_buf_len, buf, elemleft);
	buflen -= elemleft;
	buf += elemleft;
	sfilter->read_buf_len += elemleft;
	certauth_handle_new_element(sfilter);
	sfilter->curr_elem = 0;
	sfilter->curr_elem_len_b1 = false;
	sfilter->curr_elem_len_b2 = false;
	sfilter->read_buf_len = 0;
	goto restart;
    } else {
	memcpy(sfilter->read_buf + sfilter->read_buf_len, buf, buflen);
	sfilter->read_buf_len += buflen;
	buf += buflen;
	buflen = 0;
    }

 out_unlock:
    err = sfilter->pending_err;
    certauth_unlock(sfilter);
 out:
    if (rcount)
	*rcount = buf - obuf;

    return err;
}

static int
certauth_setup(struct gensio_filter *filter)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);
    gensio_time tv_rand;

    /* Make sure the random number generator is seeded. */
    sfilter->o->get_monotonic_time(sfilter->o, &tv_rand);
    tv_rand.secs += tv_rand.nsecs;
    RAND_add(&tv_rand.secs, sizeof(tv_rand.secs), 0);

    return 0;
}

static void
certauth_cleanup(struct gensio_filter *filter)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);
    struct gensio_os_funcs *o = sfilter->o;

    if (sfilter->is_client) {
	if (sfilter->challenge_data)
	    o->free(o, sfilter->challenge_data);
	sfilter->challenge_data = NULL;
	memset(sfilter->password, 0, sfilter->password_len);
    } else {
	if (sfilter->cert)
	    X509_free(sfilter->cert);
	if (sfilter->sk_ca)
	    sk_X509_pop_free(sfilter->sk_ca, X509_free);
	sfilter->cert = NULL;
	sfilter->sk_ca = NULL;
	if (sfilter->password)
	    memset(sfilter->password, 0, sfilter->password_len);
	if (!sfilter->is_client && sfilter->password) {
	    o->free(o, sfilter->password);
	    sfilter->password = NULL;
	    sfilter->password_len = 0;
	}
	if (sfilter->username)
	    o->free(o, sfilter->username);
	sfilter->username = NULL;
	sfilter->username_len = 0;
	if (sfilter->service)
	    o->free(o, sfilter->service);
	sfilter->service = NULL;
	sfilter->service_len = 0;
    }
    if (sfilter->val_2fa)
	o->free(o, sfilter->val_2fa);
    sfilter->val_2fa = NULL;
    sfilter->len_2fa = 0;

    if (sfilter->val_aux)
	o->free(o, sfilter->val_aux);
    sfilter->val_aux = NULL;
    sfilter->len_aux = 0;
    if (sfilter->val_rem_aux)
	o->free(o, sfilter->val_rem_aux);
    sfilter->val_rem_aux = NULL;
    sfilter->len_rem_aux = 0;

    sfilter->pending_err = 0;
    sfilter->password_req_val = 0;
    sfilter->read_buf_len = 0;
    sfilter->write_buf_len = 0;
    sfilter->write_buf_pos = 0;
    sfilter->version = 0;
    sfilter->result = 0;
    sfilter->response_result = 0;
    sfilter->verified = false;
}

static void
sfilter_free(struct certauth_filter *sfilter)
{
    struct gensio_os_funcs *o = sfilter->o;

    if (sfilter->cert)
	X509_free(sfilter->cert);
    if (sfilter->sk_ca)
	sk_X509_pop_free(sfilter->sk_ca, X509_free);
    if (sfilter->cert_bio)
	BIO_free(sfilter->cert_bio);
    if (sfilter->lock)
	o->free_lock(sfilter->lock);
    if (sfilter->read_buf) {
	memset(sfilter->read_buf, 0, sfilter->max_read_size);
	o->free(o, sfilter->read_buf);
    }
    if (sfilter->write_buf)
	o->free(o, sfilter->write_buf);
    if (sfilter->pkey)
	EVP_PKEY_free(sfilter->pkey);
    if (sfilter->password) {
	memset(sfilter->password, 0, sfilter->password_len);
	o->free(o, sfilter->password);
    }
    if (sfilter->username)
	o->free(o, sfilter->username);
    if (sfilter->service)
	o->free(o, sfilter->service);
    if (sfilter->challenge_data)
	o->free(o, sfilter->challenge_data);
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    if (sfilter->verify_store)
	X509_STORE_free(sfilter->verify_store);
    o->free(o, sfilter);
}

static void
certauth_free(struct gensio_filter *filter)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);

    sfilter_free(sfilter);
}

static int
certauth_filter_control(struct gensio_filter *filter, bool get, int op,
			char *data, gensiods *datalen)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);
    X509_STORE *store;
    char *CApath = NULL, *CAfile = NULL;
    int rv = 0;

    switch (op) {
    case GENSIO_CONTROL_GET_PEER_CERT_NAME:
	if (!get)
	    return GE_NOTSUP;
	return gensio_cert_get_name(sfilter->cert, data, datalen);

    case GENSIO_CONTROL_CERT:
	if (!get)
	    return GE_NOTSUP;
	if (!sfilter->cert)
	    return GE_NOTFOUND;
	return gensio_cert_to_buf(sfilter->cert, data, datalen);

    case GENSIO_CONTROL_USERNAME: {
	certauth_lock(sfilter);
	if (get) {
	    if (!sfilter->username) {
		rv = GE_DATAMISSING;
		goto out_username;
	    }
	    *datalen = snprintf(data, *datalen, "%s", sfilter->username);
	} else {
	    char *newusername = NULL;

	    if (data) {
		newusername = gensio_strdup(sfilter->o, data);
		if (!newusername) {
		    rv = GE_NOMEM;
		    goto out_username;
		}
	    }
	    if (sfilter->username)
		sfilter->o->free(sfilter->o, sfilter->username);
	    sfilter->username = newusername;
	}
	out_username:
	certauth_unlock(sfilter);
	return rv;
    }

    case GENSIO_CONTROL_PASSWORD: {
	certauth_lock(sfilter);
	if (get) {
	    if (!sfilter->password) {
		rv = GE_DATAMISSING;
		goto out_username;
	    }
	    *datalen = snprintf(data, *datalen, "%s", sfilter->password);
	} else {
	    char *newpw = NULL;

	    if (data) {
		newpw = gensio_strdup(sfilter->o, data);
		if (!newpw) {
		    rv = GE_NOMEM;
		    goto out_pw;
		}
	    }
	    if (sfilter->password)
		sfilter->o->free(sfilter->o, sfilter->password);
	    sfilter->password = newpw;
	}
	out_pw:
	certauth_unlock(sfilter);
	return rv;
    }

    case GENSIO_CONTROL_2FA: {
	gensiods len;

	certauth_lock(sfilter);
	if (get) {
	    if (!sfilter->val_2fa) {
		rv = GE_DATAMISSING;
		goto out_username;
	    }
	    len = sfilter->len_2fa;
	    if (len > *datalen)
		len = *datalen;
	    memcpy(data, sfilter->val_2fa, len);
	    *datalen = sfilter->len_2fa;
	} else {
	    unsigned char *new2fa = NULL;

	    if (*datalen == 0)
		data = NULL;
	    if (data) {
		new2fa = sfilter->o->zalloc(sfilter->o, *datalen);
		if (!new2fa) {
		    rv = GE_NOMEM;
		    goto out_2fa;
		}
		memcpy(new2fa, data, *datalen);
	    }
	    if (sfilter->val_2fa)
		sfilter->o->free(sfilter->o, sfilter->val_2fa);
	    sfilter->val_2fa = new2fa;
	    sfilter->len_2fa = *datalen;
	}
	out_2fa:
	certauth_unlock(sfilter);
	return rv;
    }

    case GENSIO_CONTROL_AUX_DATA: {
	gensiods len;

	certauth_lock(sfilter);
	if (get) {
	    if (!sfilter->val_aux) {
		rv = GE_DATAMISSING;
		goto out_username;
	    }
	    len = sfilter->len_aux;
	    if (len > *datalen)
		len = *datalen;
	    memcpy(data, sfilter->val_aux, len);
	    *datalen = sfilter->len_aux;
	} else {
	    unsigned char *newaux = NULL;

	    if (*datalen == 0)
		data = NULL;
	    if (data) {
		newaux = sfilter->o->zalloc(sfilter->o, *datalen);
		if (!newaux) {
		    rv = GE_NOMEM;
		    goto out_aux;
		}
		memcpy(newaux, data, *datalen);
	    }
	    if (sfilter->val_aux)
		sfilter->o->free(sfilter->o, sfilter->val_aux);
	    sfilter->val_aux = newaux;
	    sfilter->len_aux = *datalen;
	}
	out_aux:
	certauth_unlock(sfilter);
	return rv;
    }

    case GENSIO_CONTROL_REM_AUX_DATA: {
	gensiods len;

	certauth_lock(sfilter);
	if (get) {
	    if (!sfilter->val_rem_aux) {
		rv = GE_DATAMISSING;
		goto out_username;
	    }
	    len = sfilter->len_rem_aux;
	    if (len > *datalen)
		len = *datalen;
	    memcpy(data, sfilter->val_rem_aux, len);
	    *datalen = sfilter->len_rem_aux;
	} else {
	    unsigned char *newrem_aux = NULL;

	    if (*datalen == 0)
		data = NULL;
	    if (data) {
		newrem_aux = sfilter->o->zalloc(sfilter->o, *datalen);
		if (!newrem_aux) {
		    rv = GE_NOMEM;
		    goto out_rem_aux;
		}
		memcpy(newrem_aux, data, *datalen);
	    }
	    if (sfilter->val_rem_aux)
		sfilter->o->free(sfilter->o, sfilter->val_rem_aux);
	    sfilter->val_rem_aux = newrem_aux;
	    sfilter->len_rem_aux = *datalen;
	}
	out_rem_aux:
	certauth_unlock(sfilter);
	return rv;
    }

    case GENSIO_CONTROL_SERVICE:
	if (get) {
	    gensiods to_copy;

	    if (!sfilter->service)
		return GE_DATAMISSING;

	    to_copy = sfilter->service_len;
	    if (to_copy > *datalen)
		to_copy = *datalen;
	    memcpy(data, sfilter->service, to_copy);
	    *datalen = sfilter->service_len;
	} else {
	    char *new_service = sfilter->o->zalloc(sfilter->o, *datalen);

	    if (!new_service)
		return GE_NOMEM;
	    memcpy(new_service, data, *datalen);
	    if (sfilter->service)
		sfilter->o->free(sfilter->o, sfilter->service);
	    sfilter->service = new_service;
	    sfilter->service_len = *datalen;
	}
	return 0;

    case GENSIO_CONTROL_CERT_AUTH:
	if (get)
	    return GE_NOTSUP;
	store = X509_STORE_new();
	if (!store)
	    return GE_NOMEM;
	if (data[strlen(data) - 1] == DIRSEP)
	    CApath = data;
	else
	    CAfile = data;
	if (!X509_STORE_load_locations(store, CAfile, CApath)) {
	    X509_STORE_free(store);
	    return GE_CERTNOTFOUND;
	}

	certauth_lock(sfilter);
	if (sfilter->verify_store)
	    X509_STORE_free(sfilter->verify_store);
	sfilter->verify_store = store;
	certauth_unlock(sfilter);
	return 0;

    case GENSIO_CONTROL_CERT_FINGERPRINT:
	if (!get)
	    return GE_NOTSUP;
	if (!sfilter->cert)
	    return GE_NOTFOUND;
	return gensio_cert_fingerprint(sfilter->cert, data, datalen);

    default:
	return GE_NOTSUP;
    }
}

static
int gensio_certauth_filter_func(struct gensio_filter *filter, int op,
				void *func, void *data,
				gensiods *count,
				void *buf, const void *cbuf,
				gensiods buflen,
				const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	certauth_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return certauth_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return certauth_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return certauth_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return certauth_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return certauth_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return certauth_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return certauth_ul_write(filter, func, data, count, cbuf, buflen, buf);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return certauth_ll_write(filter, func, data, count, buf, buflen, NULL);

    case GENSIO_FILTER_FUNC_SETUP:
	return certauth_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	certauth_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	certauth_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return certauth_filter_control(filter, *((bool *) cbuf), buflen, data,
				  count);

    case GENSIO_FILTER_FUNC_TIMEOUT:
    default:
	return GE_NOTSUP;
    }
}

static int
gensio_certauth_filter_raw_alloc(struct gensio_os_funcs *o,
				 bool is_client, X509_STORE *store,
				 X509 *cert, STACK_OF(X509) *sk_ca,
				 EVP_PKEY *pkey,
				 const char *username, const char *password,
				 const char *val_2fa, gensiods len_2fa,
				 const char *service,
				 bool allow_authfail, bool use_child_auth,
				 bool enable_password, bool do_2fa,
				 struct gensio_filter **rfilter)
{
    struct certauth_filter *sfilter;
    int rv;

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return GE_NOMEM;

    sfilter->o = o;
    sfilter->is_client = is_client;
    sfilter->allow_authfail = allow_authfail;
    sfilter->use_child_auth = use_child_auth;
    sfilter->enable_password = enable_password;
    sfilter->do_2fa = do_2fa;
    sfilter->my_version = GENSIO_CERTAUTH_VERSION;
    sfilter->rsa_md5 = EVP_get_digestbyname("ssl3-md5");
    if (!sfilter->rsa_md5) {
	rv = GE_IOERR;
	goto out_err;
    }
    sfilter->sha3_512 = EVP_get_digestbyname("sha3-512");
    if (!sfilter->sha3_512)
	sfilter->my_version = 2;

    if (is_client) {
	/* Extra byte at the end so it's always nil terminated. */
	sfilter->password = o->zalloc(o, GENSIO_CERTAUTH_PASSWORD_LEN + 1);
	if (!sfilter->password) {
	    rv = GE_NOMEM;
	    goto out_err;
	}
	sfilter->password_len = GENSIO_CERTAUTH_PASSWORD_LEN;

	if (password) {
	    size_t pwlen = strlen(password);

	    if (pwlen > GENSIO_CERTAUTH_PASSWORD_LEN) {
		rv = GE_TOOBIG;
		goto out_err;
	    }

	    strncpy(sfilter->password, password, GENSIO_CERTAUTH_PASSWORD_LEN);
	}

	if (val_2fa) {
	    sfilter->val_2fa = o->zalloc(o, len_2fa);
	    if (!sfilter->val_2fa) {
		rv = GE_NOMEM;
		goto out_err;
	    }
	    memcpy(sfilter->val_2fa, val_2fa, len_2fa);
	    sfilter->len_2fa = len_2fa;
	}
    }

    sfilter->lock = o->alloc_lock(o);
    if (!sfilter->lock)
	goto out_nomem;

    sfilter->cert_bio = BIO_new(BIO_s_mem());
    if (!sfilter->cert_bio)
	goto out_nomem;

    if (username) {
	sfilter->username = gensio_strdup(o, username);
	if (!sfilter->username)
	    goto out_nomem;
	sfilter->username_len = strlen(username);
    }

    if (service) {
	sfilter->service = gensio_strdup(o, service);
	if (!sfilter->service)
	    goto out_nomem;
	sfilter->service_len = strlen(service);
    }

    if (is_client) {
	sfilter->state = CERTAUTH_CLIENT_START;
	sfilter->got_msg = true; /* Go ahead and run the state machine. */
    } else {
	sfilter->state = CERTAUTH_CLIENTHELLO;
	sfilter->challenge_data = o->zalloc(o, GENSIO_CERTAUTH_CHALLENGE_SIZE);
	if (!sfilter->challenge_data)
	    goto out_nomem;
	sfilter->challenge_data_size = GENSIO_CERTAUTH_CHALLENGE_SIZE;
    }

    sfilter->read_buf = o->zalloc(o, GENSIO_CERTAUTH_DATA_SIZE);
    if (!sfilter->read_buf)
	goto out_nomem;
    sfilter->max_read_size = GENSIO_CERTAUTH_DATA_SIZE;

    sfilter->write_buf = o->zalloc(o, GENSIO_CERTAUTH_DATA_SIZE);
    if (!sfilter->write_buf)
	goto out_nomem;
    sfilter->max_write_size = GENSIO_CERTAUTH_DATA_SIZE;

    sfilter->filter = gensio_filter_alloc_data(o, gensio_certauth_filter_func,
					       sfilter);
    if (!sfilter->filter)
	goto out_nomem;

    /* Don't set these until here so sfilter_free() doesn't free them on err. */
    sfilter->cert = cert;
    sfilter->sk_ca = sk_ca;
    sfilter->pkey = pkey;
    sfilter->verify_store = store;

    *rfilter = sfilter->filter;
    return 0;

 out_nomem:
    rv = GE_NOMEM;
 out_err:
    sfilter_free(sfilter);
    return rv;
}

void
gensio_certauth_filter_config_free(struct gensio_certauth_filter_data *data)
{
    struct gensio_os_funcs *o;

    if (!data)
	return;

    o = data->o;
    if (data->CAfilepath)
	o->free(o, data->CAfilepath);
    if (data->keyfile)
	o->free(o, data->keyfile);
    if (data->certfile)
	o->free(o, data->certfile);
    if (data->password) {
	memset(data->password, 0, strlen(data->password));
	o->free(o, data->password);
    }
    if (data->val_2fa) {
	memset(data->val_2fa, 0, data->len_2fa);
	o->free(o, data->val_2fa);
    }
    if (data->username)
	o->free(o, data->username);
    if (data->service)
	o->free(o, data->service);
    o->free(o, data);
}

int
gensio_certauth_filter_config(struct gensio_os_funcs *o,
			      const char * const args[],
			      bool default_is_client,
			      struct gensio_certauth_filter_data **rdata)
{
    unsigned int i;
    struct gensio_certauth_filter_data *data = o->zalloc(o, sizeof(*data));
    int rv = GE_NOMEM, ival;
    const char *str;
    char *fstr;

    if (!data)
	return GE_NOMEM;
    data->o = o;
    data->is_client = default_is_client;

    rv = gensio_get_default(o, "certauth", "allow-authfail", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    data->allow_authfail = ival;

    rv = gensio_get_default(o, "certauth", "use-child-auth", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    data->use_child_auth = ival;

    rv = gensio_get_default(o, "certauth", "enable-password", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    data->enable_password = ival;

    rv = gensio_get_default(o, "certauth", "mode", false,
			    GENSIO_DEFAULT_STR, &fstr, NULL);
    if (rv) {
	gensio_log(o, GENSIO_LOG_ERR,
		   "Failed getting certauth mode: %s",
		   gensio_err_to_str(rv));
	return rv;
    }
    if (fstr) {
	if (strcasecmp(fstr, "client") == 0)
	    data->is_client = true;
	else if (strcasecmp(fstr, "server") == 0)
	    data->is_client = false;
	else {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unknown default certauth mode (%s), ignoring", fstr);
	}
	o->free(o, fstr);
    }

    rv = GE_NOMEM;
    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyvalue(args[i], "CA", &str) > 0) {
	    data->CAfilepath = gensio_strdup(o, str);
	    if (!data->CAfilepath)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "key", &str) > 0) {
	    data->keyfile = gensio_strdup(o, str);
	    if (!data->keyfile)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "cert", &str) > 0) {
	    data->certfile = gensio_strdup(o, str);
	    if (!data->certfile)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "username", &str) > 0) {
	    data->username = gensio_strdup(o, str);
	    if (!data->username)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "password", &str) > 0) {
	    data->password = gensio_strdup(o, str);
	    if (!data->password)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "2fa", &str) > 0) {
	    data->len_2fa = strlen(str);
	    if (data->len_2fa == 0)
		goto out_err;
	    data->val_2fa = gensio_strdup(o, str);
	    if (!data->val_2fa)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "service", &str) > 0) {
	    data->service = gensio_strdup(o, str);
	    if (!data->service)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyboolv(args[i], "mode", "client", "server",
				  &data->is_client) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "allow-authfail",
				 &data->allow_authfail) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "use-child-auth",
				 &data->use_child_auth) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "enable-password",
				 &data->enable_password) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "enable-2fa",
				 &data->do_2fa) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "allow-unencrypted",
				 &data->allow_unencrypted) > 0)
	    continue;
	rv = GE_INVAL;
	goto out_err;
    }

    if (!data->keyfile) {
	rv = gensio_get_default(o, "certauth", "key", false, GENSIO_DEFAULT_STR,
				&data->keyfile, NULL);
	if (rv) {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unable to get default key for certauth: %s",
		       gensio_err_to_str(rv));
	    goto out_err;
	}
    }
    if (!data->certfile) {
	rv = gensio_get_default(o, "certauth", "cert", false,
				GENSIO_DEFAULT_STR, &data->certfile, NULL);
	if (rv) {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unable to get default cert for certauth: %s",
		       gensio_err_to_str(rv));
	    goto out_err;
	}
    }
    if (!data->CAfilepath) {
	rv = gensio_get_default(o, "certauth", "CA", false, GENSIO_DEFAULT_STR,
				&data->CAfilepath, NULL);
	if (rv) {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unable to get default CA for certauth: %s",
		       gensio_err_to_str(rv));
	    goto out_err;
	}
    }
    if (!data->username) {
	rv = gensio_get_default(o, "certauth", "username", false,
				GENSIO_DEFAULT_STR, &data->username, NULL);
	if (rv) {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unable to get default username for certauth: %s",
		       gensio_err_to_str(rv));
	    goto out_err;
	}
    }
    if (!data->password) {
	rv = gensio_get_default(o, "certauth", "password", false,
				GENSIO_DEFAULT_STR, &data->password, NULL);
	if (rv) {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unable to get default password for certauth: %s",
		       gensio_err_to_str(rv));
	    goto out_err;
	}
    }
    if (!data->service) {
	gensio_get_default(o, "certauth", "service", false, GENSIO_DEFAULT_STR,
			   &data->service, NULL);
	if (rv) {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unable to get default service for certauth: %s",
		       gensio_err_to_str(rv));
	    goto out_err;
	}
    }

    if (!data->keyfile && data->certfile) {
	data->keyfile = gensio_strdup(o, data->certfile);
	if (!data->keyfile) {
	    rv = GE_NOMEM;
	    goto out_err;
	}
    }

    if (data->is_client) {
	if (data->CAfilepath || data->do_2fa) {
	    rv = GE_INVAL;
	    goto out_err;
	}
    } else {
	if (data->keyfile || data->username || data->val_2fa) {
	    rv = GE_INVAL;
	    goto out_err;
	}
    }

    *rdata = data;

    return 0;
 out_err:
    gensio_certauth_filter_config_free(data);
    return rv;
}

bool
gensio_certauth_filter_config_allow_unencrypted(
	     struct gensio_certauth_filter_data *data)
{
    return data->allow_unencrypted;
}

bool
gensio_certauth_filter_config_is_client(
	     struct gensio_certauth_filter_data *data)
{
    return data->is_client;
}


static int
read_certificate_chain(const char *file, X509 **rcert, STACK_OF(X509) **rca)
{
    BIO *in;
    int rv = 0;
    X509 *cert = NULL, *ca = NULL;
    STACK_OF(X509) *sk_ca = NULL;

    ERR_clear_error();

    in = BIO_new(BIO_s_file());
    if (!in)
	return GE_NOMEM;

    if (BIO_read_filename(in, file) <= 0) {
	rv = GE_CERTNOTFOUND;
        goto out_err;
    }

    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    if (!cert) {
	rv = GE_CERTINVALID;
	goto out_err;
    }

    sk_ca = sk_X509_new_null();
    if (!sk_ca) {
	rv = GE_NOMEM;
	goto out_err;
    }

    if (!sk_X509_push(sk_ca, cert)) {
	rv = GE_NOMEM;
	goto out_err;
    }
    X509_up_ref(cert);

    while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
	if (!sk_X509_push(sk_ca, ca)) {
	    X509_free(ca);
	    rv = GE_NOMEM;
	    goto out_err;
	}
    }
    *rcert = cert;
    *rca = sk_ca;

    goto out;

 out_err:
    if (sk_ca)
	sk_X509_pop_free(sk_ca, X509_free);
    if (cert)
	X509_free(cert);
 out:
    BIO_free(in);
    return rv;
}

static int
read_private_key(const char *file, EVP_PKEY **rpkey)
{
    BIO *in;
    EVP_PKEY *pkey;

    ERR_clear_error();

    in = BIO_new(BIO_s_file());
    if (!in)
	return GE_NOMEM;

    if (BIO_read_filename(in, file) <= 0) {
	BIO_free(in);
	return GE_KEYNOTFOUND;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);
    if (!pkey)
	return GE_KEYINVALID;
    *rpkey = pkey;
    return 0;
}

int
gensio_certauth_filter_alloc(struct gensio_certauth_filter_data *data,
			     struct gensio_filter **rfilter)
{
    struct gensio_os_funcs *o = data->o;
    struct gensio_filter *filter;
    X509_STORE *store = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    STACK_OF(X509) *sk_ca = NULL;
    int rv = GE_INVAL;

    store = X509_STORE_new();
    if (!store) {
	rv = GE_NOMEM;
	goto err;
    }

    if (data->CAfilepath && data->CAfilepath[0]) {
	char *CAfile = NULL, *CApath = NULL;

	if (data->CAfilepath[strlen(data->CAfilepath) - 1] == DIRSEP)
	    CApath = data->CAfilepath;
	else
	    CAfile = data->CAfilepath;
	if (!X509_STORE_load_locations(store, CAfile, CApath)) {
	    rv = GE_CERTNOTFOUND;
	    goto err;
	}
    }

    if (data->certfile && data->certfile[0]) {
	rv = read_certificate_chain(data->certfile, &cert, &sk_ca);
	if (rv)
	    goto err;
	rv = read_private_key(data->keyfile, &pkey);
	if (rv)
	    goto err;
    }

    rv = gensio_certauth_filter_raw_alloc(o, data->is_client, store,
					  cert, sk_ca, pkey,
					  data->username, data->password,
					  data->val_2fa, data->len_2fa,
					  data->service,
					  data->allow_authfail,
					  data->use_child_auth,
					  data->enable_password,
					  data->do_2fa,
					  &filter);
    if (rv)
	goto err;

    *rfilter = filter;
    return 0;

 err:
    if (sk_ca)
	sk_X509_pop_free(sk_ca, X509_free);
    if (cert)
	X509_free(cert);
    if (pkey)
	EVP_PKEY_free(pkey);
    if (store)
	X509_STORE_free(store);
    return rv;
}
