/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2019  Corey Minyard <minyard@acm.org>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include "config.h"
#include <errno.h>

#include <gensio/gensio_class.h>

#include "gensio_filter_ssl.h"
#include "gensio_filter_certauth.h"

struct gensio_certauth_filter_data {
    struct gensio_os_funcs *o;
    bool is_client;
    char *CAfilepath;
    char *keyfile;
    char *certfile;
    char *username;
    char *password;
    char *service;
    bool allow_authfail;
    bool use_child_auth;
    bool disable_password;
};

#ifdef HAVE_OPENSSL

#include <assert.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define GENSIO_CERTAUTH_DATA_SIZE	2048
#define GENSIO_CERTAUTH_CHALLENGE_SIZE	32
#define GENSIO_CERTAUTH_VERSION		1

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
     */
    CERTAUTH_CHALLENGE_RESPONSE = 3,

    /*
     * Client waits for PASSWORD_REQUEST.  One byte, after the request
     * tells whether to actually send the password (1) or send a dummy (2).
     *
     * Client may also receive a SERVERDONE in this state if the
     * authorization is rejected or authorized by the certificate.
     */
    CERTAUTH_PASSWORD_REQUEST = 4,

    /*
     * Server waits for a password.  When received. the application is
     * notified of the password.  Send a SERVERDONE with error result
     * from the app.
     */
    CERTAUTH_PASSWORD = 5,

    /*
     * Client waits for SERVERDONE and goes into passthrough mode if
     * successful, contains the result.
     */
    CERTAUTH_SERVERDONE = 6,

    /*
     * Just pass all the data through.
     */
    CERTAUTH_PASSTHROUGH = 107,

    /*
     * Something went wrong, abort.
     */
    CERTAUTH_ERR = 108
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
     * 110 <n>
     * What password data we are asking for.
     */
    CERTAUTH_PASSWORD_TYPE	= 110,

    /*
     * 200
     *
     * This is the last thing in the message.
     */
    CERTAUTH_END		= 200
};
#define CERTAUTH_MIN_ELEMENT CERTAUTH_VERSION
#define CERTAUTH_MAX_ELEMENT CERTAUTH_PASSWORD_TYPE

#define CERTAUTH_RESULT_SUCCESS	1
#define CERTAUTH_RESULT_ERR	2

#define CERTAUTH_PASSWORD_TYPE_REQ	1
#define CERTAUTH_PASSWORD_TYPE_DUMMY	2

struct certauth_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;
    bool is_client;
    bool connected;
    enum certauth_state state;
    struct gensio_lock *lock;

    /*
     * If we get an error while reading, hold it here until the try
     * connect is called.
     */
    int pending_err;

    /* Version number from the remote end. */
    unsigned int version;

    /* Result from the server or local verification. */
    unsigned int result;

    /* Result from the response check. */
    unsigned int response_result;

    /* Certificate verification result, server only. */
    bool verified;

    /* Use authenticated from the child gensio to skip this layer. */
    bool use_child_auth;

    /* Disable password authentication. */
    bool disable_password;

    char *username;
    unsigned int username_len;

    unsigned int password_req_val;
    char *password;
    unsigned int password_len;

    char *service;
    unsigned int service_len;

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
    if (!sfilter->is_client && sfilter->result != CERTAUTH_RESULT_SUCCESS
		&& !sfilter->allow_authfail)
    	rv = EKEYREJECTED;
    else if (sfilter->result == CERTAUTH_RESULT_SUCCESS)
	gensio_set_is_authenticated(io, true);
    certauth_unlock(sfilter);
    return rv;
}

static void
certauth_write(struct certauth_filter *sfilter, void *data, unsigned int len)
{
    if (len + sfilter->write_buf_len > sfilter->max_write_size) {
	gca_log_err(sfilter, "Unable to write data to network");
	sfilter->pending_err = EOVERFLOW;
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
	sfilter->pending_err = EOVERFLOW;
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
	rv = ENOMEM;
	goto out_err;
    }

    if (!X509_STORE_CTX_init(cert_store_ctx, sfilter->verify_store,
			     sfilter->cert, sfilter->sk_ca)) {
	rv = ENOMEM;
	goto out_err;
    }

    verify_err = X509_verify_cert(cert_store_ctx);
    if (verify_err <= 0) {
	verify_err = X509_STORE_CTX_get_error(cert_store_ctx);
	if (verify_err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
	    verify_err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	    rv = ENOKEY;
	else if (verify_err == X509_V_ERR_CERT_REVOKED)
	    rv = EKEYREVOKED;
	else if (verify_err == X509_V_ERR_CERT_HAS_EXPIRED ||
		 verify_err == X509_V_ERR_CRL_HAS_EXPIRED)
	    rv = EKEYEXPIRED;
	else
	    rv = EKEYREJECTED;
    } else {
	verify_err = X509_V_OK;
    }

    certauth_unlock(sfilter);
    if (rv)
	auxdata[0] = X509_verify_cert_error_string(verify_err);
    rv = gensio_filter_do_event(sfilter->filter, GENSIO_EVENT_POSTCERT_VERIFY,
				rv, NULL, NULL, auxdata);
    certauth_lock(sfilter);
    if (rv == ENOTSUP) {
	if (verify_err != X509_V_OK) {
	    gca_logs_info(sfilter,
			  "Remote peer certificate verify failed: %s",
			  X509_verify_cert_error_string(verify_err));
	    rv = EKEYREJECTED;
	} else {
	    rv = 0;
	}
    }
    if (rv == 0)
	sfilter->verified = true;
    rv = 0;

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
	return EOVERFLOW;
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
	return ENOKEY;
    }
    sfilter->write_buf_len += sfilter->cert_buf_mem.length;

    sfilter->sk_ca = sk_X509_new_null();
    if (!sfilter->sk_ca) {
	gca_log_err(sfilter, "Failure allocating CA stack");
	return ENOMEM;
    }
    if (!sk_X509_push(sfilter->sk_ca, sfilter->cert)) {
	gca_log_err(sfilter, "Failure pushing to CA stack");
	return ENOMEM;
    }
    /* cert is in the stack and held by the user. */
    X509_up_ref(sfilter->cert);

    return 0;
}

static int
certauth_add_challenge_rsp(struct certauth_filter *sfilter)
{
    EVP_MD_CTX *sign_ctx;
    unsigned int lenpos, len;
    int rv = 0;

    certauth_write_byte(sfilter, CERTAUTH_CHALLENGE_RSP);
    lenpos = sfilter->write_buf_len;
    sfilter->write_buf_len += 2;
    if (certauth_writeleft(sfilter) < EVP_PKEY_size(sfilter->pkey)) {
	gca_log_err(sfilter, "Key too large to fit in the data");
	return EOVERFLOW;
    }

    sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx) {
	gca_log_err(sfilter, "Unable to allocate signature context");
	return ENOMEM;
    }
    if (!EVP_SignInit(sign_ctx, sfilter->rsa_md5)) {
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
    rv = ENOMEM;
    goto out;
}

static int
certauth_check_challenge(struct certauth_filter *sfilter)
{
    EVP_MD_CTX *sign_ctx;
    int rv = 0;

    sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx) {
	gca_log_err(sfilter, "Unable to allocate verify context");
	return ENOMEM;
    }
    if (!EVP_VerifyInit(sign_ctx, sfilter->rsa_md5)) {
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
    rv = EVP_VerifyFinal(sign_ctx, sfilter->read_buf, sfilter->read_buf_len,
			 X509_get0_pubkey(sfilter->cert));
    if (rv < 0) {
	gca_logs_err(sfilter, "Verify final failed");
	goto out_nomem;
    }

    if (rv) {
	sfilter->response_result = CERTAUTH_RESULT_SUCCESS;
    } else {
	sfilter->response_result = CERTAUTH_RESULT_ERR;
	gca_logs_info(sfilter, "Challenge verify failed");
    }

    rv = 0;

 out:
    EVP_MD_CTX_free(sign_ctx);
    return rv;

 out_nomem:
    rv = ENOMEM;
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
    if (!sfilter->result)
	sfilter->result = CERTAUTH_RESULT_ERR;
    sfilter->write_buf_len = 0;
    certauth_write_byte(sfilter, CERTAUTH_SERVERDONE);
    certauth_write_byte(sfilter, CERTAUTH_RESULT);
    certauth_write_u16(sfilter, 2);
    certauth_write_u16(sfilter, sfilter->result);
    certauth_write_byte(sfilter, CERTAUTH_END);
}

static int
certauth_try_connect(struct gensio_filter *filter, struct timeval *timeout)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);
    struct gensio *io;
    bool password_requested = false;
    int err;

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
	certauth_write_u16(sfilter, GENSIO_CERTAUTH_VERSION);
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
			   "Remote client didn't send username or version");
	    sfilter->pending_err = ENOENT;
	    break;
	}
	io = gensio_filter_get_gensio(filter);
	if (sfilter->use_child_auth) {
	    if (gensio_is_authenticated(io)) {
		/*
		 * A lower layer has already authenticated, just skip this.
		 */
		gca_log_info(sfilter, "Using lower layer authentication");
		sfilter->result = CERTAUTH_RESULT_SUCCESS;
		goto finish_result;
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
	if (err == EKEYREJECTED) {
	    gca_log_err(sfilter, "Application rejected auth begin");
	    sfilter->pending_err = err;
	    goto finish_result;
	}
	if (err && err != ENOTSUP) {
	    gca_log_err(sfilter, "Error from application at auth begin: %s",
			strerror(err));
	    sfilter->pending_err = err;
	    goto finish_result;
	}

	sfilter->write_buf_len = 0;
	certauth_write_byte(sfilter, CERTAUTH_SERVERHELLO);
	certauth_write_byte(sfilter, CERTAUTH_VERSION);
	certauth_write_u16(sfilter, 2);
	certauth_write_u16(sfilter, GENSIO_CERTAUTH_VERSION);
	certauth_write_byte(sfilter, CERTAUTH_CHALLENGE_DATA);
	certauth_write_u16(sfilter, sfilter->challenge_data_size);
	if (!RAND_bytes(sfilter->challenge_data,
			sfilter->challenge_data_size)) {
	    gca_log_err(sfilter, "Unable to get random data");
	    sfilter->pending_err = ENOTUNIQ;
	    break;
	}
	certauth_write(sfilter, sfilter->challenge_data,
		       sfilter->challenge_data_size);

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
	    sfilter->pending_err = ENOENT;
	    break;
	}
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

	certauth_write_byte(sfilter, CERTAUTH_END);

	sfilter->state = CERTAUTH_PASSWORD_REQUEST;
	break;

    case CERTAUTH_CHALLENGE_RESPONSE:
	if (!sfilter->cert && !sfilter->response_result) {
	    /* 
	     * Remote end didn't send certificate and challenge
	     * response, try password.
	     */
	    goto try_password;
	}
	if (!!sfilter->cert != !!sfilter->response_result) {
	    gca_log_err(sfilter, "Application did not send cert and response");
	    sfilter->pending_err = EPROTO;
	    goto finish_result;
	}

	certauth_unlock(sfilter);
	err = gensio_filter_do_event(sfilter->filter,
				     GENSIO_EVENT_PRECERT_VERIFY, 0,
				     NULL, NULL, NULL);
	certauth_lock(sfilter);
	if (!err) {
	    sfilter->result = CERTAUTH_RESULT_SUCCESS;
	    goto finish_result;
	}
	if (err == EKEYREJECTED) {
	    gca_log_err(sfilter, "Application rejected precert key");
	    sfilter->pending_err = err;
	    goto finish_result;
	}
	if (err != ENOTSUP) {
	    gca_log_err(sfilter, "Error from application at precert: %s",
			strerror(err));
	    sfilter->pending_err = err;
	    goto finish_result;
	}

	sfilter->pending_err = certauth_verify_cert(sfilter);
	if (sfilter->pending_err)
	    goto finish_result;

	if (sfilter->verified) {
	    if (sfilter->response_result != CERTAUTH_RESULT_SUCCESS) {
		/*
		 * Certificate verification log already sent for result
		 * If the signature fails, reject the connection.
		 */
		sfilter->pending_err = EKEYREJECTED;
		goto finish_result;
	    }

	    /*
	     * We mark it as authenticated, but go through the password
	     * request so an attacker can't tell how the authentication
	     * was done.
	     */
	    sfilter->result = CERTAUTH_RESULT_SUCCESS;
	}

    try_password:
	sfilter->write_buf_len = 0;
	certauth_write_byte(sfilter, CERTAUTH_PASSWORD_REQUEST);
	certauth_write_byte(sfilter, CERTAUTH_PASSWORD_TYPE);
	certauth_write_u16(sfilter, 2);
	certauth_write_u16(sfilter,
			   sfilter->result || sfilter->disable_password ?
			   CERTAUTH_PASSWORD_TYPE_DUMMY :
			   CERTAUTH_PASSWORD_TYPE_REQ);
	certauth_write_byte(sfilter, CERTAUTH_END);
	sfilter->state = CERTAUTH_PASSWORD;
	break;

    case CERTAUTH_PASSWORD_REQUEST:
	if (!sfilter->password_req_val) {
	    gca_log_err(sfilter,
			   "Remote client didn't send request value");
	    sfilter->pending_err = ENOENT;
	    goto finish_result;
	}

	sfilter->write_buf_len = 0;
	if (sfilter->password_req_val != CERTAUTH_PASSWORD_TYPE_REQ) {
	    certauth_write_byte(sfilter, CERTAUTH_PASSWORD);
	    certauth_add_dummy(sfilter, sfilter->password_len);
	    goto password_done;
	}

	if (sfilter->disable_password) {
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
	    if (!err) {
		if (err && err != ENOTSUP) {
		    gca_log_err(sfilter, "Error fetching password: %s",
				strerror(err));
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
	    certauth_write(sfilter, sfilter->password,
			   sfilter->password_len);
	if (password_requested)
	    memset(sfilter->password, 0, sfilter->password_len);

    password_done:
	certauth_write_byte(sfilter, CERTAUTH_END);

	sfilter->state = CERTAUTH_SERVERDONE;
	break;

    case CERTAUTH_PASSWORD:
	if (!sfilter->password && !sfilter->result) {
	    /* Remote end didn't send a password. */
	    gca_log_err(sfilter, "Remote client didn't send password");
	    sfilter->pending_err = ENOENT;
	    goto finish_result;
	}

	if (sfilter->result)
	    /* Already verified, the rest was for show. */
	    goto finish_result;

	if (!sfilter->password || !*sfilter->password)
	    goto finish_result;

	certauth_unlock(sfilter);
	err = gensio_filter_do_event(sfilter->filter,
				     GENSIO_EVENT_PASSWORD_VERIFY, 0,
				     (unsigned char *) sfilter->password,
				     NULL, NULL);
	certauth_lock(sfilter);
	memset(sfilter->password, 0, sfilter->password_len);
	if (!err) {
	    sfilter->result = CERTAUTH_RESULT_SUCCESS;
	    goto finish_result;
	}
	if (err == EKEYREJECTED) {
	    gca_log_err(sfilter, "Application rejected password");
	    sfilter->pending_err = err;
	    goto finish_result;
	}
	gca_log_err(sfilter, "Error from application at password: %s",
		    strerror(err));
	sfilter->pending_err = err;

    finish_result:
	certauth_send_server_done(sfilter);
	if (sfilter->pending_err)
	    sfilter->state = CERTAUTH_ERR;
	else
	    sfilter->state = CERTAUTH_PASSTHROUGH;
	goto out_finish;

    case CERTAUTH_SERVERDONE:
	if (!sfilter->result) {
	    /* Remote end didn't send result. */
	    gca_log_err(sfilter, "Remote server didn't send result");
	    sfilter->pending_err = ENOENT;
	    goto out_finish;
	}

    handle_server_done:
	if (sfilter->result != CERTAUTH_RESULT_SUCCESS) {
	    sfilter->pending_err = EKEYREJECTED;
	    goto out_finish;
	}

	sfilter->state = CERTAUTH_PASSTHROUGH;
	goto out_finish;

    default:
	assert(false);
    }

    sfilter->got_msg = false;
 out_inprogress:
    certauth_unlock(sfilter);
    return EINPROGRESS;
 out_finish:
    certauth_unlock(sfilter);
    return sfilter->pending_err;
}

static int
certauth_try_disconnect(struct gensio_filter *filter, struct timeval *timeout)
{
    return 0;
}

static int
certauth_ul_write(struct gensio_filter *filter,
		  gensio_ul_filter_data_handler handler, void *cb_data,
		  gensiods *rcount,
		  const unsigned char *buf, gensiods buflen,
		  const char *const *auxdata)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);

    if (buf && (sfilter->state != CERTAUTH_PASSTHROUGH || sfilter->pending_err))
	return EBADFD;

    if (buf)
	return handler(cb_data, rcount, buf, buflen, auxdata);

    if (sfilter->write_buf_len) {
	gensiods count = 0;
	int rv;

	rv = handler(cb_data, &count,
		     sfilter->write_buf + sfilter->write_buf_pos,
		     sfilter->write_buf_len - sfilter->write_buf_pos,
		     auxdata);
	if (rv)
	    return rv;
	if (count + sfilter->write_buf_pos >= sfilter->write_buf_len) {
	    sfilter->write_buf_len = 0;
	    sfilter->write_buf_pos = 0;
	} else {
	    sfilter->write_buf_pos += count;
	}
    }

    return 0;
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
	    sfilter->pending_err = EPROTO;
	    break;
	}
	if (sfilter->curr_elem_len != 2) {
	    gca_log_err(sfilter, "Version size not 2");
	    sfilter->pending_err = EPROTO;
	} else {
	    sfilter->version = certauth_buf_to_u16(sfilter->read_buf);
	    if (!sfilter->version) {
		gca_log_err(sfilter, "Version was zero");
		sfilter->pending_err = EPROTO;
	    }
	}
	break;

    case CERTAUTH_USERNAME:
	if (sfilter->username) {
	    gca_log_err(sfilter, "Username received when already set");
	    sfilter->pending_err = EPROTO;
	    break;
	}
	sfilter->username = o->zalloc(0, sfilter->curr_elem_len + 1);
	sfilter->username_len = sfilter->curr_elem_len;
	if (!sfilter->username) {
	    gca_log_err(sfilter, "Unable to allocate memory for username");
	    sfilter->pending_err = ENOMEM;
	} else {
	    memcpy(sfilter->username, sfilter->read_buf,
		   sfilter->curr_elem_len);
	}
	break;

    case CERTAUTH_SERVICE:
	if (sfilter->service) {
	    gca_log_err(sfilter, "Service received when already set");
	    sfilter->pending_err = EPROTO;
	    break;
	}
	sfilter->service = o->zalloc(0, sfilter->curr_elem_len + 1);
	sfilter->service_len = sfilter->curr_elem_len;
	if (!sfilter->service) {
	    gca_log_err(sfilter, "Unable to allocate memory for service");
	    sfilter->pending_err = ENOMEM;
	} else {
	    memcpy(sfilter->service, sfilter->read_buf,
		   sfilter->curr_elem_len);
	}
	break;

    case CERTAUTH_PASSWORD_TYPE:
	if (sfilter->password_req_val) {
	    gca_log_err(sfilter, "password req received when already set");
	    sfilter->pending_err = EPROTO;
	    break;
	}
	if (sfilter->curr_elem_len != 2) {
	    gca_log_err(sfilter, "password req size not 2");
	    sfilter->pending_err = EPROTO;
	} else {
	    sfilter->password_req_val = certauth_buf_to_u16(sfilter->read_buf);
	    if (!sfilter->password_req_val) {
		gca_log_err(sfilter, "password req was zero");
		sfilter->pending_err = EPROTO;
	    }
	}
	break;

    case CERTAUTH_PASSWORD_DATA:
	if (sfilter->password) {
	    gca_log_err(sfilter, "Password received when already set");
	    sfilter->pending_err = EPROTO;
	    break;
	}
	sfilter->password_len = limited_strlen((char *) sfilter->read_buf,
					       sfilter->curr_elem_len);
	sfilter->password = o->zalloc(0, sfilter->password_len + 1);
	if (!sfilter->password) {
	    gca_log_err(sfilter, "Unable to allocate memory for password");
	    sfilter->pending_err = ENOMEM;
	} else {
	    memcpy(sfilter->password, sfilter->read_buf,
		   sfilter->password_len);
	}
	break;

    case CERTAUTH_OPTIONS:
	break;

    case CERTAUTH_CHALLENGE_DATA:
	if (sfilter->challenge_data) {
	    gca_log_err(sfilter, "Challenge data received when already set");
	    sfilter->pending_err = EPROTO;
	    break;
	}
	sfilter->challenge_data = o->zalloc(0, sfilter->curr_elem_len);
	sfilter->challenge_data_size = sfilter->curr_elem_len;
	if (!sfilter->challenge_data) {
	    gca_log_err(sfilter, "Unable to allocate memory for challenge");
	    sfilter->pending_err = ENOMEM;
	} else {
	    memcpy(sfilter->challenge_data, sfilter->read_buf,
		   sfilter->curr_elem_len);
	}
	break;

    case CERTAUTH_CHALLENGE_RSP:
	if (sfilter->response_result) {
	    gca_log_err(sfilter,
			"Challenge response received when already set");
	    sfilter->pending_err = EPROTO;
	    break;
	}
	sfilter->pending_err = certauth_check_challenge(sfilter);
	break;

    case CERTAUTH_CERTIFICATE:
	if (sfilter->cert) {
	    gca_log_err(sfilter, "Certificate received when already set");
	    sfilter->pending_err = EPROTO;
	    break;
	}
	sfilter->pending_err = certauth_get_cert(sfilter);
	break;

    case CERTAUTH_RESULT:
	if (sfilter->result) {
	    gca_log_err(sfilter, "Result received when already set");
	    sfilter->pending_err = EPROTO;
	    break;
	}
	if (sfilter->curr_elem_len != 2) {
	    gca_log_err(sfilter, "Result size not 2");
	    sfilter->pending_err = EPROTO;
	} else {
	    sfilter->result = certauth_buf_to_u16(sfilter->read_buf);
	    if (!sfilter->result) {
		gca_log_err(sfilter, "Result value was zero");
		sfilter->pending_err = EPROTO;
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
    int err;
    unsigned char *obuf = buf;
    gensiods elemleft;

    if (buflen == 0)
	goto out;

    certauth_lock(sfilter);
    if (sfilter->state == CERTAUTH_PASSTHROUGH) {
	certauth_unlock(sfilter);
	err = gensio_filter_do_event(sfilter->filter, GENSIO_EVENT_READ, 0,
				     buf, &buflen, auxdata);
	*rcount = buflen;
	return err;
    }

    if (sfilter->pending_err) {
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
	    sfilter->pending_err = EPROTO;
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
			sfilter->curr_msg_type, sfilter->state);
	    sfilter->pending_err = EPROTO;
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
	    sfilter->pending_err = EPROTO;
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
	    sfilter->pending_err = EPROTO;
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
	buflen = 0;
	buf += buflen;
    }

 out_unlock:
    err = sfilter->pending_err;
    certauth_unlock(sfilter);
 out:
    *rcount = obuf - buf;

    return err;
}

static int
certauth_setup(struct gensio_filter *filter)
{
    struct timeval tv_rand;

    /* Make sure the random number generator is seeded. */
    gettimeofday(&tv_rand, NULL);
    tv_rand.tv_sec += tv_rand.tv_usec;
    RAND_add(&tv_rand.tv_sec, sizeof(tv_rand.tv_sec), 0);

    return 0;
}

static void
certauth_cleanup(struct gensio_filter *filter)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);

    if (sfilter->is_client) {
	if (sfilter->challenge_data)
	    sfilter->o->free(sfilter->o, sfilter->challenge_data);
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
	    sfilter->o->free(sfilter->o, sfilter->password);
	    sfilter->password = NULL;
	    sfilter->password_len = 0;
	}
	if (sfilter->username)
	    sfilter->o->free(sfilter->o, sfilter->username);
	sfilter->username = NULL;
	sfilter->username_len = 0;
	if (sfilter->service)
	    sfilter->o->free(sfilter->o, sfilter->service);
	sfilter->service = NULL;
	sfilter->service_len = 0;
    }

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
certauth_free(struct gensio_filter *filter)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);

    if (sfilter->cert)
	X509_free(sfilter->cert);
    if (sfilter->sk_ca)
	sk_X509_pop_free(sfilter->sk_ca, X509_free);
    if (sfilter->cert_bio)
	BIO_free(sfilter->cert_bio);
    if (sfilter->lock)
	sfilter->o->free_lock(sfilter->lock);
    if (sfilter->read_buf)
	sfilter->o->free(sfilter->o, sfilter->read_buf);
    if (sfilter->write_buf)
	sfilter->o->free(sfilter->o, sfilter->write_buf);
    if (sfilter->pkey)
	EVP_PKEY_free(sfilter->pkey);
    if (sfilter->password) {
	memset(sfilter->password, 0, sfilter->password_len);
	sfilter->o->free(sfilter->o, sfilter->password);
    }
    if (sfilter->username)
	sfilter->o->free(sfilter->o, sfilter->username);
    if (sfilter->service)
	sfilter->o->free(sfilter->o, sfilter->service);
    if (sfilter->challenge_data)
	sfilter->o->free(sfilter->o, sfilter->challenge_data);
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    if (sfilter->verify_store)
	X509_STORE_free(sfilter->verify_store);
    sfilter->o->free(sfilter->o, sfilter);
}

/* In gensio_filter_ssl.c, semi-private. */
int gensio_cert_get_name(X509 *cert, char *data, gensiods *datalen);
int gensio_cert_to_buf(X509 *cert, char *buf, gensiods *datalen);
int gensio_cert_fingerprint(X509 *cert, char *buf, gensiods *buflen);

static int
certauth_filter_control(struct gensio_filter *filter, bool get, int op,
			char *data, gensiods *datalen)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);
    X509_STORE *store;
    char *CApath = NULL, *CAfile = NULL;

    switch (op) {
    case GENSIO_CONTROL_GET_PEER_CERT_NAME:
	if (!get)
	    return ENOTSUP;
	return gensio_cert_get_name(sfilter->cert, data, datalen);

    case GENSIO_CONTROL_CERT:
	if (!get)
	    return ENOTSUP;
	if (!sfilter->cert)
	    return ENOENT;
	return gensio_cert_to_buf(sfilter->cert, data, datalen);

    case GENSIO_CONTROL_USERNAME:
	if (!sfilter->username)
	    return ENOENT;
	*datalen = snprintf(data, *datalen, "%s", sfilter->username);
	return 0;

    case GENSIO_CONTROL_SERVICE:
	if (!sfilter->service)
	    return ENOENT;
	*datalen = snprintf(data, *datalen, "%s", sfilter->service);
	return 0;

    case GENSIO_CONTROL_CERT_AUTH:
	if (get)
	    return ENOTSUP;
	store = X509_STORE_new();
	if (!store)
	    return ENOMEM;
	if (data[strlen(data) - 1] == '/')
	    CApath = data;
	else
	    CAfile = data;
	if (!X509_STORE_load_locations(store, CAfile, CApath)) {
	    X509_STORE_free(store);
	    return ENOENT;
	}

	certauth_lock(sfilter);
	if (sfilter->verify_store)
	    X509_STORE_free(sfilter->verify_store);
	sfilter->verify_store = store;
	certauth_unlock(sfilter);
	return 0;

    case GENSIO_CONTROL_CERT_FINGERPRINT:
	if (!get)
	    return ENOTSUP;
	if (!sfilter->cert)
	    return ENOENT;
	return gensio_cert_fingerprint(sfilter->cert, data, datalen);

    default:
	return ENOTSUP;
    }
}

static
int gensio_certauth_filter_func(struct gensio_filter *filter, int op,
				const void *func, void *data,
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

    case GENSIO_FILTER_FUNC_UL_WRITE_PENDING:
	return certauth_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return certauth_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return certauth_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return certauth_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return certauth_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE:
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
	return ENOTSUP;
    }
}

static int
gensio_certauth_filter_raw_alloc(struct gensio_os_funcs *o,
				 bool is_client, X509_STORE *store,
				 X509 *cert, STACK_OF(X509) *sk_ca,
				 EVP_PKEY *pkey,
				 const char *username, const char *password,
				 const char *service,
				 bool allow_authfail, bool use_child_auth,
				 bool disable_password,
				 struct gensio_filter **rfilter)
{
    struct certauth_filter *sfilter;
    int rv;

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return ENOMEM;

    sfilter->o = o;
    sfilter->is_client = is_client;
    sfilter->allow_authfail = allow_authfail;
    sfilter->use_child_auth = use_child_auth;
    sfilter->disable_password = disable_password,
    sfilter->rsa_md5 = EVP_get_digestbyname("ssl3-md5");
    if (!sfilter->rsa_md5) {
	rv = ENXIO;
	goto out_err;
    }
    sfilter->cert = cert;
    sfilter->sk_ca = sk_ca;
    sfilter->pkey = pkey;
    sfilter->verify_store = store;

    if (is_client) {
	/* Extra byte at the end so it's always nil terminated. */
	sfilter->password = o->zalloc(o, GENSIO_CERTAUTH_PASSWORD_LEN + 1);
	if (!sfilter->password) {
	    rv = ENOMEM;
	    goto out_err;
	}
	sfilter->password_len = GENSIO_CERTAUTH_PASSWORD_LEN;

	if (password) {
	    unsigned int pwlen = strlen(password);

	    if (pwlen > GENSIO_CERTAUTH_PASSWORD_LEN) {
		rv = EINVAL;
		goto out_err;
	    }

	    strncpy(sfilter->password, password, GENSIO_CERTAUTH_PASSWORD_LEN);
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

    *rfilter = sfilter->filter;
    return 0;

 out_nomem:
    rv = ENOMEM;
 out_err:
    certauth_free(sfilter->filter);
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
    const char *CAfilepath = NULL, *keyfile = NULL, *certfile = NULL;
    const char *username = NULL, *password = NULL, *service = NULL;
    int rv = ENOMEM, ival;

    if (!data)
	return ENOMEM;
    data->o = o;
    data->is_client = default_is_client;

    rv = gensio_get_default(o, "certauth", "allow_authfail", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (!rv)
	data->allow_authfail = ival;

    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyvalue(args[i], "CA", &CAfilepath))
	    continue;
	if (gensio_check_keyvalue(args[i], "key", &keyfile))
	    continue;
	if (gensio_check_keyvalue(args[i], "cert", &certfile))
	    continue;
	if (gensio_check_keyvalue(args[i], "username", &username))
	    continue;
	if (gensio_check_keyvalue(args[i], "password", &password))
	    continue;
	if (gensio_check_keyvalue(args[i], "service", &service))
	    continue;
	if (gensio_check_keyboolv(args[i], "mode", "client", "server",
				  &data->is_client) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "allow-authfail",
				 &data->allow_authfail) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "use-child-auth",
				 &data->use_child_auth) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "disable-password",
				 &data->disable_password) > 0)
	    continue;
	rv = EINVAL;
	goto out_err;
    }

    if (!keyfile) {
	gensio_get_default(o, "certauth", "key", false, GENSIO_DEFAULT_STR,
			   &keyfile, NULL);
    }
    if (!certfile) {
	gensio_get_default(o, "certauth", "cert", false, GENSIO_DEFAULT_STR,
			   &certfile, NULL);
    }
    if (!CAfilepath) {
	gensio_get_default(o, "certauth", "CA", false, GENSIO_DEFAULT_STR,
			   &CAfilepath, NULL);
    }
    if (!username) {
	gensio_get_default(o, "certauth", "username", false, GENSIO_DEFAULT_STR,
			   &username, NULL);
    }
    if (!password) {
	gensio_get_default(o, "certauth", "password", false, GENSIO_DEFAULT_STR,
			   &password, NULL);
    }

    if (!service) {
	gensio_get_default(o, "certauth", "service", false, GENSIO_DEFAULT_STR,
			   &service, NULL);
    }

    if (!keyfile)
	keyfile = certfile;

    if (data->is_client) {
	if (CAfilepath) {
	    rv = EINVAL;
	    goto out_err;
	}
    } else {
	if (keyfile || username) {
	    rv = EINVAL;
	    goto out_err;
	}
    }

    if (CAfilepath) {
	data->CAfilepath = gensio_strdup(o, CAfilepath);
	if (!data->CAfilepath)
	    goto out_err;
    }

    if (keyfile) {
	data->keyfile = gensio_strdup(o, keyfile);
	if (!data->keyfile)
	    goto out_err;
    }

    if (certfile) {
	data->certfile = gensio_strdup(o, certfile);
	if (!data->certfile)
	    goto out_err;
    }

    if (username) {
	data->username = gensio_strdup(o, username);
	if (!data->username)
	    goto out_err;
    }

    if (password) {
	data->password = gensio_strdup(o, password);
	if (!data->password)
	    goto out_err;
    }

    if (service) {
	data->service = gensio_strdup(o, service);
	if (!data->service)
	    goto out_err;
    }

    *rdata = data;

    return 0;
 out_err:
    gensio_certauth_filter_config_free(data);
    return rv;
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
	return ENOMEM;

    if (BIO_read_filename(in, file) <= 0) {
	rv = ENOENT;
        goto out_err;
    }

    cert = PEM_read_bio_X509_AUX(in, NULL, NULL, NULL);
    if (!cert) {
	rv = EINVAL;
	goto out_err;
    }

    sk_ca = sk_X509_new_null();
    if (!sk_ca) {
	rv = ENOMEM;
	goto out_err;
    }

    if (!sk_X509_push(sk_ca, cert)) {
	rv = ENOMEM;
	goto out_err;
    }
    X509_up_ref(cert);

    while ((ca = PEM_read_bio_X509(in, NULL, NULL, NULL))) {
	if (!sk_X509_push(sk_ca, ca)) {
	    X509_free(ca);
	    rv = ENOMEM;
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
	return ENOMEM;

    if (BIO_read_filename(in, file) <= 0) {
	BIO_free(in);
	return ENOENT;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);
    if (!pkey)
	return ENOKEY;
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
    int rv = EINVAL;

    store = X509_STORE_new();
    if (!store) {
	rv = ENOMEM;
	goto err;
    }

    if (data->CAfilepath) {
	char *CAfile = NULL, *CApath = NULL;

	if (data->CAfilepath[strlen(data->CAfilepath) - 1] == '/')
	    CApath = data->CAfilepath;
	else
	    CAfile = data->CAfilepath;
	if (!X509_STORE_load_locations(store, CAfile, CApath)) {
	    rv = ENOENT;
	    goto err;
	}
    }

    if (data->certfile) {
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
					  data->service,
					  data->allow_authfail,
					  data->use_child_auth,
					  data->disable_password,
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

#else /* HAVE_OPENSSL */

int
gensio_certauth_filter_config(struct gensio_os_funcs *o,
			      const char * const args[],
			      bool default_is_client,
			      struct gensio_certauth_filter_data **rdata)
{
    return ENOTSUP;
}

void
gensio_certauth_filter_config_free(struct gensio_certauth_filter_data *data)
{
}

int
gensio_certauth_filter_alloc(struct gensio_certauth_filter_data *data,
			     struct gensio_filter **rfilter)
{
    return ENOTSUP;
}

#endif /* HAVE_OPENSSL */
