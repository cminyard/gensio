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

#include <errno.h>

#include <gensio/gensio_class.h>

#include "gensio_filter_ssl.h"

struct gensio_certauth_filter_data {
    struct gensio_os_funcs *o;
    bool is_client;
    char *CAfilepath;
    char *keyfile;
    char *certfile;
    char *username;
    bool allow_authfail;
    bool use_child_auth;
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
 * State machines for both the client and the server, also message
 * numbers (except for CLIENT_START).
 */
enum certauth_state {
    /*
     * Client first sends the hello (containing the version, userid,
     * and optional options) and goes into SERVERHELLO.
     */
    CERTAUTH_CLIENT_START = 0,

    /*
     * Server waits for CLIENTHELLO and sends the SERVERHELLO
     * (containing the version, random challenge, and optional
     * options) and goes into CHALLENGE_RESPONSE.
     */
    CERTAUTH_CLIENTHELLO = 1,

    /*
     * Client waits for SERVERHELLO and uses the random challenge to
     * generate a challenge response and sends challenge response
     * (containing certificate and challenge response).
     */
    CERTAUTH_SERVERHELLO = 2,

    /*
     * Server receives the challenge response verifies the reponse and
     * the certificate against the CA.  It sends a SERVERDONE giving
     * the result and goes into passthrough mode.
     */
    CERTAUTH_CHALLENGE_RESPONSE = 3,

    /*
     * Client waits for SERVERDONE and goes into passthrough mode,
     * contains the result.
     */
    CERTAUTH_SERVERDONE = 4,

    /*
     * Just pass all the data through.
     */
    CERTAUTH_PASSTHROUGH = 5
};
#define CERTAUTH_STATE_MAX CERTAUTH_PASSTHROUGH

/* Various message components */
enum certauth_elements {
    CERTAUTH_VERSION		= 100,
    CERTAUTH_USERID		= 101,
    CERTAUTH_OPTIONS		= 102,
    CERTAUTH_CHALLENGE_DATA	= 103,
    CERTAUTH_CHALLENGE_RSP	= 104,
    CERTAUTH_CERTIFICATE	= 105,
    CERTAUTH_RESULT		= 106,
    CERTAUTH_END		= 200
};
#define CERTAUTH_MIN_ELEMENT CERTAUTH_VERSION
#define CERTAUTH_MAX_ELEMENT CERTAUTH_RESULT

#define CERTAUTH_RESULT_SUCCESS	1
#define CERTAUTH_RESULT_ERR	2

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

    /* Result from the server or the response check. */
    unsigned int result;

    /* Certificate verification result, server only. */
    bool verified;

    /* Use authenticated from the child gensio to skip this layer. */
    bool use_child_auth;

    char *username;
    unsigned int username_len;

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
    if (!sfilter->is_client && !sfilter->verified && !sfilter->allow_authfail)
    	rv = EKEYREJECTED;
    else if (sfilter->verified)
	gensio_set_is_authenticated(io, true);
    certauth_unlock(sfilter);
    return rv;
}

static void
certauth_write(struct certauth_filter *sfilter, void *data, unsigned int len)
{
    if (len + sfilter->write_buf_len > sfilter->max_write_size) {
	sfilter->pending_err = EOVERFLOW;
	return;
    }
    memcpy(sfilter->write_buf + sfilter->write_buf_len, data, len);
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
    int rv = 0;

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

    rv = X509_verify_cert(cert_store_ctx);
    if (rv < 0) {
	rv = ENOMEM;
	goto out_err;
    }
    if (rv > 0)
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
    if (PEM_write_bio_X509(sfilter->cert_bio, sfilter->cert) == 0)
	return EOVERFLOW;
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
    if (!sfilter->cert)
	return ENOKEY;
    sfilter->write_buf_len += sfilter->cert_buf_mem.length;

    sfilter->sk_ca = sk_X509_new_null();
    if (!sfilter->sk_ca)
	return ENOMEM;
    if (!sk_X509_push(sfilter->sk_ca, sfilter->cert))
	return ENOMEM;
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
    if (certauth_writeleft(sfilter) < EVP_PKEY_size(sfilter->pkey))
	return EOVERFLOW;

    sign_ctx = EVP_MD_CTX_new();
    if (!sign_ctx)
	return ENOMEM;
    if (!EVP_SignInit(sign_ctx, sfilter->rsa_md5))
	goto out_nomem;
    if (!EVP_SignUpdate(sign_ctx, sfilter->challenge_data,
			sfilter->challenge_data_size))
	goto out_nomem;
    if (!EVP_SignFinal(sign_ctx, certauth_writepos(sfilter), &len,
		       sfilter->pkey))
	goto out_nomem;
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
    if (!sign_ctx)
	return ENOMEM;
    if (!EVP_VerifyInit(sign_ctx, sfilter->rsa_md5))
	goto out_nomem;
    if (!EVP_VerifyUpdate(sign_ctx, sfilter->challenge_data,
			  sfilter->challenge_data_size))
	goto out_nomem;
    rv = EVP_VerifyFinal(sign_ctx, sfilter->read_buf, sfilter->read_buf_len,
			 X509_get0_pubkey(sfilter->cert));
    if (rv < 0)
	goto out_nomem;

    if (rv)
	sfilter->result = CERTAUTH_RESULT_SUCCESS;
    else
	sfilter->result = CERTAUTH_RESULT_ERR;
    rv = 0;

 out:
    EVP_MD_CTX_free(sign_ctx);
    return rv;

 out_nomem:
    rv = ENOMEM;
    goto out;
}

static int
certauth_try_connect(struct gensio_filter *filter, struct timeval *timeout)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);

    certauth_lock(sfilter);
    if (sfilter->pending_err)
	goto out_err;
    if (!sfilter->got_msg)
	goto out_err;

    switch (sfilter->state) {
    case CERTAUTH_CLIENT_START:
	sfilter->write_buf_len = 0;
	certauth_write_byte(sfilter, CERTAUTH_CLIENTHELLO);
	certauth_write_byte(sfilter, CERTAUTH_VERSION);
	certauth_write_u16(sfilter, 2);
	certauth_write_u16(sfilter, GENSIO_CERTAUTH_VERSION);
	certauth_write_byte(sfilter, CERTAUTH_USERID);
	certauth_write_u16(sfilter, sfilter->username_len);
	if (sfilter->username_len)
	    certauth_write(sfilter, sfilter->username, sfilter->username_len);

	certauth_write_byte(sfilter, CERTAUTH_END);

	if (sfilter->username_len) {
	    sfilter->state = CERTAUTH_SERVERHELLO;
	} else {
	    sfilter->state = CERTAUTH_PASSTHROUGH;
	    goto out_finish;
	}
	break;

    case CERTAUTH_CLIENTHELLO:
	if (!sfilter->username || !sfilter->version) {
	    /* Remote end didn't send version or userid. */
	    sfilter->pending_err = ENOENT;
	    break;
	}
	if (sfilter->use_child_auth) {
	    struct gensio *io = gensio_filter_get_gensio(filter);

	    if (gensio_is_authenticated(io)) {
		/*
		 * A lower layer has already authenticated, just skip this.
		 */
		sfilter->result = CERTAUTH_RESULT_SUCCESS;
		goto finish_result;
	    }
	}
	if (sfilter->username_len == 0) {
	    sfilter->state = CERTAUTH_PASSTHROUGH;
	    goto out_finish;
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
	    /* Remote end didn't send challenge or userid. */
	    sfilter->pending_err = ENOENT;
	    break;
	}
	sfilter->write_buf_len = 0;
	certauth_write_byte(sfilter, CERTAUTH_CHALLENGE_RESPONSE);

	sfilter->pending_err = certauth_add_cert(sfilter);
	if (sfilter->pending_err)
	    goto out_err;

	sfilter->pending_err = certauth_add_challenge_rsp(sfilter);
	if (sfilter->pending_err)
	    goto out_err;

	certauth_write_byte(sfilter, CERTAUTH_END);
	
	sfilter->state = CERTAUTH_SERVERDONE;
	break;

    case CERTAUTH_CHALLENGE_RESPONSE:
	if (!sfilter->cert || !sfilter->result) {
	    /* Remote end didn't send certificate or challenge response. */
	    sfilter->pending_err = ENOENT;
	    goto out_err;
	}

	certauth_unlock(sfilter);
	sfilter->pending_err =
	    gensio_filter_do_event(sfilter->filter,
				   GENSIO_EVENT_PRECERT_VERIFY, 0,
				   NULL, NULL, NULL);
	certauth_lock(sfilter);
	if (sfilter->pending_err)
	    goto out_err;

	sfilter->pending_err = certauth_verify_cert(sfilter);
	if (sfilter->pending_err)
	    goto out_err;

    finish_result:
	sfilter->write_buf_len = 0;
	certauth_write_byte(sfilter, CERTAUTH_SERVERDONE);
	certauth_write_byte(sfilter, CERTAUTH_RESULT);
	certauth_write_u16(sfilter, 2);
	certauth_write_u16(sfilter, sfilter->result);
	certauth_write_byte(sfilter, CERTAUTH_END);

	sfilter->state = CERTAUTH_PASSTHROUGH;
	goto out_finish;

    case CERTAUTH_SERVERDONE:
	if (!sfilter->result) {
	    /* Remote end didn't send result. */
	    sfilter->pending_err = ENOENT;
	    goto out_err;
	}

    handle_server_done:
	if (sfilter->result != CERTAUTH_RESULT_SUCCESS) {
	    sfilter->pending_err = EKEYREJECTED;
	    goto out_err;
	}

	sfilter->state = CERTAUTH_PASSTHROUGH;
	goto out_finish;

    default:
	assert(false);
    }

    sfilter->got_msg = false;
 out_err:
    certauth_unlock(sfilter);
    if (sfilter->pending_err)
	return sfilter->pending_err;
    return EINPROGRESS;
 out_finish:
    certauth_unlock(sfilter);
    return 0;
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

static void
certauth_handle_new_element(struct certauth_filter *sfilter)
{
    struct gensio_os_funcs *o = sfilter->o;

    switch (sfilter->curr_elem) {
    case CERTAUTH_VERSION:
	if (sfilter->version) {
	    sfilter->pending_err = EPROTO;
	    break;
	}
	if (sfilter->curr_elem_len != 2)
	    sfilter->pending_err = EPROTO;
	else {
	    sfilter->version = certauth_buf_to_u16(sfilter->read_buf);
	    if (!sfilter->version)
		sfilter->pending_err = EPROTO;
	}
	break;

    case CERTAUTH_USERID:
	if (sfilter->username) {
	    sfilter->pending_err = EPROTO;
	    break;
	}
	sfilter->username = o->zalloc(0, sfilter->curr_elem_len + 1);
	sfilter->username_len = sfilter->curr_elem_len;
	if (!sfilter->username)
	    sfilter->pending_err = ENOMEM;
	else
	    memcpy(sfilter->username, sfilter->read_buf, sfilter->curr_elem_len);
	break;

    case CERTAUTH_OPTIONS:
	break;

    case CERTAUTH_CHALLENGE_DATA:
	if (sfilter->challenge_data) {
	    sfilter->pending_err = EPROTO;
	    break;
	}
	sfilter->challenge_data = o->zalloc(0, sfilter->curr_elem_len);
	sfilter->challenge_data_size = sfilter->curr_elem_len;
	if (!sfilter->challenge_data)
	    sfilter->pending_err = ENOMEM;
	else
	    memcpy(sfilter->challenge_data, sfilter->read_buf,
		   sfilter->curr_elem_len);
	break;

    case CERTAUTH_CHALLENGE_RSP:
	if (sfilter->result) {
	    sfilter->pending_err = EPROTO;
	    break;
	}
	sfilter->pending_err = certauth_check_challenge(sfilter);
	break;

    case CERTAUTH_CERTIFICATE:
	if (sfilter->cert) {
	    sfilter->pending_err = EPROTO;
	    break;
	}
	sfilter->pending_err = certauth_get_cert(sfilter);
	break;

    case CERTAUTH_RESULT:
	if (sfilter->result) {
	    sfilter->pending_err = EPROTO;
	    break;
	}
	if (sfilter->curr_elem_len != 2)
	    sfilter->pending_err = EPROTO;
	else {
	    sfilter->result = certauth_buf_to_u16(sfilter->read_buf);
	    if (!sfilter->result)
		sfilter->pending_err = EPROTO;
	}
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
	    sfilter->pending_err = EPROTO;
	    goto out_unlock;
	}
	sfilter->curr_elem = 0;
	sfilter->curr_elem_len_b1 = false;
	sfilter->curr_elem_len_b2 = false;
	sfilter->read_buf_len = 0;
	/* Note that we allow server done when waiting for a server hello. */
	if (sfilter->curr_msg_type != sfilter->state &&
	    !(sfilter->curr_msg_type == CERTAUTH_SERVERDONE &&
	      sfilter->state == CERTAUTH_SERVERHELLO)) {
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
    } else {
	if (sfilter->cert)
	    X509_free(sfilter->cert);
	if (sfilter->sk_ca) 
	    sk_X509_pop_free(sfilter->sk_ca, X509_free);
	sfilter->cert = NULL;
	sfilter->sk_ca = NULL;
	if (sfilter->username)
	    sfilter->o->free(sfilter->o, sfilter->username);
	sfilter->username = NULL;
    }

    sfilter->read_buf_len = 0;
    sfilter->write_buf_len = 0;
    sfilter->write_buf_pos = 0;
    sfilter->version = 0;
    sfilter->result = 0;
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
    if (sfilter->username)
	sfilter->o->free(sfilter->o, sfilter->username);
    if (sfilter->challenge_data)
	sfilter->o->free(sfilter->o, sfilter->challenge_data);
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    if (sfilter->verify_store)
	X509_STORE_free(sfilter->verify_store);
    sfilter->o->free(sfilter->o, sfilter);
}

static int
certauth_filter_control(struct gensio_filter *filter, bool get, int op,
			char *data, gensiods *datalen)
{
    struct certauth_filter *sfilter = filter_to_certauth(filter);
    char *s, *nidstr, *end;
    int index = -1, len, tlen, nid;
    int datasize;
    X509_NAME *nm;
    X509_NAME_ENTRY *e;
    ASN1_STRING *as;
    X509_STORE *store;
    char *CApath = NULL, *CAfile = NULL;
    unsigned char *obj;
    int objlen;

    switch (op) {
    case GENSIO_CONTROL_GET_PEER_CERT_NAME:
	if (!get)
	    return ENOTSUP;
	if (!sfilter->cert)
	    return ENXIO;
	datasize = *datalen;
	nidstr = data;
	s = strchr(data, ',');
	if (s) {
	    index = strtol(data, &end, 0);
	    if (*end != ',')
		return EINVAL;
	    nidstr = end + 1;
	}
	nid = OBJ_sn2nid(nidstr);
	if (nid == NID_undef) {
	    nid = OBJ_ln2nid(data);
	    if (nid == NID_undef)
		return EINVAL;
	}
	nm = X509_get_subject_name(sfilter->cert);
	index = X509_NAME_get_index_by_NID(nm, nid, index);
	if (index < 0)
	    return ENOENT;
	len = snprintf(data, datasize, "%d,", index);
	e = X509_NAME_get_entry(nm, index);
	as = X509_NAME_ENTRY_get_data(e);
	objlen = ASN1_STRING_to_UTF8(&obj, as);
	if (objlen < 0)
	    return ENOMEM;
	tlen = objlen;
	if (len + 1 < datasize) {
	    if (objlen > datasize - len - 1)
		objlen = datasize - len - 1;
	    memcpy(data + len, obj, objlen);
	    data[objlen + len] = '\0';
	}
	len += tlen;
	OPENSSL_free(obj);
	*datalen = len;
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
				 const char *username,
				 bool allow_authfail, bool use_child_auth,
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
    sfilter->rsa_md5 = EVP_get_digestbyname("ssl3-md5");
    if (!sfilter->rsa_md5) {
	rv = ENXIO;
	goto out_err;
    }
    sfilter->cert = cert;
    sfilter->sk_ca = sk_ca;
    sfilter->pkey = pkey;
    sfilter->verify_store = store;

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

int
gensio_certauth_filter_config(struct gensio_os_funcs *o,
			      const char * const args[],
			      bool default_is_client,
			      struct gensio_certauth_filter_data **rdata)
{
    unsigned int i;
    struct gensio_certauth_filter_data *data = o->zalloc(o, sizeof(*data));
    const char *CAfilepath = NULL, *keyfile = NULL, *certfile = NULL;
    const char *username = NULL;
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
	if (gensio_check_keyboolv(args[i], "mode", "client", "server",
				  &data->is_client) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "allow-authfail",
				 &data->allow_authfail) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "use-child-auth",
				 &data->use_child_auth) > 0)
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

    if (!keyfile)
	keyfile = certfile;

    if (data->is_client) {
	if (!keyfile) {
	    rv = ENOKEY;
	    goto out_err;
	}
	if (CAfilepath) {
	    rv = EINVAL;
	    goto out_err;
	}
	if (!username) {
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
    *rdata = data;

    return 0;
 out_err:
    if (data->CAfilepath)
	o->free(o, data->CAfilepath);
    if (data->keyfile)
	o->free(o, data->keyfile);
    if (data->certfile)
	o->free(o, data->certfile);
    if (data->username)
	o->free(o, data->username);
    o->free(o, data);
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
    if (data->username)
	o->free(o, data->username);
    o->free(o, data);
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
					  data->username,
					  data->allow_authfail,
					  data->use_child_auth,
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
