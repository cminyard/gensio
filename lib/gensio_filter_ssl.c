/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */

#include "config.h"

#include <gensio/gensio_class.h>
#include <gensio/gensio_err.h>

#include "gensio_filter_ssl.h"

#include <assert.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <gensio/gensio.h>
#include <gensio/gensio_os_funcs.h>

#ifdef _WIN32
#define DIRSEP '\\'
#else
#define DIRSEP '/'
#endif

struct gensio_ssl_filter_data {
    struct gensio_os_funcs *o;
    bool is_client;
    char *CAfilepath;
    char *keyfile;
    char *certfile;
    gensiods max_read_size;
    gensiods max_write_size;
    bool allow_authfail;
    bool clientauth;
};

static void
gensio_do_ssl_init(void *cb_data)
{
    SSL_library_init();
}

static struct gensio_once gensio_ssl_init_once;

static void
gensio_ssl_initialize(struct gensio_os_funcs *o)
{
    o->call_once(o, &gensio_ssl_init_once, gensio_do_ssl_init, NULL);
}

struct ssl_filter {
    struct gensio_filter *filter;
    struct gensio_os_funcs *o;
    bool is_client;
    bool connected;
    bool shutdown_success;
    int err;
    struct gensio_lock *lock;

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *ssl_bio;
    BIO *io_bio;
    X509 *remcert;
    X509_STORE *verify_store;

    bool expect_peer_cert;
    bool allow_authfail;

    /* This is data from SSL_read() that is waiting to be sent to the user. */
    unsigned char *read_data;
    gensiods read_data_pos;
    gensiods read_data_len;
    gensiods max_read_size;

    bool in_ul_handler;

    /*
     * This is data from the user waiting to be sent to SSL_write().  This
     * is required because if SSL_write() return that it needs I/O, it must
     * be called again with exactly the same data.
     */
    unsigned char *write_data;
    gensiods max_write_size;
    gensiods write_data_len;

    /* This is data from BIO_read() waiting to be sent to the lower layer. */
    unsigned char *xmit_buf;
    gensiods xmit_buf_pos;
    gensiods xmit_buf_len;
    gensiods max_xmit_buf;

    /*
     * SSL has asked for something.
     */
    bool want_write;
    bool want_read;

    /*
     * This is not intrinsically part of the SSL protocol, but is here
     * so the set username control works, for convenience of the user
     * and consistency with certauth.
     */
    char *username;
};

#define filter_to_ssl(v) ((struct ssl_filter *) gensio_filter_get_user_data(v))

static void
gssl_vlog(struct ssl_filter *f, enum gensio_log_levels l,
	  bool do_ssl_err, char *fmt, va_list ap)
{
    if (do_ssl_err) {
	char buf[256], buf2[200];
	unsigned long ssl_err = ERR_get_error();

	if (!ssl_err)
	    goto no_ssl_err;

	ERR_error_string_n(ssl_err, buf2, sizeof(buf2));
	snprintf(buf, sizeof(buf), "ssl: %s: %s", fmt, buf2);
	gensio_vlog(f->o, l, buf, ap);
    } else {
    no_ssl_err:
	gensio_vlog(f->o, l, fmt, ap);
    }
}


static void
gssl_log_info(struct ssl_filter *f, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gssl_vlog(f, GENSIO_LOG_INFO, false, fmt, ap);
    va_end(ap);
}

static void
gssl_log_err(struct ssl_filter *f, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gssl_vlog(f, GENSIO_LOG_ERR, false, fmt, ap);
    va_end(ap);
}

static void
gssl_logs_info(struct ssl_filter *f, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gssl_vlog(f, GENSIO_LOG_INFO, true, fmt, ap);
    va_end(ap);
}

static void
gssl_logs_err(struct ssl_filter *f, char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    gssl_vlog(f, GENSIO_LOG_ERR, true, fmt, ap);
    va_end(ap);
}

static void
ssl_lock(struct ssl_filter *sfilter)
{
    sfilter->o->lock(sfilter->lock);
}

static void
ssl_unlock(struct ssl_filter *sfilter)
{
    sfilter->o->unlock(sfilter->lock);
}

static void
ssl_set_callbacks(struct gensio_filter *filter,
		  gensio_filter_cb cb, void *cb_data)
{
    /* We don't currently use callbacks. */
}

static bool
ssl_ul_read_pending(struct gensio_filter *filter)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);
    char buf[1];
    bool rv;

    ssl_lock(sfilter);
    rv = sfilter->read_data_len || SSL_peek(sfilter->ssl, buf, 1) > 0;
    ssl_unlock(sfilter);
    return rv;
}

static bool
ssl_ll_write_pending(struct gensio_filter *filter)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);
    bool rv;

    ssl_lock(sfilter);
    rv = BIO_pending(sfilter->io_bio) || sfilter->write_data_len ||
	sfilter->xmit_buf_len || sfilter->want_write;
    ssl_unlock(sfilter);
    return rv;
}

static bool
ssl_ll_read_needed(struct gensio_filter *filter)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);
    bool rv;

    ssl_lock(sfilter);
    rv = BIO_should_read(sfilter->io_bio) || sfilter->want_read;
    ssl_unlock(sfilter);
    return rv;
}

static bool
ssl_ul_can_write(struct gensio_filter *filter, bool *val)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);

    ssl_lock(sfilter);
    *val = sfilter->write_data_len == 0 && sfilter->xmit_buf_len == 0;
    ssl_unlock(sfilter);

    return 0;
}

static int
ssl_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    /* Always succeed, check the result in ssl_check_open_done(). */
    return 1;
}

static int
ssl_check_open_done(struct gensio_filter *filter, struct gensio *io)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);
    long verify_err;
    int rv = 0;
    const char *auxdata[] = { NULL, NULL };

    ssl_lock(sfilter);
    if (sfilter->expect_peer_cert) {
	sfilter->remcert = SSL_get_peer_certificate(sfilter->ssl);
	if (!sfilter->remcert) {
	    gssl_log_info(sfilter, "Remote peer offered no certificate");
	    rv = GE_NOCERT;
	    goto out_unlock;
	}

	verify_err = SSL_get_verify_result(sfilter->ssl);
	if (verify_err == X509_V_OK)
	    gensio_set_is_authenticated(io, true);
	else if (verify_err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
		 verify_err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	    rv = GE_CERTNOTFOUND;
	else if (verify_err == X509_V_ERR_CERT_REVOKED)
	    rv = GE_CERTREVOKED;
	else if (verify_err == X509_V_ERR_CERT_HAS_EXPIRED ||
		 verify_err == X509_V_ERR_CRL_HAS_EXPIRED)
	    rv = GE_CERTEXPIRED;
	else
	    rv = GE_CERTINVALID;

	ssl_unlock(sfilter);
	if (rv)
	    auxdata[0] = X509_verify_cert_error_string(verify_err);
	rv = gensio_cb(io, GENSIO_EVENT_POSTCERT_VERIFY, rv,
		       NULL, NULL, auxdata);
	ssl_lock(sfilter);

	if (rv == GE_NOTSUP) {
	    if (verify_err != X509_V_OK) {
		gssl_logs_info(sfilter,
			       "Remote peer certificate verify failed");
		X509_free(sfilter->remcert);
		sfilter->remcert = NULL;
		rv = GE_CERTINVALID;
	    } else {
		rv = 0;
	    }
	}
    }
 out_unlock:
    if (rv && sfilter->allow_authfail)
	rv = 0;
    ssl_unlock(sfilter);
    return rv;
}

static int
ssl_try_connect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);
    int rv, success, err;

    ssl_lock(sfilter);
    sfilter->want_read = false;
    sfilter->want_write = false;
    if (sfilter->is_client)
	success = SSL_connect(sfilter->ssl);
    else
	success = SSL_accept(sfilter->ssl);

    if (!success) {
	err = SSL_get_error(sfilter->ssl, success);
	goto err_rpt;
    } else if (success == 1) {
	sfilter->connected = true;
	rv = 0;
    } else {
	err = SSL_get_error(sfilter->ssl, success);
	switch (err) {
	case SSL_ERROR_WANT_READ:
	    sfilter->want_read = true;
	    rv = GE_INPROGRESS;
	    break;

	case SSL_ERROR_WANT_WRITE:
	    sfilter->want_write = true;
	    rv = GE_INPROGRESS;
	    break;

	case SSL_ERROR_SSL:
	    gssl_logs_err(sfilter, "Failed SSL startup");
	    rv = GE_PROTOERR;
	    break;

	case SSL_ERROR_ZERO_RETURN:
	    rv = GE_REMCLOSE;
	    break;

	default:
	err_rpt:
	    gssl_log_err(sfilter, "Failed SSL startup: 0x%8.8x", err);
	    rv = GE_COMMERR;
	}
    }
    ssl_unlock(sfilter);
    return rv;
}

static int
ssl_try_disconnect(struct gensio_filter *filter, gensio_time *timeout)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);
    int success, rv = GE_INPROGRESS, shutdown, err;

    ssl_lock(sfilter);
    sfilter->connected = false;

    shutdown = SSL_get_shutdown(sfilter->ssl);
    shutdown &= SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN;
    if (shutdown == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN)) {
	/* Shutdown is complete. */
	rv = 0;
	goto out_unlock;
    }

    sfilter->want_read = false;
    sfilter->want_write = false;

    if (!sfilter->shutdown_success) {
	success = SSL_shutdown(sfilter->ssl);
	if (success >= 0) {
	    sfilter->shutdown_success = true;
	    if (success == 1)
		rv = 0;
	    else
		sfilter->want_read = true;
	    goto out_unlock;
	}

	err = SSL_get_error(sfilter->ssl, success);
	switch (err) {
	case SSL_ERROR_WANT_READ:
	    sfilter->want_read = true;
	    break;

	case SSL_ERROR_WANT_WRITE:
	    sfilter->want_write = true;
	    break;

	case SSL_ERROR_SSL:
	    gssl_logs_err(sfilter, "Failed SSL shutdown");
	    rv = GE_PROTOERR;
	    break;

	default:
	    gssl_log_err(sfilter, "Failed SSL shutdown");
	    rv = GE_COMMERR;
	}
    } else {
	/* Waiting to receive the shutdown from the other end. */
	sfilter->want_read = true;
    }
 out_unlock:
    if (!rv)
	sfilter->err = GE_LOCALCLOSED;
    ssl_unlock(sfilter);

    return rv;
}

static int
ssl_ul_write(struct gensio_filter *filter,
	     gensio_ul_filter_data_handler handler, void *cb_data,
	     gensiods *rcount,
	     const struct gensio_sg *sg, gensiods sglen,
	     const char *const *auxdata)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);
    int err = 0;
    gensiods i;

    ssl_lock(sfilter);
    if (sfilter->err) {
	if (rcount) {
	    *rcount = 0;
	    for (i = 0; i < sglen; i++)
		*rcount += sg[i].buflen;
	}
	err = sfilter->err;
	goto out_unlock;
    }

    if (!sfilter->connected) {
	/* No new data after a close. */
	if (rcount) {
	    *rcount = 0;
	    for (i = 0; i < sglen; i++)
		*rcount += sg[i].buflen;
	}
    } else if (sfilter->write_data_len) {
	/* Ignore any incoming data if we already have some. */
	if (rcount)
	    *rcount = 0;
    } else {
	for (i = 0; i < sglen; i++) {
	    gensiods buflen = sg[i].buflen;

	    if (buflen > sfilter->max_write_size - sfilter->write_data_len)
		buflen = sfilter->max_write_size - sfilter->write_data_len;
	    memcpy(sfilter->write_data + sfilter->write_data_len,
		   sg[i].buf, buflen);
	    sfilter->write_data_len += buflen;
	}
	if (rcount)
	    *rcount = sfilter->write_data_len;
    }

 restart:
    if (sfilter->xmit_buf_len) {
	gensiods written;
	struct gensio_sg sg = { sfilter->xmit_buf + sfilter->xmit_buf_pos,
				sfilter->xmit_buf_len - sfilter->xmit_buf_pos };

	err = handler(cb_data, &written, &sg, 1, NULL);
	if (err) {
	    sfilter->xmit_buf_len = 0;
	    sfilter->write_data_len = 0;
	} else {
	    sfilter->xmit_buf_pos += written;
	    if (sfilter->xmit_buf_pos >= sfilter->xmit_buf_len)
		sfilter->xmit_buf_len = 0;
	}
    }

    if (!err && sfilter->xmit_buf_len == 0 && sfilter->write_data_len > 0) {
	sfilter->want_read = false;
	sfilter->want_write = false;
	err = SSL_write(sfilter->ssl, sfilter->write_data,
			sfilter->write_data_len);
	if (err <= 0) {
	    err = SSL_get_error(sfilter->ssl, err);
	    switch (err) {
	    case SSL_ERROR_WANT_READ:
		sfilter->want_read = true;
		err = 0;
		break;

	    case SSL_ERROR_WANT_WRITE:
		sfilter->want_write = true;
		err = 0;
		break;

	    case SSL_ERROR_SSL:
		gssl_logs_err(sfilter, "Failed SSL write");
		err = GE_PROTOERR;
		sfilter->write_data_len = 0;
		break;

	    case SSL_ERROR_ZERO_RETURN:
		err = GE_REMCLOSE;
		sfilter->write_data_len = 0;
		break;

	    default:
		gssl_log_err(sfilter, "Failed SSL write: %d", err);
		err = GE_COMMERR;
		sfilter->write_data_len = 0;
	    }
	} else {
	    assert(err == sfilter->write_data_len);
	    sfilter->write_data_len = 0;
	    err = 0;
	}
    }

    if (!err && sfilter->xmit_buf_len == 0) {
	int rdlen = BIO_read(sfilter->io_bio, sfilter->xmit_buf,
			     sfilter->max_xmit_buf);

	if (rdlen <= 0) {
	    if (!BIO_should_retry(sfilter->io_bio)) {
		gssl_log_err(sfilter, "Failed BIO read");
		err = GE_COMMERR;
	    }
	} else {
	    sfilter->xmit_buf_len = rdlen;
	    sfilter->xmit_buf_pos = 0;
	    goto restart;
	}
    }
    if (err)
	sfilter->err = err;
 out_unlock:
    ssl_unlock(sfilter);

    return err;
}

static int
ssl_ll_write(struct gensio_filter *filter,
	     gensio_ll_filter_data_handler handler, void *cb_data,
	     gensiods *rcount,
	     unsigned char *buf, gensiods buflen,
	     const char *const *auxdata)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);
    int err = 0;

    if (gensio_str_in_auxdata(auxdata, "oob")) {
	/* Ignore oob data. */
	if (rcount)
	    *rcount = buflen;
	return 0;
    }

    ssl_lock(sfilter);
    if (sfilter->err) {
	if (rcount)
	    *rcount = buflen;
	err = sfilter->err;
	goto out_unlock;
    }

    if (buflen > 0) {
	int wrlen = BIO_write(sfilter->io_bio, buf, buflen);

	if (wrlen <= 0) {
	    if (!BIO_should_retry(sfilter->io_bio)) {
		gssl_log_err(sfilter, "Failed BIO write");
		err = GE_COMMERR;
		wrlen = buflen;
	    } else {
		wrlen = 0;
	    }
	}
	if (rcount)
	    *rcount = wrlen;
    }

 process_more:
    if (!sfilter->read_data_len) {
	int rlen;

	sfilter->want_read = false;
	sfilter->want_write = false;
	rlen = SSL_read(sfilter->ssl, sfilter->read_data,
			sfilter->max_read_size);
	if (rlen <= 0) {
	    err = SSL_get_error(sfilter->ssl, rlen);
	    switch (err) {
	    case SSL_ERROR_WANT_READ:
		sfilter->want_read = true;
		err = 0;
		break;

	    case SSL_ERROR_WANT_WRITE:
		sfilter->want_write = true;
		err = 0;
		break;

	    case SSL_ERROR_SSL:
		gssl_logs_err(sfilter, "Failed SSL read");
#ifdef ENABLE_INTERNAL_TRACE
		/*
		 * Report these as REMCLOSE when testing.  These can
		 * happen, I think, when data gets cut off to the SSL
		 * code.  It's a protocol error, but that can fail
		 * some tests, and we want protocol errors elsewhere
		 * to actually fail the tests.
		 */
		err = GE_REMCLOSE;
#else
		err = GE_PROTOERR;
#endif
		break;

	    case SSL_ERROR_ZERO_RETURN:
		err = GE_REMCLOSE;
		break;

	    default:
		gssl_log_err(sfilter, "Failed SSL read: %d", err);
		err = GE_COMMERR;
	    }
	} else {
	    sfilter->read_data_len = rlen;
	}
	sfilter->read_data_pos = 0;
    }

    if (!err && sfilter->read_data_len) {
	gensiods count = 0;

	assert(!sfilter->in_ul_handler);
	sfilter->in_ul_handler = true;
	ssl_unlock(sfilter);
	err = handler(cb_data, &count,
		      sfilter->read_data + sfilter->read_data_pos,
		      sfilter->read_data_len, NULL);
	ssl_lock(sfilter);
	sfilter->in_ul_handler = false;
	if (!err) {
	    if (count >= sfilter->read_data_len) {
		sfilter->read_data_len = 0;
		sfilter->read_data_pos = 0;
		if (!sfilter->err && sfilter->connected)
		    goto process_more;
	    } else {
		sfilter->read_data_len -= count;
		sfilter->read_data_pos += count;
	    }
	}
    }
    if (err && !sfilter->err)
	sfilter->err = err;
 out_unlock:
    ssl_unlock(sfilter);

    return err;
}

static int
ssl_setup(struct gensio_filter *filter, struct gensio *io)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);
    int success;
    gensiods bio_size = sfilter->max_read_size * 2;

    sfilter->ssl = SSL_new(sfilter->ctx);
    if (!sfilter->ssl)
	return GE_NOMEM;

    /* The BIO has to be large enough to hold a full SSL key transaction. */
    if (bio_size < 4096)
	bio_size = 4096;
    success = BIO_new_bio_pair(&sfilter->ssl_bio, bio_size,
			       &sfilter->io_bio, bio_size);
    if (!success) {
	SSL_free(sfilter->ssl);
	sfilter->ssl = NULL;
	return GE_NOMEM;
    }

    SSL_set_bio(sfilter->ssl, sfilter->ssl_bio, sfilter->ssl_bio);

    if (sfilter->is_client)
	SSL_set_connect_state(sfilter->ssl);
    else
	SSL_set_accept_state(sfilter->ssl);

    return 0;
}

static void
ssl_cleanup(struct gensio_filter *filter)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);

    if (sfilter->verify_store)
	X509_STORE_free(sfilter->verify_store);
    sfilter->verify_store = NULL;
    if (sfilter->remcert)
	X509_free(sfilter->remcert);
    sfilter->remcert = NULL;
    if (sfilter->ssl)
	SSL_free(sfilter->ssl);
    sfilter->ssl = NULL;
    if (sfilter->io_bio)
	/* Just free one BIO to free both parts of the pair. */
	BIO_free(sfilter->io_bio);
    sfilter->ssl_bio = NULL;
    sfilter->io_bio = NULL;
    sfilter->err = 0;
    sfilter->read_data_len = 0;
    sfilter->read_data_pos = 0;
    sfilter->xmit_buf_len = 0;
    sfilter->xmit_buf_pos = 0;
    sfilter->write_data_len = 0;
    sfilter->connected = false;
    sfilter->shutdown_success = false;
}

static void
sfilter_free(struct ssl_filter *sfilter)
{
    if (sfilter->verify_store)
	X509_STORE_free(sfilter->verify_store);
    if (sfilter->remcert)
	X509_free(sfilter->remcert);
    if (sfilter->ssl)
	SSL_free(sfilter->ssl);
    if (sfilter->io_bio)
	/* Just free one BIO to free both parts of the pair. */
	BIO_free(sfilter->io_bio);
    if (sfilter->ctx)
	SSL_CTX_free(sfilter->ctx);
    if (sfilter->lock)
	sfilter->o->free_lock(sfilter->lock);
    if (sfilter->read_data) {
	memset(sfilter->read_data, 0, sfilter->max_read_size);
	sfilter->o->free(sfilter->o, sfilter->read_data);
    }
    if (sfilter->xmit_buf)
	sfilter->o->free(sfilter->o, sfilter->xmit_buf);
    if (sfilter->write_data)
	sfilter->o->free(sfilter->o, sfilter->write_data);
    if (sfilter->filter)
	gensio_filter_free_data(sfilter->filter);
    sfilter->o->free(sfilter->o, sfilter);
}

static void
ssl_free(struct gensio_filter *filter)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);

    return sfilter_free(sfilter);
}

/* Also in gensio_filter_certauth.c. */
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

/* Also in gensio_filter_certauth.c. */
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

/* Also in gensio_filter_certauth.c. */
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

static int
ssl_filter_control(struct gensio_filter *filter, bool get, int op, char *data,
		   gensiods *datalen)
{
    struct ssl_filter *sfilter = filter_to_ssl(filter);
    X509_STORE *store;
    char *CApath = NULL, *CAfile = NULL;

    switch (op) {
    case GENSIO_CONTROL_GET_PEER_CERT_NAME:
	if (!get)
	    return GE_NOTSUP;
	return gensio_cert_get_name(sfilter->remcert, data, datalen);

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

	ssl_lock(sfilter);
	if (sfilter->verify_store)
	    X509_STORE_free(sfilter->verify_store);
	sfilter->verify_store = store;
	ssl_unlock(sfilter);
	return 0;

    case GENSIO_CONTROL_CERT:
	if (!get)
	    return GE_NOTSUP;
	if (!sfilter->remcert)
	    return GE_NOTFOUND;
	return gensio_cert_to_buf(sfilter->remcert, data, datalen);

    case GENSIO_CONTROL_CERT_FINGERPRINT:
	if (!get)
	    return GE_NOTSUP;
	if (!sfilter->remcert)
	    return GE_NOTFOUND;
	return gensio_cert_fingerprint(sfilter->remcert, data, datalen);

    case GENSIO_CONTROL_USERNAME: {
	int rv = 0;

	ssl_lock(sfilter);
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
	    sfilter->username = data;
	}
	out_username:
	ssl_unlock(sfilter);
	return rv;
    }

    case GENSIO_CONTROL_MAX_WRITE_PACKET:
	if (!get)
	    return GE_NOTSUP;
	*datalen = snprintf(data, *datalen, "%lu",
			    (unsigned long) sfilter->max_write_size);
	return 0;

    default:
	return GE_NOTSUP;
    }
}

static int gensio_ssl_filter_func(struct gensio_filter *filter, int op,
				  void *func, void *data,
				  gensiods *count,
				  void *buf, const void *cbuf,
				  gensiods buflen,
				  const char *const *auxdata)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	ssl_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return ssl_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_LL_WRITE_PENDING:
	return ssl_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return ssl_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_UL_CAN_WRITE:
	return ssl_ul_can_write(filter, data);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return ssl_check_open_done(filter, data);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return ssl_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return ssl_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE_SG:
	return ssl_ul_write(filter, func, data, count, cbuf, buflen, buf);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return ssl_ll_write(filter, func, data, count, buf, buflen, NULL);

    case GENSIO_FILTER_FUNC_SETUP:
	return ssl_setup(filter, data);

    case GENSIO_FILTER_FUNC_CLEANUP:
	ssl_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	ssl_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_CONTROL:
	return ssl_filter_control(filter, *((bool *) cbuf), buflen, data,
				  count);

    case GENSIO_FILTER_FUNC_TIMEOUT:
    default:
	return GE_NOTSUP;
    }
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_STORE_CTX_get0_cert(ctx) ((ctx)->cert)
#define X509_STORE_CTX_get0_chain(ctx) ((ctx)->chain)
#endif

static int
gensio_ssl_cert_verify(X509_STORE_CTX *ctx, void *cb_data)
{
    struct ssl_filter *sfilter = cb_data;
    X509_STORE_CTX *nctx = NULL;
    X509 *cert = X509_STORE_CTX_get0_cert(ctx);
    int rv;

    sfilter->remcert = cert;

    /*
     * This should only occur from the BIO_write() into OpenSSL, so it
     * should be ok to unlock here.
     */
    ssl_unlock(sfilter);
    rv = gensio_filter_do_event(sfilter->filter, GENSIO_EVENT_PRECERT_VERIFY, 0,
				NULL, NULL, NULL);
    ssl_lock(sfilter);
    if (rv && rv != GE_NOTSUP)
	return 0;

    if (sfilter->verify_store) {
	STACK_OF(X509) *cert_chain = X509_STORE_CTX_get0_chain(ctx);
	int ssl_ex_idx = SSL_get_ex_data_X509_STORE_CTX_idx();
	SSL *s = X509_STORE_CTX_get_ex_data(ctx, ssl_ex_idx);
	X509_VERIFY_PARAM *param;

	rv = -1;
	nctx = X509_STORE_CTX_new();
	if (!nctx)
	    goto out_err;

	if (!X509_STORE_CTX_init(nctx, sfilter->verify_store, cert, cert_chain))
	    goto out_err;

	param = X509_VERIFY_PARAM_new();
	if (!param)
	    goto out_err;

	if (!X509_VERIFY_PARAM_set1(param, X509_STORE_CTX_get0_param(ctx))) {
	    X509_VERIFY_PARAM_free(param);
	    goto out_err;
	}

	X509_STORE_CTX_set0_param(nctx, param);
	X509_STORE_CTX_set_ex_data(nctx, ssl_ex_idx, s);
	ctx = nctx;
    }

    rv = X509_verify_cert(ctx);
    if (rv <= 0)
	gssl_log_err(sfilter, "Error verifying certificate: %s",
	     X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));

 out:
    if (nctx)
	X509_STORE_CTX_free(nctx);
    return rv;

 out_err:
    gssl_log_err(sfilter, "Error initializing verify store");
    goto out;
}

static struct gensio_filter *
gensio_ssl_filter_raw_alloc(struct gensio_os_funcs *o,
			    bool is_client,
			    SSL_CTX *ctx,
			    bool expect_peer_cert,
			    bool allow_authfail,
			    gensiods max_read_size,
			    gensiods max_write_size)
{
    struct ssl_filter *sfilter;

    sfilter = o->zalloc(o, sizeof(*sfilter));
    if (!sfilter)
	return NULL;

    sfilter->o = o;
    sfilter->is_client = is_client;
    sfilter->max_write_size = max_write_size;
    sfilter->max_read_size = max_read_size;
    sfilter->expect_peer_cert = expect_peer_cert;
    sfilter->allow_authfail = allow_authfail;

    SSL_CTX_set_cert_verify_callback(ctx, gensio_ssl_cert_verify, sfilter);

    sfilter->lock = o->alloc_lock(o);
    if (!sfilter->lock)
	goto out_nomem;

    sfilter->read_data = o->zalloc(o, sfilter->max_read_size);
    if (!sfilter->read_data)
	goto out_nomem;

    sfilter->write_data = o->zalloc(o, sfilter->max_write_size);
    if (!sfilter->write_data)
	goto out_nomem;

    sfilter->max_xmit_buf = sfilter->max_write_size + 128;
    if (sfilter->max_xmit_buf < 1024)
	sfilter->max_xmit_buf = 1024; /* Enough room for the protocol. */
    sfilter->xmit_buf = o->zalloc(o, sfilter->max_xmit_buf);
    if (!sfilter->xmit_buf)
	goto out_nomem;

    sfilter->filter = gensio_filter_alloc_data(o, gensio_ssl_filter_func,
					       sfilter);
    if (!sfilter->filter)
	goto out_nomem;

    /*
     * Delay setting this so that it's not freed if there is a memory
     * allocation error.  The caller passed it in, they should free it.
     */
    sfilter->ctx = ctx;
    return sfilter->filter;

 out_nomem:
    sfilter_free(sfilter);
    return NULL;
}

int
gensio_ssl_filter_config(struct gensio_os_funcs *o,
			 const char * const args[],
			 bool default_is_client,
			 struct gensio_ssl_filter_data **rdata)
{
    unsigned int i;
    struct gensio_ssl_filter_data *data = o->zalloc(o, sizeof(*data));
    int rv = GE_NOMEM, ival;
    char *str;
    const char *cstr;

    if (!data)
	return GE_NOMEM;
    data->o = o;
    data->is_client = default_is_client;
    data->max_write_size = SSL3_RT_MAX_PLAIN_LENGTH;
    data->max_read_size = SSL3_RT_MAX_PLAIN_LENGTH;

    rv = gensio_get_default(o, "ssl", "allow-authfail", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    data->allow_authfail = ival;
    rv = gensio_get_default(o, "ssl", "clientauth", false,
			    GENSIO_DEFAULT_BOOL, NULL, &ival);
    if (rv)
	return rv;
    data->clientauth = ival;

    rv = gensio_get_default(o, "ssl", "mode", false,
			    GENSIO_DEFAULT_STR, &str, NULL);
    if (rv) {
	gensio_log(o, GENSIO_LOG_ERR,
		   "Failed getting ssl mode: %s", gensio_err_to_str(rv));
	return rv;
    }
    if (str) {
	if (strcasecmp(str, "client") == 0)
	    data->is_client = true;
	else if (strcasecmp(str, "server") == 0)
	    data->is_client = false;
	else {
	    gensio_log(o, GENSIO_LOG_ERR,
		       "Unknown default ssl mode (%s), ignoring", str);
	}
	o->free(o, str);
    }

    rv = GE_NOMEM;
    for (i = 0; args && args[i]; i++) {
	if (gensio_check_keyvalue(args[i], "CA", &cstr)) {
	    data->CAfilepath = gensio_strdup(o, cstr);
	    if (!data->CAfilepath)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "key", &cstr)) {
	    data->keyfile = gensio_strdup(o, cstr);
	    if (!data->keyfile)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyvalue(args[i], "cert", &cstr)) {
	    data->certfile = gensio_strdup(o, cstr);
	    if (!data->certfile)
		goto out_err;
	    continue;
	}
	if (gensio_check_keyds(args[i], "readbuf", &data->max_read_size) > 0)
	    continue;
	if (gensio_check_keyds(args[i], "writebuf", &data->max_write_size) > 0)
	    continue;
	if (gensio_check_keyboolv(args[i], "mode", "client", "server",
				  &data->is_client) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "allow-authfail",
				 &data->allow_authfail) > 0)
	    continue;
	if (gensio_check_keybool(args[i], "clientauth",
				 &data->clientauth) > 0)
	    continue;
	rv = GE_INVAL;
	goto out_err;
    }

    if (!data->keyfile) {
	rv = gensio_get_default(o, "ssl", "key", false, GENSIO_DEFAULT_STR,
				&data->keyfile, NULL);
	if (rv)
	    goto out_err;
    }
    if (!data->certfile) {
	rv = gensio_get_default(o, "ssl", "cert", false, GENSIO_DEFAULT_STR,
				&data->certfile, NULL);
	if (rv)
	    goto out_err;
    }
    if (!data->CAfilepath) {
	rv = gensio_get_default(o, "ssl", "CA", false, GENSIO_DEFAULT_STR,
				&data->CAfilepath, NULL);
	if (rv)
	    goto out_err;
    }

    if (!data->is_client) {
	if (!data->keyfile) {
	    rv = GE_KEYNOTFOUND;
	    goto out_err;
	}
    }

    if (data->keyfile && !data->certfile) {
	data->certfile = gensio_strdup(o, data->keyfile);
	if (!data->certfile) {
	    rv = GE_NOMEM;
	    goto out_err;
	}
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
    o->free(o, data);
    return rv;
}

void
gensio_ssl_filter_config_free(struct gensio_ssl_filter_data *data)
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
    o->free(o, data);
}

int
gensio_ssl_filter_alloc(struct gensio_ssl_filter_data *data,
			struct gensio_filter **rfilter)
{
    struct gensio_os_funcs *o = data->o;
    SSL_CTX *ctx = NULL;
    struct gensio_filter *filter;
    bool expect_peer_cert;
    int rv = GE_INVAL;

    gensio_ssl_initialize(o);

    if (data->is_client) {
	expect_peer_cert = true;
	ctx = SSL_CTX_new(SSLv23_client_method());
    } else {
	expect_peer_cert = data->clientauth;
	ctx = SSL_CTX_new(SSLv23_server_method());
    }
    if (!ctx)
	return GE_NOMEM;

    if (!data->is_client && expect_peer_cert)
	/*
	 * In server mode, the certificate will not be requested unless
	 * mode is SSL_VERIFY_PEER.  But in that mode, it terminates
	 * the connection if there is no certificate in the default
	 * verify callback.  So use the below so that the server mode
	 * works like client mode, request a certificate, but don't
	 * terminate the connection automatically if it is not there
	 * or fails.  We will do that in the check open call.
	 */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, ssl_verify_cb);

    if (data->CAfilepath && data->CAfilepath[0]) {
	char *CAfile = NULL, *CApath = NULL;

	if (data->CAfilepath[strlen(data->CAfilepath) - 1] == DIRSEP)
	    CApath = data->CAfilepath;
	else
	    CAfile = data->CAfilepath;
	if (!SSL_CTX_load_verify_locations(ctx, CAfile, CApath)) {
	    rv = GE_CERTNOTFOUND;
	    goto err;
	}
    }

    if (data->certfile && data->certfile[0]) {
	if (!SSL_CTX_use_certificate_chain_file(ctx, data->certfile)) {
	    rv = GE_CERTNOTFOUND;
	    goto err;
	}
	if (!SSL_CTX_use_PrivateKey_file(ctx, data->keyfile,
					 SSL_FILETYPE_PEM)) {
	    rv = GE_KEYNOTFOUND;
	    goto err;
	}
	if (!SSL_CTX_check_private_key(ctx)) {
	    rv = GE_KEYINVALID;
	    goto err;
	}
    }

    filter = gensio_ssl_filter_raw_alloc(o, data->is_client, ctx,
					 expect_peer_cert,
					 data->allow_authfail,
					 data->max_read_size,
					 data->max_write_size);
    if (!filter) {
	rv = GE_NOMEM;
	goto err;
    }


    *rfilter = filter;
    return 0;

 err:
    SSL_CTX_free(ctx);
    return rv;
}
