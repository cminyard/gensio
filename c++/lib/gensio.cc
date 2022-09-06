//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

#include <map>
#include <gensio/gensio>
#include <string.h>
#include <stdarg.h>

namespace gensios {
#include <gensio/gensio_osops.h>

    int Event::new_channel(Gensio *new_channel,
			   const char *const *auxdata)
    {
	return GE_NOTSUP;
    }

    struct gensio_cpp_data {
	struct gensio_frdata frdata;
	Gensio *g;
    };

    Gensio *gensio_alloc(struct gensio *io, Os_Funcs &o,
			 class Event *cb);

    class GENSIOCPP_DLL_PUBLIC Main_Raw_Event_Handler:
	public Raw_Event_Handler {
    public:
	Main_Raw_Event_Handler() { }
	int handle(Gensio *g, struct gensio *io,
		   int event, int err,
		   unsigned char *buf, gensiods *buflen,
		   const char *const *auxdata) override
	{
	    Event *cb = g->get_cb();
	    Gensio *g2;

	    try {
		if (event >= GENSIO_EVENT_USER_MIN &&
		    event <= GENSIO_EVENT_USER_MAX) {
		    std::vector<unsigned char> val(buf, buf + *buflen);
		    return cb->user_event(event, err, val, auxdata);
		}

		if (event >= SERGENSIO_EVENT_BASE &&
		    event <= SERGENSIO_EVENT_MAX) {
		    Serial_Event *scb = dynamic_cast<Serial_Event *>(cb);
		    unsigned int *val = (unsigned int *) buf;

		    if (!scb)
			return GE_NOTSUP;

		    if (event == GENSIO_EVENT_SER_SIGNATURE) {
			std::vector<unsigned char> sig(buf, buf + *buflen);
			scb->signature(sig);
			return 0;
		    }

		    switch (event) {
		    case GENSIO_EVENT_SER_MODEMSTATE:
			scb->modemstate(*val);
			break;

		    case GENSIO_EVENT_SER_LINESTATE:
			scb->linestate(*val);
			break;

		    case GENSIO_EVENT_SER_FLOW_STATE:
			scb->flow_state(*val);
			break;

		    case GENSIO_EVENT_SER_FLUSH:
			scb->flush(*val);
			break;

		    case GENSIO_EVENT_SER_SYNC:
			scb->sync();
			break;

		    case GENSIO_EVENT_SER_BAUD:
			scb->baud(*val);
			break;

		    case GENSIO_EVENT_SER_DATASIZE:
			scb->datasize(*val);
			break;

		    case GENSIO_EVENT_SER_PARITY:
			scb->parity(*val);
			break;

		    case GENSIO_EVENT_SER_STOPBITS:
			scb->stopbits(*val);
			break;

		    case GENSIO_EVENT_SER_FLOWCONTROL:
			scb->flowcontrol(*val);
			break;

		    case GENSIO_EVENT_SER_IFLOWCONTROL:
			scb->iflowcontrol(*val);
			break;

		    case GENSIO_EVENT_SER_SBREAK:
			scb->sbreak(*val);
			break;

		    case GENSIO_EVENT_SER_DTR:
			scb->dtr(*val);
			break;

		    case GENSIO_EVENT_SER_RTS:
			scb->rts(*val);
			break;

		    default:
			return GE_NOTSUP;
		    }
		    return 0;
		}

		switch (event) {
		case GENSIO_EVENT_READ: {
		    if (buflen) {
			SimpleUCharVector vdata(buf, *buflen);
			*buflen = cb->read(err, vdata, auxdata);
		    } else {
			SimpleUCharVector vdata(NULL, 0);
			cb->read(err, vdata, auxdata);
		    }
		    return 0;
		}

		case GENSIO_EVENT_WRITE_READY:
		    cb->write_ready();
		    return 0;

		case GENSIO_EVENT_NEW_CHANNEL:
		    g2 = gensio_alloc((struct gensio *) buf,
				      g->get_os_funcs(), NULL);
		    return g->raw_event_handler->new_channel(cb, g2,
							     auxdata);

		case GENSIO_EVENT_SEND_BREAK:
		    cb->send_break();
		    return 0;

		case GENSIO_EVENT_AUTH_BEGIN:
		    return cb->auth_begin();

		case GENSIO_EVENT_PRECERT_VERIFY:
		    return cb->precert_verify();

		case GENSIO_EVENT_POSTCERT_VERIFY:
		    return cb->postcert_verify(err,
					       auxdata ? auxdata[0] : NULL);

		case GENSIO_EVENT_PASSWORD_VERIFY: {
		    std::string pwstr((char *) buf);
		    return cb->password_verify(pwstr);
		}

		case GENSIO_EVENT_REQUEST_PASSWORD: {
		    int rv;
		    std::string pwstr("");

		    rv = cb->request_password(*buflen, pwstr);
		    if (rv)
			return rv;
		    if (pwstr.size() > *buflen)
			return GE_TOOBIG;
		    *buflen = (gensiods) pwstr.size();
		    memcpy(buf, pwstr.c_str(), *buflen);
		    return 0;
		}

		case GENSIO_EVENT_2FA_VERIFY: {
		    std::vector<unsigned char> val(buf, buf + *buflen);
		    return cb->verify_2fa(val);
		}

		case GENSIO_EVENT_REQUEST_2FA: {
		    int rv;
		    std::vector<unsigned char> val(0);
		    Os_Funcs o = g->get_os_funcs();
		    unsigned char *rbuf;

		    rv = cb->request_2fa(val);
		    if (rv)
			return rv;
		    rbuf = (unsigned char *) o->zalloc(o, (gensiods) val.size());
		    if (!rbuf)
			return GE_NOMEM;
		    *buflen = (gensiods) val.size();
		    memcpy(rbuf, val.data(), *buflen);
		    *((unsigned char **) buf) = rbuf;
		    return 0;
		}
		}
		return GE_NOTSUP;
	    } catch (std::exception &e) {
		gensio_log(g->get_os_funcs(), GENSIO_LOG_ERR,
			   "Received C++ exception in callback handler: %s",
			   e.what());
		return GE_APPERR;
	    }
	}

	int new_channel(Event *e, Gensio *new_chan,
			const char *const *auxdata) override
	{
	    if (e)
		return e->new_channel(new_chan, auxdata);
	    return GE_NOTSUP;
	}

	void freed(Event *e) override
	{
	    if (e)
		e->freed();
	}
    };

    static int
    gensio_cpp_cb(struct gensio *io, void *user_data,
		  int event, int err,
		  unsigned char *buf, gensiods *buflen,
		  const char *const *auxdata)
   {
	Gensio *g = static_cast<Gensio *>(user_data);

	return g->raw_event_handler->handle(g, io, event, err, buf, buflen,
					    auxdata);
    }

    void gensio_cpp_freed(struct gensio *io, struct gensio_frdata *frdata)
    {
	struct gensio_cpp_data *d = gensio_container_of(frdata,
							struct gensio_cpp_data,
							frdata);
	Event *cb = d->g->get_cb();

	// Disable callbacks from here out.
	d->g->set_event_handler(NULL);

	// Gensios that are not top-level will not have a raw event
	// handler.  This only matters for freed, as the freed call
	// doesn't come in from the gensio event handler, but from the
	// frdata handler.
	if (d->g->raw_event_handler)
	    d->g->raw_event_handler->freed(cb);
	else if (cb)
	    cb->freed();
	delete d->g;
	delete d;
    }

    // Note - If this fails, it deletes the object it is part of and
    // throws an exception.  Most of the time that's what you want,
    // but some places needs special handling.
    void
    Gensio::set_gensio(struct gensio *io, bool set_cb)
    {
	struct gensio_cpp_data *d;

	try {
	    d = new struct gensio_cpp_data;
	} catch (...) {
	    delete this;
	    throw;
	}
	this->io = io;
	d->g = this;
	d->frdata.freed = gensio_cpp_freed;
	gensio_set_frdata(io, &d->frdata);
	if (set_cb) {
	    gensio_set_callback(io, gensio_cpp_cb, this);
	    try {
		this->raw_event_handler = new Main_Raw_Event_Handler();
	    } catch (...) {
		delete d;
		delete this;
		throw;
	    }
	}
    }

    void
    Serial_Gensio::set_gensio(struct gensio *io, bool set_cb)
    {
	this->sio = gensio_to_sergensio(io);
	Gensio::set_gensio(io, set_cb);
    }

    Gensio *
    gensio_alloc(struct gensio *io, Os_Funcs &o)
    {
	struct gensio *cio;
	struct sergensio *sio;
	unsigned int i;
	struct gensio_frdata *f;
	struct gensio_cpp_data *d;
	Gensio *g;

	// Set frdata for the gensio and all children.
	for (i = 0; (cio = gensio_get_child(io, i)); i++) {
	    if (gensio_get_frdata(cio))
		break; // It's already been set.
	    sio = gensio_to_sergensio(cio);
	    if (sio) {
		g = new Serial_Gensio(o, NULL);
	    } else {
		g = new Gensio(o, NULL);
	    }
	    g->set_gensio(cio, i == 0);
	}
	f = gensio_get_frdata(io);
	d = gensio_container_of(f, struct gensio_cpp_data, frdata);
	return d->g;
    }

    Gensio *
    gensio_alloc(struct gensio *io, Os_Funcs &o, Event *cb)
    {
	Gensio *g;

	g = gensio_alloc(io, o);
	g->set_event_handler(cb);
	return g;
    }

    Gensio *
    gensio_alloc(std::string str, Os_Funcs &o, Event *cb)
    {
	struct gensio *io;
	int err;
	Gensio *g;

	err = str_to_gensio(str.c_str(), o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	g = gensio_alloc(io, o, cb);
	return g;
    }

    Gensio *
    gensio_alloc(Gensio *child, std::string str,
		 Os_Funcs &o, Event *cb)
    {
	struct gensio *io;
	int err;
	Gensio *g;

	err = str_to_gensio_child(child->get_gensio(), str.c_str(), o,
				  NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	g = gensio_alloc(io, o, cb);
	return g;
    }

    Gensio *
    gensio_alloc(const char *gensiotype, const void *gdata,
		 const char * const args[], Os_Funcs &o,
		 Event *cb)
    {
	struct gensio *io;
	int err;
	Gensio *g;

	err = gensio_terminal_alloc(gensiotype, gdata, args, o,
				    NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	g = gensio_alloc(io, o, cb);
	return g;
    }

    void Gensio::free()
    {
	gensio_free(io);
    }

    static void gensio_cpp_open_done(struct gensio *io, int err,
				     void *user_data)
    {
	if (!user_data)
	    return;
	struct gensio_frdata *f = gensio_get_frdata(io);
	struct gensio_cpp_data *d = gensio_container_of(f,
					      struct gensio_cpp_data, frdata);
	Gensio *g = d->g;
	Gensio_Open_Done *done = static_cast<Gensio_Open_Done *>(user_data);

	try {
	    done->open_done(err);
	} catch (const std::exception &e) {
	    gensio_log(g->get_os_funcs(), GENSIO_LOG_ERR,
		       "Received C++ exception in open done handler: %s",
		       e.what());
	}
    }

    void Gensio::open(Gensio_Open_Done *done)
    {
	int err;

	err = gensio_open(io, gensio_cpp_open_done, done);
	if (err)
	    throw gensio_error(err);
    }

    void Gensio::open_s()
    {
	int err = gensio_open_s(io);

	if (err)
	    throw gensio_error(err);
    }

    void Gensio::open_nochild(Gensio_Open_Done *done)
    {
	int err;

	err = gensio_open_nochild(io, gensio_cpp_open_done, done);
	if (err)
	    throw gensio_error(err);
    }

    void Gensio::open_nochild_s()
    {
	int err = gensio_open_nochild_s(io);
	if (err)
	    throw gensio_error(err);
    }

    gensiods Gensio::write(const void *data, gensiods datalen,
			   const char *const *auxdata)
    {
	gensiods count;
	int err = gensio_write(io, &count, data, datalen, auxdata);
	if (err)
	    throw gensio_error(err);
	return count;
    }

    gensiods Gensio::write(const std::vector<unsigned char> data,
			   const char *const *auxdata)
    {
	return write(data.data(), (gensiods) data.size(), auxdata);
    }

    gensiods Gensio::write(const SimpleUCharVector data,
			   const char *const *auxdata)
    {
	return write(data.data(), (gensiods) data.size(), auxdata);
    }

    gensiods Gensio::write(const struct gensio_sg *sg, gensiods sglen,
			   const char *const *auxdata)
    {
	gensiods count;
	int err = gensio_write_sg(io, &count, sg, sglen, auxdata);
	if (err)
	    throw gensio_error(err);
	return count;
    }

    int Gensio::write_s(gensiods *count, const void *data, gensiods datalen,
			gensio_time *timeout, bool intr)
    {
	int err;

	if (intr)
	    err = gensio_write_s_intr(io, count, data, datalen, timeout);
	else
	    err = gensio_write_s(io, count, data, datalen, timeout);
	if (err == GE_TIMEDOUT || err == GE_INTERRUPTED)
	    return err;
	if (err)
	    throw gensio_error(err);
	return 0;
    }

    int Gensio::write_s(gensiods *count, std::vector<unsigned char> data,
			gensio_time *timeout, bool intr)
    {
	return write_s(count, data.data(), (gensiods) data.size(), timeout, intr);
    }

    int Gensio::write_s(gensiods *count, SimpleUCharVector data,
			gensio_time *timeout, bool intr)
    {
	return write_s(count, data.data(), (gensiods) data.size(), timeout, intr);
    }

    Gensio *Gensio::alloc_channel(const char *const args[], Event *cb)
    {
	struct gensio *nio;
	int err = gensio_alloc_channel(io, args, NULL, NULL, &nio);
	Gensio *g;

	if (err)
	    throw gensio_error(err);
	g = gensio_alloc(nio, go, cb);
	return g;
    }

    static void gensio_cpp_close_done(struct gensio *io, void *user_data)
    {
	if (!user_data)
	    return;
	struct gensio_frdata *f = gensio_get_frdata(io);
	struct gensio_cpp_data *d = gensio_container_of(f,
					      struct gensio_cpp_data, frdata);
	Gensio *g = d->g;
	Gensio_Close_Done *done = static_cast<Gensio_Close_Done *>(user_data);

	try {
	    done->close_done();
	} catch (std::exception &e) {
	    gensio_log(g->get_os_funcs(), GENSIO_LOG_ERR,
		       "Received C++ exception in close done handler: %s",
		       e.what());
	}
    }

    void Gensio::close(Gensio_Close_Done *done)
    {
	int err;

	if (done)
	    err = gensio_close(io, gensio_cpp_close_done, done);
	else
	    err = gensio_close(io, NULL, NULL);
	if (err)
	    throw gensio_error(err);
    }

    void Gensio::close_s()
    {
	int err = gensio_close_s(io);
	if (err)
	    throw gensio_error(err);
    }

    int Gensio::control(int depth, bool get, unsigned int option,
			char *data, gensiods *datalen)
    {
	return gensio_control(io, depth, get, option, data, datalen);
    }

    int Gensio::read_s(std::vector<unsigned char> &rvec,
		       gensio_time *timeout, bool intr)
    {
	int err;
	gensiods len = (gensiods) rvec.capacity(), count = 0;
	unsigned char *buf;

	buf = (unsigned char *) go->zalloc(go, len);
	if (!buf)
	    throw gensio_error(GE_NOMEM);
	if (intr)
	    err = gensio_read_s_intr(io, &count, buf, len, timeout);
	else
	    err = gensio_read_s(io, &count, buf, len, timeout);
	if (err == GE_TIMEDOUT || err== GE_INTERRUPTED) {
	    go->free(go, (void *) buf);
	    return err;
	}
	if (err) {
	    go->free(go, (void *) buf);
	    throw gensio_error(err);
	}
	rvec.assign(buf, buf + count);
	go->free(go, (void *) buf);
	return 0;
    }

    int Gensio::read_s(SimpleUCharVector &data,
		       gensio_time *timeout, bool intr)
    {
	int err;
	gensiods len = data.capacity(), count = 0;

	if (intr)
	    err = gensio_read_s_intr(io, &count, data.data(), len, timeout);
	else
	    err = gensio_read_s(io, &count, data.data(), len, timeout);
	data.resize(count);
	if (err == GE_TIMEDOUT || err== GE_INTERRUPTED)
	    return err;
	if (err)
	    throw gensio_error(err);
	return 0;
    }

    static void sergensio_cpp_done(struct sergensio *sio, int err,
			    unsigned int val, void *cb_data)
    {
	if (!cb_data)
	    return;
	Serial_Op_Done *done = static_cast<Serial_Op_Done *>(cb_data);

	done->serial_op_done(err, val);
    }

    void Serial_Gensio::flush(unsigned int flush)
    {
	int err;

	err = sergensio_flush(sio, flush);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::baud(unsigned int baud, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_baud(sio, baud, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::datasize(unsigned int size, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_datasize(sio, size, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::parity(unsigned int par, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_parity(sio, par, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::stopbits(unsigned int bits, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_stopbits(sio, bits, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::flowcontrol(unsigned int flow, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_flowcontrol(sio, flow, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::iflowcontrol(unsigned int flow,
					 Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_iflowcontrol(sio, flow, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::sbreak(unsigned int sbreak, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_sbreak(sio, sbreak, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::dtr(unsigned int dtr, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_dtr(sio, dtr, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::rts(unsigned int rts, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_rts(sio, rts, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::cts(unsigned int cts, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_cts(sio, cts, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::dcd_dsr(unsigned int dcd_dsr, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_dcd_dsr(sio, dcd_dsr, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::ri(unsigned int ri, Serial_Op_Done *done)
    {
	int err;
	sergensio_done donefunc = sergensio_cpp_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_ri(sio, ri, donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    static void sergensio_cpp_sig_done(struct sergensio *sio, int err,
				       const char *sig, unsigned int len,
				       void *cb_data)
    {
	if (!cb_data)
	    return;
	Serial_Op_Sig_Done *done = static_cast<Serial_Op_Sig_Done *>(cb_data);
	std::vector<unsigned char> sigv(sig, sig + len);

	done->serial_op_sig_done(err, sigv);
    }

    void Serial_Gensio::signature(const std::vector<unsigned char> sig,
				  Serial_Op_Sig_Done *done)
    {
	int err;
	sergensio_done_sig donefunc = sergensio_cpp_sig_done;

	if (!done)
	    donefunc = NULL;
	err = sergensio_signature(sio, (const char *) sig.data(),
				  (gensiods) sig.size(), donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    class Std_Ser_Op_Done: public Serial_Op_Done {
    public:
	Std_Ser_Op_Done(Os_Funcs &o) : waiter(o) { }

	int wait(gensio_time *timeout = NULL, bool intr = false)
	{
	    return waiter.wait(1, timeout, intr);
	}

	int err = 0;
	unsigned int val = 0;

    private:
	void serial_op_done(int err, unsigned int val)
	{
	    this->err = err;
	    this->val = val;
	    waiter.wake();
	}
	Waiter waiter;
    };

    int Serial_Gensio::baud_s(unsigned int *baud, gensio_time *timeout,
			      bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->baud(*baud, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*baud = w.val;
	return 0;
    }

    int Serial_Gensio::datasize_s(unsigned int *size, gensio_time *timeout,
				  bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->datasize(*size, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*size = w.val;
	return 0;
    }

    int Serial_Gensio::parity_s(unsigned int *par, gensio_time *timeout,
				bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->parity(*par, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*par = w.val;
	return 0;
    }

    int Serial_Gensio::stopbits_s(unsigned int *bits, gensio_time *timeout,
				  bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->stopbits(*bits, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*bits = w.val;
	return 0;
    }

    int Serial_Gensio::flowcontrol_s(unsigned int *flow, gensio_time *timeout,
				     bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->flowcontrol(*flow, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*flow = w.val;
	return 0;
    }

    int Serial_Gensio::iflowcontrol_s(unsigned int *flow, gensio_time *timeout,
				      bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->iflowcontrol(*flow, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*flow = w.val;
	return 0;
    }

    int Serial_Gensio::sbreak_s(unsigned int *sbreak, gensio_time *timeout,
				bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->sbreak(*sbreak, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*sbreak = w.val;
	return 0;
    }

    int Serial_Gensio::dtr_s(unsigned int *dtr, gensio_time *timeout,
			     bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->dtr(*dtr, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*dtr = w.val;
	return 0;
    }

    int Serial_Gensio::rts_s(unsigned int *rts, gensio_time *timeout,
			     bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->rts(*rts, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*rts = w.val;
	return 0;
    }

    int Serial_Gensio::cts_s(unsigned int *cts, gensio_time *timeout,
			     bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->cts(*cts, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*cts = w.val;
	return 0;
    }

    int Serial_Gensio::dcd_dsr_s(unsigned int *dcd_dsr, gensio_time *timeout,
				 bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->dcd_dsr(*dcd_dsr, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*dcd_dsr = w.val;
	return 0;
    }

    int Serial_Gensio::ri_s(unsigned int *ri, gensio_time *timeout,
			    bool intr)
    {
	Std_Ser_Op_Done w(this->get_os_funcs());
	int err;

	this->ri(*ri, &w);
	err = w.wait(timeout, intr);
	if (err)
	    return err;
	if (w.err)
	    throw gensio_error(w.err);
	*ri = w.val;
	return 0;
    }

    void Serial_Gensio::modemstate(unsigned int state)
    {
	int err = sergensio_modemstate(sio, state);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::linestate(unsigned int state)
    {
	int err = sergensio_linestate(sio, state);
	if (err)
	    throw gensio_error(err);
    }

    void Serial_Gensio::flow_state(bool state)
    {
	int err = sergensio_flowcontrol_state(sio, state);
	if (err)
	    throw gensio_error(err);
    }

    struct gensio_acc_cpp_data {
	struct gensio_acc_frdata frdata;
	Accepter *a;
    };

    class GENSIOCPP_DLL_PUBLIC Main_Raw_Accepter_Event_Handler:
	public Raw_Accepter_Event_Handler {
    public:
	Main_Raw_Accepter_Event_Handler() { }
	int handle(Accepter *a, int event, void *data) override
	{
	    Accepter_Event *cb = a->get_cb();
	    struct gensio *io;

	    try {
		switch (event) {
		case GENSIO_ACC_EVENT_NEW_CONNECTION: {
		    io = (struct gensio *) data;
		    Gensio *g = gensio_alloc(io, a->get_os_funcs(), NULL);
		    a->raw_event_handler->new_connection(cb, g);
		    break;
		}

		case GENSIO_ACC_EVENT_LOG: {
		    struct gensio_loginfo *l = (struct gensio_loginfo *) data;
		    va_list argcopy;
		    va_copy(argcopy, l->args);
		    size_t len = vsnprintf(NULL, 0, l->str, argcopy);
		    va_end(argcopy);
		    std::string outstr(len + 1, '\0');
		    vsnprintf(&outstr[0], len + 1, l->str, l->args);
		    cb->log(l->level, outstr);
		    break;
		}

		case GENSIO_ACC_EVENT_PRECERT_VERIFY: {
		    io = (struct gensio *) data;
		    Gensio g(io, a->get_os_funcs());
		    return cb->precert_verify(&g);
		}

		case GENSIO_ACC_EVENT_AUTH_BEGIN: {
		    io = (struct gensio *) data;
		    Gensio g(io, a->get_os_funcs());
		    return cb->auth_begin(&g);
		}

		case GENSIO_ACC_EVENT_PASSWORD_VERIFY: {
		    struct gensio_acc_password_verify_data *p =
			(struct gensio_acc_password_verify_data *) data;
		    std::string pwstr((char *) p->password);
		    Gensio g(p->io, a->get_os_funcs());
		    return cb->password_verify(&g, pwstr);
		}

		case GENSIO_ACC_EVENT_REQUEST_PASSWORD: {
		    struct gensio_acc_password_verify_data *p =
			(struct gensio_acc_password_verify_data *) data;
		    std::string pwstr("");
		    int rv;
		    Gensio g(p->io, a->get_os_funcs());

		    rv = cb->request_password(&g, p->password_len, pwstr);
		    if (rv)
			return rv;
		    if (pwstr.size() > p->password_len)
			return GE_TOOBIG;
		    p->password_len = (gensiods) pwstr.size();
		    memcpy(p->password, pwstr.c_str(), p->password_len);
		    return 0;
		}

		case GENSIO_ACC_EVENT_2FA_VERIFY: {
		    struct gensio_acc_password_verify_data *p =
			(struct gensio_acc_password_verify_data *) data;
		    std::vector<unsigned char> val(p->password,
					p->password + p->password_len);
		    Gensio g(p->io, a->get_os_funcs());
		    return cb->verify_2fa(&g, val);
		}

		case GENSIO_ACC_EVENT_REQUEST_2FA: {
		    struct gensio_acc_password_verify_data *p =
			(struct gensio_acc_password_verify_data *) data;
		    int rv;
		    std::vector<unsigned char> val(0);
		    Gensio g(p->io, a->get_os_funcs());
		    Os_Funcs o = a->get_os_funcs();
		    unsigned char *rbuf;

		    rv = cb->request_2fa(&g, val);
		    if (rv)
			return rv;
		    rbuf = (unsigned char *) o->zalloc(o, (gensiods) val.size());
		    if (!rbuf)
			return GE_NOMEM;
		    p->password_len = (gensiods) val.size();
		    memcpy(rbuf, val.data(), p->password_len);
		    *((unsigned char **) p->password) = rbuf;
		    return 0;
		}

		case GENSIO_ACC_EVENT_POSTCERT_VERIFY: {
		    struct gensio_acc_postcert_verify_data *p =
			(struct gensio_acc_postcert_verify_data *) data;
		    Gensio g(p->io, a->get_os_funcs());
		    return cb->postcert_verify(&g, p->err, p->errstr);
		}

		default:
		    return GE_NOTSUP;
		}
	    } catch (std::exception &e) {
		gensio_log(a->get_os_funcs(), GENSIO_LOG_ERR,
		     "Received C++ exception in accepter callback handler: %s",
		     e.what());
		return GE_APPERR;
	    }

	    return 0;
	}

	void new_connection(Accepter_Event *e, Gensio *new_g) override
	{
	    if (e)
		e->new_connection(new_g);
	}

	void freed(Accepter_Event *e) override
	{
	    if (e)
		e->freed();
	}
    };

    static int gensio_acc_cpp_cb(struct gensio_accepter *acc, void *user_data,
				 int event, void *data)
    {
	Accepter *a = static_cast<Accepter *>(user_data);

	return a->raw_event_handler->handle(a, event, data);
    }

    void gensio_acc_cpp_freed(struct gensio_accepter *acc,
			      struct gensio_acc_frdata *frdata)
    {
	struct gensio_acc_cpp_data *d = gensio_container_of(frdata,
						 struct gensio_acc_cpp_data,
						 frdata);
	Accepter_Event *cb = d->a->get_cb();

	d->a->set_event_handler(NULL);

	// See comments in gensio_cpp_freed
	if (d->a->raw_event_handler)
	    d->a->raw_event_handler->freed(cb);
	else if (cb)
	    cb->freed();
	delete d->a;
	delete d;
    }

    void
    Accepter::set_accepter(struct gensio_accepter *acc, bool set_cb)
    {
	struct gensio_acc_cpp_data *d;

	try {
	    d = new struct gensio_acc_cpp_data;
	} catch (...) {
	    delete this;
	    throw;
	}
	this->acc = acc;
	d->a = this;
	d->frdata.freed = gensio_acc_cpp_freed;
	gensio_acc_set_frdata(acc, &d->frdata);
	if (set_cb) {
	    gensio_acc_set_callback(acc, gensio_acc_cpp_cb, this);
	    try {
		this->raw_event_handler = new Main_Raw_Accepter_Event_Handler();
	    } catch (...) {
		delete d;
		delete this;
		throw;
	    }
	}
    }

    Accepter *gensio_acc_alloc(struct gensio_accepter *acc,
			       Os_Funcs &o)
    {
	struct gensio_accepter *cacc;
	unsigned int i;
	struct gensio_acc_frdata *f;
	struct gensio_acc_cpp_data *d;
	Accepter *a;

	// Set frdata for the gensio and all children.
	for (i = 0; (cacc = gensio_acc_get_child(acc, i)); i++) {
	    if (gensio_acc_get_frdata(cacc))
		break; // It's already been set.

	    a = new Accepter(o, NULL);
	    a->set_accepter(cacc, i == 0);
	}
	f = gensio_acc_get_frdata(acc);
	d = gensio_container_of(f, struct gensio_acc_cpp_data, frdata);
	return d->a;
    }

    Accepter *gensio_acc_alloc(std::string str, Os_Funcs &o,
			       Accepter_Event *cb)
    {
	struct gensio_accepter *acc;
	int err;
	Accepter *a;

	err = str_to_gensio_accepter(str.c_str(), o, NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	a = gensio_acc_alloc(acc, o);
	a->set_event_handler(cb);
	gensio_acc_set_callback(acc, gensio_acc_cpp_cb, a);
	return a;
    }

    Accepter *gensio_acc_alloc(Accepter *child, std::string str,
			       Os_Funcs &o,
			       Accepter_Event *cb)
    {
	struct gensio_accepter *acc;
	int err;
	Accepter *a;

	err = str_to_gensio_accepter_child(child->get_accepter(),
					   str.c_str(), o,
					   NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	a = gensio_acc_alloc(acc, o);
	a->set_event_handler(cb);
	gensio_acc_set_callback(acc, gensio_acc_cpp_cb, a);
	return a;
    }

    Accepter *
    gensio_acc_alloc(const char *gensiotype, const void *gdata,
		     const char * const args[], Os_Funcs &o,
		     Accepter_Event *cb)
    {
	struct gensio_accepter *acc;
	int err;
	Accepter *a;

	err = gensio_terminal_acc_alloc(gensiotype, gdata, args,
					o, NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	a = gensio_acc_alloc(acc, o);
	a->set_event_handler(cb);
	gensio_acc_set_callback(acc, gensio_acc_cpp_cb, a);
	return a;
    }

    Accepter *gensio_acc_alloc(const char *gensiotype, Accepter *child,
			       const char * const args[], Os_Funcs &o,
			       Accepter_Event *cb)
    {
	struct gensio_accepter *acc;
	int err;
	Accepter *a;

	err = gensio_filter_acc_alloc(gensiotype, child->get_accepter(), args,
				      o, NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	a = gensio_acc_alloc(acc, o);
	a->set_event_handler(cb);
	gensio_acc_set_callback(acc, gensio_acc_cpp_cb, a);
	return a;
    }

    void Accepter::free()
    {
	gensio_acc_free(acc);
    }

    void Accepter::startup()
    {
	int err = gensio_acc_startup(acc);
	if (err)
	    throw gensio_error(err);
    }

    static void gensio_acc_cpp_shutdown_done(struct gensio_accepter *acc,
					     void *user_data)
    {
	if (!user_data)
	    return;
	struct gensio_acc_frdata *f = gensio_acc_get_frdata(acc);
	struct gensio_acc_cpp_data *d = gensio_container_of(f,
					  struct gensio_acc_cpp_data, frdata);
	Accepter *a = d->a;
	Accepter_Shutdown_Done *done =
	    static_cast<Accepter_Shutdown_Done *>(user_data);

	try {
	    done->shutdown_done();
	} catch (std::exception &e) {
	    gensio_log(a->get_os_funcs(), GENSIO_LOG_ERR,
		       "Received C++ exception in accepter done handler: %s",
		       e.what());
	}
    }

    void Accepter::shutdown(Accepter_Shutdown_Done *done)
    {
	int err;

	if (done)
	    err = gensio_acc_shutdown(acc, gensio_acc_cpp_shutdown_done, done);
	else
	    err = gensio_acc_shutdown(acc, NULL, NULL);;
	if (err)
	    throw gensio_error(err);
    }

    void Accepter::shutdown_s()
    {
	int err = gensio_acc_shutdown_s(acc);
	if (err)
	    throw gensio_error(err);
    }

    static void gensio_acc_cpp_enable_done(struct gensio_accepter *acc,
					   void *user_data)
    {
	if (!user_data)
	    return;
	struct gensio_acc_frdata *f = gensio_acc_get_frdata(acc);
	struct gensio_acc_cpp_data *d = gensio_container_of(f,
					  struct gensio_acc_cpp_data, frdata);
	Accepter *a = d->a;
	Accepter_Enable_Done *done =
	    static_cast<Accepter_Enable_Done *>(user_data);

	try {
	    done->enable_done();
	} catch (std::exception &e) {
	    gensio_log(a->get_os_funcs(), GENSIO_LOG_ERR,
		       "Received C++ exception in accepter done handler: %s",
		       e.what());
	}
    }

    void Accepter::set_callback_enable(bool enabled, Accepter_Enable_Done *done)
    {
	int err;

	if (done)
	    err = gensio_acc_set_accept_callback_enable_cb(acc,
						enabled,
						gensio_acc_cpp_enable_done,
						done);
	else
	    err = gensio_acc_set_accept_callback_enable_cb(acc, enabled,
							   NULL, NULL);
	if (err)
	    throw gensio_error(err);
    }

    void Accepter::set_callback_enable_s(bool enabled)
    {
	int err = gensio_acc_set_accept_callback_enable_s(acc, enabled);
	if (err)
	    throw gensio_error(err);
    }

    int Accepter::control(int depth, bool get, unsigned int option,
			  char *data, gensiods *datalen)
    {
	return gensio_acc_control(acc, depth, get, option, data, datalen);
    }

    int Accepter::accept_s(Gensio **g, gensio_time *timeout, bool intr)
    {
	struct gensio *io;
	int err;

	if (intr)
	    err = gensio_acc_accept_s_intr(acc, timeout, &io);
	else
	    err = gensio_acc_accept_s(acc, timeout, &io);
	if (err == GE_TIMEDOUT || err == GE_INTERRUPTED)
	    return err;
	if (err)
	    throw gensio_error(err);
	*g = gensio_alloc(io, go, NULL);
	return 0;
    }

    Gensio *Accepter::str_to_gensio(std::string str, Event *cb)
    {
	struct gensio *io;
	Gensio *g;
	int err = gensio_acc_str_to_gensio(acc, str.c_str(), NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	g = gensio_alloc(io, go, cb);
	return g;
    }

    std::string Accepter::get_port() const
    {
	char portbuf[100];
	gensiods len = sizeof(portbuf);

	portbuf[0] = '0';
	portbuf[1] = '\0';
	int err = gensio_acc_control(acc, GENSIO_CONTROL_DEPTH_FIRST,
				     true, GENSIO_ACC_CONTROL_LPORT,
				     portbuf, &len);
	if (err)
	    throw gensio_error(err);
	return std::string(portbuf, len);
    }
}
