//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

#include <map>
#include <gensio/gensio_classes>
#include <string.h>
#include <stdarg.h>

namespace gensio {
#include <gensio/gensio_builtins.h>
#include <gensio/gensio_osops.h>

    void gensio_cpp_vlog_handler(struct gensio_os_funcs *io,
				 enum gensio_log_levels level,
				 const char *log, va_list args)
    {
	class Os_Funcs *o =
	    static_cast<Os_Funcs *>(gensio_os_funcs_get_data(io));
	Os_Funcs_Log_Handler *logger = o->get_log_handler();

	if (logger) {
	    va_list argcopy;
	    va_copy(argcopy, args);
	    size_t len = vsnprintf(NULL, 0, log, argcopy);
	    va_end(argcopy);
	    std::string outstr(len + 1, '\0');
	    vsnprintf(&outstr[0], len + 1, log, args);
	    logger->log(level, outstr);
	}
    }

    void Os_Funcs::init(struct gensio_os_funcs *o,
			Os_Funcs_Log_Handler *ilogger)
    {
	logger = ilogger;
	refcnt = new std::atomic<unsigned int>(1);
	osf = o;
	gensio_os_funcs_set_vlog(osf, gensio_cpp_vlog_handler);
	gensio_os_funcs_set_data(osf, this);
    }

    Os_Funcs::Os_Funcs(int wait_sig, Os_Funcs_Log_Handler *logger)
    {
	int err;
	struct gensio_os_funcs *o;

	err = gensio_default_os_hnd(wait_sig, &o);
	if (err)
	    throw gensio_error(err);
	this->init(o, logger);
    }

    void Os_Funcs::proc_setup() {
	int err;

	err = gensio_os_proc_setup(osf, &proc_data);
	if (err)
	    throw gensio_error(err);
    }

    void Os_Funcs::refcount_from(const Os_Funcs *o)
    {
	std::atomic<unsigned int> *old_refcnt = refcnt;
	struct gensio_os_funcs *old_osf = osf;

	refcnt = o->refcnt;
	osf = o->osf;
	logger = o->logger;
	++*refcnt;
	if (old_refcnt) {
	    if (old_refcnt->fetch_sub(1) == 1) {
		gensio_os_funcs_free(old_osf);
		delete old_refcnt;
	    }
	}
    }

    Os_Funcs& Os_Funcs::operator=(const Os_Funcs &o)
    {
	refcount_from(&o);
	return *this;
    }

    Os_Funcs::Os_Funcs(const Os_Funcs &o) {
	refcount_from(&o);
    }

    Os_Funcs::~Os_Funcs()
    {
	if (proc_data)
	    gensio_os_proc_cleanup(proc_data);
	if (refcnt->fetch_sub(1) == 1) {
	    gensio_os_funcs_free(osf);
	    if (logger)
		delete logger;
	    delete refcnt;
	}
    }

    Addr::Addr(Os_Funcs &o, std::string str, bool listen, int *protocol,
	       int *argc, const char ***args)
    {
	int err;

	err = gensio_scan_network_port(o, str.c_str(), listen, &gaddr,
				       protocol, &is_port_set,
				       argc, args);
	if (err)
	    throw gensio_error(err);
    }

    Addr::Addr(Os_Funcs &o, std::string str, bool listen, int protocol)
    {
	int err;

	is_port_set = true;
	err = gensio_os_scan_netaddr(o, str.c_str(), listen,
				     protocol, &gaddr);
	if (err)
	    throw gensio_error(err);
    }

    Addr::Addr(Os_Funcs &o, int nettype, const void *iaddr, gensiods len,
	       unsigned int port)
    {
	int err;

	this->is_port_set = port != 0;
	err = gensio_addr_create(o, nettype, iaddr, len, port, &gaddr);
	if (err)
	    throw gensio_error(err);
    }

    Addr::~Addr()
    {
	gensio_addr_free(gaddr);
    }

    std::string do_to_string(struct gensio_addr *addr, bool all)
    {
	int err;
	gensiods len = 0;
	char *buf = NULL;
	std::string s;

	if (all)
	    err = gensio_addr_to_str_all(addr, buf, &len, 0);
	else
	    err = gensio_addr_to_str(addr, buf, &len, 0);
	if (err)
	    throw gensio_error(err);
	buf = new char[len + 1];
	if (all)
	    err = gensio_addr_to_str_all(addr, buf, NULL, len);
	else
	    err = gensio_addr_to_str(addr, buf, NULL, len);
	if (err) {
	    delete[] buf;
	    throw gensio_error(err);
	}

	try {
	    s = std::string(buf);
	} catch (...) {
	    delete[] buf;
	    throw;
	}
	delete[] buf;
	return s;
    }

    std::string Addr::to_string() const
    {
	return do_to_string(gaddr, false);
    }

    std::string Addr::to_string_all() const
    {
	return do_to_string(gaddr, true);
    }

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
		    g2 = gensio_alloc(io, g->get_os_funcs(), NULL);
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
    alloc_tcp_class(Os_Funcs &o,
		    struct gensio *io)
    {
	return new Tcp(o);
    }

    Gensio *
    alloc_udp_class(Os_Funcs &o,
		    struct gensio *io)
    {
	return new Udp(o);
    }

    Gensio *
    alloc_unix_class(Os_Funcs &o,
		     struct gensio *io)
    {
	return new Unix(o);
    }

    Gensio *
    alloc_sctp_class(Os_Funcs &o,
		     struct gensio *io)
    {
	return new Sctp(o);
    }

    Gensio *
    alloc_stdio_class(Os_Funcs &o,
		      struct gensio *io)
    {
	return new Stdio(o);
    }

    Gensio *
    alloc_pty_class(Os_Funcs &o,
		    struct gensio *io)
    {
	return new Pty(o);
    }

    Gensio *
    alloc_echo_class(Os_Funcs &o,
		     struct gensio *io)
    {
	return new Echo(o);
    }

    Gensio *
    alloc_file_class(Os_Funcs &o,
		     struct gensio *io)
    {
	return new File(o);
    }

    Gensio *
    alloc_mdns_class(Os_Funcs &o,
		     struct gensio *io)
    {
	return new Mdns(o);
    }

    Gensio *
    alloc_serialdev_class(Os_Funcs &o,
			  struct gensio *io)
    {
	return new Serialdev(o);
    }

    Gensio *
    alloc_ipmisol_class(Os_Funcs &o,
			struct gensio *io)
    {
	return new Ipmisol(o);
    }

    Gensio *
    alloc_ssl_class(Os_Funcs &o,
		    struct gensio *io)
    {
	return new Ssl(o);
    }

    Gensio *
    alloc_certauth_class(Os_Funcs &o,
			 struct gensio *io)
    {
	return new Certauth(o);
    }

    Gensio *
    alloc_telnet_class(Os_Funcs &o,
		       struct gensio *io)
    {
	if (gensio_to_sergensio(io))
	    return new Serial_Telnet(o);
	else
	    return new Telnet(o);
    }

    Gensio *
    alloc_msgdelim_class(Os_Funcs &o,
			 struct gensio *io)
    {
	return new Msgdelim(o);
    }

    Gensio *
    alloc_relpkt_class(Os_Funcs &o,
		       struct gensio *io)
    {
	return new Relpkt(o);
    }

    Gensio *
    alloc_trace_class(Os_Funcs &o,
		      struct gensio *io)
    {
	return new Trace(o);
    }

    Gensio *
    alloc_perf_class(Os_Funcs &o,
		     struct gensio *io)
    {
	return new Perf(o);
    }

    Gensio *
    alloc_mux_class(Os_Funcs &o,
		    struct gensio *io)
    {
	return new Mux(o);
    }

    Gensio *
    alloc_kiss_class(Os_Funcs &o,
		     struct gensio *io)
    {
	return new Kiss(o);
    }

    Gensio *
    alloc_ax25_class(Os_Funcs &o,
		     struct gensio *io)
    {
	return new AX25(o);
    }

    typedef Gensio *(*gensio_allocator)(Os_Funcs &o,
					struct gensio *io);

    static std::map<std::string, gensio_allocator> classes = {
	{ "tcp", alloc_tcp_class },
	{ "udp", alloc_udp_class },
	{ "unix", alloc_unix_class },
	{ "sctp", alloc_sctp_class },
	{ "pty", alloc_pty_class },
	{ "echo", alloc_echo_class },
	{ "file", alloc_file_class },
	{ "mdns", alloc_mdns_class },
	{ "stdio", alloc_stdio_class },
	{ "serialdev", alloc_serialdev_class },
	{ "ipmisol", alloc_ipmisol_class },
	{ "ssl", alloc_ssl_class },
	{ "mux", alloc_mux_class },
	{ "certauth", alloc_certauth_class },
	{ "telnet", alloc_telnet_class },
	{ "msgdelim", alloc_msgdelim_class },
	{ "relpkt", alloc_relpkt_class },
	{ "trace", alloc_trace_class },
	{ "perf", alloc_perf_class },
	{ "kiss", alloc_kiss_class },
	{ "ax25", alloc_ax25_class },
    };

    void gensio_add_class(const char *name,
			  Gensio *(*allocator)(Os_Funcs &o,
					       struct gensio *io))
    {
	classes[name] = allocator;
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
	    const char *type = gensio_get_type(cio, 0);
	    auto iter = classes.find(type);

	    g = NULL;
	    if (iter != classes.end()) {
		g = iter->second(o, cio);
	    }

	    // If we don't find an assigned class for the gensio, just
	    // use the base classes.  FIXME - Should this go away?
	    if (!g) {
		sio = gensio_to_sergensio(cio);
		if (sio) {
		    g = new Serial_Gensio(o, NULL);
		} else {
		    g = new Gensio(o, NULL);
		}
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
	go->free(go, (void *) buf);
	if (err == GE_TIMEDOUT || err== GE_INTERRUPTED)
	    return err;
	if (err)
	    throw gensio_error(err);
	rvec.assign(buf, buf + count);
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

    Tcp::Tcp(const Addr &addr, const char * const args[],
	     Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = tcp_gensio_alloc(addr, args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Udp::Udp(const Addr &addr, const char * const args[],
	     Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = udp_gensio_alloc(addr, args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Unix::Unix(const Addr &addr, const char * const args[],
	       Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = unix_gensio_alloc(addr, args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Sctp::Sctp(const Addr &addr, const char * const args[],
	       Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = sctp_gensio_alloc(addr, args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Stdio::Stdio(const char *const argv[], const char * const args[],
		 Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = stdio_gensio_alloc(argv, args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Pty::Pty(const char *const argv[], const char * const args[],
	     Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = pty_gensio_alloc(argv, args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Echo::Echo(const char * const args[],
	       Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = echo_gensio_alloc(args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    File::File(const char * const args[],
	       Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = file_gensio_alloc(args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Mdns::Mdns(const char *str, const char * const args[],
	       Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = mdns_gensio_alloc(str, args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Ssl::Ssl(Gensio *child, const char * const args[],
	     Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = ssl_gensio_alloc(child->get_gensio(), args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Mux::Mux(Gensio *child, const char * const args[],
	     Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = mux_gensio_alloc(child->get_gensio(), args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Certauth::Certauth(Gensio *child, const char * const args[],
		       Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = certauth_gensio_alloc(child->get_gensio(), args, o,
				    NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Telnet::Telnet(Gensio *child, const char * const args[],
		   Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = telnet_gensio_alloc(child->get_gensio(), args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Msgdelim::Msgdelim(Gensio *child, const char * const args[],
		       Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = msgdelim_gensio_alloc(child->get_gensio(), args, o,
				    NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Relpkt::Relpkt(Gensio *child, const char * const args[],
		   Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = relpkt_gensio_alloc(child->get_gensio(), args, o,
				  NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Trace::Trace(Gensio *child, const char * const args[],
		 Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = trace_gensio_alloc(child->get_gensio(), args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Perf::Perf(Gensio *child, const char * const args[],
	       Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = perf_gensio_alloc(child->get_gensio(), args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Kiss::Kiss(Gensio *child, const char * const args[],
	       Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = kiss_gensio_alloc(child->get_gensio(), args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    AX25::AX25(Gensio *child, const char * const args[],
	       Os_Funcs &o, Event *cb)
	: Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = ax25_gensio_alloc(child->get_gensio(), args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    static void sergensio_cpp_done(struct sergensio *sio, int err,
			    unsigned int val, void *cb_data)
    {
	if (!cb_data)
	    return;
	struct gensio *io = sergensio_to_gensio(sio);
	struct gensio_frdata *f = gensio_get_frdata(io);
	struct gensio_cpp_data *d = gensio_container_of(f,
					      struct gensio_cpp_data, frdata);
	Serial_Gensio *sg = (Serial_Gensio *) d->g;
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
	struct gensio *io = sergensio_to_gensio(sio);
	struct gensio_frdata *f = gensio_get_frdata(io);
	struct gensio_cpp_data *d = gensio_container_of(f,
					      struct gensio_cpp_data, frdata);
	Serial_Gensio *sg = (Serial_Gensio *) d->g;
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
	err = sergensio_signature(sio, (const char *) sig.data(), (gensiods) sig.size(),
				  donefunc, done);
	if (err)
	    throw gensio_error(err);
    }

    Waiter::Waiter(Os_Funcs &io) : o(io)
    {
	waiter = gensio_os_funcs_alloc_waiter(o);
	if (!waiter)
	    throw std::bad_alloc();
    }

    Waiter::~Waiter()
    {
	gensio_os_funcs_free_waiter(o, waiter);
    }

    void Waiter:: wake()
    {
	gensio_os_funcs_wake(o, waiter);
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

    Serialdev::Serialdev(const char *devname, const char * const args[],
			 Os_Funcs &o, Event *cb)
	: Serial_Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = serialdev_gensio_alloc(devname, args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Serial_Telnet::Serial_Telnet(Gensio *child, const char * const args[],
				 Os_Funcs &o, Event *cb)
	: Serial_Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = telnet_gensio_alloc(child->get_gensio(), args, o,
				  NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
    }

    Ipmisol::Ipmisol(const char *devname, const char * const args[],
		     Os_Funcs &o, Event *cb)
	: Serial_Gensio(o, cb)
    {
	struct gensio *io;
	int err;

	err = ipmisol_gensio_alloc(devname, args, o, NULL, NULL, &io);
	if (err)
	    throw gensio_error(err);
	this->set_gensio(io, true);
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

    Accepter *
    alloc_tcp_accepter_class(Os_Funcs &o,
			     struct gensio_accepter *acc)
    {
	return new Tcp_Accepter(o);
    }

    Accepter *
    alloc_udp_accepter_class(Os_Funcs &o,
			     struct gensio_accepter *acc)
    {
	return new Udp_Accepter(o);
    }

    Accepter *
    alloc_unix_accepter_class(Os_Funcs &o,
			      struct gensio_accepter *acc)
    {
	return new Unix_Accepter(o);
    }

    Accepter *
    alloc_sctp_accepter_class(Os_Funcs &o,
			      struct gensio_accepter *acc)
    {
	return new Sctp_Accepter(o);
    }

    Accepter *
    alloc_stdio_accepter_class(Os_Funcs &o,
			       struct gensio_accepter *acc)
    {
	return new Stdio_Accepter(o);
    }

    Accepter *
    alloc_dummy_accepter_class(Os_Funcs &o,
			       struct gensio_accepter *acc)
    {
	return new Dummy_Accepter(o);
    }

    Accepter *
    alloc_conacc_accepter_class(Os_Funcs &o,
				struct gensio_accepter *acc)
    {
	return new Conacc_Accepter(o);
    }

    Accepter *
    alloc_ssl_accepter_class(Os_Funcs &o,
			     struct gensio_accepter *acc)
    {
	return new Ssl_Accepter(o);
    }

    Accepter *
    alloc_mux_accepter_class(Os_Funcs &o,
			     struct gensio_accepter *acc)
    {
	return new Mux_Accepter(o);
    }

    Accepter *
    alloc_certauth_accepter_class(Os_Funcs &o,
				  struct gensio_accepter *acc)
    {
	return new Certauth_Accepter(o);
    }

    Accepter *
    alloc_telnet_accepter_class(Os_Funcs &o,
				struct gensio_accepter *acc)
    {
	return new Telnet_Accepter(o);
    }

    Accepter *
    alloc_msgdelim_accepter_class(Os_Funcs &o,
				  struct gensio_accepter *acc)
    {
	return new Msgdelim_Accepter(o);
    }

    Accepter *
    alloc_relpkt_accepter_class(Os_Funcs &o,
				struct gensio_accepter *acc)
    {
	return new Relpkt_Accepter(o);
    }

    Accepter *
    alloc_trace_accepter_class(Os_Funcs &o,
			       struct gensio_accepter *acc)
    {
	return new Trace_Accepter(o);
    }

    Accepter *
    alloc_perf_accepter_class(Os_Funcs &o,
			      struct gensio_accepter *acc)
    {
	return new Perf_Accepter(o);
    }

    Accepter *
    alloc_kiss_accepter_class(Os_Funcs &o,
			      struct gensio_accepter *acc)
    {
	return new Kiss_Accepter(o);
    }

    Accepter *
    alloc_ax25_accepter_class(Os_Funcs &o,
			      struct gensio_accepter *acc)
    {
	return new AX25_Accepter(o);
    }

    typedef Accepter *(*gensio_acc_allocator)(Os_Funcs &o,
					      struct gensio_accepter *acc);

    static std::map<std::string, gensio_acc_allocator> acc_classes = {
	{ "tcp", alloc_tcp_accepter_class },
	{ "udp", alloc_udp_accepter_class },
	{ "unix", alloc_unix_accepter_class },
	{ "sctp", alloc_sctp_accepter_class },
	{ "stdio", alloc_stdio_accepter_class },
	{ "dummy", alloc_dummy_accepter_class },
	{ "conacc", alloc_conacc_accepter_class },
	{ "ssl", alloc_ssl_accepter_class },
	{ "mux", alloc_mux_accepter_class },
	{ "certauth", alloc_certauth_accepter_class },
	{ "telnet", alloc_telnet_accepter_class },
	{ "msgdelim", alloc_msgdelim_accepter_class },
	{ "relpkt", alloc_relpkt_accepter_class },
	{ "trace", alloc_trace_accepter_class },
	{ "perf", alloc_perf_accepter_class },
	{ "kiss", alloc_kiss_accepter_class },
	{ "ax25", alloc_ax25_accepter_class },
    };

    void gensio_add_accepter_class(
			  const char *name,
			  Accepter *(*allocator)(Os_Funcs &o,
						 struct gensio_accepter *a))
    {
	acc_classes[name] = allocator;
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
	    const char *type = gensio_acc_get_type(cacc, 0);
	    auto iter = acc_classes.find(type);

	    a = NULL;
	    if (iter != acc_classes.end()) {
		a = iter->second(o, cacc);
	    }

	    // Fall back to the general class if the subclass wasn't
	    // registered.
	    if (!a) {
		a = new Accepter(o, NULL);
	    }

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

    Tcp_Accepter::Tcp_Accepter(const Addr &addr,
			       const char * const args[],
			       Os_Funcs &o, Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = tcp_gensio_accepter_alloc(addr, args, o, NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Udp_Accepter::Udp_Accepter(const Addr &addr,
			       const char * const args[],
			       Os_Funcs &o, Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = udp_gensio_accepter_alloc(addr, args, o, NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Unix_Accepter::Unix_Accepter(const Addr &addr,
				 const char * const args[],
				 Os_Funcs &o, Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = unix_gensio_accepter_alloc(addr, args, o, NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Sctp_Accepter::Sctp_Accepter(const Addr &addr,
				 const char * const args[],
				 Os_Funcs &o, Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = sctp_gensio_accepter_alloc(addr, args, o, NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Stdio_Accepter::Stdio_Accepter(const char * const args[],
				   Os_Funcs &o,
				   Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = stdio_gensio_accepter_alloc(args, o, NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Dummy_Accepter::Dummy_Accepter(const char * const args[],
				   Os_Funcs &o,
				   Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = dummy_gensio_accepter_alloc(args, o, NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Conacc_Accepter::Conacc_Accepter(const char *str, const char * const args[],
				     Os_Funcs &o,
				     Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = conacc_gensio_accepter_alloc(str, args, o, NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Ssl_Accepter::Ssl_Accepter(Accepter *child,
			       const char * const args[],
			       Os_Funcs &o, Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = ssl_gensio_accepter_alloc(child->get_accepter(), args, o,
					NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Mux_Accepter::Mux_Accepter(Accepter *child,
			       const char * const args[],
			       Os_Funcs &o, Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = mux_gensio_accepter_alloc(child->get_accepter(), args, o,
					NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Certauth_Accepter::Certauth_Accepter(Accepter *child,
					 const char * const args[],
					 Os_Funcs &o,
					 Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = certauth_gensio_accepter_alloc(child->get_accepter(), args, o,
					     NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Telnet_Accepter::Telnet_Accepter(Accepter *child,
				     const char * const args[],
				     Os_Funcs &o,
				     Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = telnet_gensio_accepter_alloc(child->get_accepter(), args, o,
					   NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Msgdelim_Accepter::Msgdelim_Accepter(Accepter *child,
					 const char * const args[],
					 Os_Funcs &o,
					 Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = msgdelim_gensio_accepter_alloc(child->get_accepter(), args, o,
					     NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Relpkt_Accepter::Relpkt_Accepter(Accepter *child,
				     const char * const args[],
				     Os_Funcs &o,
				     Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = relpkt_gensio_accepter_alloc(child->get_accepter(), args, o,
					   NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Trace_Accepter::Trace_Accepter(Accepter *child,
				   const char * const args[],
				   Os_Funcs &o,
				   Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = trace_gensio_accepter_alloc(child->get_accepter(), args, o,
					  NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Perf_Accepter::Perf_Accepter(Accepter *child,
				 const char * const args[],
				 Os_Funcs &o,
				 Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = perf_gensio_accepter_alloc(child->get_accepter(), args, o,
					 NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    AX25_Accepter::AX25_Accepter(Accepter *child,
				 const char * const args[],
				 Os_Funcs &o,
				 Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = ax25_gensio_accepter_alloc(child->get_accepter(), args, o,
					 NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    Kiss_Accepter::Kiss_Accepter(Accepter *child,
				 const char * const args[],
				 Os_Funcs &o,
				 Accepter_Event *cb)
	: Accepter(o, cb)
    {
	struct gensio_accepter *acc;
	int err;

	err = kiss_gensio_accepter_alloc(child->get_accepter(), args, o,
					 NULL, NULL, &acc);
	if (err)
	    throw gensio_error(err);
	this->set_accepter(acc, true);
    }

    int
    Waiter::wait(unsigned int count, gensio_time *timeout, bool intr) {
	int rv;

	if (intr)
	    rv = gensio_os_funcs_wait_intr_sigmask(o, waiter, count, timeout,
						   o.get_proc_data());
	else
	    rv = gensio_os_funcs_wait(o, waiter, count, timeout);

	if (rv == GE_TIMEDOUT || rv == GE_INTERRUPTED)
	    return rv;
	if (rv)
	    throw gensio_error(rv);
	return 0;
    }

    MDNS::MDNS(Os_Funcs &o): go(o)
    {
	int rv;

	rv = gensio_alloc_mdns(o, &this->m);
	if (rv)
	    throw gensio_error(rv);
    }

    void mdns_free_done(struct gensio_mdns *m, void *user_data)
    {
	if (!user_data)
	    return;
	MDNS_Free_Done *done = static_cast<MDNS_Free_Done *>(user_data);
	MDNS *mdns = done->m;

	try {
	    done->mdns_free_done();
	} catch (std::exception &e) {
	    gensio_log(done->m->get_os_funcs(), GENSIO_LOG_ERR,
		       "Received C++ exception in mdns open done handler: %s",
		       e.what());
	}
	delete mdns;
    }

    void MDNS::free(MDNS_Free_Done *done)
    {
	int rv;

	if (done) {
	    done->m = this;
	    rv = gensio_free_mdns(this->m, mdns_free_done, done);
	} else {
	    rv = gensio_free_mdns(this->m, NULL, NULL);
	}
	if (rv)
	    throw gensio_error(rv);
    }

    MDNS_Service *MDNS::add_service(int interfacenum, int ipdomain,
				    const char *name, const char *type,
				    const char *domain, const char *host,
				    int port, const char * const *txt)
    {
	return new MDNS_Service(this, interfacenum, ipdomain, name, type,
				domain, host, port, txt);
    }

    MDNS_Watch *MDNS::add_watch(int interfacenum, int ipdomain,
				const char *name, const char *type,
				const char *domain, const char *host,
				MDNS_Watch_Event *event,
				Raw_MDNS_Event_Handler *evh)
    {
	return new MDNS_Watch(this, interfacenum, ipdomain, name, type,
			      domain, host, event, evh);
    }

    MDNS_Service::MDNS_Service(MDNS *m, int interfacenum, int ipdomain,
			       const char *name, const char *type,
			       const char *domain, const char *host,
			       int port, const char * const *txt)
    {
	int rv;

	rv = gensio_mdns_add_service(m->m, interfacenum, ipdomain, name, type,
				     domain, host, port, txt, &this->s);
	if (rv)
	    throw gensio_error(rv);
    }

    MDNS_Service::~MDNS_Service()
    {
	/* FIXME - no return code handling from this, C++ gives an error. */
	gensio_mdns_remove_service(this->s);
    }

    class GENSIOCPP_DLL_PUBLIC Main_Raw_MDNS_Event_Handler:
	public Raw_MDNS_Event_Handler {
    public:
	Main_Raw_MDNS_Event_Handler(Os_Funcs io): o(io) { }

	Os_Funcs o;

	void handle(MDNS_Watch_Event *event,
		    enum gensio_mdns_data_state state,
		    int interfacenum, int ipdomain,
		    const char *name, const char *type,
		    const char *domain, const char *host,
		    const struct gensio_addr *addr,
		    const char * const *txt) override
	{
	    struct gensio_addr *naddr = NULL;

	    if (addr) {
		naddr = gensio_addr_dup(addr);
		if (!naddr) {
		    gensio_log(o, GENSIO_LOG_ERR,
			       "Memory allocation failure in mdns watch event");
		    return;
		}
	    }

	    try {
		if (naddr) {
		    Addr a(naddr);

		    event->event(state, interfacenum, ipdomain, name, type,
				 domain, host, &a, txt);
		} else {
		    event->event(state, interfacenum, ipdomain, name, type,
				 domain, host, NULL, txt);
		}
	    } catch (std::exception &e) {
		gensio_log(o, GENSIO_LOG_ERR,
		      "Received C++ exception in mdns watch event handler: %s",
		      e.what());
	    }
	}
    };

    void mdns_watch_event(struct gensio_mdns_watch *w,
			  enum gensio_mdns_data_state state,
			  int interfacenum, int ipdomain,
			  const char *name, const char *type,
			  const char *domain, const char *host,
			  const struct gensio_addr *addr,
			  const char * const *txt, void *userdata)
    {
	MDNS_Watch_Event *event = static_cast<MDNS_Watch_Event *>(userdata);

	event->w->raw_event_handler->handle(event, state,
					    interfacenum, ipdomain,
					    name, type, domain, host,
					    addr, txt);
    }

    MDNS_Watch::MDNS_Watch(MDNS *m, int interfacenum, int ipdomain,
			   const char *name, const char *type,
			   const char *domain, const char *host,
			   MDNS_Watch_Event *event,
			   Raw_MDNS_Event_Handler *raw_event_handler)
    {
	int rv;

	this->m = m;
	this->event = event;
	event->w = this;
	this->raw_event_handler = new Main_Raw_MDNS_Event_Handler(m->go);
	if (raw_event_handler) {
	    raw_event_handler->set_parent(this->raw_event_handler);
	    this->raw_event_handler = raw_event_handler;
	}
	rv = gensio_mdns_add_watch(m->m, interfacenum, ipdomain, name, type,
				   domain, host, mdns_watch_event,
				   event, &this->w);
	if (rv) {
	    delete this->raw_event_handler;
	    throw gensio_error(rv);
	}
    }

    void mdns_watch_free_done(struct gensio_mdns_watch *w, void *user_data)
    {
	if (!user_data)
	    return;
	MDNS_Watch_Free_Done *done =
	    static_cast<MDNS_Watch_Free_Done *>(user_data);
	MDNS_Watch *watch = done->w;

	try {
	    done->mdns_watch_free_done();
	} catch (std::exception &e) {
	    gensio_log(done->w->get_os_funcs(), GENSIO_LOG_ERR,
		       "Received C++ exception in mdns watch done handler: %s",
		       e.what());
	}
	delete watch;
    }

    void MDNS_Watch::free(MDNS_Watch_Free_Done *done)
    {
	if (done) {
	    done->w = this;
	    gensio_mdns_remove_watch(this->w, mdns_watch_free_done, done);
	} else {
	    gensio_mdns_remove_watch(this->w, NULL, NULL);
	}
    }
}
