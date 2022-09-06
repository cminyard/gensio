//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

#include <string>
#include <gensio/gensioosh>

namespace gensios {
#include <gensio/gensio_os_funcs.h>
#include <gensio/gensio_os_funcs_public.h>
#include <gensio/gensio_osops.h>
#include <gensio/netif.h>

    std::string
    err_to_string(int err) {
	return std::string(gensio_err_to_str(err));
    }

    std::string
    log_level_to_str(enum gensio_log_levels level) {
	return std::string(gensio_log_level_to_str(level));
    }

    void set_log_mask(int mask) { gensio_set_log_mask(mask); }

    int get_log_mask() { return gensio_get_log_mask(); }

    void
    gensio_cpp_vlog_handler(struct gensio_os_funcs *io,
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

    void
    Os_Funcs::init(struct gensio_os_funcs *o, Os_Funcs_Log_Handler *ilogger)
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

    void
    Os_Funcs::proc_setup() {
	int err;

	err = gensio_os_proc_setup(osf, &proc_data);
	if (err)
	    throw gensio_error(err);
    }

    void
    Os_Funcs::refcount_from(const Os_Funcs *o)
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

    std::string
    do_to_string(struct gensio_addr *addr, bool all)
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

    void
    Waiter::wake()
    {
	gensio_os_funcs_wake(o, waiter);
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
}
