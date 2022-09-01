//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

#include <gensio/gensio>
#include <gensio/gensiomdns>

namespace gensios {
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

    class GENSIOMDNSCPP_DLL_PUBLIC Main_Raw_MDNS_Event_Handler:
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
