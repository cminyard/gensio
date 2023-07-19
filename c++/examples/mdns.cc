//
// Copyright 2021 Corey Minyard
//
// SPDX-License-Identifier: Apache-2.0

// This does some basic MDNS operations.

#include <iostream>
#include <string>
#include <cstring>
#include <gensio/gensio>
#include <gensio/gensiomdns>

using namespace std;
using namespace gensios;

class Watch_Event: public MDNS_Watch_Event {
public:
    Watch_Event(Waiter *w) { waiter = w; }

private:
    void event(enum gensio_mdns_data_state state,
	       int interfacenum, int ipdomain,
	       const char *name, const char *type,
	       const char *domain, const char *host,
	       const Addr *addr, const char * const *txt) override
    {
	if (state == GENSIO_MDNS_ALL_FOR_NOW)
	    waiter->wake();
	if (state != GENSIO_MDNS_NEW_DATA)
	    return;
	cout << "Got MDNS interface " << interfacenum << " ipdomain " << ipdomain
	     << endl;
	cout << " name:" << name << endl;
	cout << " type:" << type << endl;
	cout << " domain:" << domain << endl;
	cout << " host:" << host << endl;
	cout << " addr:" << addr->to_string() << endl;
	if (txt) {
	    cout << " txt:" << endl;
	    for (unsigned int i = 0; txt[i]; i++)
		cout << "  " << txt[i] << endl;
	}
    }

    Waiter *waiter;
};

class Watch_Done: public MDNS_Watch_Free_Done {
public:
    Watch_Done(Waiter *w) { waiter = w; }

private:
    void mdns_watch_free_done()
    {
	waiter->wake();
    }
    Waiter *waiter;
};

class Service_Event: public MDNS_Service_Event {
public:
    Service_Event(Waiter *w) { waiter = w; }

private:
    void event(enum gensio_mdns_service_event ev,
	       const char *info) override
    {
	if (ev == GENSIO_MDNS_SERVICE_REMOVED) {
	    cout << "MDNS service removed" << endl;
	    waiter->wake();
	    return;
	}

	if (ev == GENSIO_MDNS_SERVICE_READY) {
	    cout << "MDNS service ready with name " << info << endl;
	} else if (ev == GENSIO_MDNS_SERVICE_READY) {
	    cout << "MDNS service ready with new name " << info << endl;
	} else if (ev == GENSIO_MDNS_SERVICE_ERROR) {
	    cout << "MDNS service error: " << info << endl;
	}
    }

    Waiter *waiter;
};

class Done: public MDNS_Free_Done {
public:
    Done(Waiter *w) { waiter = w; }

private:
    void mdns_free_done()
    {
	waiter->wake();
    }
    Waiter *waiter;
};

// Internal gensio errors come in through this mechanism.
class MDNS_Logger: public Os_Funcs_Log_Handler {
    void log(enum gensio_log_levels level, const std::string log) override
    {
	std::cerr << "gensio " << gensio_log_level_to_str(level) <<
	    " log: " << log << std::endl;
    }
};

int main(int argc, char *argv[])
{
    int err = 1;

    try {
	Os_Funcs o(0, new MDNS_Logger);
	Waiter w(o);
	Watch_Event e(&w);
	Service_Event s(&w);
	Watch_Done d(&w);
	Done d2(&w);
	MDNS *m;
	const char *txt[3] = { "gensio1-1", "gensio1-2", NULL };
	MDNS_Service *serv;
	MDNS_Watch *watch;

	o.proc_setup();
	m = new MDNS(o);
	serv = m->add_service(-1, GENSIO_NETTYPE_UNSPEC, "gensio1",
			      "_gensio1._tcp", NULL, NULL, 5001, txt, &s);
	watch = m->add_watch(-1, GENSIO_NETTYPE_UNSPEC, "gensio1", NULL,
			     NULL, NULL, &e);

	w.wait(1, NULL);
	serv->free();
	watch->free(&d);
	m->free(&d2);
	w.wait(3, NULL);
	err = 0;
    } catch (gensio_error &e) {
	cerr << "gensio error: " << e.what() << endl;
    }
    return err;
}
