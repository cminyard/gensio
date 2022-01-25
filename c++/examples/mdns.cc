//
// Copyright 2021 Corey Minyard
//
// SPDX-License-Identifier: Apache-2.0

// This does some basic MDNS operations.

#include <iostream>
#include <string>
#include <cstring>
#include <gensio/gensio>

using namespace std;
using namespace gensio;

class Watch_Event: public MDNS_Watch_Event {
public:
    Watch_Event(Waiter *w) { waiter = w; }

private:
    void event(MDNS_Watch *w,
	       enum gensio_mdns_data_state state,
	       int interface, int ipdomain,
	       const char *name, const char *type,
	       const char *domain, const char *host,
	       const Addr *addr, const char * const *txt) override
    {
	if (state == GENSIO_MDNS_ALL_FOR_NOW)
	    waiter->wake();
	if (state != GENSIO_MDNS_NEW_DATA)
	    return;
	cout << "Got MDNS interface " << interface << " ipdomain " << ipdomain
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

class Watch_Done: public MDNS_Watch_Done {
public:
    Watch_Done(Waiter *w) { waiter = w; }

private:
    void done(MDNS_Watch *w)
    {
	waiter->wake();
    }
    Waiter *waiter;
};

class Done: public MDNS_Done {
public:
    Done(Waiter *w) { waiter = w; }

private:
    void done(MDNS *m)
    {
	waiter->wake();
    }
    Waiter *waiter;
};

// Internal gensio errors come in through this mechanism.
static void
gensio_log(struct gensio_os_funcs *f, enum gensio_log_levels level,
	   const char *log, va_list args)
{
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

int main(int argc, char *argv[])
{
    int err;

    try {
	Os_Funcs o(0);
	Waiter w(o);
	Watch_Event e(&w);
	Watch_Done d(&w);
	Done d2(&w);
	MDNS *m;
	const char *txt[3] = { "gensio1-1", "gensio1-2", NULL };
	MDNS_Service *serv;
	MDNS_Watch *watch;

	o.set_vlog(gensio_log);
	o.proc_setup();
	m = new MDNS(o);
	serv = new MDNS_Service(m, -1, GENSIO_NETTYPE_UNSPEC, "gensio1",
				"_gensio1._tcp", NULL, NULL, 5001, txt);
	watch = new MDNS_Watch(m, -1, GENSIO_NETTYPE_UNSPEC, "gensio1", NULL,
			       NULL, NULL, &e);

	w.wait(1, NULL);
	delete serv;
	watch->free(&d);
	m->free(&d2);
	w.wait(2, NULL);
    } catch (gensio_error e) {
	cerr << "gensio error: " << e.what() << endl;
    }
    return err;
}
