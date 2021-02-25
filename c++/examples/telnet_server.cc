//
// Copyright 2021 Corey Minyard
//
// SPDX-License-Identifier: Apache-2.0

// This is a basic telnet server, it accepts one connection and echos
// back everything it receives.
//
// This directly allocates the accepter classes instead of using
// alloc_accepter() and letting strings drive it.  Generally, using
// alloc_accepter() is preferred, it's easier and more flexible, but
// this shows another way it can be done.

#include <iostream>
#include <string>
#include <cstring>
#include <gensio/gensio>

using namespace std;
using namespace gensio;

class Server_Event: public Event {
public:
    Server_Event(Waiter *w) { waiter = w; }

    const char *get_err() { return errstr; }

private:
    int read(Gensio *io, int err, unsigned char *buf,
	     gensiods *buflen, const char *const *auxdata) override
    {
	gensiods count;

	if (err) {
	    if (err != GE_REMCLOSE)
		errstr = gensio_err_to_str(err);
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->free();
	    return 0;
	}

	try {
	    io->write(&count, buf, *buflen, NULL);
	} catch (gensio_error e) {
	    errstr = e.what();
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->free();
	    return 0;
	}

	if (count < *buflen) {
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(true);
	}
	*buflen = count;
	return 0;
    }

    void write_ready(Gensio *io) override
    {
	io->set_read_callback_enable(true);
	io->set_write_callback_enable(false);
    }

    void freed() override {
	waiter->wake();
    }

    const char *errstr = NULL;

    Waiter *waiter;
};

class Acc_Event: public Accepter_Event {
public:
    Acc_Event(Waiter *w, Event *e) { waiter = w; ev = e; }

private:
    void log(enum gensio_log_levels level, char *str, va_list args)
    {
	fprintf(stderr, "accepter %s log: ", gensio_log_level_to_str(level));
	vfprintf(stderr, str, args);
	fprintf(stderr, "\n");
	fflush(stderr);
    }

    void new_connection(Accepter *acc, Gensio *g) override
    {
	g->set_event_handler(ev);
	ev = NULL;
	g->set_read_callback_enable(true);
	g->set_write_callback_enable(true);
	acc->free();
    }

    void freed() override
    {
	waiter->wake();
    }

    Waiter *waiter;
    Event *ev;
};

static int
do_server_test(struct gensio_os_funcs *o, struct gensio_addr *addr)
{
    Waiter w(o);
    Server_Event e(&w);
    Acc_Event ae(&w, &e);
    Accepter *atcp, *atelnet;
    const char *errstr;

    atcp = new Tcp_Accepter(addr, NULL, o, NULL);
    atelnet = new Telnet_Accepter(atcp, NULL, o, &ae);

    try {
	atelnet->startup();
    } catch (gensio_error e) {
	cerr << "Error opening: " << e.what() << endl;
	return 1;
    }
    cout << "Port is: " << atcp->get_port() << endl;
    atelnet->set_callback_enable(true);
    w.wait(2, NULL);

    errstr = e.get_err();
    if (errstr) {
	cerr << "Server error handling: " << errstr << endl;
    }

    return 0;
}

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
    struct gensio_os_funcs *o;
    const char *errstr;
    struct gensio_addr *addr;
    bool is_port_set;

    err = gensio_default_os_hnd(0, &o);
    if (err) {
	cerr << "Error getting os handler: " << gensio_err_to_str(err);
	return 1;
    }
    o->vlog = gensio_log;

    if (argc < 2) {
	cerr << "No listen address argument given" << endl;
	return 1;
    }

    err = gensio_scan_network_port(o, argv[1], true, &addr, NULL,
				   &is_port_set, NULL, NULL);
    if (err) {
	cerr << "Invalid network address: " << gensio_err_to_str(err) << endl;
	return 1;
    }

    err = do_server_test(o, addr);

    gensio_addr_free(addr);

    o->free_funcs(o);
    return err;
}
