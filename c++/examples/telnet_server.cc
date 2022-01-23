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
// this shows another way it can be done, if, for instance, you need
// to dynamically stack new gensios onto an existing stack.

#include <iostream>
#include <string>
#include <cstring>
#include <gensio/gensio>

using namespace std;
using namespace gensio;

// This is a Gensio event handler for the server.  It's job is to echo
// received characters.
class Server_Event: public Event {
public:
    Server_Event(Waiter *w) { waiter = w; }

    // This allows the user to determine if the event handler had an
    // error.
    const char *get_err() { return errstr; }

private:
    // Handle errors, and if no error wreite the read data back into
    // the gensio for echoing.
    gensiods read(Gensio *io, int err, const std::vector<unsigned char> data,
		  const char *const *auxdata) override
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
	    count = io->write(data.data(), data.size(), NULL);
	} catch (gensio_error e) {
	    errstr = e.what();
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->free();
	    return 0;
	}

	if (count < data.size()) {
	    // We couldn't write all the data, so the write side is in
	    // flow control.  Enable the write callback so we know
	    // when we can write again.
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(true);
	}
	return count;
    }

    void write_ready(Gensio *io) override
    {
	// We were flow controlled on write and we can write again.
	// Kick back off the reads.
	io->set_read_callback_enable(true);
	io->set_write_callback_enable(false);
    }

    // Called when the free is complete.  We wake up whatever is
    // waiting on us.
    void freed() override
    {
	waiter->wake();
    }

    const char *errstr = NULL;

    Waiter *waiter;
};

// Handle accept events from the accepter stack.  Basically, just kick
// off the handling on the new gensio, using the event handler passed
// in to the constructor.
class Acc_Event: public Accepter_Event {
public:
    Acc_Event(Waiter *w, Event *e) { waiter = w; ev = e; }

private:
    // If errors occur in the accepter stack, they generally can't be
    // reported through normal mechanisms.  So those types of errors
    // come in through this mechanism.
    void log(enum gensio_log_levels level, char *str, va_list args) override
    {
	fprintf(stderr, "accepter %s log: ", gensio_log_level_to_str(level));
	vfprintf(stderr, str, args);
	fprintf(stderr, "\n");
	fflush(stderr);
    }

    // New connection, kick off the new connection's echo handling.
    void new_connection(Accepter *acc, Gensio *g) override
    {
	if (connected) {
	    // We got a second connection, this can happen due to a
	    // race.  Just shut it down.
	    g->free();
	    return;
	}
	connected = true;
	g->set_event_handler(ev);
	ev = NULL;
	g->set_read_callback_enable(true);
	g->set_write_callback_enable(true);
	acc->free();
    }

    // The free of the accepter has completed, wake up whatever is
    // waiting.
    void freed() override
    {
	waiter->wake();
    }

    bool connected = false;
    Waiter *waiter;
    Event *ev;
};

// The basic server handling.  Allocate the gensio stack, tcp and
// telnet, and kick off processing.  Wait until the accepter and new
// gensio are freed.
static int
do_server(Os_Funcs &o, const Addr &addr)
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

	o.set_vlog(gensio_log);
	o.proc_setup();
	Addr addr(o, argv[1], true, NULL, NULL, NULL);

	if (argc < 2) {
	    cerr << "No listen address argument given" << endl;
	    return 1;
	}

	err = do_server(o, addr);
    } catch (gensio_error e) {
	cerr << "gensio error: " << e.what() << endl;
    }
    return err;
}
