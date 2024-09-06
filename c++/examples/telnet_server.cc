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
using namespace gensios;

// This is a Gensio event handler for the server.  It's job is to echo
// received characters.
class Server_Event: public Event {
public:
    // Allocate an event handler for a gensio.  When the gensio
    // closes, wake the waiter.
    Server_Event(Waiter *w) { waiter = w; }

    // Due to initialation order, we have to create this object and
    // pass it to the constructor of the gensio, but we need the
    // gensio, too.  So we have to set this after the gensio is
    // created.
    void set_gensio(Gensio *g) { io = g; }

private:
    // Handle errors, and if no error write the read data back into
    // the gensio for echoing.
    gensiods read(int err, const SimpleUCharVector data,
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
	    count = io->write(data, NULL);
	} catch (gensio_error &e) {
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

    void write_ready() override
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
	if (errstr.length() > 0) {
	    cerr << "Server error handling: " << errstr << endl;
	}

	waiter->wake();
	delete this;
    }

    std::string errstr;

    Gensio *io = NULL;

    Waiter *waiter;
};

// Handle accept events from the accepter stack.  Basically, just kick
// off the handling on the new gensio, using the event handler passed
// in to the constructor.
class Acc_Event: public Accepter_Event {
public:
    Acc_Event(Waiter *w) { waiter = w; }

    void set_accepter(Accepter *iacc) { acc = iacc; }

private:
    Accepter *acc = NULL;

    // If errors occur in the accepter stack, they generally can't be
    // reported through normal mechanisms.  So those types of errors
    // come in through this mechanism.
    void log(enum gensio_log_levels level, const std::string log) override
    {
	std::cerr << "accepter " << gensio_log_level_to_str(level) <<
	    " log: " << log << std::endl;
    }

    // New connection, kick off the new connection's echo handling.
    void new_connection(Gensio *g) override
    {
	if (connected) {
	    // We got a second connection, this can happen due to a
	    // race.  Just shut it down.
	    g->free();
	    return;
	}
	connected = true;
	Server_Event *ev = new Server_Event(waiter);
	g->set_event_handler(ev);
	ev->set_gensio(g);
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
};

// The basic server handling.  Allocate the gensio stack, tcp and
// telnet, and kick off processing.  Wait until the accepter and new
// gensio are freed.
static int
do_server(Os_Funcs &o, const Addr &addr)
{
    Waiter w(o);
    Acc_Event ae(&w);
    Accepter *atcp, *atelnet;

    // An example of hand-creating a stack instead of using the normal
    // allocation method.
    atcp = gensio_acc_alloc("tcp", (void *) ((struct gensio_addr *) addr),
			    NULL, o, NULL);
    atelnet = gensio_acc_alloc("telnet", atcp, NULL, o, &ae);
    ae.set_accepter(atelnet);

    try {
	atelnet->startup();
    } catch (gensio_error &e) {
	cerr << "Error opening: " << e.what() << endl;
	return 1;
    }
    cout << "Port is: " << atcp->get_port() << endl;
    atelnet->set_callback_enable(true);
    w.wait(2, NULL);

    return 0;
}

// Internal gensio errors come in through this mechanism.
class Telnet_Logger: public Os_Funcs_Log_Handler {
    void log(enum gensio_log_levels level, const std::string log) override
    {
	std::cerr << "gensio " << gensio_log_level_to_str(level) <<
	    " log: " << log << std::endl;
    }
};

class Telnet_Thread: public Os_Funcs_Thread_Func {
public:
    Telnet_Thread(Os_Funcs &o) : w(o), o(o) {
	tid = o.new_thread(this);
    }

    ~Telnet_Thread() {
	w.wake();
	o.wait_thread(tid);
    }

    void start() {
	w.wait(1, NULL);
    }

private:
    Os_Funcs o;
    struct gensio_thread *tid;
    Waiter w;
};

int main(int argc, char *argv[])
{
    int err = 1;

    try {
	// -1 (or a specific signal) is required for threads.  It chooses
	// the default wake signal.
	Os_Funcs o(-1, new Telnet_Logger);

	o.proc_setup();

	// Add a thread for handling capacity.
	Telnet_Thread thread1(o);

	Addr addr(o, argv[1], true, NULL, NULL, NULL);

	if (argc < 2) {
	    cerr << "No listen address argument given" << endl;
	    return 1;
	}

	err = do_server(o, addr);
    } catch (gensio_error &e) {
	cerr << "gensio error: " << e.what() << endl;
    }
    return err;
}
