//
// Copyright 2021 Corey Minyard
//
// SPDX-License-Identifier: Apache-2.0

// This is a basic telnet client, it makes a telnet connection and in
// line mode sends anything typed on stdin to the telnet server and
// prints anything that comes back to stdout.
//
// This demonstrates using an GensioW.

#include <iostream>
#include <string>
#include <gensio/gensio>

using namespace gensios;

// This is a Gensio event handler for the client.  It transfers read
// data from it's gensio (io) to the other gensio (otherio).
class Client_Event: public Event {
public:
    Client_Event(Waiter *w) { waiter = w; }

    // This allows the user to determine if the event handler had an
    // error.
    int get_err() { return err; }

    void set_gensios(Gensio *g, Gensio *og) {
	io = g;
	otherio = og;
    }

private:
    // Handle errors, and if no error write the read data into the
    // other gensio.
    gensiods read(int ierr, const SimpleUCharVector data,
		  const char *const *auxdata) override
    {
	gensiods count;

	if (ierr) {
	    err = ierr;
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    waiter->wake();
	    return 0;
	}

	try {
	    count = otherio->write(data.data(), data.size(), NULL);
	} catch (gensio_error &e) {
	    err = e.get_error();
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    otherio->set_read_callback_enable(false);
	    otherio->set_write_callback_enable(false);
	    waiter->wake();
	    return 0;
	}

	if (count < data.size()) {
	    // We couldn't write all the data, so the write side is in
	    // flow control.  Enable the write callback so we know
	    // when we can write again.
	    io->set_read_callback_enable(false);
	    otherio->set_write_callback_enable(true);
	}
	return count;
    }

    void write_ready() override
    {
	// We were flow controlled on write and we can write again.
	// Kick back off the reads.
	otherio->set_read_callback_enable(true);
	io->set_write_callback_enable(false);
    }

    int err = 0;

    Gensio *io = NULL;
    Gensio *otherio = NULL;

    Waiter *waiter;
};

// Internal gensio errors come in through this mechanism.
class Telnet_Logger: public Os_Funcs_Log_Handler {
    void log(enum gensio_log_levels level,
	     const std::string log) override
    {
	std::cerr << "gensio " << gensio_log_level_to_str(level) <<
	    " log: " << log << std::endl;
    }
};

int main(int argc, char *argv[])
{
    try {
	// Note that Telnet_Logger must be dynamically allocated.
	// Os_Funcs will delete it when the Os_Funcs is destroyed.
	Os_Funcs o(0, new Telnet_Logger);
	std::string constr(argv[1]);
	Waiter waiter(o);

	o.proc_setup();

	Client_Event telnet_evh(&waiter);
	Client_Event user_evh(&waiter);
	GensioW tgensio("telnet," + constr, o, &telnet_evh);
	GensioW ugensio("stdio(self)", o, &user_evh);

	telnet_evh.set_gensios(&tgensio, &ugensio);
	user_evh.set_gensios(&ugensio, &tgensio);

	ugensio->open_s();
	tgensio->open_s();

	tgensio->set_read_callback_enable(true);
	ugensio->set_read_callback_enable(true);

	waiter.wait(1);

	int terr = telnet_evh.get_err();
	int uerr = user_evh.get_err();
	if (terr && terr != GE_REMCLOSE) {
	    std::cerr << "Error from telnet connection: " <<
		err_to_string(terr) << std::endl;
	}
	if (uerr && uerr != GE_REMCLOSE) {
	    std::cerr << "Error from stdio: " <<
		err_to_string(uerr) << std::endl;
	}

	// It's better to close these before they are destroyed, but
	// the close must complete before the destruction.
	tgensio->close_s();
	ugensio->close_s();

	// Destruction happens in reverse order, so the gensios are
	// freed, then the user events, the waiter, and the OS funcs.
    } catch (gensio_error &e) {
	std::cerr << "gensio error: " << e.what() << std::endl;
	return 1;
    }
    return 0;
}
