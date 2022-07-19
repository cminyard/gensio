//
// Copyright 2021 Corey Minyard
//
// SPDX-License-Identifier: GPL-2.0-only

#include <iostream>
#include <string>
#include <cstring>
#include <gensio/gensio>
#include <gensio/gensiotcl>

using namespace std;
using namespace gensios;

class Open_Done: public Gensio_Open_Done {
public:
    Open_Done(Waiter *w) { waiter = w; }
    const char *get_err() { return errstr; }

private:

    const char *errstr = NULL;

    void open_done(int err) override {
	if (err)
	    errstr = gensio_err_to_str(err);
	waiter->wake();
    }

    Waiter *waiter;
};

class Close_Done: public Gensio_Close_Done {
public:
    Close_Done(Waiter *w) { waiter = w; }

    void set_gensio(Gensio *g) { io = g; }

private:
    Gensio *io;

    void close_done() override {
	io->free();
    }

    Waiter *waiter;
};

class Client_Event: public Event {
public:
    Client_Event(Waiter *w, const unsigned char *data, gensiods datalen): ce(w)
    {
	waiter = w;
	this->data = data;
	this->datalen = datalen;
    }

    void set_gensio(Gensio *g) { io = g; ce.set_gensio(g); }

    const char *get_err() { return errstr; }

private:
    Gensio *io;

    gensiods read(int err, SimpleUCharVector idata,
		  const char *const *auxdata) override
    {
	if (err) {
	    errstr = gensio_err_to_str(err);
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->close(&ce);
	    return 0;
	}

	string str((char *) idata.data(), idata.size());

	if (readpos + idata.size() > datalen) {
	    errstr = "Too much data";
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->close(&ce);
	    return idata.size();
	}

	if (memcmp(data + readpos, idata.data(), idata.size()) != 0) {
	    errstr = "Data mismatch";
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->close(&ce);
	    return idata.size();
	}

	readpos += idata.size();
	if (readpos == datalen) {
	    io->set_read_callback_enable(false);
	    io->close(&ce);
	}
	return idata.size();
    }

    void write_ready() override
    {
	gensiods count;

	try {
	    count = io->write(data + writepos, datalen - writepos, NULL);
	} catch (gensio_error e) {
	    errstr = e.what();
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->close(&ce);
	    return;
	}

	writepos += count;
	if (writepos == datalen)
	    io->set_write_callback_enable(false);
    }

    void freed() override {
	waiter->wake();
    }

    const char *errstr = NULL;

    const unsigned char *data;
    gensiods datalen;
    gensiods readpos = 0;
    gensiods writepos = 0;

    Close_Done ce;

    Waiter *waiter;
};

static int
do_client_test(Os_Funcs &o, string ios)
{
    Waiter w(o);
    Gensio *g;
    string s("This is a test!\r\n");
    Open_Done oe(&w);
    Client_Event e(&w, (unsigned char *) s.c_str(), (gensiods) s.size());
    const char *errstr;
    gensio_time waittime = { 2, 0 };
    int err;

    g = gensio_alloc(ios, o, &e);
    e.set_gensio(g);
    try {
	g->open(&oe);
    } catch (gensio_error e) {
	cerr << "Error opening '" << ios << "': " << e.what() << endl;
	return 1;
    }
    err = w.wait(1, &waittime);
    if (err) {
	g->free();
	cerr << "Error from open wait for '" << ios << "': " <<
	    gensio_err_to_str(err) << endl;
	return 1;
    }
    errstr = oe.get_err();
    if (errstr) {
	g->free();
	cerr << "Error from open for '" << ios << "': " << errstr << endl;
	return 1;
    }
    g->set_read_callback_enable(true);
    g->set_write_callback_enable(true);
    waittime = { 2, 0 };
    err = w.wait(1, &waittime);
    if (err) {
	cerr << "Error from wait for '" << ios << "': " <<
	    gensio_err_to_str(err) << endl;
	return 1;
    }

    errstr = e.get_err();
    if (errstr) {
	cerr << "Error handler '" << ios << "': " << errstr << endl;
	return 1;
    }
    return 0;
}

class Server_Event: public Event {
public:
    Server_Event(Waiter *w) { waiter = w; }

    void set_gensio(Gensio *g) { io = g; }

    const char *get_err() { return errstr; }

private:
    Gensio *io;

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
	} catch (gensio_error e) {
	    errstr = e.what();
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->free();
	    return data.size();
	}

	if (count < data.size()) {
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(true);
	}
	return data.size();
    }

    void write_ready() override
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
    Acc_Event(Waiter *w, Server_Event *e) { waiter = w; ev = e; }

    void set_accepter(Accepter *a) { acc = a; }

private:
    void log(enum gensio_log_levels level, const std::string log) override
    {
	std::cerr << "accepter " << gensio_log_level_to_str(level) <<
	    " log: " << log << std::endl;
    }

    void new_connection(Gensio *g) override
    {
	io = g;
	ev->set_gensio(g);
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

    Accepter *acc;
    Gensio *io;
    Waiter *waiter;
    Server_Event *ev;
};

static void
do_server_test(Os_Funcs &o, string ios)
{
    Waiter w(o);
    Accepter *a;
    Server_Event e(&w);
    Acc_Event ae(&w, &e);
    const char *errstr;

    a = gensio_acc_alloc(ios, o, &ae);
    ae.set_accepter(a);
    try {
	a->startup();
    } catch (gensio_error e) {
	cerr << "Error opening '" << ios << "': " << e.what() << endl;
	return;
    }
    cout << a->get_port() << endl;
    a->set_callback_enable(true);
    w.wait(2, NULL);

    errstr = e.get_err();
    if (errstr) {
	cerr << "Server error handling '" << ios << "': " << errstr << endl;
    }
}

// Internal gensio errors come in through this mechanism.
class Logger: public Os_Funcs_Log_Handler {
    void log(enum gensio_log_levels level, const std::string log) override
    {
	std::cerr << "gensio " << gensio_log_level_to_str(level) <<
	    " log: " << log << std::endl;
    }
};

class Sub_Event: public Event {
public:
    Sub_Event(Waiter *w)
    {
	waiter = w;
    }

    void set_gensio(Gensio *g) { io = g; }

    const char *get_err() { return errstr; }

    string get_port() { return string(port, portpos); }

private:
    Gensio *io;

    gensiods read(int err, const SimpleUCharVector data,
		  const char *const *auxdata) override
    {
	gensiods i;

	if (portfound) {
	    io->set_read_callback_enable(false);
	    return 0;
	}

	if (err) {
	    io->set_read_callback_enable(false);
	    waiter->wake();
	    errstr = "subprogram failed before reading port";
	    return 0;
	}

	for (i = 0; i < data.size(); i++) {
	    if (portpos >= sizeof(port)) {
		errstr = "Port from sub too large";
		waiter->wake();
		io->set_read_callback_enable(false);
		return i;
	    }
	    if (data[i] == '\n' || data[i] == '\r') {
		port[portpos] = '\0';
		portfound = true;
		waiter->wake();
		io->set_read_callback_enable(false);
		return i;
	    }
	    port[portpos++] = data[i];
	}
	return i;
    }

    void write_ready() override {
	io->set_write_callback_enable(false);
    }

    void freed() override
    {
	waiter->wake();
    }

    char port[100];
    gensiods portpos = 0;
    bool portfound = false;

    const char *errstr = NULL;
    Waiter *waiter;
};

int main(int argc, char *argv[])
{
    int err = 0;
    Tcl_Os_Funcs o(new Logger);
    const char *test = "mux,tcp,localhost,";
    const char *errstr;

    o.proc_setup();

    if (argc > 1) {
	do_server_test(o, argv[1]);
    } else {
	char *s;
	string ios("stdio(noredir-stderr),");
	string ioc(test);
	Gensio *sub;
	Waiter w(o);
	Sub_Event se(&w);
	gensio_time waittime = { 2, 0 };
	int err2;
	char buf[10];
	gensiods len = sizeof(buf);

	cout << "Starting subprogram to act as a server" << endl;
	s = gensio_quote_string(o, argv[0]);
	if (!s) {
	    cerr << "Out of memory duplicating argv[0]" << endl;
	    err = 1;
	    goto out;
	}
	ios += s;
	gensio_os_funcs_zfree(o, s);
	ios += " ";
	ios += test;
	ios += "0";
	try {
	    sub = gensio_alloc(ios, o, &se);
	} catch (gensio_error e) {
	    cerr << "Unable to open " << ios << ": " << e.what() << endl;
	    err = 1;
	    goto out;
	}
	se.set_gensio(sub);
	sub->open_s();
	sub->set_read_callback_enable(true);
	err = w.wait(1, &waittime);
	if (err) {
	    cerr << "Error from sub wait for '" << ios << "': " <<
		gensio_err_to_str(err) << endl;
	    err = 1;
	} else {
	    errstr = se.get_err();
	    if (errstr) {
		cerr << "Unable to handle sub " << ios << ": " <<
		    errstr << endl;
		err = 1;
	    } else {
		ioc += se.get_port();
		cout << "Connecting to " << ioc << endl;
		err = do_client_test(o, ioc);
	    }
	}
	cout << "Closing sub program" << endl;
	sub->close_s();
	err2 = sub->control(0, true, GENSIO_CONTROL_EXIT_CODE, buf, &len);
	if (err2) {
	    cerr << "Error getting exit code: " << gensio_err_to_str(err2)
		 << endl;
	    err = 1;
	}
	err2 = strtoul(buf, NULL, 0);
	if (err2) {
	    cerr << "Error from subprogram: " << err2 << endl;
	    err = 1;
	}
	sub->free();
	waittime = { 2, 0 };
	err2 = w.wait(1, &waittime);
	if (err2) {
	    cerr << "Error from sub wait for '" << ios << "': " <<
		gensio_err_to_str(err2) << endl;
	    err = 1;
	}
    }

 out:
    if (!err)
	cout << "Success!" << endl;
    return err;
}
