//
// Copyright 2021 Corey Minyard
//
// SPDX-License-Identifier: GPL-2.0-only

#include <iostream>
#include <string>
#include <cstring>
#include <gensio/gensio>

using namespace std;
using namespace gensio;

class Open_Done: public Gensio_Done_Err {
public:
    Open_Done(Waiter *w) { waiter = w; }
    const char *get_err() { return errstr; }

private:

    const char *errstr = NULL;

    void done(Gensio *io, int err) override {
	if (err)
	    errstr = gensio_err_to_str(err);
	waiter->wake();
    }

    Waiter *waiter;
};

class Close_Done: public Gensio_Done {
public:
    Close_Done(Waiter *w) { waiter = w; }
private:

    void done(Gensio *io) override {
	io->free();
    }

    Waiter *waiter;
};

class Client_Event: public Event {
public:
    Client_Event(Waiter *w, unsigned char *data, gensiods datalen,
		 Close_Done *ce)
    {
	waiter = w;
	this->data = data;
	this->datalen = datalen;
	this->ce = ce;
    }

    const char *get_err() { return errstr; }

private:
    int read(Gensio *io, int err, unsigned char *buf,
	     gensiods *buflen, const char *const *auxdata) override
    {
	if (err) {
	    errstr = gensio_err_to_str(err);
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->close(ce);
	    return 0;
	}
		  
	string str((char *) buf, *buflen);

	if (readpos + *buflen > datalen) {
	    errstr = "Too much data";
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->close(ce);
	    return 0;
	}

	if (memcmp(data + readpos, buf, *buflen) != 0) {
	    errstr = "Data mismatch";
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->close(ce);
	    return 0;
	}

	readpos += *buflen;
	if (readpos == datalen) {
	    io->set_read_callback_enable(false);
	    io->close(ce);
	}

	return 0;
    }

    void write_ready(Gensio *io) override
    {
	gensiods count;

	try {
	    io->write(&count, data + writepos, datalen - writepos, NULL);
	} catch (gensio_error e) {
	    errstr = e.what();
	    io->set_read_callback_enable(false);
	    io->set_write_callback_enable(false);
	    io->close(ce);
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

    unsigned char *data;
    gensiods datalen;
    gensiods readpos = 0;
    gensiods writepos = 0;

    Close_Done *ce;

    Waiter *waiter;
};

static int
do_client_test(Os_Funcs &o, string ios)
{
    Waiter w(o);
    Gensio *g;
    string s("This is a test!\r\n");
    Open_Done oe(&w);
    Close_Done ce(&w);
    Client_Event e(&w, (unsigned char *) s.c_str(), (gensiods) s.size(), &ce);
    const char *errstr;
    gensio_time waittime = { 2, 0 };
    int err;

    g = gensio_alloc(ios, o, &e);
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
    void log(enum gensio_log_levels level, char *str, va_list args) override
    {
	fprintf(stderr, "accepter %s log: ", gensio_log_level_to_str(level));
	vfprintf(stderr, str, args);
	fprintf(stderr, "\n");
	fflush(stderr);
    }

    void new_connection(Accepter *acc, Gensio *g) override
    {
	io = g;
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

    Gensio *io;
    Waiter *waiter;
    Event *ev;
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

static void
gensio_log(struct gensio_os_funcs *f, enum gensio_log_levels level,
	   const char *log, va_list args)
{
    fprintf(stderr, "gensio %s log: ", gensio_log_level_to_str(level));
    vfprintf(stderr, log, args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

class Sub_Event: public Event {
public:
    Sub_Event(Waiter *w)
    {
	waiter = w;
    }

    const char *get_err() { return errstr; }

    string get_port() { return string(port, portpos); }

private:
    int read(Gensio *io, int err, unsigned char *buf,
	     gensiods *buflen, const char *const *auxdata) override
    {
	gensiods i;

	if (portfound)
	    return 0;

	if (err) {
	    io->set_read_callback_enable(false);
	    waiter->wake();
	    errstr = "subprogram failed before reading port";
	    return 0;
	}

	for (i = 0; i < *buflen; i++) {
	    if (portpos >= sizeof(port)) {
		errstr = "Port from sub too large";
		waiter->wake();
		io->set_read_callback_enable(false);
		return 0;
	    }
	    if (buf[i] == '\n' || buf[i] == '\r') {
		port[portpos] = '\0';
		portfound = true;
		waiter->wake();
		io->set_read_callback_enable(false);
		return 0;
	    }
	    port[portpos++] = buf[i];
	}
	return 0;
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
    Os_Funcs o(0);
    const char *test = "mux,tcp,localhost,";
    const char *errstr;

    o.set_vlog(gensio_log);
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
