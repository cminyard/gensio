//
// Copyright 2021 Corey Minyard
//
// SPDX-License-Identifier: GPL-2.0-only


#include <iostream>
#include <gensio/gensio>
using namespace std;
using namespace gensio;

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
    Os_Funcs o(0);
    int err;
    Waiter w(o);
    static const char *serial_parms[] = { "nouucplock=false", NULL };
#ifdef _WIN32
    Serial_Gensio *sg = new Serialdev("COM1,9600N81", serial_parms, o, NULL);
#else
    Serial_Gensio *sg = new Serialdev("/dev/ttyEcho0,9600N81", serial_parms,
				      o, NULL);
#endif
    unsigned int v;

    o->vlog = gensio_log;
    o.proc_setup();

    err = 0;
    sg->open_s();
    cout << "Allocated" << endl;
    cout << "Validating baud is 9600" << endl;
    v = 0;
    sg->baud_s(&v);
    if (v != 9600) {
	err = 1;
	cout << "*** Baud was not 9600" << endl;
    }
    cout << "Setting baud to 19200" << endl;
    v = 19200;
    sg->baud_s(&v);
    if (v != 19200) {
	err = 1;
	cout << "*** Baud was not 19200" << endl;
    } else {
	cout << "baud set to 19200" << endl;
    }
    cout << "Closing" << endl;
    sg->close_s();
    sg->free();

    return 0;
}
