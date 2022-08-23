//
// Copyright 2021 Corey Minyard
//
// SPDX-License-Identifier: GPL-2.0-only

// Some systems want C includes first.
#ifndef _WIN32
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

#include <iostream>
#include <gensio/gensio>
using namespace std;
using namespace gensios;

// Internal gensio errors come in through this mechanism.
class Logger: public Os_Funcs_Log_Handler {
    void log(enum gensio_log_levels level, const std::string log) override
    {
	std::cerr << "gensio " << gensio_log_level_to_str(level) <<
	    " log: " << log << std::endl;
    }
};

#ifdef _WIN32
#define DEFAULT_ECHO_COMMPORT "COM0"
bool
file_is_accessible_dev(const char *filename)
{
    return true;
}
#else
#define DEFAULT_ECHO_COMMPORT "/dev/ttyEcho0"

bool
file_is_accessible_dev(const char *filename)
{
    struct stat sb;
    int rv;

    rv = stat(filename, &sb);
    if (rv == -1)
	return false;

    if (!S_ISCHR(sb.st_mode))
	return false;

    rv = open(filename, O_RDWR);
    if (rv >= 0) {
	close(rv);
	return true;
    } else {
	return false;
    }
}
#endif

int main(int argc, char *argv[])
{
    if (!file_is_accessible_dev(DEFAULT_ECHO_COMMPORT))
	return 77;

    Os_Funcs o(0, new Logger);
    int err;
    Waiter w(o);
    static const char *serial_parms[] = { "nouucplock=false", NULL };
#ifdef _WIN32
    Gensio *bg = gensio_alloc("serialdev", "COM1,9600N81", serial_parms,
			      o, NULL);
#else
    Gensio *bg = gensio_alloc("serialdev", "/dev/ttyEcho0,9600n81",
			      serial_parms, o, NULL);
#endif
    Serial_Gensio *sg = (Serial_Gensio *) bg;
    GensioW g(sg); // Take over lifetime of the gensio
    unsigned int v;

    o.proc_setup();

    err = 0;
    g->open_s();
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

    return 0;
}
