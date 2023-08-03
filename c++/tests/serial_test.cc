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
#include <string.h>
#endif

#include <iostream>
#include <gensio/gensio>
using namespace std;
using namespace gensios;
#include <gensio/gensio_osops_env.h>

// Internal gensio errors come in through this mechanism.
class Logger: public Os_Funcs_Log_Handler {
    void log(enum gensio_log_levels level, const std::string log) override
    {
	std::cerr << "gensio " << gensio_log_level_to_str(level) <<
	    " log: " << log << std::endl;
    }
};

#define ECHO_DEV_ENV "GENSIO_TEST_ECHO_DEV"
#define DEFAULT_ECHO_COMMPORT "/dev/ttyEcho0"

static int
get_echo_dev(Os_Funcs &o, char *echo_dev, gensiods len)
{
    int rv;

    rv = gensio_os_env_get(ECHO_DEV_ENV, echo_dev, &len);
#ifdef _WIN32
    if (rv)
	return rv;
#else
    if (rv == GE_NOTFOUND) {
	if (len < strlen(DEFAULT_ECHO_COMMPORT) + 1)
	    return GE_TOOBIG;
	strncpy(echo_dev, DEFAULT_ECHO_COMMPORT, len);
    } else if (rv) {
	return rv;
    }

    struct stat sb;

    rv = stat(echo_dev, &sb);
    if (rv == -1)
	return gensio_os_err_to_err(o, errno);

    if (!S_ISCHR(sb.st_mode))
	return GE_INVAL;

    rv = open(echo_dev, O_RDWR);
    if (rv < 0)
	return gensio_os_err_to_err(o, errno);
    close(rv);
#endif
    return 0;
}

int main(int argc, char *argv[])
{
    Os_Funcs o(0, new Logger);
    char echo_dev[100];
    int err;

    err = get_echo_dev(o, echo_dev, sizeof(echo_dev));
    if (err) {
	printf("Unable to get echo dev, test skipped: %s\n",
	       gensio_err_to_str(err));
	return 77;
    }
    std::string devstr(echo_dev);
    devstr.append(",9600n81");

    Waiter w(o);
    static const char *serial_parms[] = { "nouucplock=false", NULL };
    Gensio *bg = gensio_alloc("serialdev", devstr.c_str(), serial_parms,
			      o, NULL);
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
