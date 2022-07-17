%module pygensioglib

%{
#include <gensio/gensioglib>
#include <gensio/pygensio.h>
using namespace gensios;
%}

%import <pygensio.i>

%catches(gensios::gensio_error) gensios::Glib_Os_Funcs::Glib_Os_Funcs;

%extend gensios::Glib_Os_Funcs {
    Glib_Os_Funcs(gensios::Os_Funcs_Log_Handler *logger = NULL)
    {
	gensios::Os_Funcs_Log_Handler *int_handler = NULL;
	if (logger)
	    int_handler = new Internal_Log_Handler(logger);
	return new gensios::Glib_Os_Funcs(int_handler);
    }

    ~Glib_Os_Funcs()
    {
	delete self;
    }
}

%ignore gensios::Glib_Os_Funcs::Glib_Os_Funcs;
%ignore gensios::Glib_Os_Funcs::~Glib_Os_Funcs;

%include <gensio/gensioglib>
