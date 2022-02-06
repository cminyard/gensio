%module pygensioglib

%{
#include <gensio/gensioglib>
#include <gensio/pygensio.h>
%}

%import <pygensio.i>

%catches(gensio::gensio_error) gensio::Glib_Os_Funcs::Glib_Os_Funcs;

%extend gensio::Glib_Os_Funcs {
    Glib_Os_Funcs(gensio::Os_Funcs_Log_Handler *logger = NULL)
    {
	gensio::Os_Funcs_Log_Handler *int_handler = NULL;
	if (logger)
	    int_handler = new Internal_Log_Handler(logger);
	return new gensio::Glib_Os_Funcs(int_handler);
    }

    ~Glib_Os_Funcs()
    {
	delete self;
    }
}

%ignore gensio::Glib_Os_Funcs::Glib_Os_Funcs;
%ignore gensio::Glib_Os_Funcs::~Glib_Os_Funcs;

%include <gensio/gensioglib>
