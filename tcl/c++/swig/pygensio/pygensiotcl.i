%module pygensiotcl;

%{
#include <gensio/gensiotcl>
#include <gensio/pygensio.h>
%}

%import <pygensio.i>

%extend gensio::Tcl_Os_Funcs {
    Tcl_Os_Funcs(gensio::Os_Funcs_Log_Handler *logger = NULL)
    {
	gensio::Os_Funcs_Log_Handler *int_handler = NULL;
	if (logger)
	    int_handler = new Internal_Log_Handler(logger);
	return new gensio::Tcl_Os_Funcs(int_handler);
    }

    ~Tcl_Os_Funcs()
    {
	delete self;
    }
}

%ignore gensio::Tcl_Os_Funcs::Tcl_Os_Funcs;
%ignore gensio::Tcl_Os_Funcs::~Tcl_Os_Funcs;

%include <gensio/gensiotcl>
