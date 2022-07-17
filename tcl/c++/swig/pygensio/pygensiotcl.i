%module pygensiotcl;

%{
#include <gensio/gensiotcl>
#include <gensio/pygensio.h>
using namespace gensios;
%}

%import <pygensio.i>

%extend gensios::Tcl_Os_Funcs {
    Tcl_Os_Funcs(gensios::Os_Funcs_Log_Handler *logger = NULL)
    {
	gensios::Os_Funcs_Log_Handler *int_handler = NULL;
	if (logger)
	    int_handler = new Internal_Log_Handler(logger);
	return new gensios::Tcl_Os_Funcs(int_handler);
    }

    ~Tcl_Os_Funcs()
    {
	delete self;
    }
}

%ignore gensios::Tcl_Os_Funcs::Tcl_Os_Funcs;
%ignore gensios::Tcl_Os_Funcs::~Tcl_Os_Funcs;

%include <gensio/gensiotcl>
