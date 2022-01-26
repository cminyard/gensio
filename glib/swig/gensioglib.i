%module gensioglib

%import <gensio/gensio_swig.i>

%{
#include "config.h"
#include <string.h>
#include <signal.h>

#include <gensio/gensio.h>
#include <gensio/gensio_glib.h>
#include <gensio/gensio_swig.h>

struct gensio_os_funcs *alloc_glib_os_funcs(swig_cb *log_handler)
{
    struct gensio_os_funcs *o;
    int err;

    err = gensio_glib_funcs_alloc(&o);
    if (err) {
	fprintf(stderr, "Unable to allocate gensio os funcs: %s, giving up\n",
		gensio_err_to_str(err));
	exit(1);
    }

    err = gensio_swig_setup_os_funcs(o, log_handler);
    if (err) {
	fprintf(stderr, "Unable to set up gensio os funcs: %s, giving up\n",
		gensio_err_to_str(err));
	exit(1);
    }

    return o;
}

%}

%nodefaultctor gensio_os_funcs;

struct gensio_os_funcs { };

%extend gensio_os_funcs {
    ~gensio_os_funcs() {
	check_os_funcs_free(self);
    }
}

%newobject alloc_glib_os_funcs;
struct gensio_os_funcs *alloc_glib_os_funcs(swig_cb *log_handler);
