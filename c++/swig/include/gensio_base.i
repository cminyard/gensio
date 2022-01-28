//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

// This is base code that all target lagnages should need.

%{
#include <gensio/gensio>
using namespace gensio;
%}

%include <typemaps/std_string.swg>
%include <std_string.i>
%include <stdint.i>

%feature("director") gensio::Os_Funcs_Log_Handler;
%feature("director") gensio::Event;
%feature("director") gensio::Gensio_Open_Done;
%feature("director") gensio::Gensio_Close_Done;
%feature("director") gensio::Serial_Event;
%feature("director") gensio::Serial_Op_Done;
%feature("director") gensio::Serial_Op_Sig_Done;
%feature("director") gensio::Accepter_Event;
%feature("director") gensio::Accepter_Shutdown_Done;
%feature("director") gensio::Accepter_Enable_Done;
%feature("director") gensio::MDNS_Free_Done;
%feature("director") gensio::MDNS_Watch_Free_Done;
%feature("director") gensio::MDNS_Watch_Event;

%define GENSIOCPP_DLL_PUBLIC %enddef
%define GENSIO_DLL_PUBLIC %enddef

%ignore gensio::gensio_error;

////////////////////////////////////////////////////
// Os_Funcs
%catches(gensio::gensio_error) gensio::Os_Funcs::Os_Funcs;
%catches(gensio::gensio_error) gensio::Os_Funcs::proc_setup;

%ignore gensio::Os_Funcs::get_log_handler;
%ignore gensio::Os_Funcs::init;
%ignore gensio::Os_Funcs::operator=;
%ignore gensio::Os_Funcs::operator struct gensio_os_funcs*;
// FIXME - ignore proc_setup?
%ignore gensio::Os_Funcs::get_proc_data;

////////////////////////////////////////////////////
// Addr
%catches(gensio::gensio_error) gensio::Addr::Addr;
%catches(gensio::gensio_error) gensio::Addr::to_string;
%catches(gensio::gensio_error) gensio::Addr::to_string_all;

%ignore gensio::Addr::Addr(Os_Funcs &o, int nettype,
			   const void *iaddr, gensiods len,
			   unsigned int port);
%ignore gensio::Addr::Addr(struct gensio_addr *iaddr);
%ignore gensio::Addr::operator=;
%ignore gensio::Addr::operator struct gensio_addr*;
%ignore gensio::Addr::getaddr;


////////////////////////////////////////////////////
// Event
// Each language will have to provide a typemap for SimpleUCharVector
%ignore gensio::SimpleUCharVector;
%ignore gensio::SimpleUCharVector::operator[];
%ignore gensio::Raw_Event_Handler;

////////////////////////////////////////////////////
// Allocators

%catches(gensio::gensio_error) gensio::gensio_alloc;

////////////////////////////////////////////////////
// Gensio
// Ignore the normal destructor, it's protected.
%ignore gensio::Gensio::~Gensio();

// We supply our own destructor
%ignore gensio::Gensio::free;

// Only allow the vector version of write()
%ignore gensio::Gensio::write(const void *data, gensiods datalen,
			      const char *const *auxdata);
%ignore gensio::Gensio::write(const SimpleUCharVector data,
			      const char *const *auxdata);
%ignore gensio::Gensio::write_s;
%ignore gensio::Gensio::write(const struct gensio_sg *sg, gensiods sglen,
			      const char *const *auxdata);
%ignore gensio::Gensio::get_os_funcs();
%ignore gensio::Gensio::get_cb();
%ignore gensio::Gensio::get_gensio();
%ignore gensio::Gensio::raw_event_handler;
%ignore gensio::Gensio::user_data;

%catches(gensio::gensio_error) gensio::Gensio::open;
%catches(gensio::gensio_error) gensio::Gensio::open_s;
%catches(gensio::gensio_error) gensio::Gensio::open_nochild;
%catches(gensio::gensio_error) gensio::Gensio::open_nochild_s;
%catches(gensio::gensio_error) gensio::Gensio::write;
%catches(gensio::gensio_error) gensio::Gensio::alloc_channel;
%catches(gensio::gensio_error) gensio::Gensio::close;
%catches(gensio::gensio_error) gensio::Gensio::close_s;
%catches(gensio::gensio_error) gensio::Gensio::read;
%catches(gensio::gensio_error) gensio::Gensio::read_s;
%catches(gensio::gensio_error) gensio::Gensio::control;

%newobject gensio::Gensio::get_child;
%newobject gensio::Gensio::alloc_channel;

////////////////////////////////////////////////////
// Accepter
%ignore gensio::Accepter::get_os_funcs;
%ignore gensio::Accepter::get_cb;
%ignore gensio::Accepter::raw_event_handler;
%ignore gensio::Accepter::user_data;

////////////////////////////////////////////////////
// MDNS
%delobject gensio::MDNS::free;
%delobject gensio::MDNS_Watch::free;
%ignore gensio::MDNS_Watch::raw_event_handler;

////////////////////////////////////////////////////
// Waiter

// We provide our own version
%ignore gensio::Waiter::wait;

////////////////////////////////////////////////////
// gensio_err.h
%ignore gensio_i_os_err_to_err;

////////////////////////////////////////////////////
// A bunch of friend functions that we need to ignore.
%ignore gensio::gensio_cpp_vlog_handler;
%ignore gensio::gensio_alloc(struct gensio *io, Os_Funcs &o);
%ignore gensio::gensio_alloc(Gensio *child, std::string str, Os_Funcs &o,
			     Event *cb);
%ignore gensio_acc_alloc(struct gensio_accepter *acc, Os_Funcs &o);
%ignore gensio_acc_alloc(Accepter *child, std::string str, Os_Funcs &o,
			 Accepter_Event *cb);
%ignore gensio::gensio_add_class;
%ignore gensio::gensio_cpp_freed;
%ignore gensio::gensio_acc_cpp_freed;
%ignore gensio::mdns_free_done;
%ignore gensio::mdns_watch_done;
%ignore gensio::mdns_watch_event;
%ignore gensio::mdns_watch_free_done;

////////////////////////////////////////////////////
// We need gensio_time from here.
%ignore "";
%rename("%s") gensio_time;
%rename("%s") gensio_time::secs;
%rename("%s") gensio_time::nsecs;
%rename("%s") gensio_log_level;
%include <gensio/gensio_types.h>
%rename("%s") "";
const int GENSIO_LOG_FATAL = GENSIO_LOG_FATAL;
const int GENSIO_LOG_ERR = GENSIO_LOG_ERR;
const int GENSIO_LOG_WARNING = GENSIO_LOG_WARNING;
const int GENSIO_LOG_INFO = GENSIO_LOG_INFO;
const int GENSIO_LOG_DEBUG = GENSIO_LOG_DEBUG;

////////////////////////////////////////////////////
// gensio_time
%extend gensio_time {
    gensio_time(long secs, int nsecs)
    {
	struct gensio_time *t = new gensio_time;

	t->secs = secs;
	t->nsecs = nsecs;
	return t;
    }
}
