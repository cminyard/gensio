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
%define GENSIO_FUNC_DEPRECATED %enddef

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
%ignore gensio::GensioW;

////////////////////////////////////////////////////
// Gensio
// Ignore the normal destructor, it's protected.
%extend gensio::Gensio {
    ~Gensio()
    {
	self->free();
    }
}

%ignore gensio::Gensio::~Gensio();

// We supply our own destructor
%ignore gensio::Gensio::free;

// Only allow the vector versions of write()
%ignore gensio::Gensio::write(const void *data, gensiods datalen,
			      const char *const *auxdata);
%ignore gensio::Gensio::write(const struct gensio_sg *sg, gensiods sglen,
			      const char *const *auxdata);
%ignore gensio::Gensio::write_s(gensiods *count,
				const void *data, gensiods datalen,
				gensio_time *timeout = NULL, bool intr = false);
%ignore gensio::Gensio::write_s(gensiods *count,
				const std::vector<unsigned char> data,
				gensio_time *timeout = NULL, bool intr = false);
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
%catches(gensio::gensio_error) gensio::Gensio::write_s;
%catches(gensio::gensio_error) gensio::Gensio::read_s;
%catches(gensio::gensio_error) gensio::Gensio::alloc_channel;
%catches(gensio::gensio_error) gensio::Gensio::close;
%catches(gensio::gensio_error) gensio::Gensio::close_s;
%catches(gensio::gensio_error) gensio::Gensio::read;
%catches(gensio::gensio_error) gensio::Gensio::read_s;
%catches(gensio::gensio_error) gensio::Gensio::control;

%newobject gensio::Gensio::get_child;
%newobject gensio::Gensio::alloc_channel;
%newobject gensio::Gensio::gensio_alloc;
%newobject gensio::Gensio::gensio_acc_alloc;

////////////////////////////////////////////////////
// Gensio
// Ignore the normal destructor, it's protected.
%extend gensio::Serial_Gensio {
    ~Serial_Gensio()
    {
	self->free();
    }
}
%ignore gensio::Serial_Gensio::~Serial_Gensio();

%catches(gensio::gensio_error) gensio::Serial_Gensio::baud;
%catches(gensio::gensio_error) gensio::Serial_Gensio::datasize;
%catches(gensio::gensio_error) gensio::Serial_Gensio::parity;
%catches(gensio::gensio_error) gensio::Serial_Gensio::stopbits;
%catches(gensio::gensio_error) gensio::Serial_Gensio::flowcontrol;
%catches(gensio::gensio_error) gensio::Serial_Gensio::iflowcontrol;
%catches(gensio::gensio_error) gensio::Serial_Gensio::sbreak;
%catches(gensio::gensio_error) gensio::Serial_Gensio::dtr;
%catches(gensio::gensio_error) gensio::Serial_Gensio::rts;
%catches(gensio::gensio_error) gensio::Serial_Gensio::cts;
%catches(gensio::gensio_error) gensio::Serial_Gensio::dcd_dsr;
%catches(gensio::gensio_error) gensio::Serial_Gensio::ri;
%catches(gensio::gensio_error) gensio::Serial_Gensio::signature;
%catches(gensio::gensio_error) gensio::Serial_Gensio::baud_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::datasize_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::parity_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::stopbits_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::flowcontrol_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::iflowcontrol_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::sbreak_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::dtr_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::rts_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::cts_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::dcd_dsr_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::ri_s;
%catches(gensio::gensio_error) gensio::Serial_Gensio::signature_s;

////////////////////////////////////////////////////
// Accepter
// Constructor is deleted.
%extend gensio::Accepter {
    ~Accepter()
    {
	self->free();
    }
}
%ignore gensio::Accepter::~Accepter;
%ignore gensio::Accepter::get_os_funcs;
%ignore gensio::Accepter::get_cb;
%ignore gensio::Accepter::raw_event_handler;
%ignore gensio::Accepter::user_data;
%ignore gensio::AccepterW;

%catches(gensio::gensio_error) gensio::Accepter::startup;
%catches(gensio::gensio_error) gensio::Accepter::shutdown;
%catches(gensio::gensio_error) gensio::Accepter::shutdown_s;
%catches(gensio::gensio_error) gensio::Accepter::set_callback_enable;
%catches(gensio::gensio_error) gensio::Accepter::set_callback_enable_s;
%catches(gensio::gensio_error) gensio::Accepter::control;
%catches(gensio::gensio_error) gensio::Accepter::accept_s;
%catches(gensio::gensio_error) gensio::Accepter::str_to_gensio;
%catches(gensio::gensio_error) gensio::Accepter::get_port;

%catches(gensio::gensio_error) gensio::gensio_acc_alloc;

%newobject gensio::Accepter::str_to_gensio;

////////////////////////////////////////////////////
// MDNS
%extend gensio::MDNS {
    ~MDNS()
    {
	self->free(NULL);
    }
}
%ignore gensio::MDNS::~MDNS;
%extend gensio::MDNS_Watch {
    ~MDNS_Watch()
    {
	self->free(NULL);
    }
}
%ignore gensio::MDNS_Watch::~MDNS_Watch;
%ignore gensio::MDNS_Watch::~MDNS;
%delobject gensio::MDNS::free;
%delobject gensio::MDNS_Watch::free;
%ignore gensio::MDNS_Watch::raw_event_handler;
%ignore gensio::Raw_MDNS_Event_Handler;
%newobject gensio::MDNS::alloc_watch;
%newobject gensio::MDNS::alloc_service;

////////////////////////////////////////////////////
// gensio_err.h
%ignore gensio_i_os_err_to_err;

////////////////////////////////////////////////////
// A bunch of friend functions that we need to ignore.
%ignore gensio::gensio_cpp_vlog_handler;
%ignore gensio::gensio_alloc(struct gensio *io, Os_Funcs &o);
%ignore gensio::gensio_acc_alloc(struct gensio_accepter *acc, Os_Funcs &o);
%ignore gensio::gensio_add_class;
%ignore gensio::gensio_cpp_freed;
%ignore gensio::gensio_acc_cpp_freed;
%ignore gensio::mdns_free_done;
%ignore gensio::mdns_watch_done;
%ignore gensio::mdns_watch_event;
%ignore gensio::mdns_watch_free_done;

////////////////////////////////////////////////////
// We need gensio_time and gensiods from here.
%ignore "";
%rename("%s") gensio_time;
%rename("%s") gensio_time::secs;
%rename("%s") gensio_time::nsecs;
%rename("%s") gensio_log_levels;
%rename("%s", regextarget=1) "GENSIO_LOG_.*";
%rename("%s") gensiods;
%include <gensio/gensio_types.h>
%rename("%s") "";

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

////////////////////////////////////////////////////
// Pull some constants from gensio.h
%ignore "";
%rename("%s", regextarget=1) "GENSIO_NETTYPE_.*";
%include <gensio/gensio.h>
%rename("%s") "";

////////////////////////////////////////////////////
// Pull some constants from gensio_mdns.h
%ignore "";
%rename("%s") gensio_mdns_data_state;
%rename("%s", regextarget=1) "GENSIO_MDNS_.*";
%include <gensio/gensio_mdns.h>
%rename("%s") "";

////////////////////////////////////////////////////
// Pull some constants from sergensio.h
%ignore "";
%rename("%s", regextarget=1) "SERGENSIO_.*";
%include <gensio/sergensio.h>
%rename("%s") "";
