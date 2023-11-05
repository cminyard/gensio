//
//  gensio - A library for abstracting stream I/O
//  Copyright (C) 2021  Corey Minyard <minyard@acm.org>
//
//  SPDX-License-Identifier: LGPL-2.1-only

// This is base code that all target lagnages should need.

%{
#include <gensio/gensioosh>
#include <gensio/gensio>
#include <gensio/gensiomdns>
using namespace gensios;
%}

%include <std_string.i>
%include <stdint.i>

%feature("director") gensios::Os_Funcs_Log_Handler;
%feature("director") gensios::Event;
%feature("director") gensios::Gensio_Open_Done;
%feature("director") gensios::Gensio_Close_Done;
%feature("director") gensios::Gensio_Control_Done;
%feature("director") gensios::Serial_Event;
%feature("director") gensios::Serial_Op_Done;
%feature("director") gensios::Serial_Op_Sig_Done;
%feature("director") gensios::Accepter_Event;
%feature("director") gensios::Accepter_Shutdown_Done;
%feature("director") gensios::Accepter_Enable_Done;
%feature("director") gensios::MDNS_Free_Done;
%feature("director") gensios::MDNS_Service_Event;
%feature("director") gensios::MDNS_Watch_Free_Done;
%feature("director") gensios::MDNS_Watch_Event;

%define GENSIOCPP_DLL_PUBLIC %enddef
%define GENSIO_DLL_PUBLIC %enddef
%define GENSIO_FUNC_DEPRECATED %enddef

%ignore gensios::gensio_error;

////////////////////////////////////////////////////
// Os_Funcs
%catches(gensios::gensio_error) gensios::Os_Funcs::Os_Funcs;
%catches(gensios::gensio_error) gensios::Os_Funcs::proc_setup;

%ignore gensios::Os_Funcs::get_log_handler;
%ignore gensios::Os_Funcs::init;
%ignore gensios::Os_Funcs::operator=;
%ignore gensios::Os_Funcs::operator struct gensio_os_funcs*;
// FIXME - ignore proc_setup?
%ignore gensios::Os_Funcs::get_proc_data;

////////////////////////////////////////////////////
// Addr
%catches(gensios::gensio_error) gensios::Addr::Addr;
%catches(gensios::gensio_error) gensios::Addr::to_string;
%catches(gensios::gensio_error) gensios::Addr::to_string_all;

%ignore gensios::Addr::Addr(Os_Funcs &o, int nettype,
			   const void *iaddr, gensiods len,
			   unsigned int port);
%ignore gensios::Addr::Addr(struct gensio_addr *iaddr);
%ignore gensios::Addr::operator=;
%ignore gensios::Addr::operator struct gensio_addr*;
%ignore gensios::Addr::getaddr;


////////////////////////////////////////////////////
// Event
// Each language will have to provide a typemap for SimpleUCharVector
%ignore gensios::SimpleUCharVector;
%ignore gensios::SimpleUCharVector::operator[];
%ignore gensios::Raw_Event_Handler;

////////////////////////////////////////////////////
// Allocators

%catches(gensios::gensio_error) gensios::gensio_alloc;
%ignore gensios::GensioW;

////////////////////////////////////////////////////
// Gensio
// Ignore the normal destructor, it's protected.
%extend gensios::Gensio {
    ~Gensio()
    {
	self->free();
    }
}

%ignore gensios::Gensio::~Gensio();

// We supply our own destructor
%ignore gensios::Gensio::free;

// Only allow the vector versions of write()
%ignore gensios::Gensio::write(const void *data, gensiods datalen,
			      const char *const *auxdata);
%ignore gensios::Gensio::write(const struct gensio_sg *sg, gensiods sglen,
			      const char *const *auxdata);
%ignore gensios::Gensio::write_s(gensiods *count,
				const void *data, gensiods datalen,
				gensio_time *timeout = NULL, bool intr = false);
%ignore gensios::Gensio::write_s(gensiods *count,
				const std::vector<unsigned char> data,
				gensio_time *timeout = NULL, bool intr = false);
%ignore gensios::Gensio::get_os_funcs();
%ignore gensios::Gensio::get_cb();
%ignore gensios::Gensio::get_gensio();
%ignore gensios::Gensio::raw_event_handler;
%ignore gensios::Gensio::user_data;

%catches(gensios::gensio_error) gensios::Gensio::open;
%catches(gensios::gensio_error) gensios::Gensio::open_s;
%catches(gensios::gensio_error) gensios::Gensio::open_nochild;
%catches(gensios::gensio_error) gensios::Gensio::open_nochild_s;
%catches(gensios::gensio_error) gensios::Gensio::write;
%catches(gensios::gensio_error) gensios::Gensio::write_s;
%catches(gensios::gensio_error) gensios::Gensio::read_s;
%catches(gensios::gensio_error) gensios::Gensio::alloc_channel;
%catches(gensios::gensio_error) gensios::Gensio::close;
%catches(gensios::gensio_error) gensios::Gensio::close_s;
%catches(gensios::gensio_error) gensios::Gensio::read;
%catches(gensios::gensio_error) gensios::Gensio::read_s;
%catches(gensios::gensio_error) gensios::Gensio::control;

%newobject gensios::Gensio::get_child;
%newobject gensios::Gensio::alloc_channel;
%newobject gensios::Gensio::gensio_alloc;
%newobject gensios::Gensio::gensio_acc_alloc;

////////////////////////////////////////////////////
// Gensio
// Ignore the normal destructor, it's protected.
%extend gensios::Serial_Gensio {
    ~Serial_Gensio()
    {
	self->free();
    }
}
%ignore gensios::Serial_Gensio::~Serial_Gensio();

%catches(gensios::gensio_error) gensios::Serial_Gensio::baud;
%catches(gensios::gensio_error) gensios::Serial_Gensio::datasize;
%catches(gensios::gensio_error) gensios::Serial_Gensio::parity;
%catches(gensios::gensio_error) gensios::Serial_Gensio::stopbits;
%catches(gensios::gensio_error) gensios::Serial_Gensio::flowcontrol;
%catches(gensios::gensio_error) gensios::Serial_Gensio::iflowcontrol;
%catches(gensios::gensio_error) gensios::Serial_Gensio::sbreak;
%catches(gensios::gensio_error) gensios::Serial_Gensio::dtr;
%catches(gensios::gensio_error) gensios::Serial_Gensio::rts;
%catches(gensios::gensio_error) gensios::Serial_Gensio::cts;
%catches(gensios::gensio_error) gensios::Serial_Gensio::dcd_dsr;
%catches(gensios::gensio_error) gensios::Serial_Gensio::ri;
%catches(gensios::gensio_error) gensios::Serial_Gensio::signature;
%catches(gensios::gensio_error) gensios::Serial_Gensio::baud_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::datasize_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::parity_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::stopbits_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::flowcontrol_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::iflowcontrol_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::sbreak_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::dtr_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::rts_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::cts_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::dcd_dsr_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::ri_s;
%catches(gensios::gensio_error) gensios::Serial_Gensio::signature_s;

////////////////////////////////////////////////////
// Accepter
// Constructor is deleted.
%extend gensios::Accepter {
    ~Accepter()
    {
	self->free();
    }
}
%ignore gensios::Accepter::~Accepter;
%ignore gensios::Accepter::get_os_funcs;
%ignore gensios::Accepter::get_cb;
%ignore gensios::Accepter::raw_event_handler;
%ignore gensios::Accepter::user_data;
%ignore gensios::AccepterW;

%catches(gensios::gensio_error) gensios::Accepter::startup;
%catches(gensios::gensio_error) gensios::Accepter::shutdown;
%catches(gensios::gensio_error) gensios::Accepter::shutdown_s;
%catches(gensios::gensio_error) gensios::Accepter::set_callback_enable;
%catches(gensios::gensio_error) gensios::Accepter::set_callback_enable_s;
%catches(gensios::gensio_error) gensios::Accepter::control;
%catches(gensios::gensio_error) gensios::Accepter::accept_s;
%catches(gensios::gensio_error) gensios::Accepter::str_to_gensio;
%catches(gensios::gensio_error) gensios::Accepter::get_port;

%catches(gensios::gensio_error) gensios::gensio_acc_alloc;

%newobject gensios::Accepter::str_to_gensio;

////////////////////////////////////////////////////
// MDNS
%extend gensios::MDNS {
    ~MDNS()
    {
	self->free(NULL);
    }
}
%ignore gensios::MDNS::~MDNS;
%extend gensios::MDNS_Watch {
    ~MDNS_Watch()
    {
	self->free(NULL);
    }
}
%extend gensios::MDNS_Service {
    ~MDNS_Service()
    {
	self->free();
    }
}
%ignore gensios::MDNS::~MDNS;
%ignore gensios::MDNS_Watch::~MDNS_Watch;
%ignore gensios::MDNS_Service::~MDNS_Service;
%delobject gensios::MDNS::free;
%delobject gensios::MDNS_Watch::free;
%delobject gensios::MDNS_Service::free;
%ignore gensios::MDNS_Watch::raw_event_handler;
%ignore gensios::MDNS_Service::raw_event_handler;
%ignore gensios::Raw_MDNS_Event_Handler;
%newobject gensios::MDNS::alloc_watch;
%newobject gensios::MDNS::alloc_service;

////////////////////////////////////////////////////
// gensio_err.h
%ignore gensio_i_os_err_to_err;

////////////////////////////////////////////////////
// A bunch of friend functions that we need to ignore.
%ignore gensios::gensio_cpp_vlog_handler;
%ignore gensios::gensio_alloc(struct gensio *io, Os_Funcs &o);
%ignore gensios::gensio_acc_alloc(struct gensio_accepter *acc, Os_Funcs &o);
%ignore gensios::gensio_add_class;
%ignore gensios::gensio_cpp_freed;
%ignore gensios::gensio_acc_cpp_freed;
%ignore gensios::mdns_free_done;
%ignore gensios::mdns_service_event;
%ignore gensios::mdns_watch_done;
%ignore gensios::mdns_watch_event;
%ignore gensios::mdns_watch_free_done;

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
// Pull some constants from gensio_addr.h
%ignore "";
%rename("%s", regextarget=1) "GENSIO_NETTYPE_.*";
#define GENSIOOSH_DLL_PUBLIC // swig is not getting these defined right
%include <gensio/gensio_addr.h>
%rename("%s") "";

////////////////////////////////////////////////////
// Pull some constants from gensio_mdns.h
%ignore "";
%rename("%s") gensio_mdns_data_state;
%rename("%s", regextarget=1) "GENSIO_MDNS_WATCH_.*";
%rename("%s") gensio_mdns_service_event;
%rename("%s", regextarget=1) "GENSIO_MDNS_SERVICE_.*";
%include <gensio/gensio_mdns.h>
%rename("%s") "";

////////////////////////////////////////////////////
// Pull some constants from sergensio.h
%ignore "";
%rename("%s", regextarget=1) "SERGENSIO_.*";
%include <gensio/sergensio.h>
%rename("%s") "";

////////////////////////////////////////////////////
// Pull some constants from gensio.h
%ignore "";
%rename("%s", regextarget=1) "GENSIO_SER_.*";
%include <gensio/gensio.h>
%rename("%s") "";

const char *gensio_parity_to_str(unsigned int ival);
int gensio_str_to_parity(const char *sval);
const char *gensio_flowcontrol_to_str(unsigned int ival);
int gensio_str_to_flowcontrol(const char *sval);
const char *gensio_onoff_to_str(unsigned int ival);
int gensio_str_to_onoff(const char *sval);
