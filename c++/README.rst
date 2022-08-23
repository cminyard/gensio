====================
gensio C++ interface
====================

This provides the C++ interface for gensio.  It's a fairly minimal
binding; gensio is already OO oriented and wrapping C++ around it is
fairly trivial.  This document describes the adaptation to C++.

The gensio/gensio include file has lots of documentation on the
interfaces.  This files covers general concepts.

The basic principles are the same as the C interface, and you can use
the man pages for the various C functions for explainations of how
most of the interfaces work.  It's a pretty straightforward mapping in
most cases.  Like ``gensio_write(g, ...)`` would map to
``g->write(...)``.

A few things are not the same:

* Everything (even the base C gensio interface) is in the gensio
  namespace.

* Unless otherwise documented, errors raise a ``gensio_error`` type
  exception.

* gensio_os_funcs is wrapped, but it's easier to use and safer in the
  C++ form since it's a smart pointer type of thing.

* Callbacks are done through subclassing an ``Event`` or
  ``Accepter_Event`` class for the main callbacks and various ``Done``
  classes for open, close, etc. operations.

* You allocate gensios/accepters with
  ``gensio_alloc()``/``gensio_acc_alloc()`` functions.  The object
  returned will be a subclass of ``Gensio`` or ``Accepter``.  There
  are specific subclasses for all the gensios.  If you are
  hand-allocating the gensio/accepter instead of using a string, you
  use the specific subclass constructor (Tcp, Serialdev, Mux, etc.).

The only thing you should need from the C gensio include file is
constants, gensiods, and gensio_sg.  Everything else should be
accessible through the C++ interface for using gensios.  Implementing
new gensios in C++ is a different story, and probably hard if not
impossible at the moment.

Note that you have glib and tcl OS_Funcs in the glib and tcl
directories.

Os_Funcs and Logging
====================

Like in the gensio C interface, Os_Funcs provides the basic operating
system interface used throughout the library.  You must allocate one
of these.  There is a default one allocated out of the main interface
that is the default for the platform.  There is also a glib and tcl
version available in the tcl and glib directories at the base of
gensio.

For the default interface, you would allocate with:

  .. code-block:: c++

  gensio::OsFuncs o(SIGUSR1, logger)

The first parameters is for Unix, a signal used to send wakeups
between threads.  It must be provided in a multi-threaded program, you
can set it to zero if you program is single-threaded.

The Logger is an object used by gensio to log events that happen
inside the library to clarify error returns or report things that
could not be reported otherwise.  You must subclass
Os_Funcs_Log_Handler and provide your own log function, something like:

  .. code-block:: c++

  class My_Logger: public gensio::Os_Funcs_Log_Handler {
      void log(enum gensio::gensio_log_levels level,
               const std::string log) override
      {
          std::cerr << "gensio " << gensio::gensio_log_level_to_str(level) <<
	        " log: " << log << std::endl;
      }
  };

You can, of course, tie this into your own logging system or whatnot.
The gensio log mask still applies to these logs, if you want logs
besides error and critical you must call set_log_mask() to set the
mask to the logs you want.

One time in your program, on one OS_Funcs, you must call proc_setup()
for everything to work right.  This does some special signal handling
setup.  The OS_Funcs you call this on must be the last one that gets
freed.

SimpleUCharVector
=================

This is a simple vector-like class for efficient transfer of data.  It
works much like a vector, but it does not do its own data management.
It used to avoid allocation and copying when transferring data over
read and write interfaces.

Gensio and Event
================

Gensios cannot be allocated or freed using normal C++ constructors or
destructors.  Instead, you use the gensio_alloc() function to allocate
one.  This allows the library to do the internal subclassing; if you
allocate a serial gensio, you will get something that can be
dynamically cast to Serial_Gensio.

To free a gensio, you must call the free() method on the gensio.  The
trouble with using a destructor is that when you free a gensio, there
may still be callbacks pending, but in a destructor you cannot prevent
the object from being deleted.  The free() method will start the free
process and free the gensio after everything has been cleaned up.

Callbacks happen through an Event object, which you must subclass.
You must provide read() and write_ready() methods when you subclass
Event, the other functions are optional, mostly for crypto handling,
but also for reporting new channels on channel-oriented gensios and
for knowing when the Gensio object its attached to has been freed.

Serial_Gensio and Serial_Event
==============================

Serial_Gensio is a subclass of Gensio that allows operations on serial
ports to be done.  This works with serialdev, telnet (with rfc2217
enabled) and ipmisol gensios.

To use this, you must allocate a gensio of the proper class and then
cast it to Serial_Gensio and provide an event handler subclassed from
Serial_Event (which is a subclass of Event).  Then you can cast it to
Serial_Gensio and perform serial port operations.

Accepter and Accepter_Event
===========================

These work pretty much like Gensio and Event.

Waiter
======

This wraps a gensio_waiter structure; it's the general way to wait for
things to happen.

RAII
====

Two classes, GensioW and AccepterW, are supplied to allow you to
allocate Gensio and Accepter objects on the stack so they get
automatically cleaned up.  See the documentation with those classes,
they have to be used carefully.

Exceptions and Errors
=====================

Unless otherwise noted in the documentation in the gensio/gensio
include file, any error returned from a C gensio operation will result
in a gensio_error exception being raised.

Operations with callbacks will return errors as expected.

Addr
====

It might be surprising, but the Addr class isn't used very much.  It
is returned by MDNS watch events to report addresses from MDNS.  And
you can use it to allocate some specific Gensio or Accepter classes.
But it's not used at all in the general interface; that uses strings
for pretty much everything where an address is required.

You can convert an Addr to a string that can be used in gensio and
accepter creation; that's generally what you should do if you are
getting MDNS watch events and making connections from those.
