========================
Using the gensio library
========================

The gensio library is designed to provide a single abstraction over a
large number of I/O and network devices.  This file describes the
basic concepts of using the library.

For a heavily annotated example of this, see basic_server.c and
basic_client.c in the examples directory.

General Concepts
================

gensio has an object oriented interface that is event-driven.
Synchronous interfaces are also available.  You deal with two main
objects in gensio: a gensio and a gensio accepter.  A gensio provides
a communication interface where you can connect, disconnect, write,
receive, etc.

A gensio accepter lets you receive incoming connections.  If a
connection comes in, it gives you a gensio.

The interface is event-driven because it is, for the most part,
completely non-blocking.  If you open a gensio, you give it a callback
that will be called when the connection is up, or the connection
fails.  Same for close.  A write will return the number of bytes
accepted, but it may not take all the bytes (or even any of the bytes)
and the caller must account for that.

The open and close interfaces have a secondary blocking interface for
convenience.  These end in _s.  This is for convenience, but it's not
necessary and use of these must be careful because you can't really
use them from callbacks.

Speaking of callbacks, data and information coming from gensio to the
user is done with a function callback.  Read data, and when the gensio
is ready for write data comes back in a callback.  A similar interface
is used for calling from the user to the gensio layer, but it is
hidden from the user.  This sort of interface is easily extensible,
new operations can be easily added without breaking old interfaces.

The library provides several ways to create a gensio or gensio
accepter.  The main way is str_to_gensio() and
str_to_gensio_accepter().  These provide a way to specify a stack of
gensios or accepters as a string and build.  In general, you should
use this interface if you can.

In general, interfaces that are not performance sensitive are string
based.  You will see this in gensio_control, and in auxiliary data in
the read and write interface to control certain aspects of the write.

The library also provides ways to set up your gensios by individually
creating each one.  In some situations this might be necessary, but it
limits the ability to use new features of the gensio library as it
gets extended.

If a gensio supports multiple streams (like SCTP), stream numbers are
passed in the auxdata with "stream=n".  Streams are not individually
flow controlled.

Channels, on the other hand, are separate flows of data over the same
connection.  Channels are represented as separate gensios, and they
can be individually flow controlled.

Include Files
=============

There are a few include files you might need to deal with when using
gensios:

gensio.h
    The main include files for gensios and gensio accepters.

gensio_os_funcs.h
    The definition for an OS handler.

argvutils.h
    Many gensio functions take an argv array, this is utilities for
    dealing with argvs.

gensio_selector.h
    A definition for a default OS handler.

These are for the most part documented in the man pages.

For creating your own gensios, the following include files are
available for you:

gensio_class.h
    The main include file for creating your own gensio.

gensio_base.h
    This handles a lot of the boiler plate for a gensio.  Most of the
    standard gensios use this.  It splits the gensio function into
    an optional filter, and a lower layer interface called an ll.

gensio_ll_fd.h
    An ll that provides most of the boilerplate for dealing with a
    file descriptor.

gensio_ll_gensio.h
    An ll that provides all that is necessary for stacking a gensio
    on top of another gensio.  The filter gensios (telnet, ssl, etc.)
    use this as the ll.

Each include file has lots of documentation about the individual calls
and handlers.

Errors
======

gensio has it's own set of errors to abstract it from the OS errors
(named GE_xxx) and provide more flexibility in error reporting.  These
are in the gensio_err.h include file (automatically included from
gensio.h) and may be translated from numbers to a meaningful string
with gensio_err_to_str().  Zero is defined to be not an error.

If an unrecognized operating system error occurs, GE_OSERR is
returned and a log is reported through the OS handler log interface.

OS Handler
==========

One slightly annoying thing about gensio is that it requires you to
provide an OS handler (struct gensio_os_funcs) to handle OS-type
functions like memory allocation, mutexes, the ability to handle file
descriptors, timers and time, and a few other things.

The library does provide several OS handlers.  You can call
gensio_alloc_os_funcs() to allocate a default one for your system
(POSIX or Windows).  You can see that man page for more details.  This
will generally be the best performing option you have for your system.

For POSIX systems, OS handlers for glib and TCL are available,
allocated with gensio_glib_funcs_alloc() and gensio_tcl_funcs_alloc().
These really don't work very well, especially from a performance point
of view, the APIs for glib and TCL are not well designed for what
gensio does.  TCL can only support single-threaded operation.  glib
multithreaded operation only has one thread at a time waiting for I/O.
But they do work, and the tests are run with them.  These are not
available on Windows because of poor abstractions on glib and because
of lack of motivation on TCL.

But if you are using something else like X Windows, etc that has it's
own event loop, you may need to adapt one for your needs.  But the
good thing is that you can do this, and integrate gensio with pretty
much anything.

There is also a waiter interface that provides a convenient way to
wait for things to occur while running the event loop.  This is how
you generally enter the event loop, because it provides a convenient
way to signal when you are done and need to leave the loop.

Documentation for this is in::

  include/gensio/gensio_os_funcs.h

Threads
=======

The gensio library fully supports threads and is completely
thread-safe.  However, it uses signals on POSIX system, and COM on
Windows systems, so some setup is required.

The "main" thread should call gensio_os_proc_setup() at startup and
call gensio_os_proc_cleanup() when it is complete.  This sets up
signals and signal handlers, thread local storage on Windows, and
other sorts of things.

You can spawn new threads from a thread that is already set up using
gensio_os_new_thread().  This gives you a basic OS thread and is
configured properly for gensio.

If you have a thread created by other means that you want to use in
gensio, as long as the thread create another thread and doesn't do any
blocking functions (any sort of wait, background processing, functions
that end in _s like read_s, etc.) you don't have to set them up.  That
way, some external thread can write data, wake another thread, or do
things like that.

If an external thread needs to do those things, it should call
gensio_os_thread_setup().

Signals
=======

As mentioned in the threads section, the gensio library on Unix uses
signals for inter-thread wakeups.  I looked hard, and there's really
no other way to do this cleanly. But Windows has a couple of
signal-like things, too, and these are available in gensio, also.

If you use gensio_alloc_os_funcs(), you will get an OS funcs using the
passed in signal for IPC.  You can pass in
GENSIO_OS_FUNCS_DEFAULT_THREAD_SIGNAL for the signal if you want the
default, which is SIGUSR1.  The signal you use will be blocked and
taken over by gensio, you can't use it.

gensio also provides some generic handling for a few signals.  On
Unix, it will handle SIGHUP through the
gensio_os_proc_register_reload_handler() function.

On Windows and Unix you can use
gensio_os_proce_register_term_handler(), which will handle termination
requests (SIGINT, SIGTERM, SIGQUIT on Unix) and
gensio_os_proc_register_winsize_handler() (SIGWINCH on Unix).  How
these come in through Windows is a little messier, but invisible to
the user.

All the callbacks from from a waiting routine's wait, *not* from the
signal handler.  That should simplify your life a lot.

You can see the man pages for more details on all of these.


Creating a gensio
=================

Connecting gensios
------------------

To create a gensio, the general way to do this is to call
``str_to_gensio()`` with a properly formatted string.  The string is
formatted like so::

  <type>[([<option>[,<option[...]]])][,<type>...][,<end option>[,<end option>]]

The ``end option`` is for terminal gensios, or ones that are at the
bottom of the stack.  For instance, ``tcp,localhost,3001`` will create
a gensio that connects to port 3001 on localhost.  For a serial port,
an example is ``serialdev,/dev/ttyS0,9600N81`` will create a connection
to the serial port /dev/ttyS0.

This lets you stack gensio layers on top of gensio layers.  For
instance, to layer telnet on top of a TCP connection:

.. code-block:: bash

  telnet,tcp,localhost,3001

Say you want to enable RFC2217 on your telnet connection.  You can add
an option to do that:

.. code-block:: bash

  telnet(rfc2217=true),tcp,localhost,3001

When you create a gensio, you supply a callback with user data.  When
events happen on a gensio, the callback will be called so the user
could handle it.

gensio accepters
----------------

A gensio accepter is similar to a connecting gensio, but with
``str_to_gensio_accepter()`` instead.  The format is the same.  For
instance:

.. code-block:: bash

  telnet(rfc2217=true),tcp,3001

will create a TCP accepter with telnet on top.  For accepters, you
generally do not need to specify the hostname if you want to bind to
all interfaces on the local machine.

Using a gensio
==============

Once you have created a gensio, it's not yet open or operational.  To
use it, you have to open it.  To open it, do:

.. code-block:: c

  struct gensio *io;
  int rv;

  rv = str_to_gensio("tcp,localhost,3001", oshnd,
                     tcpcb, mydata, &io);
  if (rv) { handle error }
  rv = gensio_open(io, tcp_open_done, mydata);
  if (rv) { handle error }

Note that when ``gensio_open()`` returns, the gensio is not open.  You
must wait until the callback (``tcp_open_done()`` in this case) is
called.  After that, you can use it.

Once the gensio is open, you won't immediately get any data on it
because receive is turned off.  You must call
``gensio_set_read_callback_enable()`` to turn on and off whether the
callback (``tcpcb`` in this case) will be called when data is received.

When the read handler is called, the buffer and length is passed in.
You do not have to handle all the data if you cannot.  You *must*
update the buflen with the number of bytes you actually handled.  If
you don't handle data, the data not handled will be buffered in the
gensio for later.  Not that if you don't handle all the data, you
should turn off the read enable or the event will immediately called
again.

If something goes wrong on a connection, the read handler is called
with an error set.  ``buf`` and ``buflen`` will be NULL in this case.

For writing, you can call ``gensio_write()`` to write data.  You may
use ``gensio_write()`` at any time on an open gensio.
``gensio_write()`` may not take all the data you write to it.  The
``count`` parameter passes back the number of bytes actually taken in
the write call.

You can design your code to call
``gensio_set_write_callback_enable()`` when you have data to send and
the gensio will call the write ready callback and you can write from
the callback.  This is generally simpler, but enabling and disabling
the write callback adds some overhead.

A more efficient approach is to write data whenever you need to and
have the write callback disabled.  If the write operation returns less
than the full request, the other end has flow-controlled and you
should enable the write callback and wait until it is called before
sending more data.

In the callbacks, you can get the user data you passed in to the
create call with ``gensio_get_user_data()``.

Note that if you open then immediately close a gensio, this is fine,
even if the open callback hasn't been called.  The open callback may
or may not be called in that case, though, so it can be difficult to
handle this properly.

Synchronous I/O
---------------

You can do basic synchronous I/O with gensios.  This is useful in some
situations where you need to read something inline.  To do this, call:

.. code-block:: c

  err = gensio_set_sync(io);

The given gensio will cease to deliver read and write events.  Other
events *are* delivered.  Then you can do:

.. code-block:: c

  err = gensio_read_s(io, &count, data, datalen, &timeout);
  err = gensio_write_s(io, &count, data, datalen, &timeout);

Count is set to the actual number of bytes read/written.  It may be
NULL if you don't care (though that doesn't make much sense for read).

Timeout may be NULL, if so then wait for forever.  If you set a
timeout, it is updated to the amount of time left.

Note that signals will cause these to return immediately, but no
error is reported.

Reads will block until some data comes in and returns that data.  It
does not wait until the buffer is full.  timeout is a timeval, the
read will wait that amount of time for the read to complete and
return.  A timeout is not an error, the count will just be set to
zero.

Writes block until the whole buffer is written or a timeout occurs.
Again, the timeout is not an error, the total bytes actually written
is returned in count.

Once you are done doing synchronous I/O with a gensio, call:

.. code-block:: c

  err = gensio_clear_sync(io);

and delivery through the event interface will continue as before.  You
must not be in a synchronous read or write call when calling this, the
results will be undefined.

Note that other I/O on other gensios will still occur when waiting for
synchronous I/O

There is not currently a way to wait for multiple gensios with
synchronous I/O.  If you are doing that, you should really just use
the event-driven I/O.  It's more efficient, and you end up doing the
same thing in the end, anyway.

Using a gensio accepter
=======================

Like a gensio, a gensio accepter is not operational when you create
it.  You must call ``gensio_acc_startup()`` to enable it:

.. code-block:: c

  struct gensio_accepter *acc;
  int rv;

  rv = str_to_gensio_accepter("tcp,3001", oshnd,
                              tcpacccb, mydata, &acc);
  if (rv) { handle error }
  rv = gensio_startup(acc);
  if (rv) { handle error }

Note that there is no callback to the startup call to know when it's
enabled, because there's no real need to know because you cannot write
to it, it only does callbacks.

Even after you start up the accepter, it still won't do anything until
you call ``gensio_acc_set_accept_callback_enable()`` to enable that
callback.

When the callback is called, it gives you a gensio in the ``data``
parameter that is already open with read disabled.  A gensio received
from a gensio acceptor may have some limitations.  For instance, you
may not be able to close and then reopen it.

gensio accepters can do synchronous accepts using ``gensio_acc_set_sync()``
and ``gensio_acc_accept_s``.  See the man pages on those for details.

Logging
=======

``struct gensio_os_funcs`` has a vlog callback for handling internal
gensio logs.  These are called when something of significance happens
but gensio has no way to report an error.  It also may be called to
make it easier to diagnose an issue when something goes wrong.

Serial I/O
==========

The gensio and gensio accepter classes each have subclasses for
handling serial I/O and setting all the parameters associated with a
serial port.

You can discover if a gensio (or any of its children) is a serial port
by calling ``gensio_is_serial()``.  If that returns false, it is not
capable of serial operation.  If it returns true, it can.

A serial gensio may be a client, meaning that it can set serial
settings, or it may be a server, meaning that it will receive serial
settings from the other end of the connection.

Most serial gensios are client only: serialdev (normal serial port),
ipmisol, and stdio accepter.  Currently only telnet has both client
and server capabilities.


Python Interface
================

NOTE: The python interface described here is deprecated.  Use the one
in c++/swig/pygensio now.

You can access pretty much all of the gensio interface through python,
though it's done a little differently than the C interface.

Since python is fully object oriented, gensios and gensio accepters
are first-class objects, along with gensio_os_funcs, and
waiters.

Here's a small program:

.. code-block:: python

  import gensio

  class Logger:
      def gensio_log(self, level, log):
          print("***%s log: %s" % (level, log))

  class GHandler:
      def __init__(self, o, to_write):
          self.to_write = to_write
          self.waiter = gensio.waiter(o)
          self.readlen = len(to_write)

      def read_callback(self, io, err, buf, auxdata):
          if err:
              print("Got error: " + err)
              return 0
          print("Got data: " + buf);
          self.readlen -= len(buf)
          if self.readlen == 0:
              io.read_cb_enable(False)
              self.waiter.wake()
          return len(buf)

      def write_callback(self, io):
          print("Write ready!")
          if self.to_write:
              written = io.write(self.to_write, None)
              if (written >= len(self.to_write)):
                  self.to_write = None
                  io.write_cb_enable(False)
              else:
                  self.to_write = self.to_write[written:]
          else:
              io.write_cb_enable(False)

      def open_done(self, io, err):
          if err:
              print("Open error: " + err);
              self.waiter.wake()
          else:
              print("Opened!")
              io.read_cb_enable(True)
              io.write_cb_enable(True)

      def wait(self):
          self.waiter.wait_timeout(1, 2000)

  o = gensio.alloc_gensio_selector(Logger())
  h = GHandler(o, "This is a test")
  g = gensio.gensio(o, "telnet,tcp,localhost,2002", h)
  g.open(h)

  h.wait()

The interface is a pretty direct translation from the C interface.  A
python representation of the interface is in swig/python/gensiodoc.py,
you can see that for documentation.

Rust
====

A full rust interface is available at
https://github.com/cminyard/rust-gensio.git

C++
===

The C++ interface is documented in c++/README.rst.

pygensio
========

The new pygensio interface is a cleaner implementation using swig
directors instead of hand-coded callbacks into python.  See the
README.rst in c++/swig/pygensio.  There are also glib and tcl OS_Funcs
in the glib and tcl directories.

GO
===

The full C++ interface is available to Go programs through swig and
swig directors.  See c++/swig/go/README.rst for details.
