===========================
gensio - General Stream I/O
===========================

This is gensio (pronounced gen'-see-oh), a framework for giving a
consistent view of various stream (and packet) I/O types.  You create
a gensio object (or a gensio), and you can use that gensio without
having to know too much about what is going on underneath.  You can
stack gensio on top of another one to add protocol funcionality.  For
instance, you can create a TCP gensio, stack SSL on top of that, and
stack Telnet on top of that.  It supports a number of network I/O and
serial ports.  gensios that stack on other gensios are called filters.

You can do the same thing with receiving ports.  You can set up a
gensio accepter (accepter) to accept connections in a stack.  So in
our previous example, you can setup TCP to listen on a specific port
and automatically stack SSL and Telnet on top when the connection
comes in, and you are not informed until everything is ready.

A *very* important feature of gensio is that it makes establishing
encrypted and authenticated connections much easier than without it.
Beyond basic key management, it's really no harder than TCP or
anything else.  It offers extended flexibility for controlling the
authentication process if needed.  It's really easy to use.

Note that the gensio(5) man page has more details on individual gensio
types.

Building
========

This is a normal autoconf system, nothing special.  Note that if you
get this directly from git, you won't have the build infrastructure
included.  There is a script named "reconf" in the main directory
that will create it for you.

If you don't know about autoconf, the INSTALL file has some info,
or google it.

gensio tools
============

A couple of tools are available that use gensios, both as an example
and for trying things out.  These are:

gensiot
    A tool for making basic gensio connections.  You can create any
    arbitrary gensio setup you like.  See gensiot(1) for details.

gtlsshd
    An sshd-like daemon that uses certauth, ssl, and SCTP or TCP
    gensios for making connections.  It uses standard PAM
    authentication and uses ptys.  See gtlsshd(8) for details.

gtlssh
    An ssh-like program that can connect to gtlsshd.  It can also
    be used with ser2net to make establishing encrypted and
    authenticated connections easier.  See gtlssh(1) for details.

Available gensios
=================

The following gensios are available in the library:

sctp
    Normal SCTP communication.  Streams and out of bound data are
    supported.  End of message demarcation is not supported because it
    doesn't currently work on Linux.

tcp
    Normal TCP communication.  Out of bound data is supported.

udp
    Sort-of connection oriented UDP.

stdio
    Access to either the calling program's stdio, or the ability
    to run a program and connect to its stdin, stdout, and stderr.
    NOTE: Do not use this for file I/O.  Use the file gensio.

file
    Used for accessing files.  Allows both input and output file,
    and streams the data to/from the files.  No accepter available.

pty
    Run a program in a PTY and use the gensio to communicate with
    its tty.  No accepter available.

serialdev
    Connect to a device.  It can hook to termios type devices, more
    than just serial ports.  It also has a write-only option for
    talking to printer ports.  No accepter available.

ipmisol
    Connect to a remote over IPMI SOL.  Full serial port capabilities
    are available.  No accepter available, unfortunately.

dummy
    An accepter that doesn't do anything except look like an accepter
    to the user.  Useful in some situations where an accepter is
    expected but you don't need to do anything.

echo
    A gensio that echos everything that is sent to it.  Useful for
    testing.  No accepter available.

telnet
    A filter gensio that implements the telnet protocol.  It can do
    full serial support with RFC2217.

ssl
    Implement SSL/TLS as a gensio filter.  It supports client
    authentication, too.

certauth
    A user authentication protocol implemented as a gensio filter.

mux
    A channel multiplexer.  You can create channels on top of it using
    open_channel().  Channels work as normal gensio, so you can have a
    number of gensios running on top of a single gensio.  It also has
    end-of-message demarcation and obviously full flow-control
    capability individually on each channel.  If you just need a
    gensio with end-of-message demarcation, you can use this as
    without creating channels.

msgdelim
    Converts an unreliable stream interface into an unreliable packet
    interface.  This is primarily so a reliable packet interface like
    relpkt can run over a serial port.  It does not support streaming
    of data, so it's not very useful by itself.

These are all documented in detail in gensio(5).  Unless otherwise
stated, these all are available as accepters or connecting gensios.

You can create your own gensios and register them with the library and
stack them along with the other gensios.

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

sergensio.h
    Serial port handling gensios and gensio accepters.

gensio_os_funcs.h
    The definition for an OS handler.

argvutils.h
    Many gensio functions take an argv array, this is utilities for
    dealing with argvs.

gensio_selector.h
    A definition for a default OS handler.


For creating your own gensios, the following include files are
available for you:

gensio_class.h
    The main include file for creating your own gensio.

sergensio_class.h
    The main include file for creating your own serial port gensio.

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

If an unrecongnized operating system error occurs, GE_OSERR is
returned and a log is reported through the OS handler log interface.

OS Handler
==========

One slightly annoying thing about gensio is that it requires you to
provide an OS handler (struct gensio_os_funcs) to handle OS-type
functions like memory allocation, mutexes, the ability to handle file
descriptors, timers and time, and a few other things.

The library does provide gensio_selector_alloc() that creates a POSIX
based OS handler that should handle what you need for most things.
But if you are using something like Tk, glib, etc that has it's own
event loop, you may need to adapt one for your needs.  But the good
thing is that you can do this, and integrate gensio with pretty much
anything.

There is also a waiter interface that provides a convenient way to
wait for things to occur.  Waiting is generally not required, but it
can be useful in some cases.

Documentation for this is in::

  include/gensio/gensio_os_funcs.h

Creating a gensio
=================

Connecting gensios
------------------

To create a gensio, the general way to do this is to call
``str_to_gensio()`` with a properly formatted string.  The string is
formatted like so::

  <type>[([<option>[,<option[...]]])][,<type>...][,<end option>[,<end option]]

The ``end option`` is for terminal gensios, or ones that are at the
bottom of the stack.  For instance, ``tcp,localhost,3001`` will create
a gensio that connects to port 3001 on localhost.  For a serial port,
an example is ``serialdev,/dev/ttyS0,9600N81`` will create a connection
to the serial port /dev/ttyS0.

This lets you stack gensio layers on top of gensio layers.  For
instance, to layer telnet on top of a TCP connection::

  telnet,tcp,localhost,3001

Say you want to enable RFC2217 on your telnet connection.  You can add
an option to do that::

  telnet(rfc2217=true),tcp,localhost,3001

When you create a gensio, you supply a callback with user data.  When
events happen on a gensio, the callback will be called so the user
could handle it.

gensio accepters
----------------

A gensio accepter is similar to a connecting gensio, but with
``str_to_gensio_accepter()`` instead.  The format is the same.  For
instance::

  telnet(rfc2217=true),tcp,3001

will create a TCP accepter with telnet on top.  For accepters, you
generally do not need to specify the hostname if you want to bind to
all interfaces on the local machine.

Using a gensio
==============

Once you have created a gensio, it's not yet open or operational.  To
use it, you have to open it.  To open it, do::

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

For writing, you can call ``gensio_write()`` to write data.  In
general, you shouldn't arbitrarily call ``gensio_write()``.  You
should call ``gensio_set_write_callback_enable()`` and the gensio will
call the write ready callback and you should write from the callback.

``gensio_write()`` may not take all the data you write to it.  The
``count`` parameter passes back the number of bytes actually taken in
the write call.

In the callbacks, you can get the user data you passed in to the
create call with ``gensio_get_user_data()``.

Note that if you open then immediately close a gensio, this is fine,
even if the open callback hasn't been called.  The open callback may
or may not be called in that case.

Synchronous I/O
---------------

You can do basic synchronous I/O with gensios.  This is useful in some
situations where you need to read something inline.  To do this, call::

  err = gensio_set_sync(io);

The given gensio will cease to deliver read and write events.  Other
events *are* delivered.  Then you can do::

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

Once you are done doing synchronous I/O with a gensio, call::

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
it.  You must call ``gensio_acc_startup()`` to enable it::

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

You can discover if a gensio is a serial port by calling
``gensio_to_sergensio()``.  If that returns NULL, it is not a
sergensio.  If it returns non-NULL, it returns the sergensio object
for you to use.

A sergensio may be a client, meaning that it can set serial settings,
or it may be a server, meaning that it will receive serial settings
from the other end of the connection.

Most sergensios are client only: serialdev (normal serial port),
ipmisol, and stdio accepter.  Currently only telnet has both client
and server capabilities.


Python Interface
================

You can access pretty much all of the gensio interface through python,
though it's done a little differently than the C interface.

Since python is fully object oriented, gensios and gensio accepters
are first-class objects, along with gensio_os_funcs, sergensios, and
waiters.

Here's a small program::

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

=============
Running Tests
=============

There are a number of tests for gensios.  They currently only run on
Linux and require some external tools.

They require the serialsim kernel module and python interface.  These
are at https://github.com/cminyard/serialsim and allow the tests to
use a simulated serial port to read modem control line, inject errors,
etc.

They also require the ipmi_sim program from the OpenIPMI library at
https://github.com/cminyard/openipmi to run the ipmisol tests.
