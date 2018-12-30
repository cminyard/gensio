===========================
gensio - General Stream I/O
===========================

This is gensio (pronounced gen'-see-oh), a framework for giving a
consistent view of various stream (and packet) I/O types.  You create
a gensio object (or a gensio), and you can use that gensio without
having to know too much about what is going on underneath.  You can
stack gensio on top of another one to add protocol funcionality.  For
instance, you can create a TCP gensio, stack SSL on top of that, and
stack Telnet on top of that.

You can do the same thing with receiving ports.  You can set up a
gensio accepter (accepter) to accept connections in a stack.  So in
our previous example, you can setup TCP to listen on a specific port
and automatically stack SSL and Telnet on top when the connection
comes in, and you are not informed until everything is ready.

General Concepts
================

gensio has an object oriented interface that is event-driven.  You
deal with two main objects in gensio: a gensio and a gensio accepter.
A gensio provides a communication interface where you can connect,
disconnect, write, receive, etc.

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

Creating a gensio
=================

