===========================
gensio library
===========================

This directory holds the code for the gensio library proper.

gensio.c
========

gensio.c provides the central interface for all gensios.  The
interface to the raw gensio themselves is through a single function
that takes an operation parameter that specifies what you want to do.
This is a little clunky, sure, but it provides easy forwards and
backwards compatibility.  The interface from the gensio back to the
user is also through a single function that the user provides, again
providing easy forwards and backwards compatibility.  gensio.c
provides pretty much all the user interface, including some helper
functions, the blocking interface, and a few other small things.

gensio_base.c
=============

gensio_base.c provides basic handling for a gensio state machine,
keeping track of if it's in open, close, or opened, or closed, etc.
This is harder than you might imagine, and having a lot of gensios
share this code has been a good thing.  Some gensios use it, and some
do not.  The gensio_base.c code takes a required low-level (ll)
interface (talking to whatever is below the gensio) and an optional
filter, which is used for processing the data going between the user
and the ll.

The interface for gensio_base.c is in the main include directory under
gensio_base.h and is available for users implementing their own
gensios.

Various gensio files
====================

The files name gensio_ll_xxx.c are ll interfaces.  gensio_ll_fd.c is
used by several gensios that deal with sockets and pipe-type things
(tcp, sctp, unix, pty, serialdev).  So, for instance, gensio_sctp.c
sets up the sctp sockets, gensio_base.c provides the state machine,
and gensio_ll_fd.c provides the code for talking to the file
descriptor.  Note that tcp and unix sockets are in the same file:
gensio_net.c  The code was so common that they were merged.

gensio_ll_gensio.c and gensio_ll_fd.c have include files in the main
include directory and are available for users implementing their own
gensios.

The files named gensio_filter_xxx.[ch] are filters.  They all stack on
top of other gensios (read the main documentation if you want to know
about this).  They all use gensio_ll_gensio.c for talking to a child
gensio.  For instance, gensio_ssl.c use gensio_ll_gensio.c for the ll,
gensio_filter_ssl.[ch] for the ssl processing (which in turn uses
openssl) and gensio_base.c provides the state machine handling.

The files name sergensio_xxx.c are gensios that provide a serial
interface class.  The main docs talk about this.

The following gensios use gensio_base.c: certauth, ssl, telnet, tcp,
unix, sctp, serialdev, pty, ipmisol

The following do not:

dummy, echo, file
  These are just too simple to have a meaningful state machine.

udp
  UDP is just too wierd to fit into anything standard.  UDP is
  kind of weird for a stream interface, anyway, but I needed it for
  ser2net.  Tons of users use it.

stdio
  The handling of stderr and having a separate fd for stdin and stdout
  makes it too hard to fit into gensio_ll_fd.c.

mux
  The mux handling is a mix of a base state machine and a state machine
  for each instance.

gensio_acc.c
============

This file implements an accepter state machine to simplify
implementation of an accepter.  It handles the locking and validation
of states so basically, anything that uses only has to do the basic
operations specific to that gensio.  This is used by
gensio_acc_gensio.c, gensio_net.c, and gensio_sctp.c.

gensio_acc_gensio.c
===================

Finally for accepters that stack over other accepter gensios
(certauth, ssl, telnet, mux) use gensio_acc_gensio.c for this
interface.

gensio_class.h
==============

For users implementing their own gensios, gensio_class.h provides the
interface between gensio.c and the connecter/accepters.
