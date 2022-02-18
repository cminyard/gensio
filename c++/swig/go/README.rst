======================
Go Bindings for gensio
======================

This document describes the Go gensio module for providing access to
the gensio library from Go.  It is based upon the C++ interface, but
is heavily wrapped to properly handle garbage collecting data and
provide Go-like naming for the classes and methods.  You will still
need to refer to the C++ interface for some documentation.

The Go module is implemented with swig, which provides a "raw"
interface to the gensio library.  Most of the "classes" are modified
to be prefixed with Raw.  With that interface, objects created from it
are not garbage collected, and some of them have unfriendly
interfaces.

To provide a nicer interface, a wrapper is done that allows the object
to be garbage collected by the system and provides a more friendly
go-like interface.  Unfortunately, this comes with some restrictions,
but not nearly as many as what comes with the swig interface.

Building with Gensio for Go
===========================

To use this, you must download, build, and install a current version
of gensio, version 2.4.0-rc2 or later.  Assuming you don't already
have it installed from your distro.  Make sure to run 'ldconfig' after
installing new libraries!  You can get gensio from git at
https://github.com/cminyard/gensio or downloads of tarballs are
available at https://sourceforge.net/projects/ser2net/files/ser2net/

After all this, add:

  .. code-block:: go
  import "github.com/cminyard/go/gensio"

to your imports in your go program, run go mod tidy to download it,
and you should be in business.

If you install gensio in a non-standard location, say the default
/usr/local, you might have to set some environment variables so "go
build" can find gensio.  These would be:

  .. code-block:: bash
  export CGO_LDFLAGS='-L/usr/local/lib -lgensiocpp -lgensio'
  export CGO_CXXFLAGS='-I/usr/local/include'

See the gensio library itself in the c++/swig/go directory for
examples and tests.

Basic Go Binding Concepts
=========================

The binding provides three types of objects:

Basic Objects
   These are Time, OSFuncs, and Waiter objects.  These are structs
   that you allocate with NewTime(), NewOsFuncs(), and NewWaiter
   functions the return pointers to the objects.

Interface Objects
   These are Gensio, Accepter, and MDNS objects, also allocated with
   New<type>().  The New routine returns an interface that you use to
   interact with the object.  SerialGensio is also an interface
   object, but you cannot allocate it.  If you allocate a gensio with
   NewGensio() and the top gensio is a serial one, it will return a
   Gensio interface that can be cast to a SerialGensio interface.
   MDNSWatch and MDNSService are also interface objects, but are
   allocated via methods on an MDNS object.

Callback Object
   These are Logger, Event, SerialEvent, GensioOpenDone,
   GensioCloseDone, SerialOpDone, SerialOpSigDone, AccepterEvent,
   AccepterShutdownDone, AccepterEnableDone, MDNSFreeDone,
   MDNSWatchFreeDone, and MDNSWatchEvent.  These are all for the
   gensio library informing the user that things have happened in the
   system.

For callback objects, a struct type with the same name ending in
"Base" is provided.  This *must* be the first item in your structure
that receives the callback event.  When you pass the callback object
to a function that uses it, it configures it and sets it up to be
garbage collected and cleaned up properly.

Note that you cannot reuse a callback object.

Here's an example:

  .. code-block:: go
  type OpenDone struct {
      gensio.GensioOpenDoneBase
      err int
      w *gensio.Waiter
  }

  func (oh *OpenDone) OpenDone(err int) {
      oh.err = err
      oh.w.Wake()
  }

  func OpenIt(g Gensio) {
      oh := &OpenDone{}
      oh.w = gensio.NewWaiter(o)
      g.Open(oh)
      rv := oh.w.Wait(1, gensio.Time(1, 0))
      if rv != 0 {
          panic("Error waiting for open: " + gensio.ErrToStr(rv))
      }
      if oh.err != 0 {
          panic("Error from open: " + gensio.ErrToStr(oh.err))
      }
      ...
  }

Obviously this is pretty close to what OpenS() would do, but it
illustrates how this interface is used.

The functions and types are all documented in the gensioapi.go file,
see that for details on the individual functions and types.
