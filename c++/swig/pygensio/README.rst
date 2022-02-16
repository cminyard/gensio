==========================
Python Bindings for gensio
==========================

This document describes the pygensio module for Python.  It provides
access to the gensio library.  It is based on the C++ interface, and
you will need to refer to that for some documentation.  This covers
the Python-specific parts of the interface.

This is a replacement for the original python interface based upon C.
The original intergace is a little easier to use, but it's not nearly
as maintainable.  That creates it's own interface for the callbacks,
which is messy and non-portable.  This binding uses swig directors to
handle the callbacks, and it's less than half the size of the previous
one and much cleaner.

Using pygensio basics
=====================

The names from the C++ interface are not modified, so this works much
like the C++ interface.  To allocate a os handler and waiter, you
would do something like:

  .. code-block:: python

  class Logger(pygensio.Os_Funcs_Log_Handler):
      def __init__(self):
          pygensio.Os_Funcs_Log_Handler.__init__(self)
          return

      def log(self, level, s):
          print("Log")
          try:
              print(pygensio.log_level_to_str(level).upper() + " LOG: " +
                    s.encode('utf-8', 'surrogateescape').decode('ISO-8859-1'))
          except:
              print("Log error")
          return

  l = Logger()
  o = pygensio.Os_Funcs(0, l);

The funky encode/decode thing avoids issues with strange characters in
the log causing the logging to crash.

Also notice the __init__ function calls the parent's __init__
function.  You *must* do this for all callback objects or bad things
will happen; the swig director code needs this for some reason.  Like
a minimal gensio event handler for reflecting data and waking a waiter
when the read side closed would be:

  .. code-block:: python
  class My_EvHnd(pygensio.Event):
      def __init__(self, w):
          pygensio.Event.__init__(self)
	  self.data = None
          self.g = None
	  self.waiter = w
          return

      def set_gensio(self, g):
          self.g = g
          return

      def read(self, err, data, auxdata):
          self.g.set_read_callback_enable(False)
          if err != 0:
              if err != pygensio.GE_REMCLOSE:
                  raise Exception("Error from event read: " +
                                  pygensio.err_to_string(err))
              self.g = None
              self.waiter.wake()
              return 0
          self.data = data
          self.g.set_write_callback_enable(True)
          return len(data)

      def write_ready(self):
          if self.data is None:
              self.g.set_write_callback_enable(False)
              return
	  try:
             count = self.g.write(self.data, None)
	  except:
	      self.g = None
	      self.data = None
              self.waiter.wake()
	      raise
          if count == len(self.data):
              self.data = None
              self.g.set_write_callback_enable(False)
              self.g.set_read_callback_enable(True)
          else:
              self.data = self.data[count:]
          return

This example shows quite a bit of things, including full error
handling, so it's a good starting place for writing event handlers.

Allocating Gensios and Accepters
================================

Gensios are allocated using gensio_alloc(), just like C++:

  .. code-block:: python
  w = pygensio.Waiter(o)
  handler = My_EvHnd(w)
  g = pygensio.gensio_alloc("tcp,localhost,1234", o, handler)
  handler.set_gensio(g)

Unlike C++, you use Python garbage collection to free gensios.  You can do
this when they are active and it's fine:

  .. code-block:: python
  del g

The gensio will be closed and freed.  The bindings handle all this
under the hood.  Of course, callbacks may still be pending.  To do a
controlled shutdown, you can, of course, close the gensio before
freeing it.

Accepters work the same way.

Other Python Issues
===================

When creating a callback object, can really only implement one
pygensio object.  Two might work, but I never got three to work, and
anything more than one is questionable.  That's somewhat annoying, but
it probably leads to cleaner design than mashing all the handlers into
one class.
