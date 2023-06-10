========================================
pygensio - A python interface for gensio
========================================

This part of the package provides a Python interface for gensio using
the swig tool.  It uses the C++ interface to generate a binding,
though it does a lot of work on that binding to make it work properly
with Python.

This is a replacement for the original python interface based upon C.
The original interafce is a little easier to use, but it's not nearly
as maintainable.  That creates it's own interface for the callbacks,
which is messy and non-portable.  This binding uses swig directors to
handle the callbacks, and it's less than half the size of the previous
one and much cleaner.
