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

