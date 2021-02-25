
AM_CPPFLAGS = -DBUILDING_GENSIO_DLL -I$(top_srcdir)/c++/include

lib_LTLIBRARIES = libgensiocpp.la

libgensiocpp_la_SOURCES = gensio.cc
libgensiocpp_la_LIBADD = $(top_builddir)/lib/libgensio.la @OPENSSL_LIBS@
libgensiocpp_la_LDFLAGS = -no-undefined -rpath $(libdir)

SUBDIRS = include . tests examples
