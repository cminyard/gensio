
AM_CPPFLAGS = -DBUILDING_GENSIOCPP_DLL -I$(top_srcdir)/c++/include

lib_LTLIBRARIES = libgensiocpp.la

libgensiocpp_la_SOURCES = gensio.cc
libgensiocpp_la_LIBADD = $(top_builddir)/lib/libgensio.la @OPENSSL_LIBS@
libgensiocpp_la_LDFLAGS = -no-undefined -rpath $(libdir)

EXTRA_DIST = libgensiocpp.pc.in

# This variable must have 'exec' in its name, in order to be installed
# by 'install-exec' target (instead of default 'install-data')
pkgconfigexecdir = $(libdir)/pkgconfig
pkgconfigexec_DATA = libgensiocpp.pc
