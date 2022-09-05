
lib_LTLIBRARIES = libgensiocpp.la

libgensiocpp_la_SOURCES = gensio.cc
libgensiocpp_la_CPPFLAGS = -DBUILDING_GENSIOCPP_DLL
libgensiocpp_la_LIBADD = $(top_builddir)/lib/libgensio.la
libgensiocpp_la_LDFLAGS = -no-undefined -rpath $(libdir) \
	-version-info 2:0:0 -fvisibility=hidden

# This variable must have 'exec' in its name, in order to be installed
# by 'install-exec' target (instead of default 'install-data')
pkgconfigexecdir = $(libdir)/pkgconfig
pkgconfigexec_DATA = libgensiocpp.pc

EXTRA_LTLIBRARIES =

lib_LTLIBRARIES += libgensiomdnscpp.la
libgensiomdnscpp_la_SOURCES = gensiomdns.cc
libgensiomdnscpp_la_CPPFLAGS = -DBUILDING_GENSIOMDNSCPP_DLL
libgensiomdnscpp_la_LIBADD = libgensiocpp.la \
	$(top_builddir)/lib/libgensiomdns.la
libgensiomdnscpp_la_LDFLAGS = -no-undefined -rpath $(libdir) \
	-version-info 0:0:0 -fvisibility=hidden

pkgconfigexec_DATA += libgensiomdnscpp.pc

EXTRA_DIST = libgensiocpp.pc.in libgensiomdnscpp.pc.in

