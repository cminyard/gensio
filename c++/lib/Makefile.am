
lib_LTLIBRARIES = libgensiooshcpp.la libgensiocpp.la

pkgconfigexecdir = $(libdir)/pkgconfig

libgensiooshcpp_la_SOURCES = gensioosh.cc
libgensiooshcpp_la_CPPFLAGS = -DBUILDING_GENSIOOSHCPP_DLL
libgensiooshcpp_la_LIBADD = $(top_builddir)/lib/libgensioosh.la
libgensiooshcpp_la_LDFLAGS = -no-undefined -rpath $(libdir) \
	-version-info $(GENSIO_LIB_VERSION) -fvisibility=hidden
pkgconfigexec_DATA = libgensiooshcpp.pc

libgensiocpp_la_SOURCES = gensio.cc
libgensiocpp_la_CPPFLAGS = -DBUILDING_GENSIOCPP_DLL
libgensiocpp_la_LIBADD = libgensiooshcpp.la $(top_builddir)/lib/libgensio.la
libgensiocpp_la_LDFLAGS = -no-undefined -rpath $(libdir) \
	-version-info $(GENSIO_LIB_VERSION) -fvisibility=hidden

# This variable must have 'exec' in its name, in order to be installed
# by 'install-exec' target (instead of default 'install-data')
pkgconfigexec_DATA += libgensiocpp.pc

lib_LTLIBRARIES += libgensiomdnscpp.la
libgensiomdnscpp_la_SOURCES = gensiomdns.cc
libgensiomdnscpp_la_CPPFLAGS = -DBUILDING_GENSIOMDNSCPP_DLL
libgensiomdnscpp_la_LIBADD = libgensiooshcpp.la \
	$(top_builddir)/lib/libgensiomdns.la
libgensiomdnscpp_la_LDFLAGS = -no-undefined -rpath $(libdir) \
	-version-info $(GENSIO_LIB_VERSION) -fvisibility=hidden

pkgconfigexec_DATA += libgensiomdnscpp.pc

EXTRA_DIST = libgensiooshcpp.pc.in libgensiocpp.pc.in libgensiomdnscpp.pc.in
