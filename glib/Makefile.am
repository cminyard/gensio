
AM_CFLAGS = -DBUILDING_IPMI_DLL

lib_LTLIBRARIES = @GLIB_TARGET@
EXTRA_LTLIBRARIES = libgensioglib.la

libgensioglib_la_SOURCES = gensio_glib.c
libgensioglib_la_CFLAGS = $(GLIB_CFLAGS) $(AM_CFLAGS)
libgensioglib_la_LIBADD = $(top_builddir)/lib/libgensio.la @OPENSSL_LIBS@ \
	@GLIB_LIBS@
libgensioglib_la_LDFLAGS = -no-undefined -rpath $(libdir)

EXTRA_DIST = libgensioglib.pc.in

SUBDIRS = . $(SWIG_DIR)
DIST_SUBDIRS = swig

# This variable must have 'exec' in its name, in order to be installed
# by 'install-exec' target (instead of default 'install-data')
pkgconfigexecdir = $(libdir)/pkgconfig
pkgconfigexec_DATA = libgensioglib.pc
