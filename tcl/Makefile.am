
AM_CFLAGS = -DBUILDING_GENSIO_DLL -I$(top_srcdir)/tcl/include \
	 -I$(top_srcdir)/swig/include

lib_LTLIBRARIES = libgensiotcl.la

libgensiotcl_la_SOURCES = gensio_tcl.c
libgensiotcl_la_CFLAGS = $(GLIB_CFLAGS) $(AM_CFLAGS) $(TCL_CFLAGS)
libgensiotcl_la_LIBADD = $(top_builddir)/lib/libgensio.la @OPENSSL_LIBS@ \
	@GLIB_LIBS@
libgensiotcl_la_LDFLAGS = -no-undefined -rpath $(libdir)

SUBDIRS = . $(SWIG_DIR) include
DIST_SUBDIRS = swig include

# This variable must have 'exec' in its name, in order to be installed
# by 'install-exec' target (instead of default 'install-data')
pkgconfigexecdir = $(libdir)/pkgconfig
pkgconfigexec_DATA = libgensiotcl.pc

if INSTALL_DOC
man3_MANS = gensio_tcl_funcs_alloc.3
endif

EXTRA_DIST = libgensiotcl.pc.in CMakeLists.txt $(man3_MANS)
