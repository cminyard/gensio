
AM_CPPFLAGS = -DBUILDING_GENSIOTCL_DLL
AM_CFLAGS = -I$(top_srcdir)/tcl/include @EXTRA_CFLAGS@

lib_LTLIBRARIES = libgensiotcl.la

libgensiotcl_la_SOURCES = gensio_tcl.c
libgensiotcl_la_CFLAGS = $(TCL_CFLAGS) $(AM_CFLAGS)
libgensiotcl_la_LIBADD = $(top_builddir)/lib/libgensio.la @OPENSSL_LIBS@ \
	@TCL_LIBS@
libgensiotcl_la_LDFLAGS = -no-undefined -rpath $(libdir) \
	-version-info $(GENSIO_LIB_VERSION) -fvisibility=hidden

SUBDIRS = . $(SWIG_DIR) include $(CPLUSPLUS_DIR)
DIST_SUBDIRS = swig include c++

# This variable must have 'exec' in its name, in order to be installed
# by 'install-exec' target (instead of default 'install-data')
pkgconfigexecdir = $(libdir)/pkgconfig
pkgconfigexec_DATA = libgensiotcl.pc

if INSTALL_DOC
man3_MANS = gensio_tcl_funcs_alloc.3
endif

EXTRA_DIST = libgensiotcl.pc.in $(man3_MANS)
