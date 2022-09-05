
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib $(SWIG_DIR) $(CPLUSPLUS_DIR) include $(GLIB_DIR) $(TCL_DIR) \
	tests tools examples
if INSTALL_DOC
SUBDIRS += man
endif

DIST_SUBDIRS = lib swig c++ include glib tcl tests tools examples man

EXTRA_DIST = README.rst reconf

# Set distcheck up so python files get installed someplace that will
# work, and enable internal trace so oomtest will work.
AM_DISTCHECK_CONFIGURE_FLAGS=--enable-internal-trace \
	--with-pythoninstall=$(abs_top_builddir)/$(distdir)/_inst/lib/python \
	--with-pythoninstalllib=$(abs_top_builddir)/$(distdir)/_inst/lib/python
