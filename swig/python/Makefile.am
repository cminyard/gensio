
AM_CFLAGS = $(PYTHON_CPPFLAGS) \
	    -I $(top_srcdir)/include \
	    -I$(top_builddir)/include \
	    -I $(top_srcdir) \
	    -DPYTHON_HAS_THREADS=@PYTHON_HAS_THREADS@

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
pythonlib_LTLIBRARIES = _gensio.la

lib_LTLIBRARIES = libgensio_python_swig.la

libgensio_python_swig_la_SOURCES = gensio_python_swig.c
libgensio_python_swig_la_CFLAGS = -DBULDING_DLL $(AM_CFLAGS)
libgensio_python_swig_la_LDFLAGS = -no-undefined
libgensio_python_swig_la_LIBADD = $(PYTHON_LIBS) \
		$(top_builddir)/lib/libgensio.la

noinst_HEADERS = gensio_python.h

gensio_wrap.c gensio.py: $(top_srcdir)/swig/gensio.i \
		$(top_srcdir)/swig/python/gensio_python.h \
		$(top_srcdir)/swig/python/gensio_python.i
	$(SWIG) $(DEFS) -python $(PYTHON_SWIG_FLAGS) -o gensio_wrap.c \
		-I$(top_srcdir)/swig/python -I$(top_srcdir)/include $<

EXTRA_DIST = gensio_python.i CMakeLists.txt libgensio_python_swig.pc.in

pkgconfigexecdir = $(libdir)/pkgconfig
pkgconfigexec_DATA = libgensio_python_swig.pc

nodist__gensio_la_SOURCES = gensio_wrap.c
_gensio_la_LIBADD = $(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS) \
		$(PYTHON_LIBS) libgensio_python_swig.la
_gensio_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS) -no-undefined

clean-local:
	rm -rf __pycache__ gensio_wrap.c gensio.py

install-exec-local: _gensio.la gensio.py
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) gensio.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_gensio.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/gensio.py"
