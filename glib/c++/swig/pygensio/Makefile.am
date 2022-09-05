
AM_CPPFLAGS = $(PYTHON_CPPFLAGS) \
	-I$(top_srcdir)/glib/c++/include -I$(top_srcdir)/glib/include \
	-I$(top_srcdir)/c++/swig/pygensio/include

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
pythonlib_LTLIBRARIES = _pygensioglib.la

pygensioglib_wrap.cc pygensioglib.py: \
			$(top_srcdir)/c++/swig/include/gensio_base.i \
			$(top_srcdir)/c++/swig/pygensio/pygensio.i \
			$(top_srcdir)/glib/c++/swig/pygensio/pygensioglib.i \
			$(top_srcdir)/c++/include/gensio
	$(SWIG) $(DEFS) -Wall -python $(PYTHON_SWIG_FLAGS) \
		-o pygensioglib_wrap.cc -c++ \
		-I$(top_srcdir)/glib/c++/include \
		-I$(top_srcdir)/c++/swig/include \
		-I$(top_srcdir)/c++/swig/pygensio -I$(top_srcdir)/c++/include \
		-I$(top_srcdir)/include -I$(top_builddir)/include \
		$(top_srcdir)/glib/c++/swig/pygensio/pygensioglib.i

EXTRA_DIST = pygensioglib.i

nodist__pygensioglib_la_SOURCES = pygensioglib_wrap.cc
_pygensioglib_la_LIBADD = $(top_builddir)/c++/lib/libgensiocpp.la \
		$(top_builddir)/lib/libgensio.la $(top_builddir)/glib/libgensioglib.la \
		$(OPENSSL_LIBS) $(PYTHON_LIBS)
_pygensioglib_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS) \
		-no-undefined

clean-local:
	rm -rf __pycache__ pygensioglib_wrap.cc pygensioglib_wrap.h \
		pygensioglib.py

install-exec-local: _pygensioglib.la pygensioglib.py
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) pygensioglib.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall \
		rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_pygensioglib.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/pygensioglib.py"
