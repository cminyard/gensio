
SUBDIRS = include tests

AM_CPPFLAGS = $(PYTHON_CPPFLAGS) -I$(top_srcdir)/c++/swig/pygensio/include

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
pythonlib_LTLIBRARIES = _pygensio.la

pygensio_wrap.cc pygensio.py: pygensio.i $(top_srcdir)/c++/include/gensio \
			$(top_srcdir)/c++/swig/include/gensio_base.i \
			$(top_srcdir)/include/gensio/gensio_err.h \
			$(top_srcdir)/include/gensio/gensio_control.h \
			$(top_srcdir)/include/gensio/gensio_types.h
	$(SWIG) $(DEFS) -Wall -python $(PYTHON_SWIG_FLAGS) \
		-o pygensio_wrap.cc -c++ \
		-I$(top_srcdir)/c++/swig/pygensio -I$(top_srcdir)/c++/include \
		-I$(top_srcdir)/include \
		-I$(top_builddir)/include -I$(top_srcdir)/c++/swig/include \
		$(top_srcdir)/c++/swig/pygensio/pygensio.i

EXTRA_DIST = pygensio.i

nodist__pygensio_la_SOURCES = pygensio_wrap.cc
_pygensio_la_LIBADD = $(top_builddir)/c++/lib/libgensiooshcpp.la \
		$(top_builddir)/c++/lib/libgensiocpp.la \
		$(top_builddir)/c++/lib/libgensiomdnscpp.la \
		$(top_builddir)/lib/libgensioosh.la \
		$(top_builddir)/lib/libgensio.la \
		$(top_builddir)/lib/libgensiomdns.la \
		$(PYTHON_LIBS)
_pygensio_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS) -no-undefined

clean-local:
	rm -rf __pycache__ pygensio_wrap.cc pygensio_wrap.h pygensio.py

install-exec-local: _pygensio.la pygensio.py
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) pygensio.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_pygensio.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/pygensio.py"
