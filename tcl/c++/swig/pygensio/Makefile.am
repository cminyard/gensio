
AM_CPPFLAGS = $(PYTHON_CPPFLAGS) \
	-I$(top_srcdir)/tcl/c++/include -I$(top_srcdir)/tcl/include \
	-I$(top_srcdir)/c++/swig/pygensio/include

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
pythonlib_LTLIBRARIES = _pygensiotcl.la

pygensiotcl_wrap.cc pygensiotcl.py: \
			$(top_srcdir)/c++/swig/include/gensio_base.i \
			$(top_srcdir)/c++/swig/pygensio/pygensio.i \
			$(top_srcdir)/tcl/c++/swig/pygensio/pygensiotcl.i \
			$(top_srcdir)/c++/include/gensio
	$(SWIG) $(DEFS) -Wall -python $(PYTHON_SWIG_FLAGS) \
		-o pygensiotcl_wrap.cc -c++ \
		-I$(top_srcdir)/tcl/c++/include \
		-I$(top_srcdir)/c++/swig/include \
		-I$(top_srcdir)/c++/swig/pygensio -I$(top_srcdir)/c++/include \
		-I$(top_srcdir)/include -I$(top_builddir)/include \
		$(top_srcdir)/tcl/c++/swig/pygensio/pygensiotcl.i

EXTRA_DIST = pygensiotcl.i

nodist__pygensiotcl_la_SOURCES = pygensiotcl_wrap.cc
_pygensiotcl_la_LIBADD = $(top_builddir)/c++/lib/libgensiocpp.la \
		$(top_builddir)/lib/libgensio.la $(top_builddir)/tcl/libgensiotcl.la \
		$(OPENSSL_LIBS) $(PYTHON_LIBS) $(TCL_LIBS)
_pygensiotcl_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS) \
		-no-undefined

clean-local:
	rm -rf __pycache__ pygensiotcl_wrap.cc pygensiotcl_wrap.h \
		pygensiotcl.py

install-exec-local: _pygensiotcl.la pygensiotcl.py
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) pygensiotcl.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall \
		rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_pygensiotcl.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/pygensiotcl.py"
