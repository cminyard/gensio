
AM_CFLAGS = $(PYTHON_CPPFLAGS) \
	    -I $(top_srcdir)/include \
	    -I$(top_builddir)/include \
	    -I $(top_srcdir) \
	    -I$(top_srcdir)/tcl/include \
	    -I$(top_srcdir)/swig/include \
	    -DPYTHON_HAS_THREADS=@PYTHON_HAS_THREADS@

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
pythonlib_LTLIBRARIES = _gensiotcl.la

gensiotcl_wrap.c gensiotcl.py: $(top_srcdir)/tcl/swig/gensiotcl.i
	$(SWIG) $(DEFS) -python $(PYTHON_SWIG_FLAGS) -o gensiotcl_wrap.c \
		-I$(top_srcdir)/include -I$(top_srcdir)/swig/include $<

nodist__gensiotcl_la_SOURCES = gensiotcl_wrap.c
_gensiotcl_la_LIBADD = $(top_builddir)/tcl/libgensiotcl.la \
		$(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS) \
		$(PYTHON_LIBS) $(TCL_LIBS) \
		$(top_builddir)/swig/python/libgensio_python_swig.la
_gensiotcl_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS) -no-undefined

clean-local:
	rm -rf __pycache__ gensiotcl_wrap.c gensiotcl.py

install-exec-local: _gensiotcl.la gensiotcl.py
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) gensiotcl.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_gensiotcl.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/gensiotcl.py"
