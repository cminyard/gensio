
AM_CFLAGS = $(PYTHON_CPPFLAGS) \
	    -I $(top_srcdir)/include \
	    -I$(top_builddir)/include \
	    -I $(top_srcdir) \
	    -I$(top_srcdir)/glib/include \
	    -I$(top_srcdir)/swig/include \
	    -DPYTHON_HAS_THREADS=@PYTHON_HAS_THREADS@

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
pythonlib_LTLIBRARIES = _gensioglib.la

gensioglib_wrap.c gensioglib.py: $(top_srcdir)/glib/swig/gensioglib.i
	$(SWIG) $(DEFS) -python $(PYTHON_SWIG_FLAGS) -o gensioglib_wrap.c \
		-I$(top_srcdir)/include -I$(top_srcdir)/swig/include \
		$(top_srcdir)/glib/swig/gensioglib.i

nodist__gensioglib_la_SOURCES = gensioglib_wrap.c
_gensioglib_la_LIBADD = $(top_builddir)/glib/libgensioglib.la \
		$(top_builddir)/lib/libgensio.la \
		$(top_builddir)/lib/libgensioosh.la \
		$(OPENSSL_LIBS) \
		$(top_builddir)/swig/python/libgensio_python_swig.la \
		$(PYTHON_UNDEF_LIBS)
_gensioglib_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS) \
		$(PYTHON_UNDEF_FLAG) $(PYTHON_EXT_EXT_SET)

clean-local:
	rm -rf __pycache__ gensioglib_wrap.c gensioglib.py

install-exec-local: _gensioglib.la gensioglib.py
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) gensioglib.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_gensioglib.$(PYTHON_EXT_EXT)"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/gensioglib.py"
