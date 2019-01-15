
AM_CFLAGS = $(PYTHON_CPPFLAGS) \
	    -I $(top_srcdir)/include \
	    -I $(top_srcdir) \
	    -DPYTHON_HAS_POSIX_THREADS=@PYTHON_HAS_POSIX_THREADS@

pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
PYPATH=$(top_builddir)/swig/python:$(top_builddir)/swig/python/.libs
pythonlib_LTLIBRARIES = _gensio.la _remote_termios.la

noinst_HEADERS = gensio_python.h

gensio_wrap.c gensio.py: $(top_srcdir)/swig/gensio.i \
		$(top_srcdir)/swig/python/gensio_python.h \
		$(top_srcdir)/swig/python/gensio_python.i
	$(SWIG) $(DEFS) -python $(PYTHON_SWIG_FLAGS) -o gensio_wrap.c \
		-I$(top_srcdir)/swig/python $<

EXTRA_DIST = gensio_python.i remote_termios.i

nodist__gensio_la_SOURCES = gensio_wrap.c
_gensio_la_LIBADD = $(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS)
_gensio_la_LDFLAGS = -module -avoid-version $(OPENSSL_LDFLAGS)

remote_termios_wrap.c remote_termios.py: remote_termios.i
	$(SWIG) $(DEFS) -python $(PYTHON_SWIG_FLAGS) -o remote_termios_wrap.c \
	$<

nodist__remote_termios_la_SOURCES = remote_termios_wrap.c
_remote_termios_la_SOURCES = remote_termios.c
_remote_termios_la_LIBADD = $(top_builddir)/lib/libgensio.la
_remote_termios_la_LDFLAGS = -module -avoid-version

clean-local:
	rm -rf __pycache__ gensio_wrap.c gensio.py remote_termios_wrap.c \
		remote_termios.py*

install-exec-local: _gensio.la gensio.py
	$(INSTALL) -d $(DESTDIR)$(PYTHON_INSTALL_DIR)
	$(INSTALL_DATA) gensio.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"
	$(INSTALL_DATA) remote_termios.py "$(DESTDIR)$(PYTHON_INSTALL_DIR)"

uninstall-local:
	$(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)$(PYTHON_INSTALL_LIB_DIR)/_gensio.so"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/gensio.py"
	rm -f "$(DESTDIR)$(PYTHON_INSTALL_DIR)/remote_termios.py"
