
noinst_pythonlibdir=$(PYTHON_INSTALL_LIB_DIR)
noinst_pythonlib_LTLIBRARIES = _remote_termios.la

# For some reason automake doesn't respect the noinst_ on the above,
# force it to not install.
install-noinst_pythonlibLTLIBRARIES:
uninstall-noinst_pythonlibLTLIBRARIES:

AM_CFLAGS = $(PYTHON_CPPFLAGS) \
	    -I $(top_srcdir)
	    -I $(top_srcdir)/include \
	    -DPYTHON_HAS_POSIX_THREADS=@PYTHON_HAS_POSIX_THREADS@

utst_builddir = $(shell readlink -f $(top_builddir))
utst_srcdir = $(shell readlink -f $(top_srcdir))

remote_termios_wrap.c remote_termios.py: remote_termios.i
	$(SWIG) $(DEFS) -python $(PYTHON_SWIG_FLAGS) -o remote_termios_wrap.c \
	$<

nodist__remote_termios_la_SOURCES = remote_termios_wrap.c remote_termios.c
_remote_termios_la_LIBADD = $(top_builddir)/lib/libgensio.la
_remote_termios_la_LDFLAGS = -module -avoid-version

AM_TESTS_ENVIRONMENT = PYTHONPATH=$(utst_builddir)/swig/python:$(utst_builddir)/tests:$(utst_builddir)/swig/python/.libs:$(utst_builddir)/tests/.libs TESTPATH=$(utst_srcdir)/tests

clean-local:
	rm -rf __pycache__ remote_termios_wrap.c

test_setup:
	echo $(AM_TESTS_ENVIRONMENT) python $(utst_srcdir)/tests/

TESTS = test_gensio.py

EXTRA_DIST = $(TESTS) utils.py ipmisimdaemon.py termioschk.py \
	CA.pem cert.pem key.pem remote_termios.i
