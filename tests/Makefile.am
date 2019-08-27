
utst_builddir = $(shell readlink -f $(top_builddir))
utst_srcdir = $(shell readlink -f $(top_srcdir))

AM_TESTS_ENVIRONMENT = \
    PYTHONPATH=$(utst_builddir)/swig/python:$(utst_builddir)/tests:$(utst_builddir)/swig/python/.libs:$(utst_builddir)/tests/.libs; export PYTHONPATH; \
    TESTPATH=$(utst_srcdir)/tests; export TESTPATH; \
    if [ ! -e ca ]; then \
	$(utst_srcdir)/tests/make_keys; \
    fi;

test_setup:
	echo $(AM_TESTS_ENVIRONMENT) python $(utst_srcdir)/tests/

TESTS = test_gensio.py test_syncio.py

EXTRA_DIST = $(TESTS) utils.py ipmisimdaemon.py termioschk.py

clean-local:
	rm -rf ca
