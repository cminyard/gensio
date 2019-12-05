
utst_builddir = $(shell readlink -f $(top_builddir))
utst_srcdir = $(shell readlink -f $(top_srcdir))

AM_TESTS_ENVIRONMENT = \
    PYTHONPATH=$(utst_builddir)/swig/python:$(utst_builddir)/tests:$(utst_builddir)/swig/python/.libs:$(utst_builddir)/tests/.libs; export PYTHONPATH; \
    TESTPATH=$(utst_srcdir)/tests; export TESTPATH; \
    if [ ! -e ca ]; then \
	$(utst_srcdir)/tests/make_keys; \
    fi;

test_setup:
	echo "$(AM_TESTS_ENVIRONMENT) python $(utst_srcdir)/tests/"

test_fuzz_certauth:
	-rm -rf fuzz-test-certauth fuzz-results-certauth
	mkdir -p fuzz-test-certauth
	mkdir -p fuzz-results-certauth
	$(AM_TESTS_ENVIRONMENT) python $(utst_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot randfile \
		'certauth(cert=ca/clientcert.pem,key=ca/clientkey.pem,allow-unencrypted),stdio'\
		'certauth(CA=ca/clientcert.pem,allow-unencrypted),stdio' \
		fuzz-test-certauth/tracefile
	afl-fuzz -i fuzz-test-certauth -o fuzz-results-certauth \
		$(top_builddir)/tools/gensiot --dummyrand randfile \
		-i echo -a \
		"certauth(CA=ca/clientcert.pem,allow-unencrypted),stdio"

test_fuzz: test_fuzz_certauth

TESTS = test_gensio.py test_syncio.py

EXTRA_DIST = $(TESTS) utils.py ipmisimdaemon.py termioschk.py \
	test_fuzz_setup.py

clean-local:
	-rm -rf ca randfile fuzz-test-certauth fuzz-results-certauth
