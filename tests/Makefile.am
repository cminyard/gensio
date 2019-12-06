
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
		'certauth(cert=ca/clientcert.pem,key=ca/clientkey.pem,allow-unencrypted)'\
		'certauth(CA=ca/clientcert.pem,allow-unencrypted)' \
		fuzz-test-certauth/tracefile
	afl-fuzz -i fuzz-test-certauth -o fuzz-results-certauth \
		$(top_builddir)/tools/gensiot --dummyrand randfile \
		-i echo -a \
		"certauth(CA=ca/clientcert.pem,allow-unencrypted),stdio"

test_fuzz_mux:
	-rm -rf fuzz-test-mux fuzz-results-mux
	mkdir -p fuzz-test-mux
	mkdir -p fuzz-results-mux
	$(AM_TESTS_ENVIRONMENT) python $(utst_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot randfile \
		'mux' 'mux' fuzz-test-mux/tracefile
	afl-fuzz -i fuzz-test-mux -o fuzz-results-mux \
		$(top_builddir)/tools/gensiot --dummyrand randfile \
		-i echo -a "mux,stdio"

test_fuzz: test_fuzz_certauth test_fuzz_mux

TESTS = test_gensio.py test_syncio.py

EXTRA_DIST = $(TESTS) utils.py ipmisimdaemon.py termioschk.py \
	test_fuzz_setup.py

clean-local:
	-rm -rf ca randfile fuzz-test-certauth fuzz-results-certauth \
		 fuzz-test-mux fuzz-results-mux
