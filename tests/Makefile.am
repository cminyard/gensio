
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

#
# If you get certauth fuzz failures, they will be in the
# fuzz-results-certauth/crashes or fuzz-results-certauth/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand randfile -i echo 'certauth(CA=ca/clientcert.pem,allow-unencrypted,mode=server),file(infile=fuzz-results-certauth/[hangs|crashes]/<file>)'
#
# where the <file> is the specific failure.
#
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

#
# If you get mux fuzz failures, they will be in the
# fuzz-results-mux/crashes or fuzz-results-mux/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand randfile -i echo 'mux(writebuf=10000,mode=server),file(infile=fuzz-results-mux/[hangs|crashes]/<file>)'
#
# where the <file> is the specific failure.
#
test_fuzz_mux:
	-rm -rf fuzz-test-mux fuzz-results-mux
	mkdir -p fuzz-test-mux
	mkdir -p fuzz-results-mux
	$(AM_TESTS_ENVIRONMENT) python $(utst_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot randfile \
		'mux' 'mux' fuzz-test-mux/tracefile
	afl-fuzz -i fuzz-test-mux -o fuzz-results-mux \
		$(top_builddir)/tools/gensiot --dummyrand randfile \
		-i echo -a "mux(writebuf=10000),stdio"

#
# If you get ssl fuzz failures, they will be in the
# fuzz-results-ssl/crashes or fuzz-results-ssl/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand randfile -i echo 'ssl(key=ca/key.pem,cert=ca/cert.pem,mode=server),file(infile=fuzz-results-ssl/[hangs|crashes]/<file>)'
#
# where the <file> is the specific failure.
#
test_fuzz_ssl:
	-rm -rf fuzz-test-ssl fuzz-results-ssl
	mkdir -p fuzz-test-ssl
	mkdir -p fuzz-results-ssl
	$(AM_TESTS_ENVIRONMENT) python $(utst_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot randfile \
		'ssl(CA=ca/CA.pem)'\
		'ssl(key=ca/key.pem,cert=ca/cert.pem)' \
		fuzz-test-ssl/tracefile
	afl-fuzz -i fuzz-test-ssl -o fuzz-results-ssl \
		$(top_builddir)/tools/gensiot --dummyrand randfile \
		-i echo -a \
		"ssl(key=ca/key.pem,cert=ca/cert.pem),stdio"

#
# If you get telnet fuzz failures, they will be in the
# fuzz-results-telnet/crashes or fuzz-results-telnet/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand randfile -i echo 'telnet,file(infile=fuzz-results-telnet/[hangs|crashes]/<file>)'
#
# where the <file> is the specific failure.
#
test_fuzz_telnet:
	-rm -rf fuzz-test-telnet fuzz-results-telnet
	mkdir -p fuzz-test-telnet
	mkdir -p fuzz-results-telnet
	$(AM_TESTS_ENVIRONMENT) python $(utst_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot randfile \
		'telnet' 'telnet' fuzz-test-telnet/tracefile
	afl-fuzz -i fuzz-test-telnet -o fuzz-results-telnet \
		$(top_builddir)/tools/gensiot --dummyrand randfile \
		-i echo -a "telnet,stdio"

test_fuzz: test_fuzz_certauth test_fuzz_mux test_fuzz_ssl test_fuzz_telnet

TESTS = test_gensio.py test_syncio.py

EXTRA_DIST = $(TESTS) utils.py ipmisimdaemon.py termioschk.py \
	test_fuzz_setup.py

clean-local:
	-rm -rf ca randfile fuzz-test-certauth fuzz-results-certauth \
		fuzz-test-mux fuzz-results-mux \
		fuzz-test-ssl fuzz-results-ssl
