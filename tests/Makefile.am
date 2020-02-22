
AM_CFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include

utst_builddir = $(shell readlink -f $(top_builddir))
utst_srcdir = $(shell readlink -f $(top_srcdir))

AM_TESTS_ENVIRONMENT = \
    PYTHONPATH=$(utst_builddir)/swig/python:$(utst_builddir)/tests:$(utst_builddir)/swig/python/.libs:$(utst_builddir)/tests/.libs; export PYTHONPATH; \
    TESTPATH=$(utst_srcdir)/tests; export TESTPATH; \
    if [ ! -e ca ]; then \
	$(utst_srcdir)/tests/make_keys; \
    fi; GENSIOT=$(top_builddir)/tools/gensiot PYTHON=$(PYTHON)

test_setup:
	echo "$(AM_TESTS_ENVIRONMENT) $(utst_srcdir)/tests/"

#
# If you get certauth fuzz failures, they will be in the
# fuzz-results-certauth/crashes or fuzz-results-certauth/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand certauth-randfile -i echo 'certauth(CA=ca/clientcert.pem,allow-unencrypted,mode=server),file(infile="fuzz-results-certauth/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
test_fuzz_certauth:
	-rm -rf fuzz-test-certauth fuzz-results-certauth
	mkdir -p fuzz-test-certauth
	mkdir -p fuzz-results-certauth
	$(AM_TESTS_ENVIRONMENT) $(PYTHON) $(utst_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot certauth-randfile \
		'certauth(cert=ca/clientcert.pem,key=ca/clientkey.pem,allow-unencrypted)'\
		'certauth(CA=ca/clientcert.pem,allow-unencrypted)' \
		fuzz-test-certauth/tracefile
	afl-fuzz -i fuzz-test-certauth -o fuzz-results-certauth \
		-f certauth-infile \
		$(top_builddir)/tools/gensiot --dummyrand certauth-randfile \
		-i echo \
		"certauth(CA=ca/clientcert.pem,allow-unencrypted,mode=server),file(infile=certauth-infile)"

#
# If you get mux fuzz failures, they will be in the
# fuzz-results-mux/crashes or fuzz-results-mux/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand mux-randfile -i echo 'mux(writebuf=10000,mode=server),file(infile="fuzz-results-mux/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
test_fuzz_mux:
	-rm -rf fuzz-test-mux fuzz-results-mux
	mkdir -p fuzz-test-mux
	mkdir -p fuzz-results-mux
	$(AM_TESTS_ENVIRONMENT) $(PYTHON) $(utst_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot mux-randfile \
		'mux' 'mux' fuzz-test-mux/tracefile
	afl-fuzz -i fuzz-test-mux -o fuzz-results-mux -f mux-infile \
		$(top_builddir)/tools/gensiot --dummyrand mux-randfile \
		-i echo \
		"mux(writebuf=10000,mode=server),file(infile=mux-infile)"

#
# If you get ssl fuzz failures, they will be in the
# fuzz-results-ssl/crashes or fuzz-results-ssl/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand ssl-randfile -i echo 'ssl(key=ca/key.pem,cert=ca/cert.pem,mode=server),file(infile="fuzz-results-ssl/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
test_fuzz_ssl:
	-rm -rf fuzz-test-ssl fuzz-results-ssl
	mkdir -p fuzz-test-ssl
	mkdir -p fuzz-results-ssl
	$(AM_TESTS_ENVIRONMENT) $(PYTHON) $(utst_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot ssl-randfile \
		'ssl(CA=ca/CA.pem)'\
		'ssl(key=ca/key.pem,cert=ca/cert.pem)' \
		fuzz-test-ssl/tracefile
	afl-fuzz -i fuzz-test-ssl -o fuzz-results-ssl -f ssl-infile \
		$(top_builddir)/tools/gensiot --dummyrand ssl-randfile \
		-i echo \
		"ssl(key=ca/key.pem,cert=ca/cert.pem,mode=server),file(infile=ssl-infile)"

#
# If you get telnet fuzz failures, they will be in the
# fuzz-results-telnet/crashes or fuzz-results-telnet/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand telnet-randfile -i echo 'telnet(mode=server),file(infile="fuzz-results-telnet/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
test_fuzz_telnet:
	-rm -rf fuzz-test-telnet fuzz-results-telnet
	mkdir -p fuzz-test-telnet
	mkdir -p fuzz-results-telnet
	$(AM_TESTS_ENVIRONMENT) $(PYTHON) $(utst_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot telnet-randfile \
		'telnet' 'telnet' fuzz-test-telnet/tracefile
	afl-fuzz -i fuzz-test-telnet -o fuzz-results-telnet -f telnet-infile \
		$(top_builddir)/tools/gensiot --dummyrand telnet-randfile \
		-i echo "telnet(mode=server),file(infile=telnet-infile)"

#
# If you get relpkt fuzz failures, they will be in the
# fuzz-results-relpkt/crashes or fuzz-results-relpkt/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand relpkt-randfile -i echo 'relpkt(mode=server),file(infile="fuzz-results-relpkt/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
test_fuzz_relpkt:
	-rm -rf fuzz-test-relpkt fuzz-results-relpkt
	mkdir -p fuzz-test-relpkt
	mkdir -p fuzz-results-relpkt
	$(AM_TESTS_ENVIRONMENT) $(PYTHON) $(utst_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot relpkt-randfile \
		'relpkt,msgdelim(crc=off)' 'relpkt,msgdelim(crc=off)' fuzz-test-relpkt/tracefile
	afl-fuzz -i fuzz-test-relpkt -o fuzz-results-relpkt -f relpkt-infile \
		$(top_builddir)/tools/gensiot --dummyrand relpkt-randfile \
		-i echo "relpkt(mode=server),msgdelim(crc=off),file(infile=relpkt-infile)"

test_fuzz: test_fuzz_certauth test_fuzz_mux test_fuzz_ssl test_fuzz_telnet \
	test_fuzz_relpkt

oomtest_SOURCES = oomtest.c

oomtest_LDADD = $(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS)

noinst_PROGRAMS = oomtest

TESTS = test_gensio test_syncio oomtest

EXTRA_DIST = test_gensio test_syncio utils.py ipmisimdaemon.py termioschk.py \
	test_fuzz_setup.py make_keys test_gensio.py test_syncio.py

clean-local:
	-rm -rf ca \
		certauth-randfile fuzz-test-certauth fuzz-results-certauth \
		certauth-infile \
		mux-randfile fuzz-test-mux fuzz-results-mux \
		mux-infile \
		ssl-randfile fuzz-test-ssl fuzz-results-ssl \
		ssl-infile \
		telnet-randfile fuzz-test-telnet fuzz-results-telnet \
		telnet-infile
