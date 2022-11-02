
AM_CFLAGS = -I$(top_srcdir)/glib/include -I$(top_srcdir)/tcl/include \
	@EXTRA_CFLAGS@

AM_TESTS_ENVIRONMENT = GENSIOT=$(top_builddir)/tools/gensiot${EXEEXT}

LOG_COMPILER = $(SHELL) $(builddir)/runtest

PYTESTS = test_syncio.py \
	test_unix_accept_connect.py test_echo_gensio.py test_echo_device.py \
	test_serial_pipe_device.py test_accept_tcp.py test_accept_udp.py \
	test_accept_sctp.py test_accept_ssl_tcp.py test_accept_certauth_tcp.py \
	test_accept_mux_sctp.py test_telnet.py test_modemstate.py \
	test_stdio_basic.py test_stdio_basic_stderr.py test_stdio_small.py \
	test_tcp_small.py test_tcp_urgent.py test_pty_basic.py \
	test_sctp_small.py test_sctp_streams.py test_sctp_oob.py \
	test_telnet_small.py test_ipmisol_small.py test_ipmisol_large.py \
	test_rs485.py test_tcp_accept_connect.py test_udp_accept_connect.py \
	test_sctp_accept_connect.py test_telnet_sctp_accept_connect.py \
	test_ssl_sctp_accept_connect.py test_certauth_sctp_accept_connect.py \
	test_certauth_ssl_tcp_accept_connect.py test_mux_sctp_small.py \
	test_mux_tcp_large.py test_mux_limits.py test_mux_oob.py \
	test_relpkt_basic.py test_relpkt_small.py test_relpkt_medium.py \
	test_relpkt_large.py test_udp_nocon.py test_conacc.py test_mdns.py \
	test_ipmisol.py test_perf.py test_trace.py test_file.py test_dummy.py \
	test_ax25_small.py test_ax25_basics.py test_script.py test_ratelimit.py

OOMTESTS = oomtest0 oomtest1 oomtest2 oomtest3 oomtest4 oomtest5 oomtest6 \
	oomtest7 oomtest8 oomtest9 oomtest10 oomtest11 oomtest12 oomtest13 \
	oomtest14 oomtest15

TESTS = $(PYTESTS) $(OOMTESTS)

oomtest_SOURCES = oomtest.c

oomtest_LDADD = $(top_builddir)/lib/libgensioosh.la \
	$(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS) \
	@GLIB_LIB@ @GLIB_LIBS@ @TCL_LIB@ @TCL_LIBS@

echotest_SOURCES = echotest.c

check_PROGRAMS = oomtest echotest

EXTRA_DIST = utils.py ipmisimdaemon.py termioschk.py \
	test_fuzz_setup.py make_keys $(PYTESTS) $(OOMTESTS) \
	gensios_enabled.py.in

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
	$(LOG_COMPILER) $(top_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot certauth-randfile \
		'certauth(cert=ca/clientcert.pem,key=ca/clientkey.pem,allow-unencrypted)'\
		'certauth(CA=ca/clientcert.pem,allow-unencrypted)' \
		fuzz-test-certauth/tracefile
	afl-fuzz -T certauth -i fuzz-test-certauth -o fuzz-results-certauth \
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
	$(LOG_COMPILER) $(top_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot mux-randfile \
		'mux' 'mux' fuzz-test-mux/tracefile
	afl-fuzz -T mux -i fuzz-test-mux -o fuzz-results-mux -f mux-infile \
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
	$(LOG_COMPILER) $(top_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot ssl-randfile \
		'ssl(CA=ca/CA.pem)'\
		'ssl(key=ca/key.pem,cert=ca/cert.pem)' \
		fuzz-test-ssl/tracefile
	afl-fuzz -T ssl -i fuzz-test-ssl -o fuzz-results-ssl -f ssl-infile \
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
	$(LOG_COMPILER) $(top_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot telnet-randfile \
		'telnet' 'telnet' fuzz-test-telnet/tracefile
	afl-fuzz -T telnet \
		-i fuzz-test-telnet -o fuzz-results-telnet -f telnet-infile \
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
	$(LOG_COMPILER) $(top_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot relpkt-randfile \
		'relpkt,msgdelim(crc=off)' 'relpkt,msgdelim(crc=off)' fuzz-test-relpkt/tracefile
	afl-fuzz -T relpkt \
		-i fuzz-test-relpkt -o fuzz-results-relpkt -f relpkt-infile \
		$(top_builddir)/tools/gensiot --dummyrand relpkt-randfile \
		-i echo "relpkt(mode=server),msgdelim(crc=off),file(infile=relpkt-infile)"

#
# If you get ax25 fuzz failures, they will be in the
# fuzz-results-ax25/crashes or fuzz-results-ax25/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand ax25-randfile -i echo 'ax25(laddr=test-1),file(infile="fuzz-results-ax25/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
# NOTE: This runs very slowly because of the timeouts.  It's not
# really useful as is.  I need to figure out how to make it run
# faster.
#
test_fuzz_ax25:
	-rm -rf fuzz-test-ax25 fuzz-results-ax25
	mkdir -p fuzz-test-ax25
	mkdir -p fuzz-results-ax25
	$(LOG_COMPILER) $(top_srcdir)/tests/test_fuzz_setup.py \
		$(top_builddir)/tools/gensiot ax25-randfile \
		'ax25(laddr=test-2,addr="0,test-1,test-2"),kiss' \
		'ax25(laddr=test-1),kiss' fuzz-test-ax25/tracefile
	afl-fuzz -T ax25 -t 10000 \
		-i fuzz-test-ax25 -o fuzz-results-ax25 -f ax25-infile \
		$(top_builddir)/tools/gensiot --dummyrand ax25-randfile \
		-i echo "ax25(laddr=test-1,srt=10,t2=20,t3=30,retries=1),kiss,file(infile=ax25-infile)"

test_fuzz: test_fuzz_certauth test_fuzz_mux test_fuzz_ssl test_fuzz_telnet \
	test_fuzz_relpkt test_fuzz_ax25

clean-local:
	-rm -rf ca \
		certauth-randfile fuzz-test-certauth fuzz-results-certauth \
		certauth-infile \
		mux-randfile fuzz-test-mux fuzz-results-mux \
		mux-infile \
		ssl-randfile fuzz-test-ssl fuzz-results-ssl \
		ssl-infile \
		telnet-randfile fuzz-test-telnet fuzz-results-telnet \
		telnet-infile \
		relpkt-randfile fuzz-test-relpkt fuzz-results-relpkt \
		relpkt-infile \
		ax25-randfile fuzz-test-ax25 fuzz-results-ax25 \
		ax25-infile \
		*.log *.trs \
		__pycache__
