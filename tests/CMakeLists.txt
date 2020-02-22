
enable_testing()

add_executable(oomtest oomtest.c)
target_link_libraries(oomtest gensio)

set (top_srcdir "${CMAKE_SOURCE_DIR}")
set (top_builddir "${CMAKE_BINARY_DIR}")
configure_file(runtest.in runtest @ONLY)

add_test(NAME syncio COMMAND runtest test_syncio.py)
add_test(NAME echo COMMAND runtest test_echo_gensio.py)
add_test(NAME echo_device COMMAND runtest test_echo_device.py)
add_test(NAME serial_pipe_device
         COMMAND runtest test_serial_pipe_device.py)
add_test(NAME accept_tcp COMMAND runtest test_accept_tcp.py)
add_test(NAME accept_udp COMMAND runtest test_accept_udp.py)
add_test(NAME accept_sctp COMMAND runtest test_accept_sctp.py)
add_test(NAME accept_ssl_tcp COMMAND runtest test_accept_ssl_tcp.py)
add_test(NAME accept_certauth_tcp
         COMMAND runtest test_accept_certauth_tcp.py)
add_test(NAME accept_mux_sctp COMMAND runtest test_accept_mux_sctp.py)
add_test(NAME telnet COMMAND runtest test_telnet.py)
add_test(NAME modemstate COMMAND runtest test_modemstate.py)
add_test(NAME stdio COMMAND runtest test_stdio_basic.py)
add_test(NAME stdio_stderr COMMAND runtest test_stdio_basic_stderr.py)
add_test(NAME stdio_small COMMAND runtest test_stdio_small.py)
add_test(NAME tcp_small COMMAND runtest test_tcp_small.py)
add_test(NAME tcp_urgent COMMAND runtest test_tcp_urgent.py)
add_test(NAME pty COMMAND runtest test_pty_basic.py)
add_test(NAME sctp_small COMMAND runtest test_sctp_small.py)
add_test(NAME sctp_streams COMMAND runtest test_sctp_streams.py)
add_test(NAME sctp_oob COMMAND runtest test_sctp_oob.py)
add_test(NAME telnet_small COMMAND runtest test_telnet_small.py)
add_test(NAME ipmisol_small COMMAND runtest test_ipmisol_small.py)
add_test(NAME ipmisol_large COMMAND runtest test_ipmisol_large.py)
add_test(NAME rs485 COMMAND runtest test_rs485.py)
add_test(NAME tcp_accept_connect
         COMMAND runtest test_tcp_accept_connect.py)
add_test(NAME udp_accept_connect
         COMMAND runtest test_udp_accept_connect.py)
add_test(NAME sctp_accept_connect
         COMMAND runtest test_sctp_accept_connect.py)
add_test(NAME telnet_sctp_accept_connect
         COMMAND runtest test_telnet_sctp_accept_connect.py)
add_test(NAME ssl_sctp_accept_connect
         COMMAND runtest test_ssl_sctp_accept_connect.py)
add_test(NAME certauth_sctp_accept_connect
         COMMAND runtest test_certauth_sctp_accept_connect.py)
add_test(NAME certauth_ssl_sctp_accept_connect
         COMMAND runtest test_certauth_ssl_sctp_accept_connect.py)
add_test(NAME mux_sctp_small COMMAND runtest test_mux_sctp_small.py)
add_test(NAME mux_tcp_large COMMAND runtest test_mux_tcp_large.py)
add_test(NAME mux_limits COMMAND runtest test_mux_limits.py)
add_test(NAME mux_oob COMMAND runtest test_mux_oob.py)
add_test(NAME relpkt COMMAND runtest test_relpkt_basic.py)
add_test(NAME relpkt_small COMMAND runtest test_relpkt_small.py)
add_test(NAME relpkt_medium COMMAND runtest test_relpkt_medium.py)
add_test(NAME relpkt_large COMMAND runtest test_relpkt_large.py)

add_test(NAME oomtest
         COMMAND runtest oomtest ${PROJECT_BINARY_DIR}/tools/gensiot)

#
# If you get certauth fuzz failures, they will be in the
# fuzz-results-certauth/crashes or fuzz-results-certauth/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand certauth-randfile -i echo 'certauth(CA=ca/clientcert.pem,allow-unencrypted,mode=server),file(infile="fuzz-results-certauth/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
add_custom_target(test_fuzz_certauth
   COMMAND rm -rf fuzz-test-certauth fuzz-results-certauth
   COMMAND mkdir -p fuzz-test-certauth
   COMMAND mkdir -p fuzz-results-certauth
   COMMAND ./runtest test_fuzz_setup.py
		${PROJECT_BINARY_DIR}/tools/gensiot certauth-randfile
		"'certauth(cert=ca/clientcert.pem,key=ca/clientkey.pem,allow-unencrypted)'"
		"'certauth(CA=ca/clientcert.pem,allow-unencrypted)'"
		fuzz-test-certauth/tracefile
   COMMAND afl-fuzz -i fuzz-test-certauth -o fuzz-results-certauth
		-f certauth-infile
		${PROJECT_BINARY_DIR}/tools/gensiot --dummyrand certauth-randfile
		-i echo
		"'certauth(CA=ca/clientcert.pem,allow-unencrypted,mode=server),file(infile=certauth-infile)'"
)

#
# If you get mux fuzz failures, they will be in the
# fuzz-results-mux/crashes or fuzz-results-mux/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand mux-randfile -i echo 'mux(writebuf=10000,mode=server),file(infile="fuzz-results-mux/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
add_custom_target(test_fuzz_mux
   COMMAND rm -rf fuzz-test-mux fuzz-results-mux
   COMMAND mkdir -p fuzz-test-mux
   COMMAND mkdir -p fuzz-results-mux
   COMMAND ./runtest test_fuzz_setup.py
		${PROJECT_BINARY_DIR}/tools/gensiot mux-randfile
		"mux" "mux"
		fuzz-test-mux/tracefile
   COMMAND afl-fuzz -i fuzz-test-mux -o fuzz-results-mux
		-f mux-infile
		${PROJECT_BINARY_DIR}/tools/gensiot --dummyrand mux-randfile
		-i echo
		"'mux,file(infile=mux-infile)'"
)

#
# If you get ssl fuzz failures, they will be in the
# fuzz-results-ssl/crashes or fuzz-results-ssl/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand ssl-randfile -i echo 'ssl(key=ca/key.pem,cert=ca/cert.pem,mode=server),file(infile="fuzz-results-ssl/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
add_custom_target(test_fuzz_ssl
   COMMAND rm -rf fuzz-test-ssl fuzz-results-ssl
   COMMAND mkdir -p fuzz-test-ssl
   COMMAND mkdir -p fuzz-results-ssl
   COMMAND ./runtest test_fuzz_setup.py
		${PROJECT_BINARY_DIR}/tools/gensiot ssl-randfile
		"'ssl(CA=ca/CA.pem)'"
		"'ssl(key=ca/key.pem,cert=ca/cert.pem)'"
		fuzz-test-ssl/tracefile
   COMMAND afl-fuzz -i fuzz-test-ssl -o fuzz-results-ssl
		-f ssl-infile
		${PROJECT_BINARY_DIR}/tools/gensiot --dummyrand ssl-randfile
		-i echo
		"'ssl(key=ca/key.pem,cert=ca/cert.pem,mode=server),file(infile=ssl-infile)'"
)

#
# If you get telnet fuzz failures, they will be in the
# fuzz-results-telnet/crashes or fuzz-results-telnet/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand telnet-randfile -i echo 'telnet(mode=server),file(infile="fuzz-results-telnet/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
add_custom_target(test_fuzz_telnet
   COMMAND rm -rf fuzz-test-telnet fuzz-results-telnet
   COMMAND mkdir -p fuzz-test-telnet
   COMMAND mkdir -p fuzz-results-telnet
   COMMAND ./runtest test_fuzz_setup.py
		${PROJECT_BINARY_DIR}/tools/gensiot telnet-randfile
		"telnet" "telnet"
		fuzz-test-telnet/tracefile
   COMMAND afl-fuzz -i fuzz-test-telnet -o fuzz-results-telnet
		-f telnet-infile
		${PROJECT_BINARY_DIR}/tools/gensiot --dummyrand telnet-randfile
		-i echo
		"'telnet,file(infile=telnet-infile)'"
)

#
# If you get relpkt fuzz failures, they will be in the
# fuzz-results-relpkt/crashes or fuzz-results-relpkt/hangs directories.
# To reproduce the failure, in this directory, run:
#
# ../tools/gensiot --dummyrand relpkt-randfile -i echo 'relpkt(mode=server),file(infile="fuzz-results-relpkt/[hangs|crashes]/<file>")'
#
# where the <file> is the specific failure.
#
add_custom_target(test_fuzz_relpkt
   COMMAND rm -rf fuzz-test-relpkt fuzz-results-relpkt
   COMMAND mkdir -p fuzz-test-relpkt
   COMMAND mkdir -p fuzz-results-relpkt
   COMMAND ./runtest test_fuzz_setup.py
		${PROJECT_BINARY_DIR}/tools/gensiot relpkt-randfile
		"'relpkt,msgdelim(crc=off)'" "'relpkt,msgdelim(crc=off)'"
		fuzz-test-relpkt/tracefile
   COMMAND afl-fuzz -i fuzz-test-relpkt -o fuzz-results-relpkt
		-f relpkt-infile
		${PROJECT_BINARY_DIR}/tools/gensiot --dummyrand relpkt-randfile
		-i echo
		"'relpkt(mode=server),msgdelim(crc=off),file(infile=relpkt-infile)'"
)
