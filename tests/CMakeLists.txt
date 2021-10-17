
enable_testing()

add_executable(oomtest oomtest.c)
target_link_libraries(oomtest gensio ${GLIB_LIB} ${GLIB_LDFLAGS}
                      ${TCL_LIB} ${TCL_LIBS})

include_directories("${PROJECT_SOURCE_DIR}/glib/include"
		    "${PROJECT_SOURCE_DIR}/tcl/include")

set (top_srcdir "${CMAKE_SOURCE_DIR}")
set (top_builddir "${CMAKE_BINARY_DIR}")
configure_file(runtest.in runtest @ONLY)
configure_file(gensios_enabled.py.in gensios_enabled.py @ONLY)

add_test(NAME syncio
         COMMAND runtest test_syncio.py)
set_tests_properties(syncio PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME echo
         COMMAND runtest test_echo_gensio.py)
set_tests_properties(echo PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME echo_device
         COMMAND runtest test_echo_device.py)
set_tests_properties(echo_device PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME serial_pipe_device
         COMMAND runtest test_serial_pipe_device.py)
set_tests_properties(serial_pipe_device PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME accept_tcp
         COMMAND runtest test_accept_tcp.py)
set_tests_properties(accept_tcp PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME accept_udp
         COMMAND runtest test_accept_udp.py)
set_tests_properties(accept_udp PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME accept_sctp
         COMMAND runtest test_accept_sctp.py)
set_tests_properties(accept_sctp PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME accept_ssl_tcp
         COMMAND runtest test_accept_ssl_tcp.py)
set_tests_properties(accept_ssl_tcp PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME accept_certauth_tcp
         COMMAND runtest test_accept_certauth_tcp.py)
set_tests_properties(accept_certauth_tcp PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME accept_mux_sctp
         COMMAND runtest test_accept_mux_sctp.py)
set_tests_properties(accept_mux_sctp PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME telnet
         COMMAND runtest test_telnet.py)
set_tests_properties(telnet PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME modemstate
         COMMAND runtest test_modemstate.py)
set_tests_properties(modemstate PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME stdio
         COMMAND runtest test_stdio_basic.py)
set_tests_properties(stdio PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME stdio_stderr
         COMMAND runtest test_stdio_basic_stderr.py)
set_tests_properties(stdio_stderr PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME stdio_small
         COMMAND runtest test_stdio_small.py)
set_tests_properties(stdio_small PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME tcp_small
         COMMAND runtest test_tcp_small.py)
set_tests_properties(tcp_small PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME tcp_urgent
         COMMAND runtest test_tcp_urgent.py)
set_tests_properties(tcp_urgent PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME pty
         COMMAND runtest test_pty_basic.py)
set_tests_properties(pty PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME sctp_small
         COMMAND runtest test_sctp_small.py)
set_tests_properties(sctp_small PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME sctp_streams
         COMMAND runtest test_sctp_streams.py)
set_tests_properties(sctp_streams PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME sctp_oob
         COMMAND runtest test_sctp_oob.py)
set_tests_properties(sctp_oob PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME telnet_small
         COMMAND runtest test_telnet_small.py)
set_tests_properties(telnet_small PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME ipmisol_small
         COMMAND runtest test_ipmisol_small.py)
set_tests_properties(ipmisol_small PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME ipmisol_large
         COMMAND runtest test_ipmisol_large.py)
set_tests_properties(ipmisol_large PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME rs485
         COMMAND runtest test_rs485.py)
set_tests_properties(rs485 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME tcp_accept_connect
         COMMAND runtest test_tcp_accept_connect.py)
set_tests_properties(tcp_accept_connect PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME unix_accept_connect
         COMMAND runtest test_unix_accept_connect.py)
set_tests_properties(unix_accept_connect PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME udp_accept_connect
         COMMAND runtest test_udp_accept_connect.py)
set_tests_properties(udp_accept_connect PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME sctp_accept_connect
         COMMAND runtest test_sctp_accept_connect.py)
set_tests_properties(sctp_accept_connect PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME telnet_sctp_accept_connect
         COMMAND runtest test_telnet_sctp_accept_connect.py)
set_tests_properties(telnet_sctp_accept_connect PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME ssl_sctp_accept_connect
         COMMAND runtest test_ssl_sctp_accept_connect.py)
set_tests_properties(ssl_sctp_accept_connect PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME certauth_sctp_accept_connect
         COMMAND runtest test_certauth_sctp_accept_connect.py)
set_tests_properties(certauth_sctp_accept_connect PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME certauth_ssl_sctp_accept_connect
         COMMAND runtest test_certauth_ssl_sctp_accept_connect.py)
set_tests_properties(certauth_ssl_sctp_accept_connect PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME mux_sctp_small
         COMMAND runtest test_mux_sctp_small.py)
set_tests_properties(mux_sctp_small PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME mux_tcp_large
         COMMAND runtest test_mux_tcp_large.py)
set_tests_properties(mux_tcp_large PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME mux_limits
         COMMAND runtest test_mux_limits.py)
set_tests_properties(mux_limits PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME mux_oob
         COMMAND runtest test_mux_oob.py)
set_tests_properties(mux_oob PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME relpkt
         COMMAND runtest test_relpkt_basic.py)
set_tests_properties(relpkt PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME relpkt_small
         COMMAND runtest test_relpkt_small.py)
set_tests_properties(relpkt_small PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME relpkt_medium
         COMMAND runtest test_relpkt_medium.py)
set_tests_properties(relpkt_medium PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME relpkt_large
         COMMAND runtest test_relpkt_large.py)
set_tests_properties(relpkt_large PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME test_udp_nocon
         COMMAND runtest test_udp_nocon.py)
 set_tests_properties(test_udp_nocon PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME test_perf
         COMMAND runtest test_perf.py)
set_tests_properties(test_perf PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME test_trace
         COMMAND runtest test_trace.py)
set_tests_properties(test_trace PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME test_file
         COMMAND runtest test_file.py)
set_tests_properties(test_file PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME test_dummy
         COMMAND runtest test_dummy.py)
set_tests_properties(test_dummy PROPERTIES SKIP_RETURN_CODE 77)

add_test(NAME oomtest0
         COMMAND runtest oomtest -t 0 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest0 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest1
         COMMAND runtest oomtest -t 1 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest1 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest2
         COMMAND runtest oomtest -t 2 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest2 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest3
         COMMAND runtest oomtest -t 3 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest3 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest4
         COMMAND runtest oomtest -t 4 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest4 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest5
         COMMAND runtest oomtest -t 5 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest5 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest6
         COMMAND runtest oomtest -t 6 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest6 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest7
         COMMAND runtest oomtest -t 7 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest7 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest8
         COMMAND runtest oomtest -t 8 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest8 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest9
         COMMAND runtest oomtest -t 9 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest9 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest10
         COMMAND runtest oomtest -t 10 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest10 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest11
         COMMAND runtest oomtest -t 11 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest11 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest12
         COMMAND runtest oomtest -t 12 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest12 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest13
         COMMAND runtest oomtest -t 13 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest13 PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME oomtest14
         COMMAND runtest oomtest -t 14 ${PROJECT_BINARY_DIR}/tools/gensiot)
set_tests_properties(oomtest14 PROPERTIES SKIP_RETURN_CODE 77)

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
