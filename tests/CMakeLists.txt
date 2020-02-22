
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
