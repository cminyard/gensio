# The tests are run through runtest, which sets up the paths to the
# python modules and libraries and runs each test with every available
# OS handler.  See the check target in Makefile.am.

tests_conf = configuration_data()
tests_conf.set('top_srcdir', meson.project_source_root())
tests_conf.set('top_builddir', meson.project_build_root())
# runtest is a shell script, so no backslashes in the path on Windows.
tests_conf.set('PYTHON_EXECUTABLE',
               python.found() ? python.full_path().replace('\\', '/') : '')
tests_conf.set('GLIB_DIR', found_deps['glib-2.0'].found() ? 'glib' : '')
tests_conf.set('TCL_DIR', found_deps['tcl'].found() ? 'tcl' : '')
foreach d : ['HAVE_LIBSCTP', 'HAVE_MDNS', 'HAVE_OPENIPMI', 'HAVE_OPENSSL',
             'HAVE_PTSNAME_R', 'HAVE_PTY', 'HAVE_UCRED']
    tests_conf.set(d, conf.get(d, 0))
endforeach

runtest = configure_file(
    input: 'runtest.in',
    output: 'runtest',
    configuration: tests_conf,
)
configure_file(
    input: 'gensios_enabled.py.in',
    output: 'gensios_enabled.py',
    configuration: tests_conf,
)
# Used by test_ax25_basics.py
configure_file(
    input: 'reflector.py.in',
    output: 'reflector.py',
    configuration: tests_conf,
)

sh = find_program('sh')
openssl_prog = find_program('openssl', required: false)

oomtest_link = [libgensioosh, libgensio]
oomtest_deps = osh_libs + [ssl_main_dep]
if found_deps['glib-2.0'].found()
    oomtest_link += libgensioglib
    oomtest_deps += found_deps['glib-2.0']
endif
if found_deps['tcl'].found()
    oomtest_link += libgensiotcl
    oomtest_deps += found_deps['tcl']
endif
oomtest = executable(
    'oomtest',
    'oomtest.c',
    include_directories: [top_inc, inc_inc, glib_inc, tcl_inc],
    link_with: oomtest_link,
    dependencies: oomtest_deps,
    build_by_default: false,
)
# Used by test_script.py
echotest = executable(
    'echotest',
    'echotest.c',
    build_by_default: false,
)

# The ssl and certauth tests need keys, make_keys puts them into ./ca.
test_deps = [oomtest, echotest]
if openssl_prog.found()
    test_deps += custom_target(
        'test-keys',
        output: 'ca.stamp',
        command: [
            sh, '-c',
            'cd "@0@" && "@1@/make_keys" >/dev/null 2>&1 && touch ca.stamp'.format(
                meson.current_build_dir(), meson.current_source_dir()),
        ],
        build_by_default: false,
    )
endif

python_tests = [
    'test_syncio.py', 'test_unix_accept_connect.py', 'test_echo_gensio.py',
    'test_echo_device.py', 'test_serial_pipe_device.py', 'test_accept_tcp.py',
    'test_accept_udp.py', 'test_accept_sctp.py', 'test_accept_ssl_tcp.py',
    'test_accept_certauth_tcp.py', 'test_accept_mux_tcp.py', 'test_telnet.py',
    'test_modemstate.py', 'test_stdio_basic.py', 'test_stdio_basic_stderr.py',
    'test_stdio_small.py', 'test_tcp_small.py', 'test_tcp_urgent.py',
    'test_pty_basic.py', 'test_sctp_small.py', 'test_sctp_streams.py',
    'test_sctp_oob.py', 'test_telnet_small.py', 'test_ipmisol_small.py',
    'test_ipmisol_large.py', 'test_rs485.py', 'test_tcp_accept_connect.py',
    'test_udp_accept_connect.py', 'test_sctp_accept_connect.py',
    'test_telnet_tcp_accept_connect.py', 'test_ssl_tcp_accept_connect.py',
    'test_certauth_tcp_accept_connect.py',
    'test_certauth_ssl_tcp_accept_connect.py', 'test_mux_tcp_small.py',
    'test_mux_tcp_large.py', 'test_mux_limits.py', 'test_mux_oob.py',
    'test_relpkt_basic.py', 'test_relpkt_small.py', 'test_relpkt_medium.py',
    'test_relpkt_large.py', 'test_udp_nocon.py', 'test_conacc.py',
    'test_mdns.py', 'test_ipmisol.py', 'test_perf.py', 'test_trace.py',
    'test_file.py', 'test_dummy.py', 'test_ax25_small.py',
    'test_ax25_basics.py', 'test_script.py', 'test_ratelimit.py',
    'test_parmlog.py', 'test_serial_break.py', 'test_chardelay.py',
]

oom_tests = []
foreach i : range(16)
    oom_tests += 'oomtest@0@'.format(i)
endforeach

test_env = environment()
test_env.set('GENSIOT', meson.project_build_root() / 'tools/gensiot')
test_env.set('VERBOSE', '1')
# The module loader only takes modules from LD_LIBRARY_PATH in libtool's
# lib/.libs, so point it at the meson build directory explicitly.
test_env.set('GENSIO_LIBRARY_PATH', meson.project_build_root() / 'lib')
if is_windows
    # Windows finds DLLs (and the gensio modules) through PATH.
    foreach d : ['lib', 'glib', 'tcl', 'swig/python', 'c++/lib',
                 'c++/swig/pygensio', 'glib/c++/swig/pygensio',
                 'tcl/c++/swig/pygensio']
        test_env.prepend('PATH', meson.project_build_root() / d)
    endforeach
endif

all_tests = oom_tests
if have_python_swig
    all_tests = python_tests + oom_tests
endif

foreach t : all_tests
    test(
        t,
        sh,
        args: [runtest, t],
        env: test_env,
        workdir: meson.current_build_dir(),
        depends: test_deps,
        is_parallel: false,
        timeout: 600,
        suite: t.startswith('oomtest') ? 'oom' : 'python',
    )
endforeach
