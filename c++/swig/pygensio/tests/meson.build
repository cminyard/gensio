# Tests for the C++ python bindings, run through runtest like the
# tests in the top level tests directory.

pygensio_runtest = configure_file(
    input: 'runtest.in',
    output: 'runtest',
    configuration: tests_conf,
)

pygensio_test_deps = []
if openssl_prog.found()
    pygensio_test_deps += custom_target(
        'pygensio-test-keys',
        output: 'ca.stamp',
        command: [
            sh, '-c',
            'cd "@0@" && "@1@/tests/make_keys" >/dev/null 2>&1 && touch ca.stamp'.format(
                meson.current_build_dir(), meson.project_source_root()),
        ],
        build_by_default: false,
    )
endif

foreach t : ['test_basic.py', 'test_ax25.py', 'test_crypto.py',
             'test_mdns.py', 'test_serial.py']
    test(
        t,
        sh,
        args: [pygensio_runtest, t],
        env: test_env,
        workdir: meson.current_build_dir(),
        depends: pygensio_test_deps,
        is_parallel: false,
        timeout: 600,
        suite: 'pygensio',
    )
endforeach
