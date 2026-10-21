
pygensio_test_env = test_env
pygensio_test_env.set('PYTHONPATH', '')
foreach d : ['glib/swig/python', 'tcl/swig/python', 'tests']
    pygensio_test_env.prepend('PYTHONPATH', meson.project_build_root() / d)
endforeach
pygensio_test_env.prepend('PYTHONPATH', meson.current_source_dir())
pygensio_test_env.prepend('PYTHONPATH', meson.project_build_root() / 'c++/swig/pygensio')

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
        python,
        args: [meson.current_source_dir() / t],
        env: pygensio_test_env,
        workdir: meson.current_build_dir(),
        depends: pygensio_test_deps,
        is_parallel: false,
        timeout: 600,
        suite: 'pygensio',
    )
endforeach
