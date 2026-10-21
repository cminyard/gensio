
pygensio_test_env = test_env
pygensio_test_env.set('GENSIO_MEMTRACK', 'abort')
pygensio_test_env.set('PYTHONPATH', '')
# The glib and tcl OS handlers come from pygensioglib and pygensiotcl.
foreach d : ['glib/c++/swig/pygensio', 'tcl/c++/swig/pygensio', 'tests']
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
    t_suite = ['pygensio']
    if t.contains('mdns')
	# Don't run MDNS on github actions
        t_suite += 'mdns'
	t_suite += 'nogithub'
    endif
    # os_handlers comes from tests/meson.build
    foreach h : os_handlers
        env = pygensio_test_env
        env.set('GENSIO_TEST_OS_HANDLER', h)
        test(
            h == 'default' ? t : t + '-' + h,
            python,
            args: [meson.current_source_dir() / t],
            env: env,
            workdir: meson.current_build_dir(),
            depends: pygensio_test_deps,
            is_parallel: false,
            timeout: 600,
            suite: t_suite + [h],
        )
    endforeach
endforeach
