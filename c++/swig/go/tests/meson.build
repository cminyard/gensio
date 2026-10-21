subdir('testbase')

configure_file(
    input: go_mod_in,
    output: 'go.mod',
    configuration: {
        'MODULE': 'tests',
        'REQUIRE': '\n'.join(['\t' + go_mod_name + go_mod_ver,
                              '\ttestbase' + go_mod_ver]),
        'REPLACE': '\n'.join(['\t' + go_mod_name + ' => ../gensio',
                              '\ttestbase => ./testbase']),
    },
)

go_test_deps = []
if openssl_prog.found()
    go_test_deps += custom_target(
        'go-test-keys',
        output: 'ca.stamp',
        command: [
            go_sh, '-c',
            'cd "@0@" && "@1@/tests/make_keys" >/dev/null 2>&1 && touch ca.stamp'.format(
                meson.current_build_dir(), meson.project_source_root()),
        ],
        build_by_default: false,
    )
endif

foreach t : ['test_basic', 'test_ax25', 'test_crypto', 'test_serial',
             'test_mdns', 'test_netifs']
    configure_file(input: 'src' + t + '.go', output: t + '.go', copy: true)
    go_test = custom_target(
        'go_' + t,
        output: t,
        command: go_build + [meson.current_build_dir(), '-o', t, t + '.go'],
        depends: go_gensio_deps,
        depend_files: files('src' + t + '.go', 'testbase/testbase.srcgo'),
        env: go_env,
        build_by_default: true,
    )
    go_exe = go_test
    if meson.version().version_compare('<1.10.0')
        # Older version of meson don't support using custom_target() as
	# a test executable.  Use an old hack that doesn't work in
	# newer versions.
        go_exe = files([go_test.full_path()])[0]
    endif
    t_suite = ['go']
    if t.contains('mdns')
	# Don't run MDNS on github actions
        t_suite += 'mdns'
	t_suite += 'nogithub'
    endif
    test(
        t,
        go_exe,
        env: test_env,
        workdir: meson.current_build_dir(),
        depends: go_test_deps + [go_test],
        is_parallel: false,
        timeout: 600,
        suite: t_suite,
    )
endforeach
