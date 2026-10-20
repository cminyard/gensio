configure_file(
    input: go_mod_in,
    output: 'go.mod',
    configuration: {
        'MODULE': 'examples',
        'REQUIRE': '\t' + go_mod_name + go_mod_ver,
        'REPLACE': '\t' + go_mod_name + ' => ../gensio',
    },
)

foreach e : ['example', 'telnet_server', 'telnet_client']
    configure_file(input: 'src' + e + '.go', output: e + '.go', copy: true)
    custom_target(
        'go_' + e,
        output: e,
        command: go_build + [meson.current_build_dir(), '-o', e, e + '.go'],
        depends: go_gensio_deps,
        depend_files: files('src' + e + '.go'),
        env: go_env,
        build_by_default: true,
    )
endforeach
