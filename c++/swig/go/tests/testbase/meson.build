configure_file(
    input: go_mod_in,
    output: 'go.mod',
    configuration: {
        'MODULE': 'testbase',
        'REQUIRE': '\t' + go_mod_name + go_mod_ver,
        'REPLACE': '\t' + go_mod_name + ' => ../../gensio',
    },
)
configure_file(input: 'testbase.srcgo', output: 'testbase.go', copy: true)
