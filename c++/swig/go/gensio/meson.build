go_gensio_wrap = custom_target(
    'go_gensio_wrap',
    input: 'gensio.srcswigcxx',
    output: ['gensio_wrap.cxx', 'gensio_wrap.h', 'gensio.go'],
    depend_files: files(
        '../../include/gensio_base.i',
        '../../../../include/gensio/gensio_err.h',
        '../../../../include/gensio/gensio_control.h',
        '../../../../include/gensio/gensio_types.h',
    ),
    command: [
        swig, '-DHAVE_CONFIG_H', '-Wall', '-go', '-intgosize', '64', '-c++',
        '-o', '@OUTPUT0@', '-outdir', '@OUTDIR@',
        '-I' + meson.project_source_root() / 'c++/swig/go',
        '-I' + meson.project_source_root() / 'c++/include',
        '-I' + meson.project_source_root() / 'include',
        '-I' + meson.project_build_root() / 'include',
        '-I' + meson.project_source_root() / 'c++/swig/include',
        '@INPUT@',
    ],
)

configure_file(input: 'gensioapi.srcgo', output: 'gensioapi.go', copy: true)
configure_file(input: 'go.srcmod', output: 'go.mod', copy: true)

# Everything a "go build" of a program using the package depends on
go_gensio_deps = [go_gensio_wrap] + go_libs
