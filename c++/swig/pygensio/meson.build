pygensio_inc = include_directories('include')
install_headers('include/gensio/pygensio.h', subdir: 'gensio')

pygensio_wrap = custom_target(
    'pygensio_wrap',
    input: 'pygensio.i',
    output: ['pygensio_wrap.cc', 'pygensio_wrap.h', 'pygensio.py'],
    depend_files: files('../include/gensio_base.i'),
    command: [
        swig, '-Wall', python_swig_flags, '-c++',
        '-o', '@OUTPUT0@', '-outdir', '@OUTDIR@',
        '-I' + meson.current_source_dir(),
        '-I' + meson.project_source_root() / 'c++/include',
        '-I' + meson.project_source_root() / 'include',
        '-I' + meson.project_build_root() / 'include',
        '-I' + meson.project_source_root() / 'c++/swig/include',
        '@INPUT@',
    ],
    install: true,
    install_dir: [false, false, python_install_dir],
)

python.extension_module(
    '_pygensio',
    pygensio_wrap[0],
    include_directories: [top_inc, inc_inc, cplusplus_inc, pygensio_inc],
    link_with: [
        libgensiooshcpp,
        libgensiocpp,
        libgensiomdnscpp,
        libgensioosh,
        libgensio,
        libgensiomdns,
    ],
    dependencies: [python_dep],
    install: true,
    install_dir: python_install_dir,
)
