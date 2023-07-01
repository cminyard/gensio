pygensiotcl_wrap = custom_target(
    'pygensiotcl_wrap',
    input: 'pygensiotcl.i',
    output: ['pygensiotcl_wrap.cc', 'pygensiotcl_wrap.h', 'pygensiotcl.py'],
    depend_files: files(
        '../../../../c++/swig/include/gensio_base.i',
        '../../../../c++/swig/pygensio/pygensio.i',
    ),
    command: [
        swig, '-Wall', python_swig_flags, '-c++',
        '-o', '@OUTPUT0@', '-outdir', '@OUTDIR@',
        '-I' + meson.project_source_root() / 'tcl/c++/include',
        '-I' + meson.project_source_root() / 'c++/swig/include',
        '-I' + meson.project_source_root() / 'c++/swig/pygensio',
        '-I' + meson.project_source_root() / 'c++/include',
        '-I' + meson.project_source_root() / 'include',
        '-I' + meson.project_build_root() / 'include',
        '@INPUT@',
    ],
    install: true,
    install_dir: [false, false, python_install_dir],
)

python.extension_module(
    '_pygensiotcl',
    pygensiotcl_wrap[0],
    include_directories: [
        top_inc,
        inc_inc,
        cplusplus_inc,
        pygensio_inc,
        tcl_inc,
        include_directories('../../include'),
    ],
    link_with: [libgensiocpp, libgensiotcl, libgensio, libgensioosh],
    dependencies: [python_dep, found_deps['tcl']],
    install: true,
    install_dir: python_install_dir,
)
