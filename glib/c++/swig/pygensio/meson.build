pygensioglib_wrap = custom_target(
    'pygensioglib_wrap',
    input: 'pygensioglib.i',
    output: ['pygensioglib_wrap.cc', 'pygensioglib_wrap.h', 'pygensioglib.py'],
    depend_files: files(
        '../../../../c++/swig/include/gensio_base.i',
        '../../../../c++/swig/pygensio/pygensio.i',
    ),
    command: [
        swig, '-Wall', python_swig_flags, '-c++',
        '-o', '@OUTPUT0@', '-outdir', '@OUTDIR@',
        '-I' + meson.project_source_root() / 'glib/c++/include',
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
    '_pygensioglib',
    pygensioglib_wrap[0],
    include_directories: [
        top_inc,
        inc_inc,
        cplusplus_inc,
        pygensio_inc,
        glib_inc,
        include_directories('../../include'),
    ],
    link_with: [libgensiocpp, libgensioglib, libgensio, libgensioosh],
    dependencies: [python_dep, found_deps['glib-2.0']],
    # See c++/swig/pygensio/meson.build.
    gnu_symbol_visibility: 'default',
    install: true,
    install_dir: python_install_dir,
)
