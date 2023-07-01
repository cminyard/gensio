gensioglib_wrap = custom_target(
    'gensioglib_wrap',
    input: '../gensioglib.i',
    output: ['gensioglib_wrap.c', 'gensioglib.py'],
    command: [
        swig, python_swig_flags,
        '-o', '@OUTPUT0@', '-outdir', '@OUTDIR@',
        '-I' + meson.project_source_root() / 'include',
        '-I' + meson.project_source_root() / 'swig/include',
        '@INPUT@',
    ],
    install: true,
    install_dir: [false, python_install_dir],
)

python.extension_module(
    '_gensioglib',
    gensioglib_wrap[0],
    include_directories: [top_inc, inc_inc, glib_inc, swig_inc],
    c_args: ['-DPYTHON_HAS_THREADS=1'],
    link_with: [libgensioglib, libgensio, libgensioosh, libgensio_python_swig],
    dependencies: [python_dep, found_deps['glib-2.0']],
    install: true,
    install_dir: python_install_dir,
)
