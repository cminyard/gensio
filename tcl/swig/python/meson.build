gensiotcl_wrap = custom_target(
    'gensiotcl_wrap',
    input: '../gensiotcl.i',
    output: ['gensiotcl_wrap.c', 'gensiotcl.py'],
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
    '_gensiotcl',
    gensiotcl_wrap[0],
    include_directories: [top_inc, inc_inc, tcl_inc, swig_inc],
    c_args: ['-DPYTHON_HAS_THREADS=1'],
    link_with: [libgensiotcl, libgensio, libgensioosh, libgensio_python_swig],
    dependencies: [python_dep, found_deps['tcl']],
    install: true,
    install_dir: python_install_dir,
)
