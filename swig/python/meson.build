swig_inc = include_directories('../include')
python_swig_inc = include_directories('.')

libgensio_python_swig = library(
    'gensio_python_swig',
    sources: ['gensio_python_swig.c'],
    include_directories: [top_inc, inc_inc, swig_inc],
    c_args: ['-DBUILDING_GENSIO_DLL', '-DPYTHON_HAS_THREADS=1'],
    link_with: [libgensio, libgensioosh, libgensiomdns],
    dependencies: [python_lib_dep],
    # The python symbols are provided by the interpreter that loads this
    override_options: ['b_lundef=false'],
    install: true,
    soversion: soversion,
    version: libversion,
)
pkg.generate(
    libgensio_python_swig,
    name: 'libgensio_python_swig',
    description: 'Python helper functions for the gensio swig bindings',
)

gensio_wrap = custom_target(
    'gensio_wrap',
    input: '../gensio.i',
    output: ['gensio_wrap.c', 'gensio.py'],
    depend_files: files('gensio_python.h', 'gensio_langinfo.i'),
    command: [
        swig, python_swig_flags,
        '-o', '@OUTPUT0@', '-outdir', '@OUTDIR@',
        '-I' + meson.current_source_dir(),
        '-I' + meson.project_source_root() / 'include',
        '-I' + meson.project_build_root() / 'include',
        '-I' + meson.project_source_root() / 'swig/include',
        '@INPUT@',
    ],
    install: true,
    install_dir: [false, python_install_dir],
)

python.extension_module(
    '_gensio',
    gensio_wrap[0],
    include_directories: [top_inc, inc_inc, swig_inc, python_swig_inc],
    c_args: ['-DPYTHON_HAS_THREADS=1'],
    link_with: [libgensio_python_swig, libgensio, libgensioosh, libgensiomdns],
    dependencies: [python_dep],
    install: true,
    install_dir: python_install_dir,
)
