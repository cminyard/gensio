libgensiotcl = library(
    'gensiotcl',
    sources: ['gensio_tcl.c'],
    c_args: ['-DBUILDING_GENSIOTCL_DLL'],
    include_directories: [top_inc, inc_inc, tcl_inc],
    link_with: [libgensioosh, libgensio],
    dependencies: [found_deps['tcl'], found_deps['openssl']],
    install: true,
    soversion: soversion,
    version: libversion,
)

pkg.generate(
    libgensiotcl,
    name: 'libgensiotcl',
    description: 'Tcl bindings for gensio',
)

install_headers(
    'include/gensio/gensio_tcl.h',
    'include/gensio/gensio_tcl_dllvisibility.h',
    subdir: 'gensio',
)
if get_option('cplusplus')
    install_headers('c++/include/gensio/gensiotcl', subdir: 'gensio')
endif
