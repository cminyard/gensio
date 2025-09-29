libgensiotcl = library(
    'gensiotcl',
    sources: ['gensio_tcl.c'],
    include_directories: [top_inc, inc_inc, tcl_inc],
    link_with: [libgensioosh, libgensio],
    dependencies: [found_deps['tcl'], found_deps['openssl']],
    install: true,
    soversion: soversion,
)

pkg.generate(
    libgensiotcl,
    name: 'libgensiotcl',
    description: 'Tcl bindings for gensio',
)
