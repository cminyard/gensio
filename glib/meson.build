libgensioglib = library(
    'gensioglib',
    sources: ['gensio_glib.c'],
    include_directories: [top_inc, glib_inc, inc_inc],
    link_with: [libgensioosh, libgensio],
    dependencies: [found_deps['glib-2.0'], found_deps['openssl']],
    install: true,
    soversion: soversion,
)

pkg.generate(
    libgensioglib,
    name: 'libgensioglib',
    description: 'Glib bindings for gensio',
)

install_man('gensio_glib_funcs_alloc.3')

subdir('include/gensio')
