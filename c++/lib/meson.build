libgensiooshcpp = library(
    'gensiooshcpp',
    sources: ['gensioosh.cc'],
    include_directories: [top_inc, inc_inc, cplusplus_inc],
    cpp_args: [
        '-DBUILDING_GENSIOOSHCPP_DLL',
    ],
    install: true,
    soversion: soversion,
    link_with: [libgensioosh],
)

pkg.generate(
    libgensiooshcpp,
    name: 'libgensiooshcpp',
    description: 'A C++ wrapper for the gensio library',
)

libgensiocpp = library(
    'gensiocpp',
    sources: ['gensio.cc'],
    include_directories: [top_inc, inc_inc, cplusplus_inc],
    cpp_args: [
        '-DBUILDING_GENSIOCPP_DLL',
    ],
    install: true,
    soversion: soversion,
    link_with: [libgensiooshcpp, libgensioosh, libgensio],
)

pkg.generate(
    libgensiocpp,
    name: 'libgensiocpp',
    description: 'A C++ wrapper for the OS handler library for gensio',
)

libgensiomdnscpp = library(
    'gensiomdnscpp',
    sources: ['gensiomdns.cc'],
    include_directories: [top_inc, inc_inc, cplusplus_inc],
    cpp_args: [
        '-DBUILDING_GENSIOMDNSCPP_DLL',
    ],
    install: true,
    soversion: soversion,
    link_with: [libgensiomdns, libgensiooshcpp, libgensioosh, libgensiocpp],
)
pkg.generate(
    libgensiomdnscpp,
    name: 'libgensiomdnscpp',
    description: 'A C++ wrapper for the gensiolibrary to abstract MDNS interfaces',
)
