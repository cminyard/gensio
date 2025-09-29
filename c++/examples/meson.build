executable(
    'mdns',
    'mdns.cc',
    link_with: [
        libgensiomdnscpp,
        libgensiooshcpp,
        libgensioosh,
        libgensio,
    ],
    include_directories: [top_inc, inc_inc, cpp_inc],
    install: false,
)

executable(
    'telnet_client',
    'telnet_client.cc',
    link_with: [
        libgensiooshcpp,
        libgensioosh,
        libgensiocpp,
        libgensio,
    ],
    include_directories: [top_inc, inc_inc, cpp_inc],
    install: false,
)

executable(
    'telnet_server',
    'telnet_server.cc',
    link_with: [
        libgensiooshcpp,
        libgensioosh,
        libgensiocpp,
        libgensio,
    ],
    include_directories: [top_inc, inc_inc, cpp_inc],
    install: false,
)
