builtin_gensios = []
builtin_gensios_str = '/* Do not edit, created by meson */\n'
foreach g : builtin_gensios
    builtin_gensios_str += '\nINIT_GENSIO(@0@);'.format(g)
endforeach
builtin_gensios_h = custom_target(
    'builtin_gensios.h',
    output: 'builtin_gensios.h',
    capture: true,
    command: ['echo', builtin_gensios_str],
)

libgensioosh_src = files(
    'gensio_addr.c',
    'gensio_addrinfo.c',
    'gensio_ax25_addr.c',
    'gensio_circbuf.c',
    'gensio_osops.c',
    'gensio_osops_env.c',
    'gensio_stdsock.c',
    'utils.c',
)
if target_machine.system() == 'linux'
    libgensioosh_src += files('gensio_unix.c', 'selector.c')
endif
if target_machine.system() == 'windows'
    libgensioosh_src += files('gensio_win.c')
endif

libgensioosh = library(
    'gensioosh',
    sources: libgensioosh_src,
    include_directories: [top_inc, inc_inc],
    c_args: [
        '-DBUILDING_GENSIOOSH_DLL',
        '-DPKG_LIBEXEC="@0@"'.format(gensio_libexec),
    ],
    install: true,
    soversion: soversion,
    dependencies: [found_deps['libsctp'], found_deps['threads'], found_deps['wrap']],
)

pkg.generate(
    libgensioosh,
    name: 'libgensioosh',
    description: 'OS handler library for gensio',
)

libgensiomdns_src = files('avahi_watcher.c', 'mdns.c')
libgensiomdns = library(
    'gensiomdns',
    sources: libgensiomdns_src,
    include_directories: [top_inc, inc_inc],
    c_args: ['-DBUILDING_GENSIOMDNS_DLL'],
    link_with: [libgensioosh],
    dependencies: [found_deps['avahi-client']],
    install: true,
    soversion: soversion,
)
pkg.generate(
    libgensiomdns,
    name: 'libgensiomdns',
    description: 'A gensiolibrary to abstract MDNS interfaces',
)

libgensio_src = files(
    'buffer.c',
    'gensio.c',
    'gensio_acc.c',
    'gensio_acc_gensio.c',
    'gensio_base.c',
    'gensio_ll_fd.c',
    'gensio_ll_gensio.c',
    'sergensio.c',
)

libgensio = library(
    'gensio',
    sources: libgensio_src + [builtin_gensios_h],
    include_directories: [top_inc, inc_inc],
    c_args: ['-DBUILDING_GENSIO_DLL'],
    link_with: [libgensioosh],
    install: true,
    soversion: soversion,
)
pkg.generate(
    libgensio,
    name: 'libgensiomdns',
    description: 'A library to abstract stream I/O like serial port, TCP, telnet, UDP, SSL, IPMI SOL, etc.',
)


dynamic_gensio_rpath = '-rpath "@0@"'.format(gensio_libexec)
dynamic_gensio_ldflags = [
    '-module',
    dynamic_gensio_rpath,
    '-avoid-version',
]

gensios = [
    {'name': 'net', 'enable': gensio_net_enable},
    {'name': 'udp', 'enable': gensio_udp_enable},
    {'name': 'sctp', 'enable': gensio_sctp_enable, 'deps': [found_deps['libsctp']]},
    #    {'name': 'stdio'},
    #    {'name': 'pty'},
    #    {'name': 'dummy'},
    #    {'name': 'conacc'},
    #    {'name': 'serialdev', 'src': ['sergensio_serialdev.c', 'seriallock.c']},
    #    {'name': 'echo'},
    #    {'name': 'file'},
    #    {
    #        'name': 'ipmisol',
    #        'src': ['gensio_ll_ipmisol.c', 'sergensio_ipmisol.c'],
    #        'deps': [found_deps['OpenIPMI']],
    #    },
    #    {'name': 'mdns', 'link': [libgensiomdns]},
    #    {
    #        'name': 'sound',
    #        'src': ['gensio_ll_sound.c', 'gensio_sound.c'],
    #        'deps': [found_deps['alsa']],
    #    },
    #    {'name': 'cm108gpio', 'deps': [found_deps['libudev']]},
    #    {
    #        'name': 'ssl',
    #        'src': ['gensio_ssl.c', 'gensio_filter_ssl.c'],
    #        'deps': [found_deps['openssl']],
    #    },
    #    {
    #        'name': 'certauth',
    #        'src': ['gensio_certauth.c', 'gensio_filter_certauth.c'],
    #        'deps': [found_deps['openssl']],
    #    },
    #    {'name': 'mux'},
    #    {
    #        'name': 'telnet',
    #        'src': ['sergensio_telnet.c', 'gensio_filter_telnet.c', 'telnet.c'],
    #    },
    #    {
    #        'name': 'msgdelim',
    #        'src': ['gensio_filter_msgdelim.c', 'gensio_msgdelim.c'],
    #    },
    #    {'name': 'relpkt', 'src': ['gensio_filter_relpkt.c', 'gensio_relpkt.c']},
    #    {'name': 'trace', 'src': ['gensio_filter_trace.c', 'gensio_trace.c']},
    #    {'name': 'perf', 'src': ['gensio_filter_perf.c', 'gensio_perf.c']},
    #    {'name': 'kiss', 'src': ['gensio_filter_kiss.c', 'gensio_kiss.c']},
    #    {'name': 'ax25'},
    #    {'name': 'xlt', 'src': ['gensio_filter_xlt.c', 'gensio_xlt.c']},
    #    {'name': 'keepopen'},
    #    {'name': 'script', 'src': ['gensio_filter_script.c', 'gensio_script.c']},
    #    {
#        'name': 'ratelimit',
#        'src': ['gensio_filter_ratelimit.c', 'gensio_ratelimit.c'],
#    },
#    {
#        'name': 'afskmdm',
#        'src': ['gensio_filter_afskmdm.c', 'gensio_afskmdm.c'],
#        'deps': [libm_dep],
#    },
]


foreach gensio : gensios
    enable_gensio = gensio.get('enable')
    if gensio_all_enable != 'no'
      enable_gensio = gensio_all_enable
    endif
    if enable_gensio == 'no'
      continue
    endif
    name = gensio.get('name')
    src = gensio.get('src', 'gensio_@0@.c'.format(name))
    deps = gensio.get('deps', [])
    link = gensio.get('link', [])
    link_args = gensio.get('link-args', [])
    if enable_gensio == 'yes'
        static_library(
            'gensio_' + name,
            src,
            include_directories: [top_inc, inc_inc],
            dependencies: [deps],
            link_with: [libgensio, libgensioosh] + link,
            link_args: link_args,
            install: true,
            install_dir: gensio_libexec,
        )
    else
        shared_library(
            'gensio_' + name,
            src,
            include_directories: [top_inc, inc_inc],
            dependencies: [deps],
            link_with: [libgensio, libgensioosh] + link,
            link_args: link_args,
            install: true,
            install_dir: gensio_libexec,
        )
    endif
endforeach
