libgensioosh_src = files(
    'circbuf.c',
    'net_addr.c',
    'net_addrinfo.c',
    'net_ax25_addr.c',
    'net_stdsock.c',
    'os_osops.c',
    'os_osops_env.c',
    'utils.c',
)
if target_machine.system() == 'windows'
    libgensioosh_src += files('os_win.c')
else
    libgensioosh_src += files('os_unix.c', 'os_unix_selector.c')
endif
if get_option('internal-trace')
    libgensioosh_src += files('errtrig.c')
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
    version: libversion,
    dependencies: [found_deps['libsctp'], found_deps['threads'], found_deps['wrap']] + osh_libs,
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
    dependencies: [found_deps['avahi-client']] + mdns_libs,
    install: true,
    soversion: soversion,
    version: libversion,
)
pkg.generate(
    libgensiomdns,
    name: 'libgensiomdns',
    description: 'A gensiolibrary to abstract MDNS interfaces',
)

if found_deps['OpenIPMI'].found()
    libgensio_openipmi_oshandler = library(
        'gensio_openipmi_oshandler',
        sources: ['gensio_openipmi_oshandler.c'],
        c_args: ['-DBUILDING_GENSIO_OI_OSH_DLL'],
        include_directories: [top_inc, inc_inc],
        link_with: [libgensioosh],
        dependencies: [found_deps['OpenIPMI']],
        install: true,
        soversion: soversion,
        version: libversion,
    )
endif

libgensio_src = files(
    'acc.c',
    'acc_gensio.c',
    'buffer.c',
    'gensio.c',
    'gensio_base.c',
    'll_2gensio.c',
    'll_fd.c',
    'll_gensio.c',
)

is_windows = target_machine.system() == 'windows'

# Each gensio may be built into libgensio ('yes'), built as a dynamically
# loaded module ('dynamic') or not built at all ('no').  'requires' tells
# whether the dependencies of the gensio are available.
gensios = [
    {'name': 'net'},
    {'name': 'dgram'},
    {
        'name': 'sctp',
        'deps': [found_deps['libsctp']],
        'requires': found_deps['libsctp'].found(),
    },
    {'name': 'stdio'},
    {'name': 'pty'},
    {'name': 'dummy'},
    {'name': 'conacc'},
    {'name': 'serialdev', 'src': ['sergensio_serialdev.c', 'seriallock.c']},
    {'name': 'echo'},
    {'name': 'file'},
    {
        'name': 'ipmisol',
        'src': ['sergensio_ipmisol.c'],
        'deps': [found_deps['OpenIPMI']],
        'link': found_deps['OpenIPMI'].found() ? [libgensio_openipmi_oshandler] : [],
        'requires': found_deps['OpenIPMI'].found(),
    },
    {
        'name': 'mdns',
        'link': [libgensiomdns],
        'requires': conf.get('HAVE_MDNS') == 1,
    },
    {
        'name': 'sound',
        'deps': [found_deps['alsa'], found_deps['portaudio-2.0']] + sound_libs,
    },
    {
        'name': 'cm108gpio',
        'deps': [found_deps['libudev']] + cm108gpio_libs,
        'requires': found_deps['libudev'].found() or is_windows,
    },
    {
        'name': 'ssl',
        'deps': [found_deps['openssl']],
        'requires': found_deps['openssl'].found(),
    },
    {
        'name': 'certauth',
        'deps': [found_deps['openssl']],
        'requires': found_deps['openssl'].found(),
    },
    {'name': 'mux'},
    {'name': 'telnet', 'src': ['sergensio_telnet.c', 'telnet.c']},
    {'name': 'msgdelim'},
    {'name': 'relpkt'},
    {'name': 'trace'},
    {'name': 'perf'},
    {'name': 'kiss'},
    {'name': 'ax25'},
    {'name': 'xlt'},
    {'name': 'keepopen'},
    {'name': 'script'},
    {'name': 'ratelimit'},
    {'name': 'chardelay'},
    {'name': 'iosplit'},
    {'name': 'fsk', 'deps': [libm_dep]},
    {'name': 'hdlc'},
    {'name': 'axfec', 'src': ['gensio_axfec.c', 'convcode.c']},
    {
        'name': 'soapy',
        'src': ['gensio_soapy.c', 'convcode.c'],
        'deps': [found_deps['SoapySDR']],
        'requires': found_deps['SoapySDR'].found(),
    },
    {'name': 'convcode', 'src': ['gensio_convcode.c', 'convcode.c']},
]

# If not creating shared libraries, build everything in.
all_gensios = get_option('all-gensios')
if all_gensios == 'auto'
    if get_option('default_library') == 'static'
        all_gensios = 'yes'
    else
        all_gensios = 'dynamic'
    endif
endif

builtin_gensios = []
builtin_gensios_src = []
builtin_gensios_deps = []
builtin_gensios_link = []
dynamic_gensios = []

foreach gensio : gensios
    name = gensio.get('name')
    mode = get_option('gensio-' + name)
    if mode == 'default'
        mode = all_gensios
        if not gensio.get('requires', true)
            mode = 'no'
        endif
    elif mode != 'no' and not gensio.get('requires', true)
        error('gensio @0@ enabled but its dependencies were not found'.format(name))
    endif

    if mode == 'yes'
        builtin_gensios += name
        foreach f : gensio.get('src', ['gensio_@0@.c'.format(name)])
            if f not in builtin_gensios_src
                builtin_gensios_src += f
            endif
        endforeach
        builtin_gensios_deps += gensio.get('deps', [])
        builtin_gensios_link += gensio.get('link', [])
    elif mode == 'dynamic'
        dynamic_gensios += gensio
    endif
endforeach

builtin_gensios_str = ''
foreach g : builtin_gensios
    builtin_gensios_str += 'INIT_GENSIO(@0@);\n'.format(g)
endforeach
builtin_conf = configuration_data()
builtin_conf.set('BUILTIN_GENSIOS', builtin_gensios_str)
builtin_gensios_h = configure_file(
    input: 'builtin_gensios.h.in',
    output: 'builtin_gensios.h',
    configuration: builtin_conf,
)

libgensio = library(
    'gensio',
    sources: libgensio_src + files(builtin_gensios_src) + [builtin_gensios_h],
    include_directories: [top_inc, inc_inc],
    c_args: ['-DBUILDING_GENSIO_DLL'],
    link_with: [libgensioosh] + builtin_gensios_link,
    dependencies: builtin_gensios_deps,
    install: true,
    soversion: soversion,
    version: libversion,
)
pkg.generate(
    libgensio,
    name: 'libgensio',
    description: 'A library to abstract stream I/O like serial port, TCP, telnet, UDP, SSL, IPMI SOL, etc.',
)

if is_windows
    gensio_module_dir = get_option('bindir')
else
    gensio_module_dir = gensio_libexec
endif

dynamic_gensio_names = []
foreach gensio : dynamic_gensios
    name = gensio.get('name')
    dynamic_gensio_names += name
    shared_module(
        'gensio_' + name,
        gensio.get('src', ['gensio_@0@.c'.format(name)]),
        name_prefix: 'lib',
        include_directories: [top_inc, inc_inc],
        dependencies: gensio.get('deps', []),
        link_with: [libgensio, libgensioosh] + gensio.get('link', []),
        install: true,
        install_dir: gensio_module_dir,
    )
endforeach

summary({
    'Built-in gensios': builtin_gensios,
    'Dynamic gensios': dynamic_gensio_names,
}, section: 'gensios', list_sep: ' ')
