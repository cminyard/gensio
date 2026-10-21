libgensiotool = static_library(
    'gensiotool',
    sources: ['ioinfo.c', 'ser_ioinfo.c', 'utils.c', 'localports.c'],
    include_directories: [top_inc, inc_inc],
    link_with: [libgensioosh, libgensio],
    # The tools use the OS libraries (sockets, user profiles on Windows)
    # directly, libtool passes libgensioosh's libraries on to them.
    dependencies: osh_libs,
)
# The gtlssh tools are only built if the ssl gensio is, like BUILD_SSL
# in configure.ac
build_ssl = 'ssl' in builtin_gensios or 'ssl' in dynamic_gensio_names

gensiot_link = [libgensiotool, libgensioosh, libgensio]
gensiot_deps = [ssl_main_dep]
if found_deps['openssl'].found()
    gensiot_deps += found_deps['openssl']
endif
if found_deps['glib-2.0'].found()
    gensiot_link += libgensioglib
    gensiot_deps += found_deps['glib-2.0']
endif
if found_deps['tcl'].found()
    gensiot_link += libgensiotcl
    gensiot_deps += found_deps['tcl']
endif

executable(
    'gensiot',
    'gensiotool.c',
    link_with: gensiot_link,
    include_directories: [top_inc, inc_inc, glib_inc, tcl_inc],
    dependencies: gensiot_deps,
    install: true,
)
install_man('gensiot.1')

if conf.get('HAVE_MDNS') == 1
    executable(
        'gmdns',
        'gensiomdns.c',
        link_with: [libgensiomdns, libgensiotool, libgensioosh],
        include_directories: [top_inc, inc_inc],
        dependencies: ssl_main_dep,
        install: true,
    )
    install_man('gmdns.1')
endif

# The build machine's python is not the one to use on the target when
# cross compiling.
reflector_conf = configuration_data()
if python.found() and not meson.is_cross_build()
    reflector_conf.set('PYTHON_EXECUTABLE', python.full_path().replace('\\', '/'))
else
    reflector_conf.set('PYTHON_EXECUTABLE', '/usr/bin/env python3')
endif
configure_file(
    input: '../tests/reflector.py.in',
    output: 'greflector',
    configuration: reflector_conf,
    install: true,
    install_dir: get_option('bindir'),
    install_mode: 'rwxr-xr-x',
)
install_man('greflector.1')

executable(
    'gsound',
    'gensiosound.c',
    link_with: [libgensiotool, libgensioosh, libgensio],
    include_directories: [top_inc, inc_inc],
    dependencies: ssl_main_dep,
    install: true,
)
install_man('gsound.1')

executable(
    'gagwpe',
    'gensioagwpe.c',
    link_with: [libgensioosh, libgensio],
    include_directories: [top_inc, inc_inc],
    dependencies: ssl_main_dep,
    install: true,
)
install_man('gagwpe.1')

if target_machine.system() == 'windows'
    executable(
        'gensio_pty_helper',
        'gensio_pty_helper.c',
        include_directories: [top_inc, inc_inc],
        install: true,
    )
endif

if build_ssl
    libgtlssh = static_library(
        'gtlssh',
        c_args: ['-DSYSCONFDIR="@0@"'.format(get_option('sysconfdir'))],
        sources: ['gtlssh-shared.c', 'run_get_output.c', 'file_utils.c'],
        include_directories: [top_inc, inc_inc],
        link_with: [libgensiotool, libgensioosh, libgensio],
        dependencies: [found_deps['openssl']] + osh_libs,
    )

    executable(
        'gtlssh-keygen',
        'gtlssh-keygen.c',
        link_with: [libgtlssh, libgensiotool, libgensioosh],
        include_directories: [top_inc, inc_inc],
        dependencies: [ssl_main_dep, found_deps['openssl']],
        install: true,
    )
    install_man('gtlssh-keygen.1')

    executable(
        'gtlssh',
        'gtlssh.c',
        link_with: [libgtlssh, libgensiomdns, libgensiotool, libgensioosh],
        include_directories: [top_inc, inc_inc],
        dependencies: [ssl_main_dep, found_deps['openssl']],
        install: true,
    )
    install_man('gtlssh.1')
    install_symlink(
        'gsh',
        pointing_to: 'gtlssh',
        install_dir: get_option('bindir'),
    )
    install_symlink(
        'gsh.1',
        pointing_to: 'gtlssh.1',
        install_dir: get_option('mandir') / 'man1',
    )

    # gtlsshd needs PAM on unix
    if found_deps['pam'].found() or target_machine.system() == 'windows'
        executable(
            'gtlsshd',
            'gtlsshd.c',
            link_with: [libgtlssh, libgensiotool, libgensioosh, libgensio, libgensiomdns],
            include_directories: [top_inc, inc_inc],
            dependencies: [ssl_main_dep, found_deps['openssl'], found_deps['pam']],
            install: true,
            install_dir: get_option('sbindir'),
        )
        install_man('gtlsshd.8')
    endif

    if target_machine.system() != 'windows'
        install_data(
            'gtlssync',
            install_dir: get_option('bindir'),
            install_mode: 'rwxr-xr-x',
        )
        install_man('gtlssync.1')
    endif
endif
