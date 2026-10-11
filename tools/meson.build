libgensiotool = static_library(
    'gensiotool',
    sources: ['ioinfo.c', 'ser_ioinfo.c', 'utils.c', 'localports.c'],
    include_directories: [top_inc, inc_inc],
    link_with: [libgensioosh, libgensio],
)
libgtlssh = static_library(
    'gtlssh',
    c_args: ['-DSYSCONFDIR="@0@"'.format(get_option('sysconfdir'))],
    sources: ['gtlssh-shared.c', 'run_get_output.c', 'file_utils.c'],
    include_directories: [top_inc, inc_inc],
    link_with: [libgensiotool, libgensioosh, libgensio],
)

executable(
    'gensiot',
    'gensiotool.c',
    link_with: [
        libgensiotcl,
        libgensioglib,
        libgensiotool,
        libgensioosh,
        libgensio,
    ],
    include_directories: [top_inc, inc_inc, glib_inc, tcl_inc],
    dependencies: [
        found_deps['glib-2.0'],
        found_deps['openssl'],
        found_deps['tcl'],
    ],
    install: true,
)
install_man('gensiot.1')

executable(
    'gmdns',
    'gensiomdns.c',
    link_with: [libgensiomdns, libgensiotool, libgensioosh],
    include_directories: [top_inc, inc_inc],
    install: true,
)
install_man('gmdns.1')
#python script
install_man('greflector.1')

executable(
    'gsound',
    'gensiosound.c',
    link_with: [libgensiotool, libgensioosh],
    include_directories: [top_inc, inc_inc],
    install: true,
)
install_man('gsound.1')

executable(
    'gtlssh-keygen',
    'gtlssh-keygen.c',
    link_with: [libgtlssh, libgensiotool, libgensioosh],
    include_directories: [top_inc, inc_inc],
    dependencies: [found_deps['openssl']],
    install: true,
)
install_man('gtlssh-keygen.1')

executable(
    'gtlssh',
    'gtlssh.c',
    link_with: [libgtlssh, libgensiomdns, libgensiotool, libgensioosh],
    include_directories: [top_inc, inc_inc],
    dependencies: [found_deps['openssl']],
    install: true,
)
install_man('gtlssh.1')

executable(
    'gtlsshd',
    'gtlsshd.c',
    link_with: [libgtlssh, libgensiotool, libgensioosh],
    include_directories: [top_inc, inc_inc],
    dependencies: [found_deps['openssl'], found_deps['pam']],
    install: true,
)
install_man('gtlsshd.8')
# shellscript
install_man('gtlssync.1')
