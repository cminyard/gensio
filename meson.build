project(
    'gensio', 'c',
    version: '2.8.5',
    default_options: [
      'warning_level=2' # value "2" will add "-Wall" and "-Wextra" to the compiler flags
    ],
)
soversion = '4.1.0'
conf = configuration_data()
cc = meson.get_compiler('c')
pkg = import('pkgconfig')
gensio_version = meson.project_version()
version_array = gensio_version.split('.')
gensio_major_version = version_array[0].to_int()
gensio_minor_version = version_array[1].to_int()
gensio_micro_version = version_array[2].to_int()

top_inc = include_directories('.')
inc_inc = include_directories('./include')
glib_inc = include_directories('./glib/include')
tcl_inc = include_directories('./tcl/include')
cplusplus_inc = include_directories('./c++/include')

conf.set10('HAVE_UNIX', cc.has_header('sys/un.h'))
conf.set(
    'HAVE_TCPD_H',
    cc.has_header('tcpd.h', required: get_option('tcp-wrappers')),
    description : 'Define if you have the <tcpd.h> header file.'
)

# configure version related variables
version_conf = configuration_data()
version_conf.set('gensio_VERSION_MAJOR', gensio_major_version)
version_conf.set('gensio_VERSION_MINOR', gensio_minor_version)
version_conf.set('gensio_VERSION_PATCH', gensio_micro_version)
version_conf.set('gensio_VERSION_STRING', gensio_version)

# check token ['HAVE_SCTP_SENDV', ]
# AC_CHECK_LIB(sctp, sctp_sendv, [HAVE_SCTP_SENDV=1])
# check token ['HAVE_RAND_SET_DRBG_TYPE']
#AC_CHECK_LIB(crypto, RAND_set_DRBG_type, HAVE_RAND_SET_DRBG_TYPE=1)
check_functions = [
    ['HAVE_CFMAKERAW', 'cfmakeraw', '#include<termios.h>'],
    ['HAVE_EPOLL_PWAIT', 'epoll_pwait', '#include<sys/epoll.h>'],
    ['HAVE_FNMATCH', 'fnmatch', '#include<fnmatch.h>'],
    ['HAVE_GETRANDOM_FUNC', 'getrandom', '#include<sys/random.h>'],
    ['HAVE_ISATTY', 'isatty', '#include<unistd.h>'],
    ['HAVE_PRCTL', 'prctl', '#include<sys/prctl.h>'],
    ['HAVE_PTSNAME_R', 'ptsname_r', ''],
    ['HAVE_RECVMSG', 'recvmsg', '#include<sys/socket.h>'],
    ['HAVE_REGEXEC', 'regexec', '#include<regex.h>'],
    ['HAVE_SENDMSG', 'sendmsg', '#include<sys/socket.h>'],
    ['HAVE_SETUTXENT', 'setutxent', '#include<utmpx.h>'],
    ['HAVE_SIGTIMEDWAIT', 'sigtimedwait', '#include<signal.h>'],
    ['HAVE_STRCASECMP', 'strcasecmp', '#include<strings.h>'],
    ['HAVE_STRNCASECMP', 'strncasecmp', '#include<strings.h>'],
]

foreach f : check_functions
    if cc.has_function(f.get(1), prefix: f.get(2))
        conf.set(f.get(0), 1)
    endif
endforeach

check_decl = [
    ['HAVE_DECL_SIGWINCH', 'SIGWINCH', '#include<signal.h>'],
    ['HAVE_DECL_TIOCSRS485', 'TIOCSRS485', '#include<sys/ioctl.h>'],
]

foreach f : check_decl
    if cc.get_define(f.get(1), prefix: f.get(2)) != ''
        conf.set(f.get(0), 1)
    endif
endforeach

conf.set10(
    'HAVE_TERMIOS2',
    cc.has_member(
        'struct termios2',
        'c_ispeed',
        prefix: '#include<asm/termios.h>',
    ),
)

conf.set10(
    'HAVE_GCC_ATOMICS',
    cc.links(
        '''
  static int counter = 0;
	int val;

	__atomic_load(&counter, &val, __ATOMIC_SEQ_CST);
	return val;
  ''',
    ),
)

if target_machine.system() == 'windows'
    conf.set('HAVE_PTY', 1)
else
    conf.set10('HAVE_PTY', cc.has_function('posix_openpt'))
endif



golang = find_program('go', required: false)
conf.set10('HAVE_GO', golang.found())

swig = find_program('swig', required: false)
conf.set10('HAVE_SWIG', swig.found())

python = import('python').find_installation('python3')
conf.set_quoted('HAVE_PYTHON', python.language_version())


if target_machine.system() == 'linux'
    conf.set('HAVE_WORKING_PORT0', 1)
endif

# Deps

found_deps = {}

deps = [
    ['HAVE_ALSA', 'alsa'],
    ['HAVE_AVAHI', 'avahi-client'],
    ['HAVE_LIBSCTP', 'libsctp'],
    #['HAVE_LIBPAM', 'pam'],
    ['HAVE_OPENIPMI', 'OpenIPMI'],
    ['HAVE_OPENSSL', 'openssl'],
    ['HAVE_GLIB', 'glib-2.0'],
    ['HAVE_TCL', 'tcl'],
    ['HAVE_UDEV', 'libudev'],
]

foreach d : deps
    dep = dependency(d.get(1))
    if dep.found()
        conf.set(d.get(0), 1)
        found_deps += {d.get(1): dep}
    endif
endforeach

libpam_dep = cc.find_library('pam', required: true)
conf.set('HAVE_LIBPAM', 1)
libm_dep = cc.find_library('m', required: true)
thread_dep = dependency('threads')
libwrap_dep = cc.find_library('wrap', required : get_option('tcp-wrappers'))

found_deps += {'pam' : libpam_dep}
found_deps += {'threads' : thread_dep}
found_deps += {'wrap' : libwrap_dep}

conf.set('USE_LOGIN_PROGRAM', 0, description : 'Set to 1 to use login, 0 to directly execute the shell on login')
conf.set('USE_PTHREADS', 1)

gensio_libexec = (
    get_option('prefix') / get_option('libexecdir') / 'gensio' / meson.project_version()
)

gensio_includedir = get_option('includedir')

# gensios
gensio_all_enable = get_option('all-gensios')
gensio_net_enable = get_option('net')
gensio_udp_enable = get_option('udp')
gensio_sctp_enable = get_option('sctp')

subdir('lib') # Done
if get_option('cplusplus')
  subdir('c++')
endif
subdir('glib')
subdir('include') # Done
subdir('man') # Done
subdir('tcl')
subdir('tools')

configure_file(output: 'config.h', configuration: conf)
