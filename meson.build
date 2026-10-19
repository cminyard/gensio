project(
    'gensio', 'c',
    # Keep in sync with AC_INIT in configure.ac
    version: '3.0.4',
    default_options: [
      'warning_level=2' # value "2" will add "-Wall" and "-Wextra" to the compiler flags
    ],
)
# The libtool version-info (current:revision:age) from GENSIO_LIB_VERSION
# in configure.ac.  libtool names the libraries
# lib.so.<current - age>.<age>.<revision>, do the same so the sonames
# are compatible.
gensio_lib_version = '16:0:2'
lt = gensio_lib_version.split(':')
lt_major = lt[0].to_int() - lt[2].to_int()
soversion = lt_major.to_string()
libversion = '@0@.@1@.@2@'.format(lt_major, lt[2], lt[1])
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
if get_option('tcp-wrappers').allowed() and cc.has_header('tcpd.h', required: get_option('tcp-wrappers'))
    conf.set('HAVE_TCPD_H', 1, description : 'Define if you have the <tcpd.h> header file.')
endif

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
    ['HAVE_INITGROUPS', 'initgroups', '#include<grp.h>'],
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

# Like AC_CHECK_DECLS, always defined to 0 or 1.  has_header_symbol()
# doesn't fail if the header is missing (no sys/ioctl.h on Windows).
check_decl = [
    ['HAVE_DECL_SIGWINCH', 'SIGWINCH', 'signal.h'],
    ['HAVE_DECL_TIOCSRS485', 'TIOCSRS485', 'sys/ioctl.h'],
]

foreach f : check_decl
    conf.set10(f.get(0), cc.has_header_symbol(f.get(2), f.get(1)))
endforeach

# Checked with #ifdef, so only define it if present.
if cc.has_member('struct termios2', 'c_ispeed',
                 prefix: '#include<asm/termios.h>')
    conf.set('HAVE_TERMIOS2', 1)
endif

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

# The C python bindings need swig >= 4.0, the C++ ones swig >= 4.1.
# swig only understands -version, so meson's version check can't be used.
swig = find_program('swig', required: get_option('swig'))
swig_version = '0'
if swig.found()
    swig_out = run_command(swig, '-version', check: true).stdout()
    swig_version = swig_out.split('SWIG Version ')[1].split('\n')[0].strip()
    if swig_version.version_compare('<4.0.0')
        if get_option('swig').enabled()
            error('swig >= 4.0.0 is required, found @0@'.format(swig_version))
        endif
    endif
endif
swig_cpp_ok = swig_version.version_compare('>=4.1.0')
conf.set10('HAVE_SWIG', swig_version.version_compare('>=4.0.0'))

pymod = import('python')
python = pymod.find_installation('python3', required: get_option('python'))
python_dep = dependency('', required: false)
if python.found()
    python_dep = python.dependency(embed: false, required: get_option('python'))
endif
# libgensio_python_swig is a normal library using the python API, on
# Windows it has to link with libpython (no undefined symbols in DLLs).
python_lib_dep = python_dep
if python.found() and target_machine.system() == 'windows'
    python_lib_dep = python.dependency(embed: true, required: false)
endif
have_python_swig = swig_version.version_compare('>=4.0.0') and python_dep.found()
if have_python_swig
    python_install_dir = get_option('python-install-dir')
    if python_install_dir == ''
        python_install_dir = python.get_install_dir()
    endif
    # -py3 is the default and deprecated starting with swig 4.1
    python_swig_flags = ['-python']
    if not swig_cpp_ok
        python_swig_flags += '-py3'
    endif
endif


if target_machine.system() == 'linux'
    conf.set('HAVE_WORKING_PORT0', 1)
endif

# Deps

found_deps = {}

deps = [
    ['HAVE_ALSA', 'alsa', 'alsa'],
    ['HAVE_AVAHI', 'avahi-client', 'avahi'],
    ['HAVE_LIBSCTP', 'libsctp'],
    #['HAVE_LIBPAM', 'pam'],
    ['HAVE_OPENIPMI', 'OpenIPMI', 'openipmi'],
    ['HAVE_OPENSSL', 'openssl'],
    ['HAVE_GLIB', 'glib-2.0', 'glib'],
    ['HAVE_TCL', 'tcl', 'tcl'],
    ['HAVE_UDEV', 'libudev'],
    ['HAVE_PORTAUDIO', 'portaudio-2.0'],
    ['HAVE_LIBSOAPY', 'SoapySDR'],
]

# Like configure.ac, HAVE_GLIB and HAVE_TCL are only defined if present
# (the code uses #ifdef), the others are always defined to 0 or 1.
ifdef_deps = ['HAVE_GLIB', 'HAVE_TCL']

foreach d : deps
    # The optional third element names the feature option controlling it
    required = d.length() > 2 ? get_option(d.get(2)) : false
    dep = dependency(d.get(1), required: required)
    if d.get(0) in ifdef_deps
        if dep.found()
            conf.set(d.get(0), 1)
        endif
    else
        conf.set10(d.get(0), dep.found())
    endif
    found_deps += {d.get(1): dep}
endforeach

libpam_dep = cc.find_library('pam', required: get_option('pam'))
if libpam_dep.found()
    conf.set('HAVE_LIBPAM', 1)
endif
libm_dep = cc.find_library('m', required: true)
thread_dep = dependency('threads')
libwrap_dep = cc.find_library('wrap', required : get_option('tcp-wrappers'))

# Libraries the OS handler needs, like OSH_LIBS in configure.ac
is_windows = target_machine.system() == 'windows'
osh_libs = []
if is_windows
    foreach l : ['ws2_32', 'iphlpapi', 'gdi32', 'bcrypt', 'secur32', 'userenv',
                 'wtsapi32', 'ole32']
        osh_libs += cc.find_library(l)
    endforeach
else
    osh_libs += cc.find_library('dl', required: false)
endif

# Windows mDNS, only used if avahi isn't available
have_winmdns = false
mdns_libs = []
if is_windows and not found_deps['avahi-client'].found()
    have_winmdns = cc.compiles('''#include <windows.h>
#include <windns.h>
int main(void) { DnsServiceBrowse(NULL, NULL); return 0; }''',
                               name: 'Windows mDNS')
endif
conf.set10('HAVE_WINMDNS', have_winmdns)
if have_winmdns
    foreach l : ['dnsapi', 'iphlpapi', 'ws2_32']
        mdns_libs += cc.find_library(l)
    endforeach
endif

# Windows sound and the cm108gpio gensio need extra libraries
conf.set10('HAVE_WIN32SOUND', is_windows)
sound_libs = []
cm108gpio_libs = []
if is_windows
    sound_libs += cc.find_library('winmm')
    foreach l : ['hid', 'setupapi']
        cm108gpio_libs += cc.find_library(l)
    endforeach
endif

# The file gensio uses stdio on Windows
conf.set10('USE_FILE_STDIO', is_windows)

conf.set10('HAVE_MDNS', found_deps['avahi-client'].found() or have_winmdns)
conf.set10(
    'HAVE_SCTP_SENDV',
    cc.has_function('sctp_sendv', dependencies: found_deps['libsctp']),
)
conf.set10(
    'HAVE_RAND_SET_DRBG_TYPE',
    cc.has_function('RAND_set_DRBG_type', dependencies: found_deps['openssl']),
)

# OS specific settings, see the target_os handling in configure.ac
system = target_machine.system()
conf.set10('HAVE_UCRED', system in ['linux', 'darwin', 'freebsd'])
conf.set10('USE_OPENPTY', system == 'darwin')
conf.set10('USE_GGL_INT', system == 'darwin')
if get_option('broken-pselect') or system in ['darwin', 'freebsd', 'netbsd', 'openbsd', 'dragonfly']
    conf.set('BROKEN_PSELECT', '', description: 'PSELECT call is not atomic')
endif

uucp_locking = get_option('uucp-locking')
if uucp_locking == ''
    uucp_locking = system in ['windows', 'darwin', 'cygwin'] ? 'no' : 'yes'
endif
uucp_lock_dir = system == 'linux' ? '/var/lock' : '/var/spool/lock'
if uucp_locking not in ['yes', 'no']
    uucp_lock_dir = uucp_locking
endif
conf.set10('USE_UUCP_LOCKING', uucp_locking != 'no')
conf.set_quoted('UUCP_LOCK_DIR', uucp_lock_dir)

flock_locking = get_option('flock-locking')
if flock_locking == 'auto'
    flock_locking = system in ['windows', 'cygwin'] ? 'no' : 'yes'
endif
conf.set10('USE_FLOCK_LOCKING', flock_locking == 'yes')

if get_option('internal-trace')
    conf.set('ENABLE_INTERNAL_TRACE', 1)
endif

found_deps += {'pam' : libpam_dep}
found_deps += {'threads' : thread_dep}
found_deps += {'wrap' : libwrap_dep}

conf.set('USE_LOGIN_PROGRAM', 0, description : 'Set to 1 to use login, 0 to directly execute the shell on login')
conf.set('USE_PTHREADS', 1)

module_install_dir = get_option('module-install-dir')
if is_windows
    # Windows loads the modules from the DLL search path, like configure
    # they go into bindir.
    if module_install_dir == ''
        module_install_dir = get_option('prefix') / get_option('bindir')
    endif
    gensio_libexec = module_install_dir
else
    if module_install_dir == ''
        module_install_dir = get_option('prefix') / get_option('libexecdir') / 'gensio'
    endif
    gensio_libexec = module_install_dir / meson.project_version()
endif

gensio_includedir = get_option('includedir')

subdir('lib') # Done
if get_option('cplusplus')
  subdir('c++')
endif
if found_deps['glib-2.0'].found()
    subdir('glib')
endif
subdir('include') # Done
subdir('man') # Done
if found_deps['tcl'].found()
    subdir('tcl')
endif
subdir('tools')

if have_python_swig
    subdir('swig/include/gensio')
    subdir('swig/python')
    if found_deps['glib-2.0'].found()
        subdir('glib/swig/python')
    endif
    if found_deps['tcl'].found()
        subdir('tcl/swig/python')
    endif
    if get_option('cplusplus') and swig_cpp_ok
        subdir('c++/swig/pygensio')
        if found_deps['glib-2.0'].found()
            subdir('glib/c++/swig/pygensio')
        endif
        if found_deps['tcl'].found()
            subdir('tcl/c++/swig/pygensio')
        endif
    endif
endif

subdir('tests')
if have_python_swig and get_option('cplusplus') and swig_cpp_ok
    subdir('c++/swig/pygensio/tests')
endif

configure_file(output: 'config.h', configuration: conf)
