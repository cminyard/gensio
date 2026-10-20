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

# Like EXTRA_CFLAGS in configure.ac: on Windows the OS handler needs the
# newer APIs (pseudo consoles, TCP_INFO), and static libraries must not
# use the DLL import/export declarations.
windows_args = []
if target_machine.system() == 'windows'
    windows_args += ['-DNTDDI_VERSION=0x0a000006', '-DWINVER=0x0602']
    if get_option('default_library') == 'static'
        windows_args += '-DGENSIO_LINK_STATIC'
    endif
endif
add_project_arguments(windows_args, language: 'c')
# Project arguments can only be added before the first target, so enable
# C++ here instead of in c++/meson.build.
if get_option('cplusplus')
    add_languages('cpp', native: false)
    add_project_arguments(windows_args, language: 'cpp')
endif
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
    if d.get(0) == 'HAVE_TCL' and target_machine.system() == 'windows'
        # The tcl OS handler uses POSIX interfaces (configure doesn't
        # find tcl on MinGW either).
        if get_option('tcl').enabled()
            error('The tcl OS handler is not supported on Windows')
        endif
        required = false
        dep = dependency('', required: false)
    elif d.get(0) == 'HAVE_TCL'
        # Only use pkg-config, so the deprecated macOS system Tcl
        # framework isn't used (configure doesn't find it either).
        dep = dependency(d.get(1), required: required, method: 'pkg-config')
    else
        dep = dependency(d.get(1), required: required)
    endif
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

# The mDNS backends in the order configure.ac tries them: avahi, dnssd
# (macOS, or avahi's compat library), Windows mDNS.
mdns_libs = []
have_dnssd = false
if not found_deps['avahi-client'].found() and not get_option('dnssd').disabled()
    if cc.has_header('dns_sd.h')
        dnssd_lib = cc.find_library('dns_sd', required: false)
        if dnssd_lib.found() and cc.has_function('DNSServiceRegister',
                                                 dependencies: dnssd_lib)
            have_dnssd = true
            mdns_libs += dnssd_lib
        else
            # On macOS it is part of libSystem
            have_dnssd = cc.has_function('DNSServiceRegister')
        endif
    endif
    if get_option('dnssd').enabled() and not have_dnssd
        error('dnssd enabled, but dns_sd.h or DNSServiceRegister not found')
    endif
endif
conf.set10('HAVE_DNSSD', have_dnssd)

have_winmdns = false
if (is_windows and not found_deps['avahi-client'].found() and not have_dnssd
    and not get_option('winmdns').disabled())
    have_winmdns = cc.compiles('''#include <windows.h>
#include <windns.h>
int main(void) { DnsServiceBrowse(NULL, NULL); return 0; }''',
                               name: 'Windows mDNS')
endif
if get_option('winmdns').enabled() and not have_winmdns
    error('winmdns enabled, but Windows mDNS is not available')
endif
conf.set10('HAVE_WINMDNS', have_winmdns)
if have_winmdns
    foreach l : ['dnsapi', 'iphlpapi', 'ws2_32']
        mdns_libs += cc.find_library(l)
    endforeach
endif

# mdns uses POSIX regex, from PCRE if the C library doesn't have it
regex_libs = []
if not conf.has('HAVE_REGEXEC')
    pcre2_posix = cc.find_library('pcre2-posix', required: false)
    pcre_posix = cc.find_library('pcreposix', required: false)
    if pcre2_posix.found() and cc.has_function('pcre2_regexec',
                                               dependencies: pcre2_posix)
        conf.set('HAVE_PCRE2_POSIX', 1)
        regex_libs += pcre2_posix
    elif pcre_posix.found() and cc.has_function('regexec',
                                                dependencies: pcre_posix)
        conf.set('HAVE_PCRE_POSIX', 1)
        regex_libs += pcre_posix
    endif
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

# The file gensio uses stdio on Windows by default
file_stdio = get_option('file-stdio')
conf.set10('USE_FILE_STDIO',
           file_stdio == 'yes' or (file_stdio == 'auto' and is_windows))

conf.set10('HAVE_MDNS',
           found_deps['avahi-client'].found() or have_dnssd or have_winmdns)

# On macOS, dlopen()ing libssl may change the signal mask of other
# threads, so libssl has to be linked with libgensio.  See "Issues with
# openssl and signal masks" in the FAQ.
link_ssl_with_main = get_option('link-ssl-with-main')
if link_ssl_with_main == 'auto'
    link_ssl_with_main = 'no'
    if target_machine.system() == 'darwin' and found_deps['openssl'].found()
        if meson.can_run_host_binaries()
            ssl_libdir = found_deps['openssl'].get_variable(pkgconfig: 'libdir',
                                                            default_value: '')
            ssl_check = cc.run(files('meson/ssl_sigmask_check.c'),
                args: ['-DSSL_LIB="@0@/libssl.dylib"'.format(ssl_libdir)],
                dependencies: [dependency('threads')],
                name: 'if ssl needs to be linked with the main library')
            if not ssl_check.compiled() or ssl_check.returncode() not in [0, 4]
                error('Error running ssl link test program')
            endif
            if ssl_check.returncode() == 4
                link_ssl_with_main = 'yes'
            endif
        else
            link_ssl_with_main = 'yes'
        endif
    endif
endif
if link_ssl_with_main == 'yes' and not found_deps['openssl'].found()
    error('link-ssl-with-main requires openssl')
endif
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
