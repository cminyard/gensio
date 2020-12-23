AC_INIT([gensio], [2.2.1], [minyard@acm.org])
AC_SUBST(gensio_VERSION_MAJOR, 2)
AC_SUBST(gensio_VERSION_MINOR, 2)
AC_SUBST(gensio_VERSION_PATCH, 1)
AC_SUBST(gensio_VERSION_STRING, ${PACKAGE_VERSION})
AM_INIT_AUTOMAKE([-Wall])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AM_PROG_AR
AM_PROG_LIBTOOL
if test ${version_type} = windows; then
 uucp_locking_flag=no
else
 uucp_locking_flag=yes
fi
AC_ARG_WITH(uucp-locking,
 [AS_HELP_STRING([--with-uucp-locking], [Enable UUCP-style locking])],
 uucp_locking_flag="$withval")
if test "$uucp_locking_flag" = yes; then
  AC_DEFINE([USE_UUCP_LOCKING], [], [Enable device locking])
fi

AC_ARG_WITH(tcp-wrappers,
 [AS_HELP_STRING([--with-tcp-wrappers], [Enable tcpwrappers support])],
 tcp_wrappers="$withval",
 tcp_wrappers="no")
if test "$tcp_wrappers" != "no"
then
  AC_HAVE_HEADERS(tcpd.h)
  AC_CHECK_LIB(wrap,main)
fi

AC_ARG_ENABLE([doc],
 [AS_HELP_STRING([--disable=doc], [disable building and installing docs])],
 [],
 [enable_doc="yes"])

AM_CONDITIONAL([INSTALL_DOC], [test "x$enable_doc" != "xno"])

AX_HAVE_EPOLL_PWAIT(
   [AX_CONFIG_FEATURE_ENABLE(epoll_pwait)],
   [AX_CONFIG_FEATURE_DISABLE(epoll_pwait)])
AX_CONFIG_FEATURE(
   [epoll_pwait], [This platform supports epoll(7) with epoll_pwait(2)],
   [HAVE_EPOLL_PWAIT], [This platform supports epoll(7) with epoll_pwait(2).])

tryopenipmi=yes
AC_ARG_WITH(openipmi,
 [AS_HELP_STRING([--with-openipmi=yes|no], [Look for openipmi])],
    if test "x$withval" = "xyes"; then
      tryopenipmi=yes
    elif test "x$withval" = "xno"; then
      tryopenipmi=no
    fi,
)

trysctp=yes
AC_ARG_WITH(sctp,
 [AS_HELP_STRING([--with-sctp=yes|no], [Look for sctp])],
    if test "x$withval" = "xyes"; then
      trysctp=yes
    elif test "x$withval" = "xno"; then
      trysctp=no
    fi,
)

use_pthreads=yes
use_pthreads_set=false
AC_ARG_WITH(pthreads,
 [AS_HELP_STRING([--with-pthreads=yes|no], [Use pthreads or not])],
    use_pthreads_set=true
    if test "x$withval" = "xyes"; then
      use_pthreads=yes
    elif test "x$withval" = "xno"; then
      use_pthreads=no
    fi,
)

if test "x$use_pthreads" != "xno"; then
   AX_PTHREAD(
      [LIBS="$LIBS $PTHREAD_LIBS"
       CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
       CC="$PTHREAD_CC"
       AC_DEFINE([USE_PTHREADS], [], [Enable multithreaded support])],
      [if $use_pthreads_set; then
          AC_MSG_FAILURE([--with-pthreads was given, but no working pthread library was found])
       fi])
fi

AC_ARG_WITH(openipmiflags,
 [AS_HELP_STRING([--with-openipmiflags=flags],
		 [Set the flags to compile with OpenIPMI.])],
    CPPFLAGS="$CPPFLAGS $withval"
)

AC_ARG_WITH(openipmilibs,
 [AS_HELP_STRING([--with-openipmilibs=libs],
		 [Set the libraries to link with OpenIPMI.])],
    LIBS="$LIBS $withval"
)

# Handle OpenIPMI support
HAVE_OPENIPMI=no
if test "x$tryopenipmi" != "xno"; then
   found_ipmiif=no
   AC_CHECK_HEADER(OpenIPMI/ipmiif.h, found_ipmiif=yes; )
   if test "x$found_ipmiif" = "xyes"; then
      AC_CHECK_LIB(OpenIPMI, ipmi_alloc_os_handler, HAVE_OPENIPMI=yes)
   fi
fi

if test "x$HAVE_OPENIPMI" != "xno"; then
   if test "x$ax_pthread_ok" = "xyes"; then
      LIBS="$LIBS -lOpenIPMI -lOpenIPMIpthread -lOpenIPMIutils"
   else
      LIBS="$LIBS -lOpenIPMI -lOpenIPMIposix -lOpenIPMIutils"
   fi
   HAVE_OPENIPMI=1
else
   HAVE_OPENIPMI=0
fi
AC_DEFINE_UNQUOTED([HAVE_OPENIPMI], [$HAVE_OPENIPMI],
	[Set to 1 to enable IPMI support through OpenIPMI, 0 to disable])
AC_SUBST(HAVE_OPENIPMI)

AX_CHECK_OPENSSL([HAVE_OPENSSL=1
		  LIBS="$LIBS $OPENSSL_LIBS"
		  LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
		  CPPFLAGS="$CPPFLAGS $OPENSSL_INCLUDES"], [HAVE_OPENSSL=0])
AC_DEFINE_UNQUOTED([HAVE_OPENSSL], [$HAVE_OPENSSL],
	[Set to 1 to enable SSL support through OpenSSL, 0 to disable])
AC_SUBST(HAVE_OPENSSL)

tryswig=yes
swigprog=
AC_ARG_WITH(swig,
 [AS_HELP_STRING([--with-swig[[=yes|no|PATH]]],
		 [Look for swig, with the optional path.])],
    if test "x$withval" = "x"; then
      tryswig=yes
    elif test "x$withval" = "xyes"; then
      tryswig=yes
    elif test "x$withval" = "xno"; then
      tryswig=no
    else
      swigprog=$withval
    fi,
)

trypython=yes
AC_ARG_WITH(python,
 [AS_HELP_STRING([--with-python[[=yes|no|PATH]]],
		 [Look for python, with the optional path.])],
    if test "x$withval" = "x"; then
      trypython=yes
    elif test "x$withval" = "xyes"; then
      trypython=yes
    elif test "x$withval" = "xno"; then
      trypython=no
    else
      pythonprog="$withval"
      trypython=yes
    fi,
)

AC_ARG_WITH(pythoninstall,
 [AS_HELP_STRING([--with-pythoninstall=PATH],
		 [Install python modules in the given location.])],
    pythoninstalldir="$withval",
)

AC_ARG_WITH(pythoninstalllib,
 [AS_HELP_STRING([--with-pythoninstalllib=PATH],
		 [Install python libraries in the given location.])],
    pythoninstalllibdir="$withval",
)

AC_ARG_WITH(pythoncflags,
 [AS_HELP_STRING([--with-pythoncflags=PATH],
		 [Use the given flags when compiling python parts.])],
    pythoncflags="$withval",
)

AC_ARG_WITH(pythonusepthreads,
 [AS_HELP_STRING([--with-pythonusepthreads[[=yes|no]]],
		 [Use threads with python.])],
   if test "x$withval" = "xyes"; then
      pythonusepthreads="yes"
   elif test "x$withval" = "xno"; then
      pythonusepthreads="no"
   elif test "x$withval" = "x"; then
      pythonusepthreads="yes"
   fi,
)

AC_SEARCH_LIBS([clock_gettime], [rt posix4])

# Handle RS485 support
AC_CHECK_DECLS([TIOCSRS485], [], [], [[#include <sys/ioctl.h>]])

# enable silent build
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_MACRO_DIR([m4])
AC_STDC_HEADERS
AC_CHECK_LIB(nsl,main)
HAVE_AVAHI=0
AC_CHECK_LIB(avahi-client, avahi_client_new,
	     [AC_DEFINE([HAVE_AVAHI], [1], [Have avahi installed])
	     HAVE_AVAHI=1
	     LIBS="-lavahi-client -lavahi-common $LIBS"])
AC_SUBST(HAVE_AVAHI)
GMDNS=
GMDNSMAN=
if test "x$HAVE_AVAHI" = "x1"; then
   GMDNS=gmdns
   GMDNSMAN=gmdns.1
fi
AM_CONDITIONAL([HAVE_AVAHI], [test "x$HAVE_AVAHI" = "x1"])
AC_SUBST(GMDNS)
AC_SUBST(GMDNSMAN)

# Now check for swig
SWIG_DIR=
SWIG=
if test "x$tryswig" = "xyes"; then
   if test "x$swigprog" != "x"; then
      SWIG="$swigprog"
   fi
   AX_PKG_SWIG([1.3.21])
   if test "x$SWIG" != "x"; then
      AC_DEFINE([HAVE_SWIG], [], [Have swig installed])
      SWIG_DIR=swig
   fi
fi
AC_SUBST(SWIG_DIR)
AC_SUBST(SWIG)

# Handle PYTHON support
PYTHON_DIR=
PYTHON_INSTALL_DIR=
PYTHON_INSTALL_LIB_DIR=
PYTHON_SWIG_FLAGS=
if test "x$trypython" = "xyes"; then
   if test "x$pythonprog" != "x"; then
      PYTHON="$pythonprog"
   fi
   if test "x$pythoncflags" != "x"; then
      PYTHON_CPPFLAGS="$pythoncflags"
   fi
   AX_PYTHON_DEVEL
fi
if test "x$PYTHON" != "x"; then
   AX_PROG_PYTHON_VERSION([3.0.0], [PYTHON_SWIG_FLAGS=-py3], [])
   PYTHON_DIR=python
   if test "x$pythoninstalldir" = "x"; then
      PYTHON_INSTALL_DIR="$PYTHON_SITE_PKG"
   else
      PYTHON_INSTALL_DIR="$pythoninstalldir"
   fi
   if test "x$pythoninstalllibdir" = "x"; then
      PYTHON_INSTALL_LIB_DIR="$PYTHON_INSTALL_DIR"
   else
      PYTHON_INSTALL_LIB_DIR="$pythoninstalllibdir"
   fi

   if test "x$pythonusepthreads" = "x"; then
      cat - <<_ACEOF >conftest.py
try:
  import threading
  print('yes')
except:
  print('no')
_ACEOF
      pythonusepthreads=`$PYTHON conftest.py`
      rm -f conftest.py
   fi
   echo "checking for python threads... $pythonusepthreads"

   if test "x$pythonusepthreads" = "xyes"; then
      PYTHON_HAS_POSIX_THREADS=1
   else
      PYTHON_HAS_POSIX_THREADS=0
   fi
fi

AC_SUBST(PYTHON_DIR)
AC_SUBST(PYTHON_INSTALL_DIR)
AC_SUBST(PYTHON_INSTALL_LIB_DIR)
AC_SUBST(PYTHON_HAS_POSIX_THREADS)
AC_SUBST(PYTHON_SWIG_FLAGS)

PYTHON_EXECUTABLE="${PYTHON}"
AC_SUBST(PYTHON_EXECUTABLE)

HAVE_LIBSCTP=0
if test "x$trysctp" != "xno"; then
   AC_CHECK_LIB(sctp, sctp_bindx,
                [HAVE_LIBSCTP=1; LIBS="$LIBS -lsctp"])
fi
AC_DEFINE_UNQUOTED([HAVE_LIBSCTP], [$HAVE_LIBSCTP],
	      [Set to 1 to enable SCTP, 0 to disable])
AC_SUBST(HAVE_LIBSCTP)

HAVE_SCTP_SENDV=0
if test "$HAVE_LIBSCTP" = "1"; then
   AC_CHECK_LIB(sctp, sctp_sendv, [HAVE_SCTP_SENDV=1])
fi
AC_DEFINE_UNQUOTED([HAVE_SCTP_SENDV], [$HAVE_SCTP_SENDV],
	      [Set to 1 if sctp_sendv() is available, 0 if not])

AC_CHECK_LIB(pam, pam_start, [HAVE_PAM=1], [HAVE_PAM=0])
if test $HAVE_PAM -eq 1; then
   AC_DEFINE([HAVE_LIBPAM], [1], [PAM libraries are present])
   PAMLIB=-lpam
fi
AC_SUBST(PAMLIB)

# python annoyingly defined HAVE_GETRANDOM
AC_CHECK_FUNC(getrandom, [AC_DEFINE([HAVE_GETRANDOM_FUNC], [1],
				    [Define if getrandom is available.])])
AC_CHECK_FUNCS(ptsname_r)
AC_CHECK_FUNCS(cfmakeraw)
AC_CHECK_FUNCS(signalfd)
AC_CHECK_FUNCS(regexec)
AC_CHECK_FUNCS(fnmatch)

case $host_os in
linux*) HAVE_WORKING_PORT0=1 ;;
*) HAVE_WORKING_PORT0=0 ;;
esac
AC_DEFINE_UNQUOTED([HAVE_WORKING_PORT0], [$HAVE_WORKING_PORT0],
	      [Set to 1 if binding with port 0 picks an ephemeral address])
AC_SUBST(HAVE_WORKING_PORT0)

GTLSSH=
GTLSSYNC=
GTLSSHD=
GTLSSH_KEYGEN=
GTLSSHMAN=
GTLSSYNCMAN=
GTLSSHDMAN=
GTLSSH_KEYGENMAN=
if test $HAVE_OPENSSL -eq 1; then
   if test $HAVE_PAM -eq 1; then
      GTLSSHD=gtlsshd
      GTLSSHDMAN=gtlsshd.8
   fi
   GTLSSH=gtlssh
   GTLSSYNC=gtlssync
   GTLSSH_KEYGEN=gtlssh-keygen
   GTLSSHMAN=gtlssh.1
   GTLSSYNCMAN=gtlssync.1
   GTLSSH_KEYGENMAN=gtlssh-keygen.1
fi
AC_SUBST(GTLSSHD)
AC_SUBST(GTLSSH)
AC_SUBST(GTLSSYNC)
AC_SUBST(GTLSSH_KEYGEN)
AC_SUBST(GTLSSHDMAN)
AC_SUBST(GTLSSHMAN)
AC_SUBST(GTLSSYNCMAN)
AC_SUBST(GTLSSH_KEYGENMAN)

AC_CHECK_MEMBER([struct termios2.c_ispeed],
	[AC_DEFINE([HAVE_TERMIOS2], [1], [termios2 is present])],
	[], [[#include <asm/termios.h>]])

AC_ARG_ENABLE([internal-trace],
  [AS_HELP_STRING([--enable-internal-trace[[=yes|no]]],
                  [Enable internal tracing of states and data])],
  [
    case $enableval in
    "" | y | ye | yes)
      enable_internal_trace=yes
      ;;
    "" | n | no)
      enable_internal_trace=no
      ;;
    *)
      AC_MSG_ERROR([Invalid --enable-internal-trace option])
      ;;
    esac
  ],
  [enable_internal_trace=no])
if test "x$enable_internal_trace" != xno; then
   AC_DEFINE([ENABLE_INTERNAL_TRACE], [1], [Enable internal tracing])
fi

HAVE_UNIX=0
AC_CHECK_HEADER(sys/un.h, [HAVE_UNIX=1] )
AC_SUBST(HAVE_UNIX)
AC_DEFINE_UNQUOTED([HAVE_UNIX], [$HAVE_UNIX], [Enable unix socket handling])

HAVE_PTY=0
AC_CHECK_HEADER(pty.h, [HAVE_PTY=1] )
AC_SUBST(HAVE_PTY)
AC_DEFINE_UNQUOTED([HAVE_PTY], [$HAVE_PTY], [Enable PTY gensio])
AM_CONDITIONAL([HAVE_PTY], [test ${HAVE_PTY} = 1])

AM_CONDITIONAL([HAVE_UNIX_OS], [test ${version_type} != windows])
AM_CONDITIONAL([HAVE_WINDOWS_OS], [test ${version_type} = windows])
AM_CONDITIONAL([HAVE_STDIO], [test ${version_type} != windows])
AM_CONDITIONAL([HAVE_SERIALDEV], [test ${version_type} != windows])

if test ${version_type} = windows; then
 HAVE_STDIO=0
 HAVE_SERIALDEV=0
else
 HAVE_STDIO=1
 HAVE_SERIALDEV=1
fi
AC_SUBST(HAVE_STDIO)
AC_DEFINE_UNQUOTED([HAVE_STDIO], [$HAVE_STDIO], [Enable stdio gensio])

AC_SUBST(HAVE_SERIALDEV)
AC_DEFINE_UNQUOTED([HAVE_SERIALDEV], [$HAVE_SERIALDEV], [Enable serialdev gensio])

if test ${version_type} = windows; then
 USE_FILE_STDIO=1
else
 USE_FILE_STDIO=0
fi
AC_ARG_WITH(file-stdio,
 [AS_HELP_STRING([--with-file-stdio[[=yes|no]]],
		 [Use stdio instead of unix files for the file gensio.])],
   if test "x$withval" = "xyes"; then
      USE_FILE_STDIO=1
   elif test "x$withval" = "xno"; then
      USE_FILE_STDIO=0
   elif test "x$withval" = "x"; then
      USE_FILE_STDIO=1
   fi,
)
AC_DEFINE_UNQUOTED([USE_FILE_STDIO], [$USE_FILE_STDIO],
	           [Use stdio for the file gensio])

AC_LANG(C)
AC_LINK_IFELSE([AC_LANG_PROGRAM([], [
	static int counter = 0;
	int val;

	__atomic_load(&counter, &val, __ATOMIC_SEQ_CST);
	return val;])],
	[HAVE_GCC_ATOMICS=1],
	[HAVE_GCC_ATOMICS=0])
AC_DEFINE_UNQUOTED([HAVE_GCC_ATOMICS], [$HAVE_GCC_ATOMICS],
	           [Are GCC atomic operations available])

AC_CHECK_FUNCS(sendmsg)
AC_CHECK_DECL(IP_ADD_MEMBERSHIP,
	      [AC_DEFINE([HAVE_MCAST], [], [Is multicast available?])],
	      [], [[#include <netinet/in.h>]])
AC_CHECK_FUNCS(isatty)
AC_CHECK_FUNCS(strcasecmp)
AC_CHECK_FUNCS(strncasecmp)
AC_CHECK_FUNCS(prctl)

CPPFLAGS="$CPPFLAGS -I\$(top_srcdir)/include -I\$(top_builddir)/include"

AC_OUTPUT([Makefile
	lib/libgensio.pc
	lib/Makefile
	include/Makefile
	include/gensio/Makefile
	include/gensio/gensio_version.h
	tests/Makefile
	tools/Makefile
	swig/Makefile
	swig/python/Makefile
	man/Makefile
	examples/Makefile
	tests/runtest
	tests/gensios_enabled.py])
