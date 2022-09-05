AC_INIT([gensio],[2.5.3],[minyard@acm.org])
AC_SUBST(gensio_VERSION_MAJOR, 2)
AC_SUBST(gensio_VERSION_MINOR, 5)
AC_SUBST(gensio_VERSION_PATCH, 3)
AC_SUBST(gensio_VERSION_STRING, ${PACKAGE_VERSION})
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([-Wall])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_CXX
AM_PROG_AR
LT_INIT

# defaults
AM_CFLAGS=
AM_CXXFLAGS=
EXTRA_CFLAGS=
uucp_locking_flag=yes
UUCP_LOCK_DIR=/var/spool/lock
USE_FILE_STDIO=0
broken_pselect=no
system_type=unix
case $target_os in
	mingw*)
		LIBS="$LIBS -lws2_32 -liphlpapi -lgdi32 -lbcrypt"
		LIBS="$LIBS -lsecur32 -luserenv -lwtsapi32 -lwinmm"
		LIBS="$LIBS -lole32"
		uucp_locking_flag=no
		system_type=windows
		USE_FILE_STDIO=1
		;;
	cygwin*)
		uucp_locking_flag=no
		;;
	linux*)
		UUCP_LOCK_DIR=/var/lock
		;;
	darwin*)
		broken_pselect=yes
		uucp_locking_flag=no
		;;
	*bsd* | *BSD*)
		broken_pselect=yes
		;;
	*)
		# Defaults, maybe it will work
		;;
esac

if test "$version_type" = "windows"; then
    # LN_S gets set to "cp -pR", which just doesn't work.  MinGW has
    # a working "ln", so force it.
    LN_SF="ln -sf"
else
    LN_SF="\$(LN_S) -f"
fi
AC_SUBST(LN_SF)

# If compiling static, turn off DLL visibility, primarily so Windows
# will link properly.  Don't allow both static and shared libraries
# to be built at the same time for now.
if test "$version_type" = "windows"; then
    if test "${enable_shared}" = yes; then
        enable_static=no
    fi
    if test "$enable_static" = "yes"; then
        EXTRA_CFLAGS="$EXTRA_CFLAGS -DGENSIO_LINK_STATIC"
    fi
    # Need to pull in some special things for osops.
    EXTRA_CFLAGS="$EXTRA_CFLAGS -DNTDDI_VERSION=0x0a000006 -DWINVER=0x0602"
fi


AC_ARG_WITH(uucp-locking,
 [AS_HELP_STRING([--with-uucp-locking], [Enable UUCP-style locking with yes/no, or set the uucp lock directory otherwise])],
 uucp_locking_flag="$withval")
case "$uucp_locking_flag" in
	yes)
		USE_UUCP_LOCKING=1
		;;
	no)
		USE_UUCP_LOCKING=0
		;;
	*)
		USE_UUCP_LOCKING=1
		UUCP_LOCK_DIR="$uucp_locking_flag"
		;;
esac
AC_DEFINE_UNQUOTED([USE_UUCP_LOCKING], [$USE_UUCP_LOCKING],
		   [Enable device locking])
AC_DEFINE_UNQUOTED([UUCP_LOCK_DIR], ["$UUCP_LOCK_DIR"],
		   [Directory holding UUCP locks])

AC_ARG_WITH(broken-pselect,
 [AS_HELP_STRING([--with-broken-pselect], [pselect is not atomic, work around it])],
 broken_pselect="$withval")
case "$broken_pselect" in
	yes)
		AC_DEFINE([BROKEN_PSELECT], [], [PSELECT call is not atomic])
		;;
	*)
		;;
esac

AC_ARG_WITH(tcp-wrappers,
 [AS_HELP_STRING([--with-tcp-wrappers], [Enable tcpwrappers support])],
 tcp_wrappers="$withval",
 tcp_wrappers="no")
if test "$tcp_wrappers" != "no"
then
  AC_CHECK_HEADERS([tcpd.h])
  AC_CHECK_LIB(wrap,request_init)
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

tryalsa=yes
AC_ARG_WITH(alsa,
 [AS_HELP_STRING([--with-alsa=yes|no], [Look for alsa])],
    if test "x$withval" = "xyes"; then
      tryalsa=yes
    elif test "x$withval" = "xno"; then
      tryalsa=no
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

if test "x$system_type" = "xunix"; then
   use_pthreads=yes
else
   use_pthreads=no
fi
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
       EXTRA_CFLAGS="$EXTRA_CFLAGS $PTHREAD_CFLAGS"
       CC="$PTHREAD_CC"
       AC_DEFINE([USE_PTHREADS], [], [Enable multithreaded support])],
      [if $use_pthreads_set; then
          AC_MSG_FAILURE([--with-pthreads was given, but no working pthread library was found])
       fi])
fi

if test "x$system_type" = "xunix"; then
   tryglib=yes
   trytcl=yes
else
   tryglib=no
   trytcl=no
fi

AC_ARG_WITH(glib,
 [AS_HELP_STRING([--with-glib=yes|no], [Look for glib.])],
    if test "x$withval" = "xyes"; then
      if test "x$tryglib" = "xno"; then
        AC_MSG_FAILURE([glib only support on Unix systems for now])
      fi
    elif test "x$withval" = "xno"; then
      tryglib=no
    fi,
)

glibcflags=
AC_ARG_WITH(glibcflags,
 [AS_HELP_STRING([--with-glibcflags=flags],
                 [Set the flags to compile with glib.])],
    glibcflags="$withval",
)

gliblibs=
AC_ARG_WITH(gliblibs,
 [AS_HELP_STRING([--with-gliblibs=libs],
                 [Set the libraries to link with glib.])],
    gliblibs="$withval",
)

AC_ARG_WITH(cplusplus,
 [AS_HELP_STRING([--with-cplusplus=yes|no],
                 [Enable or disable C++ support.])],
    cplusplus="$withval",
    [if test -z "$CXX"; then
        cplusplus=no
    else
        cplusplus=yes
    fi]
)

AC_ARG_WITH(cplusplus-ver,
 [AS_HELP_STRING([--with-cplusplus-ver=],
                 [Set the C++ version, same as the value of __cplusplus.])],
    cplusplusver="$withval",
    [if test "$cplusplus" = "yes"; then
        AC_LANG_PUSH([C++])
	AC_MSG_CHECKING([for C++ version support])
        cat confdefs.h - <<_ACEOF >conftest.$ac_ext
Version: __cplusplus
_ACEOF
        cplusplusver=`(eval "$ac_cpp conftest.$ac_ext") | grep '^Version:'`
        if test $? -ne 0; then
            AC_MSG_RESULT([check faied])
	    cplusplus=no
        else
	    cplusplusver=`echo $cplusplusver | sed 's/^Version: //'`
	    cplusplusver=`echo $cplusplusver | sed 's/L$//'`
            AC_MSG_RESULT([$cplusplusver])
        fi
	rm -f conftest.$ac_ext
        AC_LANG_POP([C++])
    else
	cplusplusver=0
    fi]
)

CPLUSPLUS_DIR=
if test "$cplusplus" = "yes"; then
    if test "$cplusplusver" -ge 201103; then
        CPLUSPLUS_DIR="c++"
    else
        AC_MSG_RESULT([C++ version $cplusplusver is too old, need at least 201102, disabling c++])
    fi
fi
AC_SUBST(CPLUSPLUS_DIR)

# Find pkg-config
pkgprog=
AC_PATH_PROG(pkgprog, pkg-config)

# Handle GLIB support
haveglib=no
if test "x$glibcflags" = "x" -o "x$gliblibs" = "x"; then
   glibprog=
   if test "x$tryglib" != "xno"; then
      if test "x$pkgprog" != "x"; then
         glibprog=$pkgprog
      fi
   fi
   GLIB_CFLAGS=
   GLIB_LIBS=
   if test "x$glibprog" != "x"; then
      GLIB_CFLAGS=`$glibprog --cflags gthread-2.0 2>/dev/null`
      if test $? = 0; then
         haveglib=yes
         GLIB_LIBS=`$glibprog --libs gthread-2.0 2>/dev/null`
      fi
   fi
else
   haveglib=yes
   GLIB_CFLAGS="$glibcflags"
   GLIB_LIBS="$gliblibs"
fi
echo "checking for glib... $haveglib"

AM_CONDITIONAL([HAVE_GLIB], [test "x$haveglib" = "xyes"])
if test "x$haveglib" = "xyes"; then
   AC_DEFINE([HAVE_GLIB], [], [Have GLIB libraries])
   GLIB_LIB='$(top_builddir)/glib/libgensioglib.la'
   GLIB_DIR=glib
else
   GLIB_LIB=
   GLIB_DIR=
fi
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)
AC_SUBST(GLIB_LIB)
AC_SUBST(GLIB_DIR)

AC_ARG_WITH(tcl,
[  --with-tcl=yes|no               Look for tcl.],
    if test "x$withval" = "xyes"; then
      trytcl=yes
    elif test "x$withval" = "xno"; then
      trytcl=no
    fi,
)

tclcflags=
AC_ARG_WITH(tclcflags,
[  --with-tclcflags=flags          Set the flags to compile with tcl.],
    tclcflags="$withval",
)

tcllibs=
AC_ARG_WITH(tcllibs,
[  --with-tcllibs=libs             Set the libraries to link with tcl.],
    tcllibs="$withval",
)

# Handle TCL support
TCL_LIBS=
TCL_CFLAGS=
havetcl=no
if test "x$trytcl" != "xno"; then
   FOUND_TCL_HEADER=no
   ver=`echo 'puts \$tcl_version' | tclsh`
   if test "x$tclcflags" = "x"; then
      AC_CHECK_HEADER(tcl/tcl.h, FOUND_TCL_HEADER=yes; )
      if test "x$FOUND_TCL_HEADER" != "xyes"; then
         AC_CHECK_HEADER(tcl/tcl.h, FOUND_TCL_HEADER=yes; )
	 if test "x$FOUND_TCL_HEADER" = "xyes"; then
	    tclcflags="-I /usr/include/tcl$ver"
            TCL_CFLAGS="$tclcflags"
	 fi
      else
	tclcflags="-I /usr/include/tcl"
        TCL_CFLAGS="$tclcflags"
      fi
   else
      TCL_CFLAGS="$tclcflags"
      FOUND_TCL_HEADER=yes
   fi
   if test "x$tcllibs" = "x"; then
      if test "x$FOUND_TCL_HEADER" = "xyes"; then
         AC_CHECK_LIB(tcl, Tcl_CancelIdleCall, TCL_LIBS=-ltcl)
         if test "x$TCL_LIBS" = "x"; then
            AC_CHECK_LIB(tcl$ver, Tcl_DoOneEvent, TCL_LIBS=-ltcl$ver)
	 fi
      fi
   else
      TCL_LIBS="$tcllibs"
   fi
   if test "x$FOUND_TCL_HEADER" = "xyes" -a "x$TCL_LIBS" != "x"; then
      havetcl=yes
   fi
fi

if test "x$havetcl" = "xyes"; then
   AC_DEFINE([HAVE_TCL], [], [Have TCL libraries])
   TCL_LIB='$(top_builddir)/tcl/libgensiotcl.la'
   TCL_DIR=tcl
else
   TCL_LIB=
   TCL_DIR=
fi
AC_SUBST(TCL_CFLAGS)
AC_SUBST(TCL_LIBS)
AC_SUBST(TCL_LIB)
AC_SUBST(TCL_DIR)

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

# Handle alsa support
HAVE_ALSA=no
if test "x$tryalsa" != "xno"; then
   found_alsa=no
   AC_CHECK_HEADER(alsa/asoundlib.h, found_alsa=yes; )
   if test "x$found_alsa" = "xyes"; then
      AC_CHECK_LIB(asound, snd_pcm_open, HAVE_ALSA=yes)
   fi
fi

if test "x$HAVE_ALSA" != "xno"; then
   LIBS="$LIBS -lasound"
   HAVE_ALSA=1
else
   HAVE_ALSA=0
fi
AC_DEFINE_UNQUOTED([HAVE_ALSA], [$HAVE_ALSA],
	[Set to 1 to enable alsa, 0 to disable])
AC_SUBST(HAVE_ALSA)

tryssl=yes
AC_ARG_WITH(ssl,
 [AS_HELP_STRING([--with-ssl[[=yes|no]]],
		 [Look for ssl.])],
    if test "x$withval" = "x"; then
      tryssl=yes
    elif test "x$withval" = "xyes"; then
      tryssl=yes
    elif test "x$withval" = "xno"; then
      tryssl=no
    fi,
)
HAVE_OPENSSL=0
if test $tryssl = yes; then
	AX_CHECK_OPENSSL([HAVE_OPENSSL=1
		  LIBS="$LIBS $OPENSSL_LIBS"
		  LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
		  CPPFLAGS="$CPPFLAGS $OPENSSL_INCLUDES"], [HAVE_OPENSSL=0])
fi
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

AC_CHECK_LIB(nsl,main)

trymdns=yes
AC_ARG_WITH(mdns,
 [AS_HELP_STRING([--with-mdns[[=yes|no]]],
		 [Look for mdns.])],
    if test "x$withval" = "x"; then
      trymdns=yes
    elif test "x$withval" = "xyes"; then
      trymdns=yes
    elif test "x$withval" = "xno"; then
      trymdns=no
    fi,
)
HAVE_AVAHI=0
if test $trymdns = yes; then
	AC_CHECK_LIB(avahi-client, avahi_client_new,
	     [AC_DEFINE([HAVE_AVAHI], [1], [Have avahi installed])
	     HAVE_AVAHI=1
	     LIBS="-lavahi-client -lavahi-common $LIBS"])
fi
AC_SUBST(HAVE_AVAHI)
GMDNS=
GMDNSMAN=
if test "x$HAVE_AVAHI" = "x1"; then
   GMDNS=gmdns
   GMDNSMAN=gmdns.1
fi
AC_SUBST(GMDNS)
AC_SUBST(GMDNSMAN)

# Now check for swig
SWIG_DIR=
SWIG_CPP_DIR=
SWIG=
if test "x$tryswig" = "xyes"; then
   if test "x$swigprog" != "x"; then
      SWIG="$swigprog"
   fi
   AX_PKG_SWIG([1.3.21])
   if test "x$SWIG" != "x"; then
      AC_DEFINE([HAVE_SWIG], [], [Have swig installed])
      SWIG_DIR=swig
      if test $SWIG_NUMVERSION -ge 40100; then
          SWIG_CPP_DIR=swig
      else
          AC_MSG_WARN([SWIG version >= 4.1.0 is required for C++ swig.])
      fi
   fi
fi
AC_SUBST(SWIG_DIR)
AC_SUBST(SWIG_CPP_DIR)
AC_SUBST(SWIG)

# Handle PYTHON support
PYTHON_DIR=
PYGENSIO_DIR=
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
   AX_PROG_PYTHON_VERSION([3.0.0],
       [
           PYTHON_SWIG_FLAGS=-py3
           PYGENSIO_DIR=pygensio
       ], [])
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
      PYTHON_HAS_THREADS=1
   else
      PYTHON_HAS_THREADS=0
   fi
fi

AC_SUBST(PYTHON_DIR)
AC_SUBST(PYGENSIO_DIR)
AC_SUBST(PYTHON_INSTALL_DIR)
AC_SUBST(PYTHON_INSTALL_LIB_DIR)
AC_SUBST(PYTHON_HAS_THREADS)
AC_SUBST(PYTHON_SWIG_FLAGS)

PYTHON_EXECUTABLE="${PYTHON}"
AC_SUBST(PYTHON_EXECUTABLE)

trygo=yes
GOPROG=
AC_ARG_WITH(go,
 [AS_HELP_STRING([--with-go[[=yes|no|PATH]]],
		 [Look for go, with the optional path.])],
    if test "x$withval" = "x"; then
      trygo=yes
    elif test "x$withval" = "xyes"; then
      trygo=yes
    elif test "x$withval" = "xno"; then
      trygo=no
    else
      GOPROG="$withval"
      trygo=yes
    fi,
)

GODIR=
if test $trygo = yes; then
	if test "x$GOPROG" = "x"; then
		AC_CHECK_TOOL([GOPROG], [go], [])
	fi
fi
if test "x$GOPROG" != "x"; then
	AC_DEFINE([HAVE_GO], [], [Have go installed])
	GO_DIR=go
fi
AC_SUBST(GOPROG)
AC_SUBST(GO_DIR)

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

AC_CHECK_FUNC(ptsname_r, [HAVE_PTSNAME_R=1], [HAVE_PTSNAME_R=0])
AC_DEFINE_UNQUOTED([HAVE_PTSNAME_R], [$HAVE_PTSNAME_R],
	[Set to 1 if ptsname_r is available, 0 if not])
AC_SUBST(HAVE_PTSNAME_R)
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
      GTLSSHD="gtlsshd\$(EXEEXT)"
      GTLSSHDMAN=gtlsshd.8
   elif test "$version_type" = "windows"; then
      GTLSSHD="gtlsshd\$(EXEEXT)"
      GTLSSHDMAN=gtlsshd.8
   fi
   GTLSSH="gtlssh\$(EXEEXT)"
   GTLSSHMAN=gtlssh.1
   if test ${system_type} = unix; then
      GTLSSYNC=gtlssync
      GTLSSYNCMAN=gtlssync.1
   fi
   GTLSSH_KEYGEN="gtlssh-keygen\$(EXEEXT)"
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
   ENABLE_INTERNAL_TRACE=1
else
   ENABLE_INTERNAL_TRACE=0
fi
AM_CONDITIONAL([ENABLE_INTERNAL_TRACE], [test ${enable_internal_trace} != no])

HAVE_UNIX=0
AC_CHECK_HEADER(sys/un.h, [HAVE_UNIX=1] )
AC_SUBST(HAVE_UNIX)
AC_DEFINE_UNQUOTED([HAVE_UNIX], [$HAVE_UNIX], [Enable unix socket handling])

if test "$version_type" = "windows"; then
   # We have PTY support for windows.
   HAVE_PTY=1
else
   HAVE_PTY=0
   AC_CHECK_FUNCS(posix_openpt, [HAVE_PTY=1])
fi
AC_SUBST(HAVE_PTY)
AC_DEFINE_UNQUOTED([HAVE_PTY], [$HAVE_PTY], [Enable PTY gensio])

AM_CONDITIONAL([HAVE_UNIX_OS], [test ${system_type} != windows])
AM_CONDITIONAL([HAVE_WINDOWS_OS], [test ${system_type} = windows])

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
AC_CHECK_FUNCS(recvmsg)
AC_CHECK_FUNCS(isatty)
AC_CHECK_FUNCS(strcasecmp)
AC_CHECK_FUNCS(strncasecmp)
AC_CHECK_FUNCS(prctl)

AC_CHECK_DECLS([SIGWINCH], [], [], [#include <signal.h>])

AM_CXXFLAGS="$AM_CXXFLAGS $EXTRA_CFLAGS -I\$(top_srcdir)/c++/include"
AM_CFLAGS="$AM_CFLAGS $EXTRA_CFLAGS"
AC_SUBST(AM_CXXFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(EXTRA_CFLAGS)

CPPFLAGS="$CPPFLAGS -I\$(top_srcdir)/include -I\$(top_builddir)/include"

AC_CONFIG_FILES([Makefile
	lib/libgensio.pc
	lib/Makefile
	swig/Makefile
	swig/python/libgensio_python_swig.pc
	swig/python/Makefile
	swig/include/gensio/Makefile
	swig/include/Makefile
	c++/Makefile
	c++/include/Makefile
	c++/include/gensio/Makefile
	c++/lib/Makefile
	c++/lib/libgensiocpp.pc
	c++/tests/Makefile
	c++/examples/Makefile
	c++/swig/Makefile
	c++/swig/include/Makefile
	c++/swig/pygensio/Makefile
	c++/swig/pygensio/include/Makefile
	c++/swig/pygensio/include/gensio/Makefile
	c++/swig/pygensio/tests/Makefile
	c++/swig/pygensio/tests/runtest
	c++/swig/go/Makefile
	c++/swig/go/gensio/Makefile
	c++/swig/go/examples/Makefile
	c++/swig/go/tests/Makefile
	c++/swig/go/tests/runtest
	c++/swig/go/tests/testbase/Makefile
	glib/libgensioglib.pc
	glib/Makefile
	glib/include/Makefile
	glib/include/gensio/Makefile
	glib/swig/Makefile
	glib/swig/python/Makefile
	glib/c++/Makefile
	glib/c++/include/Makefile
	glib/c++/include/gensio/Makefile
	glib/c++/tests/Makefile
	glib/c++/swig/Makefile
	glib/c++/swig/pygensio/Makefile
	tcl/libgensiotcl.pc
	tcl/Makefile
	tcl/include/Makefile
	tcl/include/gensio/Makefile
	tcl/swig/Makefile
	tcl/swig/python/Makefile
	tcl/c++/Makefile
	tcl/c++/include/Makefile
	tcl/c++/include/gensio/Makefile
	tcl/c++/tests/Makefile
	tcl/c++/swig/Makefile
	tcl/c++/swig/pygensio/Makefile
	include/Makefile
	include/gensio/Makefile
	include/gensio/gensio_version.h
	tests/Makefile
	tools/Makefile
	man/Makefile
	examples/Makefile
	tests/runtest
	tests/gensios_enabled.py
	tests/reflector.py])
AC_OUTPUT
