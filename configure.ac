AC_INIT([gensio],[3.0.0],[minyard@acm.org])
AC_SUBST(gensio_VERSION_MAJOR, 3)
AC_SUBST(gensio_VERSION_MINOR, 0)
AC_SUBST(gensio_VERSION_PATCH, 0)
AC_SUBST(gensio_VERSION_STRING, ${PACKAGE_VERSION})
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([-Wall])
AC_CONFIG_HEADERS([config.h])
AC_PROG_CC
AC_PROG_CXX

# Per discussions with the Debian maintainer, it's best for
# maintainers to have all the soname libary versions be the same if
# they come from a single source.  So here it is.
GENSIO_LIB_VERSION=14:0:0
AC_SUBST(GENSIO_LIB_VERSION)

AC_ARG_ENABLE([debug],
 [AS_HELP_STRING([--enable-debug], [add -g option when building])
AS_HELP_STRING([--disable-debug], [remove -g option when building])])
if test -z ${enable_debug}; then
   add_mg=yes
else
   add_mg=${enable_debug}
fi

# Add or remove -g as necessary.  This is message because we have to match
# -g at the beginning, end, in the middle, or by itself in the CFLAGS string.
# Maybe there is a better way to do this?

# Space and tab
ST='[[ 	]]'
if test "${add_mg}" = yes; then
   if ! echo "$CFLAGS" | grep -e "^-g${ST}" -e "${ST}-g$" -e "${ST}-g${ST}" -e "^-g$" ; then
      CFLAGS="$CFLAGS -g"
   fi
else
   CFLAGS=`echo $CFLAGS | sed -e "s/^-g${ST}//" -e "s/${ST}-g$//" -e "s/${ST}-g${ST}/ /g" -e "s/^-g$//"`
fi

AM_PROG_AR

# Per discussion at:
# https://lists.gnu.org/archive/html/libtool/2022-09/msg00000.html
# This enabled RUNPATH over RPATH.  libtool will not set
# LD_LIBRARY_PATH if RPATH is used, but the code uses LD_LIBRARY_PATH
# as a way to find module object files.  So this is a hack until a
# workaround is available.
OLD_LDFLAGS="$LDFLAGS"
if uname -a | grep '^Linux' >/dev/null 2>/dev/null; then
   LDFLAGS="$LDFLAGS -Wl,--enable-new-dtags"
fi
LT_INIT(dlopen)
LDFLAGS="$OLD_LDFLAGS"

# defaults
OSH_LIBS=
BASE_LIBS=
AM_CFLAGS=
AM_CXXFLAGS=
EXTRA_CFLAGS=
uucp_locking_flag=yes
UUCP_LOCK_DIR=/var/spool/lock
flock_locking_flag=yes
USE_FILE_STDIO=0
broken_pselect=no
system_type=unix

# macos defines git_t, but getgrouplist() takes int*
USE_GGL_INT=0

# posix_openpt doesn't work like what we want on macos.  You have to
# open the client before you can set the file descriptor non-blocking,
# which is a fairly annoying thing.  See
# https://developer.apple.com/forums/thread/734230 for details.
USE_OPENPTY=0

# openssl calls sigprocmask() in it's startup code for ARM and some
# other processors.  On at least macos, this affects all threads, not
# just the calling thread.  So if you load it while threads are
# running, it will modify the thread masks of all running threads, and
# screw things up for waking using signals.  Check for this on
# platforms that need it, and link -lssl to the main program to avoid
# the issue.  See
# https://github.com/openssl/openssl/issues/21541
link_ssl_with_main=no

# Python extension modules end in .pyd on Windows, so we need to override
# the extension from .dll to that.  We can ignore it on everything else.
PYTHON_EXT_EXT=.so
PYTHON_EXT_EXT_SET=

# Windows requires that -no-undefined be set, but homebrew on MacOS requires
# that -undefined be set.  Sigh.
PYTHON_UNDEF_FLAG=-undefined

# Do we use the login program to login with gtlsshd, or do we directly
# run the shell?  On MacOS you need to use login for things to work right.
USE_LOGIN_PROGRAM=0

# Do we have unix credentials on unix sockets?
HAVE_UCRED=0

HAVE_WIN32SOUND=0

DISABLE_GO=no

DISABLE_GTLSSHD=no

case $target_os in
	msys)
		# MSYS presents some challenges.  We hack things to
		# get them to compile, but not much works well.  See
		# the README file for details.
		OSH_LIBS="$OSH_LIBS -ldl"
		uucp_locking_flag=no
		flock_locking_flag=no
		PYTHON_UNDEF_FLAG=-no-undefined
		HAVE_WIN32SOUND=1
		DISABLE_GO=yes
		DISABLE_GTLSSHD=yes
		;;
	mingw*)
		OSH_LIBS="$OSH_LIBS -lws2_32 -liphlpapi -lgdi32 -lbcrypt"
		OSH_LIBS="$OSH_LIBS -lsecur32 -luserenv -lwtsapi32"
		OSH_LIBS="$OSH_LIBS -lole32"
		uucp_locking_flag=no
		flock_locking_flag=no
		system_type=windows
		USE_FILE_STDIO=1
		PYTHON_EXT_EXT=".pyd"
		PYTHON_EXT_EXT_SET="-shrext .pyd"
		PYTHON_UNDEF_FLAG=-no-undefined
		HAVE_WIN32SOUND=1
		;;
	cygwin*)
		OSH_LIBS="$OSH_LIBS -ldl"
		uucp_locking_flag=no
		flock_locking_flag=no
		;;
	linux*)
		OSH_LIBS="$OSH_LIBS -ldl"
		UUCP_LOCK_DIR=/var/lock
		HAVE_UCRED=1
		;;
	darwin*)
		# macos
		OSH_LIBS="$OSH_LIBS -ldl"
		link_ssl_with_main=check
		uucp_locking_flag=no
		USE_GGL_INT=1
		USE_OPENPTY=1
		USE_LOGIN_PROGRAM=1
		HAVE_UCRED=1
		broken_pselect=yes
		;;
	freebsd*)
		OSH_LIBS="$OSH_LIBS -ldl"
		broken_pselect=yes
		HAVE_UCRED=1
		;;
	*bsd* | *BSD*)
		OSH_LIBS="$OSH_LIBS -ldl"
		broken_pselect=yes
		;;
	*)
		# Defaults, maybe it will work
		OSH_LIBS="$OSH_LIBS -ldl"
		;;
esac
AC_DEFINE_UNQUOTED([USE_GGL_INT], [$USE_GGL_INT],
	[Set to 1 to use gid_t, 0 to use int for groups])
AM_CONDITIONAL([USE_GGL_INT], [test ${USE_GGL_INT} = 1])
AC_SUBST(USE_GGL_INT)
AC_DEFINE_UNQUOTED([USE_OPENPTY], [$USE_OPENPTY],
	[Set to 1 to use openpty, 0 to use posix_openpt])
AM_CONDITIONAL([USE_OPENPTY], [test ${USE_OPENPTY} = 1])
AC_SUBST(USE_OPENPTY)

AC_SUBST(PYTHON_EXT_EXT)
AC_SUBST(PYTHON_EXT_EXT_SET)

AC_DEFINE_UNQUOTED([USE_LOGIN_PROGRAM], [$USE_LOGIN_PROGRAM],
	[Set to 1 to use login, 0 to directly execute the shell on login])
AM_CONDITIONAL([USE_LOGIN_PROGRAM], [test ${USE_LOGIN_PROGRAM} = 1])
AC_SUBST(USE_LOGIN_PROGRAM)

AC_DEFINE_UNQUOTED([HAVE_UCRED], [$HAVE_UCRED],
	[Set to 1 if Unix credentials (permissions) enabled, 0 if not])
AM_CONDITIONAL([HAVE_UCRED], [test ${HAVE_UCRED} = 1])
AC_SUBST(HAVE_UCRED)

AC_ARG_WITH(link-ssl-with-main,
	    [AS_HELP_STRING([--with-link-ssl-with-main=[yes|no]],
			    [Link libssl with the main program.  See "Issues with openssl and signal masks" in the FAQ])],
	    [link_ssl_with_main="$withval"]
)

pkgconfig_update_info() {
   AC_MSG_CHECKING(["CPPFLAGS for $1"])
   new_cppflags=`pkg-config --cflags $1`
   if test -z $new_cppflags; then
      AC_MSG_RESULT(["Not available"])
   else
      CPPFLAGS="$new_cppflags $CPPFLAGS"
      AC_MSG_RESULT(["$new_cppflags"])
   fi

   AC_MSG_CHECKING(["LDFLAGS for $1"])
   new_ldflags=`pkg-config --libs-only-L $1`
   if test -z $new_ldflags; then
      AC_MSG_RESULT(["Not available"])
   else
      LDFLAGS="$new_ldflags $LDFLAGS"
      AC_MSG_RESULT(["$new_ldflags"])
   fi
}

case $target_os in
   darwin*)
      pkgconfig_update_info openssl
      pkgconfig_update_info portaudio-2.0
      ;;
   *) ;;
esac

if test "$link_ssl_with_main" = "check"; then
    AC_MSG_CHECKING([if ssl needs to be linked with the main library])
    OPENSSLLIBDIR=`pkg-config --libs-only-L openssl | sed 's/-L//'`
    AC_LANG_PUSH(C)
    AC_RUN_IFELSE(
	[AC_LANG_SOURCE([[
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <assert.h>
#include <sys/select.h>

struct cross_thread_info {
    int waitfd;
    int err;
};

static void *
cross_thread(void *data)
{
    struct cross_thread_info *info = data;
    sigset_t sigmask, omask;
    int rv = 0;
    fd_set rfds;

    rv = pthread_sigmask(SIG_SETMASK, NULL, &sigmask);
    assert(rv == 0);

    if (!sigismember(&sigmask, SIGUSR1)) {
	fprintf(stderr, "SIGUSR1 not in sigmask 1\n");
	info->err = 1;
	goto out_err;
    }

    FD_ZERO(&rfds);
    FD_SET(info->waitfd, &rfds);
    sigdelset(&sigmask, SIGUSR1);
    rv = pthread_sigmask(SIG_SETMASK, &sigmask, &omask);
    assert(rv == 0);

    rv = pselect(info->waitfd + 1, &rfds, NULL, NULL, NULL, NULL);
    assert(rv == 1);

    rv = pthread_sigmask(SIG_SETMASK, &omask, &sigmask);
    assert(rv == 0);
    if (sigismember(&sigmask, SIGUSR1)) {
	fprintf(stderr, "SIGUSR1 in sigmask 1\n");
	info->err = 4;
	goto out_err;
    }

 out_err:
    return NULL;
}

static int
check_pselect_cross_thread(sigset_t mask)
{
    int rv = 1;
    int pipefds[2] = { -1, -1 };
    struct cross_thread_info info;
    pthread_t th;
    char dummy = 0;

    rv = pipe(pipefds);
    if (rv == -1) {
	perror("pipe");
	return 1;
    }

    info.err = 0;
    info.waitfd = pipefds[0];
    rv = pthread_create(&th, NULL, cross_thread, &info);

    sleep(2); /* Give the thread time to enter pselect() */

    if (dlopen("$OPENSSLLIBDIR/libssl.dylib", RTLD_LAZY | RTLD_GLOBAL) == NULL) {
	fprintf(stderr, "dlopen failed: %s\n", dlerror());
	rv = 1;
    }

    write(pipefds[1], &dummy, 1);

    pthread_join(th, NULL);

    if (!rv)
	rv = info.err;

    if (!rv)
	printf("dlopen does not affect other threads' sigmasks\n");

    close(pipefds[0]);
    close(pipefds[1]);
    return rv;
}

int
main(int argc, char *argv[])
{
    sigset_t mask;
    int rv;

    /* Start with SIGUSR1 blocked. */
    rv = sigprocmask(SIG_SETMASK, NULL, &mask);
    assert(rv == 0);
    sigaddset(&mask, SIGUSR1);
    rv = sigprocmask(SIG_SETMASK, &mask, NULL);
    assert(rv == 0);

    rv = check_pselect_cross_thread(mask);
    return rv;
}]])],
	[link_ssl_with_main=no],
	[[if test $? = 4; then
	     link_ssl_with_main=yes
	 else
	     link_ssl_with_main=failed
	 fi
	]],
	[link_ssl_with_main=yes])
    AC_LANG_POP(C)
    AC_MSG_RESULT($link_ssl_with_main)
    if test $link_ssl_with_main == failed; then
	AC_MSG_FAILURE([Error running ssl link test program.])
    fi
fi

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

moduleinstalldir="\$(pkglibexecdir)"
AC_ARG_WITH(moduleinstall,
 [AS_HELP_STRING([--with-moduleinstall=PATH],
		 [Install gensio modules in the given location.])],
    moduleinstalldir="$withval",
)
AC_SUBST(moduleinstalldir)

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

AC_ARG_WITH(flock-locking,
 [AS_HELP_STRING([--with-flock-locking], [Enable flock-style on serial port locking with yes/no])],
 flock_locking_flag="$withval")
case "$flock_locking_flag" in
	yes)
		USE_FLOCK_LOCKING=1
		;;
	no)
		USE_FLOCK_LOCKING=0
		;;
	*)
		USE_FLOCK_LOCKING=1
		;;
esac
AC_DEFINE_UNQUOTED([USE_FLOCK_LOCKING], [$USE_FLOCK_LOCKING],
		   [Enable device locking])

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
  AC_CHECK_LIB(wrap, request_init,
	       [HAVE_LIBWRAP=1; OSH_LIBS="-lwrap $OSH_LIBS"])
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

AC_CHECK_FUNCS(kevent)

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
    else
      AC_MSG_FAILURE([Unknown value for --with-pthreads. Use yes or no])
    fi,
)

if test "x$use_pthreads" != "xno"; then
   AX_PTHREAD(
      [OSH_LIBS="$OSH_LIBS $PTHREAD_LIBS"
       EXTRA_CFLAGS="$EXTRA_CFLAGS $PTHREAD_CFLAGS"
       CC="$PTHREAD_CC"
       AC_DEFINE([USE_PTHREADS], [], [Enable multithreaded support])],
      [if $use_pthreads_set; then
          AC_MSG_FAILURE([--with-pthreads was given, but no working pthread library was found])
       fi
       use_pthreads=no])
fi

if test "x$system_type" = "xunix"; then
   tryglib=yes
   trytcl=yes
else
   tryglib=no
   trytcl=no
fi

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

HAVE_CXX11=0
CPLUSPLUS_DIR=
if test "$cplusplus" = "yes"; then
    AX_CXX_COMPILE_STDCXX(11, [], [optional])
    if test "$HAVE_CXX11" = 1; then
        CPLUSPLUS_DIR="c++"
    else
        AC_MSG_RESULT([C++ version $cplusplusver is too old, need at least 201102, disabling c++])
    fi
fi
AC_SUBST(CPLUSPLUS_DIR)

# Find pkg-config
pkgprog=
AC_PATH_PROG(pkgprog, pkg-config)

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
         AC_CHECK_HEADER(tcl.h, FOUND_TCL_HEADER=yes; )
	 if test "x$FOUND_TCL_HEADER" = "xyes"; then
            TCL_CFLAGS=""
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

AC_CHECK_FUNCS(regexec)
AC_CHECK_FUNCS(fnmatch)
have_pcre_posix=no
REGEX_LIB=
if test "x$ac_cv_func_regexec" != xyes; then
   AC_CHECK_LIB(pcreposix, regexec, have_pcre_posix=yes)
   if test $have_pcre_posix = yes; then
      REGEX_LIB=-lpcreposix
      AC_DEFINE([HAVE_PCRE_POSIX], [], [Have PCRE POSIX regex])
      ac_cv_func_regexec=pcre
   fi
fi
AC_SUBST(REGEX_LIB)

AC_CHECK_FUNCS(fnmatch)

# If not creating shared libraries, build everything in.
if test "$enable_shared" = "no"; then
   default_all=yes
else
   default_all=dynamic
fi
AC_ARG_WITH(all-gensios,
 [AS_HELP_STRING([--with-all-gensios=yes|dynamic|no],
                 [Default setting for all gensios])],
    if test "x$withval" = "xyes"; then
      default_all=yes
    elif test "x$withval" = "xdynamic"; then
      default_all=dynamic
    elif test "x$withval" = "xno"; then
      default_all=no
    fi,
)

BUILTIN_GENSIOS=""
DYNAMIC_GENSIOS=""

net=$default_all
AC_ARG_WITH(net,
 [AS_HELP_STRING([--with-net=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      net=yes
    elif test "x$withval" = "xdynamic"; then
      net=dynamic
    elif test "x$withval" = "xno"; then
      net=no
    fi,
)
BUILTIN_NET=0
DYNAMIC_NET=
case $net in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS net"
      BUILTIN_NET=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS net"
      DYNAMIC_NET=libgensio_net.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_NET], [test ${BUILTIN_NET} = 1])
AC_SUBST(DYNAMIC_NET)

dgram=$default_all
AC_ARG_WITH(dgram,
 [AS_HELP_STRING([--with-dgram=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      dgram=yes
    elif test "x$withval" = "xdynamic"; then
      dgram=dynamic
    elif test "x$withval" = "xno"; then
      dgram=no
    fi,
)
BUILTIN_DGRAM=0
DYNAMIC_DGRAM=
case $dgram in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS dgram"
      BUILTIN_DGRAM=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS dgram"
      DYNAMIC_DGRAM=libgensio_dgram.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_DGRAM], [test ${BUILTIN_DGRAM} = 1])
AC_SUBST(DYNAMIC_DGRAM)

trysctp=yes
AC_ARG_WITH(sctp,
 [AS_HELP_STRING([--with-sctp=yes|no], [Look for sctp])],
    if test "x$withval" = "xyes"; then
      trysctp=yes
    elif test "x$withval" = "xno"; then
      trysctp=no
    fi,
)

HAVE_LIBSCTP=0
if test "x$trysctp" != "xno"; then
   AC_CHECK_LIB(sctp, sctp_bindx, [HAVE_LIBSCTP=1])
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

if test "$HAVE_LIBSCTP" = "1"; then
   sctp=$default_all
   OSH_LIBS="-lsctp $OSH_LIBS"
else
   sctp=no
fi

AC_ARG_WITH(sctp,
 [AS_HELP_STRING([--with-sctp=yes|dynamic|no], [Enable sctp gensio])],
    if test "x$withval" = "xyes"; then
      sctp=yes
    elif test "x$withval" = "xdynamic"; then
      sctp=dynamic
    elif test "x$withval" = "xno"; then
      sctp=no
    fi,
)
BUILTIN_SCTP=0
DYNAMIC_SCTP=
case $sctp in
   yes)
      if test $HAVE_LIBSCTP = 0; then
         AC_MSG_ERROR("sctp enabled but libsctp not found")
      fi
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS sctp"
      BUILTIN_SCTP=1
      ;;
   dynamic)
      if test $HAVE_LIBSCTP = 0; then
         AC_MSG_ERROR("sctp enabled but libsctp not found")
      fi
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS sctp"
      DYNAMIC_SCTP=libgensio_sctp.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_SCTP], [test ${BUILTIN_SCTP} = 1])
AC_SUBST(DYNAMIC_SCTP)

stdio=$default_all
AC_ARG_WITH(stdio,
 [AS_HELP_STRING([--with-stdio=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      stdio=yes
    elif test "x$withval" = "xdynamic"; then
      stdio=dynamic
    elif test "x$withval" = "xno"; then
      stdio=no
    fi,
)
BUILTIN_STDIO=0
DYNAMIC_STDIO=
case $stdio in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS stdio"
      BUILTIN_STDIO=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS stdio"
      DYNAMIC_STDIO=libgensio_stdio.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_STDIO], [test ${BUILTIN_STDIO} = 1])
AC_SUBST(DYNAMIC_STDIO)

pty=$default_all
AC_ARG_WITH(pty,
 [AS_HELP_STRING([--with-pty=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      pty=yes
    elif test "x$withval" = "xdynamic"; then
      pty=dynamic
    elif test "x$withval" = "xno"; then
      pty=no
    fi,
)
BUILTIN_PTY=0
DYNAMIC_PTY=
case $pty in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS pty"
      BUILTIN_PTY=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS pty"
      DYNAMIC_PTY=libgensio_pty.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_PTY], [test ${BUILTIN_PTY} = 1])
AC_SUBST(DYNAMIC_PTY)

dummy=$default_all
AC_ARG_WITH(dummy,
 [AS_HELP_STRING([--with-dummy=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      dummy=yes
    elif test "x$withval" = "xdynamic"; then
      dummy=dynamic
    elif test "x$withval" = "xno"; then
      dummy=no
    fi,
)
BUILTIN_DUMMY=0
DYNAMIC_DUMMY=
case $dummy in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS dummy"
      BUILTIN_DUMMY=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS dummy"
      DYNAMIC_DUMMY=libgensio_dummy.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_DUMMY], [test ${BUILTIN_DUMMY} = 1])
AC_SUBST(DYNAMIC_DUMMY)

conacc=$default_all
AC_ARG_WITH(conacc,
 [AS_HELP_STRING([--with-conacc=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      conacc=yes
    elif test "x$withval" = "xdynamic"; then
      conacc=dynamic
    elif test "x$withval" = "xno"; then
      conacc=no
    fi,
)
BUILTIN_CONACC=0
DYNAMIC_CONACC=
case $conacc in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS conacc"
      BUILTIN_CONACC=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS conacc"
      DYNAMIC_CONACC=libgensio_conacc.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_CONACC], [test ${BUILTIN_CONACC} = 1])
AC_SUBST(DYNAMIC_CONACC)

serialdev=$default_all
AC_ARG_WITH(serialdev,
 [AS_HELP_STRING([--with-serialdev=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      serialdev=yes
    elif test "x$withval" = "xdynamic"; then
      serialdev=dynamic
    elif test "x$withval" = "xno"; then
      serialdev=no
    fi,
)
BUILTIN_SERIALDEV=0
DYNAMIC_SERIALDEV=
case $serialdev in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS serialdev"
      BUILTIN_SERIALDEV=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS serialdev"
      DYNAMIC_SERIALDEV=libgensio_serialdev.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_SERIALDEV], [test ${BUILTIN_SERIALDEV} = 1])
AC_SUBST(DYNAMIC_SERIALDEV)

echo=$default_all
AC_ARG_WITH(echo,
 [AS_HELP_STRING([--with-echo=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      echo=yes
    elif test "x$withval" = "xdynamic"; then
      echo=dynamic
    elif test "x$withval" = "xno"; then
      echo=no
    fi,
)
BUILTIN_ECHO=0
DYNAMIC_ECHO=
case $echo in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS echo"
      BUILTIN_ECHO=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS echo"
      DYNAMIC_ECHO=libgensio_echo.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_ECHO], [test ${BUILTIN_ECHO} = 1])
AC_SUBST(DYNAMIC_ECHO)

file=$default_all
AC_ARG_WITH(file,
 [AS_HELP_STRING([--with-file=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      file=yes
    elif test "x$withval" = "xdynamic"; then
      file=dynamic
    elif test "x$withval" = "xno"; then
      file=no
    fi,
)
BUILTIN_FILE=0
DYNAMIC_FILE=
case $file in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS file"
      BUILTIN_FILE=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS file"
      DYNAMIC_FILE=libgensio_file.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_FILE], [test ${BUILTIN_FILE} = 1])
AC_SUBST(DYNAMIC_FILE)

# Handle OpenIPMI support
OPENIPMI_CPPFLAGS=
AC_ARG_WITH(openipmiflags,
 [AS_HELP_STRING([--with-openipmiflags=flags],
		 [Set the flags to compile with OpenIPMI.])],
    OPENIPMI_CPPFLAGS="$withval"
)

OPENIPMI_LIBS=
AC_ARG_WITH(openipmilibs,
 [AS_HELP_STRING([--with-openipmilibs=libs],
		 [Set the libraries to link with OpenIPMI.])],
    OPENIPMI_LIBS="$withval"
)

AC_ARG_WITH(openipmi,
 [AS_HELP_STRING([--with-openipmi=yes|dynamic|no], [Look for openipmi])],
    if test "x$withval" = "xyes"; then
      tryopenipmi=yes
    elif test "x$withval" = "xno"; then
      tryopenipmi=no
    fi,
)
HAVE_OPENIPMI=0
if test "x$tryopenipmi" != "xno"; then
   found_ipmiif=no
   AC_CHECK_HEADER(OpenIPMI/ipmiif.h, found_ipmiif=yes; )
   if test "x$found_ipmiif" = "xyes"; then
      AC_CHECK_LIB(OpenIPMI, ipmi_alloc_os_handler, [HAVE_OPENIPMI=1])
   fi
fi

if test "$HAVE_OPENIPMI" = "1"; then
   ipmisol=$default_all
   if test "x$OPENIPMI_LIBS" = "x"; then
      if test "x$ax_pthread_ok" = "xyes"; then
         OPENIPMI_LIBS="-lOpenIPMI -lOpenIPMIpthread -lOpenIPMIutils"
      else
         OPENIPMI_LIBS="-lOpenIPMI -lOpenIPMIposix -lOpenIPMIutils"
      fi
   fi
else
   ipmisol=no
fi
AC_DEFINE_UNQUOTED([HAVE_OPENIPMI], [$HAVE_OPENIPMI],
	[Set to 1 to enable IPMI support through OpenIPMI, 0 to disable])
AM_CONDITIONAL([HAVE_OPENIPMI], [test ${HAVE_OPENIPMI} = 1])
AC_SUBST(HAVE_OPENIPMI)
AC_SUBST(OPENIPMI_CPPFLAGS)
AC_SUBST(OPENIPMI_LIBS)

AC_ARG_WITH(ipmisol,
 [AS_HELP_STRING([--with-ipmisol=yes|dynamic|no], [Enable ipmisol gensio])],
    if test "x$withval" = "xyes"; then
      ipmisol=yes
    elif test "x$withval" = "xdynamic"; then
      ipmisol=dynamic
    elif test "x$withval" = "xno"; then
      ipmisol=no
    fi,
)
BUILTIN_IPMISOL=0
DYNAMIC_IPMISOL=
case $ipmisol in
   yes)
      if test $HAVE_OPENIPMI = 0; then
         AC_MSG_ERROR("ipmisol enabled but openipmi not found")
      fi
      BASE_LIBS="$BASE_LIBS $OPENIPMI_LIBS"
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS ipmisol"
      BUILTIN_IPMISOL=1
      ;;
   dynamic)
      if test $HAVE_OPENIPMI = 0; then
         AC_MSG_ERROR("ipmisol enabled but openipmi not found")
      fi
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS ipmisol"
      DYNAMIC_IPMISOL=libgensio_ipmisol.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_IPMISOL], [test ${BUILTIN_IPMISOL} = 1])
AC_SUBST(DYNAMIC_IPMISOL)

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
HAVE_MDNS=0

HAVE_AVAHI=0
tryavahi=yes
AC_ARG_WITH(avahi,
 [AS_HELP_STRING([--with-avahi[[=yes|no]]],
		 [Look for avahi.])],
    if test "x$withval" = "x"; then
      tryavahi=yes
    elif test "x$withval" = "xyes"; then
      tryavahi=yes
    elif test "x$withval" = "xno"; then
      tryavahi=no
    fi,
)
if test $trymdns = yes -a $tryavahi = yes; then
    AC_CHECK_LIB(avahi-client, avahi_client_new, [HAVE_AVAHI=1])
fi
if test "$HAVE_AVAHI" = "1"; then
   mdns=$default_all
   MDNS_LIBS="-lavahi-client -lavahi-common"
   HAVE_MDNS=1
fi
AC_DEFINE_UNQUOTED([HAVE_AVAHI], [$HAVE_AVAHI],
	[Set to 1 to enable MDNS support through avahi, 0 to disable])
AM_CONDITIONAL([HAVE_AVAHI], [test ${HAVE_AVAHI} = 1])
AC_SUBST(HAVE_AVAHI)

HAVE_DNSSD=0
trydnssd=yes
AC_ARG_WITH(dnssd,
 [AS_HELP_STRING([--with-dnssd[[=yes|no]]],
		 [Look for dnssd.])],
    if test "x$withval" = "x"; then
      trydnssd=yes
    elif test "x$withval" = "xyes"; then
      trydnssd=yes
    elif test "x$withval" = "xno"; then
      trydnssd=no
    fi,
)
if test $trymdns = yes -a ${HAVE_AVAHI} = 0 -a $trydnssd = yes; then
   found_dns_sh=no
   AC_CHECK_HEADER(dns_sd.h, [found_dns_sd=yes])
   if test "x$found_dns_sd" = "xyes"; then
      AC_CHECK_LIB(dns_sd, DNSServiceRegister, [HAVE_DNSSD=1])
      if test "$HAVE_DNSSD" = "1"; then
         MDNS_LIBS="-ldns_sd"
      else
         AC_CHECK_FUNC(DNSServiceRegister, [HAVE_DNSSD=1])
      fi
      if test "$HAVE_DNSSD" = "1"; then
         mdns=$default_all
         HAVE_MDNS=1
      fi
   fi
fi
AC_DEFINE_UNQUOTED([HAVE_DNSSD], [$HAVE_DNSSD],
	[Set to 1 to enable MDNS support through dnssd, 0 to disable])
AM_CONDITIONAL([HAVE_DNSSD], [test ${HAVE_DNSSD} = 1])
AC_SUBST(HAVE_DNSSD)

HAVE_WINMDNS=0
if test "$version_type" = "windows"; then
   trywinmdns=yes
else
   trywinmdns=no
fi
AC_ARG_WITH(winmdns,
 [AS_HELP_STRING([--with-winmdns[[=yes|no]]],
		 [Look for windows mdns.])],
    if test "x$withval" = "x"; then
      trywinmdns=yes
    elif test "x$withval" = "xyes"; then
      trywinmdns=yes
    elif test "x$withval" = "xno"; then
      trywinmdns=no
    fi,
)
if test $trymdns = yes -a ${HAVE_AVAHI} = 0 -a ${HAVE_DNSSD} = 0 \
		-a $trywinmdns = yes; then
   found_windns=no
   AC_CHECK_HEADER(windns.h, [found_windns=yes], [], [#include <windows.h>])
   if test "x$found_windns" = "xyes"; then
       # AC_CHECK_LIB() doesn't work on DnsServiceBrowse() on mingw32,
       # for some reason it won't compile without includeing windns.h.
       AC_MSG_CHECKING([for MDNS support in Windows])
       AC_LANG_PUSH(C)
       AC_COMPILE_IFELSE(
	   [AC_LANG_PROGRAM([[#include <windows.h>
#include <windns.h>]],
			    [[DnsServiceBrowse(NULL, NULL);]])],
	   [HAVE_WINMDNS=1; AC_MSG_RESULT([yes])], [AC_MSG_RESULT([no])])
       AC_LANG_POP(C)
   fi
   if test "$HAVE_WINMDNS" = "1"; then
      mdns=$default_all
      MDNS_LIBS="-ldnsapi"
      if test $target_os = msys; then
	  # We are using Windows MDNS on MSYS2
	  MDNS_LIBS="-liphlpapi $MDNS_LIBS"
      fi
      HAVE_MDNS=1
   fi
fi
AC_DEFINE_UNQUOTED([HAVE_WINMDNS], [$HAVE_WINMDNS],
	[Set to 1 to enable MDNS support through winmdns, 0 to disable])
AM_CONDITIONAL([HAVE_WINMDNS], [test ${HAVE_WINMDNS} = 1])
AC_SUBST(HAVE_WINMDNS)

AC_SUBST(MDNS_LIBS)

GMDNS=
GMDNSMAN=
if test ${HAVE_MDNS} = 1; then
   GMDNS="gmdns\$(EXEEXT)"
   GMDNSMAN=gmdns.1
else
   mdns=no
fi
AC_SUBST(GMDNS)
AC_SUBST(GMDNSMAN)
AC_DEFINE_UNQUOTED([HAVE_MDNS], [$HAVE_MDNS],
	[Set to 1 to enable MDNS support, 0 to disable])
AM_CONDITIONAL([HAVE_MDNS], [test ${HAVE_MDNS} = 1])
AC_SUBST(HAVE_MDNS)

AC_ARG_WITH(mdns,
 [AS_HELP_STRING([--with-mdns=yes|dynamic|no], [Enable mdns gensio])],
    if test "x$withval" = "xyes"; then
      mdns=yes
    elif test "x$withval" = "xdynamic"; then
      mdns=dynamic
    elif test "x$withval" = "xno"; then
      mdns=no
    fi,
)
BUILTIN_MDNS=0
DYNAMIC_MDNS=
BUILTIN_MDNS_LIBS=
case $mdns in
   yes)
      if test $HAVE_MDNS = 0; then
         AC_MSG_ERROR("mdns enabled but no support not found")
      fi
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS mdns"
      BUILTIN_MDNS_LIBS="$MDNS_LIBS"
      BUILTIN_MDNS=1
      ;;
   dynamic)
      if test $HAVE_MDNS = 0; then
         AC_MSG_ERROR("mdns enabled but no support not found")
      fi
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS mdns"
      DYNAMIC_MDNS=libgensio_mdns.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_MDNS], [test ${BUILTIN_MDNS} = 1])
AC_SUBST(DYNAMIC_MDNS)
AC_SUBST(BUILTIN_MDNS_LIBS)

SOUND_LIBS=

# Handle alsa support
tryalsa=yes
AC_ARG_WITH(alsa,
 [AS_HELP_STRING([--with-alsa=yes|no], [Look for alsa])],
    if test "x$withval" = "xyes"; then
      tryalsa=yes
    elif test "x$withval" = "xno"; then
      tryalsa=no
    fi,
)

HAVE_ALSA=no
if test "x$tryalsa" != "xno"; then
   found_alsa=no
   AC_CHECK_HEADER(alsa/asoundlib.h, found_alsa=yes; )
   if test "x$found_alsa" = "xyes"; then
      AC_CHECK_LIB(asound, snd_pcm_open, HAVE_ALSA=yes)
   fi
fi

if test "x$HAVE_ALSA" != "xno"; then
   SOUND_LIBS="$SOUND_LIBS -lasound"
   HAVE_ALSA=1
else
   HAVE_ALSA=0
fi
AC_DEFINE_UNQUOTED([HAVE_ALSA], [$HAVE_ALSA],
	[Set to 1 to enable alsa, 0 to disable])
AC_SUBST(HAVE_ALSA)

# Allow windows sound to be disabled
AC_ARG_WITH(winsound,
 [AS_HELP_STRING([--with-winsound=yes|no], [Use windows sound])],
    if test "x$withval" = "xyes"; then
      HAVE_WIN32SOUND=1
    elif test "x$withval" = "xno"; then
      HAVE_WIN32SOUND=0
    fi,
)
AC_DEFINE_UNQUOTED([HAVE_WIN32SOUND], [$HAVE_WIN32SOUND],
	[Set to 1 to enable windows , 0 to disable])
AC_SUBST(HAVE_WIN32SOUND)
if test $HAVE_WIN32SOUND = 1; then
    SOUND_LIBS="$SOUND_LIBS -lwinmm"
fi

# Handle portaudio support, only try if we don't have something else
if test $HAVE_ALSA = 1 -o $HAVE_WIN32SOUND == 1; then
   tryportaudio=no
else
   tryportaudio=yes
fi
HAVE_PORTAUDIO=no
AC_ARG_WITH(portaudio,
 [AS_HELP_STRING([--with-portaudio=yes|no], [Look for portaudio])],
    if test "x$withval" = "xyes"; then
      tryportaudio=yes
    elif test "x$withval" = "xno"; then
      tryportaudio=no
    fi,
)
if test "x$tryportaudio" != "xno"; then
   found_portaudio=no
   AC_CHECK_HEADER(portaudio.h, found_portaudio=yes; )
   if test "x$found_portaudio" = "xyes"; then
      AC_CHECK_LIB(portaudio, Pa_OpenStream, HAVE_PORTAUDIO=yes)
   fi
fi

if test "x$HAVE_PORTAUDIO" != "xno"; then
   SOUND_LIBS="$SOUND_LIBS -lportaudio"
   HAVE_PORTAUDIO=1
else
   HAVE_PORTAUDIO=0
fi
AC_DEFINE_UNQUOTED([HAVE_PORTAUDIO], [$HAVE_PORTAUDIO],
	[Set to 1 to enable portaudio, 0 to disable])
AC_SUBST(HAVE_PORTAUDIO)

AC_SUBST(SOUND_LIBS)

sound=$default_all
AC_ARG_WITH(sound,
 [AS_HELP_STRING([--with-sound=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      sound=yes
    elif test "x$withval" = "xdynamic"; then
      sound=dynamic
    elif test "x$withval" = "xno"; then
      sound=no
    fi,
)
BUILTIN_SOUND=0
DYNAMIC_SOUND=
case $sound in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS sound"
      BUILTIN_SOUND=1
      BASE_LIBS="$BASE_LIBS $SOUND_LIBS"
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS sound"
      DYNAMIC_SOUND=libgensio_sound.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_SOUND], [test ${BUILTIN_SOUND} = 1])
AC_SUBST(DYNAMIC_SOUND)

# Handle udev support
tryudev=yes
AC_ARG_WITH(udev,
 [AS_HELP_STRING([--with-udev=yes|no], [Look for udev])],
    if test "x$withval" = "xyes"; then
      tryudev=yes
    elif test "x$withval" = "xno"; then
      tryudev=no
    fi,
)

HAVE_UDEV=no
if test "x$tryudev" != "xno"; then
   found_udev=no
   AC_CHECK_HEADER(libudev.h, found_udev=yes; )
   if test "x$found_udev" = "xyes"; then
      AC_CHECK_LIB(udev, udev_new, HAVE_UDEV=yes)
   fi
fi

if test "x$HAVE_UDEV" != "xno"; then
   HAVE_UDEV=1
else
   HAVE_UDEV=0
fi
AC_DEFINE_UNQUOTED([HAVE_UDEV], [$HAVE_UDEV],
	[Set to 1 to enable udev, 0 to disable])
AC_SUBST(HAVE_UDEV)

if test "$HAVE_UDEV" = "1" -o "$version_type" = "windows"; then
   cm108gpio=$default_all
else
   cm108gpio=no
fi
AC_ARG_WITH(cm108gpio,
 [AS_HELP_STRING([--with-cm108gpio=yes|dynamic|no],[Enable cm108 GPIO gensio])],
    if test "x$withval" = "xyes"; then
      cm108gpio=yes
    elif test "x$withval" = "xdynamic"; then
      cm108gpio=dynamic
    elif test "x$withval" = "xno"; then
      cm108gpio=no
    fi,
)
BUILTIN_CM108GPIO=0
DYNAMIC_CM108GPIO=
if test "x$HAVE_UDEV" != "0"; then
   CM108GPIO_LIBS="-ludev"
fi
if test "$version_type" = "windows"; then
   CM108GPIO_LIBS="-lhid -lsetupapi"
fi

case $cm108gpio in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS cm108gpio"
      BUILTIN_CM108GPIO=1
      BASE_LIBS="$BASE_LIBS $CM108GPIO_LIBS"
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS cm108gpio"
      DYNAMIC_CM108GPIO=libgensio_cm108gpio.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_CM108GPIO], [test ${BUILTIN_CM108GPIO} = 1])
AC_SUBST(CM108GPIO_LIBS)
AC_SUBST(DYNAMIC_CM108GPIO)

HAVE_OPENSSL=0
AX_CHECK_OPENSSL([HAVE_OPENSSL=1])

HAVE_RAND_SET_DRBG_TYPE=0
if test "$HAVE_OPENSSL" = "1"; then
   ssl=$default_all
   certauth=$default_all
   AC_CHECK_LIB(crypto, RAND_set_DRBG_type, HAVE_RAND_SET_DRBG_TYPE=1)
else
   ssl=no
   certauth=no
fi
AC_DEFINE_UNQUOTED([HAVE_OPENSSL], [$HAVE_OPENSSL],
	[Set to 1 to enable SSL support through OpenSSL, 0 to disable])
AC_SUBST(HAVE_OPENSSL)
AC_DEFINE_UNQUOTED([HAVE_RAND_SET_DRBG_TYPE], [$HAVE_RAND_SET_DRBG_TYPE],
	[Set to 1 to new random support in SSL, 0 to disable])

AC_ARG_WITH(ssl,
 [AS_HELP_STRING([--with-ssl=yes|dynamic|no], [Enable ssl gensio])],
    if test "x$withval" = "xyes"; then
      ssl=yes
    elif test "x$withval" = "xdynamic"; then
      ssl=dynamic
    elif test "x$withval" = "xno"; then
      ssl=no
    fi,
)
BUILTIN_SSL=0
DYNAMIC_SSL=
case $ssl in
   yes)
      if test $HAVE_OPENSSL = 0; then
         AC_MSG_ERROR("ssl enabled but openssl not found")
      fi
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS ssl"
      BUILTIN_SSL=1
      ;;
   dynamic)
      if test $HAVE_OPENSSL = 0; then
         AC_MSG_ERROR("ssl enabled but openssl not found")
      fi
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS ssl"
      DYNAMIC_SSL=libgensio_ssl.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_SSL], [test ${BUILTIN_SSL} = 1])
AC_SUBST(DYNAMIC_SSL)

AC_ARG_WITH(certauth,
 [AS_HELP_STRING([--with-certauth=yes|dynamic|no], [Enable certauth gensio])],
    if test "x$withval" = "xyes"; then
      certauth=yes
    elif test "x$withval" = "xdynamic"; then
      certauth=dynamic
    elif test "x$withval" = "xno"; then
      certauth=no
    fi,
)
BUILTIN_CERTAUTH=0
DYNAMIC_CERTAUTH=
case $certauth in
   yes)
      if test $HAVE_OPENCERTAUTH = 0; then
         AC_MSG_ERROR("certauth enabled but openssl not found")
      fi
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS certauth"
      BUILTIN_CERTAUTH=1
      ;;
   dynamic)
      if test $HAVE_OPENSSL = 0; then
         AC_MSG_ERROR("certauth enabled but openssl not found")
      fi
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS certauth"
      DYNAMIC_CERTAUTH=libgensio_certauth.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_CERTAUTH], [test ${BUILTIN_CERTAUTH} = 1])
AC_SUBST(DYNAMIC_CERTAUTH)

if test $ssl = yes -o $certauth = yes -o $link_ssl_with_main = yes; then
   BASE_LIBS="$BASE_LIBS $OPENSSL_LIBS"
   LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
fi

mux=$default_all
AC_ARG_WITH(mux,
 [AS_HELP_STRING([--with-mux=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      mux=yes
    elif test "x$withval" = "xdynamic"; then
      mux=dynamic
    elif test "x$withval" = "xno"; then
      mux=no
    fi,
)
BUILTIN_MUX=0
DYNAMIC_MUX=
case $mux in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS mux"
      BUILTIN_MUX=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS mux"
      DYNAMIC_MUX=libgensio_mux.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_MUX], [test ${BUILTIN_MUX} = 1])
AC_SUBST(DYNAMIC_MUX)

telnet=$default_all
AC_ARG_WITH(telnet,
 [AS_HELP_STRING([--with-telnet=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      telnet=yes
    elif test "x$withval" = "xdynamic"; then
      telnet=dynamic
    elif test "x$withval" = "xno"; then
      telnet=no
    fi,
)
BUILTIN_TELNET=0
DYNAMIC_TELNET=
case $telnet in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS telnet"
      BUILTIN_TELNET=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS telnet"
      DYNAMIC_TELNET=libgensio_telnet.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_TELNET], [test ${BUILTIN_TELNET} = 1])
AC_SUBST(DYNAMIC_TELNET)

msgdelim=$default_all
AC_ARG_WITH(msgdelim,
 [AS_HELP_STRING([--with-msgdelim=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      msgdelim=yes
    elif test "x$withval" = "xdynamic"; then
      msgdelim=dynamic
    elif test "x$withval" = "xno"; then
      msgdelim=no
    fi,
)
BUILTIN_MSGDELIM=0
DYNAMIC_MSGDELIM=
case $msgdelim in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS msgdelim"
      BUILTIN_MSGDELIM=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS msgdelim"
      DYNAMIC_MSGDELIM=libgensio_msgdelim.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_MSGDELIM], [test ${BUILTIN_MSGDELIM} = 1])
AC_SUBST(DYNAMIC_MSGDELIM)

relpkt=$default_all
AC_ARG_WITH(relpkt,
 [AS_HELP_STRING([--with-relpkt=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      relpkt=yes
    elif test "x$withval" = "xdynamic"; then
      relpkt=dynamic
    elif test "x$withval" = "xno"; then
      relpkt=no
    fi,
)
BUILTIN_RELPKT=0
DYNAMIC_RELPKT=
case $relpkt in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS relpkt"
      BUILTIN_RELPKT=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS relpkt"
      DYNAMIC_RELPKT=libgensio_relpkt.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_RELPKT], [test ${BUILTIN_RELPKT} = 1])
AC_SUBST(DYNAMIC_RELPKT)

trace=$default_all
AC_ARG_WITH(trace,
 [AS_HELP_STRING([--with-trace=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      trace=yes
    elif test "x$withval" = "xdynamic"; then
      trace=dynamic
    elif test "x$withval" = "xno"; then
      trace=no
    fi,
)
BUILTIN_TRACE=0
DYNAMIC_TRACE=
case $trace in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS trace"
      BUILTIN_TRACE=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS trace"
      DYNAMIC_TRACE=libgensio_trace.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_TRACE], [test ${BUILTIN_TRACE} = 1])
AC_SUBST(DYNAMIC_TRACE)

perf=$default_all
AC_ARG_WITH(perf,
 [AS_HELP_STRING([--with-perf=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      perf=yes
    elif test "x$withval" = "xdynamic"; then
      perf=dynamic
    elif test "x$withval" = "xno"; then
      perf=no
    fi,
)
BUILTIN_PERF=0
DYNAMIC_PERF=
case $perf in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS perf"
      BUILTIN_PERF=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS perf"
      DYNAMIC_PERF=libgensio_perf.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_PERF], [test ${BUILTIN_PERF} = 1])
AC_SUBST(DYNAMIC_PERF)

kiss=$default_all
AC_ARG_WITH(kiss,
 [AS_HELP_STRING([--with-kiss=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      kiss=yes
    elif test "x$withval" = "xdynamic"; then
      kiss=dynamic
    elif test "x$withval" = "xno"; then
      kiss=no
    fi,
)
BUILTIN_KISS=0
DYNAMIC_KISS=
case $kiss in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS kiss"
      BUILTIN_KISS=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS kiss"
      DYNAMIC_KISS=libgensio_kiss.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_KISS], [test ${BUILTIN_KISS} = 1])
AC_SUBST(DYNAMIC_KISS)

ax25=$default_all
AC_ARG_WITH(ax25,
 [AS_HELP_STRING([--with-ax25=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      ax25=yes
    elif test "x$withval" = "xdynamic"; then
      ax25=dynamic
    elif test "x$withval" = "xno"; then
      ax25=no
    fi,
)
BUILTIN_AX25=0
DYNAMIC_AX25=
case $ax25 in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS ax25"
      BUILTIN_AX25=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS ax25"
      DYNAMIC_AX25=libgensio_ax25.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_AX25], [test ${BUILTIN_AX25} = 1])
AC_SUBST(DYNAMIC_AX25)

xlt=$default_all
AC_ARG_WITH(xlt,
 [AS_HELP_STRING([--with-xlt=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      xlt=yes
    elif test "x$withval" = "xdynamic"; then
      xlt=dynamic
    elif test "x$withval" = "xno"; then
      xlt=no
    fi,
)
BUILTIN_XLT=0
DYNAMIC_XLT=
case $xlt in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS xlt"
      BUILTIN_XLT=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS xlt"
      DYNAMIC_XLT=libgensio_xlt.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_XLT], [test ${BUILTIN_XLT} = 1])
AC_SUBST(DYNAMIC_XLT)

keepopen=$default_all
AC_ARG_WITH(keepopen,
 [AS_HELP_STRING([--with-keepopen=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      keepopen=yes
    elif test "x$withval" = "xdynamic"; then
      keepopen=dynamic
    elif test "x$withval" = "xno"; then
      keepopen=no
    fi,
)
BUILTIN_KEEPOPEN=0
DYNAMIC_KEEPOPEN=
case $keepopen in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS keepopen"
      BUILTIN_KEEPOPEN=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS keepopen"
      DYNAMIC_KEEPOPEN=libgensio_keepopen.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_KEEPOPEN], [test ${BUILTIN_KEEPOPEN} = 1])
AC_SUBST(DYNAMIC_KEEPOPEN)

script=$default_all
AC_ARG_WITH(script,
 [AS_HELP_STRING([--with-script=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      script=yes
    elif test "x$withval" = "xdynamic"; then
      script=dynamic
    elif test "x$withval" = "xno"; then
      script=no
    fi,
)
BUILTIN_SCRIPT=0
DYNAMIC_SCRIPT=
case $script in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS script"
      BUILTIN_SCRIPT=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS script"
      DYNAMIC_SCRIPT=libgensio_script.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_SCRIPT], [test ${BUILTIN_SCRIPT} = 1])
AC_SUBST(DYNAMIC_SCRIPT)

ratelimit=$default_all
AC_ARG_WITH(ratelimit,
 [AS_HELP_STRING([--with-ratelimit=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      ratelimit=yes
    elif test "x$withval" = "xdynamic"; then
      ratelimit=dynamic
    elif test "x$withval" = "xno"; then
      ratelimit=no
    fi,
)
BUILTIN_RATELIMIT=0
DYNAMIC_RATELIMIT=
case $ratelimit in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS ratelimit"
      BUILTIN_RATELIMIT=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS ratelimit"
      DYNAMIC_RATELIMIT=libgensio_ratelimit.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_RATELIMIT], [test ${BUILTIN_RATELIMIT} = 1])
AC_SUBST(DYNAMIC_RATELIMIT)

chardelay=$default_all
AC_ARG_WITH(chardelay,
 [AS_HELP_STRING([--with-chardelay=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      chardelay=yes
    elif test "x$withval" = "xdynamic"; then
      chardelay=dynamic
    elif test "x$withval" = "xno"; then
      chardelay=no
    fi,
)
BUILTIN_CHARDELAY=0
DYNAMIC_CHARDELAY=
case $chardelay in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS chardelay"
      BUILTIN_CHARDELAY=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS chardelay"
      DYNAMIC_CHARDELAY=libgensio_chardelay.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_CHARDELAY], [test ${BUILTIN_CHARDELAY} = 1])
AC_SUBST(DYNAMIC_CHARDELAY)

afskmdm=$default_all
AC_ARG_WITH(afskmdm,
 [AS_HELP_STRING([--with-afskmdm=yes|dynamic|no], [Enable tcp/unix gensio])],
    if test "x$withval" = "xyes"; then
      afskmdm=yes
    elif test "x$withval" = "xdynamic"; then
      afskmdm=dynamic
    elif test "x$withval" = "xno"; then
      afskmdm=no
    fi,
)
BUILTIN_AFSKMDM=0
DYNAMIC_AFSKMDM=
case $afskmdm in
   yes)
      BUILTIN_GENSIOS="$BUILTIN_GENSIOS afskmdm"
      BUILTIN_AFSKMDM=1
      ;;
   dynamic)
      DYNAMIC_GENSIOS="$DYNAMIC_GENSIOS afskmdm"
      DYNAMIC_AFSKMDM=libgensio_afskmdm.la
      ;;
   no)
      ;;
esac
AM_CONDITIONAL([BUILTIN_AFSKMDM], [test ${BUILTIN_AFSKMDM} = 1])
AC_SUBST(DYNAMIC_AFSKMDM)

echo "creating builtin_gensios.h"
rm -f "$ac_pwd/lib/builtin_gensios.h"
if ! test -e "$ac_pwd/lib"; then
    mkdir "$ac_pwd/lib"
fi
echo "/* Do not edit, created by configure.h */" >"$ac_pwd/lib/builtin_gensios.h"
for i in $BUILTIN_GENSIOS; do
    echo "INIT_GENSIO($i);" >>"$ac_pwd/lib/builtin_gensios.h"
done

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

AC_CHECK_LIB(nsl, main, [HAVE_LIBNSL=1; OSH_LIBS="-lnsl $OSH_LIBS"])

# Now check for swig
SWIG_DIR=
SWIG_CPP_DIR=
SWIG=
available_swig_vernum=0
if test "x$tryswig" = "xyes"; then
   if test "x$swigprog" != "x"; then
      SWIG="$swigprog"
   fi
   AX_PKG_SWIG(4.1.0,
        [
            AC_DEFINE([HAVE_SWIG], [], [Have swig installed])
            SWIG_DIR=swig
            SWIG_CPP_DIR=swig
        ], [
            AC_MSG_WARN([SWIG version >= 4.1.0 is required for C++ swig.])
            AX_PKG_SWIG(4.0.0,
              [
                AC_DEFINE([HAVE_SWIG], [], [Have swig installed])
                SWIG_DIR=swig
              ], [
                AC_MSG_WARN([SWIG version >= 4.0.0 is required for C swig.])
              ])
        ])
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
   else
      if test -z "$PYTHON_VERSION"; then
         AC_PATH_PROG([PYTHON],[python3])
         if test ! -z "$PYTHON"; then
            PYTHON_VERSION="3"
         fi
      fi
   fi
   if test "x$pythoncflags" != "x"; then
      PYTHON_CPPFLAGS="$pythoncflags"
   fi
   AX_PYTHON_DEVEL([], [true])
else
   ax_python_devel_found=no
fi
if test $ax_python_devel_found = yes; then
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

PYTHON_UNDEF_LIBS=
if test $PYTHON_UNDEF_FLAG = "-no-undefined"; then
   PYTHON_UNDEF_LIBS="$PYTHON_LIBS"
fi
AC_SUBST(PYTHON_DIR)
AC_SUBST(PYGENSIO_DIR)
AC_SUBST(PYTHON_INSTALL_DIR)
AC_SUBST(PYTHON_INSTALL_LIB_DIR)
AC_SUBST(PYTHON_HAS_THREADS)
AC_SUBST(PYTHON_SWIG_FLAGS)
AC_SUBST(PYTHON_UNDEF_FLAG)
AC_SUBST(PYTHON_UNDEF_LIBS)

PYTHON_EXECUTABLE="${PYTHON}"
AC_SUBST(PYTHON_EXECUTABLE)

if test $available_swig_vernum -ge 40100 -a "${enable_shared}" = yes -a $DISABLE_GO != yes; then
   trygo=yes
else
   trygo=no
fi
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

if test $trygo = yes -a $available_swig_vernum -lt 40100; then
   AC_MSG_ERROR([Go enabled, but swig version must be >= 4.1.0 for that])
fi
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
if test $BUILD_OPENSSL -eq 1; then
   if test $DISABLE_GTLSSHD = yes; then
      echo "gltsshD disabled"
   elif test $HAVE_PAM -eq 1; then
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
AC_DEFINE_UNQUOTED([HAVE_UNIX], [$HAVE_UNIX], [Enable unix socket file handling])

GENSIO_PTY_HELPER=
if test "$version_type" = "windows" -a "$target_os" != "msys"; then
   # We have PTY support for windows.
   HAVE_PTY=1
   GENSIO_PTY_HELPER="gensio_pty_helper\$(EXEEXT)"
else
   HAVE_PTY=0
   AC_CHECK_FUNCS(posix_openpt, [HAVE_PTY=1])
fi
AC_SUBST(HAVE_PTY)
AC_DEFINE_UNQUOTED([HAVE_PTY], [$HAVE_PTY], [Enable PTY gensio])
AC_SUBST(GENSIO_PTY_HELPER)

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

AC_CHECK_FUNCS(sendmsg)
AC_CHECK_FUNCS(recvmsg)
AC_CHECK_FUNCS(isatty)
AC_CHECK_FUNCS(strcasecmp)
AC_CHECK_FUNCS(strncasecmp)
AC_CHECK_FUNCS(prctl)
AC_CHECK_FUNCS(setutxent)
AC_CHECK_FUNCS(sigtimedwait)
AC_CHECK_FUNCS(initgroups)

AC_CHECK_DECLS([SIGWINCH], [], [], [#include <signal.h>])

AM_CXXFLAGS="$AM_CXXFLAGS $EXTRA_CFLAGS -I\$(top_srcdir)/c++/include"
AM_CFLAGS="$AM_CFLAGS $EXTRA_CFLAGS"
AC_SUBST(AM_CXXFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(EXTRA_CFLAGS)

AC_SUBST(OSH_LIBS)
AC_SUBST(BASE_LIBS)

CPPFLAGS="$CPPFLAGS -I\$(top_srcdir)/include -I\$(top_builddir)/include"

AC_CONFIG_FILES([Makefile
	lib/libgensioosh.pc
	lib/libgensio.pc
	lib/libgensiomdns.pc
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
	c++/lib/libgensiooshcpp.pc
	c++/lib/libgensiocpp.pc
	c++/lib/libgensiomdnscpp.pc
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

pr_op() {
    #echo "A: '$1' $2"
    if test "x$2" = x1; then
	str='Yes'
    elif test "x$2" = "xyes"; then
	str='Yes'
    else
	str='no'
    fi
    echo "$1$str"
}

pr_vop() {
    #echo "A: '$1' $2"
    if test -n "$2"; then
	str=$2
    else
	str='no'
    fi
    echo "$1$str"
}

prrw() {
    echo "$1$2"
}

echo "**************************************************"
echo "Options:"
	
pr_op  "  UUCP Locking:		" $USE_UUCP_LOCKING
pr_op  "  flock Locking:	" $USE_FLOCK_LOCKING
pr_op  "  Broken pselect():	" $broken_pselect
pr_op  "  TCP Wrappers:		" $ac_cv_header_tcpd_h
prrw   "  Regular Expressions:	" $ac_cv_func_regexec
pr_op  "  Install Docs:		" $enable_doc
pr_op  "  epoll_pwait():	" $ax_config_feature_epoll_pwait
pr_op  "  kevent():		" $ac_cv_func_kevent
pr_op  "  pthreads:		" $use_pthreads
pr_op  "  c++11			" $HAVE_CXX11
pr_vop "  pkgconfig:		" $pkgprog
pr_op  "  glib:			" $haveglib
pr_op  "  tcl:			" $havetcl
pr_op  "  shared libraries:	" $enable_shared
pr_op  "  sctp sendv:		" $ac_cv_lib_sctp_sctp_sendv
pr_vop "  python:		" "$ax_python_version"
if test "$SWIG_CPP_DIR" = "swig"; then
  prrw "  swig:			" "$available_swig_vernum"
else
  prrw "  swig:			" "no"
fi
pr_vop "  go:			" $GOPROG
pr_op  "  pam:			" $HAVE_PAM
pr_op  "  internal trace:	" $ENABLE_INTERNAL_TRACE
pr_op  "  link ssl with main:	" $link_ssl_with_main
pr_op  "  alsa:			" $HAVE_ALSA
pr_op  "  win32 sound:		" $HAVE_WIN32SOUND
pr_op  "  portaudio:		" $HAVE_PORTAUDIO
echo
echo "**************************************************"
echo "Gensios:"
echo   "  net:		" $net
echo   "  dgram:	" $dgram
echo   "  sctp:		" $sctp
echo   "  stdio:	" $stdio
echo   "  pty:		" $pty
echo   "  dummy:	" $dummy
echo   "  conacc:	" $conacc
echo   "  serialdev:	" $serialdev
echo   "  echo:		" $echo
echo   "  file:		" $file
echo   "  ipmisol:	" $ipmisol
echo   "  mdns:		" $mdns
echo   "  sound:	" $sound
echo   "  cm108gpio:	" $cm108gpio
echo   "  ssl:		" $ssl
echo   "  certauth:	" $certauth
echo   "  mux:		" $mux
echo   "  telnet:	" $telnet
echo   "  msgdelim:	" $msgdelim
echo   "  relpkt:	" $relpkt
echo   "  trace:	" $trace
echo   "  perf:		" $perf
echo   "  kiss:		" $kiss
echo   "  ax25:		" $ax25
echo   "  xlt:		" $xlt
echo   "  keepopen:	" $keepopen
echo   "  script:	" $script
echo   "  ratelimit:	" $ratelimit
echo   "  chardelay:	" $chardelay
echo   "  afskmdm:	" $afskmdm
echo
echo "**************************************************"
echo
