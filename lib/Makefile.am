
# libgensio.la can depend on iibgensiomdns if BUILTIN_MDNS is set.
# Therefore it must be built after libgensiomdns, so it has to be
# added after.
lib_LTLIBRARIES = libgensioosh.la libgensiomdns.la libgensio.la

noinst_HEADERS = telnet.h heap.h utils.h uucplock.h \
	gensio_filter_ssl.h gensio_filter_telnet.h gensio_ll_ipmisol.h \
	gensio_filter_certauth.h gensio_filter_msgdelim.h \
	gensio_filter_relpkt.h gensio_filter_trace.h gensio_filter_perf.h \
	errtrig.h avahi_watcher.h gensio_net.h gensio_filter_kiss.h \
	gensio_filter_xlt.h gensio_filter_script.h \
	gensio_ll_sound.h alsa_sound.h win_sound.h file_sound.h \
	gensio_filter_ratelimit.h gensio_filter_afskmdm.h

libgensioosh_la_SOURCES = \
	gensio_osops.c gensio_circbuf.c gensio_osops_env.c gensio_addrinfo.c \
	gensio_stdsock.c gensio_ax25_addr.c utils.c gensio_addr.c
if HAVE_UNIX_OS
libgensioosh_la_SOURCES += gensio_unix.c selector.c
endif
if HAVE_WINDOWS_OS
libgensioosh_la_SOURCES += gensio_win.c
endif
libgensioosh_la_CPPFLAGS = -DBUILDING_GENSIOOSH_DLL \
	-DPKG_LIBEXEC="\"$(gensiolibexec)\""
libgensioosh_la_LDFLAGS = -no-undefined -version-info $(GENSIO_LIB_VERSION) \
	-fvisibility=hidden
libgensioosh_la_LIBADD = @LIBSCTP_LIBS@
if ENABLE_INTERNAL_TRACE
libgensioosh_la_SOURCES += errtrig.c
endif

libgensiomdns_la_SOURCES = mdns.c avahi_watcher.c
libgensiomdns_la_CPPFLAGS = -DBUILDING_GENSIOMDNS_DLL
libgensiomdns_la_LDFLAGS = -no-undefined -version-info $(GENSIO_LIB_VERSION) \
	-fvisibility=hidden
libgensiomdns_la_LIBADD = libgensioosh.la ${MDNS_LIBS}

libgensio_la_SOURCES = \
	gensio.c gensio_base.c sergensio.c buffer.c \
	gensio_ll_fd.c gensio_ll_gensio.c gensio_acc.c gensio_acc_gensio.c
libgensio_la_CPPFLAGS = -DBUILDING_GENSIO_DLL
libgensio_la_LDFLAGS = -no-undefined -version-info $(GENSIO_LIB_VERSION) \
	-fvisibility=hidden
libgensio_la_LIBADD = libgensioosh.la

if HAVE_WINDOWS_OS
gensiolibexec = $(bindir)
else
gensiolibexec = $(moduleinstalldir)/$(PACKAGE_VERSION)
endif
# Note that xgensio_libexecdir starts with "x" because it has to
# install after libgensio and libgensiomdns for proper relinking, and
# automake organizes the installs alphabetically
xgensio_libexecdir = $(gensiolibexec)

EXTRA_LTLIBRARIES =
xgensio_libexec_LTLIBRARIES =
DYNAMIC_LDFLAGS = -no-undefined -module -rpath "$(gensiolibexec)" -avoid-version
DYNAMIC_LIBS = libgensio.la

if BUILTIN_NET
libgensio_la_SOURCES += gensio_net.c
else
EXTRA_LTLIBRARIES += libgensio_net.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_NET)
libgensio_net_la_SOURCES = gensio_net.c
libgensio_net_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_net_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_UDP
libgensio_la_SOURCES += gensio_udp.c
else
EXTRA_LTLIBRARIES += libgensio_udp.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_UDP)
libgensio_udp_la_SOURCES = gensio_udp.c
libgensio_udp_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_udp_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_SCTP
libgensio_la_SOURCES += gensio_sctp.c
else
EXTRA_LTLIBRARIES += libgensio_sctp.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_SCTP)
libgensio_sctp_la_SOURCES = gensio_sctp.c
libgensio_sctp_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_sctp_la_LIBADD = $(DYNAMIC_LIBS) $(SCTP_LIBS)

if BUILTIN_STDIO
libgensio_la_SOURCES += gensio_stdio.c
else
EXTRA_LTLIBRARIES += libgensio_stdio.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_STDIO)
libgensio_stdio_la_SOURCES = gensio_stdio.c
libgensio_stdio_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_stdio_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_PTY
libgensio_la_SOURCES += gensio_pty.c
else
EXTRA_LTLIBRARIES += libgensio_pty.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_PTY)
libgensio_pty_la_SOURCES = gensio_pty.c
libgensio_pty_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_pty_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_DUMMY
libgensio_la_SOURCES += gensio_dummy.c
else
EXTRA_LTLIBRARIES += libgensio_dummy.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_DUMMY)
libgensio_dummy_la_SOURCES = gensio_dummy.c
libgensio_dummy_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_dummy_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_CONACC
libgensio_la_SOURCES += gensio_conacc.c
else
EXTRA_LTLIBRARIES += libgensio_conacc.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_CONACC)
libgensio_conacc_la_SOURCES = gensio_conacc.c
libgensio_conacc_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_conacc_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_SERIALDEV
libgensio_la_SOURCES += sergensio_serialdev.c uucplock.c
else
EXTRA_LTLIBRARIES += libgensio_serialdev.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_SERIALDEV)
libgensio_serialdev_la_SOURCES = sergensio_serialdev.c uucplock.c
libgensio_serialdev_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_serialdev_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_ECHO
libgensio_la_SOURCES += gensio_echo.c
else
EXTRA_LTLIBRARIES += libgensio_echo.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_ECHO)
libgensio_echo_la_SOURCES = gensio_echo.c
libgensio_echo_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_echo_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_FILE
libgensio_la_SOURCES += gensio_file.c
else
EXTRA_LTLIBRARIES += libgensio_file.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_FILE)
libgensio_file_la_SOURCES = gensio_file.c
libgensio_file_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_file_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_IPMISOL
libgensio_la_SOURCES += gensio_ll_ipmisol.c sergensio_ipmisol.c
else
EXTRA_LTLIBRARIES += libgensio_ipmisol.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_IPMISOL)
libgensio_ipmisol_la_SOURCES = gensio_ll_ipmisol.c sergensio_ipmisol.c 
libgensio_ipmisol_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_ipmisol_la_CFLAGS = $(OPENIPMI_CPPFLAGS)
libgensio_ipmisol_la_LIBADD = $(DYNAMIC_LIBS) $(OPENIPMI_LIBS)

if HAVE_AVAHI
if BUILTIN_MDNS
libgensio_la_SOURCES += gensio_mdns.c
libgensio_la_LIBADD += libgensiomdns.la
else
EXTRA_LTLIBRARIES += libgensio_mdns.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_MDNS)
libgensio_mdns_la_SOURCES = gensio_mdns.c
libgensio_mdns_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_mdns_la_LIBADD = $(DYNAMIC_LIBS) libgensiomdns.la
endif

if BUILTIN_SOUND
libgensio_la_SOURCES += gensio_ll_sound.c gensio_sound.c
else
EXTRA_LTLIBRARIES += libgensio_sound.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_SOUND)
libgensio_sound_la_SOURCES = gensio_ll_sound.c gensio_sound.c
libgensio_sound_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_sound_la_LIBADD = $(DYNAMIC_LIBS) $(SOUND_LIBS)

if BUILTIN_SSL
libgensio_la_SOURCES += gensio_ssl.c gensio_filter_ssl.c
else
EXTRA_LTLIBRARIES += libgensio_ssl.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_SSL)
libgensio_ssl_la_SOURCES = gensio_ssl.c gensio_filter_ssl.c
libgensio_ssl_la_CPPFLAGS = $(OPENSSL_INCLUDES)
libgensio_ssl_la_LDFLAGS = $(DYNAMIC_LDFLAGS) $(OPENSSL_LDFLAGS)
libgensio_ssl_la_LIBADD = $(DYNAMIC_LIBS) $(OPENSSL_LIBS)

if BUILTIN_CERTAUTH
libgensio_la_SOURCES += gensio_certauth.c gensio_filter_certauth.c
else
EXTRA_LTLIBRARIES += libgensio_certauth.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_CERTAUTH)
libgensio_certauth_la_SOURCES = gensio_certauth.c gensio_filter_certauth.c
libgensio_certauth_la_CPPFLAGS = $(OPENSSL_INCLUDES)
libgensio_certauth_la_LDFLAGS = $(DYNAMIC_LDFLAGS) $(OPENSSL_LDFLAGS)
libgensio_certauth_la_LIBADD = $(DYNAMIC_LIBS) $(OPENSSL_LIBS)

if BUILTIN_MUX
libgensio_la_SOURCES += gensio_mux.c
else
EXTRA_LTLIBRARIES += libgensio_mux.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_MUX)
libgensio_mux_la_SOURCES = gensio_mux.c
libgensio_mux_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_mux_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_TELNET
libgensio_la_SOURCES += sergensio_telnet.c gensio_filter_telnet.c telnet.c
else
EXTRA_LTLIBRARIES += libgensio_telnet.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_TELNET)
libgensio_telnet_la_SOURCES = sergensio_telnet.c gensio_filter_telnet.c telnet.c
libgensio_telnet_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_telnet_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_MSGDELIM
libgensio_la_SOURCES += gensio_filter_msgdelim.c gensio_msgdelim.c
else
EXTRA_LTLIBRARIES += libgensio_msgdelim.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_MSGDELIM)
libgensio_msgdelim_la_SOURCES = gensio_filter_msgdelim.c gensio_msgdelim.c
libgensio_msgdelim_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_msgdelim_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_RELPKT
libgensio_la_SOURCES += gensio_filter_relpkt.c gensio_relpkt.c
else
EXTRA_LTLIBRARIES += libgensio_relpkt.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_RELPKT)
libgensio_relpkt_la_SOURCES = gensio_filter_relpkt.c gensio_relpkt.c
libgensio_relpkt_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_relpkt_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_TRACE
libgensio_la_SOURCES += gensio_filter_trace.c gensio_trace.c
else
EXTRA_LTLIBRARIES += libgensio_trace.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_TRACE)
libgensio_trace_la_SOURCES = gensio_filter_trace.c gensio_trace.c
libgensio_trace_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_trace_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_PERF
libgensio_la_SOURCES += gensio_filter_perf.c gensio_perf.c
else
EXTRA_LTLIBRARIES += libgensio_perf.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_PERF)
libgensio_perf_la_SOURCES = gensio_filter_perf.c gensio_perf.c
libgensio_perf_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_perf_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_KISS
libgensio_la_SOURCES += gensio_filter_kiss.c gensio_kiss.c
else
EXTRA_LTLIBRARIES += libgensio_kiss.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_KISS)
libgensio_kiss_la_SOURCES = gensio_filter_kiss.c gensio_kiss.c
libgensio_kiss_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_kiss_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_AX25
libgensio_la_SOURCES += gensio_ax25.c
else
EXTRA_LTLIBRARIES += libgensio_ax25.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_AX25)
libgensio_ax25_la_SOURCES = gensio_ax25.c
libgensio_ax25_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_ax25_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_XLT
libgensio_la_SOURCES += gensio_filter_xlt.c gensio_xlt.c
else
EXTRA_LTLIBRARIES += libgensio_xlt.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_XLT)
libgensio_xlt_la_SOURCES = gensio_filter_xlt.c gensio_xlt.c
libgensio_xlt_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_xlt_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_KEEPOPEN
libgensio_la_SOURCES += gensio_keepopen.c
else
EXTRA_LTLIBRARIES += libgensio_keepopen.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_KEEPOPEN)
libgensio_keepopen_la_SOURCES = gensio_keepopen.c
libgensio_keepopen_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_keepopen_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_SCRIPT
libgensio_la_SOURCES += gensio_filter_script.c gensio_script.c
else
EXTRA_LTLIBRARIES += libgensio_script.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_SCRIPT)
libgensio_script_la_SOURCES = gensio_filter_script.c gensio_script.c
libgensio_script_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_script_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_RATELIMIT
libgensio_la_SOURCES += gensio_filter_ratelimit.c gensio_ratelimit.c
else
EXTRA_LTLIBRARIES += libgensio_ratelimit.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_RATELIMIT)
libgensio_ratelimit_la_SOURCES = gensio_filter_ratelimit.c gensio_ratelimit.c
libgensio_ratelimit_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_ratelimit_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_AFSKMDM
libgensio_la_SOURCES += gensio_filter_afskmdm.c gensio_afskmdm.c
libgensio_la_LIBADD += -lm
else
EXTRA_LTLIBRARIES += libgensio_afskmdm.la
endif
xgensio_libexec_LTLIBRARIES += $(DYNAMIC_AFSKMDM)
libgensio_afskmdm_la_SOURCES = gensio_filter_afskmdm.c gensio_afskmdm.c
libgensio_afskmdm_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_afskmdm_la_LIBADD = $(DYNAMIC_LIBS) -lm

EXTRA_DIST = README.rst libgensioosh.pc.in libgensio.pc.in libgensiomdns.pc.in

DISTCLEANFILES = builtin_gensios.h

# This variable must have 'exec' in its name, in order to be installed
# by 'install-exec' target (instead of default 'install-data')
pkgconfigexecdir = $(libdir)/pkgconfig
pkgconfigexec_DATA = libgensioosh.pc libgensio.pc libgensiomdns.pc
