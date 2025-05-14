
# libgensio.la can depend on iibgensiomdns if BUILTIN_MDNS is set.
# Therefore it must be built after libgensiomdns, so it has to be
# added after.
lib_LTLIBRARIES = libgensioosh.la libgensiomdns.la libgensio.la

noinst_HEADERS = telnet.h heap.h utils.h seriallock.h crc.h \
	errtrig.h avahi_watcher.h gensio_net.h \
	gensio_sound_alsa.h gensio_sound_win.h \
	gensio_sound_portaudio.h gensio_sound_file.h \
	gensio_base_parms.h

libgensioosh_la_SOURCES = \
	os_osops.c circbuf.c os_osops_env.c net_addrinfo.c \
	net_stdsock.c net_ax25_addr.c utils.c net_addr.c
if HAVE_UNIX_OS
libgensioosh_la_SOURCES += os_unix.c os_unix_selector.c
endif
if HAVE_WINDOWS_OS
libgensioosh_la_SOURCES += os_win.c
endif
libgensioosh_la_CPPFLAGS = -DBUILDING_GENSIOOSH_DLL \
	-DPKG_LIBEXEC="\"$(gensiolibexecdir)\""
libgensioosh_la_LDFLAGS = -no-undefined -version-info $(GENSIO_LIB_VERSION) \
	-fvisibility=hidden
libgensioosh_la_LIBADD = @OSH_LIBS@
if ENABLE_INTERNAL_TRACE
libgensioosh_la_SOURCES += errtrig.c
endif

libgensiomdns_la_SOURCES = mdns.c avahi_watcher.c
libgensiomdns_la_CPPFLAGS = -DBUILDING_GENSIOMDNS_DLL
libgensiomdns_la_LDFLAGS = -no-undefined -version-info $(GENSIO_LIB_VERSION) \
	-fvisibility=hidden
libgensiomdns_la_LIBADD = libgensioosh.la ${MDNS_LIBS} \
	${REGEX_LIB}

libgensio_la_SOURCES = \
	gensio.c gensio_base.c sergensio.c buffer.c \
	ll_fd.c ll_gensio.c acc.c acc_gensio.c
libgensio_la_CPPFLAGS = -DBUILDING_GENSIO_DLL
libgensio_la_LDFLAGS = -no-undefined -version-info $(GENSIO_LIB_VERSION) \
	-fvisibility=hidden
libgensio_la_LIBADD = libgensioosh.la @BASE_LIBS@

if HAVE_WINDOWS_OS
gensiolibexecdir = $(bindir)
else
gensiolibexecdir = $(moduleinstalldir)/$(PACKAGE_VERSION)
endif

if HAVE_OPENIPMI
lib_LTLIBRARIES += libgensio_openipmi_oshandler.la
libgensio_openipmi_oshandler_la_SOURCES = gensio_openipmi_oshandler.c
libgensio_openipmi_oshandler_la_CPPFLAGS = $(OPENIPMI_CPPFLAGS)
libgensio_openipmi_oshandler_la_LDFLAGS = -no-undefined -version-info \
	$(GENSIO_LIB_VERSION) -fvisibility=hidden
libgensio_openipmi_oshandler_la_LIBADD = $(OPENIPMI_LIBS)
endif

EXTRA_LTLIBRARIES =
gensiolibexec_LTLIBRARIES =
DYNAMIC_LDFLAGS = -no-undefined -module -rpath "$(gensiolibexecdir)" -avoid-version
DYNAMIC_LIBS = libgensio.la libgensioosh.la

if BUILTIN_NET
libgensio_la_SOURCES += gensio_net.c
else
EXTRA_LTLIBRARIES += libgensio_net.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_NET)
libgensio_net_la_SOURCES = gensio_net.c
libgensio_net_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_net_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_DGRAM
libgensio_la_SOURCES += gensio_dgram.c
else
EXTRA_LTLIBRARIES += libgensio_dgram.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_DGRAM)
libgensio_dgram_la_SOURCES = gensio_dgram.c
libgensio_dgram_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_dgram_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_SCTP
libgensio_la_SOURCES += gensio_sctp.c
else
EXTRA_LTLIBRARIES += libgensio_sctp.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_SCTP)
libgensio_sctp_la_SOURCES = gensio_sctp.c
libgensio_sctp_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_sctp_la_LIBADD = $(DYNAMIC_LIBS) $(SCTP_LIBS)

if BUILTIN_STDIO
libgensio_la_SOURCES += gensio_stdio.c
else
EXTRA_LTLIBRARIES += libgensio_stdio.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_STDIO)
libgensio_stdio_la_SOURCES = gensio_stdio.c
libgensio_stdio_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_stdio_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_PTY
libgensio_la_SOURCES += gensio_pty.c
else
EXTRA_LTLIBRARIES += libgensio_pty.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_PTY)
libgensio_pty_la_SOURCES = gensio_pty.c
libgensio_pty_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_pty_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_DUMMY
libgensio_la_SOURCES += gensio_dummy.c
else
EXTRA_LTLIBRARIES += libgensio_dummy.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_DUMMY)
libgensio_dummy_la_SOURCES = gensio_dummy.c
libgensio_dummy_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_dummy_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_CONACC
libgensio_la_SOURCES += gensio_conacc.c
else
EXTRA_LTLIBRARIES += libgensio_conacc.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_CONACC)
libgensio_conacc_la_SOURCES = gensio_conacc.c
libgensio_conacc_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_conacc_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_SERIALDEV
libgensio_la_SOURCES += sergensio_serialdev.c seriallock.c
else
EXTRA_LTLIBRARIES += libgensio_serialdev.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_SERIALDEV)
libgensio_serialdev_la_SOURCES = sergensio_serialdev.c seriallock.c
libgensio_serialdev_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_serialdev_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_ECHO
libgensio_la_SOURCES += gensio_echo.c
else
EXTRA_LTLIBRARIES += libgensio_echo.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_ECHO)
libgensio_echo_la_SOURCES = gensio_echo.c
libgensio_echo_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_echo_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_FILE
libgensio_la_SOURCES += gensio_file.c
else
EXTRA_LTLIBRARIES += libgensio_file.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_FILE)
libgensio_file_la_SOURCES = gensio_file.c
libgensio_file_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_file_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_IPMISOL
libgensio_la_SOURCES += sergensio_ipmisol.c
else
EXTRA_LTLIBRARIES += libgensio_ipmisol.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_IPMISOL)
libgensio_ipmisol_la_SOURCES = sergensio_ipmisol.c 
libgensio_ipmisol_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_ipmisol_la_CFLAGS = $(OPENIPMI_CPPFLAGS)
libgensio_ipmisol_la_LIBADD = $(DYNAMIC_LIBS) $(OPENIPMI_LIBS) \
				libgensio_openipmi_oshandler.la

if HAVE_MDNS
if BUILTIN_MDNS
libgensio_la_SOURCES += gensio_mdns.c
libgensio_la_LIBADD += libgensiomdns.la
else
EXTRA_LTLIBRARIES += libgensio_mdns.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_MDNS)
libgensio_mdns_la_SOURCES = gensio_mdns.c
libgensio_mdns_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_mdns_la_LIBADD = $(DYNAMIC_LIBS) libgensiomdns.la
endif

if BUILTIN_SOUND
libgensio_la_SOURCES += gensio_sound.c
else
EXTRA_LTLIBRARIES += libgensio_sound.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_SOUND)
libgensio_sound_la_SOURCES = gensio_sound.c
libgensio_sound_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_sound_la_LIBADD = $(DYNAMIC_LIBS) $(SOUND_LIBS)

if BUILTIN_CM108GPIO
libgensio_la_SOURCES += gensio_cm108gpio.c
else
EXTRA_LTLIBRARIES += libgensio_cm108gpio.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_CM108GPIO)
libgensio_cm108gpio_la_SOURCES = gensio_cm108gpio.c
libgensio_cm108gpio_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_cm108gpio_la_LIBADD = $(DYNAMIC_LIBS) $(CM108GPIO_LIBS)

if BUILTIN_SSL
libgensio_la_SOURCES += gensio_ssl.c
else
EXTRA_LTLIBRARIES += libgensio_ssl.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_SSL)
libgensio_ssl_la_SOURCES = gensio_ssl.c
libgensio_ssl_la_CPPFLAGS = $(OPENSSL_INCLUDES)
libgensio_ssl_la_LDFLAGS = $(DYNAMIC_LDFLAGS) $(OPENSSL_LDFLAGS)
libgensio_ssl_la_LIBADD = $(DYNAMIC_LIBS) $(OPENSSL_LIBS)

if BUILTIN_CERTAUTH
libgensio_la_SOURCES += gensio_certauth.c
else
EXTRA_LTLIBRARIES += libgensio_certauth.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_CERTAUTH)
libgensio_certauth_la_SOURCES = gensio_certauth.c
libgensio_certauth_la_CPPFLAGS = $(OPENSSL_INCLUDES)
libgensio_certauth_la_LDFLAGS = $(DYNAMIC_LDFLAGS) $(OPENSSL_LDFLAGS)
libgensio_certauth_la_LIBADD = $(DYNAMIC_LIBS) $(OPENSSL_LIBS)

if BUILTIN_MUX
libgensio_la_SOURCES += gensio_mux.c
else
EXTRA_LTLIBRARIES += libgensio_mux.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_MUX)
libgensio_mux_la_SOURCES = gensio_mux.c
libgensio_mux_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_mux_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_TELNET
libgensio_la_SOURCES += sergensio_telnet.c telnet.c
else
EXTRA_LTLIBRARIES += libgensio_telnet.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_TELNET)
libgensio_telnet_la_SOURCES = sergensio_telnet.c telnet.c
libgensio_telnet_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_telnet_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_MSGDELIM
libgensio_la_SOURCES += gensio_msgdelim.c
else
EXTRA_LTLIBRARIES += libgensio_msgdelim.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_MSGDELIM)
libgensio_msgdelim_la_SOURCES = gensio_msgdelim.c
libgensio_msgdelim_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_msgdelim_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_RELPKT
libgensio_la_SOURCES += gensio_relpkt.c
else
EXTRA_LTLIBRARIES += libgensio_relpkt.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_RELPKT)
libgensio_relpkt_la_SOURCES = gensio_relpkt.c
libgensio_relpkt_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_relpkt_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_TRACE
libgensio_la_SOURCES += gensio_trace.c
else
EXTRA_LTLIBRARIES += libgensio_trace.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_TRACE)
libgensio_trace_la_SOURCES = gensio_trace.c
libgensio_trace_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_trace_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_PERF
libgensio_la_SOURCES += gensio_perf.c
else
EXTRA_LTLIBRARIES += libgensio_perf.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_PERF)
libgensio_perf_la_SOURCES = gensio_perf.c
libgensio_perf_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_perf_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_KISS
libgensio_la_SOURCES += gensio_kiss.c
else
EXTRA_LTLIBRARIES += libgensio_kiss.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_KISS)
libgensio_kiss_la_SOURCES = gensio_kiss.c
libgensio_kiss_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_kiss_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_AX25
libgensio_la_SOURCES += gensio_ax25.c
else
EXTRA_LTLIBRARIES += libgensio_ax25.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_AX25)
libgensio_ax25_la_SOURCES = gensio_ax25.c
libgensio_ax25_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_ax25_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_XLT
libgensio_la_SOURCES += gensio_xlt.c
else
EXTRA_LTLIBRARIES += libgensio_xlt.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_XLT)
libgensio_xlt_la_SOURCES = gensio_xlt.c
libgensio_xlt_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_xlt_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_KEEPOPEN
libgensio_la_SOURCES += gensio_keepopen.c
else
EXTRA_LTLIBRARIES += libgensio_keepopen.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_KEEPOPEN)
libgensio_keepopen_la_SOURCES = gensio_keepopen.c
libgensio_keepopen_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_keepopen_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_SCRIPT
libgensio_la_SOURCES += gensio_script.c
else
EXTRA_LTLIBRARIES += libgensio_script.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_SCRIPT)
libgensio_script_la_SOURCES = gensio_script.c
libgensio_script_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_script_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_RATELIMIT
libgensio_la_SOURCES += gensio_ratelimit.c
else
EXTRA_LTLIBRARIES += libgensio_ratelimit.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_RATELIMIT)
libgensio_ratelimit_la_SOURCES = gensio_ratelimit.c
libgensio_ratelimit_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_ratelimit_la_LIBADD = $(DYNAMIC_LIBS)

if BUILTIN_AFSKMDM
libgensio_la_SOURCES += gensio_afskmdm.c
libgensio_la_LIBADD += -lm
else
EXTRA_LTLIBRARIES += libgensio_afskmdm.la
endif
gensiolibexec_LTLIBRARIES += $(DYNAMIC_AFSKMDM)
libgensio_afskmdm_la_SOURCES = gensio_afskmdm.c
libgensio_afskmdm_la_LDFLAGS = $(DYNAMIC_LDFLAGS)
libgensio_afskmdm_la_LIBADD = $(DYNAMIC_LIBS) -lm

# We need to make sure the main libraries are compiled and ready before
# doing the plugins, since the plugins link against them.
$(gensiolibexec_LTLIBRARIES): $(lib_LTLIBRARIES)

# Same thing as above, but for relinking on installation.  We have to
# have the main libraries installed before relinking.  The rule as
# specified below add prerequisites to the targets instead of creating
# a rule.
install-gensiolibexecLTLIBRARIES gensiolibexec-dummyprereq: install-libLTLIBRARIES

.PHONY gensiolibexec-dummyprereq:

EXTRA_DIST = README.rst libgensioosh.pc.in libgensio.pc.in libgensiomdns.pc.in

DISTCLEANFILES = builtin_gensios.h

# This variable must have 'exec' in its name, in order to be installed
# by 'install-exec' target (instead of default 'install-data')
pkgconfigexecdir = $(libdir)/pkgconfig
pkgconfigexec_DATA = libgensioosh.pc libgensio.pc libgensiomdns.pc

if HAVE_WINDOWS_OS
xgensio_libs = $(gensiolibexec_LTLIBRARIES:.la=.dll.a)
xgensio_solibs = $(gensiolibexec_LTLIBRARIES:.la=.dll)
else
xgensio_libs = $(gensiolibexec_LTLIBRARIES:.la=.a)
xgensio_solibs = $(gensiolibexec_LTLIBRARIES:.la=.so)
endif

install-exec-hook:
	@(cd $(DESTDIR)$(gensiolibexecdir) && $(RM) -f $(gensiolibexec_LTLIBRARIES))
	@(cd $(DESTDIR)$(gensiolibexecdir) && $(RM) -f $(xgensio_libs))

# Since we remove the bogus .la and .a files above at install time,
# libtool will not remove the .so or .dll files since the .la file is
# no longer there.  We have to do that by hand.
uninstall-hook:
	@(cd $(DESTDIR)$(gensiolibexecdir) && $(RM) -f $(xgensio_solibs))
