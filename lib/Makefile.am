
AM_CFLAGS = -DBUILDING_GENSIO_DLL

lib_LTLIBRARIES = libgensio.la

noinst_HEADERS = telnet.h heap.h utils.h uucplock.h buffer.h \
	gensio_filter_ssl.h gensio_filter_telnet.h gensio_ll_ipmisol.h \
	gensio_filter_certauth.h gensio_filter_msgdelim.h \
	gensio_filter_relpkt.h gensio_filter_trace.h gensio_filter_perf.h \
	errtrig.h avahi_watcher.h gensio_net.h gensio_filter_kiss.h crc16.h

libgensio_la_SOURCES = \
	gensio.c gensio_osops.c gensio_base.c sergensio.c utils.c buffer.c \
	gensio_ll_fd.c gensio_ll_gensio.c gensio_acc.c gensio_acc_gensio.c \
	gensio_circbuf.c gensio_osops_env.c \
	gensio_net.c gensio_udp.c gensio_sctp.c \
	sergensio_telnet.c gensio_filter_telnet.c telnet.c \
	gensio_ssl.c gensio_filter_ssl.c \
	gensio_ll_ipmisol.c sergensio_ipmisol.c \
	gensio_filter_certauth.c gensio_certauth.c \
	gensio_dummy.c gensio_echo.c gensio_mux.c gensio_file.c \
	gensio_filter_msgdelim.c gensio_msgdelim.c \
	gensio_filter_relpkt.c gensio_relpkt.c \
	gensio_filter_trace.c gensio_trace.c \
	gensio_filter_perf.c gensio_perf.c gensio_conacc.c \
	gensio_stdio.c \
	sergensio_serialdev.c uucplock.c \
	gensio_pty.c \
	mdns.c avahi_watcher.c gensio_mdns.c \
	gensio_addrinfo.c gensio_stdsock.c \
	gensio_filter_kiss.c gensio_kiss.c crc16.c

if HAVE_UNIX_OS
libgensio_la_SOURCES += gensio_unix.c selector.c
endif
if HAVE_WINDOWS_OS
libgensio_la_SOURCES += gensio_win.c
endif
if ENABLE_INTERNAL_TRACE
libgensio_la_SOURCES += errtrig.c
endif

libgensio_la_LDFLAGS = $(OPENSSL_LIBS) -no-undefined

EXTRA_DIST = README.rst libgensio.pc.in CMakeLists.txt

# This variable must have 'exec' in its name, in order to be installed
# by 'install-exec' target (instead of default 'install-data')
pkgconfigexecdir = $(libdir)/pkgconfig
pkgconfigexec_DATA = libgensio.pc
