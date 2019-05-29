
AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir) $(OPENSSL_INCLUDES)

lib_LTLIBRARIES = libgensio.la

noinst_HEADERS = telnet.h heap.h utils.h uucplock.h buffer.h \
	gensio_filter_ssl.h gensio_filter_telnet.h gensio_ll_ipmisol.h \
	gensio_filter_certauth.h

libgensio_la_SOURCES = \
	gensio.c gensio_osops.c gensio_tcp.c gensio_udp.c gensio_stdio.c \
	sergensio.c sergensio_telnet.c sergensio_serialdev.c uucplock.c \
	gensio_selector.c waiter.c \
	gensio_ssl.c gensio_base.c gensio_filter_ssl.c \
	gensio_filter_telnet.c telnet.c buffer.c \
	gensio_ll_fd.c gensio_ll_gensio.c gensio_acc_gensio.c \
	gensio_ll_ipmisol.c sergensio_ipmisol.c \
	utils.c selector.c gensio_sctp.c \
	gensio_filter_certauth.c gensio_certauth.c gensio_pty.c \
	gensio_dummy.c gensio_echo.c gensio_mux.c

libgensio_la_LDFLAGS = $(OPENSSL_LIBS)
