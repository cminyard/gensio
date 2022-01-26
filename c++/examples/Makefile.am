
AM_CPPFLAGS = -I$(top_srcdir)/c++/include

noinst_PROGRAMS = telnet_server mdns

telnet_server_SOURCES = telnet_server.cc

mdns_SOURCES = mdns.cc

telnet_server_LDADD = $(top_builddir)/lib/libgensio.la \
	$(top_builddir)/c++/lib/libgensiocpp.la \
	$(OPENSSL_LIBS)

mdns_LDADD = $(top_builddir)/lib/libgensio.la \
	$(top_builddir)/c++/lib/libgensiocpp.la \
	$(OPENSSL_LIBS)

EXTRA_DIST = CMakeLists.txt
