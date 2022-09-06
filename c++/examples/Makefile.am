
AM_CPPFLAGS = -I$(top_srcdir)/c++/include

noinst_PROGRAMS = telnet_server telnet_client mdns

telnet_server_SOURCES = telnet_server.cc

telnet_server_LDADD = $(top_builddir)/c++/lib/libgensiooshcpp.la \
	$(top_builddir)/c++/lib/libgensiocpp.la \
	$(top_builddir)/lib/libgensioosh.la \
	$(top_builddir)/lib/libgensio.la

telnet_client_SOURCES = telnet_client.cc

telnet_client_LDADD = $(top_builddir)/c++/lib/libgensiooshcpp.la \
	$(top_builddir)/lib/libgensioosh.la \
	$(top_builddir)/c++/lib/libgensiocpp.la \
	$(top_builddir)/lib/libgensio.la

mdns_SOURCES = mdns.cc

mdns_LDADD = $(top_builddir)/c++/lib/libgensiooshcpp.la \
	$(top_builddir)/c++/lib/libgensiomdnscpp.la \
	$(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la
