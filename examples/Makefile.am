
AM_CFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = basic_server basic_server_sync

basic_server_SOURCES = basic_server.c

basic_server_LDADD = $(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS)

basic_server_sync_SOURCES = basic_server_sync.c

basic_server_sync_LDADD = $(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS)

