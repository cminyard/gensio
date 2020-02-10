
AM_CFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = basic_server basic_server_sync basic_client

EXTRA_DIST = basic_server.py basic_client.py

basic_server_SOURCES = basic_server.c

basic_server_LDADD = $(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS)

basic_client_SOURCES = basic_client.c

basic_client_LDADD = $(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS)

basic_server_sync_SOURCES = basic_server_sync.c

basic_server_sync_LDADD = $(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS)

