
noinst_PROGRAMS = basic_server basic_server_sync basic_client \
	basic_server_sync_fork use_iods poll_and_gensio

EXTRA_DIST = basic_server.py basic_client.py

basic_server_SOURCES = basic_server.c

basic_server_LDADD = $(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la

basic_client_SOURCES = basic_client.c

basic_client_LDADD = $(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la

basic_server_sync_SOURCES = basic_server_sync.c

basic_server_sync_LDADD = $(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la

basic_server_sync_fork_SOURCES = basic_server_sync_fork.c

basic_server_sync_fork_LDADD = $(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la

use_iods_SOURCES = use_iods.c

use_iods_LDADD = $(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la

poll_and_gensio_SOURCES = poll_and_gensio.c

poll_and_gensio_LDADD = $(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la

