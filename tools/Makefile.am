
AM_CFLAGS = -I$(top_srcdir)/include

AM_CPPFLAGS = -DSYSCONFDIR="\"${sysconfdir}\""

noinst_LIBRARIES = libgensiotool.a

libgensiotool_a_SOURCES = ioinfo.c ser_ioinfo.c utils.c

bin_PROGRAMS = gensiotool gtlssh gtlsshd

bin_SCRIPTS = gtlssh-keygen

do_subst = sed -e 's,[@]sysconfdir[@],$(sysconfdir),g'

gtlssh-keygen: gtlssh-keygen.in
	$(do_subst) <$(srcdir)/gtlssh-keygen.in >gtlssh-keygen
	chmod +x gtlssh-keygen

gensiotool_SOURCES = gensiotool.c

gtlssh_SOURCES = gtlssh.c

gtlsshd_SOURCES = gtlsshd.c

noinst_HEADERS = ioinfo.h ser_ioinfo.h utils.h

gensiotool_LDADD = libgensiotool.a $(top_builddir)/lib/libgensio.la \
	$(OPENSSL_LIBS) -lpam

gtlssh_LDADD = libgensiotool.a $(top_builddir)/lib/libgensio.la \
	$(OPENSSL_LIBS) -lpam

gtlsshd_LDADD = libgensiotool.a $(top_builddir)/lib/libgensio.la \
	$(OPENSSL_LIBS) -lpam

man_MANS = gensiotool.1 gtlsshd.8 gtlssh.1

EXTRA_DIST = $(man_MANS)
