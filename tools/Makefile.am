
AM_CPPFLAGS = -DSYSCONFDIR="\"${sysconfdir}\""

noinst_LIBRARIES = libgensiotool.a libgtlssh.a

bin_PROGRAMS = gensiot @GMDNS@ @GTLSSH@
sbin_PROGRAMS = @GTLSSHD@
EXTRA_PROGRAMS = gtlsshd gtlssh gmdns

bin_SCRIPTS = @GTLSSH_KEYGEN@ @GTLSSYNC@
EXTRA_SCRIPTS = gtlssync gtlssh-keygen

do_subst = sed -e 's,[@]SYSCONFDIR[@],$(sysconfdir),g'

gtlssh-keygen: gtlssh-keygen.in
	$(do_subst) <$(srcdir)/gtlssh-keygen.in >gtlssh-keygen
	chmod +x gtlssh-keygen

gensiot_SOURCES = gensiotool.c

gmdns_SOURCES = gensiomdns.c

libgensiotool_a_SOURCES = ioinfo.c ser_ioinfo.c utils.c localports.c

libgtlssh_a_SOURCES = gtlssh-shared.c

gtlssh_SOURCES = gtlssh.c

gtlsshd_SOURCES = gtlsshd.c

noinst_HEADERS = ioinfo.h ser_ioinfo.h utils.h localports.h gtlssh.h

gmdns_LDADD = libgensiotool.a $(top_builddir)/lib/libgensio.la \
	@OPENSSL_LIBS@

gensiot_LDADD = libgensiotool.a $(top_builddir)/lib/libgensio.la \
	@OPENSSL_LIBS@

gtlssh_LDADD = libgtlssh.a libgensiotool.a $(top_builddir)/lib/libgensio.la \
	@OPENSSL_LIBS@

gtlsshd_LDADD = libgtlssh.a libgensiotool.a $(top_builddir)/lib/libgensio.la \
	@PAMLIB@ @OPENSSL_LIBS@

manpages = gensiot.1 gtlsshd.8 gtlssh.1 gtlssh-keygen.1 gtlssync.1 gmdns.1

if INSTALL_DOC
man_MANS = gensiot.1 @GTLSSHDMAN@ @GTLSSHMAN@ @GTLSSH_KEYGENMAN@ @GTLSSYNCMAN@ \
	@GMDNSMAN@
endif

EXTRA_DIST = $(manpages) gtlssh-keygen.in CMakeLists.txt gtlssync

