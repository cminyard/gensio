
AM_CFLAGS = -DSYSCONFDIR="\"${sysconfdir}\"" -I$(top_builddir) \
	    -I$(top_srcdir)/glib/include -I$(top_srcdir)/tcl/include \
            @EXTRA_CFLAGS@

noinst_LIBRARIES = libgensiotool.a libgtlssh.a

bin_PROGRAMS = gensiot @GMDNS@ @GTLSSH@ @GTLSSH_KEYGEN@ gsound \
	@GENSIO_PTY_HELPER@
sbin_PROGRAMS = @GTLSSHD@
EXTRA_PROGRAMS = gtlsshd gtlssh gmdns gtlssh-keygen gensio_pty_helper

bin_SCRIPTS = @GTLSSYNC@ greflector
EXTRA_SCRIPTS = gtlssync

greflector: $(top_builddir)/tests/reflector.py
	cp $(top_builddir)/tests/reflector.py $@

do_subst = sed -e 's,[@]SYSCONFDIR[@],$(sysconfdir),g'

gtlssh_keygen_SOURCES = gtlssh-keygen.c

gtlssh_keygen_LDADD = libgtlssh.a libgensiotool.a \
	$(top_builddir)/lib/libgensioosh.la $(top_builddir)/lib/libgensio.la \
	@OPENSSL_LIBS@

libgensiotool_a_SOURCES = ioinfo.c ser_ioinfo.c utils.c localports.c

libgtlssh_a_SOURCES = gtlssh-shared.c run_get_output.c file_utils.c

noinst_HEADERS = ioinfo.h ser_ioinfo.h utils.h localports.h gtlssh.h

gmdns_SOURCES = gensiomdns.c
gmdns_LDADD = libgtlssh.a libgensiotool.a $(top_builddir)/lib/libgensioosh.la \
	$(top_builddir)/lib/libgensio.la $(top_builddir)/lib/libgensiomdns.la

gensiot_SOURCES = gensiotool.c
gensiot_LDADD = libgensiotool.a $(top_builddir)/lib/libgensioosh.la \
	$(top_builddir)/lib/libgensio.la \
	@GLIB_LIB@ @GLIB_LIBS@ @TCL_LIB@ @TCL_LIBS@ @OPENSSL_LIBS@

gtlssh_SOURCES = gtlssh.c
gtlssh_LDADD = libgtlssh.a libgensiotool.a $(top_builddir)/lib/libgensioosh.la \
	$(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensiomdns.la @OPENSSL_LIBS@

gtlsshd_SOURCES = gtlsshd.c
gtlsshd_LDADD = libgtlssh.a libgensiotool.a $(top_builddir)/lib/libgensioosh.la\
	$(top_builddir)/lib/libgensio.la \
	@PAMLIB@ @OPENSSL_LIBS@

gsound_SOURCES = gensiosound.c
gsound_LDADD = $(top_builddir)/lib/libgensioosh.la \
	$(top_builddir)/lib/libgensio.la libgensiotool.a

gensio_pty_helper_SOURCES = gensio_pty_helper.c

manpages = gensiot.1 gtlsshd.8 gtlssh.1 gtlssh-keygen.1 gtlssync.1 gmdns.1 \
	greflector.1 gsound.1

if INSTALL_DOC
man1_MANS = gensiot.1 @GTLSSHMAN@ @GTLSSH_KEYGENMAN@ @GTLSSYNCMAN@ @GMDNSMAN@ \
	greflector.1 gsound.1
man8_MANS = @GTLSSHDMAN@
endif

EXTRA_DIST = $(manpages) gtlssync

clean-local:
	rm -f gtlssh-keygen greflector
