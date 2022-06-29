
AM_CFLAGS = -DSYSCONFDIR="\"${sysconfdir}\"" -I$(top_builddir) \
	    -I$(top_srcdir)/glib/include -I$(top_srcdir)/tcl/include \
            @EXTRA_CFLAGS@

noinst_LIBRARIES = libgensiotool.a libgtlssh.a

bin_PROGRAMS = gensiot @GMDNS@ @GTLSSH@ @GTLSSH_KEYGEN@
sbin_PROGRAMS = @GTLSSHD@
EXTRA_PROGRAMS = gtlsshd gtlssh gmdns gtlssh-keygen

bin_SCRIPTS = @GTLSSYNC@ greflector
EXTRA_SCRIPTS = gtlssync

greflector: $(top_builddir)/tests/reflector.py
	cp $(top_builddir)/tests/reflector.py $@

do_subst = sed -e 's,[@]SYSCONFDIR[@],$(sysconfdir),g'

gtlssh_keygen_SOURCES = gtlssh-keygen.c

gtlssh_keygen_LDADD = libgtlssh.a libgensiotool.a \
	$(top_builddir)/lib/libgensio.la @OPENSSL_LIBS@ \
	@EXTRA_WINDOWS_USER_LIBS@

gensiot_SOURCES = gensiotool.c

gmdns_SOURCES = gensiomdns.c

libgensiotool_a_SOURCES = ioinfo.c ser_ioinfo.c utils.c localports.c

libgtlssh_a_SOURCES = gtlssh-shared.c run_get_output.c file_utils.c

gtlssh_SOURCES = gtlssh.c

gtlsshd_SOURCES = gtlsshd.c

noinst_HEADERS = ioinfo.h ser_ioinfo.h utils.h localports.h gtlssh.h

gmdns_LDADD = libgtlssh.a libgensiotool.a $(top_builddir)/lib/libgensio.la \
	@OPENSSL_LIBS@

gensiot_LDADD = libgensiotool.a $(top_builddir)/lib/libgensio.la \
	@OPENSSL_LIBS@ @GLIB_LIB@ @GLIB_LIBS@ @TCL_LIB@ @TCL_LIBS@

gtlssh_LDADD = libgtlssh.a libgensiotool.a $(top_builddir)/lib/libgensio.la \
	@OPENSSL_LIBS@ @EXTRA_WINDOWS_USER_LIBS@

gtlsshd_LDADD = libgtlssh.a libgensiotool.a $(top_builddir)/lib/libgensio.la \
	@PAMLIB@ @OPENSSL_LIBS@ @EXTRA_WINDOWS_USER_LIBS@

manpages = gensiot.1 gtlsshd.8 gtlssh.1 gtlssh-keygen.1 gtlssync.1 gmdns.1 \
	greflector.1

if INSTALL_DOC
man1_MANS = gensiot.1 @GTLSSHMAN@ @GTLSSH_KEYGENMAN@ @GTLSSYNCMAN@ @GMDNSMAN@
man8_MANS = @GTLSSHDMAN@
endif

EXTRA_DIST = $(manpages) CMakeLists.txt gtlssync

clean-local:
	rm -f gtlssh-keygen greflector
