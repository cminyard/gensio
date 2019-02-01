
AM_CFLAGS = -I$(top_srcdir)/include

noinst_LIBRARIES = libgensiotool.a

libgensiotool_a_SOURCES = ioinfo.c ser_ioinfo.c utils.c

bin_PROGRAMS = gensiotool

gensiotool_SOURCES = gensiotool.c

noinst_HEADERS = ioinfo.h ser_ioinfo.h utils.h

gensiotool_LDADD = libgensiotool.a $(top_builddir)/lib/libgensio.la \
	$(OPENSSL_LIBS)

man_MANS = gensiotool.1

EXTRA_DIST = $(man_MANS)
