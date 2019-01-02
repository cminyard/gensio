
AM_CFLAGS = -I$(top_srcdir)/include

bin_PROGRAMS = gensiotool

gensiotool_SOURCES = gensiotool.c

gensiotool_LDADD = $(top_builddir)/lib/libgensio.la $(OPENSSL_LIBS)

man_MANS = gensiotool.1
