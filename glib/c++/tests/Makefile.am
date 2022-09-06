
AM_CPPFLAGS = -I$(top_srcdir)/c++/include -I$(top_srcdir)/glib/c++/include \
	-I$(top_srcdir)/glib/include

TESTS = basic_glib_test

basic_glib_test_SOURCES = basic_glib_test.cc

basic_glib_test_LDADD = $(top_builddir)/lib/libgensio.la \
	$(top_builddir)/c++/lib/libgensiocpp.la \
	$(top_builddir)/c++/lib/libgensiooshcpp.la \
	$(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la \
	$(top_builddir)/glib/libgensioglib.la \
	$(OPENSSL_LIBS)

check_PROGRAMS = basic_glib_test
