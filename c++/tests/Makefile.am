
AM_CPPFLAGS = -I$(top_srcdir)/c++/include

TESTS = basic_cpp_test serial_test

basic_cpp_test_SOURCES = basic_cpp_test.cc

basic_cpp_test_LDADD = $(top_builddir)/c++/lib/libgensiooshcpp.la \
	$(top_builddir)/c++/lib/libgensiocpp.la \
	$(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la \
	$(OPENSSL_LIBS)

serial_test_SOURCES = serial_test.cc

serial_test_LDADD = $(top_builddir)/c++/lib/libgensiooshcpp.la \
	$(top_builddir)/c++/lib/libgensiocpp.la \
	$(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la \
	$(OPENSSL_LIBS)

check_PROGRAMS = basic_cpp_test serial_test
