
AM_CPPFLAGS = -I$(top_srcdir)/c++/include -I$(top_srcdir)/tcl/c++/include \
	-I$(top_srcdir)/tcl/include

TESTS = basic_tcl_test

basic_tcl_test_SOURCES = basic_tcl_test.cc

basic_tcl_test_LDADD = $(top_builddir)/lib/libgensio.la \
	$(top_builddir)/c++/lib/libgensiocpp.la \
	$(top_builddir)/c++/lib/libgensiooshcpp.la \
	$(top_builddir)/lib/libgensio.la \
	$(top_builddir)/lib/libgensioosh.la \
	$(top_builddir)/tcl/libgensiotcl.la \
	$(TCL_LIBS) $(OPENSSL_LIBS)

check_PROGRAMS = basic_tcl_test
