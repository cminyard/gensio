
SUBDIRS = testbase

LOG_COMPILER = $(SHELL) $(builddir)/runtest

TESTS = test_basic test_ax25 test_crypto test_serial test_mdns test_netifs

TEST_SRCS = test_basic.go test_ax25.go test_crypto.go test_serial.go \
	test_mdns.go test_netifs.go

GOMOD = github.com/cminyard/go/gensio

test_basic.go: $(srcdir)/srctest_basic.go testbase/testbase.go
	cp $(srcdir)/srctest_basic.go test_basic.go

test_ax25.go: $(srcdir)/srctest_ax25.go testbase/testbase.go
	cp $(srcdir)/srctest_ax25.go test_ax25.go

test_crypto.go: $(srcdir)/srctest_crypto.go testbase/testbase.go
	cp $(srcdir)/srctest_crypto.go test_crypto.go

test_serial.go: $(srcdir)/srctest_serial.go testbase/testbase.go
	cp $(srcdir)/srctest_serial.go test_serial.go

test_mdns.go: $(srcdir)/srctest_mdns.go testbase/testbase.go
	cp $(srcdir)/srctest_mdns.go test_mdns.go

test_netifs.go: $(srcdir)/srctest_netifs.go testbase/testbase.go
	cp $(srcdir)/srctest_netifs.go test_netifs.go

go.mod: $(TEST_SRCS)
	rm -f go.mod
	go mod init tests
	go mod edit -replace $(GOMOD)=../gensio
	go mod edit -replace testbase=./testbase
	go mod tidy

MORE_LIBS=
if BUILTIN_MDNS
MORE_LIBS += $(MDNS_LIBS)
endif
if BUILTIN_SOUND
MORE_LIBS += $(SOUND_LIBS)
endif
if BUILTIN_SCTP
MORE_LIBS += $(LIBSCTP_LIBS)
endif
if BUILTIN_SSL
MORE_LIBS += $(OPENSSL_LIBS)
endif
if BUILTIN_IPMISOL
MORE_LIBS += $(OPENIPMI_LIBS)
endif
export CGO_CXXFLAGS = $(CXXFLAGS) $(AM_CXXFLAGS)
export CGO_CPPFLAGS = $(CPPFLAGS)
export CGO_LDFLAGS = -L$(top_builddir)/c++/lib/.libs \
	-lgensiooshcpp -lgensiocpp -lgensiomdnscpp \
	-L$(top_builddir)/lib/.libs -lgensioosh -lgensio -lgensiomdns \
	$(MORE_LIBS)

test_basic: ../gensio/gensio.go \
		../gensio/gensio_wrap.cxx \
		../gensio/gensio_wrap.h \
		test_basic.go ../gensio/gensioapi.go go.mod
	echo $(MORE_LIBS)
	go build test_basic.go

test_ax25: ../gensio/gensio.go \
		../gensio/gensio_wrap.cxx \
		../gensio/gensio_wrap.h \
		test_ax25.go ../gensio/gensioapi.go go.mod
	go build test_ax25.go

test_crypto: ../gensio/gensio.go \
		../gensio/gensio_wrap.cxx \
		../gensio/gensio_wrap.h \
		test_crypto.go ../gensio/gensioapi.go go.mod
	go build test_crypto.go

test_serial: ../gensio/gensio.go \
		../gensio/gensio_wrap.cxx \
		../gensio/gensio_wrap.h \
		test_serial.go ../gensio/gensioapi.go go.mod
	go build test_serial.go

test_mdns: ../gensio/gensio.go \
		../gensio/gensio_wrap.cxx \
		../gensio/gensio_wrap.h \
		test_mdns.go ../gensio/gensioapi.go go.mod
	go build test_mdns.go

test_netifs: ../gensio/gensio.go \
		../gensio/gensio_wrap.cxx \
		../gensio/gensio_wrap.h \
		test_netifs.go ../gensio/gensioapi.go go.mod
	go build test_netifs.go

EXTRA_DIST = srctest_basic.go srctest_ax25.go srctest_crypto.go \
	srctest_serial.go srctest_mdns.go srctest_netifs.go

clean-local:
	rm -rf go.mod ca $(TESTS) $(TEST_SRCS)
