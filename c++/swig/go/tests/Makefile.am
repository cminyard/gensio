
TESTS = test_basic

TEST_SRCS = test_basic.go

GOMOD = github.com/cminyard/go/gensio

test_basic.go: $(srcdir)/srctest_basic.go
	cp $(srcdir)/srctest_basic.go test_basic.go

go.mod: $(TEST_SRCS)
	rm -f go.mod
	go mod init tests
	go mod edit -replace $(GOMOD)=../gensio
	go mod tidy

export CGO_CXXFLAGS = -I$(abs_top_srcdir)/c++/include
export CGO_CPPFLAGS = -I$(abs_top_srcdir)/include -I$(abs_top_builddir)/include
export CGO_LDFLAGS = -L$(abs_top_builddir)/c++/lib/.libs -lgensiocpp -L$(abs_top_builddir)/lib/.libs -lgensio

test_basic: ../gensio/gensio.go \
		../gensio/rawgensio/rawgensio_wrap.cxx \
		../gensio/rawgensio/rawgensio_wrap.h \
		test_basic.go ../gensio/gensioapi.go go.mod
	go build test_basic.go

EXTRA_DIST = srctest_basic.go

clean-local:
	rm -rf go.mod $(TESTS) $(TEST_SRCS)
