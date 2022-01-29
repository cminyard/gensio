
noinst_SCRIPTS = example

GOMOD = github.com/cminyard/go/gensio

example.go: $(srcdir)/srcexample.go
	cp $(srcdir)/srcexample.go example.go

go.mod: example.go
	rm -f go.mod
	go mod init examples
	go mod edit -replace $(GOMOD)=../gensio
	go mod tidy

export CGO_CXXFLAGS = $(CXXFLAGS) -I$(abs_top_srcdir)/c++/include
export CGO_CPPFLAGS = -I$(abs_top_srcdir)/include -I$(abs_top_builddir)/include
export CGO_LDFLAGS = -L$(abs_top_builddir)/c++/lib/.libs -lgensiocpp -L$(abs_top_builddir)/lib/.libs -lgensio

example: ../gensio/gensio.go \
		../gensio/rawgensio_wrap.cxx \
		../gensio/rawgensio_wrap.h \
		example.go ../gensio/gensioapi.go go.mod
	go build example.go

EXTRA_DIST = srcexample.go

clean-local:
	rm -rf example example.go go.mod
