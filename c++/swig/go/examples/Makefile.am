
noinst_SCRIPTS = example telnet_server telnet_client

GOMOD = github.com/cminyard/go/gensio

example.go: $(srcdir)/srcexample.go
	cp $(srcdir)/srcexample.go example.go

telnet_server.go: $(srcdir)/srctelnet_server.go
	cp $(srcdir)/srctelnet_server.go telnet_server.go

telnet_client.go: $(srcdir)/srctelnet_client.go
	cp $(srcdir)/srctelnet_client.go telnet_client.go

go.mod: example.go
	rm -f go.mod
	go mod init examples
	go mod edit -replace $(GOMOD)=../gensio
	go mod tidy

export CGO_CXXFLAGS = $(CXXFLAGS) -I$(abs_top_srcdir)/c++/include
export CGO_CPPFLAGS = -I$(abs_top_srcdir)/include -I$(abs_top_builddir)/include
export CGO_LDFLAGS = -L$(abs_top_builddir)/c++/lib/.libs -lgensiocpp -L$(abs_top_builddir)/lib/.libs -lgensio

example: ../gensio/gensio.go \
		../gensio/gensio_wrap.cxx \
		../gensio/gensio_wrap.h \
		example.go ../gensio/gensioapi.go go.mod
	go build example.go

telnet_server: ../gensio/gensio.go \
		../gensio/gensio_wrap.cxx \
		../gensio/gensio_wrap.h \
		telnet_server.go ../gensio/gensioapi.go go.mod
	go build telnet_server.go

telnet_client: ../gensio/gensio.go \
		../gensio/gensio_wrap.cxx \
		../gensio/gensio_wrap.h \
		telnet_client.go ../gensio/gensioapi.go go.mod
	go build telnet_client.go

EXTRA_DIST = srcexample.go srctelnet_server.go srctelnet_client.go

clean-local:
	rm -rf go.mod example example.go telnet_server telnet_server.go \
		 telnet_client telnet_client.go
