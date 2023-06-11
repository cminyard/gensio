
noinst_SCRIPTS = go.mod

GOMOD = github.com/cminyard/go/gensio

go.mod: testbase.go
	rm -f go.mod
	go mod init testbase
	go mod edit -replace $(GOMOD)=$(abs_builddir)/../../gensio
	go mod tidy

$(builddir)/testbase.go: $(srcdir)/testbase.srcgo
	cp $(srcdir)/testbase.srcgo testbase.go

EXTRA_DIST = testbase.srcgo

clean-local:
	rm -f testbase.go go.mod
