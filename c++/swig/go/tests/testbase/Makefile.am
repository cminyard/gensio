
noinst_SCRIPTS = go.mod

GOMOD = github.com/cminyard/go/gensio

go.mod: testbase.go
	rm -f go.mod
	go mod init testbase
	go mod edit -replace $(GOMOD)=$(abs_builddir)/../../gensio
	go mod tidy

$(builddir)/testbase.go: $(srcdir)/srctestbase.go
	cp $(srcdir)/srctestbase.go testbase.go

EXTRA_DIST = srctestbase.go

clean-local:
	rm -f testbase.go go.mod
