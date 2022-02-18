
SUBDIRS = gensio examples tests

# A helper to transfer info to where it needs to go and rename everything
# properly.

GOLANG_INSTALLDIR = /personal/git/go/gensio

golang-install:
	cp $(srcdir)/README.rst $(GOLANG_INSTALLDIR)
	cp $(srcdir)/gensio/gensio.swigcxx $(GOLANG_INSTALLDIR)
	cp $(srcdir)/gensio/srcgensioapi.go $(GOLANG_INSTALLDIR)/gensioapi.go
	cp $(srcdir)/gensio/srcgo.mod $(GOLANG_INSTALLDIR)/go.mod
	cp $(srcdir)/../include/gensio_base.i $(GOLANG_INSTALLDIR)
