
GOMOD = github.com/cminyard/go/gensio

noinst_SCRIPTS = go.mod

gensio_wrap.cxx gensio_wrap.h gensio.go: \
			gensio.swigcxx $(top_srcdir)/c++/include/gensio \
			$(top_srcdir)/c++/swig/include/gensio_base.i \
			$(top_srcdir)/include/gensio/gensio_err.h \
			$(top_srcdir)/include/gensio/gensio_control.h \
			$(top_srcdir)/include/gensio/gensio_types.h
	$(SWIG) $(DEFS) -Wall -go -intgosize 64 $(GO_SWIG_FLAGS) \
		-o gensio_wrap.cxx -c++ \
		-I$(top_srcdir)/c++/swig/go -I$(top_srcdir)/c++/include \
		-I$(top_srcdir)/include \
		-I$(top_builddir)/include -I$(top_srcdir)/c++/swig/include \
		$(srcdir)/gensio.swigcxx


$(builddir)/go.mod: $(srcdir)/srcgo.mod gensioapi.go gensio.go
	rm -f go.mod
	cp $(srcdir)/srcgo.mod go.mod

$(builddir)/gensioapi.go: $(srcdir)/srcgensioapi.go
	cp $(srcdir)/srcgensioapi.go gensioapi.go

EXTRA_DIST = srcgensioapi.go gensio.swigcxx srcgo.mod

clean-local:
	rm -rf gensioapi.go go.mod
	rm -rf gensio_wrap.cxx gensio_wrap.h gensio.go
