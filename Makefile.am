
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib include $(SWIG_DIR) tests tools examples

if HAVE_DOC
SUBDIRS += man
endif

DIST_SUBDIRS = lib swig include tests tools examples

if HAVE_DOC
DIST_SUBDIRS += man
endif

EXTRA_DIST = README.rst reconf CMakeLists.txt config.h.cmake
