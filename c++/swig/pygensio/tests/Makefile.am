
export VERBOSE = 1

LOG_COMPILER = $(SHELL) $(builddir)/runtest

TESTS = test_basic.py test_ax25.py test_crypto.py test_mdns.py \
	test_serial.py

EXTRA_DIST = testbase.py $(TESTS)

test_crypto.py: ca/CA.key

ca/CA.key:
	$(top_srcdir)/tests/make_keys

clean-local:
	rm -rf ca __pycache__
