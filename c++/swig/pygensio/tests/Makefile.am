
LOG_COMPILER = $(SHELL) $(builddir)/runtest

TESTS = test_basic.py test_ax25.py test_crypto.py test_mdns.py \
	test_serial.py

EXTRA_DIST = testbase.py $(TESTS)

clean-local:
	rm -rf ca __pycache__
