#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

check_sctp()

print("Test certauth over ssl over sctp accepter connect")
goterr = False
try:
    TestAcceptConnect(o,
            "certauth(CA=%s/clientcert.pem),ssl(key=%s/key.pem,cert=%s/cert.pem),sctp,0" % (keydir, keydir, keydir),
            "certauth(CA=%s/clientcert.pem),ssl(key=%s/key.pem,cert=%s/cert.pem),sctp,0" % (keydir, keydir, keydir),
            "certauth(cert=%s/cert.pem,key=%s/key.pem,username=test1),ssl(CA=%s/CA.pem),sctp,localhost," % (keydir, keydir, keydir),
                       do_small_test)
except Exception as E:
    s = str(E)
    # We can race and get either one of these
    if (not (s.endswith("Communication error") or
             s.endswith("Authentication tokens rejected") or
             s.endswith("Remote end closed connection"))):
        raise
    print("  Success checking invalid client cert")
    goterr = True
if not goterr:
    raise Exception("Did not get error on invalid client certificate.")

TestAcceptConnect(o,
            "certauth(),ssl(key=%s/key.pem,cert=%s/cert.pem),sctp,0" % (keydir, keydir),
            "certauth(),ssl(key=%s/key.pem,cert=%s/cert.pem),sctp,0" % (keydir, keydir),
            "certauth(cert=%s/clientcert.pem,key=%s/clientkey.pem,username=test1),ssl(CA=%s/CA.pem),sctp,localhost," % (keydir, keydir, keydir),
                       do_small_test, CA="%s/clientcert.pem" % keydir)

del o
test_shutdown()
