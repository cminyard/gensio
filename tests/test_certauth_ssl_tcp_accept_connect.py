#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test certauth over ssl over tcp")

# First test bypassing authentication from the auth_begin callback;
TestAcceptConnect(o,
       ("certauth(),ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,ipv4,0" %
        (keydir, keydir)),
       ("certauth(),ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,ipv4,0" %
        (keydir, keydir)),
       "certauth(),ssl(CA=%s/CA.pem),tcp,localhost," % keydir,
                  do_small_test, auth_begin_rv=0)

# Now try password authentication.
TestAcceptConnect(o,
       ("certauth(enable-password),ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,ipv4,0" %
        (keydir, keydir)),
       ("certauth(enable-password),ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,ipv4,0" %
        (keydir, keydir)),
       ("certauth(enable-password,password=asdfasdf),ssl(CA=%s/CA.pem),tcp,localhost," %
        keydir),
                  do_small_test, expect_pw = "asdfasdf", expect_pw_rv = 0)

# Test the password request
TestAcceptConnect(o,
       ("certauth(enable-password),ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,0" %
        (keydir, keydir)),
       ("certauth(enable-password),ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,0" %
        (keydir, keydir)),
       ("certauth(enable-password),ssl(CA=%s/CA.pem),tcp,localhost," %
        keydir),
                  do_small_test, expect_pw = "jkl;", expect_pw_rv = 0,
                  password = "jkl;")

# Test the password with 2-factor authentication request
TestAcceptConnect(o,
       ("certauth(enable-password,enable-2fa),ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,0" %
        (keydir, keydir)),
       ("certauth(enable-password,enable-2fa),ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,0" %
        (keydir, keydir)),
       ("certauth(enable-password),ssl(CA=%s/CA.pem),tcp,localhost," %
        keydir),
                  do_small_test, expect_pw = "jkl;", expect_pw_rv = 0,
                  password = "jkl;",
                  expect_2fa = "Hello There", expect_2fa_rv = 0,
                  val_2fa = "Hello There")

del o
test_shutdown()
