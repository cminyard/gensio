#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

# Use certauth to verify crypto interfaces

import pygensio
import sys
from testbase import *

class Crypto_Refl_Acc_EvHnd(Refl_Acc_EvHnd):
    def __init__(self):
        Refl_Acc_EvHnd.__init__(self)
        return

    def auth_begin(self, g):
        (rv, name) = g.control(pygensio.GENSIO_CONTROL_DEPTH_FIRST, True,
                               pygensio.GENSIO_CONTROL_USERNAME, "0")
        if str(name, "utf8") != "asdf":
            raise Exception("Name mismatch in auth_begin")
        return pygensio.GE_NOTSUP

    def precert_verify(self, g):
        return pygensio.GE_NOTSUP

    def postcert_verify(self, g, err, errstr):
        return pygensio.GE_NOTSUP

    def password_verify(self, g, password):
        if password != "jkl":
            raise Exception("password mismatch in password_verify")
        return pygensio.GE_NOTSUP

    def request_password(self, g, maxsize):
        return (0, "jkl")

    def verify_2fa(self, g, val):
        if str(val, "utf8") != "1234":
            raise Exception("2fa mismatch in verify_2fa")
        return 0

    def request_2fa(self, g):
        return (0, bytes("1234", "utf8"))

class Crypto_EvHnd(EvHnd):
    def __init__(self, o):
        EvHnd.__init__(self, o)
        self.wrauxdata = None
        self.rdauxdata = None
        return

    def auth_begin(self):
        (rv, name) = self.g.control(pygensio.GENSIO_CONTROL_DEPTH_FIRST, True,
                                    pygensio.GENSIO_CONTROL_USERNAME, "0")
        if str(name, "utf8") != "asdf":
            raise Exception("Name mismatch in auth_begin")
        return pygensio.GE_NOTSUP

    def precert_verify(self):
        return pygensio.GE_NOTSUP

    def postcert_verify(self, err, errstr):
        return pygensio.GE_NOTSUP

    def password_verify(self, password):
        if password != "jkl":
            raise Exception("password mismatch in password_verify")
        return pygensio.GE_NOTSUP

    def request_password(self, maxsize):
        return (0, "jkl")

    def verify_2fa(self, val):
        if str(val, "utf8") != "1234":
            raise Exception("2fa mismatch in verify_2fa")
        return 0

    def request_2fa(self):
        return (0, bytes("1234", "utf8"))

print("Verify crypto interfaces")
acch = Crypto_Refl_Acc_EvHnd()
r = Reflector(o,
              "certauth(enable-password,enable-2fa)," +
              "ssl(key=ca/key.pem,cert=ca/cert.pem),tcp,0",
              acc_evh = acch)
r.startup()
port = r.get_port()

h = Crypto_EvHnd(o)
g = pygensio.gensio_alloc("certauth(username=asdf,enable-password)," +
                          "ssl(ca=ca/CA.pem),tcp,localhost," + port,
                          o, h)
h.set_gensio(g)

g.open_s()

h.set_data(conv_to_bytes("Crypto Test string"))
rv = h.wait(timeout=pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for I/O: " + pygensio.err_to_string(rv))

g.close_s()
h.g = None
r.shutdown()
rv = r.wait(pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for acc shutdown: " +
                    pygensio.err_to_string(rv))
del g
del r
del h
del acch

print("Verify backwards crypto interfaces")
acch = Crypto_Refl_Acc_EvHnd()
r = Reflector(o,
              "certauth(username=asdf,enable-password,mode=client)," +
              "ssl(ca=ca/CA.pem,mode=client),tcp,0",
              acc_evh = acch)
r.startup()
port = r.get_port()

verify_acc(r.acc, "certauth", True, True, False)

h = Crypto_EvHnd(o)
g = pygensio.gensio_alloc("certauth(enable-password,enable-2fa,mode=server)," +
                          "ssl(key=ca/key.pem,cert=ca/cert.pem,mode=server)," +
                          "tcp,localhost," + port,
                          o, h)
h.set_gensio(g)

g.open_s()

verify_gen(g, "certauth", False, True, True, True, True, False)

h.set_data(conv_to_bytes("Crypto Test string"))
rv = h.wait(timeout=pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for I/O: " + pygensio.err_to_string(rv))
verify_gen(r.g, "certauth", True, True, True, True, True, False)

g.close_s()
h.g = None
r.shutdown()
rv = r.wait(pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for acc shutdown: " +
                    pygensio.err_to_string(rv))
del g
del r
del h
del acch

del o

test_shutdown()

print("Pass")
sys.exit(0)
