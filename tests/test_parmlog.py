#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

import utils
import gensio
import gensios_enabled
import sys

gensios_enabled.check_iostr_gensios("tcp")

class ParmEvent:
    def __init__(self):
        self.log = None
        return

    def parmlog(self, log):
        self.log = log
        return

print("Testing parameter error logs")

o = utils.o
p = ParmEvent()

print("  Testing accepter error logs")

handled = False
try:
    a = gensio.gensio_accepter(o, "tcp(x=asdf),0", p)
except Exception as E:
    if str(E) != "gensio:gensio_accepter constructor: Invalid data to parameter":
        raise Exception("Unknown exception from accepter: " + str(E))
    handled = True

if not handled:
    raise Exception("Did not get an exception from accepter error")

if p.log is None:
    raise Exception("Did not get a parm log from accepter error")

if p.log != "accepter tcp: unknown parameter x=asdf":
    raise Exception("Invalid parm log: " + p.log)

print("    Success!")

print("  Testing gensio error logs")

p.log = None
handled = False
try:
    a = gensio.gensio(o, "tcp(x=asdf),0", p)
except Exception as E:
    if str(E) != "gensio:gensio alloc: Invalid data to parameter":
        raise Exception("Unknown exception from gensio: " + str(E))
    handled = True

if not handled:
    raise Exception("Did not get an exception from gensio error")

if p.log is None:
    raise Exception("Did not get a parm log from gensio error")

if p.log != "gensio tcp: Invalid network address: 0":
    raise Exception("Invalid parm log: " + p.log)

del o
del p
utils.test_shutdown()

print("    Success!")
