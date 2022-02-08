#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

# Use AX25 to test passing of auxdata.

import pygensio
import sys
from testbase import *

# Basic test with blocking I/O
r = Reflector(o, "tcp,0")
r.startup()
port = r.get_port()

class Auxdata_EvHnd(EvHnd):
    def __init__(self, o):
        EvHnd.__init__(self, o)
        self.wrauxdata = None
        self.rdauxdata = None
        return

    def set_wrauxdata(self, auxdata):
        self.wrauxdata = auxdata
        return

    def set_rdauxdata(self, auxdata):
        self.rdauxdata = auxdata
        return

    def read(self, err, data, auxdata):
        if err == 0:
            if len(auxdata) != len(self.rdauxdata):
                raise Exception("auxdata length mismatch, expected %s, got %s" %
                                (str(self.rdauxdata), str(auxdata)))
            for i in range(0, len(auxdata)):
                if auxdata[i] != self.rdauxdata[i]:
                    raise Exception("auxdata parameter mismatch, expecte %s, got %s" %
                                    (str(self.rdauxdata), str(auxdata)))
        return EvHnd.read(self, err, data, auxdata)

    def write_ready(self):
        if self.data is None or self.writepos >= len(self.data):
            return
        count = self.g.write(self.data[self.writepos:], self.wrauxdata)
        self.writepos = self.writepos + count
        if self.writepos == len(self.data):
            self.g.set_write_callback_enable(False)
        return


h = Auxdata_EvHnd(o)
g = pygensio.gensio_alloc("ax25(laddr=AE5KM-1),kiss(server=yes),tcp,localhost," + port,
                          o, h)
h.set_gensio(g)
(rv, rsp) = g.control(0, False, pygensio.GENSIO_CONTROL_ENABLE_OOB, "1")
if rv != 0:
    raise Exception("Error enabling oob: " + pygensio.err_to_string(rv))

g.open_s()

h.set_wrauxdata(("pid:33", "addr:0,AE5KM-1,AE5KM-1", "oob"))
h.set_rdauxdata(("oob", "addr:ax25:0,AE5KM-1,AE5KM-1", "pid:33"))
h.set_data(conv_to_bytes("AX25 Test string"))
rv = h.wait(timeout=pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for I/O: " + pygensio.err_to_string(rv))

g.close_s()
r.shutdown()
rv = r.wait(pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for acc shutdown: " + pygensio.err_to_string(rv))
del g
del r
del h
del o

test_shutdown()

print("Pass")
sys.exit(0)
