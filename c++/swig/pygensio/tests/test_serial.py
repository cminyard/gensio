#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

# Test basic operation, both synchronous and asynchronous open, close,
# and data passing. Also shutdown, enable, and new connections for
# Accepters.

from testbase import *
import pygensio
import sys

# Note that serial_event must be first.
class STelnet_Refl_EvHnd(pygensio.Serial_Event, Refl_EvHnd):
    def __init__(self, w):
        pygensio.Serial_Event.__init__(self)
        Refl_EvHnd.__init__(self, w)
        self.got_break = False
        self.baud_v = 9600
        self.sig_v = bytes("mysig", "utf8")
        self.datasize_v = 8
        self.parity_v = pygensio.GENSIO_SER_PARITY_NONE
        self.stopbits_v = 1
        self.flowcontrol_v = pygensio.GENSIO_SER_FLOWCONTROL_NONE
        self.iflowcontrol_v = pygensio.GENSIO_SER_FLOWCONTROL_DCD
        self.break_v = pygensio.GENSIO_SER_OFF
        self.rts_v = pygensio.GENSIO_SER_OFF
        return

    def set_gensio(self, g):
        self.g = pygensio.cast_to_serial_gensio(g)
        return

    def signature(self, sig):
        if sig is not None and len(sig) > 0:
            self.sig_v = sig
        self.g.signature(self.sig_v, None)
        return

    def flush(self, val):
        # FIXME - how to detect?
        return

    def sync(self):
        return

    def baud(self, speed):
        if speed != 0:
            self.baud_v = speed
        self.g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
                        pygensio.GENSIO_ACONTROL_SER_BAUD,
                        str(self.baud_v), None)
        return

    def datasize(self, size):
        if size != 0:
            self.datasize_v = size
        self.g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
                        pygensio.GENSIO_ACONTROL_SER_DATASIZE,
                        str(self.datasize_v), None)
        return

    def parity(self, par):
        if par != 0:
            self.parity_v = par
        par = pygensio.gensio_parity_to_str(self.parity_v)
        rv = self.g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
                            pygensio.GENSIO_ACONTROL_SER_PARITY,
                            par, None)
        return

    def stopbits(self, bits):
        if bits != 0:
            self.stopbits_v = bits
        self.g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
                        pygensio.GENSIO_ACONTROL_SER_STOPBITS,
                        str(self.stopbits_v), None)
        return

    def flowcontrol(self, flow):
        if flow != 0:
            self.flowcontrol_v = flow
        flow = pygensio.gensio_flowcontrol_to_str(self.flowcontrol_v)
        self.g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
                        pygensio.GENSIO_ACONTROL_SER_FLOWCONTROL,
                        flow, None)
        return

    def iflowcontrol(self, flow):
        if flow != 0:
            self.iflowcontrol_v = flow
        flow = pygensio.gensio_flowcontrol_to_str(self.iflowcontrol_v)
        self.g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
                        pygensio.GENSIO_ACONTROL_SER_IFLOWCONTROL,
                        flow, None)
        return

    def sbreak(self, val):
        if val != 0:
            self.break_v = val
        val = pygensio.gensio_onoff_to_str(self.break_v)
        self.g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
                        pygensio.GENSIO_ACONTROL_SER_SBREAK,
                        val, None)
        return

    def dtr(self, val):
        if val != 0:
            self.dtr_v = val
        val = pygensio.gensio_onoff_to_str(self.dtr_v)
        self.g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
                        pygensio.GENSIO_ACONTROL_SER_DTR,
                        val, None)
        return

    def rts(self, val):
        if val != 0:
            self.rts_v = val
        val = pygensio.gensio_onoff_to_str(self.rts_v)
        self.g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
                        pygensio.GENSIO_ACONTROL_SER_RTS,
                        val, None)
        return

    def send_break(self):
        self.got_break = True
        self.w.wake()
        return

class STelnet_EvHnd(pygensio.Serial_Event, EvHnd):
    def __init__(self, w):
        pygensio.Serial_Event.__init__(self)
        EvHnd.__init__(self, w)
        self.got_break = False
        self.baud_v = None
        return

    def modemstate(self, state):
        return

    def linestate(self, state):
        return

    def flow_state(self, state):
        return

    def send_break(self):
        self.got_break = True
        self.w.wake()
        return

class Ser_Op_Done(pygensio.Serial_Op_Done):
    def __init__(self, w):
        pygensio.Serial_Op_Done.__init__(self)
        self.w = w
        return

    def serial_op_done(self, err, val):
        self.err = err
        self.val = val
        self.w.wake()
        return

class Gen_Control_Done(pygensio.Gensio_Control_Done):
    def __init__(self, w):
        pygensio.Gensio_Control_Done.__init__(self)
        self.w = w

    def control_done(self, err, val):
        self.err = err
        self.val = val
        self.w.wake()

w = pygensio.Waiter(o)
treh = STelnet_Refl_EvHnd(w)
r = Reflector(o, "telnet(rfc2217),tcp,localhost,0", w = w, evh = treh)
r.startup()
port = r.get_port()

h = STelnet_EvHnd(o)
g = pygensio.gensio_alloc("telnet(rfc2217),tcp,localhost," + port, o, h)
h.set_gensio(g)
g.open_s()

h.set_data(conv_to_bytes("Test string"))
rv = h.wait(timeout=pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for I/O: " + pygensio.err_to_string(rv))

g.set_read_callback_enable(True)

od = Gen_Control_Done(w)
g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
           pygensio.GENSIO_ACONTROL_SER_SIGNATURE,
           "", od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for sig: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching sig: " + pygensio.err_to_string(od.err))
if od.val != bytes("mysig", "utf8"):
    raise Exception("Invalid sig: %s" % str(od.sig, "utf8"))
del od

g.control(0, pygensio.GENSIO_CONTROL_SET,
          pygensio.GENSIO_CONTROL_SER_FLUSH, "recv")

(rv, baud) = g.acontrol_s(0, pygensio.GENSIO_CONTROL_GET,
                          pygensio.GENSIO_ACONTROL_SER_BAUD,
                          "0")
if rv != 0:
    raise Exception("Error getting baud: " + pygensio.err_to_string(rv))
if baud != b"9600":
    raise Exception("Invalid baud: %s" % str(baud))
od = Gen_Control_Done(w)
g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
           pygensio.GENSIO_ACONTROL_SER_BAUD,
           "19200", od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for baud: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching baud: " + pygensio.err_to_string(od.err))
if od.val != b"19200":
    raise Exception("Invalid baud(2): %s" % str(od.val))
del od

(rv, datasize) = g.acontrol_s(0, pygensio.GENSIO_CONTROL_GET,
                              pygensio.GENSIO_ACONTROL_SER_DATASIZE,
                              "0")
if rv != 0:
    raise Exception("Error getting datasize: " + pygensio.err_to_string(rv))
if datasize != b"8":
    raise Exception("Invalid datasize: %d" % datasize)
od = Gen_Control_Done(w)
g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
           pygensio.GENSIO_ACONTROL_SER_DATASIZE,
           "7", od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for datasize: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching datasize: " + pygensio.err_to_string(od.err))
if od.val != b"7":
    raise Exception("Invalid datasize(2): %s" % str(od.val))
del od

(rv, parity) = g.acontrol_s(0, pygensio.GENSIO_CONTROL_GET,
                            pygensio.GENSIO_ACONTROL_SER_PARITY,
                            "0")
if rv != 0:
    raise Exception("Error getting parity: " + pygensio.err_to_string(rv))
if parity != b"none":
    raise Exception("Invalid parity: %d" % parity)
od = Gen_Control_Done(w)
g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
           pygensio.GENSIO_ACONTROL_SER_PARITY,
           "odd", od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for parity: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching parity: " + pygensio.err_to_string(od.err))
if od.val != b"odd":
    raise Exception("Invalid parity(2): %s" % str(od.val))
del od

(rv, stopbits) = g.acontrol_s(0, pygensio.GENSIO_CONTROL_GET,
                              pygensio.GENSIO_ACONTROL_SER_STOPBITS,
                              "0")
if rv != 0:
    raise Exception("Error getting stopbits: " + pygensio.err_to_string(rv))
if stopbits != b"1":
    raise Exception("Invalid stopbits: %d" % stopbits)
od = Gen_Control_Done(w)
g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
           pygensio.GENSIO_ACONTROL_SER_STOPBITS,
           "2", od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for stopbits: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching stopbits: " + pygensio.err_to_string(od.err))
if od.val != b"2":
    raise Exception("Invalid stopbits(2): %s" % str(od.val))
del od

(rv, flowcontrol) = g.acontrol_s(0, pygensio.GENSIO_CONTROL_GET,
                                 pygensio.GENSIO_ACONTROL_SER_FLOWCONTROL,
                                 "0")
if rv != 0:
    raise Exception("Error getting flowcontrol: " + pygensio.err_to_string(rv))
if flowcontrol != b"none":
    raise Exception("Invalid flowcontrol: %d" % flowcontrol)
od = Gen_Control_Done(w)
g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
           pygensio.GENSIO_ACONTROL_SER_FLOWCONTROL,
           "xonxoff", od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for flowcontrol: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching flowcontrol: " + pygensio.err_to_string(od.err))
if od.val != b"xonxoff":
    raise Exception("Invalid flowcontrol(2): %s" % str(od.val))
del od

(rv, iflowcontrol) = g.acontrol_s(0, pygensio.GENSIO_CONTROL_GET,
                                  pygensio.GENSIO_ACONTROL_SER_IFLOWCONTROL,
                                  "0")
if rv != 0:
    raise Exception("Error getting iflowcontrol: " + pygensio.err_to_string(rv))
if iflowcontrol != b"dcd":
    raise Exception("Invalid iflowcontrol: %d" % iflowcontrol)
od = Gen_Control_Done(w)
g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
           pygensio.GENSIO_ACONTROL_SER_IFLOWCONTROL,
           "dsr", od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for iflowcontrol: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching iflowcontrol: " + pygensio.err_to_string(od.err))
if od.val != b"dsr":
    raise Exception("Invalid iflowcontrol(2): %s" % str(od.val))
del od

(rv, breakv) = g.acontrol_s(0, pygensio.GENSIO_CONTROL_GET,
                            pygensio.GENSIO_ACONTROL_SER_SBREAK,
                            "0")
if rv != 0:
    raise Exception("Error getting break: " + pygensio.err_to_string(rv))
if breakv != b"off":
    raise Exception("Invalid break: %d" % breakv)
od = Gen_Control_Done(w)
g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
           pygensio.GENSIO_ACONTROL_SER_SBREAK,
           "on", od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for break: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching break: " + pygensio.err_to_string(od.err))
if od.val != b"on":
    raise Exception("Invalid break(2): %s" % str(od.val))
del od

(rv, rts) = g.acontrol_s(0, pygensio.GENSIO_CONTROL_GET,
                          pygensio.GENSIO_ACONTROL_SER_RTS,
                          "0")
if rv != 0:
    raise Exception("Error getting rts: " + pygensio.err_to_string(rv))
if rts != b"off":
    raise Exception("Invalid rts: %d" % rts)
od = Gen_Control_Done(w)
g.acontrol(0, pygensio.GENSIO_CONTROL_SET,
           pygensio.GENSIO_ACONTROL_SER_RTS,
           "on", od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for rts: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching rts: " + pygensio.err_to_string(od.err))
if od.val != b"on":
    raise Exception("Invalid rts(2): %s" % str(od.val))
del od

# No tests for cts, dcd_dsr, ri.  Those require ipmisol

ch = Close_Done(w)
g.close(ch)
rv = w.wait(1, pygensio.gensio_time(1, 0))
del ch
h.g = None
if rv != 0:
    raise Exception("Error waiting for close: " + pygensio.err_to_string(rv))
r.shutdown()
rv = r.wait(pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for acc shutdown: " + pygensio.err_to_string(rv))
del g
del r
del h
del treh
del w

del o

test_shutdown()

print("Pass")
sys.exit(0)
