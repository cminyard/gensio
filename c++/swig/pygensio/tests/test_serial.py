#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

# Test basic operation, both synchronous and asynchronous open, close,
# and data passing. Also shutdown, enable, and new connections for
# Accepters.

import pygensio
import sys
from testbase import *

# Note that serial_event must be first.
class STelnet_Refl_EvHnd(pygensio.Serial_Event, Refl_EvHnd):
    def __init__(self, w):
        pygensio.Serial_Event.__init__(self)
        Refl_EvHnd.__init__(self, w)
        self.got_break = False
        self.baud_v = 9600
        self.sig_v = bytes("mysig", "utf8")
        self.datasize_v = 8
        self.parity_v = pygensio.SERGENSIO_PARITY_NONE
        self.stopbits_v = 1
        self.flowcontrol_v = pygensio.SERGENSIO_FLOWCONTROL_NONE
        self.iflowcontrol_v = pygensio.SERGENSIO_FLOWCONTROL_DCD
        self.break_v = pygensio.SERGENSIO_BREAK_OFF
        self.rts_v = pygensio.SERGENSIO_RTS_OFF
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
        self.g.baud(self.baud_v, None)
        return

    def datasize(self, size):
        if size != 0:
            self.datasize_v = size
        self.g.datasize(self.datasize_v, None)
        return

    def parity(self, par):
        if par != 0:
            self.parity_v = par
        self.g.parity(self.parity_v, None)
        return

    def stopbits(self, bits):
        if bits != 0:
            self.stopbits_v = bits
        self.g.stopbits(self.stopbits_v, None)
        return

    def flowcontrol(self, flow):
        if flow != 0:
            self.flowcontrol_v = flow
        self.g.flowcontrol(self.flowcontrol_v, None)
        return

    def iflowcontrol(self, flow):
        if flow != 0:
            self.iflowcontrol_v = flow
        self.g.iflowcontrol(self.iflowcontrol_v, None)
        return

    def sbreak(self, val):
        if val != 0:
            self.break_v = val
        self.g.sbreak(self.break_v, None)
        return

    def dtr(self, val):
        if val != 0:
            self.dtr_v = val
        self.g.dtr(self.dtr_v, None)
        return

    def rts(self, val):
        if val != 0:
            self.rts_v = val
        self.g.rts(self.rts_v, None)
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

class Ser_Op_Sig_Done(pygensio.Serial_Op_Sig_Done):
    def __init__(self, w):
        pygensio.Serial_Op_Sig_Done.__init__(self)
        self.w = w
        return

    def serial_op_sig_done(self, err, sig):
        self.err = err
        self.sig = sig
        self.w.wake()
        return

w = pygensio.Waiter(o)
treh = STelnet_Refl_EvHnd(w)
r = Reflector(o, "telnet(rfc2217),tcp,0", w = w, evh = treh)
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
sg = pygensio.cast_to_serial_gensio(g)

od = Ser_Op_Sig_Done(w)
sg.signature(bytes("", "utf8"), od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for sig: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching sig: " + pygensio.err_to_string(od.err))
if od.sig != bytes("mysig", "utf8"):
    raise Exception("Invalid sig: %s" % str(od.sig, "utf8"))
del od

sg.flush(pygensio.SERGENSIO_FLUSH_RCV_BUFFER)

(rv, baud) = sg.baud_s(0)
if rv != 0:
    raise Exception("Error getting baud: " + pygensio.err_to_string(rv))
if baud != 9600:
    raise Exception("Invalid baud: %d" % baud)
od = Ser_Op_Done(w)
sg.baud(19200, od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for baud: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching baud: " + pygensio.err_to_string(od.err))
if od.val != 19200:
    raise Exception("Invalid baud(2): %d" % od.val)
del od

(rv, datasize) = sg.datasize_s(0)
if rv != 0:
    raise Exception("Error getting datasize: " + pygensio.err_to_string(rv))
if datasize != 8:
    raise Exception("Invalid datasize: %d" % datasize)
od = Ser_Op_Done(w)
sg.datasize(7, od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for datasize: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching datasize: " + pygensio.err_to_string(od.err))
if od.val != 7:
    raise Exception("Invalid datasize(2): %d" % od.val)
del od

(rv, parity) = sg.parity_s(0)
if rv != 0:
    raise Exception("Error getting parity: " + pygensio.err_to_string(rv))
if parity != pygensio.SERGENSIO_PARITY_NONE:
    raise Exception("Invalid parity: %d" % parity)
od = Ser_Op_Done(w)
sg.parity(pygensio.SERGENSIO_PARITY_ODD, od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for parity: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching parity: " + pygensio.err_to_string(od.err))
if od.val != pygensio.SERGENSIO_PARITY_ODD:
    raise Exception("Invalid parity(2): %d" % od.val)
del od

(rv, stopbits) = sg.stopbits_s(0)
if rv != 0:
    raise Exception("Error getting stopbits: " + pygensio.err_to_string(rv))
if stopbits != 1:
    raise Exception("Invalid stopbits: %d" % stopbits)
od = Ser_Op_Done(w)
sg.stopbits(2, od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for stopbits: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching stopbits: " + pygensio.err_to_string(od.err))
if od.val != 2:
    raise Exception("Invalid stopbits(2): %d" % od.val)
del od

(rv, flowcontrol) = sg.flowcontrol_s(0)
if rv != 0:
    raise Exception("Error getting flowcontrol: " + pygensio.err_to_string(rv))
if flowcontrol != pygensio.SERGENSIO_FLOWCONTROL_NONE:
    raise Exception("Invalid flowcontrol: %d" % flowcontrol)
od = Ser_Op_Done(w)
sg.flowcontrol(pygensio.SERGENSIO_FLOWCONTROL_XON_XOFF, od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for flowcontrol: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching flowcontrol: " + pygensio.err_to_string(od.err))
if od.val != pygensio.SERGENSIO_FLOWCONTROL_XON_XOFF:
    raise Exception("Invalid flowcontrol(2): %d" % od.val)
del od

(rv, iflowcontrol) = sg.iflowcontrol_s(0)
if rv != 0:
    raise Exception("Error getting iflowcontrol: " + pygensio.err_to_string(rv))
if iflowcontrol != pygensio.SERGENSIO_FLOWCONTROL_DCD:
    raise Exception("Invalid iflowcontrol: %d" % iflowcontrol)
od = Ser_Op_Done(w)
sg.iflowcontrol(pygensio.SERGENSIO_FLOWCONTROL_DSR, od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for iflowcontrol: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching iflowcontrol: " + pygensio.err_to_string(od.err))
if od.val != pygensio.SERGENSIO_FLOWCONTROL_DSR:
    raise Exception("Invalid iflowcontrol(2): %d" % od.val)
del od

(rv, breakv) = sg.sbreak_s(0)
if rv != 0:
    raise Exception("Error getting break: " + pygensio.err_to_string(rv))
if breakv != pygensio.SERGENSIO_BREAK_OFF:
    raise Exception("Invalid break: %d" % breakv)
od = Ser_Op_Done(w)
sg.sbreak(pygensio.SERGENSIO_BREAK_ON, od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for break: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching break: " + pygensio.err_to_string(od.err))
if od.val != pygensio.SERGENSIO_BREAK_ON:
    raise Exception("Invalid break(2): %d" % od.val)
del od

(rv, rts) = sg.rts_s(0)
if rv != 0:
    raise Exception("Error getting rts: " + pygensio.err_to_string(rv))
if rts != pygensio.SERGENSIO_RTS_OFF:
    raise Exception("Invalid rts: %d" % rts)
od = Ser_Op_Done(w)
sg.rts(pygensio.SERGENSIO_RTS_ON, od)
rv = w.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for rts: " + pygensio.err_to_string(rv))
if od.err != 0:
    raise Exception("Error fetching rts: " + pygensio.err_to_string(od.err))
if od.val != pygensio.SERGENSIO_RTS_ON:
    raise Exception("Invalid rts(2): %d" % od.val)
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
del sg
del r
del h
del treh
del w

del o

test_shutdown()

print("Pass")
sys.exit(0)
