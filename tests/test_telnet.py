#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

class SigRspHandler:
    def __init__(self, o, sigval):
        self.sigval = sigval
        self.waiter = gensio.waiter(o)
        return

    def control_done(self, io, err, value):
        if (err):
            raise Exception("Error getting signature: %s" % err)
        value = value.decode(encoding='utf-8')
        if (value != self.sigval):
            raise Exception("Signature value was '%s', expected '%s'" %
                            (value, self.sigval))
        self.waiter.wake();
        return

    def signature(self, sio, err, value):
        if (err):
            raise Exception("Error getting signature: %s" % err)
        value = value.decode(encoding='utf-8')
        if (value != self.sigval):
            raise Exception("Signature value was '%s', expected '%s'" %
                            (value, self.sigval))
        self.waiter.wake();
        return

    def wait_timeout(self, timeout):
        return self.waiter.wait_timeout(1, timeout)

class CtrlRspHandler:
    def __init__(self, o, val):
        self.val = val
        self.waiter = gensio.waiter(o)
        return

    def control_done(self, io, err, value):
        if (err):
            raise Exception("Error getting signature: %s" % err)
        value = value.decode(encoding='utf-8')
        if (value != str(self.val)):
            raise Exception("Value was '%s', expected '%s'" %
                            (value, self.val))
        self.waiter.wake();
        return

    def wait_timeout(self, timeout):
        return self.waiter.wait_timeout(1, timeout)

import sys
def do_telnet_test(io1, io2):
    # Modemstate must be the first test
    io1.handler.set_expected_modemstate(0)
    io1.read_cb_enable(True);

    io2.control(0, gensio.GENSIO_CONTROL_SET,
                gensio.GENSIO_CONTROL_SER_MODEMSTATE, "0")
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for telnet modemstate 1" %
                        ("test open", io1.handler.name))
    do_test(io1, io2)
    io1.read_cb_enable(True);
    io2.read_cb_enable(True);

    io2.handler.set_expected_win_size(12, 83)
    io1.control(0, False, gensio.GENSIO_CONTROL_WIN_SIZE, "12:83");
    if (io2.handler.wait_timeout(2000) == 0):
        raise Exception("%s: Timed out waiting for telnet win size" %
                        io1.handler.name)

    h = SigRspHandler(o, "testsig")
    io2.handler.set_expected_sig_server_cb("testsig")
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_SIGNATURE, "testsig", h, -1)
    if (h.wait_timeout(1000) == 0):
        raise Exception("Timeout waiting for signature")

    h = CtrlRspHandler(o, 2000)
    io2.handler.set_expected_server_cb("baud", 1000, 2000)
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_BAUD,
                 "1000", h, -1)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server baud set")
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client baud response")

    h = CtrlRspHandler(o, 6)
    io2.handler.set_expected_server_cb("datasize", 5, 6)
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_DATASIZE,
                 "5", h, -1)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server datasize set")
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client datasize response")

    h = CtrlRspHandler(o, "space")
    io2.handler.set_expected_server_cb("parity", gensio.GENSIO_SER_PARITY_NONE,
                                       "space")
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_PARITY,
                 "none", h, -1)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server parity set")
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client parity response")

    h = CtrlRspHandler(o, 1)
    io2.handler.set_expected_server_cb("stopbits", 2, 1)
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_STOPBITS,
                 "2", h, -1)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server stopbits set")
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client stopbits response")

    h = CtrlRspHandler(o, "xonxoff")
    io2.handler.set_expected_server_cb("flowcontrol",
                                       gensio.GENSIO_SER_FLOWCONTROL_NONE,
                                       "xonxoff")
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_FLOWCONTROL,
                 "none", h, -1)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server flowcontrol set")
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client flowcontrol response")

    h = CtrlRspHandler(o, "dsr")
    io2.handler.set_expected_server_cb("iflowcontrol",
                                       gensio.GENSIO_SER_FLOWCONTROL_DCD,
                                       "dsr")
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_IFLOWCONTROL,
                 "dcd", h, -1)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server flowcontrol set")
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client flowcontrol response")

    h = CtrlRspHandler(o, "off")
    io2.handler.set_expected_server_cb("sbreak",
                                       gensio.GENSIO_SER_ON,
                                       "off")
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_SBREAK,
                 "on", h, -1)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server sbreak set")
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client sbreak response")

    h = CtrlRspHandler(o, "on")
    io2.handler.set_expected_server_cb("dtr",
                                       gensio.GENSIO_SER_OFF,
                                       "on")
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_DTR,
                 "off", h, -1)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server dtr set")
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client dtr response")

    h = CtrlRspHandler(o, "on")
    io2.handler.set_expected_server_cb("rts",
                                       gensio.GENSIO_SER_OFF,
                                       "on")
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_RTS,
                 "off", h, -1)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server rts set")
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client rts response")
    io1.read_cb_enable(False)
    io2.read_cb_enable(False)
    return

print("Test accept telnet")
TestAccept(o, "telnet(rfc2217,winsize),tcp,localhost,",
           "telnet(rfc2217=true,winsize),tcp,localhost,0", do_telnet_test)
del o
test_shutdown()
