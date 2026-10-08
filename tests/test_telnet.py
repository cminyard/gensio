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
                gensio.GENSIO_CONTROL_SER_SEND_MODEMSTATE, "0")
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for telnet modemstate 1" %
                        ("test open", io1.handler.name))
    do_test(io1, io2)
    io1.read_cb_enable(True);
    io2.read_cb_enable(True);

    io2.handler.set_expected_modemstate_mask(3)
    h = SigRspHandler(o, "3")
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_SET_MODEMSTATE_MASK, "3",
                 h, -1)
    if (io2.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for telnet modemstate 2" %
                        ("test open", io1.handler.name))
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client telnet modemstate rsp")

    io2.handler.set_expected_linestate_mask(7)
    h = SigRspHandler(o, "7")
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_SET_LINESTATE_MASK, "7",
                 h, -1)
    if (io2.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for telnet linestate 2" %
                        ("test open", io1.handler.name))
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client telnet linestate rsp")

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

    h = CtrlRspHandler(o, "both")
    io2.handler.set_expected_server_cb("flush",
                                       gensio.GENSIO_SER_FLUSH_BOTH,
                                       "both")
    io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                 gensio.GENSIO_ACONTROL_SER_FLUSH,
                 "both", h, -1)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server flush set")
    if h.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client flush response")

    io1.read_cb_enable(False)
    io2.read_cb_enable(False)
    return

print("Test accept telnet")
TestAccept(o, "telnet(rfc2217,winsize),tcp,localhost,",
           "telnet(rfc2217=true,winsize),tcp,localhost,0", do_telnet_test)

class SerialparmOpen:
    def __init__(self, o):
        self.err = None
        self.waiter = gensio.waiter(o)
        return

    def open_done(self, io, err):
        self.err = err
        self.waiter.wake()
        return

    def wait_timeout(self, timeout):
        return self.waiter.wait_timeout(1, timeout)

    pass

def do_telnet_serialparm_test(o, acc, parms):
    try:
        io1 = acc.io1
        open_done = SerialparmOpen(o)
        io1.open(open_done)

        # Wait for the open to come in for io2
        if (acc.wait_timeout(2000) == 0):
            raise Exception(("%s: %s: " % ("serialparm_test",
                                           acc.name)) +
                            ("Timed out waiting for io2 open"))
        io2 = acc.io2

        # Set what parms we expect to receive.
        for i in parms:
            io2.handler.set_expected_server_cb(i[0], i[1], i[2])
            pass

        # Modemstate must be done to make the protocol happy.
        io2.handler.set_expected_modemstate_mask(0xff)
        io1.handler.set_expected_modemstate(0)
        io1.read_cb_enable(True);
        io2.read_cb_enable(True);

        io2.control(0, gensio.GENSIO_CONTROL_SET,
                    gensio.GENSIO_CONTROL_SER_SEND_MODEMSTATE, "0")
        if (io1.handler.wait_timeout(2000) == 0):
            raise Exception("%s: %s: Timed out waiting for telnet modemstate 1" %
                            ("test open", io1.handler.name))

        # Wait for io1 to finish opening
        if open_done.wait_timeout(2000) == 0:
            raise Exception(("%s: %s: " % ("serialparm_test",
                                           io2.handler.name)) +
                            ("Timed out waiting for io1 open"))

        if open_done.err != None:
            # The io is not open, so just kill it here so the acc close
            # doesn't try to close it.
            io1.handler.io = None
            io1.handler = None
            raise Exception(("%s: %s: " % ("serialparm_test",
                                           acc.name)) +
                            ("io1 open failed: %s" % open_done.err))

        # Make sure we got all the callbacks
        if io2.handler.expected_cb:
            raise Exception(("%s: %s: " % ("serialparm_test",
                                           acc.name)) +
                            ("Not all callbacks called: %s"
                             % str(io2.handler.expected_cb)))
        print("  Success")
    finally:
        acc.close()
        pass
    return

#import utils
#utils.debug = True

print("Test accept telnet serial parms 9600n81")
acc = TestAccept(o, "telnet(rfc2217,9600n81),tcp,localhost,",
                 "telnet(rfc2217=true),tcp,localhost,0", None,
                 return_before_io1_open = True)
do_telnet_serialparm_test(o, acc,
                          (("baud", 9600, 9600),
                           ("datasize", 8, 8),
                           ("parity", 1, "none"),
                           ("stopbits", 1, 1)))

print("Test accept telnet serial parms 2400o72")
acc = TestAccept(o, "telnet(rfc2217,speed=2400o72),tcp,localhost,",
                 "telnet(rfc2217=true),tcp,localhost,0", None,
                 return_before_io1_open = True)
do_telnet_serialparm_test(o, acc,
                          (("baud", 2400, 2400),
                           ("datasize", 7, 7),
                           ("parity", 2, "odd"),
                           ("stopbits", 2, 2)))

print("Test accept telnet serial parms 1000e52,noflow,dtr=on,rts=off")
acc = TestAccept(o, "telnet(rfc2217,1000e52,noflow,dtr=on,rts=off),tcp,localhost,",
                 "telnet(rfc2217=true),tcp,localhost,0", None,
                 return_before_io1_open = True)
do_telnet_serialparm_test(o, acc,
                          (("baud", 1000, 1000),
                           ("datasize", 5, 5),
                           ("parity", 3, "even"),
                           ("stopbits", 2, 2),
                           ("flowcontrol", 1, "none"),
                           ("dtr", 1, "on"),
                           ("rts", 2, "off")))

print("Test accept telnet serial parms ")
acc = TestAccept(o, "telnet(rfc2217,115200m62,xonxoff,dtr=off,rts=on),tcp,localhost,",
                 "telnet(rfc2217=true),tcp,localhost,0", None,
                 return_before_io1_open = True)
do_telnet_serialparm_test(o, acc,
                          (("baud", 115200, 115200),
                           ("datasize", 6, 6),
                           ("parity", 4, "mark"),
                           ("stopbits", 2, 2),
                           ("flowcontrol", 2, "xonxoff"),
                           ("dtr", 2, "off"),
                           ("rts", 1, "on")))

print("Test accept telnet serial parms ")
acc = TestAccept(o, "telnet(rfc2217,200000s61,rtscts),tcp,localhost,",
                 "telnet(rfc2217=true),tcp,localhost,0", None,
                 return_before_io1_open = True)
do_telnet_serialparm_test(o, acc,
                          (("baud", 200000, 200000),
                           ("datasize", 6, 6),
                           ("parity", 5, "space"),
                           ("stopbits", 1, 1),
                           ("flowcontrol", 3, "rtscts")))

print("Test accept telnet serial parms baud returns wrong")
try:
    acc = TestAccept(o, "telnet(rfc2217,200000s61,rtscts),tcp,localhost,",
                     "telnet(rfc2217=true),tcp,localhost,0", None,
                     return_before_io1_open = True)
    do_telnet_serialparm_test(o, acc,
                              (("baud", 200000, 115200),
                               ("datasize", 6, 6),
                               ("parity", 5, "space"),
                               ("stopbits", 1, 1),
                               ("flowcontrol", 3, "rtscts")))
except Exception as e:
    if str(e) != "serialparm_test: telnet(rfc2217=true),tcp,localhost,0: io1 open failed: Operation not supported":
        raise Exception("Unexpected exception: '%s'" % str(e))
    pass
print("  Success")

print("Test accept telnet serial parms datasize returns wrong")
try:
    acc = TestAccept(o, "telnet(rfc2217,200000s61,rtscts),tcp,localhost,",
                     "telnet(rfc2217=true),tcp,localhost,0", None,
                     return_before_io1_open = True)
    do_telnet_serialparm_test(o, acc,
                              (("baud", 200000, 200000),
                               ("datasize", 6, 7),
                               ("parity", 5, "space"),
                               ("stopbits", 1, 1),
                               ("flowcontrol", 3, "rtscts")))
except Exception as e:
    if str(e) != "serialparm_test: telnet(rfc2217=true),tcp,localhost,0: io1 open failed: Operation not supported":
        raise Exception("Unexpected exception: '%s'" % str(e))
    pass
print("  Success")

print("Test invalid telnet serial parms")
try:
    acc = TestAccept(o, "telnet(rfc2217,s61,rtscts),tcp,localhost,",
                     "telnet(rfc2217=true),tcp,localhost,0", None,
                     return_before_io1_open = True)
    do_telnet_serialparm_test(o, acc,
                              (("baud", 200000, 200000),
                               ("datasize", 6, 7),
                               ("parity", 5, "space"),
                               ("stopbits", 1, 1),
                               ("flowcontrol", 3, "rtscts")))
except Exception as e:
    if str(e) != "gensio:gensio alloc: Invalid data to parameter":
        raise Exception("Unexpected exception: '%s'" % str(e))
    pass
try:
    acc = TestAccept(o, "telnet(rfc2217,0s61,rtscts),tcp,localhost,",
                     "telnet(rfc2217=true),tcp,localhost,0", None,
                     return_before_io1_open = True)
    do_telnet_serialparm_test(o, acc,
                              (("baud", 200000, 200000),
                               ("datasize", 6, 7),
                               ("parity", 5, "space"),
                               ("stopbits", 1, 1),
                               ("flowcontrol", 3, "rtscts")))
except Exception as e:
    if str(e) != "gensio:gensio alloc: Invalid data to parameter":
        raise Exception("Unexpected exception: '%s'" % str(e))
    pass
try:
    acc = TestAccept(o, "telnet(rfc2217,-1s61,rtscts),tcp,localhost,",
                     "telnet(rfc2217=true),tcp,localhost,0", None,
                     return_before_io1_open = True)
    do_telnet_serialparm_test(o, acc,
                              (("baud", 200000, 200000),
                               ("datasize", 6, 7),
                               ("parity", 5, "space"),
                               ("stopbits", 1, 1),
                               ("flowcontrol", 3, "rtscts")))
except Exception as e:
    if str(e) != "gensio:gensio alloc: Invalid data to parameter":
        raise Exception("Unexpected exception: '%s'" % str(e))
    pass
try:
    acc = TestAccept(o, "telnet(rfc2217,2147483648s61,rtscts),tcp,localhost,",
                     "telnet(rfc2217=true),tcp,localhost,0", None,
                     return_before_io1_open = True)
    do_telnet_serialparm_test(o, acc,
                              (("baud", 200000, 200000),
                               ("datasize", 6, 7),
                               ("parity", 5, "space"),
                               ("stopbits", 1, 1),
                               ("flowcontrol", 3, "rtscts")))
except Exception as e:
    if str(e) != "gensio:gensio alloc: Invalid data to parameter":
        raise Exception("Unexpected exception: '%s'" % str(e))
    pass
acc = TestAccept(o, "telnet(rfc2217,2147483647s61,rtscts),tcp,localhost,",
                 "telnet(rfc2217=true),tcp,localhost,0", None,
                 return_before_io1_open = True)
do_telnet_serialparm_test(o, acc,
                          (("baud", 2147483647, 2147483647),
                           ("datasize", 6, 6),
                           ("parity", 5, "space"),
                           ("stopbits", 1, 1),
                           ("flowcontrol", 3, "rtscts")))

del acc

del o
test_shutdown()
