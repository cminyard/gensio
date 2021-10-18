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

import sys
def do_telnet_test(io1, io2):
    io1.handler.set_expected_modemstate(0)
    io1.read_cb_enable(True);
    sio2 = io2.cast_to_sergensio()
    sio2.sg_modemstate(0);
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for telnet modemstate 1" %
                        ("test open", io1.handler.name))
    do_test(io1, io2)
    sio1 = io1.cast_to_sergensio()
    io1.read_cb_enable(True);
    io2.read_cb_enable(True);

    h = SigRspHandler(o, "testsig")
    io2.handler.set_expected_sig_server_cb("testsig")
    sio1.sg_signature(None, h)
    if (h.wait_timeout(1000) == 0):
        raise Exception("Timeout waiting for signature")

    io2.handler.set_expected_server_cb("baud", 1000, 2000)
    io1.handler.set_expected_client_cb("baud", 2000)
    sio1.sg_baud(1000, io1.handler)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server baud set")
    if io1.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client baud response")

    io2.handler.set_expected_server_cb("datasize", 5, 6)
    io1.handler.set_expected_client_cb("datasize", 6)
    sio1.sg_datasize(5, io1.handler)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server datasize set")
    if io1.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client datasize response")

    io2.handler.set_expected_server_cb("parity", 1, 5)
    io1.handler.set_expected_client_cb("parity", 5)
    sio1.sg_parity(1, io1.handler)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server parity set")
    if io1.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client parity response")

    io2.handler.set_expected_server_cb("stopbits", 2, 1)
    io1.handler.set_expected_client_cb("stopbits", 1)
    sio1.sg_stopbits(2, io1.handler)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server stopbits set")
    if io1.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client stopbits response")

    io2.handler.set_expected_server_cb("flowcontrol", 1, 2)
    io1.handler.set_expected_client_cb("flowcontrol", 2)
    sio1.sg_flowcontrol(1, io1.handler)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server flowcontrol set")
    if io1.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client flowcontrol response")

    io2.handler.set_expected_server_cb("iflowcontrol", 3, 4)
    io1.handler.set_expected_client_cb("iflowcontrol", 4)
    sio1.sg_iflowcontrol(3, io1.handler)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server flowcontrol set")
    if io1.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client flowcontrol response")

    io2.handler.set_expected_server_cb("sbreak", 2, 1)
    io1.handler.set_expected_client_cb("sbreak", 1)
    sio1.sg_sbreak(2, io1.handler)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server sbreak set")
    if io1.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client sbreak response")

    io2.handler.set_expected_server_cb("dtr", 1, 2)
    io1.handler.set_expected_client_cb("dtr", 2)
    sio1.sg_dtr(1, io1.handler)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server dtr set")
    if io1.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client dtr response")

    io2.handler.set_expected_server_cb("rts", 2, 1)
    io1.handler.set_expected_client_cb("rts", 1)
    sio1.sg_rts(2, io1.handler)
    if io2.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for server rts set")
    if io1.handler.wait_timeout(1000) == 0:
        raise Exception("Timeout waiting for client rts response")
    io1.read_cb_enable(False)
    io2.read_cb_enable(False)
    return

print("Test accept telnet")
TestAccept(o, "telnet(rfc2217),tcp,localhost,",
           "telnet(rfc2217=true),tcp,0", do_telnet_test,
           is_sergensio = True)
del o
test_shutdown()
