#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

import sys
from utils import *
import gensio
import ipmisimdaemon
try:
    import termios
    from termioschk import *
    from serialsim import *
except:
    sys.exit(77)

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

gensios_enabled.check_iostr_gensios("ipmisol")

s2n_termios_base = dup_termios(base_termios,
                               cflags = termios.CLOCAL,
                               cflags_mask = termios.CLOCAL)
s2n_termios_base[6][termios.VSTART] = '\0'
s2n_termios_base[6][termios.VSTOP] = '\0'


def check_baud_set(speed, bspeed):
    t = dup_termios(s2n_termios_base, cflags = bspeed,
                    cflags_mask = termios.CBAUD)
    t[4] = bspeed
    t[5] = bspeed

    isim = ipmisimdaemon.IPMISimDaemon(o, ttypipe[1])
    io1 = alloc_io(o, "serialdev," + ttypipe[0] + ",%d" % speed)
    io2 = alloc_io(o, "ipmisol,lan -U ipmiusr -P test -p %d localhost,%d" %
                   (isim.port, speed))

    io1_r_termios = get_remote_termios(utils.remote_id_int(io1))
    c = compare_termios(t, io1_r_termios)
    if c != -1:
        raise Exception("Termios failure on baud %d" % speed)
    io1_r_termios = get_remote_termios(utils.remote_id_int(io1))
    c = compare_termios(t, io1_r_termios);
    if c != -1:
        raise Exception("Termios %d failure on item %d" % (speed, c))
    utils.io_close((io1, io2))
    isim.terminate()

check_pipe_dev()

print("Test ipmisol operations")

print("Testing baud rates")
check_baud_set(9600, termios.B9600)
check_baud_set(19200, termios.B19200)
check_baud_set(38400, termios.B38400)
check_baud_set(57600, termios.B57600)
check_baud_set(115200, termios.B115200)

# NOTE: Previous runs of ipmi_sim should have left CTS and DCD/DSR off.
# We rely on that here.
io1 = alloc_io(o, "serialdev," + ttypipe[0] + ",9600,LOCAL")
isim = ipmisimdaemon.IPMISimDaemon(o, ttypipe[1])
io1.handler.set_expected_modemstate(gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_CTS |
                                    gensio.GENSIO_SER_MODEMSTATE_CD |
                                    gensio.GENSIO_SER_MODEMSTATE_DSR)
io2 = alloc_io(o, "ipmisol,lan -U ipmiusr -P test -p %d localhost,9600" %
               isim.port)
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("Timed out waiting for initial modemstate")
io1_fd = utils.remote_id_int(io1)

print("Testing break")
# Set up to receive breaks as 0xff, 0, 0 char sequence.
t = termios.tcgetattr(io1_fd)
t = dup_termios(t, iflags = termios.PARMRK,
                iflags_mask = termios.IGNBRK | termios.BRKINT)
termios.tcsetattr(io1_fd, termios.TCSANOW, t)

io1.handler.set_compare(b"\377\0\0")
io2.control(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_CONTROL_SER_SEND_BREAK,
            "")
if (io1.handler.wait_timeout(1000) == 0):
    raise Exception("Timed out waiting for break receive")

print("Testing flush")
# Flush is hard to test, just make sure it doesn't crash.
io2.control_set(0, gensio.GENSIO_CONTROL_SER_FLUSH, "recv")
io2.control_set(0, gensio.GENSIO_CONTROL_SER_FLUSH, "xmit")

print("Testing CTS")
h = CtrlRspHandler(o, "off")
io1.handler.set_expected_modemstate(gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_CD |
                                    gensio.GENSIO_SER_MODEMSTATE_DSR)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_CTS,
             "off", h, -1)
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("Timed out waiting for CTS off indicator")
if (h.wait_timeout(2000) == 0):
    raise Exception("Timed out waiting for CTS off response")

h = CtrlRspHandler(o, "auto")
io1.handler.set_expected_modemstate(gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_CTS |
                                    gensio.GENSIO_SER_MODEMSTATE_CD |
                                    gensio.GENSIO_SER_MODEMSTATE_DSR)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_CTS,
             "auto", h, -1)
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("Timed out waiting for CTS on indicator")
if (h.wait_timeout(2000) == 0):
    raise Exception("Timed out waiting for CTS off response")

print("Testing DCD/DSR")
io1.handler.set_expected_modemstate(gensio.GENSIO_SER_MODEMSTATE_CTS |
                                    gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_DCD_DSR,
             "off", None, -1)
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR off indicator")
io1.handler.set_expected_modemstate(gensio.GENSIO_SER_MODEMSTATE_CTS |
                                    gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_CD |
                                    gensio.GENSIO_SER_MODEMSTATE_DSR)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_DCD_DSR,
             "on", None, -1)
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR on indicator")

# No easy way to test ring.

io_close((io1, io2))
isim.terminate()

print("Testing deassertion of CTS, DCD, and DSR at start");
io1 = alloc_io(o, "serialdev," + ttypipe[0] + ",9600,LOCAL")
io1.handler.set_expected_modemstate(0)
isim = ipmisimdaemon.IPMISimDaemon(o, ttypipe[1])
io2 = alloc_io(o, "ipmisol(),lan -U ipmiusr -P test -p %d localhost,9600,deassert-CTS-DCD-DSR-on-connect" % isim.port)
io1.control(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_CONTROL_SER_MODEMSTATE,
            str(gensio.GENSIO_SER_MODEMSTATE_CTS |
                gensio.GENSIO_SER_MODEMSTATE_CD |
                gensio.GENSIO_SER_MODEMSTATE_DSR |
                gensio.GENSIO_SER_MODEMSTATE_RI))
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR/CTS off")

io1.handler.set_expected_modemstate(gensio.GENSIO_SER_MODEMSTATE_CTS |
                                    gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_CD |
                                    gensio.GENSIO_SER_MODEMSTATE_DSR)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_DCD_DSR,
             "on", None, -1)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_CTS,
             "auto", None, -1)
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR/CTS on")

print("Testing modemstate callbacks");
h = CtrlRspHandler(o, "off")
io1.handler.set_expected_modemstate(gensio.GENSIO_SER_MODEMSTATE_CTS |
                                    gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
                                    gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_DCD_DSR,
             "off", h, -1)
if h.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting 1")
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR off")

print("Testing multiple pending operations");
h1 = CtrlRspHandler(o, "on")
h2 = CtrlRspHandler(o, "off")
io1.handler.set_expected_modemstate(gensio.GENSIO_SER_MODEMSTATE_CTS)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_DCD_DSR,
             "on", h1, -1)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_DCD_DSR,
             "off", h2, -1)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_DCD_DSR,
             "on", h1, -1)
io2.acontrol(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_DCD_DSR,
             "off", h2, -1)
if h1.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting 1")
if h2.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting 2")
if h1.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting 3")
if h2.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting 4")
del h1
del h2
io1.control(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_CONTROL_SER_MODEMSTATE,
            str(gensio.GENSIO_SER_MODEMSTATE_CTS |
                gensio.GENSIO_SER_MODEMSTATE_CD |
                gensio.GENSIO_SER_MODEMSTATE_DSR |
                gensio.GENSIO_SER_MODEMSTATE_RI))
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR on")

io_close((io1, io2))
del io1
del io2
del h
isim.terminate()
del isim
del o
test_shutdown()
print("Success!")
