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
    io2 = alloc_io(o, "ipmisol,lan -U ipmiusr -P test -p 9001 localhost,%d" %
                   speed)
    sio2 = io2.cast_to_sergensio()

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
io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CTS |
                                    gensio.SERGENSIO_MODEMSTATE_CD |
                                    gensio.SERGENSIO_MODEMSTATE_DSR)
io2 = alloc_io(o, "ipmisol,lan -U ipmiusr -P test -p 9001 localhost,9600")
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("Timed out waiting for initial modemstate")
sio1 = io1.cast_to_sergensio()
sio2 = io2.cast_to_sergensio()
io1_fd = utils.remote_id_int(io1)

print("Testing break")
# Set up to receive breaks as 0xff, 0, 0 char sequence.
t = termios.tcgetattr(io1_fd)
t = dup_termios(t, iflags = termios.PARMRK,
                iflags_mask = termios.IGNBRK | termios.BRKINT)
termios.tcsetattr(io1_fd, termios.TCSANOW, t)

io1.handler.set_compare(b"\377\0\0")
sio2.sg_send_break()
if (io1.handler.wait_timeout(1000) == 0):
    raise Exception("Timed out waiting for break receive")

print("Testing flush")
# Flush is hard to test, just make sure it doesn't crash.
sio2.sg_flush(gensio.SERGENSIO_FLUSH_RCV_BUFFER)
sio2.sg_flush(gensio.SERGENSIO_FLUSH_XMIT_BUFFER)

print("Testing CTS")
io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD |
                                    gensio.SERGENSIO_MODEMSTATE_DSR)
sio2.sg_cts(gensio.SERGENSIO_CTS_OFF, None)
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("Timed out waiting for CTS off indicator")
io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CTS |
                                    gensio.SERGENSIO_MODEMSTATE_CD |
                                    gensio.SERGENSIO_MODEMSTATE_DSR)
sio2.sg_cts(gensio.SERGENSIO_CTS_AUTO, None)
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("Timed out waiting for CTS on indicator")

print("Testing DCD/DSR")
io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS |
                                    gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED)
sio2.sg_dcd_dsr(gensio.SERGENSIO_DCD_DSR_OFF, None)
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR off indicator")
io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS |
                                    gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD |
                                    gensio.SERGENSIO_MODEMSTATE_DSR)
sio2.sg_dcd_dsr(gensio.SERGENSIO_DCD_DSR_ON, None)
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR on indicator")

# No easy way to test ring.

io_close((io1, io2))
isim.terminate()

print("Testing deassertion of CTS, DCD, and DSR at start");
io1 = alloc_io(o, "serialdev," + ttypipe[0] + ",9600,LOCAL")
sio1 = io1.cast_to_sergensio()
io1.handler.set_expected_modemstate(0)
isim = ipmisimdaemon.IPMISimDaemon(o, ttypipe[1])
io2 = alloc_io(o, "ipmisol(),lan -U ipmiusr -P test -p 9001 localhost,9600,deassert-CTS-DCD-DSR-on-connect")
sio2 = io2.cast_to_sergensio()
sio1.sg_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS |
                   gensio.SERGENSIO_MODEMSTATE_CD |
                   gensio.SERGENSIO_MODEMSTATE_DSR |
                   gensio.SERGENSIO_MODEMSTATE_RI)
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR/CTS off")

io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS |
                                    gensio.SERGENSIO_MODEMSTATE_CTS_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD |
                                    gensio.SERGENSIO_MODEMSTATE_DSR)
sio2.sg_dcd_dsr(gensio.SERGENSIO_DCD_DSR_ON, None)
sio2.sg_cts(gensio.SERGENSIO_CTS_AUTO, None)
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR/CTS on")

print("Testing modemstate callbacks");
class sg_cb_handler:
    def __init__(self, o):
        self.waiter = gensio.waiter(o)

    def wait_timeout(self, timeout):
        return self.waiter.wait_timeout(1, timeout)

    def dcd_dsr(self, sg, err, val):
        self.waiter.wake()

h = sg_cb_handler(o)
io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS |
                                    gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED)
sio2.sg_dcd_dsr(gensio.SERGENSIO_DCD_DSR_OFF, h)
if h.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting 1")
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR off")

print("Testing multiple pending operations");
io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS)
sio2.sg_dcd_dsr(gensio.SERGENSIO_DCD_DSR_ON, h)
sio2.sg_dcd_dsr(gensio.SERGENSIO_DCD_DSR_OFF, h)
sio2.sg_dcd_dsr(gensio.SERGENSIO_DCD_DSR_ON, h)
sio2.sg_dcd_dsr(gensio.SERGENSIO_DCD_DSR_OFF, h)
if h.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting 1")
if h.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting 2")
if h.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting 3")
if h.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting 4")
sio1.sg_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS |
                   gensio.SERGENSIO_MODEMSTATE_CD |
                   gensio.SERGENSIO_MODEMSTATE_DSR |
                   gensio.SERGENSIO_MODEMSTATE_RI)
if (io1.handler.wait_timeout(3000) == 0):
    raise Exception("Timed out waiting for DCD/DSR on")

io_close((io1, io2))
del io1
del io2
del sio1
del sio2
del h
isim.terminate()
del isim
del o
test_shutdown()
print("Success!")
