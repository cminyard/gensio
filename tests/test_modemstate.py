#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
check_pipe_dev()

import gensio
if is_serialsim_pipe():
    from serialsim import *

print("Test modemstates")

io1str = "serialdev," + ttypipe[0] + ",9600N81,LOCAL"
io2str = "serialdev," + ttypipe[1] + ",9600N81,hangup-when-done=off,rts=off,dtr=off"

print("serialdev modemstate:\n  io1=%s\n  io2=%s" % (io1str, io2str))

io1 = alloc_io(o, io1str, do_open = False)
io2 = alloc_io(o, io2str)

# If we have a serialsim serial ports pair, we can do lots of special
# checking for correctness.
def check_serialsim_pipe(io1, io2):
    io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                   gensio.GENSIO_ACONTROL_SER_DTR, "off", -1)
    io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                   gensio.GENSIO_ACONTROL_SER_RTS, "off", -1)
    set_remote_null_modem(remote_id_int(io2), False);
    set_remote_modem_ctl(remote_id_int(io2), (SERIALSIM_TIOCM_CAR |
                                              SERIALSIM_TIOCM_CTS |
                                              SERIALSIM_TIOCM_DSR |
                                              SERIALSIM_TIOCM_RNG) << 16)

    io1.handler.set_expected_modemstate(0)
    io1.open_s()
    io1.read_cb_enable(True);
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 1" %
                        ("test dtr", io1.handler.name))

    io2.read_cb_enable(True);

    io1.handler.set_expected_modemstate(
        gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CD)
    set_remote_modem_ctl(remote_id_int(io2), ((SERIALSIM_TIOCM_CAR << 16) |
                                              SERIALSIM_TIOCM_CAR))
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 2" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(
        gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CD |
        gensio.GENSIO_SER_MODEMSTATE_DSR)
    set_remote_modem_ctl(remote_id_int(io2), ((SERIALSIM_TIOCM_DSR << 16) |
                                              SERIALSIM_TIOCM_DSR))
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 3" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(
        gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CD |
        gensio.GENSIO_SER_MODEMSTATE_DSR |
        gensio.GENSIO_SER_MODEMSTATE_CTS)
    set_remote_modem_ctl(remote_id_int(io2), ((SERIALSIM_TIOCM_CTS << 16) |
                                              SERIALSIM_TIOCM_CTS))
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 4" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(
        gensio.GENSIO_SER_MODEMSTATE_RI_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CD |
        gensio.GENSIO_SER_MODEMSTATE_DSR |
        gensio.GENSIO_SER_MODEMSTATE_CTS |
        gensio.GENSIO_SER_MODEMSTATE_RI)
    set_remote_modem_ctl(remote_id_int(io2), ((SERIALSIM_TIOCM_RNG << 16) |
                                              SERIALSIM_TIOCM_RNG))
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 5" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(
        gensio.GENSIO_SER_MODEMSTATE_RI_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED)
    set_remote_modem_ctl(remote_id_int(io2), (SERIALSIM_TIOCM_CAR |
                                              SERIALSIM_TIOCM_CTS |
                                              SERIALSIM_TIOCM_DSR |
                                              SERIALSIM_TIOCM_RNG) << 16)
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 6" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(
        gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CD |
        gensio.GENSIO_SER_MODEMSTATE_DSR |
        gensio.GENSIO_SER_MODEMSTATE_CTS)
    io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_DTR,
                   "on", -1);
    io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET, gensio.GENSIO_ACONTROL_SER_RTS,
                   "on", -1);
    set_remote_null_modem(remote_id_int(io2), True);
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 7" %
                        ("test dtr", io1.handler.name))
    pass

# Normal NULL modem serial port pair, do what we can.
def check_normal_pipe(io1, io2):
    io1.handler.set_expected_modemstate(0)
    io1.open_s()
    io1.read_cb_enable(True);
    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 1" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(
        gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CD |
        gensio.GENSIO_SER_MODEMSTATE_DSR)

    io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                   gensio.GENSIO_ACONTROL_SER_DTR, "on", -1)

    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 2" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(
        gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CD |
        gensio.GENSIO_SER_MODEMSTATE_DSR |
        gensio.GENSIO_SER_MODEMSTATE_CTS)

    io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                   gensio.GENSIO_ACONTROL_SER_RTS, "on", -1)

    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 3" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(
        gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
        gensio.GENSIO_SER_MODEMSTATE_CTS)

    io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                   gensio.GENSIO_ACONTROL_SER_DTR, "off", -1)

    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 3" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(
        gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED)

    io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                   gensio.GENSIO_ACONTROL_SER_RTS, "off", -1)

    if (io1.handler.wait_timeout(2000) == 0):
        raise Exception("%s: %s: Timed out waiting for modemstate 3" %
                        ("test dtr", io1.handler.name))

    pass

if is_serialsim_pipe():
    check_serialsim_pipe(io1, io2)
else:
    check_normal_pipe(io1, io2)
    pass

io_close((io1, io2))
del io1
del io2
del o
test_shutdown()
print("  Success!")

