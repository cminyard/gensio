#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
check_pipe_dev(is_serialsim = True)

import gensio
from serialsim import *

print("Test modemstates")

io1str = "serialdev," + ttypipe[0] + ",9600N81,LOCAL"
io2str = "serialdev," + ttypipe[1] + ",9600N81"

print("serialdev modemstate:\n  io1=%s\n  io2=%s" % (io1str, io2str))

io1 = alloc_io(o, io1str, do_open = False)
io2 = alloc_io(o, io2str)
sio2 = io2.cast_to_sergensio();

sio2.sg_dtr_s(gensio.SERGENSIO_DTR_OFF);
sio2.sg_rts_s(gensio.SERGENSIO_RTS_OFF);
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

io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD)
set_remote_modem_ctl(remote_id_int(io2), ((SERIALSIM_TIOCM_CAR << 16) |
                                       SERIALSIM_TIOCM_CAR))
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("%s: %s: Timed out waiting for modemstate 2" %
                    ("test dtr", io1.handler.name))

io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD |
                                    gensio.SERGENSIO_MODEMSTATE_DSR)
set_remote_modem_ctl(remote_id_int(io2), ((SERIALSIM_TIOCM_DSR << 16) |
                                       SERIALSIM_TIOCM_DSR))
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("%s: %s: Timed out waiting for modemstate 3" %
                    ("test dtr", io1.handler.name))

io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD |
                                    gensio.SERGENSIO_MODEMSTATE_DSR |
                                    gensio.SERGENSIO_MODEMSTATE_CTS)
set_remote_modem_ctl(remote_id_int(io2), ((SERIALSIM_TIOCM_CTS << 16) |
                                       SERIALSIM_TIOCM_CTS))
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("%s: %s: Timed out waiting for modemstate 4" %
                    ("test dtr", io1.handler.name))

io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_RI_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD |
                                    gensio.SERGENSIO_MODEMSTATE_DSR |
                                    gensio.SERGENSIO_MODEMSTATE_CTS |
                                    gensio.SERGENSIO_MODEMSTATE_RI)
set_remote_modem_ctl(remote_id_int(io2), ((SERIALSIM_TIOCM_RNG << 16) |
                                       SERIALSIM_TIOCM_RNG))
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("%s: %s: Timed out waiting for modemstate 5" %
                    ("test dtr", io1.handler.name))

io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_RI_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CTS_CHANGED)
set_remote_modem_ctl(remote_id_int(io2), (SERIALSIM_TIOCM_CAR |
                                       SERIALSIM_TIOCM_CTS |
                                       SERIALSIM_TIOCM_DSR |
                                       SERIALSIM_TIOCM_RNG) << 16)
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("%s: %s: Timed out waiting for modemstate 6" %
                    ("test dtr", io1.handler.name))

io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CTS_CHANGED |
                                    gensio.SERGENSIO_MODEMSTATE_CD |
                                    gensio.SERGENSIO_MODEMSTATE_DSR |
                                    gensio.SERGENSIO_MODEMSTATE_CTS)
sio2.sg_dtr_s(gensio.SERGENSIO_DTR_ON);
sio2.sg_rts_s(gensio.SERGENSIO_RTS_ON);
set_remote_null_modem(remote_id_int(io2), True);
if (io1.handler.wait_timeout(2000) == 0):
    raise Exception("%s: %s: Timed out waiting for modemstate 7" %
                    ("test dtr", io1.handler.name))

io_close((io1, io2))
del io1
del io2
del sio2
del o
test_shutdown()
print("  Success!")

