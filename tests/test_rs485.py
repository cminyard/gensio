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

print("Test RS485")

io1str = "serialdev," + ttypipe[0] + ",9600N81,LOCAL,rs485=103:495"
io2str = "serialdev," + ttypipe[1] + ",9600N81"

print("serialdev rs485:\n  io1=%s\n  io2=%s" % (io1str, io2str))

io1 = alloc_io(o, io1str)
io2 = alloc_io(o, io2str)

rs485 = get_remote_rs485(remote_id_int(io2))
check_rs485 = "103 495 enabled"
if rs485 != check_rs485:
    raise Exception("%s: %s: RS485 was not '%s', it was '%s'" %
                    ("test rs485", io1.handler.name, check_rs485, rs485))

io_close((io1, io2))
del io1
del io2
del o
test_shutdown()
print("  Success!")
