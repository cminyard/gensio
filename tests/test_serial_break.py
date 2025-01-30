#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2025  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

import sys

from utils import *
check_pipe_dev()

import gensio

print("Test serial break")

io1str = "serialdev," + ttypipe[0] + ",9600N81,LOCAL"
io2str = "serialdev," + ttypipe[1] + ",9600N81,LOCAL"

print("serialdev:\n  io1=%s\n  io2=%s" % (io1str, io2str))

io1 = alloc_io(o, io1str)
io2 = alloc_io(o, io2str)

print("Make sure 0xff transfers correctly")

test_dataxfer(io1, io2, "a\xffx\xff\xffy")

do_small_test(io1, io2)

# Allow io2 to receive a serial break.
try:
    io2.control(0, gensio.GENSIO_CONTROL_SET,
                gensio.GENSIO_CONTROL_SER_LINESTATE,
                str(gensio.GENSIO_SER_LINESTATE_BREAK |
                    gensio.GENSIO_SER_LINESTATE_PARITY_ERR))
except Exception as e:
    print("receive serial break not supported: " + str(e))
    sys.exit(77)

print("Cause a break")

io2.handler.set_expected_linestate(gensio.GENSIO_SER_LINESTATE_BREAK)

io2.read_cb_enable(True);

io1.control(0, gensio.GENSIO_CONTROL_SET,
            gensio.GENSIO_CONTROL_SER_SEND_BREAK, "")

if (io2.handler.wait_timeout(2000) == 0):
    raise Exception("Timed out waiting for serial break")
print("  Success!")

do_small_test(io1, io2)

io_close((io1, io2))
del io1
del io2
del o
test_shutdown()
print("Success!")

