#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

def do_no_test(io1, io2, timeout=2000):
    io1.handler.ignore_input = True
    io2.handler.ignore_input = True
    io1.handler.waiting_rem_close = True
    io2.handler.waiting_rem_close = True
    io1.read_cb_enable(True)
    io2.read_cb_enable(True)
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception("test_perf: io1 did not finish in time")
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception("test_perf: io2 did not finish in time")
    return

print("Test perf")
TestAccept(o,
           "perf(write_len=1000000,expect_len=1000000),tcp,localhost,",
           "perf(write_len=1000000,expect_len=1000000),tcp,0",
           do_no_test)
del o
test_shutdown()
print("  Success!")
