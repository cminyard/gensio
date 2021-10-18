#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio


print("Test medium relpkt over msgdelim over serial")
check_pipe_dev()
if is_serialsim_pipe():
    fast_baud = "1000000"
    timeout = 10000
else:
    # Normal serial ports don't always support high speeds
    fast_baud = "115200"
    timeout = 100000

io1 = alloc_io(o, "mux(mode=server),relpkt(mode=server),msgdelim,serialdev," + ttypipe[0] + "," + fast_baud, do_open = False)
io2 = alloc_io(o, "mux,relpkt,msgdelim,serialdev," + ttypipe[1] + "," + fast_baud, do_open = False)
TestConCon(o, io1, io2, do_medium_test, "relpkt1",
           expected_raddr1 = ttypipe[0] + "," + fast_baud + "N81 RTSHI DTRHI",
           expected_raddr2 = ttypipe[1] + "," + fast_baud + "N81 RTSHI DTRHI",
           timeout = timeout)
del io1
del io2
del o
test_shutdown()
