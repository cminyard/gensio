#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test small relpkt over msgdelim over serial")
check_pipe_dev()
io1 = alloc_io(o, "relpkt(mode=server),msgdelim,serialdev," + ttypipe[0], do_open = False)
io2 = alloc_io(o, "relpkt,msgdelim,serialdev," + ttypipe[1], do_open = False)
TestConCon(o, io1, io2, do_small_test, "relpkt1",
           expected_raddr1 = ttypipe[0] + ",9600N81 RTSHI DTRHI",
           expected_raddr2 = ttypipe[1] + ",9600N81 RTSHI DTRHI")
del io1
del io2
del o
test_shutdown()
