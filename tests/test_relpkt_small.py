#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test small relpkt over msgdelim over serial")
io1 = alloc_io(o, "relpkt(mode=server),msgdelim,serialdev,/dev/ttyPipeA0", do_open = False)
io2 = alloc_io(o, "relpkt,msgdelim,serialdev,/dev/ttyPipeB0", do_open = False)
TestConCon(o, io1, io2, do_small_test, "relpkt1",
           expected_raddr1 = "/dev/ttyPipeA0,9600N81 RTSHI DTRHI",
           expected_raddr2 = "/dev/ttyPipeB0,9600N81 RTSHI DTRHI")
