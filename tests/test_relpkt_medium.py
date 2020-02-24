#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test medium relpkt over msgdelim over serial")
io1 = alloc_io(o, "mux(mode=server),relpkt(mode=server),msgdelim,serialdev,/dev/ttyPipeA0,1000000", do_open = False)
io2 = alloc_io(o, "mux,relpkt,msgdelim,serialdev,/dev/ttyPipeB0,1000000", do_open = False)
TestConCon(o, io1, io2, do_medium_test, "relpkt1",
           expected_raddr1 = "/dev/ttyPipeA0,1000000N81 RTSHI DTRHI",
           expected_raddr2 = "/dev/ttyPipeB0,1000000N81 RTSHI DTRHI")
