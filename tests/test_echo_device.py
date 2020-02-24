#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test echo device")
io = alloc_io(o, "serialdev,/dev/ttyEcho0,38400")
check_raddr(io, "echo device", "/dev/ttyEcho0,38400N81 RTSHI DTRHI")
test_dataxfer(io, io, "This is a test string!")
io_close(io)
print("  Success!")
