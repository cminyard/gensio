#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test stdio basic echo")
io = alloc_io(o, "stdio,cat", chunksize = 64)
check_raddr(io, "stdio basic", 'stdio,"cat"')
test_dataxfer(io, io, "This is a test string!")
io_close([io])
del io
del o
test_shutdown()
print("  Success!")

