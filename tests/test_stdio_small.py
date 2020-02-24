#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test stdio small echo")
rb = os.urandom(512)
io = alloc_io(o, "stdio,cat", chunksize = 64)
test_dataxfer(io, io, rb)
io_close(io)
print("  Success!")
