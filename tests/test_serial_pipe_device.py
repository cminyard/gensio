#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test serial pipe device")
check_pipe_dev()
io1 = alloc_io(o, "serialdev," + ttypipe[0] + ",9600")
io2 = alloc_io(o, "serialdev," + ttypipe[1] + ",9600")
test_dataxfer(io1, io2, "This is a test string!")
io_close((io1, io2))
del io1
del io2
del o
test_shutdown()
print("  Success!")
