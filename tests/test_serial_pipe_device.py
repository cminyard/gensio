#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test serial pipe device")
io1 = alloc_io(o, "serialdev,/dev/ttyPipeA0,9600")
io2 = alloc_io(o, "serialdev,/dev/ttyPipeB0,9600")
test_dataxfer(io1, io2, "This is a test string!")
io_close(io1)
io_close(io2)
print("  Success!")
