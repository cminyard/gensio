#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio
import ipmisimdaemon

print("Test ipmisol small")
check_pipe_dev()
isim = ipmisimdaemon.IPMISimDaemon(o, ttypipe[1])
io1 = alloc_io(o, "serialdev," + ttypipe[0] + ",9600")
io2 = alloc_io(o, "ipmisol,lan -U ipmiusr -P test -p 9001 localhost,9600")
test_dataxfer(io1, io2, "This is a test string!")
io_close(io1)
io_close(io2)
print("  Success!")
