#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test stdio basic stderr echo")
io = alloc_io(o, "stdio,sh -c 'cat 1>&2'", chunksize = 64)
io.handler.ignore_input = True
io.read_cb_enable(True)
err = io.alloc_channel(None, None)
err.open_s()
check_raddr(err, "stderr basic", 'stderr,"sh" "-c" "cat 1>&2"')
HandleData(o, "stderr", chunksize = 64, io = err)
test_dataxfer(io, err, "This is a test string!")
io_close((io, err))
del io
del err
del o
test_shutdown()
print("  Success!")
