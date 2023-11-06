#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test telnet small")
TestAccept(o, "telnet,tcp,localhost,", "telnet(rfc2217=true),tcp,localhost,0",
           do_small_test, chunksize = 64, enable_read_io1 = True)
del o
test_shutdown()
