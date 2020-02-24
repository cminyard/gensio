#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test tcp small")
io1 = alloc_io(o, "tcp,localhost,3023", do_open = False,
                     chunksize = 64)
ta = TestAccept(o, io1, "tcp,3023", do_small_test)
