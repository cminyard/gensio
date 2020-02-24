#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test sctp oob")
io1 = alloc_io(o, "sctp,localhost,3023",
                     do_open = False, chunksize = 64)
ta = TestAccept(o, io1, "sctp,3023", do_oob_test)
