#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test tcp small")
ta = TestAccept(o, "tcp,localhost,", "tcp,0", do_small_test, chunksize = 64)
