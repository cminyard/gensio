#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test mux tcp oob")
TestAccept(o, "mux,tcp,localhost,", "mux,tcp,localhost,0", do_oob_test,
           chunksize = 64, enable_oob = True)

del o
test_shutdown()
