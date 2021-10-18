#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test mux tcp large")
TestAccept(o, "mux,tcp,localhost,", "mux,tcp,0", do_large_test,
           chunksize = 64)
del o
test_shutdown()
