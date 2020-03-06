#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test mux tcp large")
ta = TestAccept(o, "mux,tcp,localhost,", "mux,tcp,0", do_large_test,
                chunksize = 64)

