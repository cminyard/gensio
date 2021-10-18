#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

check_sctp()

print("Test mux sctp small")
TestAccept(o, "mux,sctp,localhost,", "mux,sctp,0", do_small_test,
           chunksize = 64)
del o
test_shutdown()
