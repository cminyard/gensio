#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

check_sctp()
print("Test sctp oob")
TestAccept(o, "sctp,localhost,", "sctp,0", do_oob_test, chunksize = 64,
           enable_oob = True)
del o
test_shutdown()
