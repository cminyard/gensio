#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

check_sctp()
print("Test sctp accepter connect")
TestAcceptConnect(o, "sctp,localhost,0", "sctp,localhost,0", "sctp,localhost,",
                  do_small_test)
del o
test_shutdown()
