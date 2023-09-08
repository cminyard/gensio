#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test tcp accepter connect")
TestAcceptConnect(o, "tcp,localhost,0", "tcp,localhost,0", "tcp,localhost,",
                  do_small_test)
del o
test_shutdown()
