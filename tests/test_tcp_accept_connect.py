#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test tcp accepter connect")
TestAcceptConnect(o, "tcp,3023", "tcp,3024", "tcp,localhost,3023",
                  do_small_test)
