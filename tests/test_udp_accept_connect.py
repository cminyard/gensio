#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test udp accepter connect")
TestAcceptConnect(o, "udp,0", "udp,0", "udp,localhost,",
                  do_small_test, io1_dummy_write = "A")

