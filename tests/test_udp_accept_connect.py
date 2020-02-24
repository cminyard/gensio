#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test udp accepter connect")
TestAcceptConnect(o, "udp,3023", "udp,3024", "udp,localhost,3023",
                  do_small_test, io1_dummy_write = "A")

