#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test ax25 small")
TestAccept(o,
           "ax25(laddr=AE5KM-2,addr='0,AE5KM-1,AE5KM-2'),udp,localhost,",
           "ax25(laddr=AE5KM-1),udp,0", do_small_test, chunksize = 64)
del o
test_shutdown()
