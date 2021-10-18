#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test unix accepter connect")
TestAcceptConnect(o, "unix,/tmp/gensiotest", "unix,/tmp/gensiotest2",
                  "unix,/tmp/gensiotest",
                  do_small_test, use_port = False)
del o
test_shutdown()
