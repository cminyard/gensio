#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test unix accepter connect")
TestAcceptConnect(o, "unix,/tmp/gensiotest", "unix,/tmp/gensiotest2",
                  "unix,/tmp/gensiotest",
                  do_small_test)
