#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test large relpkt over udp")
TestAccept(o, "mux,relpkt,udp,localhost,",
           "mux,relpkt,udp,localhost,0", do_large_test)
