#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test large relpkt over udp")
io1 = alloc_io(o, "mux,relpkt,udp,localhost,3023", do_open = False)
TestAccept(o, io1, "mux,relpkt,udp,localhost,3023", do_large_test)
