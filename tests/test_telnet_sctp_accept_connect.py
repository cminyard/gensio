#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test telnet over sctp accepter connect")
TestAcceptConnect(o, "telnet,sctp,3023", "telnet,sctp,3024",
                  "telnet,sctp,localhost,3023", do_small_test)

