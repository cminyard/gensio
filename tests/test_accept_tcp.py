#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

print("Test accept tcp")
TestAccept(o, "tcp,ipv4,localhost,", "tcp,localhost,0", do_test,
           expected_raddr = "ipv4,127.0.0.1,",
           expected_acc_laddr = "ipv4,127.0.0.1,")
del o
test_shutdown()
