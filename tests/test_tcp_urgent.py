#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

def do_urgent_test(io1, io2):
    rb = "A" # We only get one byte of urgent data.
    print("  testing io1 to io2")
    test_dataxfer_oob(io1, io2, rb)
    print("  testing io2 to io1")
    test_dataxfer_oob(io2, io1, rb)
    print("  Success!")

print("Test tcp urgent")
TestAccept(o, "tcp,localhost,", "tcp,0", do_urgent_test,
           chunksize = 64, enable_oob = True)
del o
test_shutdown()

