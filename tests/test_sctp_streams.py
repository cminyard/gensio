#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

check_sctp()

def do_stream_test(io1, io2):
    rb = os.urandom(10)
    print("  testing io1 to io2")
    test_dataxfer_stream(io1, io2, rb, 2)
    print("  testing io2 to io1")
    test_dataxfer_stream(io2, io1, rb, 1)
    print("  Success!")

print("Test sctp streams")
TestAccept(o, "sctp(instreams=2,ostreams=3),localhost,",
           "sctp(instreams=3,ostreams=2),0", do_stream_test,
           chunksize = 64)
del o
test_shutdown()
