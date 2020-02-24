#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

def do_stream_test(io1, io2):
    rb = os.urandom(10)
    print("  testing io1 to io2")
    test_dataxfer_stream(io1, io2, rb, 2)
    print("  testing io2 to io1")
    test_dataxfer_stream(io2, io1, rb, 1)
    print("  Success!")

print("Test sctp streams")
io1 = alloc_io(o, "sctp(instreams=2,ostreams=3),localhost,3023",
                     do_open = False, chunksize = 64)
ta = TestAccept(o, io1, "sctp(instreams=3,ostreams=2),3023", do_stream_test)
