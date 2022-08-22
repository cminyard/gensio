#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

def do_ratelimit_test1(io1, io2, timeout=2000):
    data = "123456789012345" # 15 characters, 1.5 seconds.
    io1.handler.set_write_data(data)
    io2.handler.set_compare(data)
    if (io1.handler.wait_timeout(1000) != 0):
        raise Exception(("%s: %s: " % ("do_ratelimit_test", io1.handler.name)) +
                        ("Sent data too fast"))
    if (io1.handler.wait_timeout(1000) == 0):
        raise Exception(("%s: %s: " % ("do_ratelimit_test", io1.handler.name)) +
                        ("Sent data too slowly"))
    if (io2.handler.wait_timeout(1000) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io2.handler.name)) +
                        ("Read data wasn't received"))

def do_ratelimit_test2(io1, io2, timeout=2000):
    do_ratelimit_test1(io2, io1, timeout)

print("Test ratelimit gensio")
TestAccept(o, "ratelimit(xmit_delay=100m),tcp,localhost,", "tcp,0",
           do_ratelimit_test1, chunksize = 64)
print("Test ratelimit accepter")
TestAccept(o, "tcp,localhost,", "ratelimit(xmit_delay=100m),tcp,0",
           do_ratelimit_test2, chunksize = 64)
del o
test_shutdown()
print("Success!")
