#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

def do_chardelay_test1(io1, io2, timeout=2000):
    data = "a"
    io1.handler.set_write_data(data)
    io2.handler.set_compare(data)
    if (io1.handler.wait_timeout(500) == 0):
        raise Exception(("%s: %s: " % ("do_chardelay_test", io1.handler.name)) +
                        ("Send data didn't happen"))
    if (io2.handler.wait_timeout(500) != 0):
        raise Exception(("%s: %s: " % ("do_chardelay_test", io1.handler.name)) +
                        ("Sent data too fast"))
    if (io2.handler.wait_timeout(1500) == 0):
        raise Exception(("%s: %s: " % ("do_chardelay_test", io1.handler.name)) +
                        ("Sent data too slowly"))

    data = "b"
    io1.handler.set_write_data(data)
    io2.handler.set_compare(data + data)
    if (io1.handler.wait_timeout(500) == 0):
        raise Exception(("%s: %s: " % ("do_chardelay_test", io1.handler.name)) +
                        ("Send data didn't happen"))
    if (io2.handler.wait_timeout(500) != 0):
        raise Exception(("%s: %s: " % ("do_chardelay_test", io1.handler.name)) +
                        ("Sent data too fast(2)"))
    io1.handler.set_write_data(data)
    if (io1.handler.wait_timeout(500) == 0):
        raise Exception(("%s: %s: " % ("do_chardelay_test", io1.handler.name)) +
                        ("Send data didn't happen"))
    if (io2.handler.wait_timeout(600) != 0):
        raise Exception(("%s: %s: " % ("do_chardelay_test", io1.handler.name)) +
                        ("Sent data too fast(2)"))
    if (io2.handler.wait_timeout(1500) == 0):
        raise Exception(("%s: %s: " % ("do_chardelay_test", io1.handler.name)) +
                        ("Sent data too slowly"))

    data = "\n"
    io1.handler.set_write_data(data)
    io2.handler.set_compare(data)
    if (io1.handler.wait_timeout(500) == 0):
        raise Exception(("%s: %s: " % ("do_chardelay_test", io1.handler.name)) +
                        ("Send data didn't happen"))
    if (io2.handler.wait_timeout(500) == 0):
        raise Exception(("%s: %s: " % ("do_chardelay_test", io1.handler.name)) +
                        ("Sent data too slowly"))
    return

def do_chardelay_test2(io1, io2, timeout=2000):
    do_chardelay_test1(io2, io1, timeout)

print("Test chardelay gensio")
TestAccept(o, "chardelay(min-delay=1000m,max-delay=2000m,sendon='\n'),tcp,localhost,", "tcp,localhost,0",
           do_chardelay_test1, chunksize = 64)
print("Test chardelay accepter")
TestAccept(o, "tcp,localhost,", "chardelay(min-delay=1000m,max-delay=2000m,sendon='\n'),tcp,localhost,0",
           do_chardelay_test2, chunksize = 64)
del o
test_shutdown()
print("Success!")
