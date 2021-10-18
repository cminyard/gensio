#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio
import os

test1 = "asdfasdf"
test2 = "jkl;jkl;"

def do_small_test(io1, io2, timeout=2000):
    print("  testing io1 to io2")
    test_dataxfer(io1, io2, test1, timeout = timeout)
    print("  testing io2 to io1")
    test_dataxfer(io2, io1, test2, timeout = timeout)

print("Test trace")
try:
    os.remove("asdf")
except:
    pass
try:
    os.remove("asdf2")
except:
    pass

TestAccept(o,
           "trace(file=asdf,dir=both,raw=yes),tcp,localhost,",
           "trace(file=asdf2,dir=both,raw=yes),tcp,0",
           do_small_test, chunksize = 64)

f = open("asdf")
s = f.read()
f.close()
if s != test1 + test2:
    raise Exception("Trace 1 data didn't match, expected %s, got %s" % (
        test1 + test2, s))

f = open("asdf2")
s = f.read()
f.close()
if s != test1 + test2:
    raise Exception("Trace 1 data didn't match, expected %s, got %s" % (
        test1 + test2, s))

os.remove("asdf")
os.remove("asdf2")
del o
test_shutdown()
print("  Success!")
