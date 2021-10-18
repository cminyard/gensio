#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

import utils
import gensio
import os

test1 = "asdfasdf"

print("Test file")

try:
    os.remove("asdf")
except:
    pass


g = gensio.gensio(utils.o, "file(outfile=asdf,create)", None)
g.set_sync()
g.open_s()
g.write_s(test1, 1000)
g.close_s()
del g

g = gensio.gensio(utils.o, "file(infile=asdf,create)", None)
g.set_sync()
g.open_s()
s = g.read_s(100, 1000)
g.close_s()
del g
s = s[0].decode('utf-8')

if s != test1:
    raise Exception("file data didn't match, expected %s, got %s" % (
        test1, s))

os.remove("asdf")

utils.test_shutdown()
print("  Success!")
