#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio
import os

print("Test pty basic echo")
io = alloc_io(o, "pty,cat", chunksize = 64)
check_raddr(io, "pty basic", '"cat"')
test_dataxfer(io, io, "This is a test string!")
io_close(io)
print("  Success!")

print("Test pty accepter")
TestAccept(o, "serialdev,", "conacc,pty", do_small_test)

print("Test pty symlinks")
try:
    os.unlink("./ptylink1")
except:
    pass

TestAccept(o, "serialdev,./ptylink1", "conacc,pty(link=./ptylink1)",
           do_small_test, get_port = False)

print("Test pty symlink failure")
os.symlink("asdf", "./ptylink1")
try:
    TestAccept(o, "serialdev,./ptylink1", "conacc,pty(link=./ptylink1)",
               do_small_test, get_port = False, except_on_log = True)
except Exception as E:
    if str(E) != "***err LOG: conacc,pty(link=./ptylink1): Error opening gensio: Value already exists":
        raise
    print("  Success!")

print("Test pty symlink force")
TestAccept(o, "serialdev,./ptylink1", "conacc,pty(link=./ptylink1,forcelink)",
           do_small_test, get_port = False)
