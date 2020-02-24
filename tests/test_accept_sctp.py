#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test accept sctp")
io1 = alloc_io(o, "sctp,localhost,3023", do_open = False)
# FIXME - the raddr and laddr areq not tested here, it's hard to
# know what it would be because of sctp multihoming.
TestAccept(o, io1, "sctp,3023", do_test,
           expected_acc_port = "3023")
c = io1.control(0, True, gensio.GENSIO_CONTROL_STREAMS, None)
if c != "instreams=1,ostreams=1":
    raise Exception("Invalid stream settings: %s" % c)
