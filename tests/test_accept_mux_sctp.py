#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test accept mux-tcp")
io1 = alloc_io(o, "mux(service=myservice),sctp,localhost,3023",
                     do_open = False)
ta = TestAccept(o, io1, "mux,sctp,3023", do_test, do_close = False)
service = ta.io2.control(0, True, gensio.GENSIO_CONTROL_SERVICE, None)
if service != "myservice":
    raise Exception(
        "Invalid service, expected %s, got %s" % ("myservice", service))
ta.close()
