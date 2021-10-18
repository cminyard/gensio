#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

check_sctp()
print("Test accept mux-tcp")
ta = TestAccept(o, "mux(service=myservice),sctp,ipv4,localhost,",
                "mux,sctp,0", do_test, do_close = False)
service = ta.io2.control(0, gensio.GENSIO_CONTROL_GET,
                         gensio.GENSIO_CONTROL_SERVICE, None)
if service != "myservice":
    raise Exception(
        "Invalid service, expected %s, got %s" % ("myservice", service))
ta.close()
del ta
del o
test_shutdown()
