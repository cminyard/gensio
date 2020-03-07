#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

cmpstr = "asdfasdfasdfsadf"

print("Test udp nocon")
io1 = alloc_io(o, "udp(nocon,laddr='0.0.0.0,0'),ipv4,localhost,1234")
addr1 = io1.control(gensio.GENSIO_CONTROL_DEPTH_FIRST, True,
                    gensio.GENSIO_CONTROL_LADDR, "0")
port1 = io1.control(gensio.GENSIO_CONTROL_DEPTH_FIRST, True,
                    gensio.GENSIO_CONTROL_LPORT, "0")
if not addr1.endswith(port1):
    raise Exception("Port/address mismatch")

io2 = alloc_io(o, "udp(nocon,laddr='0.0.0.0,0')," + addr1)
addr2 = io2.control(gensio.GENSIO_CONTROL_DEPTH_FIRST, True,
                    gensio.GENSIO_CONTROL_LADDR, "0")

h1 = io1.handler
h2 = io2.handler

h1.set_compare(cmpstr)
io2.write(cmpstr, None)
if h1.wait_timeout(1000) == 0:
    raise Exception("test_udp_nocon: read timeout 1")
    
h2.set_compare(cmpstr)
io1.write(cmpstr, [ "addr:" + addr2 ])
if h2.wait_timeout(1000) == 0:
    raise Exception("test_udp_nocon: read timeout 2")
    
print("  Success!")
