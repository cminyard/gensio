#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

cmpstr = "asdfasdfasdfsadf"

print("Test udp nocon")
io1 = alloc_io(o, "udp(nocon,laddr='127.0.0.1,0'),ipv4,localhost,1234")
addr1 = io1.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                    gensio.GENSIO_CONTROL_GET,
                    gensio.GENSIO_CONTROL_LADDR, "0")
port1 = io1.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                    gensio.GENSIO_CONTROL_GET,
                    gensio.GENSIO_CONTROL_LPORT, "0")
if not addr1.endswith(port1):
    raise Exception("Port/address mismatch")

io2 = alloc_io(o, "udp(nocon,laddr='127.0.0.1,0')," + addr1)
addr2 = io2.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                    gensio.GENSIO_CONTROL_GET,
                    gensio.GENSIO_CONTROL_LADDR, "0")

h1 = io1.handler
h2 = io2.handler

h1.set_compare(cmpstr, auxdata = [ "addr:" + addr2 ])
io2.write(cmpstr, None)
if h1.wait_timeout(1000) == 0:
    raise Exception("test_udp_nocon: read timeout 1")

h2.set_compare(cmpstr, auxdata = [ "addr:" + addr1 ])
io1.write(cmpstr, [ "addr:" + addr2 ])
if h2.wait_timeout(1000) == 0:
    raise Exception("test_udp_nocon: read timeout 2")

# Turn on extrainfo and see that it works.

print("Checking extrainfo in received packdets")

# Find the loopback address index so we can check it on received packets
ifs = gensio.ifinfo(o)
loopidx = 0
for i in range(0, ifs.get_num_ifs()):
    flags = ""
    ifidx = ifs.get_ifindex(i)
    if ifs.is_up(i):
        flags = flags + ",UP"
    if ifs.is_loopback(i):
        flags = flags + ",LOOPBACK"
        loopidx = ifidx
    if ifs.is_multicast(i):
        flags = flags + ",MULTICAST"
    if len(flags) > 0:
        flags = flags[1:]
    print("  %s(%d): %s" % (ifs.get_name(i), ifidx, flags))
    for j in range(0, ifs.get_num_addrs(i)):
        print("    %s/%d" % (ifs.get_addr(i, j), ifs.get_addr_netbits(i, j)))
del ifs

io2.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
            gensio.GENSIO_CONTROL_SET,
            gensio.GENSIO_CONTROL_EXTRAINFO, "1")

h1.set_compare(cmpstr, auxdata = [ "addr:" + addr2 ])
io2.write(cmpstr, None)
if h1.wait_timeout(1000) == 0:
    raise Exception("test_udp_nocon: read timeout 1")

h2.set_compare(cmpstr, auxdata = [ "addr:" + addr1,
                                   "ifidx:%d" % loopidx,
                                   "daddr:ipv4,127.0.0.1" ])
io1.write(cmpstr, [ "addr:" + addr2 ])
if h2.wait_timeout(1000) == 0:
    raise Exception("test_udp_nocon: read timeout 2")

io_close((io1, io2))
del io1
del io2
del h1
del h2
del o
test_shutdown()
print("  Success!")
