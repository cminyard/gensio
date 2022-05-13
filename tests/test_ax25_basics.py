#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio
import reflector


class AX25HandleData(HandleData):
    def __init__(self, o, iostr, name = None, chunksize=10240,
                 io = None, expect_remclose = True):
        HandleData.__init__(self, o, iostr, name = name, chunksize = chunksize,
                            io = io, expect_remclose = expect_remclose)
        self.newchan = None
        self.expected_channel = None

    def set_expected_channel(self, raddr):
        self.expected_channel = raddr

    def new_channel(self, oldio, io, auxdata):
        raddr = io.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                           gensio.GENSIO_CONTROL_GET,
                           gensio.GENSIO_CONTROL_RADDR, "0")
        if not self.expected_channel:
            raise HandlerException("Unexpected new channel from " + raddr)
        if raddr != self.expected_channel:
            raise HandlerException("Expect new channel from " +
                                   self.expected_channel + " but got " + raddr)
        self.newchan = io
        self.expected_channel = None
        self.waiter.wake()
        return 0

def ax25_alloc_io(o, iostr, do_open = True, chunksize = 1024, oob = 0):
    h = AX25HandleData(o, iostr, chunksize = chunksize)
    if oob > 0:
        h.io.control(0, gensio.GENSIO_CONTROL_SET,
                     gensio.GENSIO_CONTROL_ENABLE_OOB, str(oob))
    if (do_open):
        h.io.open_s()
    return h.io

def ax25_setup_io(o, name, io, chunksize = 1024, oob = 0):
    h = AX25HandleData(o, iostr = name, io = io, chunksize = chunksize)
    if oob > 0:
        h.io.control(0, gensio.GENSIO_CONTROL_SET,
                     gensio.GENSIO_CONTROL_ENABLE_OOB, str(oob))

refl = reflector.Reflector(o, "udp,0", close_on_no_con = True)
port = refl.get_port()
print("port is " + port)

io1str = "ax25(laddr=AE5KM-1),udp,localhost," + port
io2str = "ax25(laddr=AE5KM-2),udp,localhost," + port

io1 = ax25_alloc_io(o, io1str, oob = 1)
io2 = ax25_alloc_io(o, io2str, oob = 1)

print("Testing UI data transfer")
# This will seed the connection, UDP doesn't connect until is receives data.
io2.write("dummy", [ "oob", "addr:0,dummy-1,dummy-2" ])
io2.handler.wait_timeout(10)

io2.handler.set_compare_oob("asdf",
               auxdata = [ "oob", "addr:ax25:0,AE5KM-2,AE5KM-1", "pid:240" ])
io1.write("asdf", [ "oob", "addr:0,AE5KM-2,AE5KM-1" ])

if io2.handler.wait_timeout(1000) == 0:
    raise HandlerException("Timed out waiting for UI data")

io2.handler.set_compare_oob("jkl;",
               auxdata = [ "oob", "addr:ax25:0,AE5KM-2,AE5KM-1", "pid:100" ])
io1.write("jkl;", [ "oob", "addr:0,AE5KM-2,AE5KM-1", "pid:100" ])

if io2.handler.wait_timeout(1000) == 0:
    raise HandlerException("Timed out waiting for UI data")

print("Making a connection")
io2.handler.set_expected_channel("ax25:0,AE5KM-1,AE5KM-2")
ch1_1 = io1.alloc_channel(["addr=0,AE5KM-2,AE5KM-1"], io1.handler)
ax25_setup_io(o, "ch1_1", ch1_1)
ch1_1.open_s()
if io2.handler.wait_timeout(1000) == 0:
    raise HandlerException("Timed out waiting for new channel")
ch2_1 = io2.handler.newchan
io2.handler.newchan = None
ax25_setup_io(o, "ch2_1", ch2_1)

print("Sending some data on the new channel")
rb = os.urandom(1234)
ch1_1.handler.set_compare(rb, auxdata = ("pid:45",))
ch2_1.handler.set_write_data(rb, auxdata = ("pid:45",))
if ch2_1.handler.wait_timeout(1000) == 0:
    raise HandlerException("Timed out waiting for channel data write")
if ch1_1.handler.wait_timeout(1000) == 0:
    raise HandlerException("Timed out waiting for channel data read")

print("Success!")

io_close((ch1_1, ch2_1))

io_close((io1, io2))
del io1
del io2
del ch1_1
del ch2_1

refl.close()
del refl

del o
test_shutdown()
