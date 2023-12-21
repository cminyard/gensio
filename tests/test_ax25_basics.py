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
        self.waiting_heard = None
        self.waiting_raw = None

    def set_expected_channel(self, raddr):
        self.expected_channel = raddr

    def set_waiting_heard(self, addr):
        self.waiting_heard = addr

    def set_waiting_raw(self, data):
        self.waiting_raw = data

    def read_callback(self, io, err, buf, auxdata):
        heard = False
        addr = None
        raw = False
        if auxdata:
            for i in auxdata:
                if i == "heard":
                    heard = True
                if i[:5] == "addr:":
                    addr = i[5:]
                if i == "raw":
                    raw = True
        if heard:
            if addr is None:
                raise Exception("heard without address")
                return len(buf)
            if self.waiting_heard is None:
                # Ignore heard reports we weren't expecting
                return len(buf)
            if addr != self.waiting_heard:
                raise Exception("Invalid heard address, expected "
                                + self.waiting_heard + " but got " + addr)
                return len(buf)
            self.waiting_heard = None
            self.wake("got heard")
            return len(buf)
        if raw:
            if self.waiting_raw is None:
                return len(buf)
            if len(buf) != len(self.waiting_raw):
                raise Exception("Invalid raw data, size mismatch, got "
                                + str(len(buf)) + " expected "
                                + str(len(self.waiting_raw)))
                return len(buf)
            for i in range(0, len(buf)):
                if (buf[i] != self.waiting_raw[i]):
                    raise Exception("raw ax25: compare failure on byte %d, "
                                    "expected %x, got %x" %
                                    (i, buf[i], self.waiting_raw[i]))
            self.waiting_raw = None
            self.wake("got raw")
            return len(buf)
        return super().read_callback(io, err, buf, auxdata)

    def new_channel(self, oldio, io, auxdata):
        raddr = io.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                           gensio.GENSIO_CONTROL_GET,
                           gensio.GENSIO_CONTROL_RADDR, "0")
        if not self.expected_channel:
            raise Exception("Unexpected new channel from " + raddr)
        if raddr != self.expected_channel:
            raise Exception("Expect new channel from " +
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

refl = reflector.Reflector(o, "udp,localhost,0", close_on_no_con = True)
port = refl.get_port()
print("port is " + port)

io1str = "ax25(laddr=AE5KM-1,heard,raw),udp,localhost," + port
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
    raise Exception("Timed out waiting for UI data")

io2.handler.set_compare_oob("jkl;",
               auxdata = [ "oob", "addr:ax25:0,AE5KM-2,AE5KM-1", "pid:100" ])
io1.write("jkl;", [ "oob", "addr:0,AE5KM-2,AE5KM-1", "pid:100" ])

if io2.handler.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting for UI data")

print("Testing heard stations")
io1.handler.set_waiting_heard("ax25:0,DUMMY-1,DUMMY-2")
io1.read_cb_enable(True)
io2.write("dummy", [ "oob", "addr:0,dummy-1,dummy-2" ])
if io1.handler.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting for heard report")

print("Testing raw data")
rb = os.urandom(20)
io1.handler.set_waiting_raw(rb)
io1.read_cb_enable(True)
io2.write(rb, [ "raw" ])
if io1.handler.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting for heard report")

print("Making a connection")
io2.handler.set_expected_channel("ax25:0,AE5KM-1,AE5KM-2")
ch1_1 = io1.alloc_channel(["addr=0,AE5KM-2,AE5KM-1"], io1.handler)
ax25_setup_io(o, "ch1_1", ch1_1)
ch1_1.open_s()
if io2.handler.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting for new channel")
ch2_1 = io2.handler.newchan
io2.handler.newchan = None
ax25_setup_io(o, "ch2_1", ch2_1)

print("Sending some data on the new channel")
rb = os.urandom(1234)
ch1_1.handler.set_compare(rb, auxdata = ("pid:45",))
ch2_1.handler.set_write_data(rb, auxdata = ("pid:45",))
if ch2_1.handler.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting for channel data write")
if ch1_1.handler.wait_timeout(1000) == 0:
    raise Exception("Timed out waiting for channel data read")

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
