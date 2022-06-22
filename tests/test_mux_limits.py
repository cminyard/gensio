#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

class MuxHandler:
    """ """
    def __init__(self, o, num_channels = 10):
        self.o = o
        self.channels = [None for x in range(num_channels)]
        self.waiter = gensio.waiter(o)
        self.expect_close = -1
        self.op_count = 0
        self.op_err = 0
        return

    def read_callback(self, io, err, buf, auxdata):
        i = int(io.control(0, gensio.GENSIO_CONTROL_GET,
                           gensio.GENSIO_CONTROL_SERVICE, None))
        if (err):
            if (self.expect_close != -1 and i != self.expect_close):
                raise HandlerException(
                    "Invalid read close on channel %d: %s" % (i, err))
            if err != "Remote end closed connection":
                raise HandlerException(
                    "Invalid error on read close: %s" % err)
            io.close(self)
            return 0
        raise HandlerException("Unexpected read")
        return len(buf)

    def write_callback(self, io):
        return

    def dec_op_count(self):
        if (self.op_count == 0):
            raise HandlerException("Too many ops")
        self.op_count -= 1
        if (self.op_count == 0):
            self.waiter.wake()
        return

    def new_channel(self, io1, io2, auxdata):
        i = int(io2.control(0, gensio.GENSIO_CONTROL_GET,
                            gensio.GENSIO_CONTROL_SERVICE, None))
        if (self.channels[i]):
            raise HandlerException(
                "Got channel %d, but it already exists" % i)
        err = 0
        if self.op_err:
            err = self.op_err
            self.op_err = 0
        else:
            self.channels[i] = io2
            io2.set_cbs(self)
            io2.read_cb_enable(True)
        self.dec_op_count()
        return err

    def new_connection(self, acc, io):
        self.new_channel(None, io, None)
        return

    def close_done(self, io):
        i = int(io.control(0, gensio.GENSIO_CONTROL_GET,
                           gensio.GENSIO_CONTROL_SERVICE, None))
        if (self.expect_close != -1 and self.expect_close != i):
            raise HandlerException("Unexpected close for channel %d" % i)
        if (self.channels[i] is None):
            raise HandlerException(
                "Got channel %d, but it didn't exist in array" % i)
        self.channels[i] = None;
        self.dec_op_count()
        return

    def set_expect_close(self, nr):
        self.expect_close = nr
        return

    def set_op_count(self, nr):
        self.op_count = nr
        return

    def set_op_err(self, err):
        self.op_err = err
        return

    def open_done(self, io, err):
        i = int(io.control(0, gensio.GENSIO_CONTROL_GET,
                           gensio.GENSIO_CONTROL_SERVICE, None))
        if self.op_err:
            if self.op_err != err:
                raise HandlerException(
                    "Bad error opening channel %d: got %s, expected %s" %
                    (i, err, str(self.op_err)))
            self.op_err = 0
        elif (err):
            raise HandlerException(
                "Error opening channel %d: %s" % (i, err))
        if not err:
            io.read_cb_enable(True)
        self.dec_op_count()
        return

    def wait(self, count = 1, timeout = 0):
        if (timeout > 0):
            return self.waiter.wait_timeout(count, timeout)
        else:
            return self.waiter.wait(count)
        return

print("Testing mux limits")
handlemuxacc = MuxHandler(o, num_channels = 10)
gensios_enabled.check_iostr_gensios("mux,tcp")
muxacc = gensio.gensio_accepter(o, "mux(max_channels=10),tcp,0",
                                handlemuxacc)
muxacc.startup()
port = muxacc.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                      gensio.GENSIO_CONTROL_GET,
                      gensio.GENSIO_ACC_CONTROL_LPORT, "0")

handlemuxcl = MuxHandler(o, num_channels = 10)
muxcl = gensio.gensio(o,
                      "mux(service=0,max_channels=10),tcp,localhost," + port,
                      handlemuxcl)
handlemuxcl.channels[0] = muxcl
handlemuxacc.set_op_count(1)
handlemuxcl.set_op_count(1)
muxcl.open(handlemuxcl)

if (handlemuxcl.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for single client open finish")
if (handlemuxacc.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for single client open finish")

print("Opening all channels")
handlemuxcl.set_op_count(9)
handlemuxacc.set_op_count(9)
for i in range(1, 10):
    handlemuxcl.channels[i] = muxcl.alloc_channel(["service=%d" % i],
                                                  handlemuxcl)
    handlemuxcl.channels[i].open(handlemuxcl)

print("Waiting for channels");
if (handlemuxcl.wait(timeout = 2000) == 0):
    raise HandlerException(
        "Timeout waiting for client open finish")
if (handlemuxacc.wait(timeout = 2000) == 0):
    raise HandlerException(
        "Timeout waiting for server open finish")

print("Trying an open that should fail")
try:
    muxcl.alloc_channel(["service=%d" % 10], handlemuxcl)
except Exception as err:
    if str(err) != "gensio:alloc_channel: Object was already in use":
        raise HandlerException("Got wrong error: %s" % str(err))
else:
    raise HandlerException(
        "No exception when opening too many channels")

print("Close one channel")
handlemuxcl.set_expect_close(3)
handlemuxacc.set_expect_close(3)
handlemuxcl.set_op_count(1)
handlemuxacc.set_op_count(1)
handlemuxacc.channels[3].close(handlemuxacc)

if (handlemuxcl.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for single client close finish")
if (handlemuxacc.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for single server close finish")

print("Open that channel again and reject the open")
handlemuxacc.set_op_count(1)
handlemuxacc.set_op_err(gensio.GE_APPERR)
handlemuxcl.set_op_count(1)
handlemuxcl.set_op_err("Application error")
handlemuxcl.channels[3] = muxcl.alloc_channel(["service=3"],
                                              handlemuxcl)
handlemuxcl.channels[3].open(handlemuxcl)

if (handlemuxcl.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for client error open finish")
if (handlemuxacc.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for server error open finish")
handlemuxcl.channels[3] = None
handlemuxacc.wait(timeout = 1)

print("Open that channel again")
handlemuxacc.set_op_count(1)
handlemuxcl.set_op_count(1)
handlemuxcl.channels[3] = muxcl.alloc_channel(["service=3"],
                                              handlemuxcl)
handlemuxcl.channels[3].open(handlemuxcl)

if (handlemuxcl.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for client single open finish")
if (handlemuxacc.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for server single open finish")

print("Close all channels")
handlemuxcl.set_expect_close(-1)
handlemuxacc.set_expect_close(-1)
handlemuxcl.set_op_count(10)
handlemuxacc.set_op_count(10)
for i in range(0, 10):
    if (i % 2 == 0):
        handlemuxcl.channels[i].close(handlemuxcl)
    else:
        handlemuxacc.channels[i].close(handlemuxacc)

if (handlemuxcl.wait(timeout = 2000) == 0):
    raise HandlerException(
        "Timeout waiting for client all close finish")
if (handlemuxacc.wait(timeout = 2000) == 0):
    raise HandlerException(
        "Timeout waiting for server all close finish")
handlemuxacc.wait(timeout = 10)

print("Re-open the mux")
handlemuxacc.set_op_count(1)
handlemuxcl.set_op_count(1)
muxcl.open(handlemuxcl)
if (handlemuxcl.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for single client open finish")
if (handlemuxacc.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for single client open finish")

print("Re-close the mux")
handlemuxacc.set_op_count(1)
handlemuxcl.set_op_count(1)
handlemuxcl.channels[0] = muxcl
muxcl.close(handlemuxcl)
if (handlemuxcl.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for single client open finish")
if (handlemuxacc.wait(timeout = 1000) == 0):
    raise HandlerException(
        "Timeout waiting for single client open finish")

del handlemuxacc
del handlemuxcl
del muxacc
del muxcl
del o
test_shutdown()
