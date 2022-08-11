#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

class ScrHandler:
    def __init__(self, name, o):
        self.name = name
        self.o = o
        self.waiter = gensio.waiter(o)
        self.io = None
        self.expect_read = None
        self.expect_read_pos = 0
        self.expect_read_err = None
        self.expect_close = False
        self.expect_open = False
        self.expect_open_err = None
        return

    def set_expect_read(self, data):
        self.expect_read_pos = 0;
        self.expect_read = conv_to_bytes(data)
        return

    def set_expect_read_err(self, err):
        self.expect_read_err = err
        return

    def read_callback(self, io, err, buf, auxdata):
        if err is not None:
            if self.expect_read_err is not None and err == self.expect_read_err:
                self.waiter.wake()
            else:
                raise HandlerException(self.name + ": Got read error: " + err);
            return 0
        i = 0
        while self.expect_read_pos < len(self.expect_read) and i < len(buf):
            if buf[i] != self.expect_read[self.expect_read_pos]:
                raise HandlerException(self.name + ": data mismatch on byte %d"
                                       % self.expect_read_pos);
            i += 1
            self.expect_read_pos += 1

        if self.expect_read_pos >= len(self.expect_read):
            if i < len(buf):
                raise HandlerException(self.name +
                                       ": Unexpected data from connection")
            self.expect_read = None
            self.waiter.wake()

        return len(buf)

    def write_callback(self, io):
        return

    def new_connection(self, acc, io):
        self.io = io
        self.io.set_cbs(self)
        self.io.read_cb_enable(True)
        self.waiter.wake()
        return

    def close_done(self, io):
        if not self.expect_close:
            raise HandlerException(self.name + ": Unexpected close")
        self.waiter.wake()
        return

    def set_expect_close(self):
        self.expect_close = True
        return

    def open_done(self, io, err):
        if not self.expect_open:
            raise HandlerException(self.name + ": Unexpected open")
        if err is not None:
            if self.expect_open_err is not None:
                if err != self.expect_open_err:
                    raise HandlerException(self.name + ": Wrong open error: "
                                           + err)
            else:
                raise HandlerException(self.name + ": Unexpected open error: "
                                       + err)
        elif self.expect_open_err is not None:
            raise HandlerException(self.name + ": Expected open error")
            
        if err is None:
            self.io.read_cb_enable(True)
        self.waiter.wake()
        return

    def set_expect_open(self, expect_err = None):
        self.expect_open = True
        self.expect_open_err = expect_err
        return

    def wait(self, count = 1, timeout = 0):
        if (timeout > 0):
            return self.waiter.wait_timeout(count, timeout)
        else:
            return self.waiter.wait(count)
        return

print("Testing basic connection")
handleacc = ScrHandler("acc", o)
acc = gensio.gensio_accepter(o, "tcp,0", handleacc)
acc.startup()
port = acc.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                   gensio.GENSIO_CONTROL_GET,
                   gensio.GENSIO_ACC_CONTROL_LPORT, "0")

handlecon = ScrHandler("con", o)
con = gensio.gensio(o, "script(script=./echotest),tcp,localhost," + port,
                    handlecon)
handlecon.io = con

con.open(handlecon)

if (handleacc.wait(timeout = 10000000) == 0):
    raise HandlerException("Timeout waiting for accepter")
if (handlecon.wait(timeout = 100) != 0):
    raise HandlerException("Got unexpected open on connection")

# The connection should be echoing from echotest
teststr = "Hi\n"
handleacc.set_expect_read(teststr)
handleacc.io.write(teststr, None)
if (handleacc.wait(timeout = 10000000) == 0):
    raise HandlerException("Timeout waiting for acc data")

# Now finish the connection successfully
handlecon.set_expect_open()
handleacc.set_expect_read("x") # \n doesn't get echoed.
handleacc.io.write("x\n", None)
if (handleacc.wait(timeout = 1000) == 0):
    raise HandlerException("Timeout waiting for acc close data")

if (handlecon.wait(timeout = 1000) == 0):
    raise HandlerException("Connection did not open")

# Transfer some data to make sure that is working
handleacc.set_expect_read("Test String1")
handlecon.io.write("Test String1", None)
if (handleacc.wait(timeout = 1000) == 0):
    raise HandlerException("Timeout waiting for acc data")

handlecon.set_expect_read("test String2")
handleacc.io.write("test String2", None)
if (handlecon.wait(timeout = 1000) == 0):
    raise HandlerException("Timeout waiting for con data")

# Now close it
handleacc.set_expect_read_err("Remote end closed connection")
handlecon.set_expect_close()
con.close(handlecon)
if (handlecon.wait(timeout = 1000) == 0):
    raise HandlerException("Timeout waiting for con close")
if (handleacc.wait(timeout = 1000) == 0):
    raise HandlerException("Timeout waiting for acc close")

del con
del acc
del handleacc.io
del handlecon.io
del handleacc
del handlecon

print("Testing error from script")
# This time cause the script to return an error
handleacc = ScrHandler("acc", o)
acc = gensio.gensio_accepter(o, "tcp,0", handleacc)
acc.startup()
port = acc.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                   gensio.GENSIO_CONTROL_GET,
                   gensio.GENSIO_ACC_CONTROL_LPORT, "0")

handlecon = ScrHandler("con", o)
con = gensio.gensio(o, "script(script=./echotest),tcp,localhost," + port,
                    handlecon)
handlecon.io = con

con.open(handlecon)

if (handleacc.wait(timeout = 10000000) == 0):
    raise HandlerException("Timeout waiting for accepter")
if (handlecon.wait(timeout = 100) != 0):
    raise HandlerException("Got unexpected open on connection")

# Finish the connection causing the script to return an error
handlecon.set_expect_open("Local end closed connection")
handleacc.set_expect_read_err("Remote end closed connection")
handleacc.set_expect_read("e") # \n doesn't get echoed.
handleacc.io.write("e\n", None)
if (handleacc.wait(timeout = 1000) == 0):
    raise HandlerException("Timeout waiting for acc close data")

if (handlecon.wait(timeout = 1000) == 0):
    raise HandlerException("Timeout waiting for con close")
if (handleacc.wait(timeout = 1000) == 0):
    raise HandlerException("Timeout waiting for acc close")

del con
del acc
del handleacc.io
del handlecon.io
del handleacc
del handlecon


del o
test_shutdown()
print("  Success!")
