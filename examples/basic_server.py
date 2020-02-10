#!/usr/bin/python3

# Copyright 2020 Corey Minyard
#
# SPDX-License-Identifier: Apache-2.0
#
# A basic server that receives connections and handles certain strings
# when it sees them.
#
# This is the same as basic_server.c, written in python.
#
# To use this, run:
#   basic_server telnet,tcp,3023
# then telnet to it.
#
# If you type in "hello" is reponds with "bonjour".
#
# If you type in "goodbye" it responds with "au revior" and closes
# the connection.
#
# If you type in "shutdown" it reponds with "adieu pour toujours" and
# shuts down the server.

import gensio
import sys

class Logger:
    def gensio_log(self, level, log):
        print("***%s log: %s" % (level, log))

gensio.gensio_set_log_mask(gensio.GENSIO_LOG_MASK_ALL);
o = gensio.alloc_gensio_selector(Logger())

class IOEvent:
    def __init__(self, io, accev):
        self.io = io
        self.accev = accev
        self.inbuf = ""
        self.outbuf = "Ready\r\n"
        self.in_close = False
        io.set_cbs(self)
        return

    def handle_buf(self, buf):
        if buf == "hello":
            self.outbuf = self.outbuf + "bonjour\r\n"
        elif buf == "goodbye":
            self.outbuf = self.outbuf + "au revior\r\n"
            self.in_close = True
        elif buf == "shutdown":
            self.outbuf = self.outbuf + "adieu pour toujours\r\n"
            self.accev.shutdown(self)
            self.in_close = True
        else:
            self.outbuf = self.outbuf + "Eh?\r\n"

    def read_callback(self, io, err, data, auxdata):
        if err:
            if err != "Remote end closed connection":
                print("read error: %s" % err)
            io.close(self)
            return 0
        self.inbuf = self.inbuf + str(data, 'utf-8')
        self.outbuf = self.outbuf + str(data, 'utf-8')
        self.io.write_cb_enable(True)
        npos = self.inbuf.find("\n")
        if npos == -1:
            npos = self.inbuf.find("\r")
            if npos == -1:
                return len(data)
            self.outbuf = self.outbuf + "\n"
        else:
            self.outbuf = self.outbuf + "\r"
        buf = self.inbuf[:npos]
        self.inbuf = self.inbuf[npos + 1:]
        self.handle_buf(buf)
        return len(data)

    def write_callback(self, io):
        if len(self.outbuf) > 0:
            try:
                count = self.io.write(self.outbuf, None)
            except Exception as E:
                if str(e) != "Remote end closed connection":
                    print("write error: %s" % str(e))
                self.io.close(self)
                return
            self.outbuf = self.outbuf[count:]

        if len(self.outbuf) == 0:
            self.io.write_cb_enable(False)
            if self.in_close:
                self.io.close(self)
        return

    def close_done(self, io):
        self.accev.io_closed(self)

        # Break loops
        self.accev = None
        self.io = None
        return

class AccEvent:
    def __init__(self):
        self.ios = []
        self.waiter = gensio.waiter(o)
        self.in_shutdown = False
        return

    def log(self, acc, level, logval):
        print("gensio acc %s err: %s" % (level, logval))
        return

    def new_connection(self, acc, io):
        if self.in_shutdown:
            # it will free automatically
            return
        ioev = IOEvent(io, self)
        self.ios.append(ioev)
        io.read_cb_enable(True)
        io.write_cb_enable(True)
        return

    def check_finish(self):
        if len(self.ios) == 0 and self.acc is None:
            self.waiter.wake()
        return

    def io_closed(self, ioev):
        i = self.ios.index(ioev)
        del(self.ios[i])
        self.check_finish()
        return

    def shutdown_done(self, acc):
        self.acc = None
        self.check_finish()
        return

    def shutdown(self, ioev):
        if self.in_shutdown:
            return
        self.in_shutdown = True
        self.acc.shutdown(self)
        for i in self.ios:
            if i != ioev:
                # The caller will close itself, let it finish its write
                i.io.close(i)

    def wait(self):
        self.waiter.wait(1)

if len(sys.argv) < 2:
    print("No gensio supplied on commandline")
    sys.exit(1)

accev = AccEvent()
accev.acc = gensio.gensio_accepter(o, sys.argv[1], accev)
accev.acc.startup()

accev.wait()
