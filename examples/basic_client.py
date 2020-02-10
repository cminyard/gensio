#!/usr/bin/python3

# Copyright 2020 Corey Minyard
#
# SPDX-License-Identifier: Apache-2.0
#
# A basic client that talks to the basic server.  It sends the string
# given in argv[2] and waits for three lines from the server, printing
# them all out.
#
# To use this, run:
#   basic_server telnet,tcp,3023 <string>

import gensio
import sys

class Logger:
    def gensio_log(self, level, log):
        print("***%s log: %s" % (level, log))

gensio.gensio_set_log_mask(gensio.GENSIO_LOG_MASK_ALL);
o = gensio.alloc_gensio_selector(Logger())

class IOEvent:
    def __init__(self, outbuf):
        self.outbuf = outbuf + "\n"
        self.in_close = False
        self.incount = 0
        self.waiter = gensio.waiter(o)
        return

    def read_callback(self, io, err, data, auxdata):
        if self.in_close:
            return len(data)
        if err:
            if err != "Remote end closed connection":
                print("read error: %s" % err)
            io.close(self)
            return 0
        inbuf = str(data, 'utf-8')
        self.io.write_cb_enable(True)
        npos = inbuf.find("\n")
        if npos == -1:
            npos = len(inbuf)
        else:
            inbuf = inbuf[:npos]
            npos += 1
            self.incount += 1
            if self.incount >= 3:
                self.in_close = True
                self.io.close(self)
        print(inbuf)
        return npos

    def write_callback(self, io):
        if len(self.outbuf) > 0:
            try:
                count = self.io.write(self.outbuf, None)
            except Exception as E:
                if str(e) != "Remote end closed connection":
                    print("write error: %s" % str(e))
                self.in_close = True
                self.io.close(self)
                return
            self.outbuf = self.outbuf[count:]

        if len(self.outbuf) == 0:
            self.io.write_cb_enable(False)
        return

    def open_done(self, io, err):
        if err:
            print("open error: %s" % err)
            self.io.close(self)
            return
        self.io.write_cb_enable(True)
        self.io.read_cb_enable(True)
        return

    def close_done(self, io):
        self.waiter.wake()
        # Break loop
        self.io = None
        return

    def wait(self):
        self.waiter.wait(1)
        return

if len(sys.argv) < 2:
    print("No gensio supplied on commandline")
    sys.exit(1)

if len(sys.argv) < 3:
    print("No string supplied on commandline")
    sys.exit(1)

ioev = IOEvent(sys.argv[2])
ioev.io = gensio.gensio(o, sys.argv[1], ioev)
ioev.io.open(ioev)

ioev.wait()
