#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

import utils
import gensio
import gensios_enabled

class Logger:
    def gensio_log(self, level, log):
        print("***%s log: %s" % (level, log))

def test_sync_gensio(o):
    print("Testing basic sync I/O")

    gensios_enabled.check_iostr_gensios("echo")
    g = gensio.gensio(o, "echo(readbuf=10)", None)
    g.set_sync()
    g.open_s()

    # Basic write then read
    (count, time) = g.write_s("Hello", 1000)
    if count != 5 or time < 500:
        raise Exception("Invalid write return: %d %d\n" % (count, time))
    (buf, time) = g.read_s(10, 1000)
    buf = buf.decode(encoding='utf8')
    if buf != "Hello" or time < 500:
        raise Exception("Invalid read return: '%s' %d\n" % (buf, time))

    # This should time out, no data
    (buf, time) = g.read_s(10, 250)
    buf = buf.decode(encoding='utf8')
    if buf != "" or time != 0:
        raise Exception("Invalid read timeout return: '%s' %d\n" % (buf, time))

    # This should time out, buffer is only 10 bytes per readbuf above
    (count, time) = g.write_s("HelloHelloHello", 250)
    if count != 10 or time != 0:
        raise Exception("Invalid write timeout return: %d %d\n" % (count, time))

    # Read out what should have been written
    time = 1000
    buf = ""
    while len(buf) < 10 and time >= 500:
        (tbuf, time) = g.read_s(10, time)
        buf = buf + tbuf.decode(encoding='utf8')

    if buf != "HelloHello" or time < 500:
        raise Exception("Invalid read return(2): '%s' %d\n" % (buf, time))

    # This should time out, no data
    (buf, time) = g.read_s(10, 250)
    buf = buf.decode(encoding='utf8')
    if buf != "" or time != 0:
        raise Exception("Invalid read timeout return: '%s' %d\n" % (buf, time))

    g.close_s()
    return

class SyncEvent:
    def __init__(self):
        self.opened = False
        return

    def read_callback(self, io, err, data, auxdata):
        return len(data)

    def write_callback(self, io):
        io.write_callback_enable(false);
        return

    def open_done(self, io, err):
        if err:
            raise Exception("accept_s_timeout open error: " + err);
        self.opened = True
        return

def test_sync_gensio_accepter(o):
    print("Testing sync accept")

    gensios_enabled.check_iostr_gensios("tcp")
    a = gensio.gensio_accepter(o, "tcp,0", None)
    a.set_sync()
    a.startup()
    port = a.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                     gensio.GENSIO_CONTROL_GET,
                     gensio.GENSIO_ACC_CONTROL_LPORT, "0")

    sa = SyncEvent()
    (io, time) = a.accept_s_timeout(o, sa, 1)
    if io != None or time != 0:
        raise Exception("accept_s_timeout didn't time out");

    sg = SyncEvent()
    gensios_enabled.check_iostr_gensios("tcp")
    g = gensio.gensio(o, "tcp,localhost," + port, sg)
    g.open(sg)

    (io, time) = a.accept_s_timeout(o, sa, 1000)
    if io == None or time == 0:
        raise Exception("accept_s_timeout timed out");

    io.close_s()
    g.close_s()
    a.shutdown_s()
    return

import utils

test_sync_gensio(utils.o)
test_sync_gensio_accepter(utils.o)
utils.test_shutdown()
