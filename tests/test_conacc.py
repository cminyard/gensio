#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio

class TestAcceptConAcc:
    def __init__(self, o, accstr, acc2str, acc3str, tester):
        self.o = o
        self.name = accstr
        self.io1 = None
        self.io2 = None
        self.waiter = gensio.waiter(o)
        gensios_enabled.check_iostr_gensios(accstr)

        self.acc = gensio.gensio_accepter(o, accstr, self);
        self.acc.startup()

        port = self.acc.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                                gensio.GENSIO_CONTROL_GET,
                                gensio.GENSIO_ACC_CONTROL_LPORT, "0")
        acc2str = acc2str + port
        self.acc2 = gensio.gensio_accepter(o, acc2str, self);

        print(" First connection")
        self.expect_connects = True
        self.acc2.startup()
        self.wait()
        tester(self.io1, self.io2)
        self.close()
        print(" Second connection")
        self.wait()
        tester(self.io1, self.io2)

        print(" Disable connections")
        self.expect_connects = False
        self.acc2.set_accept_callback_enable_cb(False, self);
        self.wait();
        self.close()

        # Make sure no connections come in
        if self.waiter.wait_timeout(1, 200) != 0:
            raise Exception("Got wakeup when nothing should happen");

        print(" Re-enable connections")
        self.expect_connects = True
        self.acc2.set_accept_callback_enable(True);
        self.wait()
        tester(self.io1, self.io2)

        print(" Disable connections synchronous")
        self.expect_connects = False
        self.acc2.set_accept_callback_enable_s(False);
        self.close()

        # Make sure no connections come in
        if self.waiter.wait_timeout(1, 200) != 0:
            raise Exception("Got wakeup when nothing should happen");

        print(" Re-enable connections")
        self.expect_connects = True
        self.acc2.set_accept_callback_enable(True);
        self.wait()
        tester(self.io1, self.io2)
        self.acc2.set_accept_callback_enable_s(False);
        self.close()

        print(" Test retry time");
        acc3str = acc3str + port
        self.acc3 = gensio.gensio_accepter(o, acc3str, self);
        self.expect_connects = True
        self.acc3.startup();
        self.wait()
        self.close()

        if self.waiter.wait_timeout(1, 200) != 0:
            raise Exception("Got wakeup when nothing should happen");

        self.expect_connects = True
        self.wait()

        self.acc.shutdown_s()
        self.acc2.shutdown_s()
        self.acc3.shutdown_s()
        self.acc = None
        self.acc2 = None
        self.acc3 = None
        self.close()

    def close(self):
        io1 = self.io1
        io2 = self.io2
        self.io1 = None
        self.io2 = None
        io1.read_cb_enable(False)
        if io2:
            io2.read_cb_enable(False)
        io_close((io1, io2))

    def set_accept_callback_done(self, acc):
        self.waiter.wake()

    def new_connection(self, acc, io):
        if not self.expect_connects:
            raise Exception("Connect when unexpected");

        if self.io1 is None:
            self.io1 = io
            self.io1_hand = HandleData(self.o, None, io = io, name = "io1")
        elif self.io2 is None:
            self.io2 = io
            self.io2_hand = HandleData(self.o, None, io = io, name = "io2")
        else:
            raise Exception("Got too many connections");

        if self.io1 and self.io2:
            self.waiter.wake()

    def accepter_log(self, acc, level, logstr):
        print("***%s LOG: %s: %s" % (level, self.name, logstr))

    def wait(self):
        if self.waiter.wait_timeout(1, 5000) == 0:
            raise Exception("test_conacc: Timed out");

print("Test conacc")
TestAcceptConAcc(o, "tcp,0", "conacc,tcp,localhost,",
                 "conacc(retry-time=1000),tcp,localhost,", do_small_test)
del o
test_shutdown()
