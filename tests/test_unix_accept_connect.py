#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

from utils import *
import gensio
import gensios_enabled
import os
import pwd
import grp

print("Test unix accepter connect")
TestAcceptConnect(o, "unix,/tmp/gensiotest", "unix,/tmp/gensiotest2",
                  "unix,/tmp/gensiotest",
                  do_small_test, use_port = False)

def test_permission_denied(perms):
    p = "unix(" + perms + "),/tmp/gensiotest"
    print("Testing permission denied for " + p);
    q1 = OpEventQueue(o)
    q2 = OpEventQueue(o)

    h = AccHandler(o, "wait1", evq = q1)
    acc = gensio.gensio_accepter(o, p, h)
    acc.startup()
    gen = alloc_io(o, "unix,/tmp/gensiotest", evq = q2)
    gen.read_cb_enable(True)
    (ev, timeout) = q2.wait()
    if timeout == 0:
        acc.shutdown_s()
        raise Exception("Error, no permission denied close.")
    if ev.op != "close":
        acc.shutdown_s()
        raise Exception("Error, connection didn't close: " + str(ev))

    (ev, timeout) = q1.wait()
    if (ev.op != "accepter_log" or ev.obj2[0] != "info" or
        ev.obj2[1] != 'Error accepting unix gensio: user not permitted'):
        acc.shutdown_s()
        raise Exception("Error, bad accepter event: " + str(ev))
    acc.shutdown_s()
    del h.opobj
    del h.evq
    gen.handler.close()
    (ev, timeout) = q2.wait()
    if timeout == 0:
        acc.shutdown_s()
        raise Exception("Error, no close done.")
    if ev.op != "close_done":
        raise Exception("Error, not close_done: " + str(ev))

    del gen.handler.io
    del gen.handler.evq
    del gen.handler
    print("  Success!")

if gensios_enabled.have_ucred == 1:
    pwe = pwd.getpwuid(os.getuid())
    uname = pwe.pw_name
    g = grp.getgrgid(pwe.pw_gid)
    ugrp = g.gr_name

    TestAccept(o, "unix,/tmp/gensiotest",
               "unix(permusers=" + uname + "),/tmp/gensiotest",
               do_small_test, get_port = False)

    TestAccept(o, "unix,/tmp/gensiotest",
               "unix(permgrps=" + ugrp + "),/tmp/gensiotest",
               do_small_test, get_port = False)

    test_permission_denied("permgrps=blablabla")
    test_permission_denied("permusers=blablabla")

del o
test_shutdown()
