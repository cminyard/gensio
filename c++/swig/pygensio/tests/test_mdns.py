#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

# Test mdns interfaces

import sys
import gensios_enabled
if not gensios_enabled.check_gensio_enabled("mdns"):
    sys.exit(77)

from testbase import *
import pygensio

class Free_Done(pygensio.MDNS_Free_Done):
    def __init__(self, waiter):
        pygensio.MDNS_Free_Done.__init__(self)
        self.waiter = waiter
        return

    def mdns_free_done(self):
        self.waiter.wake()
        return

class Watch_Free_Done(pygensio.MDNS_Watch_Free_Done):
    def __init__(self, waiter):
        pygensio.MDNS_Watch_Free_Done.__init__(self)
        self.waiter = waiter
        return

    def mdns_watch_free_done(self):
        self.waiter.wake()
        return

class Watch_EvHnd(pygensio.MDNS_Watch_Event):
    def __init__(self, waiter):
        pygensio.MDNS_Watch_Event.__init__(self)
        self.waiter = waiter
        self.watch_count = 0
        self.found = False
        return

    def event(self, state, interfacenum, ipdomain,
              name, mtype, domain, host, addr, txt):
        self.watch_count += 1
        if state == pygensio.GENSIO_MDNS_WATCH_ALL_FOR_NOW:
            # Don't use this for anything, it's unreliable
            return
        if self.found:
            return
        if state == pygensio.GENSIO_MDNS_WATCH_NEW_DATA:
            self.found = True
            self.waiter.wake()
        return

class Service_EvHnd(pygensio.MDNS_Service_Event):
    def __init__(self, waiter):
        pygensio.MDNS_Service_Event.__init__(self)
        self.waiter = waiter
        return

    def event(self, ev, info):
        if ev == pygensio.GENSIO_MDNS_SERVICE_REMOVED:
            self.waiter.wake()
        elif ev == pygensio.GENSIO_MDNS_SERVICE_ERROR:
            print("Error: " + info)
        else:
            print("Service name: " + info);
            self.waiter.wake()
        return

waiter = pygensio.Waiter(o)
waiter2 = pygensio.Waiter(o)
m = pygensio.MDNS(o)
e = Watch_EvHnd(waiter)
w = m.add_watch(-1,  pygensio.GENSIO_NETTYPE_UNSPEC, None,
                "=_gensio_pytest._tcp", None, None, e)
se = Service_EvHnd(waiter2)
s = m.add_service(-1, pygensio.GENSIO_NETTYPE_UNSPEC, "gensio1",
                  "_gensio_pytest._tcp", None, None, 5001,
                  ("A=1", "B=2"), se)
rv = waiter.wait(1, pygensio.gensio_time(5,0))
if rv != 0:
    raise Exception("Error waiting for mdns service: " +
                    pygensio.err_to_string(rv))

if not e.found:
    raise Exception("mdns watch not found")

wfh = Watch_Free_Done(waiter)
w.free(wfh)
rv = waiter.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for mdns watch free: " +
                    pygensio.err_to_string(rv))
del wfh

s.free()
rv = waiter2.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for mdns service free: " +
                    pygensio.err_to_string(rv))
del s

mfh = Free_Done(waiter)
m.free(mfh)
rv = waiter.wait(1, pygensio.gensio_time(1, 0))
if rv != 0:
    raise Exception("Error waiting for mdns free: " +
                    pygensio.err_to_string(rv))
del mfh

del se
del e
del waiter
del waiter2
del o

test_shutdown()

print("Pass")
sys.exit(0)

