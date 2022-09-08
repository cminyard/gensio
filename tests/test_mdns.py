#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2020  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

import utils
import gensio
import gensios_enabled
import sys

if not gensios_enabled.check_gensio_enabled("mdns"):
    sys.exit(77)

class mdns_closer:
    def __init__(self):
        self.mdns_closed = False;
        self.watch_closed = False;
        self.waiter = gensio.waiter(utils.o)

    def mdns_close_done(self):
        self.mdns_closed = True;
        self.waiter.wake()

    def mdns_close_watch_done(self):
        self.watch_closed = True;
        self.waiter.wake()

    def wait(self, timeout = 10000):
        return self.waiter.wait_timeout(1, timeout)

def print_mdns(is_add, interface, ipdomain, name, types, domain,
               host, addr, txt):
    if is_add:
        print("New mdns entry:")
    else:
        print("Removed mdns entry:")
    print(" interface: " + str(interface))
    print(" ipdomain: " + str(ipdomain))
    print(" name: " + name)
    print(" type: " + types)
    print(" domain: " + domain)
    print(" host: " + host)
    print(" addr: " + addr)
    if len(txt) > 0:
        print(" txt:")
        for i in txt:
            print("  " + i)

class mdns_handler:
    def __init__(self):
        self.done = False
        self.check = None
        self.printit = True
        self.waiter = gensio.waiter(utils.o)
        self.addr = None

    def mdns_all_for_now(self):
        self.done = True
        print("Done for now!\n")
        return

    def mdns_cb(self, is_add, interface, ipdomain, name, types, domain,
                host, addr, txt):
        self.addr = addr
        if self.printit:
            print_mdns(is_add, interface, ipdomain, name, types, domain,
                       host, addr, txt)
        if self.check:
            if "name" in self.check and self.check["name"] != name:
                raise Exception("Mismatch on name, got %s, expected %s" %
                                (name, self.check["name"]))
            if "type" in self.check and self.check["type"] != types:
                raise Exception("Mismatch on type, got %s, expected %s" %
                                (types, self.check["type"]))
            if "domain" in self.check and self.check["domain"] != domain:
                raise Exception("Mismatch on type, got %s, expected %s" %
                                (domain, self.check["domain"]))
            if "host" in self.check and self.check["host"] != host:
                raise Exception("Mismatch on type, got %s, expected %s" %
                                (host, self.check["host"]))
            if "port" in self.check:
                port = addr.rsplit(",", 1)[1]
                if self.check["port"] != int(port):
                    raise Exception("Mismatch on port, got %s, expected %d" %
                                    (addr, self.check["port"]))
            if "txt" in self.check:
                t = self.check["txt"]
                for i in t:
                    if i not in txt:
                        raise Exception("txt missing field " + i);
            self.check = None
            self.waiter.wake()
        return

    def wait(self):
        return self.waiter.wait_timeout(1, 10000)

print("Testing mdns")
c = mdns_closer()
e = mdns_handler()

print("  Free close")
mdns = gensio.mdns(utils.o)
watch = mdns.add_watch(-1, gensio.GENSIO_NETTYPE_UNSPEC,
                       None, None, None, None, e)
watch.close(c)
if c.wait() == 0:
    raise Exception("Didn't get close in time")
if not c.watch_closed:
    raise Exception("Didn't get watch close")
c.watch_closed = False
mdns.close(c)
if c.wait() == 0:
    raise Exception("Didn't get close in time")
if not c.mdns_closed:
    raise Exception("Didn't get mdns close")
c.mdns_closed = False
del watch
import sys
del mdns

print("  Watch free close")
mdns = gensio.mdns(utils.o)
watch = mdns.add_watch(-1, gensio.GENSIO_NETTYPE_UNSPEC,
                       None, None, None, None, e)
watch.close(c)
if c.wait() == 0:
    raise Exception("Didn't get close in time")
if not c.watch_closed:
    raise Exception("Didn't get watch close")
c.watch_closed = False
del watch
del mdns

print("  Data check")
mdns = gensio.mdns(utils.o)
watch = mdns.add_watch(-1, gensio.GENSIO_NETTYPE_UNSPEC,
                       "=gensiotest_service", '%_gensiotest\..*', None, None, e)
e.check = { "name" : "gensiotest_service",
            "type" : '_gensiotest._tcp',
            "port" : 5000,
            "txt" : ("Hello=yes", "Goodbye=no") }
service = mdns.add_service(-1, gensio.GENSIO_NETTYPE_UNSPEC,
                           "gensiotest_service", '_gensiotest._tcp', None, None,
                           5000, ("Hello=yes", "Goodbye=no"))
if e.wait() == 0:
    raise Exception("Didn't get data in time")
if e.check is not None:
    raise Exception("Didn't get right data")

utils.TestAccept(utils.o, "mdns,gensiotest_service", "tcp,5000",
                 utils.do_small_test, chunksize = 64, get_port=False)

del mdns
del watch
del service
del c
del e
w = gensio.waiter(utils.o)
w.wait_timeout(1, 10)
del w
utils.test_shutdown()
