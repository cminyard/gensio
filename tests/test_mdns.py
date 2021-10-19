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

    def mdns_close_done(self):
        self.mdns_closed = True;

    def mdns_close_watch_done(self):
        self.watch_closed = True;

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
        self.print = False

    def mdns_all_for_now(self):
        self.done = True
        print("Done for now!\n")
        return

    def mdns_cb(self, is_add, interface, ipdomain, name, types, domain,
                host, addr, txt):
        if self.print:
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
        return

print("Testing mdns")

print("  Free close")
waiter = gensio.waiter(utils.o)
e = mdns_handler()
c = mdns_closer()
mdns = gensio.mdns(utils.o)
watch = mdns.add_watch(-1, gensio.GENSIO_NETTYPE_UNSPEC,
                       None, None, None, None, e)
mdns.close(c)
del watch
while not c.mdns_closed:
    if waiter.service(10000) == 0:
        raise Exception("Didn't get close in time")
c.mdns_closed = False

print("  Watch free close")
mdns = gensio.mdns(utils.o)
watch = mdns.add_watch(-1, gensio.GENSIO_NETTYPE_UNSPEC,
               None, None, None, None, e)
watch.close(c)
while not c.watch_closed:
    if waiter.service(10000) == 0:
        raise Exception("Didn't get close in time")
c.watch_closed = False

print("  Data check")
mdns = gensio.mdns(utils.o)
watch = mdns.add_watch(-1, gensio.GENSIO_NETTYPE_UNSPEC,
               None, '%_gensiotest\.*', None, None, e)
service = mdns.add_service(-1, gensio.GENSIO_NETTYPE_UNSPEC,
                           "gensiotest_service", '_gensiotest._tcp', None, None,
                           5000, ("Hello=yes", "Goodbye=no"))
e.check = { "name" : "gensiotest_service",
            "type" : '_gensiotest._tcp',
            "port" : 5000,
            "txt" : ("Hello=yes", "Goodbye=no") }
while e.check is not None:
    if waiter.service(10000) == 0:
        raise Exception("Didn't get all data in time")

print("  Success!")
