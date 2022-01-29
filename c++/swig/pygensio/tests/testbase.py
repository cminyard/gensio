#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

import sys
import os
import pygensio

# Allocate an OS handler
class Logger(pygensio.Os_Funcs_Log_Handler):
    def __init__(self):
        pygensio.Os_Funcs_Log_Handler.__init__(self)
        return

    def log(self, level, s):
        print("Log")
        try:
            print(pygensio.log_level_to_str(level).upper() + " LOG: " +
                  s.encode('utf-8', 'surrogateescape').decode('ISO-8859-1'))
        except:
            print("Log error")
        return

l = Logger()
oshndname = os.getenv("GENSIO_TEST_OS_HANDLER")
if oshndname is None or oshndname == "default":
    o = pygensio.Os_Funcs(0, l);
elif oshndname == "glib":
    import pygensioglib
    o = pygensioglib.Glib_Os_Funcs(l);
elif oshndname == "tcl":
    import pygensiotcl
    o = pygensiotcl.Tcl_Os_Funcs(l);
else:
    print("Unknown OS handler name: " + oshndname)
    sys.exit(1)
del l

class Refl_EvHnd(pygensio.Event):
    def __init__(self, w):
        pygensio.Event.__init__(self)
        self.data = None
        self.g = None
        self.w = w
        return

    def set_gensio(self, g):
        self.g = g
        return

    def read(self, err, data, auxdata):
        self.g.set_read_callback_enable(False)
        if err != 0:
            if err != pygensio.GE_REMCLOSE:
                raise Exception("Error from reflector event read: " +
                                pygensio.err_to_string(err))
            self.g = None
            self.w.wake()
            return 0
        self.data = data
        self.g.set_write_callback_enable(True)
        return len(data)

    def write_ready(self):
        if self.data is None:
            self.g.set_write_callback_enable(False)
            return
        count = self.g.write(self.data, None)
        if count == len(self.data):
            self.data = None
            self.g.set_write_callback_enable(False)
            self.g.set_read_callback_enable(True)
        else:
            self.data = self.data[count:]
        return

class Refl_Acc_EvHnd(pygensio.Accepter_Event):
    def __init__(self):
        pygensio.Accepter_Event.__init__(self)
        return

    def set_reflector(self, r):
        self.r = r
        return

    def new_connection(self, g):
        self.r.new_connection(g)
        return;

class Refl_Acc_Shutdown(pygensio.Accepter_Shutdown_Done):
    def __init__(self, r):
        pygensio.Accepter_Shutdown_Done.__init__(self)
        self.r = r
        return

    def shutdown_done(self):
        self.r.shutdown_done()
        return

class Refl_Acc_Enable(pygensio.Accepter_Enable_Done):
    def __init__(self, r):
        pygensio.Accepter_Enable_Done.__init__(self)
        self.r = r
        return

    def enable_done(self):
        self.r.enable_done()
        return

class Reflector:
    def __init__(self, o, accstr, evh = None, w = None, acc_evh = None):
        self.o = o
        if acc_evh is None:
            self.e = Refl_Acc_EvHnd()
        else:
            self.e = acc_evh
        self.e.set_reflector(self)
        self.acc = pygensio.gensio_acc_alloc(accstr, o, self.e)
        if w is None:
            self.w = pygensio.Waiter(o)
        else:
            self.w = w
        self.g = None
        if evh is None:
            self.h = Refl_EvHnd(self.w)
        else:
            self.h = evh
        return

    def startup(self):
        self.acc.startup()
        return

    def new_connection(self, g):
        if self.g is not None:
            raise Exception("New connection while connected")
        self.g = g
        self.h.set_gensio(g)
        self.g.set_event_handler(self.h)
        self.g.set_read_callback_enable(True)
        return

    def set_enable(self, val, do_cb = True):
        if do_cb:
            h = Refl_Acc_Enable(self)
            self.acc.set_callback_enable(val, h)
        else:
            self.acc.set_callback_enable(val, None)
        return

    def set_enable_s(self, val):
        self.acc.set_callback_enable_s(val)
        return

    def enable_done(self):
        self.w.wake()
        return

    def shutdown(self):
        h = Refl_Acc_Shutdown(self)
        self.acc.shutdown(h)
        return

    def shutdown_done(self):
        self.w.wake()
        self.del_links()
        return

    def shutdown_s(self):
        self.acc.shutdown_s()
        self.del_links()
        return

    def del_links(self):
        self.g = None
        self.acc = None
        self.h = None
        self.e = None
        return

    def wait(self, timeout = None):
        return self.w.wait(2, timeout)

    def wait1(self, timeout = None):
        return self.w.wait(1, timeout)

    def get_port(self):
        return self.acc.get_port()

class Open_Done(pygensio.Gensio_Open_Done):
    def __init__(self, w):
        pygensio.Gensio_Open_Done.__init__(self)
        self.err = None
        self.w = w
        return

    def open_done(self, err):
        self.err = err
        self.w.wake()

class Close_Done(pygensio.Gensio_Close_Done):
    def __init__(self, w):
        pygensio.Gensio_Close_Done.__init__(self)
        self.w = w
        return

    def close_done(self):
        self.w.wake()

class EvHnd(pygensio.Event):
    def __init__(self, o):
        pygensio.Event.__init__(self)
        self.data = None
        self.g = None
        self.w = pygensio.Waiter(o)
        return

    def set_gensio(self, g):
        self.g = g
        return

    def read(self, err, data, auxdata):
        readlen = len(data)
        if readlen + self.readpos > len(self.data):
            raise Exception("Read too much data")
        if data != self.data[self.readpos:self.readpos + readlen]:
            raise Exception("Data mismatch")
        self.readpos = self.readpos + readlen
        if self.readpos == len(self.data):
            self.w.wake()
            self.g = None
        return len(data)

    def write_ready(self):
        if self.data is None or self.writepos >= len(self.data):
            self.g.set_write_callback_enable(False)
            return
        count = self.g.write(self.data[self.writepos:], None)
        self.writepos = self.writepos + count
        if self.writepos == len(self.data):
            self.g.set_write_callback_enable(False)
        return

    def set_data(self, d):
        self.data = d
        self.readpos = 0
        self.writepos = 0
        self.g.set_read_callback_enable(True)
        self.g.set_write_callback_enable(True)
        return

    def wait(self, count = 1, timeout = None):
        return self.w.wait(count, timeout)

def conv_to_bytes(s):
    if (isinstance(s, str)):
        return bytes(s, "utf-8")
    else:
        return s

def conv_from_bytes(b):
    return str(b, "utf-8")

def verify_acc(acc, acctype, is_reliable, is_packet, is_message):
    if acc.get_type(0) != acctype:
        raise Exception("Accepter type incorrect, expected %s, got %s" %
                        (acctype, r.acc.get_type(0)))
    if acc.is_reliable() != is_reliable:
        raise Exception("Accepter is_reliable incorrect, expect %s, got %s" %
                        (is_reliable, acc.is_reliable()))
    if acc.is_packet() != is_packet:
        raise Exception("Accepter is_packet incorrect, expect %s, got %s" %
                        (is_packet, acc.is_packet()))
    if acc.is_message():
        raise Exception("Accepter is_message incorrect, expect %s, got %s" %
                        (is_message, acc.is_message()))

def verify_gen(g, gtype, is_client, is_reliable, is_packet,
               is_authenticated, is_encrypted, is_message):
    if g.get_type(0) != gtype:
        raise Exception("Gensio type incorrect, expected %s, got %s" %
                        (gentype, g.get_type(0)))
    if g.is_client() != is_client:
        raise Exception("Gensio is_client incorrect, expect %s, got %s" %
                        (is_client, g.is_client()))
    if g.is_reliable() != is_reliable:
        raise Exception("Gensio is_reliable incorrect, expect %s, got %s" %
                        (is_reliable, g.is_reliable()))
    if g.is_packet() != is_packet:
        raise Exception("Gensio is_packet incorrect, expect %s, got %s" %
                        (is_packet, g.is_packet()))
    if g.is_authenticated() != is_authenticated:
        raise Exception("Gensio is_authenticated incorrect, expect %s, got %s" %
                        (is_authenticated, g.is_authenticated()))
    if g.is_encrypted() != is_encrypted:
        raise Exception("Gensio is_encrypted incorrect, expect %s, got %s" %
                        (is_encrypted, g.is_encrypted()))
    if g.is_message():
        raise Exception("Gensio is_message incorrect, expect %s, got %s" %
                        (is_message, g.is_message()))

def test_shutdown():
    global o
    w = pygensio.Waiter(o)
    count = 0
    while pygensio.gensio_num_alloced() > 0:
        count += 1
        if (count > 100):
            raise Exception("All gensios were not freed in time, %d left" %
                            pygensio.gensio_num_alloced())
        w.service(pygensio.gensio_time(0, 1000000))
    while w.service(pygensio.gensio_time(0, 0)) == 0:
        # Give some time for everyting to clear out.
        pass
    del w
    o.set_log_handler(None)
    c = sys.getrefcount(o)
    if c != 2:
        raise Exception("OS object refcount was %d, not 2" % c)
    c = o.get_refcount()
    if c != 1:
        raise Exception("OS funcs refcount was %d, not 1" % c)
    o.cleanup_mem()
    del o
