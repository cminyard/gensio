#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

#
# gensio test utilities
#
# This file contains some classes and functions useful for testing
# gensio handling
#

import os
import gensio
import tempfile
import signal
import time
import curses.ascii
import sys
import sysconfig
import gensios_enabled

debug = 0

def conv_to_bytes(s):
    if (sysconfig.get_python_version() >= "3.0"):
        if (isinstance(s, str)):
            return bytes(s, "utf-8")
        else:
            return s
    else:
        return s

class HandlerException(Exception):
    """Exception for HandleData errors"""

    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return repr(self.value)
    def __str__(self):
        return str(self.value)

def find_sergensio(io):
    sio = io.cast_to_sergensio();
    while sio is None:
        io = io.child(0)
        sio = io.cast_to_sergensio();
    return sio

class HandleData:
    """Data handler for testing gensio.

    This is designed to handle input and output from gensio.  To write
    data, call set_write_data() to set some data and write it.  To wait
    for data to be read, call set_compare() to wait for the given data
    to be read.

    This just starts things up and runs asynchronously.  You can wait
    for a completion with wait() or wait_timeout().

    The io handler is in the io attribute of the object.  The handler
    object of that io will be this object.
    """

    def __init__(self, o, iostr, name = None, chunksize=10240,
                 io = None, password = None, expect_remclose = True,
                 val_2fa = None):
        """Start a gensio object with this handler"""
        if (name):
            self.name = name
        else:
            self.name = iostr
        self.waiter = gensio.waiter(o)
        self.to_write = None
        self.compared = 0
        self.to_compare = None
        self.compared_oob = 0
        self.to_compare_oob = None
        self.to_waitfor = None
        self.expecting_modemstate = False
        self.expecting_linestate = False
        self.expecting_remclose = expect_remclose
        self.expected_server_cb = None
        self.expected_server_value = 0
        self.expected_server_return = 0
        self.expected_sig_server_cb = False
        self.expected_sig_server_val = None
        self.ignore_input = False
        self.waiting_rem_close = False
        self.stream = None
        self.password = password
        self.val_2fa = val_2fa
        if (io):
            self.io = io
            io.set_cbs(self)
        else:
            gensios_enabled.check_iostr_gensios(iostr)
            self.io = gensio.gensio(o, iostr, self)
        self.io.handler = self
        self.chunksize = chunksize
        self.debug = 0
        return

    def set_compare(self, to_compare, start_reader = True, stream = None,
                    auxdata = None):
        """Set some data to compare

        If start_reader is true (default), it enable the read callback.
        If the data does not compare, an exception is raised.
        """
        self.compared = 0
        self.stream = stream
        self.compare_auxdata = auxdata
        self.to_compare = conv_to_bytes(to_compare);
        if (start_reader):
            self.io.read_cb_enable(True)
        return

    def set_compare_oob(self, to_compare, start_reader = True, stream = None,
                        auxdata = None):
        """Set some oob data to compare

        If start_reader is true (default), it enable the read callback.
        If the data does not compare, an exception is raised.
        """
        self.compared_oob = 0
        self.stream = stream
        self.compare_auxdata = auxdata
        self.to_compare_oob = conv_to_bytes(to_compare)
        if (start_reader):
            self.io.read_cb_enable(True)
        return

    def set_waitfor(self, waitfor, start_reader = True):
        """Wait for the given string to come in

        If start_reader is true (default), it enable the read callback.
        If the data does not compare, an exception is raised.
        """
        self.compared = 0
        self.to_waitfor = conv_to_bytes(waitfor)
        if (start_reader):
            self.io.read_cb_enable(True)
        return

    def set_write_data(self, to_write, start_writer = True,
                       close_on_done = False, auxdata = None):
        self.close_on_done = close_on_done
        self.wrpos = 0
        self.wrlen = len(to_write)
        self.to_write = conv_to_bytes(to_write)
        self.write_auxdata = auxdata
        if (start_writer):
            self.io.write_cb_enable(True)
        return

    def close(self):
        self.ignore_input = True
        self.io.close(self)
        return

    def wait(self):
        self.waiter.wait(1)

    def wait_timeout(self, timeout):
        return self.waiter.wait_timeout(1, timeout)


    # Everything below here is internal handling functions.

    def read_callback(self, io, err, buf, auxdata):
        if self.to_compare:
            iolen = len(self.to_compare)
        elif self.to_waitfor:
            iolen = len(self.to_waitfor)
        else:
            iolen = None

        if (debug or self.debug) and iolen != None and buf is not None:
            print("%s: Got %d bytes at pos %d of %d" % (self.name, len(buf),
                                                        self.compared, iolen))
        if ((debug >= 2 or self.debug >= 2) and not err):
            s = ""
            for i in range(0, len(buf)):
                if curses.ascii.isprint(buf[i]):
                    if (sysconfig.get_python_version() >= "3.0"):
                        s = s + str(buf[i:i+1], "utf-8")
                    else:
                        s = s + str(buf[i:i+1])
                else:
                    s = s + "\\x%2.2x" % ord(buf[i:i+1])
            print("%s: Got data: (err %s %d bytes) %s" % (self.name, str(err),
                                                          len(buf), s))
        if self.expecting_remclose and err == "Remote end closed connection":
            if (self.waiting_rem_close):
                self.waiter.wake()
            io.read_cb_enable(False)
            return 0
        if (err):
            raise HandlerException(self.name + ": read: " + err)
        if (self.ignore_input):
            return len(buf)

        if (self.to_waitfor):
            for i in range(0, len(buf)):
                if buf[i] == self.to_waitfor[self.compared]:
                    self.compared += 1
                    if (len(self.to_waitfor) == self.compared):
                        self.to_waitfor = None
                        io.read_cb_enable(False)
                        self.waiter.wake()
                else:
                    self.compared = 0
            return len(buf)

        oob = False;
        stream = 0

        if (self.compare_auxdata is not None):
            if not auxdata:
                raise HandlerException("%s: no auxdata, expected %s" %
                                       (self.name, str(self.compare_auxdata)))
            if len(auxdata) != len(self.compare_auxdata):
                raise HandlerException(
                    "%s: length mismatch in auxdata, expected %s, got %s" %
                    (self.name, str(self.compare_auxdata), str(auxdata)))

            for i in range(0, len(auxdata)):
                if auxdata[i] != self.compare_auxdata[i]:
                    raise HandlerException(
                        "%s: auxdata item %d wrong, expected %s, got %s" %
                        (self.name, i, str(self.compare_auxdata), str(auxdata)))

        if auxdata:
            for i in auxdata:
                if i == "oob":
                    oob = True
                elif i[0:7] == "stream=":
                    stream = int(i[7:])

        if self.stream and stream != self.stream:
            raise HandlerException("%s: stream mismatch, expected %d, got %d " %
                                       (self.name, self.stream, stream))
        if not self.stream and stream != 0:
            raise HandlerException("%s: not expecting stream, got %d " %
                                       (self.name, stream))

        if oob:
            if not self.to_compare_oob:
                if (debug):
                    print(self.name +
                          ": Got oob data, but nothing to compare")
                io.read_cb_enable(False)
                return len(buf)
            compared = self.compared_oob
            compare_with = self.to_compare_oob
            oob = "oob "
        else:
            if not self.to_compare:
                if (debug):
                    print(self.name + ": Got data, but nothing to compare")
                io.read_cb_enable(False)
                return len(buf)
            compared = self.compared
            compare_with = self.to_compare
            oob = ""

        if (len(buf) > len(compare_with)):
            count = len(compare_with)
        else:
            count = len(buf)

        if count > self.chunksize:
            count = self.chunksize

        for i in range(0, count):
            if (buf[i] != compare_with[compared]):
                raise HandlerException("%s: %scompare failure on byte %d, "
                                       "expected %x, got %x" %
                                       (self.name, oob, compared,
                                        compare_with[compared],
                                        buf[i]))
            compared += 1

        if oob == "oob ":
            self.compared_oob = compared
            if (self.compared_oob >= len(self.to_compare_oob)):
                self.to_compare_oob = None
                io.read_cb_enable(False)
                self.waiter.wake()
        else:
            self.compared = compared
            if (self.compared >= len(self.to_compare)):
                self.to_compare = None
                io.read_cb_enable(False)
                self.waiter.wake()

        return count

    def write_callback(self, io):
        if (not self.to_write):
            if (debug or self.debug):
                print(self.name + ": Got write, but no data")
            io.write_cb_enable(False)
            return

        if (self.wrpos + self.chunksize > self.wrlen):
            wrdata = self.to_write[self.wrpos:]
        else:
            wrdata = self.to_write[self.wrpos:self.wrpos + self.chunksize]
        count = io.write(wrdata, self.write_auxdata)
        if (debug or self.debug):
            print(self.name + ": wrote %d bytes" % count)

        if (count + self.wrpos >= self.wrlen):
            io.write_cb_enable(False)
            if (self.close_on_done):
                self.io.closeme = False
                self.close()
            self.to_write = None
            self.waiter.wake()
        else:
            self.wrpos += count
        return

    def request_password(self, io):
        if self.password is None:
            return gensio.ENOTSUP
        return self.password

    def request_2fa(self, io):
        if self.val_2fa is None:
            return gensio.ENOTSUP
        return self.val_2fa

    def set_expecting_oob(self, data):
        self.to_compare_oob = data
        return

    def modemstate(self, io, modemstate):
        if (not self.expecting_modemstate):
            if (debug or self.debug):
                print("Got unexpected modemstate for %s: %x" %
                      (self.name, modemstate))
            return
        if (modemstate != self.expected_modemstate):
            raise HandlerException("%s: Expecting modemstate 0x%x, got 0x%x" %
                                   (self.name, self.expected_modemstate,
                                    modemstate))
        self.expecting_modemstate = False
        self.waiter.wake()
        return

    def set_expected_modemstate(self, modemstate):
        self.expecting_modemstate = True
        self.expected_modemstate = modemstate
        return

    def linestate(self, io, linestate):
        if (not self.expecting_linestate):
            if (debug or self.debug):
                print("Got unexpected linestate %x" % linestate)
            return
        if (linestate != self.expected_linestate):
            raise HandlerException("%s: Expecting linestate 0x%x, got 0x%x" %
                                   (self.name, self.expected_linestate,
                                    linestate))
        self.expecting_linestate = False
        self.waiter.wake()
        return

    def set_expected_linestate(self, linestate):
        self.expecting_linestate = True
        self.expected_linestate = linestate
        return

    def set_expected_server_cb(self, name, value, retval):
        self.expected_server_cb = name
        self.expected_server_value = value
        self.expected_server_return = retval
        return

    def set_expected_client_cb(self, name, value):
        self.expected_server_cb = name
        self.expected_server_value = value
        return

    def check_set_expected_telnet_cb(self, name, value):
        if not self.expected_server_cb:
            if (debug or self.debug):
                print("Got unexpected server cb: %s %d" % (name, value))
            return False
        if self.expected_server_cb != name:
            raise HandlerException(
                "Got wrong server cb, expected %s, got %s (%d)" %
                (self.expected_server_cb, name, value))
        if self.expected_server_value != value:
            raise HandlerException(
                "Got wrong server cb value for %s, expected %d, got %d" %
                (name, self.expected_server_value, value))
        self.waiter.wake()
        return True

    def baud(self, sio, err, baud):
        if not self.check_set_expected_telnet_cb("baud", baud):
            return
        return

    def datasize(self, sio, err, datasize):
        if not self.check_set_expected_telnet_cb("datasize", datasize):
            return
        return

    def parity(self, sio, err, parity):
        if not self.check_set_expected_telnet_cb("parity", parity):
            return
        return

    def stopbits(self, sio, err, stopbits):
        if not self.check_set_expected_telnet_cb("stopbits", stopbits):
            return
        return

    def flowcontrol(self, sio, err, flowcontrol):
        if not self.check_set_expected_telnet_cb("flowcontrol", flowcontrol):
            return
        return

    def iflowcontrol(self, sio, err, iflowcontrol):
        if not self.check_set_expected_telnet_cb("iflowcontrol", iflowcontrol):
            return
        return

    def sbreak(self, sio, err, sbreak):
        if not self.check_set_expected_telnet_cb("sbreak", sbreak):
            return
        return

    def dtr(self, sio, err, dtr):
        if not self.check_set_expected_telnet_cb("dtr", dtr):
            return
        return

    def rts(self, sio, err, rts):
        if not self.check_set_expected_telnet_cb("rts", rts):
            return
        return

    def sbaud(self, io, baud):
        sio = find_sergensio(io)
        if not self.check_set_expected_telnet_cb("baud", baud):
            return
        sio.sg_baud(self.expected_server_return, None)
        return

    def sdatasize(self, io, datasize):
        sio = find_sergensio(io)
        if not self.check_set_expected_telnet_cb("datasize", datasize):
            return
        sio.sg_datasize(self.expected_server_return, None)
        return

    def sparity(self, io, parity):
        sio = find_sergensio(io)
        if not self.check_set_expected_telnet_cb("parity", parity):
            return
        sio.sg_parity(self.expected_server_return, None)
        return

    def sstopbits(self, io, stopbits):
        sio = find_sergensio(io)
        if not self.check_set_expected_telnet_cb("stopbits", stopbits):
            return
        sio.sg_stopbits(self.expected_server_return, None)
        return

    def sflowcontrol(self, io, flowcontrol):
        sio = find_sergensio(io)
        if not self.check_set_expected_telnet_cb("flowcontrol", flowcontrol):
            return
        sio.sg_flowcontrol(self.expected_server_return, None)
        return

    def siflowcontrol(self, io, iflowcontrol):
        sio = find_sergensio(io)
        if not self.check_set_expected_telnet_cb("iflowcontrol", iflowcontrol):
            return
        sio.sg_iflowcontrol(self.expected_server_return, None)
        return

    def ssbreak(self, io, sbreak):
        sio = find_sergensio(io)
        if not self.check_set_expected_telnet_cb("sbreak", sbreak):
            return
        sio.sg_sbreak(self.expected_server_return, None)
        return

    def sdtr(self, io, dtr):
        sio = find_sergensio(io)
        if not self.check_set_expected_telnet_cb("dtr", dtr):
            return
        sio.sg_dtr(self.expected_server_return, None)
        return

    def srts(self, io, rts):
        sio = find_sergensio(io)
        if not self.check_set_expected_telnet_cb("rts", rts):
            return
        sio.sg_rts(self.expected_server_return, None)
        return

    def set_expected_sig_server_cb(self, value):
        self.expected_sig_server_cb = True
        self.expected_sig_server_val = value
        return

    def signature(self, io):
        sio = find_sergensio(io)
        if not self.expected_sig_server_cb:
            raise Exception("Got unexpected signature request");
        sio.sg_signature(self.expected_sig_server_val, None)
        self.expected_sig_server_cb = False
        return

    def close_done(self, io):
        if (debug or self.debug):
            print(self.name + ": Closed")
        self.waiter.wake()
        return

def alloc_io(o, iostr, do_open = True, chunksize = 10240, enable_oob = False):
    """Allocate an io instance with a HandlerData handler

    If do_open is True (default), open it, too.
    """
    gensios_enabled.check_iostr_gensios(iostr)
    h = HandleData(o, iostr, chunksize = chunksize)
    if enable_oob:
        h.io.control(0, gensio.GENSIO_CONTROL_SET,
                     gensio.GENSIO_CONTROL_ENABLE_OOB, "1")
    if (do_open):
        h.io.open_s()
    return h.io

def test_dataxfer(io1, io2, data, timeout = 1000):
    """Test a transfer of data from io1 to io2

    If the transfer does not complete by "timeout" milliseconds, raise
    an exception.
    """
    io1.handler.set_write_data(data)
    io2.handler.set_compare(data)
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io1.handler.name)) +
                        ("Timed out waiting for write completion at byte %d" %
                         io1.handler.wrpos))
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io2.handler.name)) +
                        ("Timed out waiting for read completion at byte %d" %
                         io2.handler.compared))
    return

def test_dataxfer_oob(io1, io2, data, timeout = 1000):
    """Test a transfer of data from io1 to io2

    If the transfer does not complete by "timeout" milliseconds, raise
    an exception.
    """
    io1.handler.set_write_data(data, auxdata = ["oob"])
    io2.handler.set_compare_oob(data)
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io1.handler.name)) +
                        ("Timed out waiting for write completion at byte %d" %
                         io1.handler.wrpos))
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io2.handler.name)) +
                        ("Timed out waiting for read completion at byte %d" %
                         io2.handler.compared))
    return

def test_dataxfer_stream(io1, io2, data, stream, timeout = 1000):
    """Test a transfer of data from io1 to io2

    If the transfer does not complete by "timeout" milliseconds, raise
    an exception.
    """
    io1.handler.set_write_data(data, auxdata = ["stream=%d" % stream])
    io2.handler.set_compare(data, stream = stream)
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer_s", io1.handler.name)) +
                        ("Timed out waiting for write completion at byte %d" %
                         io1.handler.wrpos))
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer_s", io2.handler.name)) +
                        ("Timed out waiting for read completion at byte %d" %
                         io2.handler.compared))
    return

def test_dataxfer_simul(io1, io2, data, timeout = 10000):
    """Test a simultaneous bidirectional transfer of data between io1 to io2

    If the transfer does not complete by "timeout" milliseconds, raise
    an exception.
    """
    io1.handler.set_write_data(data)
    io1.handler.set_compare(data)
    io2.handler.set_write_data(data)
    io2.handler.set_compare(data)
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception("%s: %s: Timed out waiting for write completion at bytes %d %d" %
                        ("test_dataxfer", io1.handler.name, io1.handler.wrpos,
                         io2.handler.wrpos))
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception("%s: %s: Timed out waiting for write completion at bytes %d %d" %
                        ("test_dataxfer", io2.handler.name, io1.handler.wrpos,
                         io2.handler.wrpos))
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception("%s: %s: Timed out waiting for read completion at bytes %d %d" %
                        ("test_dataxfer", io1.handler.name,
                         io1.handler.compared, io2.handler.compared))
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception("%s: %s: Timed out waiting for read completion at bytes %d %d" %
                        ("test_dataxfer", io2.handler.name,
                         io1.handler.compared, io2.handler.compared))
    return

def test_write_drain(io1, io2, data, timeout = 1000):
    """Test that a close does not loose data.

    If the transfer does not complete by "timeout" milliseconds, raise
    an exception.
    """
    io1.handler.set_write_data(data, close_on_done = True)
    io2.handler.set_compare(data)
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io1.handler.name)) +
                        ("Timed out waiting for write completion at byte %d" %
                         io1.handler.wrpos))
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io2.handler.name)) +
                        ("Timed out waiting for read completion at byte %d" %
                         io2.handler.compared))
    return

def io_close(ios, timeout = 1000):
    """close the given tuple of gensios

    If it does not succeed in timeout milliseconds, raise and exception.
    """
    for io in ios:
        if not io:
            continue
        io.handler.close()
    for io in ios:
        if not io:
            continue
        if (io.handler.wait_timeout(timeout) == 0):
            raise Exception("%s: %s: Timed out waiting for close" %
                            ("io_close", io.handler.name))
        # Break all the possible circular references.
        del io.handler.io
        del io.handler
    return

keydir = os.getenv("keydir")
if not keydir:
    if (not keydir):
        keydir = "ca"

class Logger:
    def gensio_log(self, level, log):
        print("***%s log: %s" % (level, log))

gensio.gensio_set_log_mask(gensio.GENSIO_LOG_MASK_ALL)

oshndname = os.getenv("GENSIO_TEST_OS_HANDLER")
if oshndname is None or oshndname == "default":
    o = gensio.alloc_gensio_selector(Logger());
elif oshndname == "glib":
    import gensioglib
    o = gensioglib.alloc_glib_os_funcs(Logger());
elif oshndname == "tcl":
    import gensiotcl
    o = gensiotcl.alloc_tcl_os_funcs(Logger());
else:
    print("Unknown OS handler name: " + oshndname)
    sys.exit(1)

def test_shutdown():
    global o
    w = gensio.waiter(o)
    count = 0
    while gensio.gensio_num_alloced() > 0:
        count += 1
        if (count > 100):
            raise Exception("All gensios were not freed in time")
        w.service(1)
    while w.service_now() == 0:
        # Give some time for everyting to clear out.
        pass
    del w
    c = sys.getrefcount(o)
    if c != 2:
        raise Exception("OS object refcount was %d, not 2" % c)
    c = gensio.get_os_funcs_refcount(o)
    if c != 1:
        raise Exception("OS funcs refcount was %d, not 1" % c)
    gensio.gensio_cleanup_mem(o)
    del o

def check_raddr(io, testname, expected):
    r = io.control(gensio.GENSIO_CONTROL_DEPTH_FIRST, gensio.GENSIO_CONTROL_GET,
                   gensio.GENSIO_CONTROL_RADDR, "0")
    if r != expected:
        raise Exception("%s raddr was not '%s', it was '%s'" %
                        (testname, expected, r));

def check_laddr(acc, testname, expected):
    r = acc.control(0, gensio.GENSIO_CONTROL_GET,
                    gensio.GENSIO_ACC_CONTROL_LADDR, "0")
    if r != expected:
        expected = expected.replace("127.0.0.1", "::1")
        expected = expected.replace("ipv4", "ipv6")
    if r != expected:
        raise Exception("%s laddr was not '%s', it was '%s'" %
                        (testname, expected, r));

def check_port(acc, testname, expected):
    r = acc.control(0, gensio.GENSIO_CONTROL_GET,
                    gensio.GENSIO_ACC_CONTROL_LPORT, "0")
    if r != expected:
        raise Exception("%s port was not '%s', it was '%s'" %
                        (testname, expected, r));

class TestAccept:
    def __init__(self, o, io1str, accstr, tester, name = None,
                 io1_dummy_write = None, do_close = True,
                 expected_raddr = None, expected_acc_laddr = None,
                 chunksize = 10240, get_port = True, except_on_log = False,
                 is_sergensio = False, enable_oob = False, timeout = 0,
                 close_timeout = 1000):
        self.o = o
        self.io1 = None
        self.io2 = None
        self.acc = None
        self.enable_oob = enable_oob
        self.close_timeout = close_timeout;

        try:
            self.except_on_log = except_on_log
            if (name):
                self.name = name
            else:
                self.name = accstr
            if debug:
                print("TestAccept " + self.name);
            self.waiter = gensio.waiter(o)
            gensios_enabled.check_iostr_gensios(accstr)
            self.acc = gensio.gensio_accepter(o, accstr, self);
            if is_sergensio:
                sga = self.acc.cast_to_sergensio_acc()
                if not sga:
                    raise Exception("Cast to sergensio_accepter failed");
                ga = sga.cast_to_gensio_acc()
                del sga
                del ga
            else:
                sga = None
                try:
                    sga = self.acc.cast_to_sergensio_acc()
                except:
                    pass
                if sga:
                    raise Exception("Cast to sergensio_accepter succeeded");
            if debug:
                print("acc startup");
            self.acc.startup()
            self.waiter.service(1) # Wait a bit for the accepter to start up.

            if get_port:
                port = self.acc.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                                        gensio.GENSIO_CONTROL_GET,
                                        gensio.GENSIO_ACC_CONTROL_LPORT, "0")
            else:
                port = ""
            io1str = io1str + port
            io1 = alloc_io(o, io1str, do_open = False,
                           chunksize = chunksize, enable_oob = enable_oob)
            self.io1 = io1
            if expected_acc_laddr:
                expected_acc_laddr = expected_acc_laddr + port
            if expected_raddr:
                expected_raddr = expected_raddr + port

            if expected_acc_laddr:
                check_laddr(self.acc, self.name, expected_acc_laddr)
            if debug:
                print("io1 open " + self.name);
            try:
                io1.open_s()
            except:
                del io1.handler.io
                del io1.handler
                raise
            if expected_raddr:
                check_raddr(io1, self.name, expected_raddr)
            if (io1_dummy_write):
                # For UDP, kick start things.
                io1.write(io1_dummy_write, None)
            if debug:
                print("wait 1 " + self.name);
            # Wait for the accept to happen
            if (self.wait_timeout(1000) == 0):
                raise Exception(("%s: %s: " % ("test_accept", self.name)) +
                                ("Timed out waiting for initial connection"))
            if (io1_dummy_write):
                self.io2.handler.set_compare(io1_dummy_write)
                if (self.io2.handler.wait_timeout(1000) == 0):
                    raise Exception(("%s: %s: " % ("test_accept",
                                                   self.io2.handler.name)) +
                                ("Timed out waiting for dummy read at byte %d" %
                                     self.io2.handler.compared))
            if timeout > 0:
                tester(self.io1, self.io2, timeout=timeout)
            else:
                tester(self.io1, self.io2)
            if do_close:
                self.close()
        except:
            self.io1 = None
            self.io2 = None
            self.acc = None
            raise

    def close(self):
        self.io1.read_cb_enable(False)
        if self.io2:
            self.io2.read_cb_enable(False)
        # Close the accepter first.  Some accepters (like conacc) will
        # re-open when the child closes.
        self.acc.shutdown_s()
        io_close((self.io1, self.io2), timeout = self.close_timeout)

        # Break all the possible circular references.
        self.io1 = None
        self.io2 = None
        self.acc = None

    def new_connection(self, acc, io):
        if self.enable_oob:
            io.control(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_CONTROL_ENABLE_OOB, "1")
        HandleData(self.o, None, io = io, name = self.name)
        print("New connection " + self.name);
        self.io2 = io
        self.waiter.wake()

    def accepter_log(self, acc, level, logstr):
        prstr = "***%s LOG: %s: %s" % (level, self.name, logstr)
        if self.except_on_log:
            raise Exception(prstr)
        else:
            print(prstr)

    def wait(self):
        self.waiter.wait(1)

    def wait_timeout(self, timeout):
        return self.waiter.wait_timeout(1, timeout)

def do_test(io1, io2, timeout = 1000):
    test_dataxfer(io1, io2, "This is a test string!", timeout = timeout)
    print("  Success!")

def do_small_test(io1, io2, timeout=2000):
    rb = os.urandom(512)
    print("  testing io1 to io2")
    test_dataxfer(io1, io2, rb, timeout = timeout)
    print("  testing io2 to io1")
    test_dataxfer(io2, io1, rb, timeout = timeout)
    print("  testing bidirection between io1 and io2")
    test_dataxfer_simul(io1, io2, rb, timeout = timeout)
    print("  Success!")

def do_medium_test(io1, io2, timeout = 10000):
    rb = os.urandom(131071)
    print("  testing io1 to io2")
    test_dataxfer(io1, io2, rb, timeout = timeout)
    print("  testing io2 to io1")
    test_dataxfer(io2, io1, rb, timeout = timeout)
    print("  testing bidirection between io1 and io2")
    test_dataxfer_simul(io1, io2, rb, timeout = timeout)
    print("  Success!")

def do_large_test(io1, io2, timeout = 30000):
    rb = os.urandom(1048570)
    print("  testing io1 to io2")
    test_dataxfer(io1, io2, rb, timeout = timeout)
    print("  testing io2 to io1")
    test_dataxfer(io2, io1, rb, timeout = timeout)
    print("  testing bidirection between io1 and io2")
    test_dataxfer_simul(io1, io2, rb, timeout = timeout)
    print("  Success!")

def do_oob_test(io1, io2):
    rb = os.urandom(512)
    print("  testing io1 to io2")
    test_dataxfer_oob(io1, io2, rb)
    print("  testing io2 to io1")
    test_dataxfer_oob(io2, io1, rb)
    print("  Success!")

class TestAcceptConnect:
    def __init__(self, o, iostr, io2str, io3str, tester, name = None,
                 io1_dummy_write = None, CA=None, do_close = True,
                 auth_begin_rv = gensio.GE_NOTSUP, expect_pw = None,
                 expect_pw_rv = gensio.GE_NOTSUP, password = None,
                 expect_remclose = True, use_port = True,
                 expect_2fa = None, expect_2fa_rv = gensio.GE_NOTSUP,
                 val_2fa = None):
        self.o = o
        self.io1 = None
        self.io2 = None
        self.acc = None
        self.acc2 = None
        try:
            if (name):
                self.name = name
            else:
                self.name = iostr
            self.waiter = gensio.waiter(o)
            gensios_enabled.check_iostr_gensios(iostr)
            gensios_enabled.check_iostr_gensios(io2str)
            self.acc = gensio.gensio_accepter(o, iostr, self);
            self.acc.startup()
            self.acc2 = gensio.gensio_accepter(o, io2str, self);
            self.acc2.startup()
            if (use_port):
                port = self.acc.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                                        gensio.GENSIO_CONTROL_GET,
                                        gensio.GENSIO_ACC_CONTROL_LPORT, "0")
                io3str = io3str + port
            self.io1 = self.acc2.str_to_gensio(io3str, None);
            self.io2 = None
            self.CA = CA
            h = HandleData(o, io3str, io = self.io1, password = password,
                           expect_remclose = expect_remclose,
                           val_2fa = val_2fa)
            self.auth_begin_rv = auth_begin_rv
            self.expect_pw = expect_pw
            self.expect_pw_rv = expect_pw_rv
            self.expect_2fa = expect_2fa
            self.expect_2fa_rv = expect_2fa_rv
            try:
                self.io1.open_s()
            except:
                del self.io1.handler.io
                del self.io1.handler
                self.io1 = None
                self.close()
                raise
            self.io1.read_cb_enable(True)
            if (io1_dummy_write):
                # For UDP, kick start things.
                self.io1.write(io1_dummy_write, None)
            try:
                self.wait()
            except:
                self.close()
                raise
            if (io1_dummy_write):
                self.io2.handler.set_compare(io1_dummy_write)
                if (self.io2.handler.wait_timeout(1000) == 0):
                    raise Exception(("%s: %s: " % ("test_accept",
                                                   self.io2.handler.name)) +
                               ("Timed out waiting for dummy read at byte %d" %
                                     self.io2.handler.compared))
            tester(self.io1, self.io2)
            if do_close:
                self.close()
        except:
            self.close()
            raise

    def close(self):
        if (self.io1):
            self.io1.read_cb_enable(False)
        if self.io2:
            self.io2.read_cb_enable(False)
        io_close((self.io1, self.io2))

        # Break all the possible circular references.
        self.io1 = None
        self.io2 = None
        if self.acc:
            self.acc.shutdown_s()
        self.acc = None
        if self.acc2:
            self.acc2.shutdown_s()
        self.acc2 = None

    def new_connection(self, acc, io):
        HandleData(self.o, None, io = io, name = self.name)
        self.io2 = io
        self.waiter.wake()

    def auth_begin(self, acc, io):
        return self.auth_begin_rv;

    def precert_verify(self, acc, io):
        if self.CA:
            io.control(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_CONTROL_CERT_AUTH, self.CA)
            return gensio.GE_NOTSUP
        return gensio.GE_NOTSUP

    def password_verify(self, acc, io, password):
        if self.expect_pw is None:
            raise Exception("got password verify when none expected")
        if self.expect_pw != password:
            raise Exception("Invalid password in verify, expected %s, got %s"
                            % (self.expect_pw, password))
        return self.expect_pw_rv

    def verify_2fa(self, acc, io, val_2fa):
        if self.expect_2fa is None:
            raise Exception("got 2-factor auth verify when none expected")
        if self.expect_2fa != val_2fa:
            raise Exception(
                "Invalid 2-factor auth in verify, expected %s, got %s"
                % (self.expect_2fa, val_2fa))
        return self.expect_2fa_rv

    def accepter_log(self, acc, level, logstr):
        print("***%s LOG: %s: %s" % (level, self.name, logstr))

    def wait(self):
        self.waiter.wait(1)

class TestConCon:
    def __init__(self, o, io1, io2, tester, name,
                 do_close = True,
                 expected_raddr1 = None, expected_raddr2 = None,
                 timeout = None):
        self.o = o
        self.name = name
        self.io1 = io1
        self.io2 = io2
        self.waiter = gensio.waiter(o)
        io1.open(self)
        io2.open(self)
        self.wait(2)
        if expected_raddr1:
            check_raddr(io1, self.name, expected_raddr1)
        if expected_raddr2:
            check_raddr(io2, self.name, expected_raddr2)
        if timeout is None:
            tester(self.io1, self.io2)
        else:
            tester(self.io1, self.io2, timeout=timeout)
        if do_close:
            self.close()

    def close(self):
        self.io1.read_cb_enable(False)
        self.io2.read_cb_enable(False)
        io_close((self.io1, self.io2))

        # Break all the possible circular references.
        del self.io1
        del self.io2

    def open_done(self, io, err):
        if err:
            raise Exception("TestConCon open error for %s: %s" %
                            (self.name, err))
        self.waiter.wake()

    def wait(self, nr):
        self.waiter.wait(nr)

e = os.getenv("GENSIO_TEST_ECHO_DEV")
if e is not None:
    if e:
        ttyecho = e
    else:
        ttyecho = None
else:
    ttyecho = "/dev/ttyEcho0"

ttyecho_def = ttyecho
if ttyecho and not os.path.exists(ttyecho):
    ttyecho = None

def check_echo_dev():
    if ttyecho is None:
        if ttyecho_def is None:
            print("Echo device is disabled")
        else:
            print("Echo device is not present")
        sys.exit(77)

e = os.getenv("GENSIO_TEST_PIPE_DEVS")
if e is not None:
    if e:
        ttypipe = e.split(":")
        if len(ttypipe) != 2:
            print("GENSIO_TESTS_PIPE_DEVS must be two devices separated by :")
            sys.exit(1)
    else:
        ttypipe = None
else:
    ttypipe = [ "/dev/ttyPipeA1", "/dev/ttyPipeB1" ]

ttypipe_def = ttypipe
if ttypipe and (not os.path.exists(ttypipe[0])
                or not os.path.exists(ttypipe[1])):
    ttypipe = None

def is_serialsim_pipe():
    return (ttypipe[0].startswith("/dev/ttyPipe") and
            ttypipe[1].startswith("/dev/ttyPipe"))

def check_pipe_dev(is_serialsim = False):
    if ttypipe is None:
        if ttypipe_def is None:
            print("Pipe device is disabled")
        else:
            print("Pipe device is not present")
        sys.exit(77)
    elif is_serialsim and not is_serialsim_pipe():
        print("Test requires a serialsim device")
        sys.exit(77)

def remote_id_int(io):
    return int(io.control(0, gensio.GENSIO_CONTROL_GET,
                          gensio.GENSIO_CONTROL_REMOTE_ID, None))

def check_sctp():
    try:
        import socket
        socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
    except:
        sys.exit(77)
