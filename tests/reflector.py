#!/usr/bin/python3

import gensio
import curses.ascii
import sysconfig

def dump_buffer(buf):
    i = 0
    left = len(buf)
    while left > 0:
        s = "  %4.4x:" % i;
        e = left
        if e > 16:
            e = 16
        for j in range(0,e):
            p = i + j
            s = s + " %2.2x" % ord(buf[p:p+1])
        while j < 16:
            s = s + "   "
            j = j + 1
        s = s + "  "
        for j in range(0,e):
            p = i + j
            if curses.ascii.isprint(buf[p]):
                if (sysconfig.get_python_version() >= "3.0"):
                    s = s + str(buf[p:p+1], "utf-8")
                else:
                    s = s + str(buf[p:p+1])
            else:
                s = s + "."
        print(s)
        i = i + e
        left = left - e
        

class Reflector:
    """This creates an accepter socket.  If you connect to it, any data
    written on any other connected socket will be sent to the
    connection.
    """
    def __init__(self, o, iostr, trace = False, close_on_no_con = False):
        self.o = o
        self.acc = gensio.gensio_accepter(o, iostr, self)
        self.acc.startup()
        self.ios = [ ]
        self.waiter = gensio.waiter(o)
        self.trace = trace
        self.close_on_no_con = close_on_no_con

    def close(self):
        """Shut down all the connections and the accepter."""
        for i in self.ios:
            i.close_s()
        self.ios = []
        self.acc.shutdown_s()
        self.acc = None

    def new_connection(self, acc, io):
        if self.trace:
            print("%s: new connection" %
                  (io.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                              gensio.GENSIO_CONTROL_GET,
                              gensio.GENSIO_CONTROL_RADDR, "0")))
        self.ios.append(io);
        io.set_cbs(self)
        io.read_cb_enable(True);

    def get_port(self):
        """Return the port number for the accepter."""
        return self.acc.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                                gensio.GENSIO_CONTROL_GET,
                                gensio.GENSIO_ACC_CONTROL_LPORT, "0")

    def read_callback(self, io, err, buf, auxdata):
        if err:
            if self.trace:
                print("%s: Error %s" %
                      (io.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                                  gensio.GENSIO_CONTROL_GET,
                                  gensio.GENSIO_CONTROL_RADDR, "0"),
                       err))
            i = 0
            for ios in self.ios:
                if ios.same_as(io):
                    ios.read_cb_enable(False);
                    del self.ios[i]
                    if self.close_on_no_con and len(self.ios) == 0:
                        self.waiter.wake()
                    break
                i = i + 1
            return 0
        if self.trace:
            print("%s: Received Message" %
                  (io.control(gensio.GENSIO_CONTROL_DEPTH_FIRST,
                              gensio.GENSIO_CONTROL_GET,
                              gensio.GENSIO_CONTROL_RADDR, "0")))
            dump_buffer(buf)
        i = 0
        for ios in self.ios:
            if ios.same_as(io):
                continue
            try:
                ios.write(buf, [])
            except Exception as E:
                ios.read_cb_enable(False);
                del self.ios[i]
                if self.close_on_no_con and len(self.ios) == 0:
                    self.waiter.wake()
            else:
                i = i + 1
        return len(buf)
                
    def wait(self):
        """Wait for all the I/O connections to close"""
        self.waiter.wait(1)

    def wait_timeout(self, timeout):
        """Wait up to timeout milliseconds for all the I/O connections to
        close"""
        return self.waiter.wait_timeout(1, timeout)

if __name__ == "__main__":
    import sys

    def print_help():
        print(sys.argv[0] + " [-t] [-c] <gensio accepter>")
        print("Program to accept connections and reflect the data to all")
        print("other connections.  Options are:")
        print("  -t - trace all connections and incoming data")
        print("  -c - close the reflector when all connections close")

    i = 1
    trace = False
    close_on_no_con = False
    while i < len(sys.argv):
        if sys.argv[i][0] == "-":
            if sys.argv[i] == "-t":
                trace = True
            elif sys.argv[i] == "-c":
                close_on_no_con = True
            elif sys.argv[i] == "-h":
                print_help()
                sys.exit(0)
            else:
                print("Unknown option: " + sys.argv[i]);
                print_help()
                sys.exit(1)
        else:
            break;
        i = i + 1
    if i == len(sys.argv):
        print("No accepter string given");
        print_help()
        sys.exit(1)

    class Logger:
        def gensio_log(self, level, log):
            print("***%s log: %s" % (level, log))

    o = gensio.alloc_gensio_selector(Logger())
    refl = Reflector(o, sys.argv[i], trace=trace,
                     close_on_no_con = close_on_no_con)
    refl.wait()
