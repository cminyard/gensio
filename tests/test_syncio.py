#!/usr/bin/python

import gensio

class Logger:
    def gensio_log(self, level, log):
        print("***%s log: %s" % (level, log))

o = gensio.alloc_gensio_selector(Logger())
g = gensio.gensio(o, "echo(readbuf=10)", None)
g.set_sync()
g.open_s()

# Basic write then read
(count, time) = g.write_s("Hello", 1000)
if count != 5 or time < 500:
    raise Exception("Invalid write return: %d %d\n" % (count, time))
(buf, time) = g.read_s(10, 1000)
if buf != "Hello" or time < 500:
    raise Exception("Invalid read return: '%s' %d\n" % (buf, time))

# This should time out, no data
(buf, time) = g.read_s(10, 250)
if buf != "" or time != 0:
    raise Exception("Invalid read timeout return: '%s' %d\n" % (buf, time))

# This should time out, buffer is only 10 bytes per readbuf above
(count, time) = g.write_s("HelloHelloHello", 250)
if count != 10 or time != 0:
    raise Exception("Invalid write timeout return: %d %d\n" % (count, time))

# Read out what should have been written
(buf, time) = g.read_s(10, 1000)
if buf != "HelloHello" or time < 500:
    raise Exception("Invalid read return: '%s' %d\n" % (buf, time))

# This should time out, no data
(buf, time) = g.read_s(10, 250)
if buf != "" or time != 0:
    raise Exception("Invalid read timeout return: '%s' %d\n" % (buf, time))

g.close_s()
