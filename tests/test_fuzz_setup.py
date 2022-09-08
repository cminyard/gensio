#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

#
# This program creates some random data into a file and then runs a
# gensio connector and accepter over stdio.  The data written to the
# accepter gensio filter is saved in tracefile.
#
# This is for support of fuzz testing.  The random data can be used to
# create a completely reproducible testcase with the ssl library.  The
# tracefile is used for fuzzing the program.
#

import sys
import subprocess
import os

gensiot = sys.argv[1]
randfile = sys.argv[2]
filter1 = sys.argv[3]
filter2 = sys.argv[4]
tracefile = sys.argv[5]

p = subprocess.Popen(["dd", "if=/dev/urandom", "of=" + randfile, "count=256"],
                     stderr = subprocess.PIPE)
p.communicate()

cmd = (filter1 + ',trace(dir=write,raw,file=' + tracefile + '),stdio(noredir-stderr),' +
       gensiot + ' --dummyrand ' + randfile + ' -i echo -a "' + filter2 +
       ',stdio"')

p = subprocess.Popen([gensiot, '--dummyrand', randfile, '-i', 'stdio(self)', cmd],
                     stdin = subprocess.PIPE,
                     stdout = subprocess.PIPE,
                     stderr = None)

p.stdin.write("a".encode(encoding='utf8'))
p.stdin.close()
p.stdout.read(1)
p.wait()
