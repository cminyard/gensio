#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

from utils import *
import gensio

print("Test mux sctp oob")
ta = TestAccept(o, "mux,sctp,localhost,", "mux,sctp,0", do_oob_test,
                chunksize = 64)

