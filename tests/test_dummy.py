#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

import utils
import gensio

print("Test dummy")

acc = gensio.gensio_accepter(utils.o, "dummy", None);
acc.startup()
waiter = gensio.waiter(utils.o)
waiter.service(1)
acc.shutdown_s()
del waiter
del acc
utils.test_shutdown()
print("  Success!")
