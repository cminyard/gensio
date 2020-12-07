#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: GPL-2.0-only
#

import termios
import copy

import gensio
import utils

# This is the termios gensio sets up when it opens a serial port.
# Same for sergensio_termios gensio.
base_termios = [ 0, 0, 0, 0, 0, 0,
                 [ '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
                   '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
                   '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
                   '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0' ]]

def setup_base_termios():
    base_termios[0] = termios.IGNBRK
    base_termios[2] = (termios.B9600 | termios.CREAD | termios.CS8)
    base_termios[4] = termios.B9600
    base_termios[5] = termios.B9600
    base_termios[6][termios.VTIME] = 0
    base_termios[6][termios.VMIN] = 1
    base_termios[6][termios.VSTART] = chr(17)
    base_termios[6][termios.VSTOP] = chr(19)
    return

setup_base_termios()

def dup_termios(t, iflags=0, iflags_mask=0,
                oflags=0, oflags_mask=0,
                cflags=0, cflags_mask=0,
                lflags=0, lflags_mask=0):
    """Duplicate the given termios, then apply the masks and or the values
    given."""
    n = copy.deepcopy(t)
    n[0] = (n[0] & ~iflags_mask) | iflags
    n[1] = (n[1] & ~oflags_mask) | oflags
    n[2] = (n[2] & ~cflags_mask) | cflags
    n[3] = (n[3] & ~lflags_mask) | lflags
    return n

def dup_base_termios(iflags=0, iflags_mask=0,
                     oflags=0, oflags_mask=0,
                     cflags=0, cflags_mask=0,
                     lflags=0, lflags_mask=0):
    return dup_termios(base_termios, iflags, iflags_mask, oflags, oflags_mask,
                       cflags, cflags_mask, lflags, lflags_mask)

def compare_termios(tio1, tio2):
    for i in range(0, 6):
        if tio1[i] != tio2[i]:
            return i;
    for i in range(0, len(tio2[6])):
        if tio1[6][i] != tio2[6][i]:
            return i + 6;
    return -1
