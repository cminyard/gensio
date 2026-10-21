#!/usr/bin/env python3
"""Run a program given on the command line and pass its exit status through.

Used as a meson test() executable so that the output of a custom_target()
can be run as a test on Meson versions that don't allow that directly:

    test('name', python, args: [files('run_wrapper.py'), gen, 'arg1', ...])

This is only needed as a hack for meson version <1.10.0.  Once that is
no longer support this and the associated meson.build hacks can go
away.
"""

import os
import signal
import subprocess
import sys


def main():
    if len(sys.argv) < 2:
        sys.stderr.write('usage: run_wrapper.py PROGRAM [ARGS...]\n')
        return 2

    cmd = sys.argv[1:]
    try:
        rc = subprocess.call(cmd)
    except OSError as e:
        sys.stderr.write('run_wrapper.py: failed to run %s: %s\n' % (cmd[0], e))
        return 127

    if rc < 0 and os.name == 'posix':
        # The child was killed by a signal.  Re-raise the same signal on
        # ourselves so meson reports it as a crash, not as a plain failure.
        sig = -rc
        sys.stdout.flush()
        sys.stderr.flush()
        signal.signal(sig, signal.SIG_DFL)
        os.kill(os.getpid(), sig)
        return 128 + sig  # fallback if the signal didn't terminate us

    return rc


if __name__ == '__main__':
    sys.exit(main())
