========
Building
========

You can obtain the library at https://github.com/cminyard/gensio or
get the tarballs at https://sourceforge.net/projects/ser2net/files/ser2net

This is a normal autoconf system, nothing special.  Note that if you
get this directly from git, you won't have the build infrastructure
included.  There is a script named "reconf" in the main directory
that will create it for you.

If you don't know about autoconf, the INSTALL file has some info,
or google it.

To fully build gensio, you need the following:

* swig - For python and go bindings

* python dev libraries - For python bindings

* go language installed in the path

* openssl dev libraries and executable - For all the crypto

* openipmi dev libraries - For IPMI serial over lan, if you want that.
  Note that you need a pretty recent one, really 2.0.31 or newer.

* libsctp dev library - For sctp support

* pkgconfig - If you want gensio to install its pkgconfig files.

* avahi dev - If you want gensio to have mdns support.

* pam dev - For support of logins with gtlsshd

* libwrap - for tcpd

* glib dev - for the glib os funcs

* tcl dev - for the tcl os funcs

* alsa dev - for sound (on Linux)

* udev dev - for cm108 GPIO soundcard support (on Linux)

The following sets everything except openipmi up on ubuntu 20.04:

  sudo apt install gcc g++ git swig python3-dev libssl-dev pkg-config	\
    libavahi-client-dev avahi-daemon libtool autoconf automake make	\
    libsctp-dev libpam-dev libwrap0-dev libglib2.0-dev tcl-dev		\
    libasound2-dev libudev-dev

On Redhat, libwrap is gone, so you won't be using that, and swig doesn't appear
to be available, so you will have to build that yourself with at least go and
python support.  Here's the command for Redhat-like systems:

  sudo yum install gcc gcc-c++ git python3-devel swig openssl-devel \
    pkg-config avahi-devel libtool autoconf automake make \
    lksctp-tools-devel pam-devel glib2-devel tcl-devel \
    alsa-lib-devel systemd-devel

You might have to do the following to enable access to the development
packages:

  sudo dnf config-manager --set-enabled devel

And get the SCTP kernel modules, you might have to do:

  sudo yum install kernel-modules-extra

To use Go language, you must get a version of swig 4.1.0 or greater.
You may have to pull a bleeding edge version out of git and use that.

Handling python installation configuration is a bit of a pain.  By
default the build scripts will put it wherever the python program
expects installed python programs to be.  A normal user generally
doesn't have write access to that directory.

To override this, you can use the --with-pythoninstall
and --with-pythoninstalllib configure options or you can set the
pythoninstalldir and pythoninstalllibdir environment variables to
where you want the libraries and modules to go.

Note that you may need to set --with-uucp-locking to your lockdir (on
older systems it's /var/lock, which is the default.  On newer it might
be /run/lock/lockdev.  You might also need to be a member of dialout
and lock groups to be able to open serial devices and/or locks.

go language support requires go to be installed and in the path.

Dynamic vs Built In gensios
===========================

As I continued to add gensios to the library, like crypto, mdns,
sound, IPMI, sctp, etc. the number of dependencies in the library was
getting out of control.  Why should you be loading libasound, or
libOpenIPMI, if you don't need it?  Plus, though the library supported
adding your own gensios through a programmatic API, it had no standard
way to add them for the system so you could write your own gensio and
let everyone on the system use it.

The gensio library supports loading gensios dynamically or building
them in to the library.  By default if you create shared libraries,
then all gensios are compiled as modules for dynamic loading and
installed in a place that makes it possible.  If you do not create
shared libraries, all gensios are built in to the library.  But you
can override this behaviour.

To set all gensios to be built in to the library, you can add
"--with-all-gensios=yes" on the configure command line and it will
build them in to the library.

You can also set them to all be dynamically loaded by adding
"--with-all-gensios=dynamic", but this is the default.

You can also disable all gensios by default by specifying
"--with-all-gensios=no".  Then no gensios will be built by default.
This is useful if you only want a few gensios, you can turn all of
them off then enable then ones you want.

To set how individual gensios are built, you do "--with-<gensio>=x"
where x is "no (don't build), yes (build into library) or dynamic
(dynamically loaded executable).  For instance, if you only wanted to
build the tcp gensio into the library and make the rest dynamic, you
could set up for all dynamic gensios and then add "--with-net=yes".

These modules are put by default into $(moduleinstalldir) (specified
with --with-moduleinstall on the configure line) which defaults to
$(pkglibexecdir) (which is generally /usr/libexec/gensio).

Note that dynamic loading is always available, even if you build in
all the gensios in the library.  So you can still add your own gensios
by adding then to the proper directory.

Gensios will be loaded first from the environment variable
LD_LIBRARY_PATH, then from GENSIO_LIBRARY_PATH, then from the default
location.

Building on MacOS
=================

MacOS, being a sort of *nix, builds pretty cleanly with Homebrew
(https://brew.sh).  You have to, of course, install all the libraries
you need.  Most everything works, with the following exceptions::

* cm108gpio
* sctp
* uucp locking

The built-in DNSSD code is used for MDNS, so avahi is not required.

flock locking for serial ports works, so uucp locking really isn't
required.

openipmi should work, but it is not available in homebrew so you would
have to build it yourself.

Building on FreeBSD
===================

Install the necessary software:

  pkg install gcc portaudio autoconf automake libtool mDNSResponder swig \
      go python3 gmake

You have to use gmake to compile it, for some reason the standard make
on BSD doesn't accept the "c++" variable in a list of requirements.  The
following don't work and are not compiled::

* sctp
* ipmisol
* cm108gpio

Add the following to /etc/rc.conf::

  mdnsd_enable=YES

And reboot or start the service.

The pty gensio fails the oomtest (oomtest 14), there seems to be
something up with the BSD PTYs. I'm seeing a 07 character inserted into
the data stream in cases.  I haven't spent too much time on it,
though, but since this is heavily tested on Linux and MacOS, I don't
think the problem is in the gensio code.


Building on Windows
===================

The gensio library can be built under Windows using mingw64 or ucrt64.
The following things don't work::

* sctp
* pam
* libwrap
* ipmisol

You also don't need to install alsa, it uses the Windows sound interface for
sound.

The cm108gpio uses native windows interfaces, so udev is not required.

You can compile under msys, which is there primarily to support file
transfers with gtlssync and gtlssh.  It uses the native Windows
interfaces MDNS and sound, but those are not well tested.  Outside of
that, things may or may not work.  In particular, gtlsshd will not
compile.  You can specify serial ports with //./COM<n>, but there are
issues.  Python maybe sort of works.  Tests do not run.  For anything
besides running gtlssh and doing file transfers, you should probably
use the native version.  These things can be fixed, but they will take
some work.

The Windows built-in MDNS interfaces are used, so you don't need avahi
or DNSSD.  You will need to install the pcre library if you want
regular expressions in it.

You need to get msys2 from https://msys2.org.  Then install autoconf,
automake, libtool, git, make, and swig as host tools:

  pacman -S autoconf automake libtool git make swig

You have to install the mingw-w64-x86_64-xxx version of all the
libraries or the mingw-w64-i686-xxx version of all the libraries.
32-bit is not well tested::

  pacman -S mingw-w64-x86_64-gcc \
    mingw-w64-x86_64-python3 \
    mingw-w64-x86_64-pcre \
    mingw-w64-x86_64-openssl

for mingw64, or for ucrt64::

  pacman -S mingw-w64-ucrt-x86_64-gcc \
    mingw-w64-ucrt-x86_64-python3 \
    mingw-w64-ucrt-x86_64-pcre \
    mingw-w64-ucrt-x86_64-openssl

For go, install go from https://go.dev and log out and log back in.
It should then be in the PATH, but if it's not, you will need to add
it to the PATH.  I haven't gotten go working on on mingw32, but I
haven't tried a 32-bit version of go.

For gtlsshd, --sysconfdir has no meaning on Windows.  Instead, the
sysconf dir is relative to the patch of the executable, in
../etc/gtlssh.  So if gtlsshd is in::

   C:/Program Files/Gensio/bin/gtlsshd

the sysconfdir will be::

   C:/Program Files/Gensio/etc/gtlssh

For standard installation, you can run::

   ../configure --sbindir=/Gensio/bin --libexecdir=/Gensio/bin \
      --mandir=/Gensio/man --includedir=/Gensio/include \
      --with-pythoninstall=/Gensio/python3 --prefix=/Gensio

and when you run "make install DESTDIR=..." and you set DESTDIR to
where you want it to go, like "C:/Program Files".  Then you can add
that to the PATH using the control panel.  To use gtlsshd, you create
an etc/gtlsshd directory in the Gensio directory.  You must set the
permissions on this directory so only System and Administrators have
access, like::

  PS C:\Program Files (x86)\Gensio\etc> icacls gtlssh
  gtlssh NT AUTHORITY\SYSTEM:(OI)(CI)(F)
         BUILTIN\Administrators:(OI)(CI)(F)

Otherwise gtlsshd will fail with an error about permissions on the
key.  You can set these permission on the .key file instead of the
directory, but you will have to set it again every time you generate a
new key.

For using the Inno Setup Compiler, do "make install DESTDIR=$HOME/install"
and then run Inno on gensio.iss.  It will create an executable installer
for installing Gensio.

Then you need to remove the .la files from the install directory, as
they screw up linking with other things::

    rm $HOME/install/Gensio/lib/*.la

=============
Running Tests
=============

There are a number of tests for gensios.  They all run on Linux if you
have the serialsim kernel module.  Besides the serial port ones, they
run on other platforms as the gensios are supported on that platform.

The serial port tests require the serialsim kernel module and python
interface.  These are at https://github.com/cminyard/serialsim and
allow the tests to use a simulated serial port to read modem control
line, inject errors, etc.

You can get by without serialsim if you have three serial devices: one
hooked in echo mode (RX and TX tied together) and two serial devices
hooked together do I/O on one device goes to/comes from the other.
This should work on non-Linux platforms.  Then set the following
environment variables:

.. code-block:: bash

  export GENSIO_TEST_PIPE_DEVS="/dev/ttyxxx:/dev/ttywww"
  export GENSIO_TEST_ECHO_DEV="/dev/ttyzzz"

It will not be able to test modemstate or rs485.

They also require the ipmi_sim program from the OpenIPMI library at
https://github.com/cminyard/openipmi to run the ipmisol tests.

To run the tests, you need to enable some internal debugging to get
the full effect.  You generally want to run something like:

.. code-block:: bash

  ./configure --enable-internal-trace CFLAGS='-g -Wall'

You can turn on -O3 in the CFLAGS, too, if you like, but it makes
debugging harder.

There are two basic types of tests.  The python tests are functional
tests testing both the python interface and the gensio library.
Currently they are ok, but there is plenty of room for improvement.
If you want to help, you can write tests.

The oomtest used to be an out of memory tester, but has morphed into
something more extensive.  It spawns a gensiot program with specific
environment variables to cause it to fail at certain points, and to do
memory leak and other memory checks.  It writes data to the gensiot
through its stdin and receives data on stdout.  Some tests (like
serialdev) use an echo.  Other tests make a separate connection over
the network and data flows both into stdin and comes back over the
separate connection, and flows into the separate connection and comes
back via stdout.  oomtest is multi-threaded and the number of threads
can be controlled.  oomtest has found a lot of bugs.  It has a lot of
knobs, but you have to look at the source code for the options.  It
needs to be documented, if someone would like to volunteer...

Fuzzing
=======

To set up for fuzzing, install afl, then configure with the following:

.. code-block:: bash

  mkdir Zfuzz; cd Zfuzz
  ../configure --enable-internal-trace=yes --disable-shared --with-go=no \
      CC=afl-gcc CXX=afl-g++

Or use clang, if available:

.. code-block:: bash

  ../configure --enable-internal-trace=yes --disable-shared --with-go=no \
      CC=afl-clang-fast CXX=afl-clang-fast++ LIBS='-lstdc++'

I'm not sure why the LIBS thing is necessary above, but I had to add
it to get it to compile.

Then build.  Then "cd tests" and run "make test_fuzz_xxx" where xxx is
one of: certauth, mux, ssl, telnet, or relpkt.  You will probably need
to adjust some things, afl will tell you.  Note that it will run
forever, you will need to ^C it when you are done.

The makefile in tests/Makefile.am has instructions on how to handle a
failure to reproduce for debugging.

Code Coverage
=============

Running code coverage on the library is pretty easy.  First you need
to configure the code to enable coverage:

.. code-block:: bash

  mkdir Ocov; cd Ocov
  ../configure --enable-internal-trace=yes \
      CC='gcc -fprofile-arcs -ftest-coverage' \
      CXX='g++ -fprofile-arcs -ftest-coverage'

The compile and run "make check".

To generate the report, run:

.. code-block:: bash

  gcovr -f '.*/.libs/.*' -e '.*python.*'

This will generate a summary.  If you want to see the coverage of
individual lines in a file, you can do:

.. code-block:: bash

  cd lib
  gcov -o .libs/ *.o

You can look in the individual .gcov files created for information
about what is covered.  See the gcov docs for detail.

At the time of writing, I was getting about 74% code coverage,
So that's really pretty good.  I'll be working to improve
that, mostly through improved functional testing.

ser2net is used for testing some things, primarily the serial port
configuration (termios and rfc2217).  You can build ser2net against
the gcov version of the gensio library and run "make check" in ser2net
to get coverage on those parts.  With that, I'm seeing about 76%
coverage, so it doesn't add much to the total.

It would be nice to be able to combine this with fuzzing, but I'm not
sure how to do that.  afl does it's own thing with code coverage.
There appears to be a afl-cov package that somehow integrated gcov,
but I haven't looked into it.
