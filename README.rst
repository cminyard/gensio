===========================
gensio - General Stream I/O
===========================

This is gensio (pronounced gen'-see-oh), a framework for giving a
consistent view of various stream (and packet) I/O types.  You create
a gensio object (or a gensio), and you can use that gensio without
having to know too much about what is going on underneath.  You can
stack gensio on top of another one to add protocol funcionality.  For
instance, you can create a TCP gensio, stack SSL on top of that, and
stack Telnet on top of that.  It supports a number of network I/O and
serial ports.  gensios that stack on other gensios are called filters.

You can do the same thing with receiving ports.  You can set up a
gensio accepter (accepter) to accept connections in a stack.  So in
our previous example, you can setup TCP to listen on a specific port
and automatically stack SSL and Telnet on top when the connection
comes in, and you are not informed until everything is ready.

A *very* important feature of gensio is that it makes establishing
encrypted and authenticated connections much easier than without it.
Beyond basic key management, it's really no harder than TCP or
anything else.  It offers extended flexibility for controlling the
authentication process if needed.  It's really easy to use.

Note that the gensio(5) man page has more details on individual gensio
types.

Building
========

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
to be available, so you will have to built that yourself with at least go and
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
---------------------------

As I continued to add gensios to the library, like crypto, mdns,
sound, IPMI, sctp, etc. the number of dependencies in the library was
getting out of control.  Why should you be loading libasound, or
libOpenIPMI, if you don't need it?  Plus, though the library supported
adding your own gensios through a programatic API, it had no standard
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
-----------------

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

Building on Windows
-------------------

The gensio library can be built under Windows using mingw64.  The following
things don't work::

* sctp
* pam
* libwrap

You also don't need to install alsa, it uses the Windows sound interface for
sound.

The cm108gpio uses native windows interfaces, so udev is not required.

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

and when you run "make install" you set DESTDIR to where you want it
to go, like "C:/Program Files".  Then you can add that to the PATH
using the control panel.  To use gtlsshd, you create an etc/gtlsshd
directory in the Gensio directory,

There is a item in FAQ.rst named "How to run gtlsshd on Windows", see
that for more details, as there are a few tricky things you have to
handle.

gensio tools
============

A couple of tools are available that use gensios, both as an example
and for trying things out.  These are:

gensiot
    A tool for making basic gensio connections.  You can create any
    arbitrary gensio setup you like.  See gensiot(1) for details.

gtlsshd
    An sshd-like daemon that uses certauth, ssl, and SCTP or TCP
    gensios for making connections.  It uses standard PAM
    authentication and uses ptys.  See gtlsshd(8) for details.

gtlssh
    An ssh-like program that can connect to gtlsshd.  It can also
    be used with ser2net to make establishing encrypted and
    authenticated connections easier.  See gtlssh(1) for details.

Available gensios
=================

The following gensios are available in the library:

sctp
    Normal SCTP communication.  Streams and out of bound data are
    supported.  End of message demarcation is not supported because it
    doesn't currently work on Linux.

tcp
    Normal TCP communication.  Out of bound data is supported.

udp
    Sort-of connection oriented UDP.

stdio
    Access to either the calling program's stdio, or the ability
    to run a program and connect to its stdin, stdout, and stderr.
    NOTE: Do not use this for file I/O.  Use the file gensio.

file
    Used for accessing files.  Allows both input and output file,
    and streams the data to/from the files.  No accepter available.

pty
    Run a program in a PTY and use the gensio to communicate with
    its tty.  No accepter available.

serialdev
    Connect to a device.  You can use "sdev" as shorthand for
    "serialdev".  It can hook to termios type devices, like ptys and
    /dev/tty, more than just serial ports.  No accepter available.

dev
    Connects to devices (like serialdev does) but does not do any
    serial port processing.  It also has a write-only option for
    talking to printer ports or other write-only devices.  It also has
    a rdonly option for talking to read-only devices.  No accepter
    available.

ipmisol
    Connect to a remote over IPMI SOL.  Full serial port capabilities
    are available.  No accepter available, unfortunately.

dummy
    An accepter that doesn't do anything except look like an accepter
    to the user.  Useful in some situations where an accepter is
    expected but you don't need to do anything.

echo
    A gensio that echos everything that is sent to it.  Useful for
    testing.  No accepter available.

telnet
    A filter gensio that implements the telnet protocol.  It can do
    full serial support with RFC2217.

ssl
    Implement SSL/TLS as a gensio filter.  It supports client
    authentication, too.

certauth
    A user authentication protocol implemented as a gensio filter.

mux
    A channel multiplexer.  You can create channels on top of it using
    open_channel().  Channels work as normal gensio, so you can have a
    number of gensios running on top of a single gensio.  It also has
    end-of-message demarcation and obviously full flow-control
    capability individually on each channel.  If you just need a
    gensio with end-of-message demarcation, you can use this as
    without creating channels.

msgdelim
    Converts an unreliable stream interface into an unreliable packet
    interface.  This is primarily so a reliable packet interface like
    relpkt can run over a serial port.  It does not support streaming
    of data, so it's not very useful by itself.

relpkt
    Converts an unreliable packet interface to a reliable packet interface
    (that also supports streaming).  Made for running over msgdelim.  It will
    run over UDP, but it's not ideal for that because it doesn't do all the
    internet-friendly flow control and such that SCTP and TCP do.

trace
    A transparent gensio that allows the data read and/or written to
    be sent to a file, either as raw data or as human-readable hex
    data.  It can also be used to block data flowing in one or both
    directions.

perf
    A gensio that can send/receive data on top of a stack of gensios
    and measure the throughput on the channel.  The received data from
    perf is information about the channel throughput.

conacc
    A gensio accepter that takes a gensio stack string as a parameter.
    This lets you use a gensio as an accepter.  When conacc is started,
    it opens the gensio, and when the gensio opens it reports a new
    child for the accepter.  When the child closes it attempts to open
    the child again and go through the process again (unless accepts
    have been disabled on conacc).

    Why would you want to use this?  Say in ser2net you wanted to
    connect one serial port to another.  You could have a connection like:

    .. code-block:: yaml

      connection: &con0
        accepter: conacc,serialdev,/dev/ttyS1,115200
        connector: serialdev,/dev/ttyS2,115200

    And it would connect /dev/ttyS1 to /dev/ttyS2.  Without conacc,
    you could not use serialdev as an accepter.  It would also let you
    use gtlsshd on a serial port if you wanted encrypted authenticated
    logins over a serial port.  If you ran gtlsshd with the following:

    .. code-block:: bash

      gtlsshd --notcp --nosctp --oneshot --nodaemon --other_acc
         'conacc,relpkt(mode=server),msgdelim,/dev/ttyUSB1,115200n81'

    You could connect with:

    .. code-block:: bash

      gtlssh --transport 'relpkt,msgdelim,/dev/ttyUSB2,115200n81' USB2

    This creates a reliable packet transport over a serial port.  The
    mode=server is required to make relpkt run as the server, since it
    would normally run as a client since it is not being started as an
    accepter.  The ssl gensio (which runs over the transport) requires
    reliable communication, so it won't run directly over a serial
    port.

xlt
    This gensio allows character translations to be done on data flowing
    through this filter.  It's primarily to convert carraige returns and
    line feeds.

mdns
    This gensio uses mDNS to lookup a service (protocol type, network
    type, port, address) and then connect to that service.  If you
    have a program like ser2net that advertise mDNS service, you don't
    have to worry about finding port numbers and such, it's all
    handled for you.

keepopen
    This gensio presents an always open connection to the upper layer and
    keeps the lower layer connection open.  If it closes, it re-opens it.

script
    This gensio executes an external program with the external program's
    stdio connected to the child of this gensio.  Once the external program
    terminates, this gensio will report that it is open and pass all the
    data through.  This can be used to run scripts to set things up on a
    connection before hooking to the parent gensio.

sound
    A gensio that provides access to sound devices and files.  It's a
    little complicated, read the docs in gensio.5

afskmdm
    Yes, it looks like a jumble of letters.

    A filter gensio that sits on top of the sound gensio and does an
    Audio Frequency Shift Keying modem, like is used on AX.25 amateur
    radio.

kiss
    An amateur radio protocol for talking to TNCs.  This is used by AX25
    in many cases.

ax25
    An amateur radio protocol for packet radio.  To fully use this you
    would need to write code, since it uses channels and oob data for
    unnumbered information, but you can do basic things with just
    gensiot if all you need is one communication channel.  For
    instance, if you wanted to chat with someone over the radio, and
    the kiss port is on 8001 on both machines, on the accepting machine
    you can run:

    .. code-block:: bash

      gensiot -i 'stdio(self)' -a \
          'ax25(laddr=AE5KM-1),kiss,conacc,tcp,localhost,8001'

    which will hook to the TNC and wait for a connection on address
    AE5KM-1.  Then you could run:

    .. code-block:: bash

      gensiot -i 'stdio(self)' \
          'ax25(laddr=AE5KM-2,addr="0,AE5KM-1,AE5KM-2"),kiss,tcp,localhost,8001'

    on the other machine.  This will connect to the other machine over
    TNC 0 with the given address.  Then anything you type in one will
    appear on the other, a line at a time.  Type "Ctrl-D" to exit.
    The 'stdio(self)' part turns off raw mode, so it's a line at a
    time and you get local echo.  Otherwise every character you types
    would send a packet and you couldn't see what you were typing.

    To hook to the N5COR-11 AX.25 BBS system, you would do:

    .. code-block:: bash

      gensiot -i 'xlt(nlcr),stdio(self)' \
        'ax25(laddr=AE5KM-2,addr="0,N5COR-11,AE5KM-2"),kiss,tcp,localhost,8001'

    Most BBS systems use CR, not NL, for the new line, so the xlt
    gensio is used to translate incoming these characters.

    Of course, this being gensio, you can put any workable gensio
    underneath ax25 that you would like.  So if you want to play
    around or test without a radio, you could do ax25 over UDP
    multicast.  Here's the accepter side:

    .. code-block:: bash

      gensiot -i 'stdio(self)' -a \
      'ax25(laddr=AE5KM-1),conacc,'\
      'udp(mcast="ipv4,224.0.0.20",laddr="ipv4,1234",nocon),'\
      'ipv4,224.0.0.20,1234'

    and here's the connector side:

    .. code-block:: bash

    gensiot -i 'stdio(self)' \
    'ax25(laddr=AE5KM-2,addr="0,AE5KM-1,AE5KM-2"),'\
    'udp(mcast="ipv4,224.0.0.20",laddr="ipv4,1234",nocon),'\
    'ipv4,224.0.0.20,1234'

    kiss is not required because UDP is already a packet-oriented
    media.  Or you can use the greflector program to create a
    simulated radio situation.  On the machine "radiopi2", run:

    .. code-block:: bash

      greflector kiss,tcp,1234

    which will create a program that will reflect all received input
    to all other connections.  Then on the accepter side:

    .. code-block:: bash

      gensiot -i 'stdio(self)' -a \
      'ax25(laddr=AE5KM-1),kiss,conacc,tcp,radiopi2,1234'

    and the connecting side:

    .. code-block:: bash

      gensiot -i 'stdio(self)' \
      'ax25(laddr=AE5KM-2,addr="0,AE5KM-1,AE5KM-2"),kiss,tcp,radiopi2,1234'

    The test code uses the reflector for some testing, since it's so
    convenient to use.

ratelimit
    Limit the data throughput for a gensio stack.

cm108gpio
    Allow a GPIO on a CMedia CM108 or equivalent sound device to be
    controlled.  Used with afskmdm for keying a transmitter.
		  
These are all documented in detail in gensio(5).  Unless otherwise
stated, these all are available as accepters or connecting gensios.

Creating Your Own Gensios
=========================

You can create your own gensios and register them with the library and
stack them along with the other gensios.

The easiest way to do this is to steal code from a gensio that does
kind of what you want, then modify it to create your own gensio.
There is, unfortunately, no good documentation on how to do this.

The include file include/gensio/gensio_class.h has the interface
between the main gensio library and the gensio.  The gensio calls all
come through a single function with numbers to identify the function
being requested.  You have to map all these to the actual operations.
This is somewhat painful, but it makes forwards and backwards
compatibility much easier.

Creating your own gensio this way is fairly complex.  The state
machine for something like this can be surprisingly complex.  Cleanup
is the hardest part.  You have to make sure you are out of all
callbacks and no timers might be called back in a race condition at
shutdown.  Only the simplest gensios (echo, dummy), strange gensios
(conadd, keepopen, stdio), and gensios that have channels (mux, ax25)
directly implement the interface.  Everything else uses
include/gensio/gensio_base.h.  gensio_base provides the basic state
machine for a gensio.  It has a filter portion (which is optional) and
a low-level (ll) portion, which is not.

The filter interface has data run through it for the processing.  This
is used for things like ssl, certauth, ratelimit, etc.  Filter gensios
would use this.  These all use gensio_ll_gensio (for stacking a gensio
on top of another gensio) for the ll.

Terminal gensios each have their own ll and generally no filter.  For
lls based on a file descriptor (fd), gensio_ll_fd is used.  There is
also an ll for IPMI serial-over-lan (ipmisol) and for sound.  Most of
the terminal gensios (tcp, udp, sctp, serial port, pty) use the fd ll,
obviously.

Once you have a gensio, you can compile it as a module and stick it in
$(moduleinstalldir)/<version>.  Then the gensio will just pick it up
and use it.  You can also link it in with your application and do the
init function from your application.

mDNS support
============

The mdns gensio has already been discussed, but the gensio library
provides an easy to use mDNS interface.  The include file for it is in
gensio_mdns.h, and you can use the gensio_mdns(3) man page to get more
information on it.

To make an mdns connection using gensiot, say you have ser2net set up
with mdns enabled like:

.. code-block:: yaml

  connection: &my-port
    accepter: telnet(rfc2217),tcp,3001
    connector: serialdev,/dev/ttyUSB1,115200N81
    options:
      mdns: true

then you can connection to it with gensiot:

.. code-block:: bash

  gensiot 'mdns,my-port'

gensiot will find the server, port, and whether telnet and rfc2217 are
enabled and make the connection.

In addition, there is an gmdns tool that lets you do queries and
advertising, and gtlssh can do mDNS queries to find services.  If you
have secure authenticated logins for ser2net, and you enable mdns on
ser2net, like:

.. code-block:: yaml

  connection: &access-console
    accepter: telnet(rfc2217),mux,certauth(),ssl,tcp,3001
    connector: serialdev,/dev/ttyUSBaccess,115200N81
    options:
      mdns: true

it makes the setup very convenient, as you can just do:

.. code-block:: bash

  gtlssh -m access-console

That's right, you can just directly use the connection name, no need
to know the host, whether telnet or rfc2217 is enabled, or what the
port is.  You still have to set up the keys and such on the ser2net
server, of course, per those instructions.

General Concepts
================

gensio has an object oriented interface that is event-driven.
Synchronous interfaces are also available.  You deal with two main
objects in gensio: a gensio and a gensio accepter.  A gensio provides
a communication interface where you can connect, disconnect, write,
receive, etc.

A gensio accepter lets you receive incoming connections.  If a
connection comes in, it gives you a gensio.

The interface is event-driven because it is, for the most part,
completely non-blocking.  If you open a gensio, you give it a callback
that will be called when the connection is up, or the connection
fails.  Same for close.  A write will return the number of bytes
accepted, but it may not take all the bytes (or even any of the bytes)
and the caller must account for that.

The open and close interfaces have a secondary blocking interface for
convenience.  These end in _s.  This is for convenience, but it's not
necessary and use of these must be careful because you can't really
use them from callbacks.

Speaking of callbacks, data and information coming from gensio to the
user is done with a function callback.  Read data, and when the gensio
is ready for write data comes back in a callback.  A similar interface
is used for calling from the user to the gensio layer, but it is
hidden from the user.  This sort of interface is easily extensible,
new operations can be easily added without breaking old interfaces.

The library provides several ways to create a gensio or gensio
accepter.  The main way is str_to_gensio() and
str_to_gensio_accepter().  These provide a way to specify a stack of
gensios or accepters as a string and build.  In general, you should
use this interface if you can.

In general, interfaces that are not performance sensitive are string
based.  You will see this in gensio_control, and in auxiliary data in
the read and write interface to control certain aspects of the write.

The library also provides ways to set up your gensios by individually
creating each one.  In some situations this might be necessary, but it
limits the ability to use new features of the gensio library as it
gets extended.

If a gensio supports multiple streams (like SCTP), stream numbers are
passed in the auxdata with "stream=n".  Streams are not individually
flow controlled.

Channels, on the other hand, are separate flows of data over the same
connection.  Channels are represented as separate gensios, and they
can be individually flow controlled.

Include Files
=============

There are a few include files you might need to deal with when using
gensios:

gensio.h
    The main include files for gensios and gensio accepters.

sergensio.h
    Serial port handling gensios and gensio accepters.

gensio_os_funcs.h
    The definition for an OS handler.

argvutils.h
    Many gensio functions take an argv array, this is utilities for
    dealing with argvs.

gensio_selector.h
    A definition for a default OS handler.

These are for the most part documented in the man pages.

For creating your own gensios, the following include files are
available for you:

gensio_class.h
    The main include file for creating your own gensio.

sergensio_class.h
    The main include file for creating your own serial port gensio.

gensio_base.h
    This handles a lot of the boiler plate for a gensio.  Most of the
    standard gensios use this.  It splits the gensio function into
    an optional filter, and a lower layer interface called an ll.

gensio_ll_fd.h
    An ll that provides most of the boilerplate for dealing with a
    file descriptor.

gensio_ll_gensio.h
    An ll that provides all that is necessary for stacking a gensio
    on top of another gensio.  The filter gensios (telnet, ssl, etc.)
    use this as the ll.

Each include file has lots of documentation about the individual calls
and handlers.

Errors
======

gensio has it's own set of errors to abstract it from the OS errors
(named GE_xxx) and provide more flexibility in error reporting.  These
are in the gensio_err.h include file (automatically included from
gensio.h) and may be translated from numbers to a meaningful string
with gensio_err_to_str().  Zero is defined to be not an error.

If an unrecongnized operating system error occurs, GE_OSERR is
returned and a log is reported through the OS handler log interface.

OS Handler
==========

One slightly annoying thing about gensio is that it requires you to
provide an OS handler (struct gensio_os_funcs) to handle OS-type
functions like memory allocation, mutexes, the ability to handle file
descriptors, timers and time, and a few other things.

The library does provide several OS handlers.  The get the default one
for your system (POSIX or Windows) call gensio_default_os_hnd().  You
can see that man page for more details.  This will generally be the
best performing option you have for your system.

For POSIX systems, OS handlers for glib and TCL are available,
allocated with gensio_glib_funcs_alloc() and gensio_tcl_funcs_alloc().
These really don't work very well, especially from a performance point
of view, the APIs for glib and TCL are not well designed for what
gensio does.  TCL can only support single-threaded operation.  glib
multithreaded operation only has one thread at a time waiting for I/O.
But they do work, and the tests are run with them.  These are not
available on Windows because of poor abstractions on glib and because
of lack of motivation on TCL.

But if you are using something else like X Windows, etc that has it's
own event loop, you may need to adapt one for your needs.  But the
good thing is that you can do this, and integrate gensio with pretty
much anything.

There is also a waiter interface that provides a convenient way to
wait for things to occur while running the event loop.  This is how
you generally enter the event loop, because it provides a convenient
way to signal when you are done and need to leave the loop.

Documentation for this is in::

  include/gensio/gensio_os_funcs.h

Creating a gensio
=================

Connecting gensios
------------------

To create a gensio, the general way to do this is to call
``str_to_gensio()`` with a properly formatted string.  The string is
formatted like so::

  <type>[([<option>[,<option[...]]])][,<type>...][,<end option>[,<end option>]]

The ``end option`` is for terminal gensios, or ones that are at the
bottom of the stack.  For instance, ``tcp,localhost,3001`` will create
a gensio that connects to port 3001 on localhost.  For a serial port,
an example is ``serialdev,/dev/ttyS0,9600N81`` will create a connection
to the serial port /dev/ttyS0.

This lets you stack gensio layers on top of gensio layers.  For
instance, to layer telnet on top of a TCP connection:

.. code-block:: bash

  telnet,tcp,localhost,3001

Say you want to enable RFC2217 on your telnet connection.  You can add
an option to do that:

.. code-block:: bash

  telnet(rfc2217=true),tcp,localhost,3001

When you create a gensio, you supply a callback with user data.  When
events happen on a gensio, the callback will be called so the user
could handle it.

gensio accepters
----------------

A gensio accepter is similar to a connecting gensio, but with
``str_to_gensio_accepter()`` instead.  The format is the same.  For
instance:

.. code-block:: bash

  telnet(rfc2217=true),tcp,3001

will create a TCP accepter with telnet on top.  For accepters, you
generally do not need to specify the hostname if you want to bind to
all interfaces on the local machine.

Using a gensio
==============

Once you have created a gensio, it's not yet open or operational.  To
use it, you have to open it.  To open it, do:

.. code-block:: c

  struct gensio *io;
  int rv;

  rv = str_to_gensio("tcp,localhost,3001", oshnd,
                     tcpcb, mydata, &io);
  if (rv) { handle error }
  rv = gensio_open(io, tcp_open_done, mydata);
  if (rv) { handle error }

Note that when ``gensio_open()`` returns, the gensio is not open.  You
must wait until the callback (``tcp_open_done()`` in this case) is
called.  After that, you can use it.

Once the gensio is open, you won't immediately get any data on it
because receive is turned off.  You must call
``gensio_set_read_callback_enable()`` to turn on and off whether the
callback (``tcpcb`` in this case) will be called when data is received.

When the read handler is called, the buffer and length is passed in.
You do not have to handle all the data if you cannot.  You *must*
update the buflen with the number of bytes you actually handled.  If
you don't handle data, the data not handled will be buffered in the
gensio for later.  Not that if you don't handle all the data, you
should turn off the read enable or the event will immediately called
again.

If something goes wrong on a connection, the read handler is called
with an error set.  ``buf`` and ``buflen`` will be NULL in this case.

For writing, you can call ``gensio_write()`` to write data.  You may
use ``gensio_write()`` at any time on an open gensio.
``gensio_write()`` may not take all the data you write to it.  The
``count`` parameter passes back the number of bytes actually taken in
the write call.

You can design your code to call
``gensio_set_write_callback_enable()`` when you have data to send and
the gensio will call the write ready callback and you can write from
the callback.  This is generally simpler, but enabling and disabling
the write callback adds some overhead.

A more efficient approach is to write data whenever you need to and
have the write callback disabled.  If the write operation returns less
than the full request, the other end has flow-controlled and you
should enable the write callback and wait until it is called before
sending more data.

In the callbacks, you can get the user data you passed in to the
create call with ``gensio_get_user_data()``.

Note that if you open then immediately close a gensio, this is fine,
even if the open callback hasn't been called.  The open callback may
or may not be called in that case, though, so it can be difficult to
handle this properly.

Synchronous I/O
---------------

You can do basic synchronous I/O with gensios.  This is useful in some
situations where you need to read something inline.  To do this, call:

.. code-block:: c

  err = gensio_set_sync(io);

The given gensio will cease to deliver read and write events.  Other
events *are* delivered.  Then you can do:

.. code-block:: c

  err = gensio_read_s(io, &count, data, datalen, &timeout);
  err = gensio_write_s(io, &count, data, datalen, &timeout);

Count is set to the actual number of bytes read/written.  It may be
NULL if you don't care (though that doesn't make much sense for read).

Timeout may be NULL, if so then wait for forever.  If you set a
timeout, it is updated to the amount of time left.

Note that signals will cause these to return immediately, but no
error is reported.

Reads will block until some data comes in and returns that data.  It
does not wait until the buffer is full.  timeout is a timeval, the
read will wait that amount of time for the read to complete and
return.  A timeout is not an error, the count will just be set to
zero.

Writes block until the whole buffer is written or a timeout occurs.
Again, the timeout is not an error, the total bytes actually written
is returned in count.

Once you are done doing synchronous I/O with a gensio, call:

.. code-block:: c

  err = gensio_clear_sync(io);

and delivery through the event interface will continue as before.  You
must not be in a synchronous read or write call when calling this, the
results will be undefined.

Note that other I/O on other gensios will still occur when waiting for
synchronous I/O

There is not currently a way to wait for multiple gensios with
synchronous I/O.  If you are doing that, you should really just use
the event-driven I/O.  It's more efficient, and you end up doing the
same thing in the end, anyway.

Using a gensio accepter
=======================

Like a gensio, a gensio accepter is not operational when you create
it.  You must call ``gensio_acc_startup()`` to enable it:

.. code-block:: c

  struct gensio_accepter *acc;
  int rv;

  rv = str_to_gensio_accepter("tcp,3001", oshnd,
                              tcpacccb, mydata, &acc);
  if (rv) { handle error }
  rv = gensio_startup(acc);
  if (rv) { handle error }

Note that there is no callback to the startup call to know when it's
enabled, because there's no real need to know because you cannot write
to it, it only does callbacks.

Even after you start up the accepter, it still won't do anything until
you call ``gensio_acc_set_accept_callback_enable()`` to enable that
callback.

When the callback is called, it gives you a gensio in the ``data``
parameter that is already open with read disabled.  A gensio received
from a gensio acceptor may have some limitations.  For instance, you
may not be able to close and then reopen it.

gensio accepters can do synchronous accepts using ``gensio_acc_set_sync()``
and ``gensio_acc_accept_s``.  See the man pages on those for details.

Logging
=======

``struct gensio_os_funcs`` has a vlog callback for handling internal
gensio logs.  These are called when something of significance happens
but gensio has no way to report an error.  It also may be called to
make it easier to diagnose an issue when something goes wrong.

Serial I/O
==========

The gensio and gensio accepter classes each have subclasses for
handling serial I/O and setting all the parameters associated with a
serial port.

You can discover if a gensio (or any of its children) is a serial port
by calling ``gensio_to_sergensio()``.  If that returns NULL, it is not
a sergensio and none of it's children are sergensios.  If it returns
non-NULL, it returns the sergensio object for you to use.  Note that
the gensio returned by ``sergensio_to_gensio()`` will be the one
passed in to ``gensio_to_sergensio()``, not necessarily the gensio
that sergensio is directly associated with.

A sergensio may be a client, meaning that it can set serial settings,
or it may be a server, meaning that it will receive serial settings
from the other end of the connection.

Most sergensios are client only: serialdev (normal serial port),
ipmisol, and stdio accepter.  Currently only telnet has both client
and server capabilities.


Python Interface
================

NOTE: The python interface described here is deprecated.  Use the one
in c++/swig/pygensio now.

You can access pretty much all of the gensio interface through python,
though it's done a little differently than the C interface.

Since python is fully object oriented, gensios and gensio accepters
are first-class objects, along with gensio_os_funcs, sergensios, and
waiters.

Here's a small program:

.. code-block:: python

  import gensio

  class Logger:
      def gensio_log(self, level, log):
          print("***%s log: %s" % (level, log))

  class GHandler:
      def __init__(self, o, to_write):
          self.to_write = to_write
          self.waiter = gensio.waiter(o)
          self.readlen = len(to_write)

      def read_callback(self, io, err, buf, auxdata):
          if err:
              print("Got error: " + err)
              return 0
          print("Got data: " + buf);
          self.readlen -= len(buf)
          if self.readlen == 0:
              io.read_cb_enable(False)
              self.waiter.wake()
          return len(buf)

      def write_callback(self, io):
          print("Write ready!")
          if self.to_write:
              written = io.write(self.to_write, None)
              if (written >= len(self.to_write)):
                  self.to_write = None
                  io.write_cb_enable(False)
              else:
                  self.to_write = self.to_write[written:]
          else:
              io.write_cb_enable(False)

      def open_done(self, io, err):
          if err:
              print("Open error: " + err);
              self.waiter.wake()
          else:
              print("Opened!")
              io.read_cb_enable(True)
              io.write_cb_enable(True)

      def wait(self):
          self.waiter.wait_timeout(1, 2000)

  o = gensio.alloc_gensio_selector(Logger())
  h = GHandler(o, "This is a test")
  g = gensio.gensio(o, "telnet,tcp,localhost,2002", h)
  g.open(h)

  h.wait()

The interface is a pretty direct translation from the C interface.  A
python representation of the interface is in swig/python/gensiodoc.py,
you can see that for documentation.

C++
===

The C++ interface is documented in c++/README.rst.

pygensio
========

The new pygensio interface is a cleaner implementation using swig
directors instead of hand-coded callbacks into python.  See the
README.rst in c++/swig/pygensio.  There are also glib and tcl OS_Funcs
in the glib and tcl directories.

GO
===

The full C++ interface is available to Go programs through swig and
swig directors.  See c++/swig/go/README.rst for details.

=============
Running Tests
=============

There are a number of tests for gensios.  They currently only run on
Linux and require some external tools.

They require the serialsim kernel module and python interface.  These
are at https://github.com/cminyard/serialsim and allow the tests to
use a simulated serial port to read modem control line, inject errors,
etc.

You can get by without serialsim if you have three serial devices: one
hooked in echo mode (RX and TX tied together) and two serial devices
hooked together do I/O on one device goes to/comes from the other.
Then set the following environment variables:

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
