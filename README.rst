===========================
gensio - General Stream I/O
===========================

.. image:: https://www.bestpractices.dev/projects/9971/badge
   :target: https://www.bestpractices.dev/projects/9971

This is gensio (pronounced gen'-see-oh), a framework for giving a
consistent view of various stream (and packet) I/O types.  You create
a gensio object (or a gensio), and you can use that gensio without
having to know too much about what is going on underneath.  You can
stack gensio on top of another one to add protocol functionality.  For
instance, you can create a TCP gensio, stack SSL on top of that, and
stack Telnet on top of that.  It supports a number of network I/O and
serial ports.  It also supports sound interfaces.  gensios that stack
on other gensios are called filters.

You can do the same thing with receiving ports.  You can set up a
gensio accepter to accept connections in a stack.  So in our previous
example, you can setup TCP to listen on a specific port and
automatically stack SSL and Telnet on top when the connection comes
in, and you are not informed until everything is ready.

gensio works on Linux, BSDs, MacOS, and Windows.  On Windows, it gives
you a single-threaded capable (but also multi-thread capable)
event-driven interface (with blocking interfaces available) to
simplify programming with lots of I/Os.  It goes a long way to making
writing portable I/O driven code easy.

A *very* important feature of gensio is that it makes establishing
encrypted and authenticated connections much easier than without it.
Beyond basic key management, it's really no harder than TCP or
anything else.  It offers extended flexibility for controlling the
authentication process if needed.  It's really easy to use.

Note that the gensio(5) man page has more details on individual gensio
types.

For instructions on building this from source, see the "BUILDING"
document.

For info on how to use the library, see the "USING" document.

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

    There is a item in FAQ.rst named "How to run gtlsshd on Windows",
    see that and the Building on Windows section in the BUILDING
    document for more details, as there are a few tricky things you
    have to handle.

gtlssh
    An ssh-like program that can connect to gtlsshd.  It can also
    be used with ser2net to make establishing encrypted and
    authenticated connections easier.  See gtlssh(1) for details.

gtlssh-keygen
    Used for handling keys for gtlssh and gtlsshd.  See gtlssh-keygen(1)
    for details.

gmdns
    Used to provide and query MDNS.  See gmdns(1) for details.

gsound
    Used to play or record sound.  See gsound(1) for details.

Available gensios
=================

The following gensios are available in the library:

sctp
    Normal SCTP communication.  Streams and out of bound data are
    supported.  End of message demarcation is not supported because it
    doesn't currently work on Linux.

tcp
    Normal TCP communication.  Out of bound data is supported.

unix
    Unix stream domain socket.

unixdgram
    Unix datagram domain socket.  This is sort-of connection oriented.

unixseq
    Unix seqpacket domain socket.  Probably only works on Linux.

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

      gtlsshd --notcp --oneshot --nodaemon --other_acc
         'conacc,relpkt(mode=server),msgdelim,serialdev,/dev/ttyUSB1,115200n81'

    You could connect with:

    .. code-block:: bash

      gtlssh --transport 'relpkt,msgdelim,serialdev,/dev/ttyUSB2,115200n81' USB2

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

chardelay
    Delay sending characters until a certain number have been received
    or a certain amount of time has passed.  Used to avoid sending a
    bunch of small packets on an interface.

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
