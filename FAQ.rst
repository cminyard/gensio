==========
gensio FAQ
==========

Here are some answer to questions about gensio.

* Why did you create gensio?

  Originally gensio was part of ser2net
  (https://sourceforge.net/projects/ser2net).  I was rewriting ser2net
  to add in encryption and authentication, and I needed some sort of
  layered protocol handling to do this.  I realized that I had a
  fairly general purpose library that I couldn't find anything else
  like (except maybe System V Streams?  remember those?), so it made
  sense to split it out into it's own thing.

  It then grew to add things on I needed for other reasons, or to
  provide proof of concept.

* Why don't you have ssh support?

  I would dearly love to have ssh support.  However, I can't find a
  library that is really suitable.  The openssh and libssh2 code only
  lets you have a single connection at a time and uses tons of global
  variables.  Obviously not suitable.  libssh might work, but it is
  not nicely layered where I could split it out and provide just a
  protocol layer without sockets underneath.  It might be possible to
  integrate libssh as a base gensio, but I didn't like that very much.
  libwebsockets has a client implementation that might work, but it's
  only a client implementation.  If anyone knows of a suitable library,
  I'd be happy to hear about it.

* You wrote a mux implementation.  Why didn't you use websockets?

  That was my first inclination.  However, websockets has no mechanism
  for flow control.  I almost didn't believe it at first.  The
  websocket description talks about the user implementing their own
  flow control.  Take the hardest part of the problem and pass it to
  the user.  The design of gensio is all about flow-control.  If I
  used websockets, I'd have to write a flow-control implementation on
  top of it, and that would be non-standard anyway.

* Why did you write gtlssh and gtlsshd?  Isn't ssh good enough?

  Well, ssh is fine, I use it all the time.  gtlssh and gtlsshd were
  written more as a proof of concept to make sure I got all the pieces
  necessary to implement proper authentication with a reasonable
  amount of flexibility.  With that said, they provide about
  everything that ssh can do except for X11 forwarding, which is kind
  of a pain.  And they are only about 1500 LOC each.  The only really
  annoying thing about them is that keys expire, since they are based
  on SSL.  Which is probably a good thing, since keys need to be
  replaced every once in a while.  gtlssh will warn you if you key
  expires in less than 30 days.  If that's too much of a problem, make
  keys that expire in 100 years.

* What's the deal with SCTP?

  SCTP is a nice protocol for a number of reasons.  It has
  multi-homing, meaning that both sides communicate all the IP
  addresses that they have, and communicate when they change, and use
  all of them.  So you could have a connection stay up even if a
  server transitions over to new IP addresses.  It has better
  protection agains SYN attacks.  A few other things.

  That said, the current implementations of SCTP (at least the one on
  Linux) leave something to be desired.  There are performance issues
  and some unimplemented features.

* Is IPv6 supported?

  Of course.  Full support.  The documentation describes how to use
  it.  The library tries to make unsurprising decisions, but
  everything can be overridden.

* How to run gtlsshd on Windows

  gtlsshd works on Windows, but you must run as System or LocalSystem for the
  proper privileges.  Normally you would start it with Task Scheduler, which
  has that option, but if you want to run it by hand for testing or debugging,
  you need to do the following:

  * Run a command prompt as an administrator.
  * Run "psexec -sid cmd".  This will open a new window running as System.
  * PATH=C:\\msys64\\mingw64\\bin;%PATH%
    or
    PATH=C:\\msys64\\ucrt64\\bin;%PATH%
  * C:\\...\\gtlsshd -d -d
  * You can also run it in gdb for debugging.

  where the "..." is the path to gtlsshd.

  To run it under task scheduler, you probably need something like the
  following script to make it work::

    PATH=C:\msys64\mingw64\bin;%PATH%
    C:\...\gtlsshd

  with ucrt64 instead of mingw64 if you are using that.  You can use
  an absolute patch to gtlsshd.exe and start the program in
  C:\\msys64\\ming64\\bin so it will pick up the dlls from the bin
  directory, then you don't need a script.  If the ming64 or ucrt64
  bin directories are in the standard path, this won't matter.

  All the gensio dlls are installed in the bin directory, you will
  need that directory in your path to be able to load gensios.

  Also, setting the permissions on C:\\etc\\gtlssh\\gtlsshd.key is important.  It
  must be accessible only by SYSTEM and Administrator.  This is checked by
  gtlsshd at startup, and if it is wrong you will get::

    error: C:\etc\gtlssh\gtlsshd.key is accessible by others, giving up

  when gtlsshd is started with debugging enabled.  To fix this, you
  must bring up the file in file explorer, disable inherited
  permissions, and delete the non SYSTEM and Administrator users.

  You will allso need to add a rule in the firewall to let connections
  through.

* Issues with openssl and signal masks

  openssl calls sigprocmask() in it's startup code for ARM and some
  other processors.  On at least macos, this affects all threads, not
  just the calling thread.  So if you load it while threads are
  running, it will modify the thread masks of all running threads, and
  screw things up for waking using signals.  configure checks for this
  on platforms that need it, and link -lssl to the main program to
  avoid the issue.
