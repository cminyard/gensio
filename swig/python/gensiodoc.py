#
#  gensio - A library for abstracting stream I/O
#  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
#
#  SPDX-License-Identifier: LGPL-2.1-only
#

# This file documents the python interface to gensio via the normal
# python documentation method.  It is not functional.

class LogHandler:
    """A template class used by gensio_os_funcs to generate logs."""
    def gensio_log(self, level, log):
        """gensio has generated a log.

        level -- A log level string: "fatal", "error", "warning",
                "info", or "debug"
        log -- The log text
        """
        return

class gensio_os_funcs:
    """This class is used to provide OS handling functions, the same as
    "struct gensio_os_funcs" in the C interface.  If you need a custom
    one, you might have to provide a Python/C interface to allocate it.
    """

def alloc_gensio_selector(h):
    """Allocate a default gensio_os_funcs for your platform.

    h -- A LogHandler class for receiving logs.

    Returns a gensio_os_funcs object.
    """
    return gensio_os_funcs()

class EventHandler:
    """A template class for handling events from a gensio.  All the
    possible callback events are here, they are the same as the C
    interfce GENSIO_EVENT_xxx defines.
    """
    def read_callback(io, err, data, auxdata):
        """Read data from the gensio, or error reporting.  When data comes in
        for the gensio, it is sent here if read is enabled.  Also, if
        something happens like an error or the gensio closes, it is
        reported through this interface (again, if read is enabled).

        io -- The gensio object reporting the read data.
        err -- An error string. If no error, this will be None, otherwise
               it is a string.  Some are not really errors, for instance
               "Remote end closed connection" just means the other end
               did a close.
        data -- A byte string holding the read data.
        auxdata -- Auxiliary data describing the read.  This is a sequence
               of strings. Some interfaces will have an "oob" string for
               out-of-bounds data (TCP and SCTP).  SCTP can have a
               channel number.  See the gensio description for details.

        Return the number of bytes consumed.  THIS IS IMPORTANT.  If
        you return 0, it will assume you did not consume any of the data
        and give you the same data again immediately.
        """
        return 0

    def write_callback(self, io):
        """Data can be written on the gensio.  You should generally
        use this for writing your data.  You can directly call the
        write() method, but it may not take all the data and you need
        a way to get it the rest of the data.

        io -- The gensio object reporting write ready.
        """
        return

    def new_channel(self, old_io, new_io, auxdata):
        """A new channel has been requested from the other end.

        old_io - an existing channel on a mux gensio
        new_io - a new channel for the mux gensio

        Return an integer. If you return 0, the new channel is
        accepted.  If you return a GE_xxx erro, it is considered a gensio
        error and that error is reported as an open channel failure on
        the remote end.  If you return non-zero, the new_io is freed,
        you should not use it.
        """
        return

    def send_break(self, io):
        """The remote end has requested that a break be sent.  This
        is for a telnet server where the remote end sent a break.

        io -- The gensio that received the break.
        """
        return

    def auth_begin(self, io):
        """An authorization event has begun.  This is used by certauth server
        side to report that authorization has begun from the client.
        The service and username will be available via controls, but
        other information is not available.

        io -- The gensio starting authorization.

        Return GE_NOTSUP to continue authentication, GE_AUTHREJECT to
        terminate the authentication, and 0 to cause the
        authentication to succeed.

        """
        return gensio.GE_NOTSUP

    def precert_verify(self, io):
        """Called from ssl and certauth server after a certificate has
        been received but before it is verified.  This allows the
        certificate to be examined with GENSIO_CONTROL_GET_PEER_CERT_NAME.
        Possible actions are rejecting the authentication, causing it to
        succeed, or continuing the authentication.  The certificate authority
        file/directory can be set with GENSIO_CONTROL_CERT_AUTH.

        io -- The gensio owning the certificate.

        Return GE_NOSUP to continue authentication, GE_AUTHREJECT to
        terminate the authentication, or 0 to cause the authentication
        to succeed.
        """
        return gensio.GE_NOTSUP

    def postcert_verify(self, io, err, errstr):
        """Called from certauth server after a certificate has been
        verified.  The results of the verification are reported in
        err and errstr.

        io -- The gensio owning the certificate.
        err -- An integer error, one of 0 (success), GE_CERTREVOKED,
            GE_CERTEXPIRED, or GE_CERTINVALID.
        errstr - Either None if the error string was not available,
            or a string representing the error.

        Return GE_NOSUP to continue authentication, GE_AUTHREJECT to
        terminate the authentication, or 0 to cause the authentication
        to succeed.
        """
        return gensio.GE_NOTSUP

    def password_verify(self, io, password):
        """Called from certauth server to report a password verification
        request from the client.  The certauth code will not do it's own
        password verification, it relies on the code using it to do this.

        io -- The gensio requesting verification.
        password -- The password string to verify.

        Return GE_NOTSUP to continue authentication (causing it to
        reject the password, or 0 to cause the authentication to
        succeed.  GE_AUTHREJECT will also reject the password

        """
        return gensio.GE_NOTSUP

    def request_password(self, io):
        """Called from the certauth client to request a password from
        the user.

        io -- The gensio requesting the password.

        Return a password string.
        """
        return ""

    def verify_2fa(self, io, data_2fa):
        """Called from certauth server to report a 2-factor authentication
        verification request from the client.  The certauth code will
        not do it's own verification, it relies on the code using it
        to do this.

        io -- The gensio requesting verification.
        data_wfa -- The 2-factor authentication byte string to verify.

        Return GE_NOTSUP to continue authentication (causing it to
        reject the password, or 0 to cause the authentication to
        succeed.  GE_AUTHREJECT will also reject the password

        """
        return gensio.GE_NOTSUP

    def request_2fa(self, io):
        """Called from the certauth client to request 2-factor auth data from
        the user.

        io -- The gensio requesting the password.

        Return a 2fa byte string.

        """
        return ""

    def signature(self, sio):
        """Called from the telnet server to report that the client has
        requested the RFC2217 signature.  Call sg_signature(signature,
        None) with the signature.

        sio -- The sergensio object requesting the signature.

        """
        return

    def flush(self, sio, val):
        """Called from telnet server or client to report that a flush has been
        requested.

        sio -- The sergensio object requesting the flush.
        val -- The flush type, one of SERGENSIO_FLUSH_RCV_BUFFER,
            SERGENSIO_FLUSH_XMIT_BUFFER, or SERGENSIO_FLUSH_RCV_XMIT_BUFFERS.
        """
        return

    def sync(self, sio):
        """Called from telnet server or client to report that a sync has been
        requested.

        sio -- The sergensio object requesting the sync.
        """
        return

    def flowcontrol_state(self, sio, disable):
        """Called from telnet server or client to report that a sync has been
        requested.  If this is received with a disable request, then the
        local end should not send any data or commands.

        sio -- The sergensio object requesting the flow control state change.
        disable -- A boolean, if true then disable transmission, if false then
            enable transmission
        """
        return

    def sbaud(self, sio, val):
        """Called from telnet server to report that a baud change has been
        requested.  sg_baud(val, None) should be called when the
        change is complete to report the actual baud rate set.

        sio -- The sergensio object requesting the change.
        val -- The baud rate as an integer.
        """
        return

    def sdatasize(self, sio, val):
        """Called from telnet server to report that a data size change has
        been requested.  sg_datasize(val, None) should be called when the
        change is complete to report the actual data size set.

        sio -- The sergensio object requesting the change.
        val -- The data size as an integer, 5, 6, 7, or 8.
        """
        return

    def sparity(self, sio, val):
        """Called from telnet server to report that a parity change has
        been requested.  sg_parity(val, None) should be called when the
        change is complete to report the actual parity set.

        sio -- The sergensio object requesting the change.
        val -- The parity, one of SERGENSIO_PARITY_NONE,
            SERGENSIO_PARITY_ODD, SERGENSIO_PARITY_EVEN,
            SERGENSIO_PARITY_MARK, SERGENSIO_PARITY_SPACE.
        """
        return

    def sstopbits(self, sio, val):
        """Called from telnet server to report that a stop bit change has
        been requested.  sg_stopbits(val, None) should be called when the
        change is complete to report the actual number of stop bits set.

        sio -- The sergensio object requesting the change.
        val -- The stop bits as an integer, 1 or 2.
        """
        return

    def sflowcontrol(self, sio, val):
        """Called from telnet server to report that a flow control change has
        been requested.  sg_flowcontrol(val, None) should be called when the
        change is complete to report the actual flow control set.

        sio -- The sergensio object requesting the change.
        val -- The flow control state, one of SERGENSIO_FLOWCONTROL_NONE,
            SERGENSIO_FLOWCONTROL_XON_XOFF, SERGENSIO_FLOWCONTROL_RTS_CTS.
        """
        return

    def siflowcontrol(self, sio, val):
        """Called from telnet server to report that a input flow control
        change has been requested.  sg_iflowcontrol(val, None) should
        be called when the change is complete to report the actual
        flow control set.

        sio -- The sergensio object requesting the change.
        val -- The input flow control state, one of
            SERGENSIO_FLOWCONTROL_DCD, SERGENSIO_FLOWCONTROL_DTR,
            SERGENSIO_FLOWCONTROL_DSR, SERGENSIO_FLOWCONTROL_NONE
        """
        return

    def sbreak(self, sio, val):
        """Called from telnet server to report that a break
        change has been requested.  sg_break(val, None) should
        be called when the change is complete to report the actual
        break value set.

        sio -- The sergensio object requesting the change.
        val -- The break setting, either SERGENSIO_BREAK_ON or
            SERGENSIO_BREAK_OFF.
        """
        return

    def sdtr(self, sio, val):
        """Called from telnet server to report that a DTR
        change has been requested.  sg_dtr(val, None) should
        be called when the change is complete to report the actual
        DTR set.

        sio -- The sergensio object requesting the change.
        val -- The DTR setting, either SERGENSIO_DTR_ON or
            SERGENSIO_DTR_OFF.
        """
        return

    def srts(self, sio, val):
        """Called from telnet server to report that a RTS
        change has been requested.  sg_rts(val, None) should
        be called when the change is complete to report the actual
        RTS set.

        sio -- The sergensio object requesting the change.
        val -- The RTS setting, either SERGENSIO_RTS_ON or
            SERGENSIO_RTS_OFF.
        """
        return

    def modemstate(self, modemstate):
        """Called from a sergensio object when a modemstate monitor is enabled
        and a modemstate value changes..

        modemstate -- A bitmask of SERGENSIO_MODEMSTATE_CTS,
            SERGENSIO_MODEMSTATE_DSR, SERGENSIO_MODEMSTATE_RI and
            SERGENSIO_MODEMSTATE_CD.  This is the current modemstate
            values.  If a value has changed, this is reported in the bits
            SERGENSIO_MODEMSTATE_CTS_CHANGED,
            SERGENSIO_MODEMSTATE_DSR_CHANGED,
            SERGENSIO_MODEMSTATE_RI_CHANGED, and
            SERGENSIO_MODEMSTATE_CD_CHANGED.
        """

    def linestate(self, modemstate):
        """Called from a sergensio object when a linestate monitor is enabled
        and a particular linestate event occurs.

        linesate -- A bitmask of
            SERGENSIO_LINESTATE_DATA_READY,
            SERGENSIO_LINESTATE_OVERRUN_ERR,
            SERGENSIO_LINESTATE_PARITY_ERR,
            SERGENSIO_LINESTATE_FRAMING_ERR,
            SERGENSIO_LINESTATE_BREAK,
            SERGENSIO_LINESTATE_XMIT_HOLD_EMPTY,
            SERGENSIO_LINESTATE_XMIT_SHIFT_EMPTY, and
            SERGENSIO_LINESTATE_TIMEOUT_ERR.
        """

class OpenDone:

        """A template for a class handling the finish of an open."""

    def open_done(self, io, err):
        """Called when the open operation completes.

        io -- The gensio that was opened.
        err -- An error string, None if no error.
        """
        return

class CloseDone:
    """A template for a class handling the finish of an close."""

    def close_done(self, io):
        """Called when the close operation completes.

        io -- The gensio that was closed.
        """
        return

class gensio:
    def __init__(o, gensiostr, handler):
        """Allocate a gensio.

        o -- The gensio_os_funcs object to use for this gensio.
        gensiostr -- A string describing the gensio stack.  See the gensio
            documentation for details.
        handler -- An EventHandler object to receive events
        """
        return

    def new_parent(self, o, gensiostr, handler):
        """Allocate a new gensio filter stacked on top of this gensio.
        This is the equivalent of str_to_gensio_child().

        o -- The gensio_os_funcs object to use
        gensiostr -- A string describing just the gensio filter.
        handler -- An EventHandler object to receive events.

        Returns a new gensio
        """
        return gensio()

    def set_cbs(self, handler):
        """Change the callback handler for the gensio.  This should
        only be done when all I/O is disabled.

        handler -- An EventHandler object to receive events.
        """
        return

    def remote_id(self):
        """Return the remote_id value for this gensio.  See the specific
        gensio for the meaning.

        Returns an integer value.
        """
        return

    def open(self, done_handler):
        """Start up operation on the gensio.  Calls done_handler.open_done
        when the open operation completes.

        done_handler -- A class (like OpenDone) that has an open_done()
        method to call when the operation completes.

        """
        return

    def open_nochild(self, done_handler):
        """Start up operation on the gensio, assuming that the child gensio is
        already open.  Useful with the new_parent() method above.  Calls
        done_handler.open_done when the open operation completes.

        done_handler -- A class (like OpenDone) that has an open_done()
        method to call when the operation completes.

        """
        return

    def open_s(self):
        """Like open(), but waits for the open to complete and raises an
        exception on an error.  The wait operation is a normal waiter,
        so gensio is fully operational during the wait.
        """
        return

    def open_nochild_s(self):
        """Like open_nochild(), but waits for the open to complete and raises
        an exception on an error.  The wait operation is a normal
        waiter, so gensio is fully operational during the wait.
        """
        return

    def alloc_channel(self, args, handler):
        """Create a new channel on the gensio.  This is gensio-specific, most
        gensios don't support channels.

        args -- A sequence of strings holding arguments for the channel.
        handler -- The EventHandler object to receive events for the channel.
        done -- An OpenDone type class whose open_done() method is called
            when the open is complete.
        """
        return

    def get_type(self):
        """Return the type string for the gensio."""
        return

    def close(self, close_done):
        """Close the gensio.  If it is not open this will raise an exception.
        When the close_done() method is called, the gensio is closed.

        close_done -- A CloseDone type object whose close_done()
            method gets called when the close is complete.
        """
        return

    def close_s(self):
        """Like close(), but waits for the close to complete.  The wait
        operation is a normal waiter, so gensio is fully operational
        during the wait.
        """
        return

    def write(self, bytestr, auxdata):
        """Write the given byte string.

        bytestr -- The data to write.
        auxdata -- A sequence of strings holding gensio-specific auxiliary
            data.  May be None if it's not applicable.

        Returns the actual number of bytes written.  This may be less
        than the given bytes, so you must account for that when calling
        write().
        """
        return 0

    def read_cb_enable(self, enable):
        """Allow read events from the gensio.  When the gensio is opened read
        is disabled, you must call this to get read events to
        read_callback().  Note that some gensios, like UDP, don't
        perform well if read is disabled a lot.  You should generally
        leave this enabled as much as possible.  You should only
        disable it if you cannot handle new data.

        enable -- A boolean, whether to enable or disable read events

        """
        return

    def write_cb_enable(self, enable):
        """Allow write ready events from the gensio.  When the gensio is
        opened write callbacks are enabled.  You should generally leave
        them disabled until you have data to write, then enable it
        and write to the gensio in the write_callback() events.

        enable -- A boolean, whether to enable or disable callback events
        """
        return

    def set_sync(self):
        """Enable synchronous I/O on the gensio.  If you call this, then read
        and write events will not go the the event handler (though
        other events will).  You must call the read_s() and write_s()
        methods to do I/O.
        """
        return

    def clear_sync(self):
        """Disable synchronous I/O on the gensio.  If you call this, then read
        and write events will go the the event handler.  Read and
        write events will be disabled by this function, you must
        enable them to start event processing.
        """
        return

    def read_s(self, reqlen, timeout):
        """Read data from the gensio synchronously.  This will read up to
        reqlen bytes and may have a timeout.  Note that this will
        return as soon as it has any data, even if it is less than
        reqlen.

        reqlen -- The number of bytes to read.
        timeout -- The number of milliseconds to wait for the data.  If -1,
            the timeout is disabled.

        Returns a sequence with a bytestr as the first item and the
        number of milliseconds left on the timeout as the second item.
        If the returned timeout is 0, the operation timed out.
        """
        return { bytes(""), 0 }

    def read_s_intr(self, reqlen, timeout):
        """Like read_s, but raises an exception for GE_INTERRUPTED if a
        signal comes in while waiting.
        """
        return { bytes(""), 0 }

    def write_s(self, bytestr, timeout):
        """Attempt to write the given byte string to the gensio.  This
        will wait up to timeout milliseconds for the write to complete.

        bytestr -- The bytes to write.
        timeout -- The number of milliseconds to wait for the write to
            complete.  Use -1 to disable the timeout.

        Returns a sequence with two items: the number of bytes
        actually written and the number of milliseconds left on the
        timeout.
        """
        return { 0, 0 }

    def write_s_intr(self, bytestr, timeout):
        """Like write_s, but raises an exception for GE_INTERRUPTED if a
        signal comes in while waiting.
        """
        return { 0, 0 }

    def control(self, depth, get, option, data):
        """Do a gensio-specific control operation.  See the specific gensios
        and the C interface for specific gensio controls.

        depth -- The gensio in the stack to choose.  0 selects the top
            gensio, 1 the second from the top, etc.
            GENSIO_CONTROL_DEPTH_ALL will call the control on every gensio
            in the stack, GENSIO_CONTROL_DEPTH_FIRST will call the control
            down the stack until a control doesn't return GE_NOTSOP.
        get -- A boolean specifying if this is a get or a put operation.
        option -- The specific gensio control to call.
        data -- A string specifying the data for the control.

        Returns a string with the result data for the control.
        """
        return ""

    def is_client(self):
        """Return whether the gensio is a client or server."""
        return True

    def is_packet(self):
        """Return whether the gensio is a packet interface.  In a packet
        interface, each write on one end will result in a single read
        on the other end with the same amount of data.
        """
        return False

    def is_reliable(self):
        """Return whether the gensio provides reliable data transport.  With
        reliable data transport, bytes will not be dropped and data
        will be delivered in the same order it was sent.
        """
        return True

    def is_authenticated(self):
        """Return whether the gensio has been authenticated.  This is
        primarily for ssl and certauth, if they succeed in their
        authentication algorithms succeeded.
        """
        return False

    def is_encrypted(self):
        """Return whether the data is is encrypted."""
        return False

    def cast_to_sergensio(self):
        """Convert the gensio to a sergensio.

        Returns the sergensio object if the gensio is a sergensio, or
        None if it is not.
        """
        return None

    def same_as(self, other):
        """Compare two gensios to see if they are the same.

        Due to the way python works, you can hold two different
        pointers to the same gensio.  This compares the base data and
        returns True if two gensio object are the same, False if not.
        """
        return False

class SergensioDone:

        """These are methods called when a sergensio request from a client
    completes.  Note that the base code may not honor the request or
    may choose a different value than requested.  Check the returned
    value to be sure.  Also, an error may occur, if the err value is
    not None, it is a string given the error.
    """

    def baud(self, sio, err, val):
        return

    def datasize(self, sio, err, val):
        return

    def parity(self, sio, err, val):
        return

    def stopbits(self, sio, err, val):
        return

    def flowcontrol(self, sio, err, val):
        return

    def iflowcontrol(self, sio, err, val):
        return

    def sbreak(self, sio, err, val):
        return

    def dtr(self, sio, err, val):
        return

    def rts(self, sio, err, val):
        return

    def signature(self, sio, err, sig):
        return

class sergensio:
    """A gensio that is capable of doing serial port operations like baud
    rate, stop bits, modem control, etc.

    Note that on all of these, if you pass in a 0, it will not set the
    value but will return the current value in the callback.

    On a telnet client, these request the operations from the other end.
    On a telnet server, these send the request values back to the client.
    """

    def cast_to_gensio(self):
        """Returns the gensio object for this sergensio.  This cannot fail."""
        return None;

    def sg_baud(self, baud, handler):
        """Set the baud rate to the given baud rate.

        val -- The baud rate as an integer.
        handler -- Call the baud() method on this class when done.
        """
        return

    def sg_datasize(self, datasize, handler):
        """Set the data size to then given value.

        datasize -- One of 5, 6, 7, or 8.
        handler -- Call the datasize() method on this class when done.
        """
        return

    def sg_parity(self, parity, handler):
        """Set the parity on the connection.

        party -- The parity, one of SERGENSIO_PARITY_NONE,
            SERGENSIO_PARITY_ODD, SERGENSIO_PARITY_EVEN,
            SERGENSIO_PARITY_MARK, SERGENSIO_PARITY_SPACE.
        handler -- Call the parity() method on this class when done.
        """
        return

    def sg_stopbits(self, stopbits, handler):
        """Set the number of stop bits.

        stop bits -- One of 1 or 2.
        handler -- Call the stopbits() method on this class when done.
        """
        return

    def sg_flowcontrol(self, flowcontrol, handler):
        """Set the flow control method on the port.

        flowcontrol -- The flow control state, one of
            SERGENSIO_FLOWCONTROL_NONE,
            SERGENSIO_FLOWCONTROL_XON_XOFF, SERGENSIO_FLOWCONTROL_RTS_CTS.
        handler -- Call the flowcontrol() method on this class when done.
        """
        return

    def sg_iflowcontrol(self, iflowcontrol, handler):
        """Set the input flow control method on the port.

        iflowcontrol -- The input flow control state, one of
            SERGENSIO_FLOWCONTROL_DCD, SERGENSIO_FLOWCONTROL_DTR,
            SERGENSIO_FLOWCONTROL_DSR, SERGENSIO_FLOWCONTROL_NONE
        handler -- Call the iflowcontrol() method on this class when done.
        """
        return

    def sg_break(self, sbreak, handler):
        """Set the break state on the port.

        sbreak -- The break setting, either SERGENSIO_BREAK_ON or
            SERGENSIO_BREAK_OFF.
        handler -- Call the sbreak() method on this class when done.
        """
        return

    def sg_dtr(self, dtr, handler):
        """Set the DTR state on the port.

        dtr -- The DTR setting, either SERGENSIO_DTR_ON or
            SERGENSIO_DTR_OFF.
        handler -- Call the dtr() method on this class when done.
        """
        return

    def srts(self, rts, handler):
        """Set the RTS state on the port

        rts -- The RTS setting, either SERGENSIO_RTS_ON or
            SERGENSIO_RTS_OFF.
        handler -- Call the rts() method on this class when done.
        """
        return

    def sg_modemstate(self, modemstate):
        """Set the particular modemstate values that are monitored.
        If the modemstate value is set and it changes, the change
        is reported via the modemstate() event.

        modemstate -- A bitmask of SERGENSIO_MODEMSTATE_CTS,
            SERGENSIO_MODEMSTATE_DSR,
            SERGENSIO_MODEMSTATE_RI, and
            SERGENSIO_MODEMSTATE_CD.
        """
        return

    def sg_linestate(self, linestate):
        """Set the particular linestate values that are monitored.
        If the linestate value is set and it changes, the change
        is reported via the linestate() event.

        linesate -- A bitmask of
            SERGENSIO_LINESTATE_DATA_READY,
            SERGENSIO_LINESTATE_OVERRUN_ERR,
            SERGENSIO_LINESTATE_PARITY_ERR,
            SERGENSIO_LINESTATE_FRAMING_ERR,
            SERGENSIO_LINESTATE_BREAK,
            SERGENSIO_LINESTATE_XMIT_HOLD_EMPTY,
            SERGENSIO_LINESTATE_XMIT_SHIFT_EMPTY, and
            SERGENSIO_LINESTATE_TIMEOUT_ERR.
        """
        return

    def sg_flush(self, val):
        """Request that the remote end do a data flush.

        val -- The flush type, one of SERGENSIO_FLUSH_RCV_BUFFER,
            SERGENSIO_FLUSH_XMIT_BUFFER, or SERGENSIO_FLUSH_RCV_XMIT_BUFFERS.
        """
        return

    def sg_signature(self, sig, handler):
        """On a client, sig should be None, the handler's signature() method
        is called with the signature.  On the server, the handler
        should be None and the sig value is sent to the remote end.
        """
        return

class AccEventHandler:
    """A template class showing which events are generated by a
    gensio_accepter object.
    """

    def log(self, acc, level, logval):
        """An internal error has occurred in the accepter that cannot be
        reported via another mechanism, like an incoming connection
        failed.

        acc -- The gensio_accepter.
        level -- The log level as a string, like "info", "debug", "warning",
            "error", and "fatal".
        logval -- The actual log string.
        """
        return

    def new_connection(self, acc, io):
        """A new connection has come in on the gensio.

        acc -- The gensio_accepter.
        io -- The new gensio.  This is open, but read and write are
            not enabled.
        """
        return

    def auth_begin(self, acc, io):
        """Authentication of the remote end has begun on the gensio.  The
        remote end has requested authentiation.  The service and
        username may be available via controls on the gensio.

        acc -- The gensio_accepter.
        io -- The gensio doing the authentication.  Note that this gensio
            has not been reported via new_connection and is not functional.
            You can do some control operations on it, but that's about it.

        See auth_begin() in EventHandler for more details and return
        values, this is functionally the same, it just occurs on the
        accepter before the gensio has been reported as operational.
        """
        return gensio.GE_NOTSUP

    def precert_verify(self, acc, io):
        """Called after a certificate has been received from the remote
        end but before verification.

        acc -- The gensio_accepter.
        io -- The gensio doing the authentication.  Note that this gensio
            has not been reported via new_connection and is not functional.
            You can do some control operations on it, but that's about it.

        See precert_verify() in EventHandler for more details and return
        values, this is functionally the same, it just occurs on the
        accepter before the gensio has been reported as operational.
        """
        return gensio.GE_NOTSUP

    def postcert_verify(self, acc, io, err, errstr):
        """Called after the certificate has been verified with the
        verification results.

        acc -- The gensio_accepter.
        io -- The gensio doing the authentication.  Note that this gensio
            has not been reported via new_connection and is not functional.
            You can do some control operations on it, but that's about it.
        err -- An integer error.
        errstr -- An error string

        See postcert_verify() in EventHandler for more details and return
        values, this is functionally the same, it just occurs on the
        accepter before the gensio has been reported as operational.
        """
        return gensio.GE_NOTSUP

    def password_verify(self, acc, io, password):
        """A password has been received and needs to be verified.

        acc -- The gensio_accepter.
        io -- The gensio doing the authentication.  Note that this gensio
            has not been reported via new_connection and is not functional.
            You can do some control operations on it, but that's about it.
        password -- the password string for verification.

        See password_verify() in EventHandler for more details and return
        values, this is functionally the same, it just occurs on the
        accepter before the gensio has been reported as operational.
        """
        return gensio.GE_NOTSUP

    def request_password(self, acc, io):
        """The remote authentication server has requested a password.

        acc -- The gensio_accepter.
        io -- The gensio doing the authentication.  Note that this gensio
            has not been reported via new_connection and is not functional.
            You can do some control operations on it, but that's about it.

        See password_verify() in EventHandler for more details and return
        values, this is functionally the same, it just occurs on the
        accepter before the gensio has been reported as operational.
        """
        return "password"

class ShutdownDone:
    """A class template for receiving shutdown done reports."""

    def shutdown_done(self, acc):
        """The shutdown operation has completed on the gensio_accepter.

        acc - The gensio_accepter
        """
        return

class gensio_accepter:
        """A class that receives incoming connections."""

        def __init__(o, gensiostr, handler):
            """Allocate a gensio_accepter.  The gensio_accepter is
            allocated in shutdown state.

            o -- The gensio_os_funcs object to use for this gensio accepter.
            gensiostr -- A string describing the gensio stack.  See the gensio
                documentation for details.
            handler -- An AccEventHandler object to receive events.
            """
            return

        def set_cbs(self, handler):
            """Set the handler object for the gensio_accepter.

            handler -- An AccEventHandler object to receive events.
            """
            return

        def str_to_gensio(self, gensiostr, handler):
            """Allocate a new gensio, coming from the address/port of the
            gensio_accepter, if possible.  This makes it possible to
            create outgoing UDP connections on the same port as the
            accepter receives connections, but is available for other
            gensios, too.

            gensiostr -- A string describing the gensio stack.  See the gensio
                documentation for details.
            handler -- An EventHandler object to receive events.

            Returns the new gensio, in an unopened state.
            """
            return None

        def startup(self):
            """Start accepting connections on the gensio accepter."""
            return

        def shutdown(self, shutdown_done):
            """Stop accepting connection on the gensio accepter.  The
            accepter will be stopped when the shutdown_done() method
            is called in the shutdown_done object.  This closes any
            underlying connections.

            shutdown_done - The object containing the shutdown_done()
                method to be called when the shutdown is complete.
            """
            return

        def shutdown_s(self):
            """Like shutdown, but blocks until the shutdown is complete."""
            return

        def set_accept_cb_enable(self, enable):
            """Enable or disabling reporting new connections on the gensio
            accepter.  This does not close the underlying connection,
            it just disables reporting any accepts.

            enable - If true, enable callbacks.  If false, disabled them.
            enable_done - The object containing the
                set_accept_callback_done() method to be called when
                the enable is complete.

            """
            return

        def set_accept_cb_enable_cb(self, enable, enable_done):
            """Like set_accept_cb_enable(), but the accepter reporting is
            guaranteed to be stopped when the
            set_accept_callback_done() method is called in the
            enabled_done object.

            enable - If true, enable callbacks.  If false, disabled them.
            enable_done - The object containing the
                set_accept_callback_done() method to be called when
                the enable is complete.

            """
            return

        def set_accept_cb_enable_s(self, enable):
            """Like set_accept_cb_enable(), but the accepter reporting is
            guaranteed to be stopped when the function returns.

            enable - If true, enable callbacks.  If false, disabled them.
            """
            return

        def set_sync(self):
            """Enable synchronous accepts on the accepter.  The accepter must not
            be started when this is called.  Once called, the accepter
            is in synchronous mode until it is shutdown"""
            return

        def accept_s(self, o, handler):
            """Wait for an incoming connection on the accepter.  Returns the
            new gensio.  The handler for the gensio is set if returned."""
            return

        def accept_s_timeout(self, o, handler, timeout):
            """Like accept_s, but takes a timeout in milliseconds.  Returns
            a tuple with the new gensio as the first item (or None if timed out)
            and the remaining time as the second item."""
            return

        def accept_s_intr(self, o, handler):
            """Wait for an incoming connection on the accepter.  Returns the
            new gensio.  If a signal comes in while waiting, raise an
            exception for GE_INTERRUPTED."""
            return

        def accept_s_intr_timeout(self, o, handler, timeout):
            """Like accept_s_intr, but takes a timeout in milliseconds.  Returns
            a tuple with the new gensio as the first item (or None if timed out)
            and the remaining time as the second item."""
            return

        def control(self, depth, get, option, data):
        """Do a gensio_accepter-specific control operation.  See the specific
        gensio and the C interface for specific gensio_accepter controls.

        depth -- The gensio_accepter in the stack to choose.  0 selects the
            top ond, 1 the second from the top, etc.
            GENSIO_CONTROL_DEPTH_ALL will call the control on every
            gensio_accepter in the stack, GENSIO_CONTROL_DEPTH_FIRST will
            call the control down the stack until a control doesn't
            return GE_NOTSOP.
        get -- A boolean specifying if this is a get or a put operation.
        option -- The specific gensio_accepter control to call.
        data -- A string specifying the data for the control.

        Returns a string with the result data for the control.
        """
        return ""

    def is_packet(self):
        """Return whether a gensio from this gensio_accepter is a packet
        interface.  In a packet interface, each write on one end will
        result in a single read on the other end with the same amount
        of data.
        """
        return False

    def is_reliable(self):
        """Return whether a gensio from this gensio_accepter provides reliable
        data transport.  With reliable data transport, bytes will not
        be dropped and data will be delivered in the same order it was
        sent.
        """
        return True

    def cast_to_sergensio(self):
        """Convert the gensio_accepter to a sergensio_accepter.

        Returns the sergensio_accepter object if the accepter is a
        sergensio_accepter, or None if it is not.

        """
        return None

class sergensio_accepter:
    """An accepter that will create a sergensio on accept.
    """
    def cast_to_gensio_accepter(self):
        """Returns the gensio_accepter object for this sergensio_accepter.
        This cannot fail."""
        return None;

class MdnsCloseDone:
    """A template for a class handling the finish of an mdns close."""

    def mdns_close_done(self):
        """Called when the close operation completes. """
        return

class MdnsCloseWatchDone:
    """A template for a class handling the finish of an mdns watch close."""

    def mdns_close_watch_done(self):
        """Called when the close operation completes. """
        return

class MdnsEvent:
    """A template for a class handling MDNS events."""

    def mdns_all_for_now(self):
        """Called when all the services currently known have been reported.
        This method is optional."""
        return

    def mdns_cb(self, is_add, interface, ipdomain, name, types, domain,
                host, addr, txt):
        """Called when a matching services is found or removed.

        is_add -- True if an add, False if removed.
        interface -- The interface the service was found on.
        ipdomain -- One of GENSIO_NETTYPE_UNSPEC, GENSIO_NETTYPE_IPV4,
            or GENSIO_NETTYPE_IPV6.  Unspec means IPv4 or IPv6.
        name -- The name of the service.
        types -- The type of the service.
        domain -- The domain of the service.
        host -- The host of the service.
        addr -- An address string in the form of "ipxx,hostname,port".
        txt -- An array of text values for the service.
        """
        return

class mdns:
    """An object used for interacting with the mDNS subsystem.  Add a
    service to advertise an mDNS service, and use a watch to find
    service(s). """

    def __init__(o):
        """Allocate an mdns.

        o -- The gensio_os_funcs object to use for this mdns."""

    def close(self, cb):
        """Close the watch.

        cb -- An object matching the MdnsCloseWatchDone template, the
              mdns_close_watch_done() method is called the the close
              finishes."""
        return

    def add_service(interface, ipdomain,
		    name, types, domain, host, port, txt):
        """Add an mDNS service based on the information given.

        interface - The network interface number to use, -1 mean all.
        ipdomain - One of GENSIO_NETTYPE_UNSPEC, GENSIO_NETTYPE_IPV4,
            or GENSIO_NETTYPE_IPV6.  Unspec means IPv4 or IPv6.
        name - The name for the service.
        types - The type for the service.
        domain - The domain for the service.  Use None, generally.
        host - The host for the service.  Use None, generally.
        port - The port number for the service.
        txt - An array of strings for the mDNS txt field.
        """
        return

    def add_watch(interface, ipdomain,
		  name, types, domain, host, cb):
        """Watch for mDNS service information matching the data given.

        interface - The network interface number to use, -1 mean all.
        ipdomain - One of GENSIO_NETTYPE_UNSPEC, GENSIO_NETTYPE_IPV4,
            or GENSIO_NETTYPE_IPV6.  Unspec means IPv4 or IPv6.
        name - Match the given name.
        types - Match the given type.
        domain - Match the given domain.
        host - Match the given host.
        cb - An object matching MdnsEvent.

        The name, types, domain, and host strings may use regular
        expressions or globs.  If the string starts with '%', then the
        data after it is treated as a regular expression and fields
        are matched against that.  If the string starts with '@', the
        the data after it is treated as a standard glob.  See the
        regex(7) and glob(7) man pages for details.

        If the string starts with '=', an exact comparison is done
        with the data after it.

        If the string starts with a-z0-9_ or a space, then an exact
        string comparison is done, including the first character.

        The behavior of matching for any other starting character is
        undefined.  In general, you should always use '@', '%', or '='
        as the starting character of all your query strings to be
        sure.
        """
        return

class mdns_service:
    def close(self):
        """Close the service."""
        return

class mdns_watch:
    def close(self, cb):
        """Close the watch.

        cb -- An object matching the MdnsCloseWatchDone template, the
              mdns_close_watch_done() method is called the the close
              finishes."""
        return

class waiter:
    """An object that can be used to wait for wakeups in gensios.  You
    should use this interface to wait for operations to finish, it
    will run the internal gensio code so that things will actually
    happen.  If you just sleep, nothing will happen with the gensios.
    """

    def __init__(o):
        """Allocate a waiter.

        o -- The gensio_os_funcs object to use for this waiter.
        """
        return

    def wait_timeout(self, count, timeout):
        """Wait for count wakeups to this object to be called, or
        for timeout (in milliseconds) to elapse.

        count -- The number of wakeups expected.
        timeout -- The time in milliseconds to wait.
        """
        return

    def wait(self, count):
        """Wait for count wakeups to this object to be called.

        count -- The number of wakeups expected.
        """
        return

    def wake(self):
        """Do a wakeup on this object."""
        return

    def service(self, timeout):
        """Run the gensio service routine for timeout milliseconds.

        timeout -- The time to wait, in milliseconds
        """
        return

    def service_now(self):
        """Run the gensio service routine and return immediately.  Returns
        0 if it did something, GE_TIMEDOUT otherwise.
        """
        return

def gensio_set_log_mask(mask):
    """Set the logs that are delivered by the gensio system.

    mask - A bitmask of the following values:  GENSIO_LOG_FATAL,
        GENSIO_LOG_ERR, GENSIO_LOG_WARNING, GENSIO_LOG_INFO,
        GENSIO_LOG_DEBUG.  GENSIO_LOG_MASK_ALL has all of these
        set.  The default is fatal and errors.
    """
    return

def gensio_get_log_mask():
    """Return the current log mask.  See gensio_set_log_mask() above
    for details."""
    return 0

class ifinfo:
    def __init__(o):
        """Get information about all the network interafces on the box and
        return them in an object.

        o -- The gensio_os_funcs to use for this.
        """
        return

    def get_num_ifs():
        """Return the number of interfaces found, used for indexing"""
        return

    def get_name(idx):
        """Return the name of interface as a string.

        idx -- The index of the interface in the list (NOT the ifindex).
        """
        return

    def is_up(idx):
        """Is the given index up?  Returns a bool.

        idx -- The index of the interface in the list (NOT the ifindex).
        """
        return

    def is_loopback(idx):
        """Is the given index a loopback?  Returns a bool.

        idx -- The index of the interface in the list (NOT the ifindex).
        """
        return

    def is_multicast(idx):
        """Is the given index multicast capable?  Returns a bool.

        idx -- The index of the interface in the list (NOT the ifindex).
        """
        return

    def get_ifindex(idx):
        """Return the system interface index of the interface, use for other
        system operations.  This is not the same as "idx".  Returns an
        integer.

        idx -- The index of the interface in the list (NOT the ifindex).

        """
        return

    def get_num_addrs(idx):
        """Return the number of IP addresses on this interface.  Returns an
        integer.

        idx -- The index of the interface in the list (NOT the ifindex).

        """
        return

    def get_addr_netbits(idx, addridx):
        """Return the number of of network bits the given address.  This is
        the same as the number after a slash in an address, like
        127.0.0.1/8.  Returns an integer.

        idx -- The index of the interface in the list (NOT the ifindex).
        addridx -- The index of the address in the interface.

        """
        return

    def get_addr(idx, addridx):
        """Return the number of of network bits the given address.  Returns a
        string in the form: "ipv4:n.n.n.n" or "ipv6:::1".

        idx -- The index of the interface in the list (NOT the ifindex).
        addridx -- The index of the address in the interface.

        """
        return
