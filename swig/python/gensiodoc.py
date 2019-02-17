
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
        auxdata -- Auxilliary data describing the read.  This is a sequence
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
        request from the client.  The certauth code will not to it's own
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

    def signature(self, sio):
        """Called from the telnet server to report that the client has
        requested the RFC2217 signature.  Call sg_signature(signature,
        None) with the signature.

        sio -- The sergensio object requesting the signature.

        """
        return

    def sflush(self, sio, val):
        """Called from telnet server or client to report that a flush has been
        requested.

        sio -- The sergensio object requesting the flush.
        val -- The flush type, one of SERGIO_FLUSH_RCV_BUFFER,
            SERGIO_FLUSH_XMIT_BUFFER, or SERGIO_FLUSH_RCV_XMIT_BUFFERS.
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
        val -- The data size as an integer, 1 or 2.
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

class gensio:
    __init__(o, gensiostr, handler):
    """Allocate a gensio.

    o -- The gensio_os_funcs object to use for this gensio.
    gensiostr -- A string describing the gensio stack.  See the gensio
        documentation for details.
    handler -- An EventHandler object to receive events
    """

    
