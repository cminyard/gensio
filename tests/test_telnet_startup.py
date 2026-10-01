#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise Telnet gensio startup serial settings against a small RFC2217 peer."""

import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import tempfile
import unittest

try:
    from gensios_enabled import gensios_enabled as FEATURES
except ImportError:
    FEATURES = {}

IAC, SB, SE, WILL, WONT, DO, DONT = 255, 250, 240, 251, 252, 253, 254
COM_PORT = 44
GENSIOT = os.environ.get("GENSIOT", "../tools/gensiot")
PROBE = os.environ.get("TELNET_STARTUP_PROBE", "./telnet_startup_probe" +
                       (".exe" if os.name == "nt" else ""))
OPENSSL = (os.environ.get("OPENSSL") or shutil.which("openssl") or
           shutil.which("openssl.exe"))


def quote(data):
    return data.replace(b"\xff", b"\xff\xff")


class Peer:
    def __init__(self, payload, settings=None, fail=None, early=b"", tls=None,
                 fragmented=False, delay_last=False, sessions=1):
        self.payload = payload
        self.expected = settings
        self.fail = fail
        self.early = early
        self.tls = tls
        self.controls = []
        self.received = bytearray()
        self.error = None
        self.fragmented = fragmented
        self.delay_last = delay_last
        self.sessions = sessions
        self.completed = 0
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(10)
        self.port = self.listener.getsockname()[1]
        self.conn = None
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def send_control(self, data):
        wire = bytes((IAC, SB, COM_PORT)) + quote(data) + bytes((IAC, SE))
        if self.fragmented:
            for char in wire:
                self.conn.sendall(bytes((char,)))
                time.sleep(0.001)
        else:
            self.conn.sendall(wire)

    def run(self):
        for session in range(self.sessions):
            self.controls.clear()
            self.received.clear()
            self.run_session()
            if self.error:
                break
            if self.received == self.payload:
                self.completed += 1
        self.listener.close()

    def run_session(self):
        try:
            self.conn, _ = self.listener.accept()
            if self.tls:
                self.conn = self.tls.wrap_socket(self.conn, server_side=True)
            self.conn.settimeout(10)
            state = "data"
            command = None
            sub = bytearray()
            sent_early = False
            while True:
                data = self.conn.recv(4096)
                if not data:
                    return
                for char in data:
                    if state == "data":
                        if char == IAC:
                            state = "iac"
                        else:
                            self.receive(bytes((char,)))
                    elif state == "iac":
                        if char == IAC:
                            self.receive(b"\xff")
                            state = "data"
                        elif char in (WILL, WONT, DO, DONT):
                            command = char
                            state = "option"
                        elif char == SB:
                            sub.clear()
                            state = "sub"
                        else:
                            state = "data"
                    elif state == "option":
                        if command == DO:
                            reply = WILL if char in (0, 3, COM_PORT) else WONT
                            self.conn.sendall(bytes((IAC, reply, char)))
                        elif command == WILL:
                            if char == COM_PORT and self.fail == "negotiate":
                                state = "data"
                                continue
                            reply = DO if char in (0, 3, COM_PORT) else DONT
                            if char == COM_PORT and self.fail == "refuse":
                                reply = DONT
                            self.conn.sendall(bytes((IAC, reply, char)))
                        state = "data"
                    elif state == "sub":
                        if char == IAC:
                            state = "sub_iac"
                        else:
                            sub.append(char)
                    elif state == "sub_iac":
                        if char == IAC:
                            sub.append(IAC)
                            state = "sub"
                        elif char == SE:
                            if sub and sub[0] == COM_PORT:
                                control = bytes(sub[1:])
                                if control and control[0] in (1, 2, 3, 4, 5):
                                    self.controls.append(control)
                                    if (self.delay_last and
                                            self.controls == self.expected):
                                        self.conn.settimeout(0.15)
                                        try:
                                            premature = self.conn.recv(1)
                                        except socket.timeout:
                                            premature = b""
                                        self.conn.settimeout(10)
                                        if premature:
                                            raise AssertionError(
                                                "Data arrived before final acknowledgement")
                                    if self.early and not sent_early:
                                        self.conn.sendall(quote(self.early))
                                        sent_early = True
                                    if self.fail == "timeout":
                                        state = "data"
                                        continue
                                    if self.fail == "disconnect":
                                        return
                                    if self.fail == "malformed":
                                        control = control[:1]
                                    if self.fail == "mismatch":
                                        control = control[:1] + struct.pack("!I", 4800)
                                if control:
                                    self.send_control(bytes((control[0] + 100,)) +
                                                      control[1:])
                            state = "data"
                        else:
                            raise AssertionError("Malformed Telnet subnegotiation")
                if len(self.received) == len(self.payload) and self.payload:
                    self.conn.sendall(quote(self.payload))
                    self.conn.shutdown(socket.SHUT_WR)
                    return
        except (ConnectionResetError, BrokenPipeError):
            if not self.fail:
                self.error = "Connection closed unexpectedly"
        except ssl.SSLError as error:
            if self.fail != "tls":
                self.error = error
        except Exception as error:
            self.error = error
        finally:
            if self.conn:
                self.conn.close()

    def receive(self, data):
        if self.expected is not None and self.controls != self.expected:
            raise AssertionError("Application data arrived before serial settings")
        self.received.extend(data)
        if not self.payload.startswith(self.received):
            raise AssertionError("Application data changed")

    def finish(self):
        self.thread.join(12)
        if self.thread.is_alive():
            if self.conn:
                self.conn.close()
            self.listener.close()
            self.thread.join(2)
            raise AssertionError("RFC2217 peer did not finish")
        if self.error:
            raise AssertionError(self.error)


class SerialStartupTest(unittest.TestCase):
    def run_peer(self, serial, expected, payload=None, extra=(), fail=None,
                 early=b"", tls=None, ca=None, fragmented=False,
                 delay_last=False):
        if payload is None:
            payload = bytes(range(256)) + b"\x1cs9600\n\x1cq\xff\x00"
        peer = Peer(payload, expected, fail, early, tls, fragmented, delay_last)
        application = None
        connection = None
        # Native Windows gensio stdio needs overlapped handles; Popen pipes
        # do not provide those. Use an ordinary socket for io1 on Windows.
        if os.name == "nt":
            application = socket.socket()
            application.bind(("127.0.0.1", 0))
            application.listen(1)
            application.settimeout(12)
            input_io = "tcp,127.0.0.1," + str(application.getsockname()[1])
        else:
            input_io = "stdio"
        args = [GENSIOT, "-i", input_io]
        stack = "telnet(rfc2217" + (("," + serial) if serial is not None else "") + "),"
        if tls:
            stack += ("ssl(CA=" + ca.replace("\\", "/") + ")," if ca
                      else "ssl,")
        args += list(extra) + [stack + "tcp,127.0.0.1," + str(peer.port)]
        process = subprocess.Popen(args, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            if application and not fail:
                connection, _ = application.accept()
                connection.settimeout(12)
                connection.sendall(payload)
                output = bytearray()
                while True:
                    data = connection.recv(4096)
                    if not data:
                        break
                    output.extend(data)
                # gensio's graceful TCP close waits for the peer's FIN.
                connection.close()
            elif not application:
                # Keep stdin open so its EOF cannot race the peer's response.
                process.stdin.write(payload)
                process.stdin.flush()
            process.wait(timeout=30)
            stdout = process.stdout.read()
            stderr = process.stderr.read()
            if connection:
                self.assertEqual(stdout, b"")
                stdout = bytes(output)
        except Exception as error:
            if process.poll() is None:
                process.kill()
                process.wait()
            raise AssertionError(
                process.stderr.read().decode(errors="replace")) from error
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
            if connection:
                connection.close()
            if application:
                application.close()
            peer.finish()
        if fail:
            self.assertNotEqual(process.returncode, 0, stderr)
            self.assertEqual(peer.received, b"")
            self.assertEqual(stdout, b"")
            self.assertIn(b"open error", stderr)
        else:
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(peer.controls, expected or [])
            self.assertEqual(peer.received, payload)
            self.assertEqual(stdout, early + payload)

    def test_defaults_and_binary_data(self):
        self.run_peer("38400n81", [
            b"\x01" + struct.pack("!I", 38400), b"\x02\x08",
            b"\x03\x01", b"\x04\x01"])

    def test_even_parity_and_two_stopbits(self):
        self.run_peer("2400e72", [
            b"\x01" + struct.pack("!I", 2400), b"\x02\x07",
            b"\x03\x03", b"\x04\x02"])

    def test_extra_event_threads(self):
        self.run_peer("38400n81", [
            b"\x01" + struct.pack("!I", 38400), b"\x02\x08",
            b"\x03\x01", b"\x04\x01"], extra=("-n", "2"),
            early=b"startup\x00\xff")

    @unittest.skipUnless(OPENSSL and FEATURES.get("ssl", True),
                         "openssl or the ssl gensio is not available")
    def test_tls(self):
        with tempfile.TemporaryDirectory() as directory:
            cert = os.path.join(directory, "cert.pem")
            key = os.path.join(directory, "key.pem")
            subprocess.run([
                OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key, "-out", cert, "-days", "1",
                "-subj", "/CN=localhost"],
                check=True, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=30)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            self.run_peer("38400n81", [
                b"\x01" + struct.pack("!I", 38400), b"\x02\x08",
                b"\x03\x01", b"\x04\x01"], tls=context, ca=cert)
            self.run_peer("38400n81", [], tls=context, fail="tls")

    def test_binary_payload_with_escapes_disabled(self):
        self.run_peer("9600n81", [
            b"\x01" + struct.pack("!I", 9600), b"\x02\x08",
            b"\x03\x01", b"\x04\x01"], extra=("-e", "-1"))

    def test_no_serial_option_keeps_existing_behavior(self):
        self.run_peer(None, None)

    def test_mismatched_confirmation(self):
        self.run_peer("9600n81", [b"\x01" + struct.pack("!I", 9600)],
                      fail="mismatch")

    def test_confirmation_timeout(self):
        self.run_peer("9600n81", [b"\x01" + struct.pack("!I", 9600)],
                      fail="timeout")

    def test_disconnect_during_configuration(self):
        self.run_peer("9600n81", [b"\x01" + struct.pack("!I", 9600)],
                      fail="disconnect")

    def test_early_remote_payload(self):
        self.run_peer("38400n81", [
            b"\x01" + struct.pack("!I", 38400), b"\x02\x08",
            b"\x03\x01", b"\x04\x01"], early=b"startup\x00\xff")

    def test_startup_buffer_limit(self):
        self.run_peer("38400n81", None, early=b"x" * 4097,
                      fail="overflow")

    def test_short_speed_and_named_speed(self):
        expected = [b"\x01" + struct.pack("!I", 9600), b"\x02\x08",
                    b"\x03\x01", b"\x04\x01"]
        self.run_peer("9600", expected)
        self.run_peer("speed=9600n81", expected)

    def test_fragmented_acknowledgements(self):
        self.run_peer("38400n81", [
            b"\x01" + struct.pack("!I", 38400), b"\x02\x08",
            b"\x03\x01", b"\x04\x01"], fragmented=True,
            early=b"startup\x00\xff")

    def test_no_data_before_final_acknowledgement(self):
        self.run_peer("38400n81", [
            b"\x01" + struct.pack("!I", 38400), b"\x02\x08",
            b"\x03\x01", b"\x04\x01"], delay_last=True)

    def test_flow_and_modem_controls(self):
        self.run_peer("9600n81,rtscts,dtr=false,rts", [
            b"\x01" + struct.pack("!I", 9600), b"\x02\x08",
            b"\x03\x01", b"\x04\x01", b"\x05\x03",
            b"\x05\x09", b"\x05\x0b"])
        self.run_peer("xonxoff", [b"\x05\x02"])
        self.run_peer("rtscts=false", [b"\x05\x01"])

    def test_rfc2217_refused(self):
        self.run_peer("9600n81", [], fail="refuse")

    def test_rfc2217_negotiation_timeout(self):
        self.run_peer("9600n81", [], fail="negotiate")

    def test_malformed_confirmation(self):
        self.run_peer("9600n81", [b"\x01" + struct.pack("!I", 9600)],
                      fail="malformed")

    def test_escaped_baud_byte(self):
        self.run_peer("65535s52", [
            b"\x01" + struct.pack("!I", 65535), b"\x02\x05",
            b"\x03\x05", b"\x04\x02"])

    def test_invalid_settings(self):
        for options in ("rfc2217,speed=", "rfc2217,0", "rfc2217,speed=-1",
                        "rfc2217,2147483648", "rfc2217,9600n41",
                        "rfc2217,9600x81", "rfc2217,9600n83",
                        "rfc2217,9600n81extra", "rfc2217,9600n81,mode=server",
                        "9600n81", "rfc2217,xonxoff,rtscts",
                        "rfc2217,readbuf=0", "rfc2217,writebuf=0"):
            with self.subTest(options=options):
                result = subprocess.run(
                    [GENSIOT, "telnet(" + options + "),tcp,127.0.0.1,1"],
                    capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Could not allocate", result.stderr)

    def test_library_reopens_same_object(self):
        if not os.path.isfile(PROBE):
            self.fail("Build telnet_startup_probe before running this test")
        peer = Peer(b"x", [b"\x01" + struct.pack("!I", 38400),
                          b"\x02\x08", b"\x03\x01", b"\x04\x01"],
                    sessions=2)
        try:
            result = subprocess.run([
                PROBE, "telnet(rfc2217,38400n81),tcp,127.0.0.1," + str(peer.port)],
                capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            peer.finish()
        self.assertEqual(peer.completed, 2)



if __name__ == "__main__":
    if not FEATURES.get("tcp", True) or not FEATURES.get("telnet", True):
        print("TCP or Telnet gensio is disabled")
        sys.exit(77)
    unittest.main()
