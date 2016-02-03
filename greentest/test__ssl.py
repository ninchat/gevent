from gevent import monkey; monkey.patch_all()
import os
import sys
import socket
import greentest
# Be careful not to have TestTCP as a bare attribute in this module,
# even aliased, to avoid running duplicate tests
import test__socket
import ssl


class TestSSL(test__socket.TestTCP):
    __timeout__ = 9000
    certfile = os.path.join(os.path.dirname(__file__), 'test_server.crt')
    privfile = os.path.join(os.path.dirname(__file__), 'test_server.key')
    # Python 2.x has socket.sslerror (which  is an alias for
    # ssl.SSLError); That's gone in Py3 though. In Python 2, most timeouts are raised
    # as SSLError, but Python 3 raises the normal socket.timeout instead. So this has
    # the effect of making TIMEOUT_ERROR be SSLError on Py2 and socket.timeout on Py3
    # See https://bugs.python.org/issue10272
    TIMEOUT_ERROR = getattr(socket, 'sslerror', socket.timeout)

    def setUp(self):
        greentest.TestCase.setUp(self)
        self.listener, self.raw_listener = ssl_listener(('127.0.0.1', 0), self.privfile, self.certfile)
        self.port = self.listener.getsockname()[1]

    def create_connection(self, port=None, timeout=None):
        return self._close_on_teardown(
            ssl.wrap_socket(super(TestSSL, self).create_connection(port=port, timeout=timeout)))

    if not sys.platform.startswith('win32'):

        # The SSL library can take a long time to buffer the large amount of data we're trying
        # to send, so we can't compare to the timeout values
        _test_sendall_timeout_check_time = False

        # The SSL layer has extra buffering, so test_sendall needs
        # to send a very large amount to make it timeout
        _test_sendall_data = data_sent = b'hello' * 100000000

        def test_sendall_timeout0(self):
            # Issue #317: SSL_WRITE_PENDING in some corner cases

            server_sock = []
            acceptor = test__socket.Thread(target=lambda: server_sock.append(self.listener.accept()))
            client = self.create_connection()
            client.setblocking(False)
            try:
                # Python 3 raises ssl.SSLWantWriteError; Python 2 simply *hangs*
                # on non-blocking sockets because it's a simple loop around
                # send(). Python 2.6 doesn't have SSLWantWriteError
                expected = getattr(ssl, 'SSLWantWriteError', ssl.SSLError)
                self.assertRaises(expected, client.sendall, self._test_sendall_data)
            finally:
                acceptor.join()
                client.close()
                server_sock[0][0].close()

        def test_ssl_sendall_timeout(self):
            # Issue #719: SSLEOFError

            data = b'HTTP/1.0\r\nGET /\r\nConnection: Keep-Alive\r\n\r\nHere is a body\r\n'
            data += b'make the body longer\r\n' * 10000

            def server_func():
                remote, _ = self.listener.accept()
                try:
                    d = remote.recv(500)
                    dd = d
                    while d:
                        d = remote.recv(5000)
                        dd += d
                    self.assertEqual(dd, data)
                finally:
                    remote.close()

            acceptor = test__socket.Thread(target=server_func)
            # set the timeout before wrapping the socket so that
            # it applies to the handshake and everything
            client = self.create_connection(timeout=0.1)
            #client.settimeout(0.001)
            try:
                for _ in range(1):
                    client.send(data)
                    #print("sent", l, 'of', len(data))
                    #import gevent
                    #gevent.sleep(10)
            finally:
                client.close()
                acceptor.join()

        def test_ssl_eof_on_handshake(self):
            return
            # Issue #719
            self.listener.close()
            self.port = -1
            raw_listener = self._close_on_teardown(socket.socket())
            greentest.bind_and_listen(raw_listener, ('127.0.0.1', 0))
            port = raw_listener.getsockname()[1]

            data = b'hi'

            def server_func():
                while True:
                    #print("Accepting")
                    remote, _ = raw_listener.accept()
                    #print("Accepted", remote)
                    remote = ssl.wrap_socket(remote, self.privfile, self.certfile, server_side=True)
                    self._close_on_teardown(remote)
                    #print("WRapped", remote)
                    f = remote.makefile('rb')
                    print("Reading")
                    try:
                        d = f.read(len(data))
                        self.assertEqual(d, data)
                    finally:
                        f.close()
                        remote.close()

            acceptor = test__socket.Thread(target=server_func)
            print("Connecting")
            for _ in range(1000):
                raw_client = self._close_on_teardown(super(TestSSL, self).create_connection(port=port))
                raw_client.close()
                continue
                print("Connected")
                try:
                    print("Sending")
                    client.sendall(data)
                    print("Sent")
                finally:
                    client.close()
            raw_listener.close()
            acceptor.join()


def ssl_listener(address, private_key, certificate):
    raw_listener = socket.socket()
    greentest.bind_and_listen(raw_listener, address)
    sock = ssl.wrap_socket(raw_listener, private_key, certificate)
    return sock, raw_listener


if __name__ == '__main__':
    greentest.main()
