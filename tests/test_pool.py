"""Tests for the connection pool."""

import http.client
import http.server
import threading
import time
import unittest

from lumen_argus.pool import ConnectionPool


class MockHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")


class TestConnectionPool(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0),
            MockHandler,
        )
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_get_creates_connection(self):
        pool = ConnectionPool(pool_size=2, timeout=5)
        conn = pool.get("127.0.0.1", self.port, False)
        self.assertIsInstance(conn, http.client.HTTPConnection)
        conn.close()
        pool.close_all()

    def test_put_and_reuse(self):
        pool = ConnectionPool(pool_size=2, timeout=5)

        # First request
        conn1 = pool.get("127.0.0.1", self.port, False)
        conn1.request("GET", "/")
        resp = conn1.getresponse()
        resp.read()

        # Return to pool
        pool.put("127.0.0.1", self.port, False, conn1)

        # Second request should reuse
        conn2 = pool.get("127.0.0.1", self.port, False)
        self.assertIs(conn1, conn2)

        conn2.request("GET", "/")
        resp = conn2.getresponse()
        self.assertEqual(resp.status, 200)
        resp.read()
        conn2.close()
        pool.close_all()

    def test_pool_size_limit(self):
        pool = ConnectionPool(pool_size=1, timeout=5)

        conn1 = pool.get("127.0.0.1", self.port, False)
        conn2 = pool.get("127.0.0.1", self.port, False)

        # Return both — only 1 should be kept
        pool.put("127.0.0.1", self.port, False, conn1)
        pool.put("127.0.0.1", self.port, False, conn2)

        # Get should return the one that was kept
        conn3 = pool.get("127.0.0.1", self.port, False)
        self.assertIs(conn3, conn1)
        conn3.close()
        pool.close_all()

    def test_idle_timeout_evicts(self):
        pool = ConnectionPool(pool_size=2, timeout=5, idle_timeout=0)

        conn = pool.get("127.0.0.1", self.port, False)
        pool.put("127.0.0.1", self.port, False, conn)

        # With idle_timeout=0, the connection should be evicted immediately
        time.sleep(0.01)
        conn2 = pool.get("127.0.0.1", self.port, False)
        self.assertIsNot(conn, conn2)
        conn2.close()
        pool.close_all()

    def test_close_all(self):
        pool = ConnectionPool(pool_size=4, timeout=5)

        conns = []
        for _ in range(3):
            c = pool.get("127.0.0.1", self.port, False)
            conns.append(c)
        for c in conns:
            pool.put("127.0.0.1", self.port, False, c)

        pool.close_all()

        # After close_all, get should create a new connection
        conn = pool.get("127.0.0.1", self.port, False)
        self.assertNotIn(conn, conns)
        conn.close()
        pool.close_all()

    def test_set_timeout_recycles_connections(self):
        pool = ConnectionPool(pool_size=2, timeout=5)

        conn = pool.get("127.0.0.1", self.port, False)
        conn.request("GET", "/")
        conn.getresponse().read()
        pool.put("127.0.0.1", self.port, False, conn)

        # Change timeout — should close all idle connections
        pool.set_timeout(10)

        # Next get should create a fresh connection (old one recycled)
        conn2 = pool.get("127.0.0.1", self.port, False)
        self.assertIsNot(conn, conn2)
        conn2.close()
        pool.close_all()


if __name__ == "__main__":
    unittest.main()
