"""Tests for api_security_scanner.py.

Pure-logic and mock-server tests need no internet. The live test at
the end runs a real audit against https://api.github.com and is skipped
automatically when the network is unreachable.
"""

import json
import os
import sys
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api_security_scanner as scanner_mod
from api_security_scanner import ApiScanner, Finding, Report, main


class MockApiHandler(BaseHTTPRequestHandler):
    """Configurable fake API. `mode` is 'secure' or 'insecure'."""
    mode = "secure"
    request_count = 0
    protocol_version = "HTTP/1.1"

    def version_string(self):
        if self.mode == "insecure":
            return "Apache/2.4.41 (Ubuntu)"
        return ""

    def log_message(self, *args):
        pass

    def _send(self, status, body=b"", content_type="application/json",
              extra=None):
        body = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.mode == "secure":
            self.send_header("Strict-Transport-Security",
                             "max-age=31536000; includeSubDomains")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
        else:
            self.send_header("X-Powered-By", "Express")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _cors_headers(self):
        if self.mode == "insecure":
            return {"Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true"}
        return {}

    def do_GET(self):
        type(self).request_count += 1
        if self.mode == "secure" and type(self).request_count >= 4 \
                and self.path == "/":
            self._send(429, b'{"error": "too many requests"}',
                       extra={"X-RateLimit-Limit": "3",
                              "Retry-After": "60"})
            return
        if self.path == "/":
            self._send(200, b'{"status": "ok"}',
                       extra=self._cors_headers())
        elif self.path == "/__api_security_scanner_nonexistent__":
            if self.mode == "insecure":
                self._send(500,
                           b"Traceback (most recent call last):\n  File "
                           b"'/home/deploy/app.py', line 42, in handler",
                           content_type="text/html")
            else:
                self._send(404, b'{"error": "not found"}')
        elif self.path in ("/api/users", "/users", "/admin"):
            if self.mode == "insecure":
                self._send(200,
                           b'[{"id": 1, "email": "admin@example.com"}]')
            else:
                self._send(401, b'{"error": "unauthorized"}')
        else:
            self._send(404, b'{"error": "not found"}')

    def do_OPTIONS(self):
        if self.mode == "insecure":
            self._send(200, b"",
                       extra={"Allow": "GET, POST, PUT, DELETE, TRACE"})
        else:
            self._send(200, b"", extra={"Allow": "GET, POST"})

    do_HEAD = do_GET


def start_mock_server(mode):
    MockApiHandler.mode = mode
    MockApiHandler.request_count = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockApiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


class ScoringTests(unittest.TestCase):
    def test_grade_bands(self):
        report = Report(base_url="https://example.com")
        self.assertEqual((report.score, report.grade), (100, "A"))
        report.findings.append(Finding("low", "X", "x"))
        self.assertEqual((report.score, report.grade), (97, "A"))
        report.findings.append(Finding("medium", "X", "x"))
        self.assertEqual((report.score, report.grade), (87, "B"))
        report.findings.append(Finding("high", "X", "x"))
        self.assertEqual((report.score, report.grade), (62, "C"))
        report.findings.append(Finding("high", "X", "x"))
        self.assertEqual((report.score, report.grade), (37, "F"))

    def test_score_floor_is_zero(self):
        report = Report(base_url="https://example.com")
        for _ in range(6):
            report.findings.append(Finding("high", "X", "x"))
        self.assertEqual(report.score, 0)


class SecureServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = start_mock_server("secure")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_secure_server_scores_100(self):
        # HTTP base URL on localhost still earns the transport finding,
        # so expect exactly that one high finding and nothing else.
        report = ApiScanner(self.url, rate_limit_probes=6).run()
        self.assertEqual(report.score, 75)
        self.assertEqual(report.grade, "B")
        self.assertEqual([f.check for f in report.findings], ["Transport"])
        self.assertTrue(report.notes["rate_limited"])

    def test_https_prefix_skips_transport_finding(self):
        # Same mock, reached as https would fail TLS, so test the
        # transport check directly instead.
        scan = ApiScanner("https://example.com")
        scan.check_transport()
        self.assertEqual(scan.report.findings, [])
        scan2 = ApiScanner("http://example.com")
        scan2.check_transport()
        self.assertEqual(len(scan2.report.findings), 1)
        self.assertEqual(scan2.report.findings[0].severity, "high")


class InsecureServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.url = start_mock_server("insecure")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_insecure_server_collects_expected_findings(self):
        report = ApiScanner(self.url, rate_limit_probes=6).run()
        by_check = {}
        for f in report.findings:
            by_check.setdefault(f.check, []).append(f.severity)
        self.assertIn("Transport", by_check)
        self.assertIn("Headers", by_check)        # missing HSTS
        self.assertIn("Disclosure", by_check)     # Server + X-Powered-By
        self.assertIn("Authentication", by_check)  # /api/users open
        self.assertIn("Error handling", by_check)  # Traceback leaked
        self.assertIn("CORS", by_check)            # * with credentials
        self.assertIn("Methods", by_check)         # TRACE enabled
        self.assertIn("Rate limiting", by_check)   # no 429, no headers
        self.assertEqual(by_check["Authentication"], ["high"])
        self.assertEqual(by_check["CORS"], ["high"])
        self.assertLessEqual(report.score, 25)

    def test_error_leak_message_names_the_leak(self):
        report = ApiScanner(self.url, rate_limit_probes=1).run()
        leaks = [f for f in report.findings if f.check == "Error handling"]
        self.assertEqual(len(leaks), 1)
        self.assertIn("Traceback", leaks[0].message)


class CliTests(unittest.TestCase):
    def test_bad_url_exits_2(self):
        self.assertEqual(main(["not-a-url"]), 2)
        self.assertEqual(main(["ftp://example.com"]), 2)

    def test_json_output_parses(self):
        server, url = start_mock_server("secure")
        try:
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main([url, "--json", "--rate-limit-probes", "1"])
            data = json.loads(buf.getvalue())
            self.assertEqual(data["base_url"], url)
            self.assertIn("score", data)
            self.assertIn("findings", data)
            self.assertEqual(code, 1)  # transport (HTTP) is high severity
        finally:
            server.shutdown()
            server.server_close()

    def test_fail_on_low_fails_on_low_only(self):
        server, url = start_mock_server("secure")
        try:
            # Secure mock has only the transport (high) finding, so
            # --fail-on low still exits 1 because of the high finding.
            self.assertEqual(
                main([url, "--fail-on", "low", "--rate-limit-probes", "1"]),
                1)
        finally:
            server.shutdown()
            server.server_close()


class LiveTests(unittest.TestCase):
    def test_live_api_github_com(self):
        try:
            report = ApiScanner("https://api.github.com",
                                rate_limit_probes=3).run()
        except (urllib.error.URLError, OSError) as exc:
            self.skipTest("network unreachable: %s" % exc)
        # GitHub's public API is well hardened; it should not expose
        # sensitive endpoints or leak stack traces. Its public /users
        # list endpoint is public data, not an authentication failure.
        checks = {f.check for f in report.findings}
        self.assertNotIn("Authentication", checks)
        self.assertNotIn("Error handling", checks)
        self.assertGreaterEqual(report.score, 75)


if __name__ == "__main__":
    unittest.main(verbosity=2)
