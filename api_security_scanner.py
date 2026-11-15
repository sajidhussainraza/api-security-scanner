#!/usr/bin/env python3
"""API Security Scanner.

A small, dependency-free Python CLI that audits a REST API base URL
against the basics of the OWASP API Security Top 10: unauthenticated
access to sensitive endpoints, missing security headers, permissive
CORS, verbose error messages, dangerous HTTP methods, missing rate
limiting, and server/version disclosure.

It grades the API A-F and explains each finding in plain language, so
students and small teams can see exactly where an API leaks data or
invites abuse and how to fix it.

Standard library only (urllib, http.client, ssl). No third-party
packages, no telemetry, nothing is stored. The scanner only sends
read-only GET/HEAD/OPTIONS requests, so it never creates, changes or
deletes data on the target.

Usage:
    python3 api_security_scanner.py https://api.example.com
    python3 api_security_scanner.py https://api.example.com --json
    python3 api_security_scanner.py https://api.example.com --fail-on high
"""

import argparse
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

__version__ = "1.0.0"

# Paths commonly exposing sensitive data when left unauthenticated.
# (OWASP API1:2023 Broken Object Level Authorization / API2 Broken
# Authentication.) Only probed with GET, never with writes.
SENSITIVE_PATHS = [
    "/admin",
    "/api/users",
    "/api/v1/users",
    "/users",
    "/api/admin",
    "/api/v1/admin",
    "/api/config",
    "/api/settings",
    "/api/keys",
    "/actuator",
    "/actuator/env",
    "/.env",
    "/api/docs",
    "/swagger.json",
    "/openapi.json",
]

# Paths that must never answer 200 without authentication: admin panels,
# configuration, secrets and environment dumps. Any 200 here is a
# high-severity finding on its own.
HIGH_SENSITIVITY_PATHS = frozenset([
    "/admin",
    "/api/admin",
    "/api/v1/admin",
    "/api/config",
    "/api/settings",
    "/api/keys",
    "/actuator/env",
    "/.env",
])

# Public-by-design paths (API docs) are probed for completeness but a
# 200 there is not an authentication failure.
PUBLIC_PATHS = frozenset([
    "/api/docs",
    "/swagger.json",
    "/openapi.json",
])

# A 200 on any other probed path only counts as exposed when the body
# actually carries sensitive data. A public list endpoint (for example
# GitHub's /users) returning public profiles is not a vulnerability.
SENSITIVE_DATA_PATTERNS = [
    r"[\w.+-]+@[\w-]+\.[\w.]+",          # email address
    r"\b(password|passwd|secret)\b",
    r"api[_-]?key",
    r"access[_-]?token",
    r"private[_-]?key",
    r"\b(token|bearer)\s*[:=]\s*[\"']?[A-Za-z0-9_\-.]{16,}",
]

# A Server header only leaks something useful when it carries a version.
VERSION_PATTERN = re.compile(r"\d+\.\d+")

# Strings that suggest a server is leaking internals in an error body.
ERROR_LEAK_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"Stack trace",
    r"at\s+[\w.$]+\([\w.$]+\.java:\d+\)",
    r"SQL syntax",
    r"ORA-\d{5}",
    r"pg_query|PostgreSQL.*ERROR",
    r"MongoError|MongoServerError",
    r"Exception in thread",
    r"NullPointerException",
    r"node_modules[\\/]",
    r"/home/[a-z0-9_]+/",
    r"C:\\[A-Za-z]+\\",
]

SEVERITY_POINTS = {"high": 25, "medium": 10, "low": 3}
GRADE_BANDS = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]


@dataclass
class Finding:
    severity: str  # high / medium / low
    check: str
    message: str
    fix: str = ""


@dataclass
class Report:
    base_url: str
    findings: list = field(default_factory=list)
    notes: dict = field(default_factory=dict)

    @property
    def score(self):
        total = 100
        for f in self.findings:
            total -= SEVERITY_POINTS.get(f.severity, 0)
        return max(total, 0)

    @property
    def grade(self):
        for threshold, letter in GRADE_BANDS:
            if self.score >= threshold:
                return letter
        return "F"

    def by_severity(self, severity):
        return [f for f in self.findings if f.severity == severity]

    def to_dict(self):
        return {
            "base_url": self.base_url,
            "score": self.score,
            "grade": self.grade,
            "notes": self.notes,
            "findings": [
                {
                    "severity": f.severity,
                    "check": f.check,
                    "message": f.message,
                    "fix": f.fix,
                }
                for f in self.findings
            ],
        }


class ApiScanner:
    """Runs the checks. `fetcher` can be replaced in tests."""

    def __init__(self, base_url, timeout=10, rate_limit_probes=6):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.rate_limit_probes = rate_limit_probes
        self.report = Report(base_url=self.base_url)
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPHandler(),
            urllib.request.HTTPSHandler(),
        )
        self._opener.addheaders = [("User-Agent", "api-security-scanner/1.0")]

    # -- low-level fetch -------------------------------------------------
    def fetch(self, url, method="GET", headers=None, data=None):
        """Return (status, headers dict, body text). Never raises for
        HTTP error statuses; network errors raise URLError."""
        req = urllib.request.Request(url, method=method, data=data)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            return exc.code, dict(exc.headers), body

    # -- checks ----------------------------------------------------------
    def check_transport(self):
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme != "https":
            self.report.findings.append(Finding(
                "high", "Transport",
                "API is served over plain HTTP; tokens and data travel "
                "in clear text.",
                "Serve the API over HTTPS only and redirect HTTP to HTTPS.",
            ))
            return
        self.report.notes["transport"] = "HTTPS"

    def check_root_headers(self):
        """Security headers and server disclosure on the base URL."""
        try:
            status, headers, _ = self.fetch(self.base_url)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError) as exc:
            self.report.findings.append(Finding(
                "high", "Reachability",
                "Could not reach the API base URL: %s" % exc,
                "Check the URL and that the API is publicly reachable.",
            ))
            return
        self.report.notes["base_status"] = status
        lowered = {k.lower(): v for k, v in headers.items()}

        if "strict-transport-security" not in lowered:
            self.report.findings.append(Finding(
                "medium", "Headers",
                "Strict-Transport-Security header is missing, so browsers "
                "and clients can be downgraded to HTTP.",
                "Send Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains.",
            ))
        if "x-content-type-options" not in lowered:
            self.report.findings.append(Finding(
                "low", "Headers",
                "X-Content-Type-Options header is missing, so responses "
                "can be MIME-sniffed.",
                "Send X-Content-Type-Options: nosniff.",
            ))
        cache = lowered.get("cache-control", "")
        if not any(token in cache
                   for token in ("no-store", "private", "no-cache")):
            self.report.findings.append(Finding(
                "low", "Headers",
                "Cache-Control does not forbid caching; authenticated API "
                "responses may be stored by intermediaries.",
                "Send Cache-Control: no-store on authenticated responses.",
            ))
        server = lowered.get("server", "")
        powered = lowered.get("x-powered-by", "")
        disclosed = []
        if server and VERSION_PATTERN.search(server):
            disclosed.append(server)
        if powered:
            disclosed.append(powered)
        if disclosed:
            self.report.findings.append(Finding(
                "low", "Disclosure",
                "Server or framework version disclosed: %s"
                % " ".join(disclosed),
                "Suppress the Server and X-Powered-By headers or strip "
                "version numbers from them.",
            ))
        self.report.notes["headers_seen"] = sorted(lowered.keys())

    def check_unauthenticated_access(self):
        """Probe common sensitive paths without any credentials.

        A path counts as exposed when it is high-sensitivity and
        answers 200 at all, or when any other probed path answers 200
        with a body that actually carries sensitive data. Public list
        endpoints (GitHub's /users, for example) and public API docs
        are not authentication failures.
        """
        exposed = []
        for path in SENSITIVE_PATHS:
            url = self.base_url + path
            try:
                status, headers, body = self.fetch(url)
            except (urllib.error.URLError, socket.timeout, ssl.SSLError):
                continue
            if status != 200 or path in PUBLIC_PATHS:
                continue
            content_type = headers.get("Content-Type", "") or headers.get(
                "content-type", "")
            is_json = "application/json" in content_type
            if path in HIGH_SENSITIVITY_PATHS:
                if is_json or len(body.strip()) > 50:
                    exposed.append((path, status))
            elif is_json or len(body.strip()) > 50:
                if any(re.search(p, body, re.IGNORECASE)
                       for p in SENSITIVE_DATA_PATTERNS):
                    exposed.append((path, status))
        if exposed:
            paths = ", ".join(p for p, _ in exposed)
            self.report.findings.append(Finding(
                "high", "Authentication",
                "Sensitive endpoints return data without authentication: %s"
                % paths,
                "Require authentication on every endpoint and enforce "
                "object-level authorization (OWASP API1/API2).",
            ))
        self.report.notes["sensitive_paths_probed"] = len(SENSITIVE_PATHS)
        self.report.notes["sensitive_paths_exposed"] = len(exposed)

    def check_error_disclosure(self):
        """Request a nonsense path and look for leaked internals."""
        url = self.base_url + "/__api_security_scanner_nonexistent__"
        try:
            status, headers, body = self.fetch(url)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError):
            return
        leak = None
        for pattern in ERROR_LEAK_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                leak = match.group(0)[:80]
                break
        if leak:
            self.report.findings.append(Finding(
                "medium", "Error handling",
                "Error responses leak internal details (%r)." % leak,
                "Return a generic error body (status + message only) and "
                "log the details server-side.",
            ))
        elif status == 200:
            self.report.findings.append(Finding(
                "low", "Error handling",
                "A nonsense path returns 200 OK instead of 404, which "
                "hides routing mistakes and confuses clients.",
                "Return 404 with a generic JSON error for unknown paths.",
            ))
        self.report.notes["error_status"] = status

    def check_cors(self):
        """Ask for a cross-origin response from an untrusted origin."""
        evil_origin = "https://evil.example.com"
        try:
            status, headers, _ = self.fetch(
                self.base_url, headers={"Origin": evil_origin})
        except (urllib.error.URLError, socket.timeout, ssl.SSLError):
            return
        lowered = {k.lower(): v for k, v in headers.items()}
        allow_origin = lowered.get("access-control-allow-origin", "")
        allow_creds = lowered.get(
            "access-control-allow-credentials", "").lower()
        if allow_origin == "*" and allow_creds == "true":
            self.report.findings.append(Finding(
                "high", "CORS",
                "CORS allows any origin (*) with credentials, so any "
                "website can make authenticated requests on a user's "
                "behalf.",
                "Reflect only trusted origins and never combine '*' with "
                "Access-Control-Allow-Credentials: true.",
            ))
        elif allow_origin == evil_origin:
            self.report.findings.append(Finding(
                "high", "CORS",
                "CORS reflects the arbitrary origin %s, so any website "
                "can call the API." % evil_origin,
                "Allow-list trusted origins instead of reflecting the "
                "request Origin header.",
            ))
        elif allow_origin == "*":
            self.report.findings.append(Finding(
                "medium", "CORS",
                "CORS allows any origin (*). Safe for public read-only "
                "data, risky if the API also serves authenticated users.",
                "Restrict Access-Control-Allow-Origin to trusted origins "
                "whenever the API uses cookies or tokens.",
            ))
        self.report.notes["cors_allow_origin"] = allow_origin or "(none)"

    def check_methods(self):
        """Ask what methods the API allows (OPTIONS)."""
        try:
            status, headers, _ = self.fetch(self.base_url, method="OPTIONS")
        except (urllib.error.URLError, socket.timeout, ssl.SSLError):
            return
        lowered = {k.lower(): v for k, v in headers.items()}
        allow = lowered.get("allow", "")
        dangerous = [m for m in ("TRACE", "PUT", "DELETE", "PATCH")
                     if m in allow.upper()]
        if "TRACE" in dangerous:
            self.report.findings.append(Finding(
                "medium", "Methods",
                "HTTP TRACE is enabled, which can be abused for "
                "cross-site tracing attacks.",
                "Disable TRACE on the server or reverse proxy.",
            ))
        self.report.notes["allow_header"] = allow or "(none)"

    def check_rate_limiting(self):
        """Fire a burst of identical requests and look for pushback."""
        statuses = []
        rate_headers = False
        for _ in range(self.rate_limit_probes):
            try:
                status, headers, _ = self.fetch(self.base_url)
            except (urllib.error.URLError, socket.timeout, ssl.SSLError):
                return
            statuses.append(status)
            lowered = {k.lower(): v for k, v in headers.items()}
            if any(k.startswith("x-ratelimit") or k == "retry-after"
                   for k in lowered):
                rate_headers = True
        limited = 429 in statuses or rate_headers
        if not limited:
            self.report.findings.append(Finding(
                "medium", "Rate limiting",
                "No rate limiting observed after %d rapid requests "
                "(no 429 response, no X-RateLimit headers)." %
                self.rate_limit_probes,
                "Add per-client rate limits and return 429 with a "
                "Retry-After header when they are hit.",
            ))
        self.report.notes["rate_limited"] = limited

    def check_content_type(self):
        """API responses should be JSON, not HTML error pages."""
        try:
            status, headers, _ = self.fetch(self.base_url)
        except (urllib.error.URLError, socket.timeout, ssl.SSLError):
            return
        content_type = (headers.get("Content-Type", "") or
                        headers.get("content-type", ""))
        if status == 200 and "application/json" not in content_type:
            self.report.findings.append(Finding(
                "low", "Content type",
                "Base URL returns %s instead of application/json."
                % (content_type.split(";")[0] or "(no content type)"),
                "Serve API responses as application/json so clients do "
                "not have to guess the format.",
            ))

    def run(self):
        self.check_transport()
        if self.base_url.startswith(("https://", "http://")):
            self.check_root_headers()
            if any(f.check == "Reachability" for f in self.report.findings):
                return self.report  # base URL unreachable: nothing more to probe
            self.check_unauthenticated_access()
            self.check_error_disclosure()
            self.check_cors()
            self.check_methods()
            self.check_rate_limiting()
            self.check_content_type()
        return self.report


def format_text(report):
    lines = []
    lines.append("API security report: %s" % report.base_url)
    lines.append("Score: %d/100  Grade: %s" % (report.score, report.grade))
    lines.append("")
    for key, value in report.notes.items():
        lines.append("  %s: %s" % (key.replace("_", " ").title(), value))
    if report.findings:
        lines.append("")
        lines.append("Findings (%d):" % len(report.findings))
        order = {"high": 0, "medium": 1, "low": 2}
        for f in sorted(report.findings, key=lambda x: order[x.severity]):
            lines.append("  [%s] %s: %s" % (f.severity.upper(), f.check,
                                             f.message))
            if f.fix:
                lines.append("        Fix: %s" % f.fix)
    else:
        lines.append("")
        lines.append("No findings: the checked basics all look good.")
    return "\n".join(lines) + "\n"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit a REST API base URL against OWASP API "
                    "security basics.")
    parser.add_argument("base_url", help="API base URL, e.g. "
                        "https://api.example.com")
    parser.add_argument("--timeout", type=float, default=10,
                        help="request timeout in seconds (default 10)")
    parser.add_argument("--rate-limit-probes", type=int, default=6,
                        help="requests fired in the rate-limit burst "
                             "(default 6)")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("--fail-on", choices=["high", "medium", "low"],
                        default="high",
                        help="exit 1 when findings at/above this severity "
                             "exist (default high)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    parsed = urllib.parse.urlparse(args.base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print("error: base_url must start with http:// or https://",
              file=sys.stderr)
        return 2
    scanner = ApiScanner(args.base_url, timeout=args.timeout,
                         rate_limit_probes=args.rate_limit_probes)
    try:
        report = scanner.run()
    except (urllib.error.URLError, socket.timeout, ssl.SSLError) as exc:
        print("error: could not reach %s: %s" % (args.base_url, exc),
              file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_text(report), end="")
    severities = {"high": 0, "medium": 1, "low": 2}
    threshold = severities[args.fail_on]
    bad = [f for f in report.findings
           if severities[f.severity] <= threshold]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
