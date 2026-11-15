# API Security Scanner

A small, dependency-free Python CLI that audits a REST API base URL
against the basics of the OWASP API Security Top 10: unauthenticated
access to sensitive endpoints, missing security headers, permissive
CORS, verbose error messages, dangerous HTTP methods, missing rate
limiting, and server/version disclosure. It grades the API A-F and
explains each finding in plain language, so students and small teams
can see exactly where an API leaks data or invites abuse and how to
fix it.

Standard library only (`urllib`, `http.client`, `ssl`). No
third-party packages, no telemetry, nothing is stored. The scanner
only sends read-only GET/HEAD/OPTIONS requests, so it never creates,
changes or deletes data on the target.

## What it checks

| Check | What a good result looks like |
| --- | --- |
| Transport | API served over HTTPS only |
| Headers | HSTS, `X-Content-Type-Options: nosniff`, and a `Cache-Control` that forbids storing authenticated responses |
| Authentication | Sensitive paths (`/admin`, `/api/config`, `/api/keys`, `/actuator/env`, `/.env`, ...) return 401/403/404 without credentials |
| Error handling | Unknown paths return a generic 404, with no stack traces, SQL errors or file paths in the body |
| CORS | No `Access-Control-Allow-Origin: *` combined with credentials, and no reflection of arbitrary origins |
| Methods | HTTP TRACE disabled (OPTIONS `Allow` header checked) |
| Rate limiting | A burst of requests is answered with 429 or `X-RateLimit` headers |
| Disclosure | No `Server` version or `X-Powered-By` header |
| Content type | API responses are `application/json`, not HTML error pages |

A path only counts as "exposed" when it is high-sensitivity and
answers 200 at all, or when another probed path answers 200 with a
body that actually carries sensitive data (an email address, a token,
a secret). Public list endpoints and public API docs are not
authentication failures: GitHub's `/users` endpoint, for example,
returns public profiles and is correctly left alone.

Findings are graded by severity:

| Severity | Examples |
| --- | --- |
| High | Plain HTTP, sensitive endpoint open without auth, CORS `*` with credentials |
| Medium | Missing HSTS, error bodies leaking internals, TRACE enabled, no rate limiting, CORS `*` |
| Low | Missing `X-Content-Type-Options`, cacheable authenticated responses, server version disclosed, non-JSON responses |

Score starts at 100 and deducts 25 / 10 / 3 per high / medium / low
finding: 90+ is A, 75+ B, 60+ C, 40+ D, below that F.

## Install

No installation needed. Python 3.8+ only, standard library only:

```bash
git clone https://github.com/sajidhussainraza/api-security-scanner.git
cd api-security-scanner
```

## Usage

Audit an API:

```bash
python3 api_security_scanner.py https://api.example.com
```

Machine-readable output:

```bash
python3 api_security_scanner.py https://api.example.com --json
```

Use it as a CI gate (fail only on high-severity findings):

```bash
python3 api_security_scanner.py https://api.example.com --fail-on high
```

Tune the rate-limit burst (default 6 rapid requests):

```bash
python3 api_security_scanner.py https://api.example.com --rate-limit-probes 10
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at/above `--fail-on` |
| 1 | Findings at/above `--fail-on` were found |
| 2 | Usage error (bad URL, API unreachable) |

Note: the scanner only probes read-only endpoints. It cannot test
authenticated behaviour, object-level authorization for a specific
user's records, or business-logic flaws; those need an authenticated
test with real credentials and per-user test accounts.

## Example

```
$ python3 api_security_scanner.py https://api.github.com
API security report: https://api.github.com
Score: 87/100  Grade: B

  Transport: HTTPS
  Base Status: 200
  ...
  Sensitive Paths Probed: 15
  Sensitive Paths Exposed: 0
  Error Status: 403
  Cors Allow Origin: *
  Allow Header: (none)
  Rate Limited: True

Findings (2):
  [MEDIUM] CORS: CORS allows any origin (*). Safe for public read-only
  data, risky if the API also serves authenticated users.
        Fix: Restrict Access-Control-Allow-Origin to trusted origins
        whenever the API uses cookies or tokens.
  [LOW] Headers: Cache-Control does not forbid caching; authenticated
  API responses may be stored by intermediaries.
        Fix: Send Cache-Control: no-store on authenticated responses.
```

Both findings are expected for GitHub's public API: its responses are
deliberately public and cacheable, and `*` CORS is intentional for a
public read-only API. For an API that serves logged-in users, both
would be real fixes. The full output of that run is saved in
`examples/sample-output-api.github.com.txt` (captured 15 November 2026).

## Teaching notes

This tool pairs well with a lesson on the OWASP API Security Top 10:
run it against a deliberately insecure demo API, then fix one issue at
a time and watch the grade move. Good discussion points:

- Why broken object-level authorization (API1) is the most common API
  flaw: an endpoint can require login and still serve another user's
  records, which no unauthenticated scanner can see.
- Why a public list endpoint is not a vulnerability, but the same
  endpoint returning email addresses or tokens is.
- Why `Access-Control-Allow-Origin: *` is fine for public data and
  dangerous the moment the API reads cookies or tokens.
- Why rate limiting is a security control, not just a performance
  feature: without it, credential stuffing and scraping are free.
- Why verbose errors help attackers more than developers: a stack
  trace names the framework, the file layout and often the database.

## Tests

```bash
python3 tests/run_tests.py   # 10 tests, including a live audit of api.github.com
```

The mock-server tests run a local fake API in secure and insecure
modes, so they need no internet. The live test runs a real audit
against api.github.com and is skipped automatically when the network
is unreachable. (pytest is also supported if it is installed:
`python3 -m pytest tests/ -q`.)

## License

MIT
