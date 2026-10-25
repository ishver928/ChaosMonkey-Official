"""Unit tests for the sandbox probe-agent logic against a mock HTTP target — no Docker needed.

These exercise exactly the deterministic probe functions that run inside the container, so
the bulk of the verification logic is tested without ever touching Docker.
"""
from __future__ import annotations

import sys
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent / "app" / "sandbox" / "agent"
if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))

from cm_canary import Canary  # noqa: E402
from cm_probes import (  # noqa: E402
    probe_command_injection, probe_debug_traceback, probe_exposed_secret,
    probe_pii_at_rest, probe_reflected_xss, probe_sqli,
)
from cm_target import Resp  # noqa: E402


class MockTarget:
    """Stands in for HttpTarget: ``responder(method, path, value)`` decides the canned Resp."""

    def __init__(self, responder) -> None:
        self.responder = responder
        self.requests_sent = 0

    def request(self, method, path, query=None, form=None, json_body=None) -> Resp:
        self.requests_sent += 1
        value = (query or form or {}).get(next(iter((query or form or {}) or {}), None), "")
        return self.responder(method, path, value)


def canary() -> Canary:
    return Canary(seed="test-seed")


# --- SQL injection -----------------------------------------------------------------------

def test_sqli_confirmed_on_db_error():
    def responder(method, path, value):
        if "'" in value and value.count("'") % 2 == 1:
            return Resp(status=500, body="sqlite3.OperationalError: near \"'\": syntax error")
        return Resp(status=200, body="ok")
    r = probe_sqli(MockTarget(responder), "/login", "username", canary())
    assert r["status"] == "confirmed"


def test_sqli_confirmed_on_boolean_differential():
    def responder(method, path, value):
        if value == "' OR '1'='1":
            return Resp(status=200, body="row1 row2 row3 lots of matching rows here padded out")
        if value == "' AND '1'='2":
            return Resp(status=200, body="no")
        return Resp(status=200, body="no")
    r = probe_sqli(MockTarget(responder), "/login", "username", canary())
    assert r["status"] == "confirmed"


def test_sqli_not_confirmed_on_parameterized_query():
    def responder(method, path, value):
        return Resp(status=200 if value else 401, body="login failed")
    r = probe_sqli(MockTarget(responder), "/login", "username", canary())
    assert r["status"] == "not_confirmed"


def test_sqli_not_confirmed_on_unrelated_500():
    """Regression: a bare 500 (e.g. a different bug entirely unlocked by the quote) must not
    be read as a SQL-injection confirmation on its own — only a real DB error signature counts."""
    def responder(method, path, value):
        if "'" in value:
            return Resp(status=500, body="<html>Internal Server Error</html>")
        return Resp(status=200, body="ok")
    r = probe_sqli(MockTarget(responder), "/login", "username", canary())
    assert r["status"] == "not_confirmed"


def test_sqli_not_testable_when_unreachable():
    def responder(method, path, value):
        return Resp(error="ConnectionRefusedError")
    r = probe_sqli(MockTarget(responder), "/login", "username", canary())
    assert r["status"] == "not_testable"


# --- Reflected XSS -------------------------------------------------------------------------

def test_xss_confirmed_when_unescaped():
    c = canary()

    def responder(method, path, value):
        return Resp(status=200, headers={"content-type": "text/html"}, body=f"<html>results for {value}</html>")
    r = probe_reflected_xss(MockTarget(responder), "/search", "q", c)
    assert r["status"] == "confirmed"
    assert c.xss_marker in r["evidence"]


def test_xss_not_confirmed_when_escaped():
    import html as html_mod
    c = canary()

    def responder(method, path, value):
        return Resp(status=200, headers={"content-type": "text/html"}, body=f"<html>{html_mod.escape(value)}</html>")
    r = probe_reflected_xss(MockTarget(responder), "/search", "q", c)
    assert r["status"] == "not_confirmed"


# --- Command injection ----------------------------------------------------------------------

def test_cmdi_confirmed_when_marker_echoed():
    def responder(method, path, value):
        if ";" in value or "&&" in value or "`" in value:
            marker = value.split("echo", 1)[1].strip().split()[0]
            return Resp(status=200, body=f"ping {marker}")
        return Resp(status=200, body="ping cm_probe")
    r = probe_command_injection(MockTarget(responder), "/ping", "host", canary())
    assert r["status"] == "confirmed"


def test_cmdi_not_confirmed_when_sanitized():
    def responder(method, path, value):
        return Resp(status=200, body="host noted (sanitized)")
    r = probe_command_injection(MockTarget(responder), "/ping", "host", canary())
    assert r["status"] == "not_confirmed"


def test_cmdi_not_confirmed_when_payload_merely_reflected():
    """Regression: an app that safely echoes the raw input back (e.g. HTML-escaped) will
    contain the marker too, since it's part of what was sent — that must not look like
    execution just because the marker string shows up."""
    def responder(method, path, value):
        return Resp(status=200, body=f"host noted: {value}")
    r = probe_command_injection(MockTarget(responder), "/ping", "host", canary())
    assert r["status"] == "not_confirmed"


# --- Exposed secrets -------------------------------------------------------------------------

def test_secret_confirmed_on_canary_key():
    c = canary()

    def responder(method, path, value):
        if path == "/config":
            return Resp(status=200, body=f"service configured with key {c.fake_api_key}")
        return Resp(status=404, body="")
    r = probe_exposed_secret(MockTarget(responder), ["/", "/config"], c)
    assert r["status"] == "confirmed"


def test_secret_not_confirmed_when_absent():
    def responder(method, path, value):
        return Resp(status=200, body="service configured")
    r = probe_exposed_secret(MockTarget(responder), ["/", "/config"], canary())
    assert r["status"] == "not_confirmed"


# --- PII at rest -------------------------------------------------------------------------

def test_pii_at_rest_confirmed_plaintext(tmp_path):
    c = canary()
    db_file = tmp_path / "store.db"
    db_file.write_text(f"some binary-ish header {c.fake_name} {c.fake_dob} trailer", encoding="utf-8")
    r = probe_pii_at_rest(str(db_file), c)
    assert r["status"] == "confirmed"


def test_pii_at_rest_not_confirmed_when_hashed(tmp_path):
    import hashlib
    c = canary()
    db_file = tmp_path / "store.db"
    db_file.write_text(hashlib.sha256(c.fake_name.encode()).hexdigest(), encoding="utf-8")
    r = probe_pii_at_rest(str(db_file), c)
    assert r["status"] == "not_confirmed"


def test_pii_at_rest_not_testable_when_missing(tmp_path):
    r = probe_pii_at_rest(str(tmp_path / "nope.db"), canary())
    assert r["status"] == "not_testable"


# --- Insecure config / debug traceback -------------------------------------------------------

def test_debug_traceback_confirmed():
    def responder(method, path, value):
        return Resp(status=500, body="Traceback (most recent call last):\n  File ... Werkzeug Debugger")
    r = probe_debug_traceback(MockTarget(responder), "/crash", "x")
    assert r["status"] == "confirmed"


def test_debug_traceback_not_confirmed_on_generic_error():
    def responder(method, path, value):
        return Resp(status=500, body="internal error")
    r = probe_debug_traceback(MockTarget(responder), "/crash", "x")
    assert r["status"] == "not_confirmed"
