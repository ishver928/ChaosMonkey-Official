"""Fixed, versioned, deterministic probes.

Each probe answers one question about the *running* app: "does this specific static finding
reproduce when exercised over HTTP?" Probes never try to pivot, exfiltrate real data, or chain
into other attacks — each is a single bounded HTTP exchange (or a read of the mounted SQLite
file) compared against a known-bad signature. This is a verification layer, not a pentester.

Every probe returns a dict: {status, probe_id, evidence, detail}. status is one of
"confirmed" | "not_confirmed" | "not_testable". Evidence strings are short and are passed
through the backend's existing `scrub()` before they ever leave the sandbox process.
"""
from __future__ import annotations

import html
import re
import sqlite3
from pathlib import Path

from cm_canary import Canary
from cm_target import HttpTarget, Resp

PROBES_VERSION = "1"

DB_ERROR_SIGNATURES = re.compile(
    r"sqlite3\.(OperationalError|ProgrammingError)|sqlalchemy\.exc|"
    r"psycopg2\.(?:errors|ProgrammingError)|near \"|unrecognized token|"
    r"syntax error.*SQL|pymysql\.err|django\.db\.utils",
    re.I,
)

DEBUG_TRACEBACK = re.compile(
    r"Traceback \(most recent call last\)|Werkzeug Debugger|'werkzeug\.debug'|"
    r"at Object\.<anonymous>.*node_modules|UnhandledPromiseRejection|NodeJS\.Process",
)


def _result(status: str, probe_id: str, evidence: str = "", detail: str = "") -> dict:
    return {"status": status, "probe_id": probe_id, "evidence": evidence[:400], "detail": detail}


# --- SQL injection (CM-A001 / CM-J003, CWE-89) -----------------------------------------------

def probe_sqli(target: HttpTarget, path: str, param: str, canary: Canary, method: str = "GET") -> dict:
    probe_id = f"sqli-v{PROBES_VERSION}"
    baseline_value = "cm_probe_baseline"
    quote_value = "cm_probe_baseline'"
    bool_true = "' OR '1'='1"
    bool_false = "' AND '1'='2"

    def send(value: str) -> Resp:
        if method.upper() == "GET":
            return target.request("GET", path, query={param: value})
        return target.request("POST", path, form={param: value})

    r_base = send(baseline_value)
    if r_base.error:
        return _result("not_testable", probe_id, detail=f"target unreachable: {r_base.error}")

    r_quote = send(quote_value)
    if r_quote.status == 500 or DB_ERROR_SIGNATURES.search(r_quote.body):
        return _result("confirmed", probe_id, evidence=_first_match(DB_ERROR_SIGNATURES, r_quote.body),
                        detail="single-quote caused a DB error signature")

    r_true = send(bool_true)
    r_false = send(bool_false)
    if not r_true.error and not r_false.error:
        true_len, false_len, base_len = len(r_true.body), len(r_false.body), len(r_base.body)
        # Signature: the always-true branch (' OR '1'='1) returns a materially different,
        # larger body than both the baseline (nonexistent row) and the always-false branch —
        # i.e. the WHERE clause itself is being altered by the injected quote.
        false_matches_base = abs(false_len - base_len) < 10 or r_false.status != 200
        true_diverges = abs(true_len - base_len) > 40 or (r_true.status == 200 and r_false.status != 200)
        if r_true.status == 200 and false_matches_base and true_diverges:
            return _result("confirmed", probe_id,
                            evidence=f"boolean differential: true-branch len={true_len} false-branch len={false_len}",
                            detail="OR '1'='1' body differs materially from AND '1'='2'")

    return _result("not_confirmed", probe_id, detail="no DB error signature or boolean differential observed")


def _first_match(rx: re.Pattern, text: str) -> str:
    m = rx.search(text)
    return m.group(0) if m else ""


# --- Reflected XSS (CM-J001, CWE-79) ---------------------------------------------------------

def probe_reflected_xss(target: HttpTarget, path: str, param: str, canary: Canary, method: str = "GET") -> dict:
    probe_id = f"xss-v{PROBES_VERSION}"
    marker = canary.xss_marker
    payload = f"<b>{marker}</b>"

    def send(value: str) -> Resp:
        if method.upper() == "GET":
            return target.request("GET", path, query={param: value})
        return target.request("POST", path, form={param: value})

    resp = send(payload)
    if resp.error:
        return _result("not_testable", probe_id, detail=f"target unreachable: {resp.error}")
    if payload in resp.body:
        return _result("confirmed", probe_id, evidence=f"unescaped marker reflected: {marker}",
                        detail="raw <b>...</b> payload present verbatim in response body")
    if html.escape(payload) in resp.body or marker in resp.body:
        return _result("not_confirmed", probe_id, detail="marker reflected but HTML-escaped")
    return _result("not_confirmed", probe_id, detail="marker not reflected")


# --- Command injection (CM-A002 / CM-J002, CWE-78) -------------------------------------------

def probe_command_injection(target: HttpTarget, path: str, param: str, canary: Canary, method: str = "GET") -> dict:
    """Fires a harmless `echo <marker>` chained onto a benign value and looks for the marker
    appearing in the response where it could only come from shell execution."""
    probe_id = f"cmdi-v{PROBES_VERSION}"
    marker = canary.cmdi_marker
    benign = "cm_probe"
    payloads = [f"{benign}; echo {marker}", f"{benign} && echo {marker}", f"{benign}` echo {marker} `"]

    def send(value: str) -> Resp:
        if method.upper() == "GET":
            return target.request("GET", path, query={param: value})
        return target.request("POST", path, form={param: value})

    for payload in payloads:
        resp = send(payload)
        if resp.error:
            continue
        if marker in resp.body:
            return _result("confirmed", probe_id, evidence=f"shell marker echoed back: {marker}",
                            detail=f"payload shape: {payload.replace(marker, '<marker>')}")
    return _result("not_confirmed", probe_id, detail="no echoed marker across tested shell metacharacters")


# --- Exposed secrets (CM-S*, CWE-798) --------------------------------------------------------

_SECRET_RX = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}|sk-ant-[A-Za-z0-9_\-]{20,}|"
    r"\bghp_[A-Za-z0-9]{36}\b|AIza[0-9A-Za-z_\-]{35}",
)


def probe_exposed_secret(target: HttpTarget, paths: list[str], canary: Canary) -> dict:
    probe_id = f"secret-v{PROBES_VERSION}"
    for path in paths:
        resp = target.request("GET", path)
        if resp.error or resp.status >= 400:
            continue
        if canary.fake_api_key in resp.body:
            return _result("confirmed", probe_id, evidence=f"canary API key served at {path}",
                            detail="seeded fake key appeared in an HTTP response")
        m = _SECRET_RX.search(resp.body)
        if m:
            return _result("confirmed", probe_id, evidence=f"secret-shaped value served at {path}",
                            detail="response matched a known secret pattern")
    return _result("not_confirmed", probe_id, detail=f"checked {len(paths)} path(s); no canary or secret pattern served")


# --- PII at rest (CM-P*/CM-D003, CWE-312) ----------------------------------------------------

def probe_pii_at_rest(db_path: str, canary: Canary) -> dict:
    probe_id = f"pii-rest-v{PROBES_VERSION}"
    p = Path(db_path)
    if not p.exists():
        return _result("not_testable", probe_id, detail="no SQLite file found to inspect")
    try:
        raw = p.read_bytes()
    except OSError as exc:
        return _result("not_testable", probe_id, detail=f"could not read DB file: {exc}")
    text = raw.decode("utf-8", "ignore")
    if canary.fake_name in text or canary.fake_dob in text:
        return _result("confirmed", probe_id, evidence="canary name/DOB found in plaintext in the DB file",
                        detail=f"db={p.name}")
    try:
        conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        for (table,) in conn.execute("select name from sqlite_master where type='table'").fetchall():
            cols = [r[1] for r in conn.execute(f"pragma table_info('{table}')").fetchall()]
            pw_cols = [c for c in cols if re.search(r"pass", c, re.I)]
            for col in pw_cols:
                rows = conn.execute(f"select \"{col}\" from \"{table}\" limit 50").fetchall()
                for (val,) in rows:
                    if val and str(val) == canary.fake_password:
                        return _result("confirmed", probe_id,
                                        evidence=f"password stored in plaintext in {table}.{col}",
                                        detail="stored value matched the seeded canary password exactly")
        conn.close()
    except sqlite3.Error:
        pass
    return _result("not_confirmed", probe_id, detail="canary values not found in plaintext in the DB file")


# --- Insecure config / debug traceback (CM-A005, CWE-489/209) --------------------------------

def probe_debug_traceback(target: HttpTarget, path: str, param: str) -> dict:
    probe_id = f"debug-v{PROBES_VERSION}"
    resp = target.request("GET", path, query={param: "}{[malformed"})
    if resp.error:
        return _result("not_testable", probe_id, detail=f"target unreachable: {resp.error}")
    if resp.status >= 500 and DEBUG_TRACEBACK.search(resp.body):
        return _result("confirmed", probe_id, evidence=_first_match(DEBUG_TRACEBACK, resp.body),
                        detail="forced error returned a framework debug traceback")
    return _result("not_confirmed", probe_id, detail="forced error did not return a debug traceback")
