"""Determinism, patch verification, severity, report generation, and Chaos Mode."""

import json

from app.models.schemas import SourceFile
from app.pipeline.fixes import generate_fix
from app.pipeline.ingest import ingest_code
from app.pipeline.orchestrator import ScanOptions, run_scan
from app.reports.render import to_html, to_json, to_markdown, to_sarif

SAMPLE = (
    "import os, hashlib, requests\n"
    'API_KEY = "sk-fake-DEADBEEF1234567890abcdef99"\n'
    "def login(name):\n"
    "    cur.execute('SELECT * FROM users WHERE name = ' + name)\n"
    "def pw(password):\n"
    "    return hashlib.md5(password.encode()).hexdigest()\n"
    "def fetch(url):\n"
    "    return requests.get(url, verify=False)\n"
)


def _scan(**opts):
    return run_scan(ingest_code(SAMPLE, "app.py"), ScanOptions(name="t", **opts), "sid")


def test_determinism_identical_reports():
    r1 = _scan()
    r2 = _scan()
    d1, d2 = r1.model_dump(), r2.model_dump()
    for d in (d1, d2):
        d["durationMs"] = 0
    assert json.dumps(d1, sort_keys=True) == json.dumps(d2, sort_keys=True)
    assert [f.id for f in r1.findings] == [f.id for f in r2.findings]


def test_findings_present_and_scored():
    r = _scan()
    ids = {f.ruleId for f in r.findings}
    assert "CM-A001" in ids  # SQLi
    assert "CM-A006" in ids  # verify=False
    assert all(0 <= f.severity_score <= 10 for f in r.findings)
    assert r.security_score < 100


def test_stable_ordering():
    r = _scan()
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    keys = [(rank[f.severity], f.file, f.line, f.ruleId) for f in r.findings]
    assert keys == sorted(keys)


def test_patch_verification():
    r = _scan()
    verified = [f for f in r.findings if f.fix_verified]
    assert verified, "at least one fix should verify"
    for f in verified:
        assert f.fix_diff


def test_fix_actually_removes_finding():
    files = [SourceFile(path="app.py", content=SAMPLE)]
    from app.pipeline.detect import run_detectors
    findings = run_detectors(files)
    verify_false = next(f for f in findings if f.ruleId == "CM-A006")
    generate_fix(verify_false, files[0], files)
    assert verify_false.fix_verified is True


def test_reports_render_all_formats():
    r = _scan()
    assert '"security_score"' in to_json(r)
    assert "# Chaos Monkey report" in to_markdown(r)
    assert "<!doctype html>" in to_html(r)
    sarif = json.loads(to_sarif(r))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]


def test_privacy_attestation_local():
    r = _scan()
    assert r.privacy is not None
    assert r.privacy.data_leaves_machine is False
    assert r.privacy.seed == 42


def test_chaos_mode_detection_rate():
    r = _scan(chaos_mode=True)
    assert r.chaos_mode is not None
    assert r.chaos_mode.injected > 0
    assert r.chaos_mode.detection_rate >= 0.8


def test_no_raw_secret_in_report_json():
    r = _scan()
    assert "DEADBEEF1234567890abcdef99" not in to_json(r)
