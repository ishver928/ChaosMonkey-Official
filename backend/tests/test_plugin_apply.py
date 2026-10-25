"""Claude Code plugin Phase 2: apply ONLY approved fixes, with backups, confinement and re-scan."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import plugin_routes
from app.api.plugin_apply import ConfinementError, confined_path
from app.api.store import store
from app.main import app

from ._netguard import block_non_loopback  # noqa: F401  (autouse fixture)

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "demo" / "apps" / "flask_store" / "vulnerable.py"
CANARY = "sk-fake-DEMOCANARY0000000000000000000000canary"
BASE = "http://127.0.0.1:8000"
UI = {"X-ChaosMonkey-Client": "chaosmonkey-ui", "Origin": BASE}


@pytest.fixture()
def client():
    plugin_routes.state.reset()
    with TestClient(app, base_url=BASE) as c:
        yield c
    plugin_routes.state.reset()


def _project(tmp_path: Path, crlf: bool = False) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    data = FIXTURE.read_bytes()
    if crlf:
        data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    (root / "app.py").write_bytes(data)
    return root.resolve()


def _scan(client, root: Path) -> tuple[str, list[dict]]:
    client.post("/api/plugin/connect", json={"project_path": str(root)}, headers=UI)
    sid = client.post("/api/scan", json={"path": str(root), "name": "proj"}).json()["scan_id"]
    assert client.post("/api/plugin/link", json={"scan_id": sid, "project_path": str(root)}, headers=UI).status_code == 200
    assert store.get(sid).done.wait(60)
    return sid, client.get(f"/api/scan/{sid}").json()["report"]["findings"]


def _approve(findings: list[dict]) -> list[str]:
    ids = [f["id"] for f in findings if f["fix_verified"] and f["fix_diff"] and (f["ruleId"] == "CM-A005" or f["cwe_id"] == "CWE-798")]
    assert ids
    return ids


def _wait_review(client, sid: str) -> dict:
    for _ in range(300):
        r = client.get(f"/api/plugin/review/{sid}").json()
        if r["status"] not in ("rescanning", "applying"):
            return r
        time.sleep(0.1)
    raise AssertionError("review did not finish")


def test_apply_writes_only_approved_fixes_with_backup_and_verification(client, tmp_path):
    root = _project(tmp_path)
    original = (root / "app.py").read_bytes()
    sid, findings = _scan(client, root)
    assert client.get(f"/api/plugin/review/{sid}").json()["status"] == "pending_review"
    approved = _approve(findings)

    r = client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": approved}, headers=UI)
    assert r.status_code == 200, r.text
    assert CANARY not in r.text
    review = _wait_review(client, sid)
    assert review["status"] == "applied"
    assert {e["id"] for e in review["applied"]} == set(approved)
    assert all(e["result"] in ("fix_verified", "fix_failed") for e in review["applied"])
    assert any(e["result"] == "fix_verified" for e in review["applied"])
    assert review["files_changed"] == ["app.py"]

    patched = (root / "app.py").read_text(encoding="utf-8")
    assert CANARY not in patched
    assert "debug=False" in patched
    # Unapproved issues are left alone (e.g. the MD5 hashing line still exists).
    assert "hashlib.md5" in patched

    backup = root / review["backup_dir"] / "app.py"
    assert backup.read_bytes() == original
    assert (root / ".chaosmonkey" / ".gitignore").read_text() == "*\n"

    body = client.get(f"/api/plugin/review/{sid}").text
    assert CANARY not in body and "DEMOCANARY" not in body and "fix_diff" not in body

    # The re-scan is a normal scan, viewable in the UI, and does not see the backup copy.
    rescan = client.get(f"/api/scan/{review['rescan_scan_id']}").json()["report"]
    assert [f["path"] for f in rescan["files"]] == ["app.py"]

    # A second apply from the same (now stale) scan is refused.
    assert client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": approved}, headers=UI).status_code == 409


def test_apply_requires_browser_origin_and_client_header(client, tmp_path):
    root = _project(tmp_path)
    sid, findings = _scan(client, root)
    ids = _approve(findings)
    no_origin = {"X-ChaosMonkey-Client": "x"}
    assert client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": ids}, headers=no_origin).status_code == 403
    evil = {"X-ChaosMonkey-Client": "x", "Origin": "http://evil.example"}
    assert client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": ids}, headers=evil).status_code == 403
    assert client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": ids}, headers={"Origin": BASE}).status_code == 403
    assert (root / "app.py").read_bytes() == FIXTURE.read_bytes()


def test_apply_refuses_unlinked_scan(client, tmp_path):
    root = _project(tmp_path)
    sid = client.post("/api/scan", json={"path": str(root), "name": "x"}).json()["scan_id"]
    assert store.get(sid).done.wait(60)
    findings = client.get(f"/api/scan/{sid}").json()["report"]["findings"]
    r = client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": _approve(findings)}, headers=UI)
    assert r.status_code == 409


def test_apply_refuses_when_file_changed_since_scan(client, tmp_path):
    root = _project(tmp_path)
    sid, findings = _scan(client, root)
    (root / "app.py").write_text("print('rewritten by Claude')\n", encoding="utf-8")
    r = client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": _approve(findings)}, headers=UI)
    assert r.status_code == 409
    assert (root / "app.py").read_text() == "print('rewritten by Claude')\n"
    assert not (root / ".chaosmonkey" / "backups").exists()


def test_apply_rejects_unverified_and_unknown(client, tmp_path):
    root = _project(tmp_path)
    sid, findings = _scan(client, root)
    unverified = [f["id"] for f in findings if not f["fix_verified"]]
    assert unverified
    assert client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": unverified}, headers=UI).status_code == 400
    assert client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": ["deadbeef"]}, headers=UI).status_code == 400
    assert client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": []}, headers=UI).status_code == 400
    assert (root / "app.py").read_bytes() == FIXTURE.read_bytes()


def test_apply_rejects_paths_escaping_the_project(client, tmp_path):
    root = _project(tmp_path)
    sid, findings = _scan(client, root)
    ids = _approve(findings)
    outside = tmp_path / "outside.py"
    outside.write_bytes(FIXTURE.read_bytes())
    session = store.get(sid)
    # Simulate a scan whose file paths point outside the project root.
    for f in session.record.report.findings:
        f.file = "../outside.py"
    for sf in session.files:
        sf.path = "../outside.py"
    r = client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": ids}, headers=UI)
    assert r.status_code == 400 and "traversal" in r.json()["detail"]
    assert outside.read_bytes() == FIXTURE.read_bytes()


def test_crlf_line_endings_are_preserved(client, tmp_path):
    root = _project(tmp_path, crlf=True)
    sid, findings = _scan(client, root)
    assert client.post(f"/api/plugin/scan/{sid}/apply", json={"finding_ids": _approve(findings)}, headers=UI).status_code == 200
    data = (root / "app.py").read_bytes()
    assert b"\r\n" in data and b"\r\r" not in data and data.count(b"\n") == data.count(b"\r\n")
    _wait_review(client, sid)


def test_decline_is_recorded(client, tmp_path):
    root = _project(tmp_path)
    sid, _ = _scan(client, root)
    assert client.post(f"/api/plugin/scan/{sid}/decision", json={"decision": "declined"}, headers=UI).status_code == 200
    assert client.get(f"/api/plugin/review/{sid}").json()["status"] == "declined"
    assert (root / "app.py").read_bytes() == FIXTURE.read_bytes()


# --- confinement unit tests -------------------------------------------------------------

@pytest.mark.parametrize("rel", ["../x.py", "a/../../x.py", "/etc/passwd", "C:/Windows/win.ini", "c:\\x.py", "\\\\server\\share\\x", "", "a//b.py"])
def test_confined_path_rejects(tmp_path, rel):
    with pytest.raises(ConfinementError):
        confined_path(tmp_path.resolve(), rel)


def test_confined_path_accepts_nested_file(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x", encoding="utf-8")
    assert confined_path(tmp_path.resolve(), "src/a.py") == tmp_path.resolve() / "src" / "a.py"


def test_confined_path_rejects_symlinked_file(tmp_path):
    root = (tmp_path / "root")
    root.mkdir()
    target = tmp_path / "secret.py"
    target.write_text("x", encoding="utf-8")
    try:
        os.symlink(target, root / "link.py")
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs Developer Mode/admin on this Windows machine")
    with pytest.raises(ConfinementError):
        confined_path(root.resolve(), "link.py")


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions are Windows-only")
def test_confined_path_rejects_junction(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "a.py").write_text("x", encoding="utf-8")
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(root / "j"), str(elsewhere)], capture_output=True)
    if r.returncode != 0:
        pytest.skip("could not create a junction")
    with pytest.raises(ConfinementError):
        confined_path(root.resolve(), "j/a.py")
    shutil.rmtree(root / "j", ignore_errors=True)
