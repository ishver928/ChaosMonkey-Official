"""Claude Code plugin routes (Phase 1): connect, UI heartbeat/navigate, scan link + summary."""

from __future__ import annotations

import shutil
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import plugin_routes
from app.api.store import store
from app.main import app

from ._netguard import NonLoopbackConnection, block_non_loopback  # noqa: F401  (autouse fixture)

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "demo" / "apps" / "flask_store" / "vulnerable.py"
CANARY = "sk-fake-DEMOCANARY0000000000000000000000canary"
HDR = {"X-ChaosMonkey-Client": "test"}


@pytest.fixture()
def client():
    plugin_routes.state.reset()
    with TestClient(app, base_url="http://127.0.0.1:8000") as c:
        yield c
    plugin_routes.state.reset()


@pytest.fixture()
def project(tmp_path):
    shutil.copy(FIXTURE, tmp_path / "app.py")
    return tmp_path


def _wait(scan_id: str) -> None:
    assert store.get(scan_id).done.wait(60)


def test_netguard_blocks_non_loopback():
    s = socket.socket()
    try:
        with pytest.raises(NonLoopbackConnection):
            s.connect(("93.184.216.34", 80))
    finally:
        s.close()


def test_non_loopback_host_header_rejected():
    with TestClient(app, base_url="http://evil.example") as c:
        assert c.get("/api/plugin/project").status_code == 403


def test_state_changing_routes_require_client_header(client, project):
    r = client.post("/api/plugin/connect", json={"project_path": str(project)})
    assert r.status_code == 403
    r = client.post("/api/plugin/navigate", json={"route": "/connected"})
    assert r.status_code == 403


def test_connect_and_project(client, project):
    r = client.post("/api/plugin/connect", json={"project_path": str(project)}, headers=HDR)
    assert r.status_code == 200 and r.json()["connected"] is True
    p = client.get("/api/plugin/project").json()
    assert p["project_path"] == str(project.resolve())
    assert p["mode"] in {"full", "mock", "detector-only"}


def test_connect_rejects_relative_and_missing(client, tmp_path):
    assert client.post("/api/plugin/connect", json={"project_path": "rel/dir"}, headers=HDR).status_code == 400
    missing = str(tmp_path / "nope")
    assert client.post("/api/plugin/connect", json={"project_path": missing}, headers=HDR).status_code == 400


def test_heartbeat_marks_ui_alive(client):
    assert client.get("/api/plugin/ui-status").json()["ui_alive"] is False
    assert client.post("/api/plugin/navigate", json={"route": "/connected"}, headers=HDR).json()["delivered"] is False
    client.post("/api/plugin/heartbeat", json={"route": "/connected"}, headers=HDR)
    assert client.get("/api/plugin/ui-status").json()["ui_alive"] is True
    r = client.post("/api/plugin/navigate", json={"route": "/report/scan_0123456789abcdef"}, headers=HDR).json()
    assert r["delivered"] is True


def test_heartbeat_expires(client, monkeypatch):
    client.post("/api/plugin/heartbeat", json={}, headers=HDR)
    monkeypatch.setattr(plugin_routes, "HEARTBEAT_TTL_S", -1.0)
    assert client.get("/api/plugin/ui-status").json()["ui_alive"] is False


def test_navigate_rejects_arbitrary_routes(client):
    for bad in ("https://evil.example", "/report/../../x", "javascript:alert(1)", "/report/scan_xyz"):
        assert client.post("/api/plugin/navigate", json={"route": bad}, headers=HDR).status_code == 400


def test_navigate_events_are_queued_for_sse(client):
    client.post("/api/plugin/navigate", json={"route": "/report/scan_0123456789abcdef"}, headers=HDR)
    events = plugin_routes.state.since(0)
    assert events[-1]["type"] == "navigate" and events[-1]["route"] == "/report/scan_0123456789abcdef"


def test_link_requires_connected_project(client, project):
    sid = client.post("/api/scan", json={"path": str(project), "name": "p"}).json()["scan_id"]
    r = client.post("/api/plugin/link", json={"scan_id": sid, "project_path": str(project)}, headers=HDR)
    assert r.status_code == 409
    _wait(sid)


def test_summary_is_metadata_only_and_masked(client, project):
    client.post("/api/plugin/connect", json={"project_path": str(project)}, headers=HDR)
    sid = client.post("/api/scan", json={"path": str(project), "name": "p"}).json()["scan_id"]
    assert client.post("/api/plugin/link", json={"scan_id": sid, "project_path": str(project)}, headers=HDR).status_code == 200
    _wait(sid)
    r = client.get(f"/api/plugin/scan/{sid}/summary")
    body = r.text
    data = r.json()
    assert data["status"] == "done"
    assert data["summary"]["total_findings"] > 0
    # The canary secret (and its distinctive body) must never reach Claude.
    assert CANARY not in body and "DEMOCANARY" not in body
    allowed = {"id", "rule_id", "cwe_id", "title", "severity", "location", "source", "fix_available", "fix_verified"}
    for f in data["summary"]["findings"]:
        assert set(f) == allowed
        assert "snippet" not in f and "evidence" not in str(f)
    # The full report endpoint is untouched by the plugin (existing contract).
    assert client.get(f"/api/scan/{sid}").json()["report"]["findings"]


def test_root_still_json_for_api_clients(client):
    r = client.get("/", headers={"accept": "application/json"})
    assert r.json()["app"] == "Chaos Monkey"


def test_health_privacy_unchanged(client):
    h = client.get("/api/health").json()
    assert h["data_leaves_machine"] is False and h["privacy_ok"] is True


def test_scan_ignores_plugin_state_folder(project):
    from app.pipeline.ingest import ingest_path
    (project / ".chaosmonkey" / "backups" / "t").mkdir(parents=True)
    (project / ".chaosmonkey" / "backups" / "t" / "app.py").write_text("x = 1\n", encoding="utf-8")
    ing = ingest_path(str(project))
    assert [f.path for f in ing.files] == ["app.py"]


def test_mode_reflects_local_ai_switch_not_ollama_reachability(client, project, monkeypatch):
    from app.llm import client as llm
    # AI off (the default): detector-only, even in mock mode, because no model output is used.
    monkeypatch.setattr(llm.ai_state(), "enabled", False)
    assert client.get("/api/plugin/project").json()["mode"] == "detector-only"
    client.post("/api/plugin/connect", json={"project_path": str(project)}, headers=HDR)
    sid = client.post("/api/scan", json={"path": str(project), "name": "p"}).json()["scan_id"]
    client.post("/api/plugin/link", json={"scan_id": sid, "project_path": str(project)}, headers=HDR)
    _wait(sid)
    s = client.get(f"/api/plugin/scan/{sid}/summary").json()
    assert s["mode"] == "detector-only" and s["summary"]["ai_enabled"] is False
    # AI switched on with a pinned model under LLM_MOCK=1: mock.
    monkeypatch.setattr(llm.ai_state(), "enabled", True)
    monkeypatch.setattr(llm.ai_state(), "pin", llm.pin_model())
    assert client.get("/api/plugin/project").json()["mode"] == "mock"
