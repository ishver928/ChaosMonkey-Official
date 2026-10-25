"""Tests for POST /api/sandbox/run-adhoc — the route the frontend actually calls, since it
scans entirely client-side and has no server-side scan_id. Exercises the route function
directly (consistent with how the rest of this test suite calls pipeline/service code rather
than spinning up a live HTTP server).
"""
from __future__ import annotations

import time

from fastapi import HTTPException
import pytest

from app.api.sandbox_routes import run_sandbox_adhoc
from app.models.schemas import Finding, SandboxAdhocRunRequest, SourceFile
from app.sandbox import docker_runner, service as sandbox_service


def test_run_adhoc_rejects_empty_files():
    with pytest.raises(HTTPException) as exc:
        run_sandbox_adhoc(SandboxAdhocRunRequest(files=[], findings=[]))
    assert exc.value.status_code == 400


def test_run_adhoc_starts_a_run_not_tied_to_any_stored_scan(monkeypatch):
    # No /api/scan was ever called for this scan_id — the adhoc route must not depend on it.
    monkeypatch.setattr(
        docker_runner, "check_docker",
        lambda: docker_runner.DockerAvailability(available=False, reason="docker executable not found on PATH"),
    )
    req = SandboxAdhocRunRequest(
        files=[SourceFile(path="app.py", content="print('hi')\n")],
        findings=[Finding(id="f1", ruleId="CM-A001", file="app.py", line=1)],
    )
    resp = run_sandbox_adhoc(req)
    assert resp["sandbox_run_id"]
    assert resp["sandbox_run_id"].startswith("")

    deadline = time.time() + 5
    rec = sandbox_service.get_record(resp["sandbox_run_id"])
    while time.time() < deadline and rec.status in ("queued", "running"):
        rec = sandbox_service.get_record(resp["sandbox_run_id"])
        time.sleep(0.05)
    assert rec.status == "docker_unavailable"
    assert rec.results[0].verification.status == "not_testable"
