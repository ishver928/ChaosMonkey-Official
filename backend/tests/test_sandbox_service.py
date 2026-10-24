"""Integration test: a real static scan of the vulnerable Flask fixture, then the sandbox
verification service attaching real dynamic results onto those exact findings — the same path
the ``/api/sandbox/run`` and ``/api/sandbox/{id}`` routes drive. Docker-dependent; skipped when
Docker is unavailable (see ``test_sandbox_docker.py`` for the bare Docker-layer tests and
``test_sandbox_agent.py`` for the Docker-free probe-logic tests).
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from app.api.store import store
from app.models.schemas import SourceFile
from app.pipeline.ingest import Ingested
from app.pipeline.orchestrator import ScanOptions
from app.sandbox import docker_runner, service as sandbox_service

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_avail = docker_runner.check_docker()
pytestmark = pytest.mark.skipif(not _avail.available, reason=f"Docker unavailable: {_avail.reason}")


def _scan_vulnerable_flask_app():
    ingested = Ingested()
    for p in (FIXTURES / "flask_vuln").glob("*.py"):
        ingested.add_raw(p.name, p.read_bytes())
    sid = "sbx_test_" + str(int(time.time() * 1000))
    return sid, store.run_sync(sid, ingested, ScanOptions(name="sandbox-fixture", use_llm=False))


def test_sandbox_run_attaches_confirmed_verification_to_real_findings():
    scan_id, report = _scan_vulnerable_flask_app()
    rule_ids_found = {f.ruleId for f in report.findings}
    # Sanity: the static pipeline itself should have actually flagged the injected bugs.
    assert "CM-A001" in rule_ids_found  # SQL injection
    assert "CM-A005" in rule_ids_found  # Flask debug mode

    rec = sandbox_service.start_run(scan_id, store.get(scan_id).files, report.findings, None)
    deadline = time.time() + 60
    while time.time() < deadline:
        rec = sandbox_service.get_record(rec.id)
        if rec.status in ("done", "error", "docker_unavailable"):
            break
        time.sleep(0.5)
    assert rec.status == "done", (rec.status, rec.error)

    by_rule = {r.ruleId: r for r in rec.results}
    assert by_rule["CM-A001"].verification.status == "confirmed"
    assert by_rule["CM-A005"].verification.status == "confirmed"
    for r in rec.results:
        assert r.verification.sandbox_run_id == rec.id

    sandbox_service.attach_verification(report.findings, rec.results)
    attached = {f.ruleId: f.verification for f in report.findings if f.verification is not None}
    assert attached["CM-A001"].status == "confirmed"
    assert attached["CM-A001"].evidence  # masked/short, but present
