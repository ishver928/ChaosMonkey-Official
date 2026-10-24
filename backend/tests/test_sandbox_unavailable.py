"""Docker-free test of the degrade path: when Docker isn't available, every requested finding
must come back ``not_testable`` with a reason, the rest of the report is untouched, and nothing
raises. Runs regardless of whether Docker happens to be installed on this machine — it forces
the "unavailable" branch directly rather than relying on the environment.
"""
from __future__ import annotations

import time

from app.models.schemas import Finding, SourceFile
from app.sandbox import docker_runner, service as sandbox_service


def test_docker_unavailable_marks_findings_not_testable(monkeypatch):
    monkeypatch.setattr(
        docker_runner, "check_docker",
        lambda: docker_runner.DockerAvailability(available=False, reason="docker executable not found on PATH"),
    )

    files = [SourceFile(path="app.py", content="print('hi')\n")]
    findings = [Finding(id="f1", ruleId="CM-A001", file="app.py", line=1)]

    rec = sandbox_service.start_run("scan_x", files, findings, None)
    deadline = time.time() + 5
    while time.time() < deadline and rec.status in ("queued", "running"):
        rec = sandbox_service.get_record(rec.id)
        time.sleep(0.05)

    assert rec.status == "docker_unavailable"
    assert rec.docker_available is False
    assert len(rec.results) == 1
    assert rec.results[0].verification.status == "not_testable"
    assert "docker" in rec.results[0].verification.detail.lower()


def test_never_dynamic_rule_skipped_even_with_docker(monkeypatch):
    """CM-A004 etc. must come back not_testable without ever reaching the docker layer."""
    called = {"run_verification": False}

    def _fail_if_called(*a, **k):
        called["run_verification"] = True
        raise AssertionError("run_verification must not be called for a never-dynamic rule")

    monkeypatch.setattr(
        docker_runner, "check_docker",
        lambda: docker_runner.DockerAvailability(available=True, reason=""),
    )
    monkeypatch.setattr(sandbox_service.docker_runner, "run_verification", _fail_if_called)
    monkeypatch.setattr(
        "app.sandbox.entrypoint.detect",
        lambda files: __import__("app.sandbox.entrypoint", fromlist=["EntrypointInfo"]).EntrypointInfo(
            ok=True, kind="flask", file="app.py", port=8080, run_cmd=["python", "app.py"],
        ),
    )

    files = [SourceFile(path="app.py", content="from flask import Flask\napp = Flask(__name__)\n")]
    findings = [Finding(id="f1", ruleId="CM-A004", file="app.py", line=1)]

    rec = sandbox_service.start_run("scan_y", files, findings, None)
    deadline = time.time() + 5
    while time.time() < deadline and rec.status in ("queued", "running"):
        rec = sandbox_service.get_record(rec.id)
        time.sleep(0.05)

    assert rec.status == "done"
    assert rec.results[0].verification.status == "not_testable"
    assert not called["run_verification"]
