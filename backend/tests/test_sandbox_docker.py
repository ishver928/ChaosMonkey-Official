"""Docker-dependent end-to-end sandbox tests: actually launches the fixture apps in containers
and runs real probes against them. Skipped automatically when Docker isn't available/working
(checked once per session) — the probe-logic unit tests in ``test_sandbox_agent.py`` cover the
same decision logic without Docker.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from app.sandbox import docker_runner, entrypoint
from app.sandbox.canary_host import make_canary_seed

FIXTURES = Path(__file__).resolve().parent / "fixtures"

_avail = docker_runner.check_docker()
pytestmark = pytest.mark.skipif(not _avail.available, reason=f"Docker unavailable: {_avail.reason}")


def _run(fixture_dir: Path, pattern: str, image: str, rule_ids: list[str]) -> dict:
    src = FIXTURES / fixture_dir
    files = {p.name: p.read_text(encoding="utf-8") for p in src.glob(pattern)}
    entry = entrypoint.detect(files)
    assert entry.ok, entry.reason

    run_id = docker_runner.new_run_id()
    seed, env = make_canary_seed(run_id)
    plan = {
        "target_host": "placeholder", "target_port": entry.port,
        "db_path": "/data/store.db", "canary_seed": seed,
        "static_findings": [{"ruleId": rid, "file": "app", "snippet": ""} for rid in rule_ids],
        "routes_hint": [], "env": env,
    }
    with tempfile.TemporaryDirectory() as tmp:
        project_dir = Path(tmp)
        for p in src.glob(pattern):
            (project_dir / p.name).write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
        docker_bin = docker_runner._docker_bin()
        result = docker_runner.run_verification(
            run_id, project_dir, image, entry.run_cmd, entry.port, plan, docker_bin,
        )
    assert result.status == "ok", result.error
    return {r["ruleId"]: r for r in result.agent_output.get("results", [])}


def _status(results: dict, rule: str) -> str:
    return results[rule]["status"]


# --- Flask ------------------------------------------------------------------------------

def test_flask_vuln_confirms_real_issues():
    results = _run(
        Path("flask_vuln"), "*.py", docker_runner.RUNNER_PY_IMAGE,
        ["CM-A001", "CM-J001", "CM-S005", "CM-D003", "CM-A005"],
    )
    assert _status(results, "CM-A001") == "confirmed"  # SQL injection
    assert _status(results, "CM-J001") == "confirmed"  # reflected XSS (shared rule id w/ JS)
    assert _status(results, "CM-S005") == "confirmed"  # leaked API key
    assert _status(results, "CM-D003") == "confirmed"  # plaintext PII at rest
    assert _status(results, "CM-A005") == "confirmed"  # debug traceback


def test_flask_safe_has_no_false_confirmations():
    results = _run(
        Path("flask_safe"), "*.py", docker_runner.RUNNER_PY_IMAGE,
        ["CM-A001", "CM-J001", "CM-S005", "CM-D003", "CM-A005"],
    )
    for rule in ("CM-A001", "CM-J001", "CM-S005", "CM-D003", "CM-A005"):
        assert _status(results, rule) != "confirmed", f"{rule}: {results[rule]}"


# --- Express ----------------------------------------------------------------------------

def test_express_vuln_confirms_real_issues():
    results = _run(
        Path("express_vuln"), "*.js", docker_runner.RUNNER_NODE_IMAGE,
        ["CM-J003", "CM-J001", "CM-J002", "CM-S005", "CM-D003"],
    )
    assert _status(results, "CM-J001") == "confirmed"  # reflected XSS
    assert _status(results, "CM-J002") == "confirmed"  # command injection
    assert _status(results, "CM-S005") == "confirmed"  # leaked API key
    assert _status(results, "CM-D003") == "confirmed"  # plaintext PII at rest


def test_express_safe_has_no_false_confirmations():
    results = _run(
        Path("express_safe"), "*.js", docker_runner.RUNNER_NODE_IMAGE,
        ["CM-J003", "CM-J001", "CM-J002", "CM-S005", "CM-D003"],
    )
    for rule in ("CM-J003", "CM-J001", "CM-J002", "CM-S005", "CM-D003"):
        assert _status(results, rule) != "confirmed", f"{rule}: {results[rule]}"


# --- Never-dynamic rules ------------------------------------------------------------------

def test_never_dynamic_rules_are_not_testable():
    """CM-A004 (unsafe deserialization) etc. must never be executed, even if requested."""
    from app.sandbox.service import NEVER_DYNAMIC
    assert "CM-A004" in NEVER_DYNAMIC
    assert "CM-D002" in NEVER_DYNAMIC
