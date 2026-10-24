"""Orchestrates one sandbox verification run: pick a stack, detect an entrypoint, launch the
Docker sandbox, map probe results back onto the scan's findings. Never raises outward — any
failure degrades to ``not_testable`` / ``docker_unavailable`` findings so the rest of the report
still renders.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..detectors.masking import scrub
from ..models.schemas import (
    Finding, SandboxFindingResult, SandboxRunRecord, SourceFile, VerificationResult,
)
from . import docker_runner
from .docker_runner import RUNNER_NODE_IMAGE, RUNNER_PY_IMAGE
from .entrypoint import detect as detect_entrypoint

_executor = ThreadPoolExecutor(max_workers=2)
_runs: dict[str, SandboxRunRecord] = {}
_lock = threading.Lock()

# Rules this layer never executes dynamically, even on request (deserialization/crypto/storage
# findings that would require unsafe payloads or aren't meaningfully dynamic).
NEVER_DYNAMIC = {"CM-A004", "CM-D002", "CM-D004", "CM-D001"}


def _store_record(rec: SandboxRunRecord) -> None:
    with _lock:
        _runs[rec.id] = rec


def get_record(run_id: str) -> SandboxRunRecord | None:
    with _lock:
        return _runs.get(run_id)


def start_run(scan_id: str, files: list[SourceFile], findings: list[Finding],
              finding_ids: list[str] | None) -> SandboxRunRecord:
    run_id = docker_runner.new_run_id()
    rec = SandboxRunRecord(id=run_id, scan_id=scan_id, status="queued")
    _store_record(rec)
    _executor.submit(_run, run_id, scan_id, files, findings, finding_ids)
    return rec


def _mark_not_testable(findings: list[Finding], reason: str) -> list[SandboxFindingResult]:
    out = []
    for f in findings:
        out.append(SandboxFindingResult(
            finding_id=f.id, ruleId=f.ruleId, file=f.file,
            verification=VerificationResult(status="not_testable", detail=reason),
        ))
    return out


def _run(run_id: str, scan_id: str, files: list[SourceFile], findings: list[Finding],
          finding_ids: list[str] | None) -> None:
    rec = get_record(run_id)
    assert rec is not None
    rec.status = "running"

    target_findings = [f for f in findings if finding_ids is None or f.id in finding_ids]

    avail = docker_runner.check_docker()
    rec.docker_available = avail.available
    rec.gvisor = avail.gvisor
    if not avail.available:
        rec.status = "docker_unavailable"
        rec.error = avail.reason
        rec.results = _mark_not_testable(target_findings, f"sandbox disabled: docker unavailable ({avail.reason})")
        return

    file_map = {f.path: f.content for f in files}
    entry = detect_entrypoint(file_map)
    if not entry.ok:
        rec.status = "done"
        rec.stack_detected = "unknown"
        rec.results = _mark_not_testable(target_findings, f"entrypoint not found: {entry.reason}")
        return
    rec.stack_detected = entry.kind

    testable, skipped = [], []
    for f in target_findings:
        (skipped if f.ruleId in NEVER_DYNAMIC else testable).append(f)

    results: list[SandboxFindingResult] = []
    for f in skipped:
        results.append(SandboxFindingResult(
            finding_id=f.id, ruleId=f.ruleId, file=f.file,
            verification=VerificationResult(
                status="not_testable", sandbox_run_id=run_id,
                detail="unsafe or meaningless to execute dynamically (deserialization/crypto/storage finding)"),
        ))

    if not testable:
        rec.status = "done"
        rec.results = results
        return

    import tempfile
    with tempfile.TemporaryDirectory(prefix="cm_sbx_src_") as tmp:
        project_dir = Path(tmp)
        for sf in files:
            dest = project_dir / sf.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(sf.content, encoding="utf-8")

        image = RUNNER_PY_IMAGE if entry.kind in ("flask", "fastapi") else RUNNER_NODE_IMAGE
        from .canary_host import make_canary_seed
        canary_seed, canary_env = make_canary_seed(run_id)
        db_path_guess = _guess_db_path(file_map)

        plan = {
            "target_host": "localhost", "target_port": entry.port,
            "db_path": f"/project/{db_path_guess}" if db_path_guess else None,
            "canary_seed": canary_seed,
            "static_findings": [
                {"ruleId": f.ruleId, "file": f.file, "snippet": f.snippet or f.evidence_snippet}
                for f in testable
            ],
            "routes_hint": [],
            "env": canary_env,
        }

        docker_bin = docker_runner._docker_bin() or "docker"
        run_result = docker_runner.run_verification(
            run_id, project_dir, image, entry.run_cmd or [], entry.port, plan, docker_bin,
        )

    rec.log = run_result.log[-40:]
    if run_result.status != "ok":
        rec.status = "error"
        rec.error = scrub(run_result.error)
        rec.results = results + _mark_not_testable(testable, f"sandbox run failed: {scrub(run_result.error)}")
        return

    agent_out = run_result.agent_output
    rec.canary_tag = agent_out.get("canary_tag", "")
    rec.requests_sent = int(agent_out.get("requests_sent", 0))
    by_rule: dict[str, list[dict]] = {}
    for r in agent_out.get("results", []):
        by_rule.setdefault(r.get("ruleId", ""), []).append(r)

    for f in testable:
        matches = by_rule.get(f.ruleId, [])
        if not matches:
            results.append(SandboxFindingResult(
                finding_id=f.id, ruleId=f.ruleId, file=f.file,
                verification=VerificationResult(status="not_testable", sandbox_run_id=run_id,
                                                 detail="no probe result returned for this rule"),
            ))
            continue
        m = matches[0]
        results.append(SandboxFindingResult(
            finding_id=f.id, ruleId=f.ruleId, file=f.file,
            verification=VerificationResult(
                status=m.get("status", "not_confirmed"),
                probe_id=m.get("probe_id", ""),
                evidence=scrub(m.get("evidence", "")),
                detail=scrub(m.get("detail", "")),
                sandbox_run_id=run_id,
            ),
        ))

    rec.status = "done"
    rec.results = results


def _guess_db_path(file_map: dict[str, str]) -> str | None:
    for path, content in file_map.items():
        if path.endswith((".db", ".sqlite", ".sqlite3")):
            return path
    import re
    rx = re.compile(r"""sqlite3?\.connect\(\s*['"]([^'":]+\.(?:db|sqlite3?))['"]""")
    for content in file_map.values():
        m = rx.search(content)
        if m:
            return m.group(1)
    return None


def attach_verification(findings: list[Finding], results: list[SandboxFindingResult]) -> None:
    """Mutates ``findings`` in place, attaching verification results by finding id."""
    by_id = {r.finding_id: r.verification for r in results}
    for f in findings:
        v = by_id.get(f.id)
        if v is not None:
            f.verification = v
