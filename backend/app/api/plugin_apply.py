"""Apply user-approved fixes to the real project (Claude Code plugin, Phase 2). Additive.

Only the explicit "Apply approved fixes" click in the UI reaches this. It:
  1. takes the finding ids the user approved, keeps those with a backend-verified fix;
  2. checks every target path is confined to the connected project root (no ``..``, no absolute
     paths, no symlinks/junctions) and that the file on disk is byte-identical to what was scanned;
  3. builds the patched contents with the existing ``apply_all_fixes`` (no new fix logic);
  4. backs up the originals to ``<project>/.chaosmonkey/backups/<timestamp>/`` and writes the
     patched files atomically;
  5. re-scans the project with the existing pipeline and reports, per applied fix,
     ``fix_verified`` (the finding is gone at the patched lines) or ``fix_failed``.

Review status returned to Claude is metadata only (rule titles, severities, file:line, results).
"""

from __future__ import annotations

import difflib
import os
import re
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from ..models.schemas import Finding, SourceFile
from ..pipeline.fixes import apply_all_fixes
from ..pipeline.ingest import ingest_path
from ..pipeline.orchestrator import ScanOptions
from .plugin_routes import require_client, report_summary, rule_title, safe_location, state
from .routes import _scan_id
from .store import store

router = APIRouter(prefix="/api/plugin")


class ApplyBody(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)


class DecisionBody(BaseModel):
    decision: str


class ConfinementError(ValueError):
    pass


def require_same_origin(request: Request) -> None:
    """Applying fixes is a browser action: require an Origin that matches the Host (the UI's own
    page). Plain scripts don't send one, so a stray tool call can't silently write files."""
    origin = request.headers.get("origin") or ""
    host = (request.headers.get("host") or "").lower()
    if not origin or urlparse(origin).netloc.lower() != host:
        raise HTTPException(status_code=403, detail="Fixes can only be applied from the ChaosMonkey UI.")


def confined_path(root: Path, rel: str) -> Path:
    """Map a scanned relative path to a real file strictly inside ``root``."""
    if not rel or "\x00" in rel:
        raise ConfinementError("empty path")
    norm = rel.replace("\\", "/")
    if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm) or norm.startswith("//"):
        raise ConfinementError(f"absolute path rejected: {rel}")
    parts = PurePosixPath(norm).parts
    if any(p in ("..", "") for p in parts):
        raise ConfinementError(f"path traversal rejected: {rel}")
    cur = root
    for part in parts:
        cur = cur / part
        if cur.is_symlink():
            raise ConfinementError(f"symlink rejected: {rel}")
    expected = root.joinpath(*parts)
    # Catches junctions / reparse points and anything else that resolves elsewhere.
    if os.path.normcase(str(expected.resolve())) != os.path.normcase(str(expected)):
        raise ConfinementError(f"path resolves outside the project: {rel}")
    if not expected.is_file():
        raise ConfinementError(f"not a regular file: {rel}")
    return expected


def _with_line_endings(original: str, patched: str) -> str:
    if "\r\n" in original:
        return patched.replace("\r\n", "\n").replace("\n", "\r\n")
    return patched


def _write_atomic(path: Path, content: str) -> None:
    tmp = path.with_name(f".{path.name}.chaosmonkey-tmp")
    tmp.write_bytes(content.encode("utf-8"))
    os.replace(tmp, path)


def _backup_dir(root: Path) -> Path:
    base = root / ".chaosmonkey" / "backups"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    d, n = base / stamp, 1
    while d.exists():
        n += 1
        d = base / f"{stamp}-{n}"
    d.mkdir(parents=True)
    gi = root / ".chaosmonkey" / ".gitignore"
    if not gi.exists():
        gi.write_text("*\n", encoding="utf-8")
    return d


def _new_span(old: list[str], new: list[str], line: int) -> tuple[int, int]:
    """1-based [start, end] range in ``new`` that replaced 1-based ``line`` of ``old``."""
    idx = line - 1
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        if i1 <= idx < i2:
            if tag == "equal":
                n = j1 + (idx - i1) + 1
                return n, n
            return j1 + 1, max(j1 + 1, j2)
    return line, line


def _entry(f: Finding, **extra) -> dict:
    return {"id": f.id, "rule_id": f.ruleId, "cwe_id": f.cwe_id, "title": rule_title(f.ruleId, f.cwe_id),
            "severity": f.severity, "location": safe_location(f.file, f.line), **extra}


def _verify_after_rescan(review: dict, root: Path, applied: list[Finding], spans: dict[str, tuple[int, int]],
                         rescan_id: str) -> None:
    session = store.get(rescan_id)
    finished = session is not None and session.done.wait(600)
    with state.lock:
        if not finished or session.record.report is None:
            review["status"] = "error"
            review["error"] = "Re-scan did not finish; fixes were applied but are not verified."
            for e in review["applied"]:
                e["result"] = "unknown"
            return
        report = session.record.report
        for e, f in zip(review["applied"], applied):
            lo, hi = spans[f.id]
            still = any(r.file == f.file and r.ruleId == f.ruleId and lo <= r.line <= hi for r in report.findings)
            e["result"] = "fix_failed" if still else "fix_verified"
        s = report_summary(report)
        review["rescan"] = {"security_score": s["security_score"], "total_findings": s["total_findings"],
                            "counts_by_severity": s["counts_by_severity"]}
        review["status"] = "applied"
        review["finished_at"] = time.time()


@router.post("/scan/{scan_id}/apply")
def apply_approved(scan_id: str, body: ApplyBody, request: Request,
                   x_chaosmonkey_client: Optional[str] = Header(None)) -> dict:
    require_client(request, x_chaosmonkey_client)
    require_same_origin(request)
    session = store.get(scan_id)
    if session is None or session.record.report is None:
        raise HTTPException(status_code=404, detail="Scan not found or not finished.")
    with state.lock:
        root_s = state.scan_projects.get(scan_id)
        existing = state.reviews.get(scan_id)
    if root_s is None:
        raise HTTPException(status_code=409, detail="This scan is not linked to a connected project.")
    if existing and existing["status"] in ("applying", "rescanning", "applied"):
        raise HTTPException(status_code=409, detail="Fixes from this scan were already applied; re-scan first.")
    if not body.finding_ids:
        raise HTTPException(status_code=400, detail="No fixes approved.")
    root = Path(root_s)

    by_id = {f.id: f for f in session.record.report.findings}
    unknown = [i for i in body.finding_ids if i not in by_id]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown finding id(s): {len(unknown)}")
    approved = [by_id[i] for i in dict.fromkeys(body.finding_ids)]
    applicable = [f for f in approved if f.fix_verified and f.fix_diff]
    skipped = [_entry(f, reason="no verified fix") for f in approved if not (f.fix_verified and f.fix_diff)]
    if not applicable:
        raise HTTPException(status_code=400, detail="None of the approved findings has a verified fix.")

    files = {sf.path: sf for sf in session.files}
    targets: dict[str, Path] = {}
    for rel in sorted({f.file for f in applicable}):
        if rel not in files:
            raise HTTPException(status_code=400, detail="Finding refers to a file that was not scanned.")
        try:
            targets[rel] = confined_path(root, rel)
        except ConfinementError as exc:
            raise HTTPException(status_code=400, detail=f"Refused: {exc}") from exc
        try:
            on_disk = targets[rel].read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise HTTPException(status_code=409, detail=f"Cannot read {rel}; re-scan first.") from exc
        if on_disk != files[rel].content:
            raise HTTPException(status_code=409, detail="Project files changed since this scan; re-scan first.")

    subset = {rel: files[rel] for rel in targets}
    patched, _ = apply_all_fixes(applicable, subset)
    changed = {rel: _with_line_endings(subset[rel].content, patched[rel])
               for rel in targets if patched[rel] != subset[rel].content}
    if not changed:
        raise HTTPException(status_code=400, detail="The approved fixes produced no change.")

    backup = _backup_dir(root)
    for rel in changed:
        dest = backup.joinpath(*PurePosixPath(rel).parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(targets[rel].read_bytes())
    for rel, content in changed.items():
        _write_atomic(targets[rel], content)

    spans: dict[str, tuple[int, int]] = {}
    for f in applicable:
        old = subset[f.file].content.split("\n")
        new = patched[f.file].split("\n")
        spans[f.id] = _new_span(old, new, f.line)

    rescan_id = _scan_id(f"plugin-rescan:{scan_id}:{time.time_ns()}")
    review = {
        "scan_id": scan_id,
        "status": "rescanning",
        "applied": [_entry(f, result="pending") for f in applicable],
        "skipped": skipped,
        "files_changed": sorted(changed),
        "backup_dir": backup.relative_to(root).as_posix(),
        "rescan_scan_id": rescan_id,
        "started_at": time.time(),
    }
    with state.lock:
        state.reviews[scan_id] = review
        state.scan_projects[rescan_id] = root_s
    store.start(rescan_id, ingest_path(str(root)), ScanOptions(name=f"{session.record.report.name} (after fixes)"))
    threading.Thread(target=_verify_after_rescan, args=(review, root, applicable, spans, rescan_id), daemon=True).start()
    return {k: review[k] for k in ("scan_id", "status", "files_changed", "backup_dir", "rescan_scan_id")} | {
        "applied_count": len(applicable), "skipped_count": len(skipped)}


@router.post("/scan/{scan_id}/decision")
def review_decision(scan_id: str, body: DecisionBody, request: Request,
                    x_chaosmonkey_client: Optional[str] = Header(None)) -> dict:
    """The user chose to keep the code as is (no fixes). Recorded so Claude can be told."""
    require_client(request, x_chaosmonkey_client)
    require_same_origin(request)
    if body.decision != "declined":
        raise HTTPException(status_code=400, detail="Unsupported decision.")
    if store.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="Unknown scan id")
    with state.lock:
        existing = state.reviews.get(scan_id)
        if existing and existing["status"] in ("rescanning", "applied"):
            raise HTTPException(status_code=409, detail="Fixes were already applied for this scan.")
        state.reviews[scan_id] = {"scan_id": scan_id, "status": "declined", "applied": [], "skipped": [],
                                  "files_changed": [], "backup_dir": None, "rescan_scan_id": None}
    return {"scan_id": scan_id, "status": "declined"}


@router.get("/review/{scan_id}")
def review_status(scan_id: str, request: Request) -> dict:
    """Metadata-only review state for Claude: what was applied and whether each fix verified."""
    from .plugin_routes import require_local
    require_local(request)
    if store.get(scan_id) is None:
        raise HTTPException(status_code=404, detail="Unknown scan id")
    with state.lock:
        review = state.reviews.get(scan_id)
        if review is None:
            return {"scan_id": scan_id, "status": "pending_review", "applied": [], "skipped": [],
                    "files_changed": [], "backup_dir": None, "rescan_scan_id": None}
        out = {k: v for k, v in review.items() if k != "error"}
        out["applied"] = [dict(e) for e in review["applied"]]
        if "error" in review:
            out["error"] = review["error"]
        return out
