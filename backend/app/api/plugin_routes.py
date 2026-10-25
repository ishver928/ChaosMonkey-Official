"""Additive routes used by the Claude Code plugin (``claude-code-plugin/``).

The plugin is a thin wrapper: it never re-implements detection, CWE retrieval, LLM, validation,
severity or fix verification. Everything here either *records* plugin state (which project is
connected, whether a UI tab is alive) or *reads* existing scan results and reduces them to
metadata that is safe to hand to Claude (counts, severities, rule titles, file:line).

Nothing returned by ``/api/plugin/*`` may contain code, evidence excerpts or secret values,
because MCP tool results enter Claude's context.

Defences for a localhost API that can trigger work on the user's machine:
  * Host header must be loopback (blocks DNS-rebinding pages from reaching these routes).
  * State-changing routes require the ``X-ChaosMonkey-Client`` header, which forces a CORS
    preflight from any other origin — and CORS only allows the local dev frontend.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..detectors.js_rules import JS_RULES
from ..detectors.masking import scrub
from ..detectors.python_ast import AST_RULES
from ..detectors.rules import RULE_BY_ID
from ..kb.store import get_kb
from ..config import settings
from ..llm import client as llm
from ..models.schemas import ScanReport
from .store import store

router = APIRouter(prefix="/api/plugin")

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}
# Heartbeats from a hidden tab can be throttled by the browser to ~1/minute, so allow slack.
HEARTBEAT_TTL_S = 75.0
_ROUTE_RX = re.compile(r"^/(connected|scan|report|report/scan_[0-9a-f]{16})$")
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


# --------------------------------------------------------------------------- guards

def require_local(request: Request) -> None:
    host = (request.headers.get("host") or "").strip().lower()
    if host.startswith("["):
        hostname = host.split("]")[0] + "]"
    else:
        hostname = host.rsplit(":", 1)[0] if ":" in host else host
    if hostname not in _LOOPBACK_HOSTS:
        raise HTTPException(status_code=403, detail="ChaosMonkey only answers loopback requests.")


def require_client(request: Request, header: Optional[str]) -> None:
    require_local(request)
    if not header:
        raise HTTPException(status_code=403, detail="Missing X-ChaosMonkey-Client header.")


def normalize_project(path: str) -> Path:
    """Resolve a project directory the user asked us to connect. Must be an existing dir."""
    if not path or "\x00" in path:
        raise HTTPException(status_code=400, detail="project_path is required.")
    p = Path(path).expanduser()
    if not p.is_absolute():
        raise HTTPException(status_code=400, detail="project_path must be absolute.")
    p = p.resolve()
    if not p.is_dir():
        raise HTTPException(status_code=400, detail="project_path is not a directory.")
    return p


# --------------------------------------------------------------------------- state

class _PluginState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.connected: Optional[str] = None
        self.connected_at: float = 0.0
        self.projects: set[str] = set()
        self.scan_projects: dict[str, str] = {}
        self.last_heartbeat: float = 0.0
        self.subscribers: int = 0
        self.events: list[dict] = []
        self.seq: int = 0
        # scan_id -> review record (see plugin_apply.py); in memory only, like scans.
        self.reviews: dict[str, dict] = {}

    def ui_alive(self) -> bool:
        with self.lock:
            return self.subscribers > 0 or (time.time() - self.last_heartbeat) < HEARTBEAT_TTL_S

    def push(self, event: dict) -> int:
        with self.lock:
            self.seq += 1
            self.events.append({**event, "seq": self.seq})
            self.events = self.events[-50:]
            return self.seq

    def since(self, seq: int) -> list[dict]:
        with self.lock:
            return [e for e in self.events if e["seq"] > seq]

    def reset(self) -> None:
        self.__init__()


state = _PluginState()


# --------------------------------------------------------------------------- models

class ProjectBody(BaseModel):
    project_path: str


class NavigateBody(BaseModel):
    route: str


class LinkBody(BaseModel):
    scan_id: str
    project_path: str


class HeartbeatBody(BaseModel):
    route: str = ""


# --------------------------------------------------------------------------- helpers

def _mode_name(ai_enabled: bool, llm_mock: bool) -> str:
    if not ai_enabled:
        return "detector-only"
    return "mock" if llm_mock else "full"


def analysis_mode() -> dict:
    """Which analysis mode new scans run in: the local model only adds output when local AI is
    switched on (AI_ENABLED=1 or /api/ai) with a pinned model. No network probe."""
    state = llm.ai_state()
    enabled = bool(state.enabled and state.pin is not None)
    mode = _mode_name(enabled, settings.llm_mock)
    return {"mode": mode, "llm_mode": {"full": "ollama", "mock": "mock"}.get(mode, "off"), "model": settings.llm_model}


def report_mode(report: ScanReport) -> Optional[str]:
    """The mode a finished scan actually ran in, from its own privacy attestation."""
    p = report.privacy
    if p is None:
        return None
    return _mode_name(bool(getattr(p, "ai_enabled", False)), bool(p.llm_mock))


def rule_title(rule_id: str, cwe_id: Optional[str]) -> str:
    """A *static* title for a finding — never model-generated text, never code."""
    if rule_id in RULE_BY_ID:
        return RULE_BY_ID[rule_id].title
    if rule_id in AST_RULES:
        return AST_RULES[rule_id][0]
    if rule_id in JS_RULES:
        return JS_RULES[rule_id][0]
    if cwe_id:
        entry = get_kb().get(cwe_id.upper())
        if entry is not None:
            return f"{entry.id}: {entry.name}"
    return "Security finding"


_SAFE_PATH = re.compile(r"[^\w./\-@+ ()\[\]]")


def safe_location(file: str, line: int) -> str:
    """file:line with nothing but path characters, scrubbed for good measure."""
    return scrub(_SAFE_PATH.sub("_", file)) + f":{int(line)}"


def report_summary(report: ScanReport) -> dict:
    """Metadata-only view of a report: safe to return to Claude."""
    findings = []
    for f in report.findings:
        findings.append({
            "id": f.id,
            "rule_id": f.ruleId,
            "cwe_id": f.cwe_id,
            "title": rule_title(f.ruleId, f.cwe_id),
            "severity": f.severity,
            "location": safe_location(f.file, f.line),
            "source": f.source,
            "fix_available": bool(f.fix_diff),
            "fix_verified": bool(f.fix_verified),
        })
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    privacy = report.privacy
    return {
        "security_score": report.security_score,
        "counts_by_severity": counts,
        "total_findings": len(report.findings),
        "files_scanned": len(report.files),
        "files_skipped": len(report.skipped),
        "llm_mock": bool(privacy.llm_mock) if privacy else None,
        "ai_enabled": bool(getattr(privacy, "ai_enabled", False)) if privacy else False,
        "data_leaves_machine": bool(privacy.data_leaves_machine) if privacy else False,
        "findings": findings,
    }


# --------------------------------------------------------------------------- routes

@router.post("/connect")
def connect(body: ProjectBody, request: Request, x_chaosmonkey_client: Optional[str] = Header(None)) -> dict:
    require_client(request, x_chaosmonkey_client)
    root = str(normalize_project(body.project_path))
    with state.lock:
        state.connected = root
        state.connected_at = time.time()
        state.projects.add(root)
    state.push({"type": "project", "project_path": root})
    return {"connected": True, "project_path": root, "ui_alive": state.ui_alive()}


@router.post("/disconnect")
def disconnect(body: ProjectBody, request: Request, x_chaosmonkey_client: Optional[str] = Header(None)) -> dict:
    require_client(request, x_chaosmonkey_client)
    root = str(normalize_project(body.project_path))
    with state.lock:
        state.projects.discard(root)
        if state.connected == root:
            state.connected = None
    state.push({"type": "project", "project_path": None})
    return {"connected": False, "project_path": root}


@router.get("/project")
def project(request: Request) -> dict:
    require_local(request)
    with state.lock:
        connected = state.connected
    return {
        "connected": connected is not None,
        "project_path": connected,
        "ui_alive": state.ui_alive(),
        **analysis_mode(),
    }


@router.post("/heartbeat")
def heartbeat(body: HeartbeatBody, request: Request, x_chaosmonkey_client: Optional[str] = Header(None)) -> dict:
    require_client(request, x_chaosmonkey_client)
    with state.lock:
        state.last_heartbeat = time.time()
    return {"ok": True}


@router.get("/ui-status")
def ui_status(request: Request) -> dict:
    require_local(request)
    with state.lock:
        subs = state.subscribers
        age = time.time() - state.last_heartbeat if state.last_heartbeat else None
    return {"ui_alive": state.ui_alive(), "subscribers": subs,
            "seconds_since_heartbeat": round(age, 1) if age is not None else None}


@router.post("/navigate")
def navigate(body: NavigateBody, request: Request, x_chaosmonkey_client: Optional[str] = Header(None)) -> dict:
    """Push the open UI tab(s) to a route. The caller opens a new tab when ui_alive is false."""
    require_client(request, x_chaosmonkey_client)
    if not _ROUTE_RX.match(body.route):
        raise HTTPException(status_code=400, detail="Unsupported route.")
    alive = state.ui_alive()
    seq = state.push({"type": "navigate", "route": body.route})
    return {"delivered": alive, "ui_alive": alive, "seq": seq}


@router.get("/events")
async def events(request: Request) -> StreamingResponse:
    """SSE stream of navigate/project events for the UI. An open stream counts as a live tab."""
    require_local(request)
    with state.lock:
        start = state.seq

    async def gen():
        with state.lock:
            state.subscribers += 1
        try:
            seen = start
            yield f"event: hello\ndata: {json.dumps({'seq': seen})}\n\n"
            ticks = 0
            while True:
                if await request.is_disconnected():
                    break
                for ev in state.since(seen):
                    seen = ev["seq"]
                    yield f"event: {ev['type']}\ndata: {json.dumps(ev)}\n\n"
                ticks += 1
                if ticks % 60 == 0:  # ~15 s keep-alive comment
                    yield ": keep-alive\n\n"
                await asyncio.sleep(0.25)
        finally:
            with state.lock:
                state.subscribers -= 1

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/link")
def link(body: LinkBody, request: Request, x_chaosmonkey_client: Optional[str] = Header(None)) -> dict:
    """Remember which connected project a scan (created via POST /api/scan) came from."""
    require_client(request, x_chaosmonkey_client)
    root = str(normalize_project(body.project_path))
    if store.get(body.scan_id) is None:
        raise HTTPException(status_code=404, detail="Unknown scan id")
    with state.lock:
        if root not in state.projects:
            raise HTTPException(status_code=409, detail="Project is not connected; enable ChaosMonkey first.")
        state.scan_projects[body.scan_id] = root
    return {"scan_id": body.scan_id, "project_path": root}


@router.get("/scan/{scan_id}/summary")
def scan_summary(scan_id: str, request: Request) -> dict:
    """Metadata-only scan status for the MCP server: no code, no evidence, no values."""
    require_local(request)
    session = store.get(scan_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown scan id")
    rec = session.record
    with state.lock:
        project_path = state.scan_projects.get(scan_id)
    out = {
        "scan_id": scan_id,
        "status": rec.status.value,
        "stage": rec.stage,
        "progress": rec.progress,
        "project_path": project_path,
        "report_url_path": f"/#/report/{scan_id}",
        **analysis_mode(),
    }
    if rec.status.value == "error":
        out["error"] = "Scan failed; see the ChaosMonkey server log."
    if rec.report is not None:
        out["summary"] = report_summary(rec.report)
        out["mode"] = report_mode(rec.report) or out["mode"]
    return out
