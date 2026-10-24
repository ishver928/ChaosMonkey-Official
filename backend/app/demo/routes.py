"""Demo engine routes: Attack -> Scan -> Fix -> Attack-again, streamed over SSE.

Everything targets the bundled demo apps on 127.0.0.1 only. The ``/full`` endpoint runs
the whole before/after sequence as one SSE stream for one-click judging.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from ..pipeline.ingest import ingest_files
from ..pipeline.orchestrator import ScanOptions, run_scan
from .scenarios import SCENARIOS, list_scenarios, scenario_source_files
from .simulator import launch, ATTACKS

router = APIRouter(prefix="/api/demo")

# Cache the most recent scan report per scenario so /fix and reports can reuse it.
_LAST_SCAN: dict[str, object] = {}


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"


def _run_attacks_events(scenario: str, variant: str) -> list[dict]:
    fn = ATTACKS[scenario]
    events = []
    with launch(scenario, variant) as app:
        for res in fn(app):
            events.append({
                "type": "attack", "name": res.name, "description": res.description,
                "request": res.request, "response": res.response,
                "verdict": res.verdict, "stolen": res.stolen, "variant": variant,
            })
    return events


@router.get("/scenarios")
def scenarios() -> dict:
    return {"scenarios": list_scenarios()}


def _check(scenario: str) -> None:
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {scenario}")


@router.post("/{scenario}/attack")
def attack(scenario: str, target: str = Query("vulnerable")) -> StreamingResponse:
    _check(scenario)
    variant = "patched" if target == "patched" else "vulnerable"

    def gen():
        yield _sse({"type": "stage", "stage": "attack", "target": variant})
        try:
            events = _run_attacks_events(scenario, variant)
        except Exception as exc:
            yield _sse({"type": "error", "message": str(exc)})
            return
        compromised = 0
        for ev in events:
            if ev["verdict"] == "COMPROMISED":
                compromised += 1
            yield _sse(ev)
        yield _sse({"type": "summary", "compromised": compromised, "total": len(events), "target": variant})
        yield _sse({"type": "done"})

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.post("/{scenario}/scan")
def scan(scenario: str) -> StreamingResponse:
    _check(scenario)
    files = scenario_source_files(scenario, "vulnerable")

    def gen():
        yield _sse({"type": "stage", "stage": "scan"})
        ingested = ingest_files(files)
        events: list[dict] = []
        report = run_scan(ingested, ScanOptions(name=f"demo:{scenario}"), f"demo_{scenario}",
                          progress=lambda e: events.append(e))
        _LAST_SCAN[scenario] = report
        for e in events:
            yield _sse({"type": "progress", **e})
        yield _sse({
            "type": "report",
            "security_score": report.security_score,
            "findings": len(report.findings),
            "counts": report.counts_by_severity,
            "summary": report.executive_summary,
            "top": [
                {"rule": f.ruleId, "cwe": f.cwe_id, "severity": f.severity,
                 "title": f.title, "file": f.file, "line": f.line}
                for f in report.findings[:10]
            ],
        })
        yield _sse({"type": "done"})

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.post("/{scenario}/fix")
def fix(scenario: str) -> StreamingResponse:
    _check(scenario)

    def gen():
        yield _sse({"type": "stage", "stage": "fix"})
        report = _LAST_SCAN.get(scenario)
        if report is None:
            files = scenario_source_files(scenario, "vulnerable")
            report = run_scan(ingest_files(files), ScanOptions(name=f"demo:{scenario}"), f"demo_{scenario}")
            _LAST_SCAN[scenario] = report
        verified = [f for f in report.findings if f.fix_verified]
        for f in report.findings:
            yield _sse({"type": "fix", "rule": f.ruleId, "cwe": f.cwe_id,
                        "verified": f.fix_verified, "file": f.file, "line": f.line,
                        "suggested_fix": f.suggested_fix})
        yield _sse({"type": "summary", "total": len(report.findings), "verified": len(verified),
                    "note": "The patched demo app embodies these fixes."})
        yield _sse({"type": "done"})

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.post("/{scenario}/replay")
def replay(scenario: str) -> StreamingResponse:
    _check(scenario)

    def gen():
        yield _sse({"type": "stage", "stage": "replay"})
        try:
            before = _run_attacks_events(scenario, "vulnerable")
            after = _run_attacks_events(scenario, "patched")
        except Exception as exc:
            yield _sse({"type": "error", "message": str(exc)})
            return
        b_comp = sum(1 for e in before if e["verdict"] == "COMPROMISED")
        a_comp = sum(1 for e in after if e["verdict"] == "COMPROMISED")
        for e in after:
            yield _sse({**e, "phase": "after"})
        yield _sse({
            "type": "comparison",
            "before": {"compromised": b_comp, "total": len(before)},
            "after": {"compromised": a_comp, "total": len(after)},
        })
        yield _sse({"type": "done"})

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.post("/{scenario}/full")
def full(scenario: str) -> StreamingResponse:
    _check(scenario)
    files = scenario_source_files(scenario, "vulnerable")

    def gen():
        # 1. Attack the vulnerable app
        yield _sse({"type": "stage", "stage": "attack", "target": "vulnerable"})
        try:
            before = _run_attacks_events(scenario, "vulnerable")
        except Exception as exc:
            yield _sse({"type": "error", "message": str(exc)})
            return
        b_comp = sum(1 for e in before if e["verdict"] == "COMPROMISED")
        for e in before:
            yield _sse({**e, "phase": "before"})
        yield _sse({"type": "summary", "phase": "before", "compromised": b_comp, "total": len(before)})

        # 2. Scan
        yield _sse({"type": "stage", "stage": "scan"})
        events: list[dict] = []
        report = run_scan(ingest_files(files), ScanOptions(name=f"demo:{scenario}"), f"demo_{scenario}",
                          progress=lambda e: events.append(e))
        _LAST_SCAN[scenario] = report
        before_score = report.security_score
        yield _sse({"type": "report", "security_score": before_score,
                    "findings": len(report.findings), "counts": report.counts_by_severity})

        # 3. Fix
        yield _sse({"type": "stage", "stage": "fix"})
        verified = [f for f in report.findings if f.fix_verified]
        yield _sse({"type": "summary", "phase": "fix", "verified": len(verified),
                    "total": len(report.findings)})

        # 4. Re-attack the patched app
        yield _sse({"type": "stage", "stage": "replay", "target": "patched"})
        after = _run_attacks_events(scenario, "patched")
        a_comp = sum(1 for e in after if e["verdict"] == "COMPROMISED")
        for e in after:
            yield _sse({**e, "phase": "after"})

        # 5. Before/after scorecard
        patched_files = scenario_source_files(scenario, "patched")
        patched_report = run_scan(ingest_files(patched_files), ScanOptions(name=f"demo:{scenario}:patched"),
                                  f"demo_{scenario}_patched")
        yield _sse({
            "type": "comparison",
            "attacks": {"before": {"compromised": b_comp, "total": len(before)},
                        "after": {"compromised": a_comp, "total": len(after)}},
            "security_score": {"before": before_score, "after": patched_report.security_score},
        })
        yield _sse({"type": "done"})

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.post("/{scenario}/reset")
def reset(scenario: str) -> dict:
    _check(scenario)
    _LAST_SCAN.pop(scenario, None)
    return {"scenario": scenario, "reset": True}
