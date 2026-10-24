"""Core REST + SSE API routes for Chaos Monkey."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse

from ..config import settings
from ..kb.store import get_kb
from ..llm.client import check_status
from ..models.schemas import ScanReport, ScanRequest
from ..pipeline.fixes import apply_all_fixes
from ..pipeline.ingest import ingest_code, ingest_files, ingest_path, ingest_zip, Ingested
from ..pipeline.orchestrator import ScanOptions, run_scan
from ..reports.render import render
from .store import store

router = APIRouter(prefix="/api")


def _scan_id(seed: str) -> str:
    return "scan_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


@router.get("/health")
def health() -> dict:
    kb = get_kb()
    llm = check_status()
    problems = settings.verify_local_only()
    return {
        "status": "ok",
        "mode": "full" if llm.available and llm.mode == "ollama" else ("mock" if llm.mode == "mock" else "detector-only"),
        "llm": {"available": llm.available, "mode": llm.mode, "model": llm.model, "detail": llm.detail},
        "kb_size": kb.size(),
        "embed_backend": kb.embed_backend,
        "data_leaves_machine": settings.data_leaves_machine,
        "privacy_ok": len(problems) == 0,
        "problems": problems,
        "privacy_attestation": {
            "analysis_location": "local-machine",
            "model": settings.llm_model,
            "seed": settings.seed,
            "endpoints": [settings.ollama_url],
        },
        "version": "1.0.0",
    }


def _build_ingested(req: ScanRequest) -> Ingested:
    inc = req.include_test_paths
    if req.files:
        return ingest_files(req.files, inc)
    if req.code is not None:
        return ingest_code(req.code, req.filename, inc)
    if req.path:
        return ingest_path(req.path, inc)
    raise HTTPException(status_code=400, detail="Provide 'code', 'files', or 'path'.")


@router.post("/scan")
def create_scan(req: ScanRequest) -> dict:
    try:
        ingested = _build_ingested(req)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not ingest input: {exc}") from exc
    if not ingested.files:
        raise HTTPException(status_code=400, detail="No analyzable files found in input.")
    opts = ScanOptions(name=req.name, enabled_rule_ids=req.enabled_rule_ids,
                       use_llm=req.use_llm, chaos_mode=req.chaos_mode)
    sid = _scan_id(f"{req.name}:{time.time_ns()}")
    store.start(sid, ingested, opts)
    return {"scan_id": sid, "status": "queued"}


@router.post("/scan/upload")
async def create_scan_upload(
    file: UploadFile = File(...),
    name: str = Form("upload"),
    use_llm: bool = Form(True),
    chaos_mode: bool = Form(False),
) -> dict:
    data = await file.read()
    if file.filename and file.filename.endswith(".zip"):
        ingested = ingest_zip(data)
    else:
        ingested = Ingested()
        ingested.add_raw(file.filename or "upload.txt", data)
    if not ingested.files:
        raise HTTPException(status_code=400, detail="No analyzable files in upload.")
    opts = ScanOptions(name=name, use_llm=use_llm, chaos_mode=chaos_mode)
    sid = _scan_id(f"{name}:{time.time_ns()}")
    store.start(sid, ingested, opts)
    return {"scan_id": sid, "status": "queued"}


@router.get("/scan/{scan_id}")
def get_scan(scan_id: str) -> dict:
    session = store.get(scan_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown scan id")
    rec = session.record
    return {
        "scan_id": scan_id,
        "status": rec.status.value,
        "stage": rec.stage,
        "progress": rec.progress,
        "error": rec.error,
        "report": rec.report.model_dump() if rec.report else None,
    }


@router.get("/scan/{scan_id}/events")
async def scan_events(scan_id: str, request: Request) -> StreamingResponse:
    session = store.get(scan_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown scan id")

    async def gen():
        idx = 0
        while True:
            if await request.is_disconnected():
                break
            new = session.snapshot(idx)
            for ev in new:
                idx += 1
                if ev.get("stage") == "_end":
                    yield f"event: done\ndata: {json.dumps({'status': session.record.status.value})}\n\n"
                    return
                yield f"data: {json.dumps(ev)}\n\n"
            if session.done.is_set() and not session.snapshot(idx):
                yield f"event: done\ndata: {json.dumps({'status': session.record.status.value})}\n\n"
                return
            await asyncio.sleep(0.1)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/scan/{scan_id}/report")
def get_report(scan_id: str, format: str = Query("json")) -> Response:
    session = store.get(scan_id)
    if session is None or session.record.report is None:
        raise HTTPException(status_code=404, detail="Report not ready")
    content, media = render(session.record.report, format)
    if format.lower() == "html":
        return Response(content=content, media_type=media)
    if format.lower() in {"md", "markdown"}:
        return PlainTextResponse(content=content, media_type=media)
    return Response(content=content, media_type=media)


@router.post("/scan/{scan_id}/apply-fixes")
def apply_fixes(scan_id: str) -> dict:
    session = store.get(scan_id)
    if session is None or session.record.report is None:
        raise HTTPException(status_code=404, detail="Scan not found or not finished")
    files = {sf.path: sf for sf in session.files}
    patched, combined = apply_all_fixes(session.record.report.findings, files)
    verified = [f for f in session.record.report.findings if f.fix_verified]
    return {
        "scan_id": scan_id,
        "fixes_applied": len(verified),
        "combined_diff": combined,
        "patched_files": patched,
    }


@router.get("/cwe/search")
def cwe_search(q: str = Query(..., min_length=1)) -> dict:
    kb = get_kb()
    results = kb.search(q)
    return {"query": q, "results": [
        {"id": e.id, "name": e.name, "description": e.description} for e in results
    ]}


@router.get("/cwe/{cwe_id}")
def cwe_get(cwe_id: str) -> dict:
    kb = get_kb()
    cid = cwe_id if cwe_id.upper().startswith("CWE-") else f"CWE-{cwe_id}"
    entry = kb.get(cid.upper())
    if entry is None:
        raise HTTPException(status_code=404, detail=f"Unknown CWE {cwe_id}")
    return {
        "id": entry.id, "name": entry.name, "description": entry.description,
        "consequences": entry.consequences, "mitigation": entry.mitigation,
        "examples": entry.examples, "pattern_rules": entry.pattern_rules,
    }


@router.get("/determinism-check")
def determinism_check() -> dict:
    """Run the same scan twice and confirm the reports are byte-identical."""
    sample = (
        'import os, hashlib\n'
        'API_KEY = "sk-fake-DEADBEEF1234567890abcdef99"\n'
        'def login(name):\n'
        '    cur.execute("SELECT * FROM users WHERE name = " + name)\n'
        'def pw(password):\n'
        '    return hashlib.md5(password.encode()).hexdigest()\n'
    )

    def _run(tag: str) -> ScanReport:
        ing = ingest_code(sample, "sample.py")
        return run_scan(ing, ScanOptions(name="determinism"), f"det_{tag}")

    r1, r2 = _run("a"), _run("b")
    d1, d2 = r1.model_dump(), r2.model_dump()
    for d in (d1, d2):
        d.pop("durationMs", None)
        d["id"] = ""
    j1 = json.dumps(d1, sort_keys=True)
    j2 = json.dumps(d2, sort_keys=True)
    identical = j1 == j2
    return {
        "identical": identical,
        "finding_ids_run1": [f.id for f in r1.findings],
        "finding_ids_run2": [f.id for f in r2.findings],
        "hash_run1": hashlib.sha256(j1.encode()).hexdigest()[:16],
        "hash_run2": hashlib.sha256(j2.encode()).hexdigest()[:16],
    }
