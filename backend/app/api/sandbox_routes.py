"""Additive sandbox-verification endpoints. Does not change any existing route or response
shape; the only way existing findings change is gaining an optional ``verification`` field
once a sandbox run has touched them (see ``sandbox.service.attach_verification``).
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..models.schemas import SandboxRunRequest
from ..sandbox import service as sandbox_service
from .store import store

router = APIRouter(prefix="/api/sandbox")


@router.post("/run")
def run_sandbox(req: SandboxRunRequest) -> dict:
    session = store.get(req.scan_id)
    if session is None or session.record.report is None:
        raise HTTPException(status_code=404, detail="Scan not found or not finished")
    rec = sandbox_service.start_run(
        req.scan_id, session.files, session.record.report.findings, req.finding_ids,
    )
    return {"sandbox_run_id": rec.id, "status": rec.status}


@router.get("/{run_id}")
def get_sandbox_run(run_id: str) -> dict:
    rec = sandbox_service.get_record(run_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Unknown sandbox run id")
    if rec.status == "done":
        session = store.get(rec.scan_id)
        if session is not None and session.record.report is not None:
            sandbox_service.attach_verification(session.record.report.findings, rec.results)
    return rec.model_dump()
