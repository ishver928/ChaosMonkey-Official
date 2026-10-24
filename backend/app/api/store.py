"""In-memory scan store + background runner with event buffering for SSE.

Each scan gets a ScanRecord, a verbatim event log (so an SSE client that connects late
still replays progress), and its original SourceFiles (kept in memory only, never persisted)
so fixes can be applied later. Scans run on a thread pool to keep the API responsive.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..models.schemas import ScanRecord, ScanReport, ScanStatus, SourceFile
from ..pipeline.ingest import Ingested
from ..pipeline.orchestrator import ScanOptions, run_scan

_executor = ThreadPoolExecutor(max_workers=4)


@dataclass
class ScanSession:
    record: ScanRecord
    events: list[dict] = field(default_factory=list)
    files: list[SourceFile] = field(default_factory=list)
    done: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add_event(self, event: dict) -> None:
        with self.lock:
            self.events.append(event)

    def snapshot(self, start: int) -> list[dict]:
        with self.lock:
            return self.events[start:]


class ScanStore:
    def __init__(self) -> None:
        self._sessions: dict[str, ScanSession] = {}
        self._lock = threading.Lock()

    def create(self, scan_id: str) -> ScanSession:
        session = ScanSession(record=ScanRecord(id=scan_id, status=ScanStatus.queued))
        with self._lock:
            self._sessions[scan_id] = session
        return session

    def get(self, scan_id: str) -> ScanSession | None:
        with self._lock:
            return self._sessions.get(scan_id)

    def start(self, scan_id: str, ingested: Ingested, opts: ScanOptions) -> ScanSession:
        session = self.create(scan_id)
        session.files = ingested.files

        def _run() -> None:
            session.record.status = ScanStatus.running
            try:
                def cb(event: dict) -> None:
                    session.record.stage = event.get("stage", session.record.stage)
                    if "progress" in event:
                        session.record.progress = float(event["progress"])
                    session.add_event(event)

                report = run_scan(ingested, opts, scan_id, progress=cb)
                session.record.report = report
                session.record.status = ScanStatus.done
                session.record.progress = 1.0
            except Exception as exc:  # pragma: no cover - defensive
                session.record.status = ScanStatus.error
                session.record.error = str(exc)
                session.add_event({"stage": "error", "message": str(exc)})
            finally:
                session.add_event({"stage": "_end"})
                session.done.set()

        _executor.submit(_run)
        return session

    def run_sync(self, scan_id: str, ingested: Ingested, opts: ScanOptions) -> ScanReport:
        """Run a scan to completion synchronously (used by demo + determinism checks)."""
        session = self.create(scan_id)
        session.files = ingested.files
        report = run_scan(ingested, opts, scan_id, progress=session.add_event)
        session.record.report = report
        session.record.status = ScanStatus.done
        session.done.set()
        return report


store = ScanStore()
