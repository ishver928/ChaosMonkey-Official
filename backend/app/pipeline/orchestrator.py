"""Pipeline orchestrator: ingest -> detect -> LLM -> validate -> merge -> score -> fix -> report.

Emits progress events (consumed by the SSE endpoint) at each stage and per finding, so the
UI can animate the scan. Deterministic throughout: stable ordering, no timestamps inside
the finding hash, cached LLM results.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..config import settings
from ..kb.store import get_kb
from ..llm.client import check_status
from ..models.schemas import (
    ChaosModeResult, Finding, FileSummary, PrivacyAttestation, ScanReport, SourceFile,
)
from .detect import run_detectors
from .fixes import generate_fix
from .ingest import Ingested
from .llm_analyze import llm_findings_for_file
from .severity import security_score
from .validate import merge_findings, stable_sort, validate_llm_findings

ProgressCb = Callable[[dict], None]


@dataclass
class ScanOptions:
    name: str = "scan"
    enabled_rule_ids: list[str] | None = None
    use_llm: bool = True
    chaos_mode: bool = False


def _emit(cb: ProgressCb | None, **event) -> None:
    if cb is not None:
        cb(event)


def _privacy() -> PrivacyAttestation:
    return PrivacyAttestation(
        data_leaves_machine=settings.data_leaves_machine,
        model=settings.llm_model,
        seed=settings.seed,
        temperature=settings.temperature,
        top_k=settings.top_k,
        top_p=settings.top_p,
        llm_mock=settings.llm_mock,
        endpoints_checked=[settings.ollama_url],
    )


def _counts(findings: list[Finding]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _summary(findings: list[Finding], score: int) -> str:
    c = _counts(findings)
    worst = next((s for s in ("critical", "high", "medium", "low") if c[s]), None)
    if not findings:
        return "No security issues found. Security score 100/100."
    lead = f"{len(findings)} issue(s) found — security score {score}/100."
    if worst:
        lead += f" Most severe: {c['critical']} critical, {c['high']} high."
    return lead


def run_scan(ingested: Ingested, opts: ScanOptions, scan_id: str, progress: ProgressCb | None = None) -> ScanReport:
    t0 = time.perf_counter()
    kb = get_kb()
    files = ingested.files
    file_map = {f.path: f for f in files}
    enabled = set(opts.enabled_rule_ids) if opts.enabled_rule_ids else None

    _emit(progress, stage="ingest", message=f"Ingested {len(files)} file(s)", progress=0.1,
          files=[f.path for f in files], skipped=len(ingested.skipped))

    # 1. Deterministic detectors
    _emit(progress, stage="detectors", message="Running deterministic detectors", progress=0.25)
    detector_findings = run_detectors(files, enabled)
    for f in detector_findings:
        _emit(progress, stage="finding", source="detector", rule=f.ruleId,
              severity=f.severity, file=f.file, line=f.line, title=f.title)

    # 2. LLM analysis + validation
    llm_valid: list[Finding] = []
    rejected = 0
    llm_status = check_status()
    if opts.use_llm:
        _emit(progress, stage="llm", message=f"Local model analysis ({llm_status.mode})", progress=0.5)
        raw: list[dict] = []
        for sf in files:
            hints = [f"{f.ruleId} {f.title} at line {f.line}" for f in detector_findings if f.file == sf.path]
            raw.extend(llm_findings_for_file(sf, kb, hints))
        llm_valid, rejected = validate_llm_findings(raw, file_map, kb)
        _emit(progress, stage="validation", message=f"Validated model findings ({rejected} rejected)", progress=0.7,
              rejected=rejected, accepted=len(llm_valid))

    # 3. Merge + order
    findings = merge_findings(detector_findings, llm_valid)
    findings = stable_sort(findings)

    # 4. Fix generation
    _emit(progress, stage="fixes", message="Generating and verifying fixes", progress=0.85)
    for f in findings:
        sf = file_map.get(f.file)
        if sf is not None:
            generate_fix(f, sf, files)

    # 5. Chaos mode (optional mutation self-test)
    chaos_result = None
    if opts.chaos_mode:
        _emit(progress, stage="chaos", message="Chaos Mode: injecting known bugs", progress=0.92)
        chaos_result = run_chaos_mode(files, enabled)

    score = security_score(findings)
    report = ScanReport(
        id=scan_id,
        name=opts.name,
        createdAt=0,
        durationMs=int((time.perf_counter() - t0) * 1000),
        files=[FileSummary(path=f.path, language=_lang(f.path), lines=f.content.count("\n") + 1, bytes=len(f.content.encode("utf-8"))) for f in files],
        skipped=ingested.skipped,
        findings=findings,
        rulesRun=_rules_run(enabled),
        security_score=score,
        counts_by_severity=_counts(findings),
        executive_summary=_summary(findings, score),
        privacy=_privacy(),
        chaos_mode=chaos_result,
    )
    _emit(progress, stage="done", message="Scan complete", progress=1.0,
          security_score=score, findings=len(findings))
    return report


def _lang(path: str):
    from ..detectors.common import detect_language
    return detect_language(path)


def _rules_run(enabled: set[str] | None) -> int:
    from ..detectors.js_rules import JS_RULES
    from ..detectors.python_ast import AST_RULES
    from ..detectors.rules import RULES
    total = len(RULES) + len(AST_RULES) + len(JS_RULES)
    return total if enabled is None else len(enabled)


# --- Chaos Mode ----------------------------------------------------------

_INJECTABLE = [
    ("py_sqli", "py", 'cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")', "CM-A001"),
    ("py_shell", "py", 'os.system("rm -rf " + target)', "CM-A002"),
    ("py_eval", "py", 'eval(request.args["expr"])', "CM-A003"),
    ("py_verify", "py", 'requests.get(url, verify=False)', "CM-A006"),
    ("js_innerhtml", "js", 'el.innerHTML = "hi " + userInput', "CM-J001"),
]


def run_chaos_mode(files: list[SourceFile], enabled: set[str] | None) -> ChaosModeResult:
    """Inject known-vulnerable snippets into copies and confirm Chaos Monkey catches them."""
    import random

    rng = random.Random(settings.seed)
    details = []
    detected = 0
    py_target = next((f for f in files if f.path.endswith(".py")), None)
    js_target = next((f for f in files if f.path.endswith((".js", ".ts", ".jsx", ".tsx"))), None)
    candidates = list(_INJECTABLE)
    rng.shuffle(candidates)
    injected = 0
    for name, kind, snippet, rule in candidates:
        target = py_target if kind == "py" else js_target
        if target is None:
            continue
        injected += 1
        mutated = SourceFile(path=target.path, content=target.content + "\n" + snippet + "\n")
        found = run_detectors(([mutated]), enabled)
        hit = any(f.ruleId == rule for f in found)
        detected += 1 if hit else 0
        details.append({"snippet_id": name, "rule": rule, "detected": hit})
    rate = round(detected / injected, 3) if injected else 0.0
    return ChaosModeResult(injected=injected, detected=detected, detection_rate=rate, details=details)
