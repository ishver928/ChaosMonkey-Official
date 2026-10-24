"""EVIDENCE VALIDATION — the anti-hallucination layer.

Every LLM finding must survive:
  1. evidence_snippet appears verbatim (whitespace-normalized) in the cited file,
  2. the CWE id exists in the knowledge base,
  3. the CWE plausibly matches the code pattern (pattern-to-CWE map).
Surviving findings are converted to grounded ``Finding`` objects, then merged with the
detector findings: a match confirmed by both gets ``source="both"`` and higher confidence;
an LLM-only finding below the confidence threshold is demoted to "needs review".
Every check is recorded in the finding's ``validation`` trace so reports stay explainable.
"""

from __future__ import annotations

import re

from ..detectors.common import detect_language, line_at
from ..detectors.masking import scrub
from ..kb.mapping import cwe_plausible_for_code
from ..kb.store import KnowledgeBase
from ..models.schemas import Finding, SourceFile, ValidationTrace
from .detect import finding_id
from .severity import score_finding

CONFIDENCE_THRESHOLD = 0.5


def _normalize(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def _locate(content: str, evidence: str) -> tuple[bool, int, str]:
    """Find evidence verbatim (whitespace-normalized). Return (found, line, actual_line_text)."""
    target = _normalize(evidence)
    if not target:
        return False, 0, ""
    for i, line in enumerate(content.split("\n"), start=1):
        norm_line = _normalize(line)
        if target in norm_line or (len(target) > 12 and norm_line and norm_line in target):
            return True, i, line
    # Fall back to a multi-line normalized search.
    if target in _normalize(content):
        # Attribute to the first line of the match region.
        idx = _normalize(content).find(target)
        approx = content[:idx].count("\n") + 1 if idx >= 0 else 1
        return True, max(1, approx), ""
    return False, 0, ""


def validate_llm_findings(
    raw_findings: list[dict],
    files: dict[str, SourceFile],
    kb: KnowledgeBase,
) -> tuple[list[Finding], int]:
    """Validate raw LLM dicts into grounded Findings. Returns (findings, rejected_count)."""
    validated: list[Finding] = []
    rejected = 0
    for raw in raw_findings:
        file = raw.get("file", "")
        sf = files.get(file)
        if sf is None:
            rejected += 1
            continue
        evidence = str(raw.get("evidence_snippet", ""))
        cwe = str(raw.get("cwe_id", ""))
        trace = ValidationTrace()

        found, line, actual = _locate(sf.content, evidence)
        trace.evidence_in_source = found
        if not found:
            rejected += 1
            trace.notes.append("evidence not found verbatim in source — rejected")
            continue

        entry = kb.get(cwe)
        trace.cwe_known = entry is not None
        if entry is None:
            rejected += 1
            trace.notes.append(f"unknown CWE {cwe} — rejected")
            continue

        line_text = actual or line_at(sf.content, 0)
        plausible = cwe_plausible_for_code(cwe, line_text or evidence)
        trace.cwe_pattern_match = plausible
        if not plausible:
            rejected += 1
            trace.notes.append(f"{cwe} does not match code pattern — rejected")
            continue

        conf = float(raw.get("confidence", 0.6) or 0.6)
        trace.needs_review = conf < CONFIDENCE_THRESHOLD
        trace.notes.append("evidence verified; CWE known and plausible")

        lang = detect_language(file)
        snippet = (actual or evidence).strip()
        fid = finding_id(file, line, cwe, snippet)
        f = Finding(
            id=fid,
            ruleId=raw.get("rule_id", f"LLM-{cwe}"),
            category=_category_for(cwe),
            severity="info",
            file=file,
            language=lang,
            line=line, column=1, endLine=int(raw.get("line_end", line) or line), endColumn=1,
            sensitive=False,
            maskedValue="",
            snippet=scrub(snippet)[:300],
            confidence=conf,
            cwe_id=cwe,
            title=scrub(str(raw.get("title", entry.name)))[:120],
            evidence_snippet=scrub(snippet)[:300],
            explanation=scrub(str(raw.get("explanation", "")))[:1000],
            attack_scenario=scrub(str(raw.get("attack_scenario", "")))[:1000],
            suggested_fix=scrub(str(raw.get("suggested_fix", "")))[:1000],
            source="llm",
            validation=trace,
            note="needs review" if trace.needs_review else None,
        )
        score_finding(f)
        validated.append(f)
    return validated, rejected


_CWE_CATEGORY = {
    "CWE-89": "injection", "CWE-78": "injection", "CWE-94": "injection", "CWE-502": "injection",
    "CWE-22": "injection", "CWE-79": "injection",
    "CWE-798": "secrets", "CWE-321": "secrets", "CWE-259": "secrets",
    "CWE-200": "pii", "CWE-532": "pii",
    "CWE-287": "auth", "CWE-306": "auth", "CWE-862": "auth", "CWE-639": "auth",
    "CWE-347": "auth", "CWE-942": "auth", "CWE-352": "auth",
}


def _category_for(cwe: str) -> str:
    return _CWE_CATEGORY.get(cwe, "storage")


def merge_findings(detector: list[Finding], llm: list[Finding]) -> list[Finding]:
    """Merge detector and LLM findings: same file+line+cwe => confirmed by both."""
    by_key: dict[tuple, Finding] = {}

    def key(f: Finding) -> tuple:
        return (f.file, f.line, f.cwe_id or f.ruleId)

    for f in detector:
        by_key[key(f)] = f
    for f in llm:
        k = key(f)
        if k in by_key:
            existing = by_key[k]
            existing.source = "both"
            existing.confidence = min(1.0, max(existing.confidence, f.confidence) + 0.1)
            # Enrich the detector finding with the LLM's narrative.
            existing.explanation = existing.explanation or f.explanation
            existing.attack_scenario = existing.attack_scenario or f.attack_scenario
            existing.suggested_fix = existing.suggested_fix or f.suggested_fix
            existing.validation.confirmed_by_detector = True
            existing.validation.notes.append("confirmed by local model")
            score_finding(existing, raw_value=None)
        else:
            by_key[k] = f
    return list(by_key.values())


def stable_sort(findings: list[Finding]) -> list[Finding]:
    """Severity desc, then file, line, rule id — deterministic ordering."""
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: (rank.get(f.severity, 5), f.file, f.line, f.ruleId))
