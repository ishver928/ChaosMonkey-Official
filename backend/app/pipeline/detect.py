"""DETECTOR stage: run every deterministic detector and build grounded Findings.

Combines the regex CM-* rules, Python AST rules (CM-A*) and extended JS rules (CM-J*),
converts each RawMatch into a Finding with a stable id, masked value, line/column, the
mapped CWE, and a severity score. Overlapping generic hits are dropped in favour of a
more specific rule, matching the frontend scanner's behaviour.
"""

from __future__ import annotations

import hashlib

from ..detectors.common import DetectContext, RawMatch, detect_language, line_at, line_col
from ..detectors.js_rules import JS_RULES, detect_js
from ..detectors.masking import mask_value
from ..detectors.python_ast import AST_RULES, detect_python_ast
from ..detectors.rules import RULES, RULE_BY_ID
from ..kb.mapping import cwe_for_rule
from ..models.schemas import Finding, SourceFile, ValidationTrace
from .severity import score_finding

GENERIC_RULES = {r.id for r in RULES if r.generic}

# Metadata for the AST/JS rule ids so findings get a title/category/severity/cwe.
_EXTRA_META: dict[str, tuple[str, str, str, str]] = {}
for _rid, (_title, _cat, _sev, _desc, _cwe) in {**AST_RULES, **JS_RULES}.items():
    _EXTRA_META[_rid] = (_title, _cat, _sev, _cwe)


def finding_id(file: str, line: int, cwe: str, snippet: str) -> str:
    """Stable, timestamp-free id = sha256(file+line+cwe+snippet)[:12]."""
    h = hashlib.sha256(f"{file}|{line}|{cwe}|{snippet}".encode("utf-8")).hexdigest()
    return h[:12]


def _meta_for(rule_id: str) -> tuple[str, str, str, str | None]:
    """Return (title, category, severity, cwe) for any rule id."""
    if rule_id in RULE_BY_ID:
        r = RULE_BY_ID[rule_id]
        return r.title, r.category, r.severity, cwe_for_rule(rule_id)
    if rule_id in _EXTRA_META:
        title, cat, sev, cwe = _EXTRA_META[rule_id]
        return title, cat, sev, cwe
    return rule_id, "misc", "info", cwe_for_rule(rule_id)


def _overlaps(a: RawMatch, b: RawMatch) -> bool:
    return a.start < b.end and b.start < a.end


def _drop_generic_overlaps(matches: list[RawMatch]) -> list[RawMatch]:
    specific = [m for m in matches if m.rule_id not in GENERIC_RULES]
    out = []
    for m in matches:
        if m.rule_id in GENERIC_RULES and any(_overlaps(m, s) for s in specific):
            continue
        out.append(m)
    return out


def run_detectors_on_file(sf: SourceFile, project: list[SourceFile], enabled: set[str] | None) -> list[Finding]:
    lang = detect_language(sf.path)
    ctx = DetectContext(path=sf.path, language=lang, content=sf.content, project=project)

    matches: list[RawMatch] = []
    for rule in RULES:
        if enabled is not None and rule.id not in enabled:
            continue
        try:
            matches.extend(rule.detect(ctx))
        except Exception:
            continue
    if lang == "python" and (enabled is None or any(r in enabled for r in AST_RULES)):
        matches.extend(detect_python_ast(sf.content))
    if lang in {"javascript", "typescript"} and (enabled is None or any(r in enabled for r in JS_RULES)):
        matches.extend(detect_js(ctx))

    matches = _drop_generic_overlaps(matches)
    findings: list[Finding] = []
    for m in matches:
        raw = sf.content[m.start:m.end]
        title, category, severity, cwe = _meta_for(m.rule_id)
        line, column = line_col(sf.content, m.start)
        end_line, end_column = line_col(sf.content, m.end)
        masked = mask_value(raw, m.rule_id, m.name) if m.sensitive else raw.strip()[:200]
        snippet_line = line_at(sf.content, m.start)
        # Build a masked snippet of the finding's line.
        if m.sensitive and raw in snippet_line:
            masked_snippet = snippet_line.replace(raw, masked)
        else:
            masked_snippet = snippet_line.strip()[:300]
        fid = finding_id(sf.path, line, cwe or m.rule_id, snippet_line.strip())
        f = Finding(
            id=fid,
            ruleId=m.rule_id,
            category=category,
            severity=severity,
            file=sf.path,
            language=lang,
            line=line, column=column, endLine=end_line, endColumn=end_column,
            sensitive=m.sensitive,
            maskedValue=masked,
            snippet=masked_snippet,
            confidence=m.confidence,
            note=m.note,
            name=m.name,
            cwe_id=cwe,
            title=title,
            evidence_snippet=snippet_line.strip(),
            source="detector",
            validation=ValidationTrace(
                evidence_in_source=True,
                cwe_known=cwe is not None,
                cwe_pattern_match=True,
                confirmed_by_detector=True,
                notes=["deterministic detector match"],
            ),
        )
        score_finding(f, raw_value=raw if m.sensitive else None)
        findings.append(f)
    return findings


def run_detectors(files: list[SourceFile], enabled: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for sf in files:
        out.extend(run_detectors_on_file(sf, files, enabled))
    return out
