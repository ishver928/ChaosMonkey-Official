"""DETECTOR stage: run every deterministic detector and build grounded Findings.

Combines the regex CM-* rules, Python AST rules (CM-A*) and extended JS rules (CM-J*),
converts each RawMatch into a Finding with a stable id, masked value, line/column, the
mapped CWE, and a severity score. Overlapping generic hits are dropped in favour of a
more specific rule, matching the frontend scanner's behaviour.
"""

from __future__ import annotations

import hashlib

from ..detectors.catalog import load_catalog
from ..detectors.code_rules import CODE_RULE_IDS, detect_code
from ..detectors.common import DetectContext, RawMatch, detect_language, line_at, line_col
from ..detectors.js_rules import JS_RULE_IDS, detect_js
from ..detectors.masking import mask_value, scrub
from ..detectors.python_ast import AST_RULE_IDS, detect_python_ast
from ..detectors.rules import RULES
from ..kb.mapping import cwe_for_rule
from ..models.schemas import Finding, SourceFile, ValidationTrace
from .severity import score_finding

GENERIC_RULES = {r.id for r in RULES if r.generic}
EXTRA_RULE_IDS = (*AST_RULE_IDS, *JS_RULE_IDS, *CODE_RULE_IDS)
ALL_RULE_IDS = tuple(r.id for r in RULES) + EXTRA_RULE_IDS


def finding_id(file: str, line: int, cwe: str, snippet: str) -> str:
    """Stable, timestamp-free id = sha256(file+line+cwe+snippet)[:12]."""
    h = hashlib.sha256(f"{file}|{line}|{cwe}|{snippet}".encode("utf-8")).hexdigest()
    return h[:12]


def _meta_for(rule_id: str) -> tuple[str, str, str, str | None]:
    """Return (title, category, severity, cwe) for any rule id, from rules/catalog.json."""
    info = load_catalog().get(rule_id)
    if info is not None:
        return info.title, info.category, info.severity, info.cwe
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


def _drop_superseded(matches: list[RawMatch], content: str) -> list[RawMatch]:
    """Drop a hit when a rule listed in its catalog ``superseded_by`` fires on the same line."""
    cat = load_catalog()
    lines = {id(m): content.count("\n", 0, m.start) for m in matches}
    out = []
    for m in matches:
        info = cat.get(m.rule_id)
        sup = set(info.superseded_by) if info else set()
        if sup and any(o.rule_id in sup and lines[id(o)] == lines[id(m)] for o in matches):
            continue
        out.append(m)
    return out


def _dedupe(matches: list[RawMatch]) -> list[RawMatch]:
    seen: set[tuple[str, int, int]] = set()
    out = []
    for m in matches:
        k = (m.rule_id, m.start, m.end)
        if k not in seen:
            seen.add(k)
            out.append(m)
    return out


def raw_matches_for_file(sf: SourceFile, project: list[SourceFile], enabled: set[str] | None) -> list[RawMatch]:
    """Every rule's raw hits for one file after overlap/supersede filtering (no masking yet)."""
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
    extra: list[RawMatch] = []
    try:
        if lang == "python":
            extra.extend(detect_python_ast(sf.content))
        extra.extend(detect_js(ctx))
        extra.extend(detect_code(ctx))
    except Exception:
        pass
    matches.extend(m for m in extra if enabled is None or m.rule_id in enabled)
    matches = _dedupe(matches)
    matches = _drop_generic_overlaps(matches)
    matches = _drop_superseded(matches, sf.content)
    return matches


def run_detectors_on_file(sf: SourceFile, project: list[SourceFile], enabled: set[str] | None) -> list[Finding]:
    lang = detect_language(sf.path)
    matches = raw_matches_for_file(sf, project, enabled)
    cat = load_catalog()
    findings: list[Finding] = []
    for m in matches:
        raw = sf.content[m.start:m.end]
        title, category, severity, cwe = _meta_for(m.rule_id)
        line, column = line_col(sf.content, m.start)
        end_line, end_column = line_col(sf.content, max(m.start, m.end - 1))
        masked = mask_value(raw, m.rule_id, m.name) if m.sensitive else raw.strip()[:200]
        snippet_line = line_at(sf.content, m.start)
        # Evidence is the finding's source line; sensitive values on it are masked.
        if m.sensitive and raw in snippet_line:
            masked_snippet = snippet_line.replace(raw, masked).strip()[:300]
        else:
            masked_snippet = scrub(snippet_line.strip()[:300])
        fid = finding_id(sf.path, line, cwe or m.rule_id, snippet_line.strip())
        info = cat.get(m.rule_id)
        f = Finding(
            id=fid,
            ruleId=m.rule_id,
            category=category,
            severity=severity,
            file=sf.path,
            language=lang,
            line=line, column=column, endLine=end_line, endColumn=end_column + 1,
            start=m.start, end=m.end,
            sensitive=m.sensitive,
            maskedValue=masked,
            snippet=masked_snippet,
            confidence=m.confidence,
            note=m.note,
            name=m.name,
            cwe_id=cwe,
            title=title,
            evidence_snippet=masked_snippet,
            explanation=info.explanation if info else "",
            suggested_fix=info.fix_example(lang) if info else "",
            remediation_steps=list(info.steps) if info else [],
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
