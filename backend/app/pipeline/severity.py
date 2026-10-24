"""Deterministic severity scoring (no LLM).

A finding's 0–10 score comes from a CWE base severity plus modifiers (live-format secret,
PII involved, auth/injection class, internet-reachable route). The score maps to
Critical/High/Medium/Low/Info and a plain-English reason, so the rating is explainable
and identical on every run.
"""

from __future__ import annotations

from ..models.schemas import Finding, Severity

# Base score per CWE (0–10).
CWE_BASE: dict[str, float] = {
    "CWE-89": 9.0, "CWE-78": 9.5, "CWE-94": 9.0, "CWE-502": 9.0, "CWE-22": 7.5,
    "CWE-798": 8.5, "CWE-321": 8.5, "CWE-259": 7.5, "CWE-327": 7.0, "CWE-328": 7.5,
    "CWE-918": 8.0, "CWE-352": 6.5, "CWE-287": 8.0, "CWE-306": 7.5, "CWE-862": 7.5,
    "CWE-639": 7.0, "CWE-200": 5.0, "CWE-532": 6.0, "CWE-312": 6.5, "CWE-311": 6.0,
    "CWE-434": 8.0, "CWE-601": 5.5, "CWE-611": 7.5, "CWE-117": 5.0, "CWE-209": 5.5,
    "CWE-295": 7.0, "CWE-330": 6.0, "CWE-489": 7.5, "CWE-1004": 5.0, "CWE-942": 7.0,
    "CWE-347": 8.0,
}

# Fallback base per category when no CWE base is known.
CATEGORY_BASE = {
    "secrets": 8.0, "injection": 8.5, "auth": 7.5, "storage": 6.0, "pii": 5.0, "misc": 5.0,
}

_LIVE_PREFIXES = ("sk_live_", "rk_live_", "AKIA", "ASIA", "ghp_", "AIza", "sk-ant-", "xoxb-")


def _bucket(score: float) -> Severity:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "info"


def score_finding(finding: Finding, raw_value: str | None = None) -> Finding:
    """Compute severity_score, severity and severity_reason for a finding in place."""
    base = CWE_BASE.get(finding.cwe_id or "", CATEGORY_BASE.get(finding.category, 5.0))
    score = base
    reasons = [f"base {base:.1f} for {finding.cwe_id or finding.category}"]

    # Modifier: a live-format secret is worse than a placeholder.
    if finding.category == "secrets" and raw_value:
        if any(raw_value.startswith(p) for p in _LIVE_PREFIXES):
            score += 0.8
            reasons.append("live-format credential (+0.8)")

    # Modifier: confirmed by two independent methods.
    if finding.source == "both":
        score += 0.5
        reasons.append("confirmed by detector and model (+0.5)")

    # Modifier: PII increases blast radius of a leak/log finding.
    if finding.category == "pii":
        reasons.append("personal data involved")

    # Modifier: injection/auth on a code file is directly exploitable.
    if finding.category in {"injection", "auth"}:
        score += 0.3
        reasons.append("directly exploitable class (+0.3)")

    # Demotion: low-confidence LLM-only finding.
    if finding.source == "llm" and finding.confidence < 0.5:
        score -= 1.5
        reasons.append("low-confidence model-only finding (-1.5)")

    score = max(0.0, min(10.0, score))
    finding.severity_score = round(score, 1)
    finding.severity = _bucket(score)
    finding.severity_reason = "; ".join(reasons)
    return finding


# 0–100 security score for the whole report (higher = safer). Inverse of weighted risk.
_WEIGHT = {"critical": 18.0, "high": 9.0, "medium": 4.0, "low": 1.5, "info": 0.3}


def security_score(findings: list[Finding]) -> int:
    import math

    risk = sum(_WEIGHT.get(f.severity, 0) * (0.5 + f.confidence / 2) for f in findings)
    safe = round(100 * math.exp(-risk / 190))
    if any(f.severity == "critical" for f in findings):
        safe = min(safe, 60)
    elif any(f.severity == "high" for f in findings):
        safe = min(safe, 80)
    return max(0, min(100, safe))
